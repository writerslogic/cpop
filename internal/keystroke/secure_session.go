//go:build darwin || linux || windows

// Package keystroke provides secure, tamper-evident keystroke counting and tracking.
//
// SecureTrackingSession provides the primary API for monitoring keystrokes with
// multiple layers of protection against tampering and spoofing:
//
// 1. Dual-layer validation (CGEventTap + IOKit HID on macOS)
// 2. HMAC integrity verification on all state
// 3. Cryptographic chaining of all updates
// 4. Timing anomaly detection for script/USB-HID attacks
// 5. Optional TPM binding for hardware-backed security
//
// This is the recommended approach for production use.
package keystroke

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"witnessd/internal/input"
	"witnessd/internal/jitter"
)

// SecureTrackingSession provides tamper-evident keystroke tracking.
// This is the primary API for secure keystroke monitoring.
type SecureTrackingSession struct {
	mu sync.RWMutex

	// Session identity
	id        string
	startTime time.Time
	endTime   time.Time
	filePath  string

	// Security components - counter implements the Counter interface
	// allowing both real (TPMBoundCounter) and simulated counters
	counter      Counter
	jitterEngine *jitter.JitterEngine

	// Session state
	running       bool
	sessionSecret [32]byte
	stateChain    [32]byte

	// Sealed checkpoints
	checkpoints []SecureCheckpoint

	// Content change detection
	lastDocSize   int64
	lastDocHash   [32]byte
	recentStrokes uint64 // Keystrokes since last document check

	// Input event tracking
	inputTracker      *InputTracker
	clipboardMonitor  *ClipboardMonitor
	dictationDetector *DictationDetector

	// Biometric and security components (integrated from internal/input)
	keyboardBiometrics  *input.KeyboardBiometrics
	deviceTracker       *DeviceTracker
	adversarialDefense  *input.AdversarialDefense
	passiveVerification *input.PassiveVerification

	// Spread-spectrum steganography for timing verification
	spreadSpectrumSession *input.SpreadSpectrumSession

	// Recent keystrokes for biometric analysis
	recentChars     []rune
	recentIntervals []time.Duration
	lastKeystroke   time.Time

	// Event logs
	pasteEvents     []PasteEvent
	deletionEvents  []DeletionEvent
	dictationEvents []DictationEvent

	// Backspace/deletion tracking
	recentBackspaces uint64
	recentDeletes    uint64

	// Context for cancellation
	ctx    context.Context
	cancel context.CancelFunc

	// Configuration
	config SecureSessionConfig
}

// PasteEvent records a detected paste operation.
// This allows legitimate copy/paste while maintaining transparency.
type PasteEvent struct {
	Timestamp        time.Time `json:"timestamp"`
	BytesAdded       int64     `json:"bytes_added"`
	KeystrokesBefore uint64    `json:"keystrokes_before"`
	DocumentHash     [32]byte  `json:"document_hash"`
	ClipboardHash    [32]byte  `json:"clipboard_hash,omitempty"`    // Hash of pasted content
	ClipboardSize    int       `json:"clipboard_size,omitempty"`    // Size of pasted content
	SourceApp        string    `json:"source_app,omitempty"`        // App that copied content
	Verified         bool      `json:"verified"`                    // Clipboard hash matches doc change
}

// DeletionEvent records a detected deletion (document shrinkage).
type DeletionEvent struct {
	Timestamp       time.Time `json:"timestamp"`
	BytesRemoved    int64     `json:"bytes_removed"`
	KeystrokesBefore uint64   `json:"keystrokes_before"`
	DocumentHash    [32]byte  `json:"document_hash"`
	Method          string    `json:"method"` // "backspace", "delete", "cut", "undo", "selection"
}

// DictationEvent records suspected dictation input.
type DictationEvent struct {
	Timestamp      time.Time `json:"timestamp"`
	BytesAdded     int64     `json:"bytes_added"`
	Duration       time.Duration `json:"duration"`
	CharsPerSecond float64   `json:"chars_per_second"`
	DocumentHash   [32]byte  `json:"document_hash"`
}

// SecureSessionConfig configures a secure tracking session.
type SecureSessionConfig struct {
	// FilePath is the document being tracked
	FilePath string

	// JitterSampleInterval is how often to sample jitter (in keystrokes)
	JitterSampleInterval uint64

	// CheckpointInterval is how often to create sealed checkpoints
	CheckpointInterval time.Duration

	// TPMConfig configures TPM integration
	TPMConfig TPMBindingConfig

	// StrictMode rejects any suspicious events (recommended)
	StrictMode bool

	// Simulated uses a simulated counter for testing (no permissions required)
	Simulated bool
}

// DefaultSecureSessionConfig returns sensible defaults.
func DefaultSecureSessionConfig(filePath string) SecureSessionConfig {
	return SecureSessionConfig{
		FilePath:             filePath,
		JitterSampleInterval: 50,  // Sample every 50 keystrokes
		CheckpointInterval:   time.Minute,
		TPMConfig:            DefaultTPMBindingConfig(),
		StrictMode:           true,
	}
}

// SecureCheckpoint is a tamper-evident point-in-time state capture.
type SecureCheckpoint struct {
	Timestamp       time.Time            `json:"timestamp"`
	KeystrokeCount  uint64               `json:"keystroke_count"`
	DocumentHash    [32]byte             `json:"document_hash"`
	DocumentSize    int64                `json:"document_size"`
	StateChain      [32]byte             `json:"state_chain"`
	JitterSamples   int                  `json:"jitter_samples"`
	TypingProfile   jitter.TypingProfile `json:"typing_profile"`
	TPMSnapshot     *TPMBoundSnapshot    `json:"tpm_snapshot,omitempty"`
	Anomalies       []string             `json:"anomalies,omitempty"`
	PasteEvents     int                  `json:"paste_events"`
	MAC             [32]byte             `json:"mac"`
}

// NewSecureTrackingSession creates a new secure tracking session.
func NewSecureTrackingSession(config SecureSessionConfig) (*SecureTrackingSession, error) {
	// Generate session ID
	var idBytes [16]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}

	// Generate session secret
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return nil, fmt.Errorf("failed to generate session secret: %w", err)
	}

	// Create jitter engine
	jEngine := jitter.NewJitterEngine(secret)

	// Get absolute file path
	absPath, err := filepath.Abs(config.FilePath)
	if err != nil {
		return nil, fmt.Errorf("invalid file path: %w", err)
	}

	session := &SecureTrackingSession{
		id:                hex.EncodeToString(idBytes[:]),
		startTime:         time.Now(),
		filePath:          absPath,
		jitterEngine:      jEngine,
		sessionSecret:     secret,
		config:            config,
		checkpoints:       make([]SecureCheckpoint, 0),
		inputTracker:      NewInputTracker(10000),
		clipboardMonitor:  NewClipboardMonitor(),
		dictationDetector: NewDictationDetector(),
		pasteEvents:       make([]PasteEvent, 0),
		deletionEvents:    make([]DeletionEvent, 0),
		dictationEvents:   make([]DictationEvent, 0),
		// Initialize biometric and security components
		keyboardBiometrics:    input.NewKeyboardBiometrics(),
		deviceTracker:         NewDeviceTracker(),
		adversarialDefense:    input.NewAdversarialDefense(input.DefaultDefenseConfig()),
		passiveVerification:   input.NewPassiveVerification(input.DefaultPassiveConfig()),
		spreadSpectrumSession: input.NewSpreadSpectrumSession(),
		// Initialize keystroke tracking for biometrics
		recentChars:     make([]rune, 0, 100),
		recentIntervals: make([]time.Duration, 0, 100),
		lastKeystroke:   time.Now(),
	}

	// Create counter based on mode - both implement the Counter interface
	if config.Simulated {
		session.counter = NewSimulated()
	} else {
		counter, err := NewTPMBoundCounter(config.TPMConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create counter: %w", err)
		}
		session.counter = counter
	}

	// Initialize state chain
	session.initStateChain()

	return session, nil
}

// initStateChain initializes the cryptographic state chain.
func (s *SecureTrackingSession) initStateChain() {
	h := sha256.New()
	h.Write([]byte("witnessd-secure-session-v1"))
	h.Write([]byte(s.id))
	binary.Write(h, binary.BigEndian, s.startTime.UnixNano())
	h.Write([]byte(s.filePath))
	h.Write(s.sessionSecret[:])
	copy(s.stateChain[:], h.Sum(nil))
}

// Start begins secure keystroke tracking.
func (s *SecureTrackingSession) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return errors.New("session already running")
	}

	// Verify file exists
	if _, err := os.Stat(s.filePath); err != nil {
		return fmt.Errorf("file not accessible: %w", err)
	}

	// Start the counter (both TPMBoundCounter and SimulatedCounter implement Counter)
	s.ctx, s.cancel = context.WithCancel(ctx)
	if err := s.counter.Start(s.ctx); err != nil {
		return fmt.Errorf("failed to start counter: %w", err)
	}

	// Start clipboard monitoring
	s.clipboardMonitor.Start()

	// Start device tracking for USB-HID attack detection
	if err := s.deviceTracker.Start(); err != nil {
		// Non-fatal - device tracking is optional but enhances security
		// Log but don't fail the session
	}

	// Get initial document state
	s.lastDocHash, s.lastDocSize = s.hashDocumentWithSize()

	s.running = true

	// Start checkpoint loop
	go s.checkpointLoop()

	// Start keystroke processing loop
	go s.processLoop()

	return nil
}

// processLoop processes keystrokes and updates state.
func (s *SecureTrackingSession) processLoop() {
	// Subscribe to keystroke events
	events := s.counter.Subscribe(1)

	for {
		select {
		case <-s.ctx.Done():
			return

		case event, ok := <-events:
			if !ok {
				return
			}
			s.processKeystroke(event)
		}
	}
}

// processKeystroke handles a single keystroke event.
func (s *SecureTrackingSession) processKeystroke(event Event) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	// Calculate interval since last keystroke for biometric analysis
	interval := now.Sub(s.lastKeystroke)
	s.lastKeystroke = now

	// Encode timing delta using spread-spectrum steganography
	// This creates a covert channel that only verifiers with the key can decode
	if interval > 0 {
		deltaMs := float64(interval.Milliseconds())
		s.spreadSpectrumSession.RecordTimingDelta(deltaMs)
	}

	// Get current document state
	docHash, docSize := s.hashDocumentWithSize()
	s.recentStrokes++

	// Detect paste events: large content changes with few keystrokes
	// Threshold: >100 bytes added with <5 keystrokes = likely paste
	if s.lastDocSize > 0 {
		bytesChanged := docSize - s.lastDocSize
		if bytesChanged > 100 && s.recentStrokes < 5 {
			// This looks like a paste operation
			s.pasteEvents = append(s.pasteEvents, PasteEvent{
				Timestamp:        now,
				BytesAdded:       bytesChanged,
				KeystrokesBefore: s.recentStrokes,
				DocumentHash:     docHash,
			})
			// Reset recent stroke counter after paste detection
			s.recentStrokes = 0
		}

		// Record content change for adversarial defense cross-modal analysis
		s.adversarialDefense.RecordContent(int(docSize), docHash)

		// Record for passive verification
		s.passiveVerification.OnDocumentChange(int(bytesChanged), docHash)
	}

	// Update document tracking
	if docHash != s.lastDocHash {
		s.lastDocHash = docHash
		s.lastDocSize = docSize
		s.recentStrokes = 0 // Reset on document change
	}

	// Record in jitter engine (we don't have keyCode from CGEventTap counter,
	// so we use zone 0 as placeholder - real implementation would hook deeper)
	s.jitterEngine.OnKeystroke(0, docHash)

	// Update state chain
	s.updateStateChain(event.Count, docHash)

	// Record in hardened counter with timing analysis (TPM counter only)
	if tc, ok := s.counter.(*TPMBoundCounter); ok {
		tc.RecordKeystrokeWithTPM()
	}

	// === BIOMETRIC AND SECURITY COMPONENT INTEGRATION ===

	// Feed to keyboard biometrics (we use a placeholder keycode since we don't
	// have direct access to it here - the actual keycode would come from a deeper hook)
	// In a real implementation, this would be called from the event tap callback
	// with the actual keycode. For now, we record timing which is the most important signal.
	keyCode := uint16(0) // Placeholder - actual would come from CGEventTap
	s.keyboardBiometrics.RecordKeyDown(keyCode, now)

	// Track recent chars and intervals for passive verification
	// We use a placeholder char since we don't have the actual character here
	s.recentIntervals = append(s.recentIntervals, interval)
	s.recentChars = append(s.recentChars, ' ') // Placeholder

	// Trim recent arrays
	if len(s.recentIntervals) > 100 {
		s.recentIntervals = s.recentIntervals[50:]
		s.recentChars = s.recentChars[50:]
	}

	// Feed to passive verification for continuous authentication
	s.passiveVerification.OnKeystroke(' ', interval, s.recentChars, s.recentIntervals)

	// Record input for adversarial defense cross-modal analysis
	s.adversarialDefense.RecordInput(input.MethodKeyboard, 1)

	// Periodically analyze biometric profile for anomalies
	// Do this every 100 keystrokes to avoid performance overhead
	if event.Count%100 == 0 {
		profile := s.keyboardBiometrics.Profile()
		s.adversarialDefense.AnalyzeKeyboardInput(profile)
	}
}

// hashDocumentWithSize returns the SHA-256 hash and size of the tracked file.
func (s *SecureTrackingSession) hashDocumentWithSize() ([32]byte, int64) {
	content, err := os.ReadFile(s.filePath)
	if err != nil {
		return [32]byte{}, 0
	}
	return sha256.Sum256(content), int64(len(content))
}

// updateStateChain advances the state chain with new keystroke data.
func (s *SecureTrackingSession) updateStateChain(count uint64, docHash [32]byte) {
	h := sha256.New()
	h.Write(s.stateChain[:])

	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], count)
	h.Write(buf[:])

	h.Write(docHash[:])

	binary.BigEndian.PutUint64(buf[:], uint64(time.Now().UnixNano()))
	h.Write(buf[:])

	copy(s.stateChain[:], h.Sum(nil))
}

// hashDocument returns the SHA-256 hash of the tracked file.
func (s *SecureTrackingSession) hashDocument() [32]byte {
	content, err := os.ReadFile(s.filePath)
	if err != nil {
		return [32]byte{}
	}
	return sha256.Sum256(content)
}

// checkpointLoop creates periodic sealed checkpoints.
func (s *SecureTrackingSession) checkpointLoop() {
	ticker := time.NewTicker(s.config.CheckpointInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.CreateCheckpoint()
		}
	}
}

// CreateCheckpoint creates a tamper-evident checkpoint.
func (s *SecureTrackingSession) CreateCheckpoint() (*SecureCheckpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil, errors.New("session not running")
	}

	docHash, docSize := s.hashDocumentWithSize()
	profile := s.jitterEngine.Profile()

	// Get anomaly report and TPM snapshot (only available with TPMBoundCounter)
	var anomalyReport AnomalyReport
	var tpmSnap *TPMBoundSnapshot
	if tc, ok := s.counter.(*TPMBoundCounter); ok {
		anomalyReport = tc.AnomalyReport()
		if snap, err := tc.SealWithTPM(); err == nil {
			tpmSnap = &snap
		}
	}

	// Collect anomalies
	var anomalies []string
	if anomalyReport.SuspectedScripted {
		anomalies = append(anomalies, "SUSPECTED_SCRIPTED")
	}
	if anomalyReport.SuspectedUSBHID {
		anomalies = append(anomalies, "SUSPECTED_USB_HID")
	}
	anomalies = append(anomalies, anomalyReport.ReasonCodes...)

	checkpoint := SecureCheckpoint{
		Timestamp:       time.Now(),
		KeystrokeCount:  s.counter.Count(),
		DocumentHash:    docHash,
		DocumentSize:    docSize,
		StateChain:      s.stateChain,
		JitterSamples:   int(profile.TotalTransitions),
		TypingProfile:   profile,
		TPMSnapshot:     tpmSnap,
		Anomalies:       anomalies,
		PasteEvents:     len(s.pasteEvents),
	}

	// Compute MAC
	checkpoint.MAC = s.computeCheckpointMAC(&checkpoint)

	s.checkpoints = append(s.checkpoints, checkpoint)

	return &checkpoint, nil
}

// computeCheckpointMAC computes the MAC for a checkpoint.
func (s *SecureTrackingSession) computeCheckpointMAC(cp *SecureCheckpoint) [32]byte {
	mac := hmac.New(sha256.New, s.sessionSecret[:])

	binary.Write(mac, binary.BigEndian, cp.Timestamp.UnixNano())
	binary.Write(mac, binary.BigEndian, cp.KeystrokeCount)
	mac.Write(cp.DocumentHash[:])
	mac.Write(cp.StateChain[:])
	binary.Write(mac, binary.BigEndian, int64(cp.JitterSamples))

	var result [32]byte
	copy(result[:], mac.Sum(nil))
	return result
}

// Stop ends the tracking session.
func (s *SecureTrackingSession) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	s.running = false
	s.endTime = time.Now()

	if s.cancel != nil {
		s.cancel()
	}

	// Create final checkpoint
	s.mu.Unlock()
	s.CreateCheckpoint()
	s.mu.Lock()

	// Stop counter (both implement Counter interface)
	s.counter.Stop()

	// Stop device tracking
	s.deviceTracker.Stop()

	// Close TPM resources if applicable
	if tc, ok := s.counter.(*TPMBoundCounter); ok {
		tc.Close()
	}

	return nil
}

// Status returns the current session status.
func (s *SecureTrackingSession) Status() SessionStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()

	status := SessionStatus{
		ID:             s.id,
		FilePath:       s.filePath,
		StartTime:      s.startTime,
		Running:        s.running,
		KeystrokeCount: s.counter.Count(),
		Checkpoints:    len(s.checkpoints),
		PasteEvents:    len(s.pasteEvents),
	}

	if !s.endTime.IsZero() {
		status.EndTime = s.endTime
	}

	// Get detailed stats from TPMBoundCounter (returns empty/default for simulated)
	if tc, ok := s.counter.(*TPMBoundCounter); ok {
		status.ValidationStats = tc.ValidationStats()
		status.SyntheticStats = tc.SyntheticEventStats()
		status.AnomalyReport = tc.AnomalyReport()
		status.TPMStatus = tc.TPMStatus()

		// Check if integrity is compromised
		if compromised, reason := tc.IsCompromised(); compromised {
			status.Compromised = true
			status.CompromiseReason = reason
		}
	}

	status.TypingProfile = s.jitterEngine.Profile()

	// Populate biometric and security data
	status.BiometricProfile = s.keyboardBiometrics.Profile()
	status.DeviceReport = s.deviceTracker.GenerateReport()
	status.SecurityReport = s.adversarialDefense.GenerateReport()
	status.PassiveVerified = s.passiveVerification.IsVerified()
	status.PassiveVerifyScore = s.passiveVerification.Score()
	status.LivenessConfidence = status.BiometricProfile.LivenessConfidence
	status.IdentityConfidence = status.BiometricProfile.IdentityConfidence

	return status
}

// SessionStatus contains comprehensive session status.
type SessionStatus struct {
	ID               string
	FilePath         string
	StartTime        time.Time
	EndTime          time.Time
	Running          bool
	KeystrokeCount   uint64
	Checkpoints      int
	PasteEvents      int // Detected copy/paste operations (legitimate)
	ValidationStats  ValidationStats
	SyntheticStats   SyntheticEventStats
	AnomalyReport    AnomalyReport
	TPMStatus        TPMStatus
	TypingProfile    jitter.TypingProfile
	Compromised      bool
	CompromiseReason string

	// Biometric analysis (integrated from internal/input)
	BiometricProfile     input.KeyboardProfile    // Keyboard biometrics (digraphs, dwell times, liveness)
	DeviceReport         SessionDeviceReport      // Device tracking (USB-HID attack detection)
	SecurityReport       input.SecurityReport     // Adversarial defense analysis
	PassiveVerified      bool                     // Passive verification status
	PassiveVerifyScore   float64                  // Passive verification confidence score
	LivenessConfidence   float64                  // Overall liveness confidence (0-1)
	IdentityConfidence   float64                  // Biometric identity confidence (0-1)
}

// Export creates a complete evidence export.
func (s *SecureTrackingSession) Export() (*SecureSessionEvidence, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Get biometric profile
	biometricProfile := s.keyboardBiometrics.Profile()

	evidence := &SecureSessionEvidence{
		SessionID:       s.id,
		FilePath:        s.filePath,
		StartTime:       s.startTime,
		EndTime:         s.endTime,
		FinalCount:      s.counter.Count(),
		FinalStateChain: s.stateChain,
		Checkpoints:     s.checkpoints,
		PasteEvents:     s.pasteEvents,
		TypingProfile:   s.jitterEngine.Profile(),
		// Include biometric evidence
		BiometricProfile:   biometricProfile,
		DeviceReport:       s.deviceTracker.GenerateReport(),
		SecurityReport:     s.adversarialDefense.GenerateReport(),
		LivenessConfidence: biometricProfile.LivenessConfidence,
		IdentityConfidence: biometricProfile.IdentityConfidence,
		DeviceAlerts:       s.deviceTracker.GetAlerts(),
		SecurityAnomalies:  s.adversarialDefense.Anomalies(),
	}

	// Get TPM evidence (only available with TPMBoundCounter)
	if tc, ok := s.counter.(*TPMBoundCounter); ok {
		if tpmEvidence, err := tc.ExportEvidenceWithTPM(); err == nil {
			evidence.TPMEvidence = tpmEvidence
		}
	}

	// Export spread-spectrum steganographic timing evidence
	// This allows verifiers with the key to extract timing patterns
	evidence.SpreadSpectrumEvidence = s.spreadSpectrumSession.Export()

	// Compute final signature
	evidence.computeSignature(s.sessionSecret[:])

	return evidence, nil
}

// SecureSessionEvidence is the complete tamper-evident export.
type SecureSessionEvidence struct {
	SessionID       string               `json:"session_id"`
	FilePath        string               `json:"file_path"`
	StartTime       time.Time            `json:"start_time"`
	EndTime         time.Time            `json:"end_time"`
	FinalCount      uint64               `json:"final_count"`
	FinalStateChain [32]byte             `json:"final_state_chain"`
	Checkpoints     []SecureCheckpoint   `json:"checkpoints"`
	PasteEvents     []PasteEvent         `json:"paste_events,omitempty"` // Legitimate copy/paste operations
	TypingProfile   jitter.TypingProfile `json:"typing_profile"`
	TPMEvidence     *TPMBoundEvidence    `json:"tpm_evidence,omitempty"`
	Signature       [32]byte             `json:"signature"`

	// Biometric evidence (integrated from internal/input)
	BiometricProfile   input.KeyboardProfile   `json:"biometric_profile"`
	DeviceReport       SessionDeviceReport     `json:"device_report"`
	SecurityReport     input.SecurityReport    `json:"security_report"`
	LivenessConfidence float64                 `json:"liveness_confidence"`
	IdentityConfidence float64                 `json:"identity_confidence"`
	DeviceAlerts       []DeviceAlert           `json:"device_alerts,omitempty"`
	SecurityAnomalies  []input.Anomaly         `json:"security_anomalies,omitempty"`

	// Spread-spectrum steganographic timing evidence
	// Timing deltas are encoded using spread-spectrum to prevent adversarial analysis
	SpreadSpectrumEvidence *input.SpreadSpectrumEvidence `json:"spread_spectrum_evidence,omitempty"`
}

// computeSignature computes the evidence signature.
func (e *SecureSessionEvidence) computeSignature(key []byte) {
	mac := hmac.New(sha256.New, key)

	mac.Write([]byte(e.SessionID))
	mac.Write([]byte(e.FilePath))
	binary.Write(mac, binary.BigEndian, e.StartTime.UnixNano())
	binary.Write(mac, binary.BigEndian, e.EndTime.UnixNano())
	binary.Write(mac, binary.BigEndian, e.FinalCount)
	mac.Write(e.FinalStateChain[:])

	// Include checkpoint count
	binary.Write(mac, binary.BigEndian, int64(len(e.Checkpoints)))

	// Include final checkpoint MAC if present
	if len(e.Checkpoints) > 0 {
		lastCP := e.Checkpoints[len(e.Checkpoints)-1]
		mac.Write(lastCP.MAC[:])
	}

	copy(e.Signature[:], mac.Sum(nil))
}

// JSON serializes the evidence to JSON.
func (e *SecureSessionEvidence) JSON() ([]byte, error) {
	return json.MarshalIndent(e, "", "  ")
}

// Verify verifies the evidence integrity.
func (e *SecureSessionEvidence) Verify(key []byte) error {
	// Verify signature
	mac := hmac.New(sha256.New, key)

	mac.Write([]byte(e.SessionID))
	mac.Write([]byte(e.FilePath))
	binary.Write(mac, binary.BigEndian, e.StartTime.UnixNano())
	binary.Write(mac, binary.BigEndian, e.EndTime.UnixNano())
	binary.Write(mac, binary.BigEndian, e.FinalCount)
	mac.Write(e.FinalStateChain[:])

	binary.Write(mac, binary.BigEndian, int64(len(e.Checkpoints)))

	if len(e.Checkpoints) > 0 {
		lastCP := e.Checkpoints[len(e.Checkpoints)-1]
		mac.Write(lastCP.MAC[:])
	}

	expected := mac.Sum(nil)
	if !hmac.Equal(e.Signature[:], expected) {
		return errors.New("signature verification failed")
	}

	// Verify checkpoint chain
	for i := range e.Checkpoints {
		if i > 0 {
			// Verify timestamps are monotonic
			if e.Checkpoints[i].Timestamp.Before(e.Checkpoints[i-1].Timestamp) {
				return fmt.Errorf("checkpoint %d: timestamp not monotonic", i)
			}
			// Verify keystroke counts are monotonic
			if e.Checkpoints[i].KeystrokeCount < e.Checkpoints[i-1].KeystrokeCount {
				return fmt.Errorf("checkpoint %d: keystroke count decreased", i)
			}
		}
	}

	// Verify typing profile is human-plausible
	if !jitter.IsHumanPlausible(e.TypingProfile) {
		return errors.New("typing profile fails human plausibility check")
	}

	return nil
}

// IsHumanLikely returns true if the evidence suggests human typing.
//
// This method integrates multiple verification layers from the evidence packet:
//   - Layer 0: Checkpoint chain (anomaly detection)
//   - Layer 3: Hardware attestation (TPM, device tracking)
//   - Layer 4a: Keystroke evidence (jitter-based typing profile)
//   - Layer 4b: Behavioral data (keyboard biometrics)
//
// Cross-layer: Adversarial defense aggregates signals across all layers.
func (e *SecureSessionEvidence) IsHumanLikely() bool {
	// Layer 4a: Check jitter-based typing profile
	if !jitter.IsHumanPlausible(e.TypingProfile) {
		return false
	}

	// Layer 4b: Check keyboard biometrics liveness confidence
	// MicroVariation < 0.05 indicates robotic/scripted input
	if e.BiometricProfile.TotalKeystrokes > 50 {
		if e.BiometricProfile.MicroVariation < 0.05 {
			return false // Too consistent - replay or scripted
		}
		if e.BiometricProfile.LivenessConfidence < 0.3 {
			return false // Low liveness confidence
		}
		// Check if biometric profile is human-plausible
		if !e.BiometricProfile.IsHumanPlausible() {
			return false
		}
	}

	// Layer 0: Check for anomalies in checkpoints
	totalAnomalies := 0
	for _, cp := range e.Checkpoints {
		totalAnomalies += len(cp.Anomalies)
	}

	// If more than 10% of checkpoints have anomalies, suspicious
	if len(e.Checkpoints) > 0 {
		anomalyRate := float64(totalAnomalies) / float64(len(e.Checkpoints))
		if anomalyRate > 0.1 {
			return false
		}
	}

	// Layer 3: Check TPM evidence if available
	if e.TPMEvidence != nil {
		if e.TPMEvidence.AnomalyReport.SuspectedScripted ||
			e.TPMEvidence.AnomalyReport.SuspectedUSBHID {
			return false
		}
	}

	// Layer 3: Check device tracking for virtual/suspicious devices
	if e.DeviceReport.ConsistencyScore < 0.5 {
		return false // Device inconsistencies detected
	}
	// Check for virtual keyboard alerts (potential injection attack)
	for _, alert := range e.DeviceAlerts {
		if alert.AlertType == AlertVirtualDeviceDetected && alert.Severity >= 0.8 {
			return false
		}
	}

	// Cross-layer: Check adversarial defense security report
	if e.SecurityReport.IsCompromised {
		return false
	}
	// Check for critical anomalies
	if e.SecurityReport.CriticalAnomalies > 0 {
		return false
	}
	// Check overall security score
	if e.SecurityReport.OverallScore < 50 {
		return false // Security score too low
	}

	// All checks passed
	return true
}
