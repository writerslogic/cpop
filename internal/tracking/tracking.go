// Package tracking manages keyboard tracking sessions.
//
// This package ties together:
// - Secure keystroke counting with HMAC integrity protection
// - TPM-backed hardware security when available
// - Timing anomaly detection for script/USB-HID attacks
// - Jitter computation and injection
// - Document hash sampling
// - Session persistence
//
// A tracking session runs in the background while the user writes,
// building tamper-evident evidence of real typing activity without capturing content.
package tracking

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"witnessd/internal/jitter"
	"witnessd/internal/keystroke"
)

// Session manages a keyboard tracking session with maximum security.
// This uses the hardened SecureTrackingSession which provides:
// - Dual-layer keystroke validation (CGEventTap + IOKit HID)
// - HMAC integrity protection on all state
// - Timing anomaly detection for script/USB-HID attacks
// - Optional TPM binding for hardware-backed security
type Session struct {
	mu sync.RWMutex

	// Session identity
	ID        string    `json:"id"`
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at,omitempty"`

	// Document being tracked
	DocumentPath string `json:"document_path"`

	// Secure tracking session (hardened CGEventTap + TPM)
	secureSession *keystroke.SecureTrackingSession

	// Legacy jitter session (for compatibility)
	jitterSession *jitter.Session

	// Control
	ctx    context.Context
	cancel context.CancelFunc

	// Status
	running bool
	error   error

	// Configuration
	config Config
}

// Config configures a tracking session.
type Config struct {
	// Document to track
	DocumentPath string

	// Jitter parameters
	JitterParams jitter.Parameters

	// Whether to inject jitter delays
	InjectJitter bool

	// Use simulated keystroke counter (for testing)
	Simulated bool

	// StrictMode rejects any suspicious events (recommended)
	StrictMode bool

	// UseTPM enables TPM binding for hardware-backed security
	UseTPM bool
}

// DefaultConfig returns sensible defaults with maximum security.
func DefaultConfig(documentPath string) Config {
	return Config{
		DocumentPath: documentPath,
		JitterParams: jitter.DefaultParameters(),
		InjectJitter: true,
		Simulated:    false,
		StrictMode:   true,
		UseTPM:       true,
	}
}

// NewSession creates a new secure tracking session.
func NewSession(cfg Config) (*Session, error) {
	// Create secure session config
	secureConfig := keystroke.SecureSessionConfig{
		FilePath:             cfg.DocumentPath,
		JitterSampleInterval: uint64(cfg.JitterParams.SampleInterval),
		CheckpointInterval:   time.Minute,
		TPMConfig:            keystroke.DefaultTPMBindingConfig(),
		StrictMode:           cfg.StrictMode,
		Simulated:            cfg.Simulated,
	}

	// Disable TPM if requested
	if !cfg.UseTPM {
		secureConfig.TPMConfig.UseTPMCounter = false
		secureConfig.TPMConfig.UseTPMAttestation = false
		secureConfig.TPMConfig.SealIntegrityKey = false
	}

	// Create secure tracking session
	secureSession, err := keystroke.NewSecureTrackingSession(secureConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create secure session: %w", err)
	}

	// Get session ID from secure session
	sessionID := secureSession.Status().ID

	// Create jitter session with the same ID for consistency
	jitterSess, err := jitter.NewSessionWithID(cfg.DocumentPath, cfg.JitterParams, sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to create jitter session: %w", err)
	}

	return &Session{
		ID:            sessionID,
		StartedAt:     time.Now(),
		DocumentPath:  cfg.DocumentPath,
		secureSession: secureSession,
		jitterSession: jitterSess,
		config:        cfg,
	}, nil
}

// Start begins the secure tracking session.
func (s *Session) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("session already running")
	}

	s.ctx, s.cancel = context.WithCancel(context.Background())

	// Start secure tracking session
	if err := s.secureSession.Start(s.ctx); err != nil {
		return fmt.Errorf("failed to start secure tracking: %w", err)
	}

	s.running = true
	return nil
}

// Stop ends the tracking session.
func (s *Session) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	// Signal shutdown
	if s.cancel != nil {
		s.cancel()
	}

	// Stop secure session
	if err := s.secureSession.Stop(); err != nil {
		s.error = err
	}

	// End jitter session
	s.jitterSession.End()

	s.EndedAt = time.Now()
	s.running = false

	return s.error
}

// Status returns the current session status.
type Status struct {
	ID               string        `json:"id"`
	Running          bool          `json:"running"`
	StartedAt        time.Time     `json:"started_at"`
	EndedAt          time.Time     `json:"ended_at,omitempty"`
	Duration         time.Duration `json:"duration"`
	DocumentPath     string        `json:"document_path"`
	KeystrokeCount   uint64        `json:"keystroke_count"`
	SampleCount      int           `json:"sample_count"`
	KeystrokesPerMin float64       `json:"keystrokes_per_minute"`
	Error            string        `json:"error,omitempty"`

	// Security stats (from hardened counter)
	Checkpoints        int     `json:"checkpoints"`
	PasteEvents        int     `json:"paste_events"`        // Detected copy/paste (legitimate)
	AnomalyPercentage  float64 `json:"anomaly_percentage"`
	SuspectedScripted  bool    `json:"suspected_scripted"`
	SuspectedUSBHID    bool    `json:"suspected_usb_hid"`
	TPMAvailable       bool    `json:"tpm_available"`
	Compromised        bool    `json:"compromised"`
	CompromiseReason   string  `json:"compromise_reason,omitempty"`
	SyntheticRejected  uint64  `json:"synthetic_rejected"`
	ValidationMismatch uint64  `json:"validation_mismatch"`
}

// Status returns the current session status with security information.
func (s *Session) Status() Status {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Get status from secure session
	secureStatus := s.secureSession.Status()

	status := Status{
		ID:               s.ID,
		Running:          s.running,
		StartedAt:        s.StartedAt,
		EndedAt:          s.EndedAt,
		DocumentPath:     s.DocumentPath,
		KeystrokeCount:   secureStatus.KeystrokeCount,
		SampleCount:      s.jitterSession.SampleCount(),
		Checkpoints:      secureStatus.Checkpoints,
		PasteEvents:      secureStatus.PasteEvents,
		TPMAvailable:     secureStatus.TPMStatus.Available,
		Compromised:      secureStatus.Compromised,
		CompromiseReason: secureStatus.CompromiseReason,
	}

	// Get anomaly report
	status.AnomalyPercentage = secureStatus.AnomalyReport.AnomalyPercentage
	status.SuspectedScripted = secureStatus.AnomalyReport.SuspectedScripted
	status.SuspectedUSBHID = secureStatus.AnomalyReport.SuspectedUSBHID

	// Get synthetic event stats
	status.SyntheticRejected = uint64(secureStatus.SyntheticStats.TotalRejected)
	status.ValidationMismatch = uint64(secureStatus.ValidationStats.Discrepancy)

	// Compute duration
	end := s.EndedAt
	if end.IsZero() {
		end = time.Now()
	}
	status.Duration = end.Sub(s.StartedAt)

	// Compute rate
	if status.Duration > 0 {
		minutes := status.Duration.Minutes()
		if minutes > 0 {
			status.KeystrokesPerMin = float64(status.KeystrokeCount) / minutes
		}
	}

	if s.error != nil {
		status.Error = s.error.Error()
	}

	return status
}

// Export returns jitter evidence from this session (legacy format).
func (s *Session) Export() jitter.Evidence {
	return s.jitterSession.Export()
}

// ExportSecure returns the secure session evidence with full tamper-evident chain.
func (s *Session) ExportSecure() (*keystroke.SecureSessionEvidence, error) {
	return s.secureSession.Export()
}

// SecureStatus returns the full secure session status.
func (s *Session) SecureStatus() keystroke.SessionStatus {
	return s.secureSession.Status()
}

// Save persists the session to disk.
func (s *Session) Save(witnessdDir string) error {
	trackingDir := filepath.Join(witnessdDir, "tracking")
	if err := os.MkdirAll(trackingDir, 0700); err != nil {
		return err
	}

	// Save legacy jitter session for compatibility
	jitterPath := filepath.Join(trackingDir, s.ID+".json")
	if err := s.jitterSession.Save(jitterPath); err != nil {
		return fmt.Errorf("failed to save jitter session: %w", err)
	}

	// Save secure evidence
	secureEvidence, err := s.secureSession.Export()
	if err != nil {
		return fmt.Errorf("failed to export secure evidence: %w", err)
	}

	secureData, err := secureEvidence.JSON()
	if err != nil {
		return fmt.Errorf("failed to serialize secure evidence: %w", err)
	}

	securePath := filepath.Join(trackingDir, s.ID+".secure.json")
	if err := os.WriteFile(securePath, secureData, 0600); err != nil {
		return fmt.Errorf("failed to save secure evidence: %w", err)
	}

	return nil
}

// Load reads a session from disk.
func Load(witnessdDir, sessionID string) (*Session, error) {
	trackingDir := filepath.Join(witnessdDir, "tracking")

	// Load jitter session
	jitterPath := filepath.Join(trackingDir, sessionID+".json")
	jitterSess, err := jitter.LoadSession(jitterPath)
	if err != nil {
		return nil, err
	}

	// Use the requested session ID (not the jitter session's internal ID)
	// The file is saved under the session ID, so we restore that
	return &Session{
		ID:            sessionID,
		StartedAt:     jitterSess.StartedAt,
		EndedAt:       jitterSess.EndedAt,
		DocumentPath:  jitterSess.DocumentPath,
		jitterSession: jitterSess,
	}, nil
}

// LoadSecureEvidence loads the secure evidence for a session.
func LoadSecureEvidence(witnessdDir, sessionID string) (*keystroke.SecureSessionEvidence, error) {
	securePath := filepath.Join(witnessdDir, "tracking", sessionID+".secure.json")
	data, err := os.ReadFile(securePath)
	if err != nil {
		return nil, err
	}

	var evidence keystroke.SecureSessionEvidence
	if err := json.Unmarshal(data, &evidence); err != nil {
		return nil, err
	}

	return &evidence, nil
}

// Manager manages multiple tracking sessions.
type Manager struct {
	mu          sync.RWMutex
	sessions    map[string]*Session
	witnessdDir string
}

// NewManager creates a session manager.
func NewManager(witnessdDir string) *Manager {
	return &Manager{
		sessions:    make(map[string]*Session),
		witnessdDir: witnessdDir,
	}
}

// StartSession starts tracking a document.
func (m *Manager) StartSession(documentPath string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if already tracking this document
	absPath, err := filepath.Abs(documentPath)
	if err != nil {
		return nil, err
	}

	for _, sess := range m.sessions {
		if sess.DocumentPath == absPath && sess.running {
			return nil, fmt.Errorf("already tracking %s", documentPath)
		}
	}

	cfg := DefaultConfig(absPath)
	sess, err := NewSession(cfg)
	if err != nil {
		return nil, err
	}

	if err := sess.Start(); err != nil {
		return nil, err
	}

	m.sessions[sess.ID] = sess
	return sess, nil
}

// StopSession stops a tracking session.
func (m *Manager) StopSession(sessionID string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	sess, ok := m.sessions[sessionID]
	if !ok {
		return nil, fmt.Errorf("session not found: %s", sessionID)
	}

	if err := sess.Stop(); err != nil {
		return sess, err
	}

	// Save session
	if err := sess.Save(m.witnessdDir); err != nil {
		return sess, fmt.Errorf("failed to save session: %w", err)
	}

	return sess, nil
}

// GetSession returns a session by ID.
func (m *Manager) GetSession(sessionID string) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	sess, ok := m.sessions[sessionID]
	return sess, ok
}

// ActiveSessions returns all active sessions.
func (m *Manager) ActiveSessions() []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var active []*Session
	for _, sess := range m.sessions {
		if sess.running {
			active = append(active, sess)
		}
	}
	return active
}

// StopAll stops all active sessions.
func (m *Manager) StopAll() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var lastErr error
	for _, sess := range m.sessions {
		if sess.running {
			if err := sess.Stop(); err != nil {
				lastErr = err
			}
			if err := sess.Save(m.witnessdDir); err != nil {
				lastErr = err
			}
		}
	}
	return lastErr
}

// ListSavedSessions lists sessions saved to disk.
func (m *Manager) ListSavedSessions() ([]string, error) {
	dir := filepath.Join(m.witnessdDir, "tracking")
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil, nil
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var ids []string
	for _, entry := range entries {
		name := entry.Name()
		// Only count main session files (.json), not secure evidence (.secure.json)
		if !entry.IsDir() && filepath.Ext(name) == ".json" && !strings.HasSuffix(name, ".secure.json") {
			id := name[:len(name)-5] // Remove .json
			ids = append(ids, id)
		}
	}
	return ids, nil
}

// LoadEvidence loads jitter evidence from a saved session.
func (m *Manager) LoadEvidence(sessionID string) (*jitter.Evidence, error) {
	path := filepath.Join(m.witnessdDir, "tracking", sessionID+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Load the session data
	sess, err := jitter.LoadSession(path)
	if err != nil {
		// Try loading as evidence directly
		var ev jitter.Evidence
		if err := json.Unmarshal(data, &ev); err != nil {
			return nil, err
		}
		return &ev, nil
	}

	ev := sess.Export()
	return &ev, nil
}

// LoadSecureEvidence loads secure evidence with full tamper-evident chain.
func (m *Manager) LoadSecureEvidence(sessionID string) (*keystroke.SecureSessionEvidence, error) {
	return LoadSecureEvidence(m.witnessdDir, sessionID)
}
