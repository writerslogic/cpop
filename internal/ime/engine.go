package ime

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
	"unicode/utf8"

	"witnessd/internal/jitter"
)

// ZoneUnknown indicates the zone should be auto-detected from Char or Code.
const ZoneUnknown = -1

// Key represents a key event from the platform IME.
type Key struct {
	// Code is the platform-specific virtual key code.
	// On macOS: virtual key code (e.g., 0x00 for 'A')
	// On Windows: virtual key code (e.g., VK_A)
	// On Linux: X11 keycode or evdev code
	Code uint16

	// Char is the character that will be produced (if known).
	// May be empty for non-character keys (modifiers, function keys).
	// Used as fallback for zone detection if Code mapping fails.
	Char rune

	// Zone is the keyboard zone (0-7) if already determined by platform.
	// Use ZoneUnknown (-1) if the core should determine it from Code or Char.
	// IMPORTANT: The zero value (0) is a valid zone (left pinky), so always
	// explicitly set this field. Use NewKey() for safe construction.
	Zone int

	// Modifiers indicates which modifier keys are held.
	Modifiers Modifiers

	// Timestamp is when the key event occurred.
	// If zero, the current time will be used.
	Timestamp time.Time

	// zoneSet tracks whether Zone was explicitly set.
	// This avoids ambiguity between Zone=0 (left pinky) and unset.
	zoneSet bool
}

// NewKey creates a Key with auto-detected zone.
func NewKey(char rune) Key {
	return Key{
		Char:    char,
		Zone:    ZoneUnknown,
		zoneSet: true,
	}
}

// NewKeyWithCode creates a Key with explicit keycode and character.
func NewKeyWithCode(code uint16, char rune) Key {
	return Key{
		Code:    code,
		Char:    char,
		Zone:    ZoneUnknown,
		zoneSet: true,
	}
}

// NewKeyWithZone creates a Key with explicit zone.
func NewKeyWithZone(char rune, zone int) Key {
	return Key{
		Char:    char,
		Zone:    zone,
		zoneSet: true,
	}
}

// NewKeyFull creates a Key with all fields specified.
func NewKeyFull(code uint16, char rune, zone int, mods Modifiers, ts time.Time) Key {
	return Key{
		Code:      code,
		Char:      char,
		Zone:      zone,
		Modifiers: mods,
		Timestamp: ts,
		zoneSet:   true,
	}
}

// Modifiers represents modifier key state.
type Modifiers uint8

const (
	ModShift Modifiers = 1 << iota
	ModControl
	ModAlt
	ModMeta // Command on macOS, Windows key on Windows
)

// SessionOptions configures a witnessing session.
type SessionOptions struct {
	// AppID identifies the application (bundle ID, package name, etc.)
	AppID string

	// DocID identifies the document or text field.
	DocID string

	// Context is optional user-provided context.
	Context string
}

// Validate checks that the session options are valid.
func (o SessionOptions) Validate() error {
	if o.AppID == "" {
		return errors.New("AppID is required")
	}
	if o.DocID == "" {
		return errors.New("DocID is required")
	}
	return nil
}

// Session represents an active witnessing session.
type Session struct {
	ID        string
	StartTime time.Time
	AppID     string
	DocID     string
	Context   string

	// Internal state
	jitterEngine *jitter.JitterEngine
	samples      []jitter.JitterSample
	docBuffer    []byte // Current document content for hashing
	secret       [32]byte
}

// Evidence contains the exportable proof of authorship.
type Evidence struct {
	SessionID string    `json:"session_id"`
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
	AppID     string    `json:"app_id"`
	DocID     string    `json:"doc_id"`
	Context   string    `json:"context,omitempty"`
	FinalHash [32]byte  `json:"final_hash"`

	// The jitter chain (proof of typing)
	Samples []jitter.JitterSample `json:"samples"`

	// Typing characteristics
	Profile jitter.TypingProfile `json:"profile"`

	// Statistics
	TotalKeystrokes   uint64  `json:"total_keystrokes"`
	DocumentEvolution int     `json:"document_evolution"` // unique doc hashes
	TypingRateKPM     float64 `json:"typing_rate_kpm"`
}

// ToJSON returns the evidence as a JSON string.
func (e *Evidence) ToJSON() (string, error) {
	data, err := json.Marshal(e)
	if err != nil {
		return "", fmt.Errorf("failed to encode evidence: %w", err)
	}
	return string(data), nil
}

// Storage is the interface for persisting IME evidence.
type Storage interface {
	// SaveEvidence persists the evidence from a completed session.
	SaveEvidence(evidence *Evidence) error
}

// Engine is the core IME integration that tracks typing and builds evidence.
type Engine struct {
	mu      sync.RWMutex
	session *Session
	storage Storage
}

// NewEngine creates a new IME engine.
func NewEngine() *Engine {
	return &Engine{}
}

// NewEngineWithStorage creates an IME engine with persistent storage.
func NewEngineWithStorage(storage Storage) *Engine {
	return &Engine{storage: storage}
}

// SetStorage sets the storage backend for automatic persistence.
func (e *Engine) SetStorage(storage Storage) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.storage = storage
}

// StartSession begins a new witnessing session.
func (e *Engine) StartSession(opts SessionOptions) error {
	// Validate options (allow empty for backwards compatibility, but warn)
	if opts.AppID == "" {
		opts.AppID = "unknown"
	}
	if opts.DocID == "" {
		opts.DocID = "unknown"
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if e.session != nil {
		return errors.New("session already active; call EndSession first")
	}

	// Generate secret for this session
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return fmt.Errorf("failed to generate session secret: %w", err)
	}

	sessionID, err := generateSessionID()
	if err != nil {
		return fmt.Errorf("failed to generate session ID: %w", err)
	}

	e.session = &Session{
		ID:           sessionID,
		StartTime:    time.Now(),
		AppID:        opts.AppID,
		DocID:        opts.DocID,
		Context:      opts.Context,
		jitterEngine: jitter.NewJitterEngine(secret),
		samples:      make([]jitter.JitterSample, 0, 1000),
		docBuffer:    nil,
		secret:       secret,
	}

	return nil
}

// OnKeyDown processes a key press and returns the jitter delay.
// The platform IME should wait this duration before committing the character.
func (e *Engine) OnKeyDown(key Key) (time.Duration, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.session == nil {
		return 0, errors.New("no active session")
	}

	// Determine zone from key
	zone := key.Zone

	// If zone wasn't explicitly set, or is ZoneUnknown, auto-detect
	if !key.zoneSet || zone == ZoneUnknown {
		zone = ZoneUnknown
		// Try to determine from character first, then keycode
		if key.Char != 0 {
			zone = jitter.CharToZone(key.Char)
		}
		if zone < 0 && key.Code != 0 {
			zone = jitter.KeyCodeToZone(key.Code)
		}
	}

	// Compute document hash
	docHash := sha256.Sum256(e.session.docBuffer)

	// Record keystroke in jitter engine
	// We pass a synthetic keycode that maps to our zone
	keyCode := zoneToKeyCode(zone)
	jitterMicros, sample := e.session.jitterEngine.OnKeystroke(keyCode, docHash)

	if sample != nil {
		e.session.samples = append(e.session.samples, *sample)
	}

	// Return the jitter delay
	return time.Duration(jitterMicros) * time.Microsecond, nil
}

// zoneToKeyCode converts a zone to a representative keycode.
// Used to bridge platform-agnostic zones to the keycode-based JitterEngine.
func zoneToKeyCode(zone int) uint16 {
	// Return a keycode that maps to the given zone
	switch zone {
	case 0:
		return 0x0C // Q (left pinky)
	case 1:
		return 0x0D // W (left ring)
	case 2:
		return 0x0E // E (left middle)
	case 3:
		return 0x0F // R (left index)
	case 4:
		return 0x10 // Y (right index)
	case 5:
		return 0x22 // I (right middle)
	case 6:
		return 0x1F // O (right ring)
	case 7:
		return 0x23 // P (right pinky)
	default:
		return 0xFF // Non-zone key
	}
}

// OnTextCommit records that text was committed to the document.
// Called after the platform IME commits characters.
func (e *Engine) OnTextCommit(text string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.session == nil {
		return errors.New("no active session")
	}

	// Append to document buffer
	e.session.docBuffer = append(e.session.docBuffer, text...)

	return nil
}

// OnTextDelete records that text was deleted from the document.
// count is the number of Unicode codepoints (runes) to delete, not bytes.
func (e *Engine) OnTextDelete(count int) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.session == nil {
		return errors.New("no active session")
	}

	if count <= 0 {
		return nil
	}

	// Count runes from the end and find the byte offset
	buf := e.session.docBuffer
	runesRemaining := count
	byteOffset := len(buf)

	for byteOffset > 0 && runesRemaining > 0 {
		_, size := utf8.DecodeLastRune(buf[:byteOffset])
		if size == 0 {
			break
		}
		byteOffset -= size
		runesRemaining--
	}

	e.session.docBuffer = buf[:byteOffset]
	return nil
}

// OnTextDeleteBytes records that bytes were deleted from the document.
// Use this when you know the exact byte count (e.g., from an editor API).
func (e *Engine) OnTextDeleteBytes(byteCount int) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.session == nil {
		return errors.New("no active session")
	}

	if byteCount > len(e.session.docBuffer) {
		byteCount = len(e.session.docBuffer)
	}
	if byteCount > 0 {
		e.session.docBuffer = e.session.docBuffer[:len(e.session.docBuffer)-byteCount]
	}

	return nil
}

// GetSessionInfo returns a copy of the current session info (nil if none active).
// This is safe to use concurrently as it returns a copy, not the internal state.
func (e *Engine) GetSessionInfo() *SessionInfo {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.session == nil {
		return nil
	}

	return &SessionInfo{
		ID:          e.session.ID,
		StartTime:   e.session.StartTime,
		AppID:       e.session.AppID,
		DocID:       e.session.DocID,
		Context:     e.session.Context,
		SampleCount: len(e.session.samples),
		DocLength:   len(e.session.docBuffer),
	}
}

// SessionInfo contains read-only session information.
type SessionInfo struct {
	ID          string
	StartTime   time.Time
	AppID       string
	DocID       string
	Context     string
	SampleCount int
	DocLength   int
}

// GetSampleCount returns the number of samples collected in the current session.
func (e *Engine) GetSampleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.session == nil {
		return 0
	}
	return len(e.session.samples)
}

// GetDocumentHash returns the current document hash.
func (e *Engine) GetDocumentHash() [32]byte {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.session == nil {
		return [32]byte{}
	}
	return sha256.Sum256(e.session.docBuffer)
}

// GetProfile returns the current typing profile.
func (e *Engine) GetProfile() jitter.TypingProfile {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.session == nil {
		return jitter.TypingProfile{}
	}
	return e.session.jitterEngine.Profile()
}

// EndSession finalizes the current session and returns the evidence.
// The returned evidence contains copies of all data and is safe to use
// after the session ends.
func (e *Engine) EndSession() (*Evidence, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.session == nil {
		return nil, errors.New("no active session")
	}

	endTime := time.Now()
	profile := e.session.jitterEngine.Profile()

	// Count unique document hashes
	docHashes := make(map[[32]byte]struct{})
	for _, s := range e.session.samples {
		docHashes[s.DocHash] = struct{}{}
	}

	// Calculate typing rate
	duration := endTime.Sub(e.session.StartTime)
	var kpm float64
	if duration.Minutes() > 0 {
		kpm = float64(len(e.session.samples)) / duration.Minutes()
	}

	// Copy samples to prevent external modification
	samplesCopy := make([]jitter.JitterSample, len(e.session.samples))
	copy(samplesCopy, e.session.samples)

	evidence := &Evidence{
		SessionID:         e.session.ID,
		StartTime:         e.session.StartTime,
		EndTime:           endTime,
		AppID:             e.session.AppID,
		DocID:             e.session.DocID,
		Context:           e.session.Context,
		FinalHash:         sha256.Sum256(e.session.docBuffer),
		Samples:           samplesCopy,
		Profile:           profile,
		TotalKeystrokes:   uint64(len(e.session.samples)),
		DocumentEvolution: len(docHashes),
		TypingRateKPM:     kpm,
	}

	// Persist to storage if configured
	if e.storage != nil {
		if err := e.storage.SaveEvidence(evidence); err != nil {
			// Log but don't fail - evidence is still returned
			// The caller can retry persistence if needed
			_ = err
		}
	}

	// Clear session
	e.session = nil

	return evidence, nil
}

// GetSecret returns the session secret (for cryptographic verification).
// Only call this when you need to provide cryptographic verification.
// The secret should be stored securely and not exposed unnecessarily.
func (e *Engine) GetSecret() ([32]byte, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.session == nil {
		return [32]byte{}, errors.New("no active session")
	}
	return e.session.secret, nil
}

// HasActiveSession returns true if a session is currently active.
func (e *Engine) HasActiveSession() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.session != nil
}

// GetDocumentContent returns a copy of the current document buffer.
// This is useful for verification or debugging.
func (e *Engine) GetDocumentContent() []byte {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.session == nil {
		return nil
	}
	result := make([]byte, len(e.session.docBuffer))
	copy(result, e.session.docBuffer)
	return result
}

// ExportSamples returns a copy of all samples collected so far.
// This can be called during an active session for incremental export.
func (e *Engine) ExportSamples() []jitter.JitterSample {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.session == nil {
		return nil
	}
	result := make([]jitter.JitterSample, len(e.session.samples))
	copy(result, e.session.samples)
	return result
}

// generateSessionID creates a unique session identifier.
func generateSessionID() (string, error) {
	now := time.Now()
	var randBytes [4]byte
	if _, err := rand.Read(randBytes[:]); err != nil {
		return "", err
	}
	return now.Format("20060102-150405") + "-" + bytesToHex(randBytes[:]), nil
}

func bytesToHex(b []byte) string {
	const hex = "0123456789abcdef"
	result := make([]byte, len(b)*2)
	for i, v := range b {
		result[i*2] = hex[v>>4]
		result[i*2+1] = hex[v&0x0f]
	}
	return string(result)
}
