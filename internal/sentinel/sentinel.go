// Package sentinel provides automatic document tracking for witnessd.
//
// The Active Document Sentinel monitors which documents have user focus and
// manages tracking sessions automatically. It operates invisibly during
// normal writing, only surfacing when the user explicitly requests status.
//
// Key features:
//   - Automatic detection of focused documents across applications
//   - Debounced focus change handling (500ms default)
//   - Multi-document session management
//   - Shadow buffers for unsaved documents
//   - Platform-specific focus detection (macOS, Linux, Windows)
//
// Patent Pending: USPTO Application No. 19/460,364
package sentinel

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"witnessd/internal/wal"
)

// Sentinel monitors active documents and manages tracking sessions.
type Sentinel struct {
	mu sync.RWMutex

	// Configuration
	config *Config

	// Focus detection (platform-specific)
	focusMonitor FocusMonitor

	// Active sessions by document path
	sessions map[string]*DocumentSession

	// Shadow buffer manager
	shadow *ShadowManager

	// Event channels
	focusEvents   chan FocusEvent
	changeEvents  chan ChangeEvent
	sessionEvents chan SessionEvent

	// Subscribers for session events
	subscribers []chan<- SessionEvent

	// State
	ctx           context.Context
	cancel        context.CancelFunc
	running       bool
	currentFocus  string
	focusDebounce *time.Timer

	// HMAC key for WAL integrity
	hmacKey []byte

	// Callbacks for hash operations (injected by caller)
	hashCallback  func(path string) (hash string, size int64, err error)
	saveCallback  func(session *DocumentSession) error
	closeCallback func(session *DocumentSession) error
}

// DocumentSession tracks a single document's editing session.
type DocumentSession struct {
	// Document identity
	Path      string    `json:"path"`
	SessionID string    `json:"session_id"`
	ShadowID  string    `json:"shadow_id,omitempty"`
	StartTime time.Time `json:"start_time"`

	// Session state
	LastFocusTime time.Time `json:"last_focus_time"`
	TotalFocusMS  int64     `json:"total_focus_ms"`
	FocusCount    int       `json:"focus_count"`

	// Content tracking
	InitialHash string `json:"initial_hash"`
	CurrentHash string `json:"current_hash"`
	SaveCount   int    `json:"save_count"`
	ChangeCount int    `json:"change_count"`

	// Application context
	AppBundleID string `json:"app_bundle_id"`
	AppName     string `json:"app_name"`
	WindowTitle string `json:"window_title"`

	// Internal state
	hasFocus     bool
	focusStarted time.Time
	shadowPath   string
	mu           sync.Mutex
	wal          *wal.WAL
}

// FocusEvent represents a document focus change.
type FocusEvent struct {
	Type        FocusEventType
	Path        string
	ShadowID    string
	AppBundleID string
	AppName     string
	WindowTitle string
	Timestamp   time.Time
}

// FocusEventType distinguishes focus event types.
type FocusEventType int

const (
	// FocusGained indicates a document gained focus.
	FocusGained FocusEventType = iota
	// FocusLost indicates a document lost focus.
	FocusLost
	// FocusUnknown indicates focus moved to an unknown/non-trackable window.
	FocusUnknown
)

// ChangeEvent represents a document content change.
type ChangeEvent struct {
	Type      ChangeEventType
	Path      string
	Hash      string
	Size      int64
	Timestamp time.Time
}

// ChangeEventType distinguishes change event types.
type ChangeEventType int

const (
	// ChangeModified indicates the document was modified.
	ChangeModified ChangeEventType = iota
	// ChangeSaved indicates the document was saved.
	ChangeSaved
	// ChangeCreated indicates a new document was created.
	ChangeCreated
	// ChangeDeleted indicates the document was deleted.
	ChangeDeleted
)

// SessionEvent is emitted when session state changes.
type SessionEvent struct {
	Type      SessionEventType
	Session   *DocumentSession
	Timestamp time.Time
}

// SessionEventType distinguishes session event types.
type SessionEventType int

const (
	// SessionStarted indicates a new tracking session began.
	SessionStarted SessionEventType = iota
	// SessionFocused indicates a session gained focus.
	SessionFocused
	// SessionUnfocused indicates a session lost focus.
	SessionUnfocused
	// SessionSaved indicates the document was saved.
	SessionSaved
	// SessionEnded indicates the session ended.
	SessionEnded
)

// FocusMonitor is implemented by platform-specific focus detection.
type FocusMonitor interface {
	// Start begins monitoring for focus changes.
	Start(ctx context.Context) error

	// Stop stops monitoring.
	Stop() error

	// FocusEvents returns a channel of focus events.
	FocusEvents() <-chan FocusEvent

	// ChangeEvents returns a channel of file change events.
	ChangeEvents() <-chan ChangeEvent

	// Available returns whether focus monitoring is available.
	Available() (bool, string)
}

var (
	// ErrNotAvailable is returned when the sentinel cannot operate.
	ErrNotAvailable = errors.New("sentinel: not available on this platform")

	// ErrAlreadyRunning is returned when Start is called while running.
	ErrAlreadyRunning = errors.New("sentinel: already running")

	// ErrNotRunning is returned for operations requiring a running sentinel.
	ErrNotRunning = errors.New("sentinel: not running")

	// ErrSessionNotFound is returned when a session doesn't exist.
	ErrSessionNotFound = errors.New("sentinel: session not found")
)

// New creates a new Sentinel with the given configuration.
func New(cfg *Config) (*Sentinel, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	s := &Sentinel{
		config:        cfg,
		sessions:      make(map[string]*DocumentSession),
		focusEvents:   make(chan FocusEvent, 100),
		changeEvents:  make(chan ChangeEvent, 100),
		sessionEvents: make(chan SessionEvent, 100),
		subscribers:   make([]chan<- SessionEvent, 0),
		hmacKey:       make([]byte, 32), // Default empty key
	}

	// Create shadow manager
	shadow, err := NewShadowManager(cfg.ShadowDir)
	if err != nil {
		return nil, err
	}
	s.shadow = shadow

	// Create platform-specific focus monitor
	s.focusMonitor = newFocusMonitor(cfg)

	// Default hash callback
	s.hashCallback = defaultHashFile

	return s, nil
}

// SetHMACKey sets the HMAC key used for WAL integrity.
func (s *Sentinel) SetHMACKey(key []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hmacKey = make([]byte, len(key))
	copy(s.hmacKey, key)
}

// Start begins monitoring for document focus.
func (s *Sentinel) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return ErrAlreadyRunning
	}

	s.ctx, s.cancel = context.WithCancel(ctx)

	// Start focus monitor
	if err := s.focusMonitor.Start(s.ctx); err != nil {
		return err
	}

	s.running = true

	// Start event processing loops
	go s.processFocusEvents()
	go s.processChangeEvents()

	return nil
}

// Stop stops monitoring and closes all sessions.
func (s *Sentinel) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	s.running = false

	if s.cancel != nil {
		s.cancel()
	}

	if s.focusDebounce != nil {
		s.focusDebounce.Stop()
	}

	// Stop focus monitor
	if err := s.focusMonitor.Stop(); err != nil {
		// Log but don't fail
	}

	// End all active sessions
	for path, session := range s.sessions {
		s.endSessionLocked(path, session)
	}

	// Clean up shadow buffers
	if s.shadow != nil {
		s.shadow.CleanupAll()
	}

	// Close subscriber channels
	for _, ch := range s.subscribers {
		close(ch)
	}
	s.subscribers = nil

	return nil
}

// processFocusEvents handles focus change events with debouncing.
func (s *Sentinel) processFocusEvents() {
	for {
		select {
		case <-s.ctx.Done():
			return

		case event := <-s.focusMonitor.FocusEvents():
			s.handleFocusEvent(event)
		}
	}
}

// processChangeEvents handles file change events.
func (s *Sentinel) processChangeEvents() {
	for {
		select {
		case <-s.ctx.Done():
			return

		case event := <-s.focusMonitor.ChangeEvents():
			s.handleChangeEvent(event)
		}
	}
}

// handleFocusEvent processes a focus change with debouncing.
func (s *Sentinel) handleFocusEvent(event FocusEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Cancel any pending focus change
	if s.focusDebounce != nil {
		s.focusDebounce.Stop()
	}

	// Debounce rapid focus changes
	s.focusDebounce = time.AfterFunc(s.config.DebounceDuration, func() {
		s.applyFocusChange(event)
	})
}

// applyFocusChange applies a focus change after debouncing.
func (s *Sentinel) applyFocusChange(event FocusEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if app is in allowlist/blocklist
	if !s.shouldTrackApp(event.AppBundleID, event.AppName) {
		// Unfocus current document if moving to untracked app
		if s.currentFocus != "" {
			s.unfocusDocument(s.currentFocus)
			s.currentFocus = ""
		}
		return
	}

	// Determine document path
	docPath := event.Path
	if docPath == "" && event.ShadowID != "" {
		// Unsaved document - use shadow
		docPath = s.shadow.GetPath(event.ShadowID)
	}

	if docPath == "" {
		// No identifiable document
		if s.currentFocus != "" {
			s.unfocusDocument(s.currentFocus)
			s.currentFocus = ""
		}
		return
	}

	// Skip if focus didn't actually change
	if docPath == s.currentFocus {
		return
	}

	// Unfocus previous document
	if s.currentFocus != "" {
		s.unfocusDocument(s.currentFocus)
	}

	// Focus new document
	s.focusDocument(docPath, event)
	s.currentFocus = docPath
}

// focusDocument handles a document gaining focus.
func (s *Sentinel) focusDocument(path string, event FocusEvent) {
	session, exists := s.sessions[path]
	if !exists {
		// Create new session
		session = s.createSession(path, event)
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	session.hasFocus = true
	session.focusStarted = time.Now()
	session.LastFocusTime = session.focusStarted
	session.FocusCount++
	session.WindowTitle = event.WindowTitle

	s.emitSessionEvent(SessionFocused, session)
}

// unfocusDocument handles a document losing focus.
func (s *Sentinel) unfocusDocument(path string) {
	session, exists := s.sessions[path]
	if !exists {
		return
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	if session.hasFocus {
		// Calculate focus duration
		focusDuration := time.Since(session.focusStarted)
		session.TotalFocusMS += focusDuration.Milliseconds()
		session.hasFocus = false
	}

	s.emitSessionEvent(SessionUnfocused, session)

	// Check if session should be closed (idle timeout)
	if s.config.IdleTimeout > 0 {
		go s.scheduleSessionTimeout(path)
	}
}

// createSession creates a new document session.
func (s *Sentinel) createSession(path string, event FocusEvent) *DocumentSession {
	now := time.Now()

	// Generate a unique session ID
	var sessionID [16]byte
	rand.Read(sessionID[:])
	sessionIDStr := hex.EncodeToString(sessionID[:])

	session := &DocumentSession{
		Path:          path,
		SessionID:     sessionIDStr,
		StartTime:     now,
		LastFocusTime: now,
		AppBundleID:   event.AppBundleID,
		AppName:       event.AppName,
		WindowTitle:   event.WindowTitle,
	}

	// Get initial hash if file exists
	var docHash [32]byte
	if hash, _, err := s.hashCallback(path); err == nil {
		session.InitialHash = hash
		session.CurrentHash = hash
		h, _ := hex.DecodeString(hash)
		copy(docHash[:], h)
	}

	// Handle shadow for unsaved documents
	if event.ShadowID != "" {
		session.ShadowID = event.ShadowID
		session.shadowPath = s.shadow.GetPath(event.ShadowID)
		// Use shadow ID as session ID for unsaved documents
		session.SessionID = event.ShadowID
	}

	// Open WAL if enabled
	if s.config.WALDir != "" {
		walPath := filepath.Join(s.config.WALDir, session.SessionID+".wal")
		var sessionID32 [32]byte
		copy(sessionID32[:], session.SessionID)

		w, err := wal.Open(walPath, sessionID32, s.hmacKey)
		if err == nil {
			session.wal = w

			// Write session start entry
			payload := &wal.SessionStartPayload{
				DocumentPath: path,
				DocumentHash: docHash,
				StartTime:    now.UnixNano(),
			}
			copy(payload.SessionID[:], sessionID32[:])
			session.wal.Append(wal.EntrySessionStart, payload.Serialize())
		}
	}

	s.sessions[path] = session
	s.emitSessionEvent(SessionStarted, session)

	return session
}

// handleChangeEvent processes a file change event.
func (s *Sentinel) handleChangeEvent(event ChangeEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, exists := s.sessions[event.Path]
	if !exists {
		return
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	switch event.Type {
	case ChangeSaved:
		session.SaveCount++

		// If hash is missing (e.g. from Cmd+S trigger), re-hash the file
		currentHash := event.Hash
		if currentHash == "" {
			if hash, _, err := s.hashCallback(event.Path); err == nil {
				currentHash = hash
			}
		}

		session.CurrentHash = currentHash

		// Write to WAL
		if session.wal != nil {
			var h [32]byte
			hashBytes, _ := hex.DecodeString(currentHash)
			copy(h[:], hashBytes)

			payload := &wal.DocumentHashPayload{
				Hash:    h,
				Size:    uint64(event.Size),
				ModTime: event.Timestamp.UnixNano(),
			}
			session.wal.Append(wal.EntryDocumentHash, payload.Serialize())
		}

		s.emitSessionEvent(SessionSaved, session)

		// Migrate shadow buffer if this was an unsaved document
		if session.ShadowID != "" {
			s.shadow.Migrate(session.ShadowID, event.Path)
			session.ShadowID = ""
			session.shadowPath = ""
		}

		// Call save callback if registered
		if s.saveCallback != nil {
			go s.saveCallback(session)
		}

	case ChangeModified:
		session.ChangeCount++
		session.CurrentHash = event.Hash

		// Write to WAL
		if session.wal != nil {
			var h [32]byte
			hashBytes, _ := hex.DecodeString(event.Hash)
			copy(h[:], hashBytes)

			payload := &wal.DocumentHashPayload{
				Hash:    h,
				Size:    uint64(event.Size),
				ModTime: event.Timestamp.UnixNano(),
			}
			session.wal.Append(wal.EntryDocumentHash, payload.Serialize())
		}

	case ChangeDeleted:
		s.endSessionLocked(event.Path, session)
	}
}

// endSessionLocked ends a session (caller must hold lock).
func (s *Sentinel) endSessionLocked(path string, session *DocumentSession) {
	session.mu.Lock()
	defer session.mu.Unlock()

	// Calculate final focus duration if currently focused
	if session.hasFocus {
		focusDuration := time.Since(session.focusStarted)
		session.TotalFocusMS += focusDuration.Milliseconds()
		session.hasFocus = false
	}

	// Write session end to WAL
	if session.wal != nil {
		var sessionID32 [32]byte
		copy(sessionID32[:], session.SessionID)

		payload := &wal.SessionEndPayload{
			EndTime: time.Now().UnixNano(),
			Clean:   true,
		}
		copy(payload.SessionID[:], sessionID32[:])
		session.wal.Append(wal.EntrySessionEnd, payload.Serialize())
		session.wal.Close()
	}

	// Call close callback if registered
	if s.closeCallback != nil {
		go s.closeCallback(session)
	}

	s.emitSessionEvent(SessionEnded, session)

	// Clean up shadow if exists
	if session.ShadowID != "" {
		s.shadow.Delete(session.ShadowID)
	}

	delete(s.sessions, path)
}

// scheduleSessionTimeout schedules a session close after idle timeout.
func (s *Sentinel) scheduleSessionTimeout(path string) {
	select {
	case <-s.ctx.Done():
		return
	case <-time.After(s.config.IdleTimeout):
		s.mu.Lock()
		defer s.mu.Unlock()

		session, exists := s.sessions[path]
		if !exists {
			return
		}

		session.mu.Lock()
		idle := !session.hasFocus && time.Since(session.LastFocusTime) > s.config.IdleTimeout
		session.mu.Unlock()

		if idle {
			s.endSessionLocked(path, session)
		}
	}
}

// shouldTrackApp checks if an app should be tracked.
func (s *Sentinel) shouldTrackApp(bundleID, appName string) bool {
	// Check blocklist first
	for _, blocked := range s.config.BlockedApps {
		if blocked == bundleID || blocked == appName {
			return false
		}
	}

	// If allowlist is empty, track all non-blocked apps (if enabled)
	if len(s.config.AllowedApps) == 0 {
		return s.config.TrackUnknownApps
	}

	// Check allowlist
	for _, allowed := range s.config.AllowedApps {
		if allowed == bundleID || allowed == appName {
			return true
		}
	}

	return s.config.TrackUnknownApps
}

// emitSessionEvent sends a session event to subscribers.
func (s *Sentinel) emitSessionEvent(eventType SessionEventType, session *DocumentSession) {
	event := SessionEvent{
		Type:      eventType,
		Session:   session,
		Timestamp: time.Now(),
	}

	// Non-blocking send to internal channel
	select {
	case s.sessionEvents <- event:
	default:
	}

	// Notify subscribers
	for _, ch := range s.subscribers {
		select {
		case ch <- event:
		default:
			// Skip slow subscribers
		}
	}
}

// Subscribe returns a channel for session events.
func (s *Sentinel) Subscribe() <-chan SessionEvent {
	s.mu.Lock()
	defer s.mu.Unlock()

	ch := make(chan SessionEvent, 100)
	s.subscribers = append(s.subscribers, ch)
	return ch
}

// Sessions returns a snapshot of all active sessions.
func (s *Sentinel) Sessions() []*DocumentSession {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sessions := make([]*DocumentSession, 0, len(s.sessions))
	for _, session := range s.sessions {
		sessions = append(sessions, session)
	}
	return sessions
}

// Session returns a specific session by path.
func (s *Sentinel) Session(path string) (*DocumentSession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	session, exists := s.sessions[path]
	if !exists {
		return nil, ErrSessionNotFound
	}
	return session, nil
}

// CurrentFocus returns the currently focused document path.
func (s *Sentinel) CurrentFocus() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.currentFocus
}

// SetHashCallback sets the function used to hash files.
func (s *Sentinel) SetHashCallback(fn func(path string) (hash string, size int64, err error)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hashCallback = fn
}

// SetSaveCallback sets the function called when documents are saved.
func (s *Sentinel) SetSaveCallback(fn func(session *DocumentSession) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saveCallback = fn
}

// SetCloseCallback sets the function called when sessions end.
func (s *Sentinel) SetCloseCallback(fn func(session *DocumentSession) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeCallback = fn
}

// Available returns whether the sentinel can operate on this platform.
func (s *Sentinel) Available() (bool, string) {
	return s.focusMonitor.Available()
}

// Running returns whether the sentinel is currently monitoring.
func (s *Sentinel) Running() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

// UpdateShadowContent updates the content of a shadow buffer.
// Used for tracking unsaved document content.
func (s *Sentinel) UpdateShadowContent(shadowID string, content []byte) error {
	return s.shadow.Update(shadowID, content)
}

// CreateShadow creates a new shadow buffer for an unsaved document.
func (s *Sentinel) CreateShadow(appName, windowTitle string) (string, error) {
	return s.shadow.Create(appName, windowTitle)
}

// defaultHashFile computes SHA-256 hash of a file.
func defaultHashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()

	h := sha256.New()
	size, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}

	return hex.EncodeToString(h.Sum(nil)), size, nil
}

// DocumentPath normalizes a document path for consistent session keys.
func DocumentPath(path string) string {
	// Clean and resolve to absolute path
	abs, err := filepath.Abs(path)
	if err != nil {
		return filepath.Clean(path)
	}

	// Resolve symlinks
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return abs
	}

	return resolved
}
