//go:build linux

package ime

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
)

// IBus D-Bus constants
const (
	IBusService           = "org.freedesktop.IBus"
	IBusPath              = "/org/freedesktop/IBus"
	IBusInterface         = "org.freedesktop.IBus"
	IBusFactoryInterface  = "org.freedesktop.IBus.Factory"
	IBusEngineInterface   = "org.freedesktop.IBus.Engine"
	IBusPanelInterface    = "org.freedesktop.IBus.Panel"
	IBusServiceInterface  = "org.freedesktop.IBus.Service"
	WitnessdBusName       = "com.witnessd.IBus"
	WitnessdEngineName    = "witnessd"
	WitnessdEngineVersion = "1.0.0"
)

// IBus key event state masks
const (
	IBusShiftMask   uint32 = 1 << 0
	IBusLockMask    uint32 = 1 << 1
	IBusControlMask uint32 = 1 << 2
	IBusMod1Mask    uint32 = 1 << 3 // Alt
	IBusMod4Mask    uint32 = 1 << 6 // Super/Meta
	IBusReleaseMask uint32 = 1 << 30
)

// Common GDK key symbols
const (
	GDKBackSpace = 0xff08
	GDKDelete    = 0xffff
	GDKReturn    = 0xff0d
	GDKTab       = 0xff09
	GDKEscape    = 0xff1b
	GDKSpace     = 0x0020
)

// IBusEngineImpl is the complete IBus engine implementation.
// It handles D-Bus communication, key event processing, and focus tracking.
type IBusEngineImpl struct {
	conn         *dbus.Conn
	engine       *Engine
	storage      Storage
	ipcClient    *IPCClient
	focusTracker *FocusTracker

	mu           sync.RWMutex
	enabled      bool
	focused      bool
	currentApp   string
	currentDoc   string
	enginePath   dbus.ObjectPath
	engineID     uint32

	// Configuration
	config IBusConfig

	// Keystroke batch for transmission to daemon
	keystrokeBatch []KeystrokeEvent
	batchMu        sync.Mutex
	lastFlush      time.Time

	// Statistics
	stats IBusEngineStats
}

// IBusConfig holds IBus engine configuration.
type IBusConfig struct {
	// SocketPath is the Unix socket path for IPC with witnessd daemon.
	SocketPath string

	// DataDir is where evidence files are stored.
	DataDir string

	// BatchSize is the number of keystrokes to batch before transmission.
	BatchSize int

	// FlushInterval is how often to flush keystrokes even if batch isn't full.
	FlushInterval time.Duration

	// LogPath is where to write log files.
	LogPath string

	// Debug enables verbose logging.
	Debug bool
}

// DefaultIBusConfig returns sensible defaults.
func DefaultIBusConfig() IBusConfig {
	home, _ := os.UserHomeDir()
	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	if runtimeDir == "" {
		runtimeDir = filepath.Join(home, ".witnessd")
	}

	dataDir := os.Getenv("XDG_DATA_HOME")
	if dataDir == "" {
		dataDir = filepath.Join(home, ".local", "share")
	}

	return IBusConfig{
		SocketPath:    filepath.Join(runtimeDir, "witnessd.sock"),
		DataDir:       filepath.Join(dataDir, "witnessd"),
		BatchSize:     50,
		FlushInterval: 5 * time.Second,
		LogPath:       filepath.Join(dataDir, "witnessd", "logs", "ibus.log"),
		Debug:         false,
	}
}

// IBusEngineStats tracks engine statistics.
type IBusEngineStats struct {
	TotalKeystrokes    uint64
	SessionsStarted    uint64
	SessionsEnded      uint64
	FocusChanges       uint64
	IPCMessagesSent    uint64
	IPCMessagesRecv    uint64
	LastKeystrokeTime  time.Time
	LastFocusChange    time.Time
}

// KeystrokeEvent represents a keystroke for IPC transmission.
type KeystrokeEvent struct {
	Timestamp  int64  `json:"ts"`      // Unix nanoseconds
	Keycode    uint16 `json:"kc"`      // Platform keycode
	Keysym     uint32 `json:"ks"`      // X11 keysym
	Modifiers  uint32 `json:"mod"`     // Modifier state
	Char       rune   `json:"char"`    // Character produced
	Zone       int    `json:"zone"`    // Keyboard zone
	IsRelease  bool   `json:"rel"`     // Key release event
	AppID      string `json:"app,omitempty"`
	DocID      string `json:"doc,omitempty"`
}

// NewIBusEngine creates a new IBus engine implementation.
func NewIBusEngine(config IBusConfig) (*IBusEngineImpl, error) {
	engine := NewEngine()

	storage, err := NewEvidenceStorage(filepath.Join(config.DataDir, "evidence"))
	if err != nil {
		return nil, fmt.Errorf("failed to create storage: %w", err)
	}
	engine.SetStorage(storage)

	focusTracker := NewFocusTracker()

	impl := &IBusEngineImpl{
		engine:         engine,
		storage:        storage,
		focusTracker:   focusTracker,
		config:         config,
		keystrokeBatch: make([]KeystrokeEvent, 0, config.BatchSize),
		lastFlush:      time.Now(),
	}

	return impl, nil
}

// Start connects to the session bus and registers the engine.
func (e *IBusEngineImpl) Start(ctx context.Context) error {
	var err error

	// Connect to session bus
	e.conn, err = dbus.SessionBus()
	if err != nil {
		return fmt.Errorf("failed to connect to session bus: %w", err)
	}

	// Try to connect to witnessd daemon
	e.ipcClient, err = NewIPCClient(e.config.SocketPath)
	if err != nil {
		log.Printf("Warning: could not connect to witnessd daemon: %v", err)
		// Continue without IPC - we'll store locally
	}

	// Start focus tracker
	if err := e.focusTracker.Start(ctx); err != nil {
		log.Printf("Warning: focus tracking unavailable: %v", err)
	}

	// Request our bus name
	reply, err := e.conn.RequestName(WitnessdBusName, dbus.NameFlagDoNotQueue)
	if err != nil {
		return fmt.Errorf("failed to request bus name: %w", err)
	}
	if reply != dbus.RequestNameReplyPrimaryOwner {
		return errors.New("bus name already taken")
	}

	// Export the factory
	factory := &IBusFactory{engine: e}
	e.conn.Export(factory, "/org/freedesktop/IBus/Factory", IBusFactoryInterface)

	// Export the engine
	e.enginePath = "/org/freedesktop/IBus/Engine/witnessd"
	e.conn.Export(e, e.enginePath, IBusEngineInterface)

	// Start background tasks
	go e.flushLoop(ctx)
	go e.focusMonitorLoop(ctx)

	log.Println("Witnessd IBus engine started")
	return nil
}

// Stop gracefully shuts down the engine.
func (e *IBusEngineImpl) Stop() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// End any active session
	if e.engine.HasActiveSession() {
		evidence, err := e.engine.EndSession()
		if err != nil {
			log.Printf("Error ending session: %v", err)
		} else if evidence != nil {
			e.stats.SessionsEnded++
			log.Printf("Session ended: %d keystrokes", evidence.TotalKeystrokes)
		}
	}

	// Flush remaining keystrokes
	e.flushKeystrokeBatch()

	// Close IPC connection
	if e.ipcClient != nil {
		e.ipcClient.Close()
	}

	// Stop focus tracker
	e.focusTracker.Stop()

	// Close D-Bus connection
	if e.conn != nil {
		e.conn.Close()
	}

	return nil
}

// ProcessKeyEvent handles key press/release events from IBus.
// Returns true if the key was consumed, false to pass through.
func (e *IBusEngineImpl) ProcessKeyEvent(keyval, keycode, state uint32) (bool, *dbus.Error) {
	isRelease := (state & IBusReleaseMask) != 0

	// Get character from keysym
	char := keyvalToRune(keyval)

	// Determine zone
	zone := e.keycodeToZone(keycode, char)

	// Create keystroke event
	event := KeystrokeEvent{
		Timestamp: time.Now().UnixNano(),
		Keycode:   uint16(keycode),
		Keysym:    keyval,
		Modifiers: state &^ IBusReleaseMask, // Remove release mask
		Char:      char,
		Zone:      zone,
		IsRelease: isRelease,
	}

	e.mu.RLock()
	event.AppID = e.currentApp
	event.DocID = e.currentDoc
	e.mu.RUnlock()

	// Only process key presses, not releases
	if !isRelease {
		e.processKeyPress(keyval, keycode, state, char, zone)
	}

	// Add to batch for IPC transmission
	e.batchKeystroke(event)

	// Always pass through - we're a transparent monitor
	return false, nil
}

// processKeyPress handles the internal engine processing for a key press.
func (e *IBusEngineImpl) processKeyPress(keyval, keycode, state uint32, char rune, zone int) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Start session if needed
	if !e.engine.HasActiveSession() {
		app := e.currentApp
		if app == "" {
			app = "unknown"
		}
		doc := e.currentDoc
		if doc == "" {
			doc = "default"
		}
		if err := e.engine.StartSession(SessionOptions{
			AppID: app,
			DocID: doc,
		}); err != nil {
			log.Printf("Failed to start session: %v", err)
			return
		}
		e.stats.SessionsStarted++
	}

	// Handle special keys
	switch keyval {
	case GDKBackSpace:
		if err := e.engine.OnTextDelete(1); err != nil {
			log.Printf("OnTextDelete error: %v", err)
		}
		return
	case GDKDelete:
		if err := e.engine.OnTextDelete(1); err != nil {
			log.Printf("OnTextDelete error: %v", err)
		}
		return
	case GDKReturn:
		if err := e.engine.OnTextCommit("\n"); err != nil {
			log.Printf("OnTextCommit error: %v", err)
		}
		return
	case GDKTab:
		if err := e.engine.OnTextCommit("\t"); err != nil {
			log.Printf("OnTextCommit error: %v", err)
		}
		return
	}

	// Skip non-character keys
	if char == 0 {
		return
	}

	// Create key with X11 keycode (add 8 for evdev offset)
	key := NewKeyWithCode(uint16(keycode+8), char)

	// Process through jitter engine
	_, err := e.engine.OnKeyDown(key)
	if err != nil {
		log.Printf("OnKeyDown error: %v", err)
		return
	}

	// Record the text commit
	if err := e.engine.OnTextCommit(string(char)); err != nil {
		log.Printf("OnTextCommit error: %v", err)
	}

	e.stats.TotalKeystrokes++
	e.stats.LastKeystrokeTime = time.Now()
}

// keycodeToZone maps an X11 keycode to a keyboard zone.
func (e *IBusEngineImpl) keycodeToZone(keycode uint32, char rune) int {
	// X11/evdev keycodes (offset by 8 from raw scancodes)
	switch keycode {
	// Zone 0: Left pinky - Q(24), A(38), Z(52)
	case 24, 38, 52:
		return 0
	// Zone 1: Left ring - W(25), S(39), X(53)
	case 25, 39, 53:
		return 1
	// Zone 2: Left middle - E(26), D(40), C(54)
	case 26, 40, 54:
		return 2
	// Zone 3: Left index - R(27), T(28), F(41), G(42), V(55), B(56)
	case 27, 28, 41, 42, 55, 56:
		return 3
	// Zone 4: Right index - Y(29), U(30), H(43), J(44), N(57), M(58)
	case 29, 30, 43, 44, 57, 58:
		return 4
	// Zone 5: Right middle - I(31), K(45), comma(59)
	case 31, 45, 59:
		return 5
	// Zone 6: Right ring - O(32), L(46), period(60)
	case 32, 46, 60:
		return 6
	// Zone 7: Right pinky - P(33), semicolon(47), slash(61)
	case 33, 47, 61:
		return 7
	default:
		// Fallback to character-based zone detection
		return zoneFromChar(char)
	}
}

// FocusIn is called when the engine gains input focus.
func (e *IBusEngineImpl) FocusIn() *dbus.Error {
	e.mu.Lock()
	e.focused = true
	e.mu.Unlock()

	log.Println("FocusIn")

	// Update focus info from tracker
	if info, err := e.focusTracker.GetFocusInfo(); err == nil {
		e.mu.Lock()
		e.currentApp = info.AppID
		e.currentDoc = info.WindowTitle
		e.stats.FocusChanges++
		e.stats.LastFocusChange = time.Now()
		e.mu.Unlock()
	}

	return nil
}

// FocusOut is called when the engine loses input focus.
func (e *IBusEngineImpl) FocusOut() *dbus.Error {
	e.mu.Lock()
	e.focused = false
	e.mu.Unlock()

	log.Println("FocusOut")

	// Optionally end session on focus out
	e.mu.Lock()
	if e.engine.HasActiveSession() {
		evidence, err := e.engine.EndSession()
		if err != nil {
			log.Printf("EndSession error: %v", err)
		} else if evidence != nil {
			e.stats.SessionsEnded++
			log.Printf("Session ended: %d keystrokes", evidence.TotalKeystrokes)
		}
	}
	e.mu.Unlock()

	return nil
}

// Enable is called when the engine is enabled.
func (e *IBusEngineImpl) Enable() *dbus.Error {
	e.mu.Lock()
	e.enabled = true
	e.mu.Unlock()

	log.Println("Enable")
	return nil
}

// Disable is called when the engine is disabled.
func (e *IBusEngineImpl) Disable() *dbus.Error {
	e.mu.Lock()
	e.enabled = false
	e.mu.Unlock()

	log.Println("Disable")

	// End session when disabled
	e.mu.Lock()
	if e.engine.HasActiveSession() {
		evidence, err := e.engine.EndSession()
		if err != nil {
			log.Printf("EndSession error: %v", err)
		} else if evidence != nil {
			e.stats.SessionsEnded++
		}
	}
	e.mu.Unlock()

	return nil
}

// Reset resets the engine state.
func (e *IBusEngineImpl) Reset() *dbus.Error {
	log.Println("Reset")
	return nil
}

// SetCapabilities informs about client capabilities.
func (e *IBusEngineImpl) SetCapabilities(caps uint32) *dbus.Error {
	log.Printf("SetCapabilities: %d", caps)
	return nil
}

// SetContentType informs about the type of content being edited.
func (e *IBusEngineImpl) SetContentType(purpose, hints uint32) *dbus.Error {
	log.Printf("SetContentType: purpose=%d hints=%d", purpose, hints)
	return nil
}

// SetCursorLocation informs about cursor position.
func (e *IBusEngineImpl) SetCursorLocation(x, y, w, h int32) *dbus.Error {
	// Could be used for popup positioning
	return nil
}

// SetSurroundingText provides context around the cursor.
func (e *IBusEngineImpl) SetSurroundingText(text string, cursorPos, anchorPos uint32) *dbus.Error {
	// Could use this for more context about the document
	return nil
}

// PropertyActivate handles property activations.
func (e *IBusEngineImpl) PropertyActivate(propName string, state uint32) *dbus.Error {
	log.Printf("PropertyActivate: %s state=%d", propName, state)
	return nil
}

// PageUp handles page up in candidate list.
func (e *IBusEngineImpl) PageUp() *dbus.Error {
	return nil
}

// PageDown handles page down in candidate list.
func (e *IBusEngineImpl) PageDown() *dbus.Error {
	return nil
}

// CursorUp handles cursor up in candidate list.
func (e *IBusEngineImpl) CursorUp() *dbus.Error {
	return nil
}

// CursorDown handles cursor down in candidate list.
func (e *IBusEngineImpl) CursorDown() *dbus.Error {
	return nil
}

// CandidateClicked handles candidate selection.
func (e *IBusEngineImpl) CandidateClicked(index, button, state uint32) *dbus.Error {
	return nil
}

// batchKeystroke adds a keystroke to the batch for IPC transmission.
func (e *IBusEngineImpl) batchKeystroke(event KeystrokeEvent) {
	e.batchMu.Lock()
	defer e.batchMu.Unlock()

	e.keystrokeBatch = append(e.keystrokeBatch, event)

	if len(e.keystrokeBatch) >= e.config.BatchSize {
		e.flushKeystrokeBatch()
	}
}

// flushKeystrokeBatch sends batched keystrokes to the daemon.
func (e *IBusEngineImpl) flushKeystrokeBatch() {
	if len(e.keystrokeBatch) == 0 {
		return
	}

	// Copy batch for transmission
	batch := make([]KeystrokeEvent, len(e.keystrokeBatch))
	copy(batch, e.keystrokeBatch)
	e.keystrokeBatch = e.keystrokeBatch[:0]
	e.lastFlush = time.Now()

	// Send via IPC if connected
	if e.ipcClient != nil && e.ipcClient.IsConnected() {
		msg := IPCMessage{
			Type: "keystrokes",
			Data: batch,
		}
		if err := e.ipcClient.Send(msg); err != nil {
			log.Printf("Failed to send keystrokes: %v", err)
		} else {
			e.stats.IPCMessagesSent++
		}
	}
}

// flushLoop periodically flushes keystroke batches.
func (e *IBusEngineImpl) flushLoop(ctx context.Context) {
	ticker := time.NewTicker(e.config.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.batchMu.Lock()
			if time.Since(e.lastFlush) >= e.config.FlushInterval {
				e.flushKeystrokeBatch()
			}
			e.batchMu.Unlock()
		}
	}
}

// focusMonitorLoop monitors for focus changes.
func (e *IBusEngineImpl) focusMonitorLoop(ctx context.Context) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	var lastApp, lastDoc string

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			info, err := e.focusTracker.GetFocusInfo()
			if err != nil {
				continue
			}

			if info.AppID != lastApp || info.WindowTitle != lastDoc {
				lastApp = info.AppID
				lastDoc = info.WindowTitle

				e.mu.Lock()
				oldApp := e.currentApp
				e.currentApp = info.AppID
				e.currentDoc = info.WindowTitle
				e.stats.FocusChanges++
				e.stats.LastFocusChange = time.Now()

				// If app changed significantly, end current session
				if oldApp != "" && oldApp != info.AppID && e.engine.HasActiveSession() {
					evidence, err := e.engine.EndSession()
					if err == nil && evidence != nil {
						e.stats.SessionsEnded++
					}
				}
				e.mu.Unlock()

				log.Printf("Focus changed: app=%s doc=%s", info.AppID, info.WindowTitle)
			}
		}
	}
}

// GetStats returns engine statistics.
func (e *IBusEngineImpl) GetStats() IBusEngineStats {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.stats
}

// keyvalToRune converts X11 keysym to Unicode rune.
func keyvalToRune(keyval uint32) rune {
	// Direct Unicode mapping for Latin-1 range
	if keyval >= 0x20 && keyval <= 0x7e {
		return rune(keyval)
	}

	// Extended Latin (ISO 8859-1)
	if keyval >= 0xa0 && keyval <= 0xff {
		return rune(keyval)
	}

	// Unicode keysyms (0x01000000 + codepoint)
	if keyval >= 0x01000000 {
		return rune(keyval - 0x01000000)
	}

	return 0
}

// IBusFactory implements the IBus Factory D-Bus interface.
type IBusFactory struct {
	engine   *IBusEngineImpl
	engineID uint32
}

// CreateEngine creates a new engine instance for IBus.
func (f *IBusFactory) CreateEngine(engineName string) (dbus.ObjectPath, *dbus.Error) {
	log.Printf("CreateEngine: %s", engineName)

	if engineName != WitnessdEngineName {
		return "", dbus.NewError("org.freedesktop.IBus.NoEngine",
			[]interface{}{"Unknown engine: " + engineName})
	}

	f.engineID++
	path := dbus.ObjectPath(fmt.Sprintf("/org/freedesktop/IBus/Engine/%d", f.engineID))

	// Export the engine at the new path
	f.engine.conn.Export(f.engine, path, IBusEngineInterface)

	return path, nil
}

// FocusInfo contains information about the focused window.
type FocusInfo struct {
	AppID       string
	WindowTitle string
	WindowClass string
	PID         int
}

// FocusTracker tracks the currently focused window.
type FocusTracker struct {
	mu       sync.RWMutex
	running  bool
	cancel   context.CancelFunc
	display  string
	isWayland bool
}

// NewFocusTracker creates a new focus tracker.
func NewFocusTracker() *FocusTracker {
	isWayland := os.Getenv("WAYLAND_DISPLAY") != ""
	display := os.Getenv("DISPLAY")

	return &FocusTracker{
		display:   display,
		isWayland: isWayland,
	}
}

// Start begins focus tracking.
func (f *FocusTracker) Start(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.running {
		return nil
	}

	ctx, f.cancel = context.WithCancel(ctx)
	f.running = true

	return nil
}

// Stop stops focus tracking.
func (f *FocusTracker) Stop() {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.cancel != nil {
		f.cancel()
	}
	f.running = false
}

// GetFocusInfo returns information about the currently focused window.
func (f *FocusTracker) GetFocusInfo() (*FocusInfo, error) {
	f.mu.RLock()
	isWayland := f.isWayland
	f.mu.RUnlock()

	if isWayland {
		return f.getWaylandFocusInfo()
	}
	return f.getX11FocusInfo()
}

// getX11FocusInfo gets focus info using X11.
func (f *FocusTracker) getX11FocusInfo() (*FocusInfo, error) {
	// Use xdotool to get active window info
	cmd := exec.Command("xdotool", "getactivewindow", "getwindowname")
	output, err := cmd.Output()
	if err != nil {
		// Try xprop as fallback
		return f.getX11FocusInfoXprop()
	}

	windowTitle := strings.TrimSpace(string(output))

	// Get window class
	cmd = exec.Command("xdotool", "getactivewindow", "getwindowclassname")
	classOutput, _ := cmd.Output()
	windowClass := strings.TrimSpace(string(classOutput))

	// Get PID
	cmd = exec.Command("xdotool", "getactivewindow", "getwindowpid")
	pidOutput, _ := cmd.Output()
	var pid int
	fmt.Sscanf(strings.TrimSpace(string(pidOutput)), "%d", &pid)

	// Try to get app ID from desktop file or process name
	appID := f.getAppIDFromClass(windowClass)
	if appID == "" {
		appID = f.getAppIDFromPID(pid)
	}
	if appID == "" {
		appID = windowClass
	}

	return &FocusInfo{
		AppID:       appID,
		WindowTitle: windowTitle,
		WindowClass: windowClass,
		PID:         pid,
	}, nil
}

// getX11FocusInfoXprop uses xprop as fallback for focus tracking.
func (f *FocusTracker) getX11FocusInfoXprop() (*FocusInfo, error) {
	// Get active window ID
	cmd := exec.Command("xprop", "-root", "_NET_ACTIVE_WINDOW")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("xprop failed: %w", err)
	}

	// Parse window ID
	var windowID string
	parts := strings.Fields(string(output))
	if len(parts) >= 5 {
		windowID = parts[len(parts)-1]
	} else {
		return nil, errors.New("could not parse window ID")
	}

	// Get window name
	cmd = exec.Command("xprop", "-id", windowID, "WM_NAME")
	nameOutput, _ := cmd.Output()
	windowTitle := parseXpropString(string(nameOutput))

	// Get window class
	cmd = exec.Command("xprop", "-id", windowID, "WM_CLASS")
	classOutput, _ := cmd.Output()
	windowClass := parseXpropString(string(classOutput))

	// Get PID
	cmd = exec.Command("xprop", "-id", windowID, "_NET_WM_PID")
	pidOutput, _ := cmd.Output()
	var pid int
	if strings.Contains(string(pidOutput), "=") {
		parts := strings.Split(string(pidOutput), "=")
		if len(parts) > 1 {
			fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &pid)
		}
	}

	appID := f.getAppIDFromClass(windowClass)
	if appID == "" {
		appID = windowClass
	}

	return &FocusInfo{
		AppID:       appID,
		WindowTitle: windowTitle,
		WindowClass: windowClass,
		PID:         pid,
	}, nil
}

// parseXpropString extracts the string value from xprop output.
func parseXpropString(output string) string {
	if idx := strings.Index(output, "="); idx != -1 {
		value := strings.TrimSpace(output[idx+1:])
		// Remove quotes
		value = strings.Trim(value, "\"")
		// Handle WM_CLASS format: "instance", "class"
		if parts := strings.Split(value, "\", \""); len(parts) > 1 {
			return strings.Trim(parts[1], "\"")
		}
		return value
	}
	return ""
}

// getWaylandFocusInfo gets focus info on Wayland.
func (f *FocusTracker) getWaylandFocusInfo() (*FocusInfo, error) {
	// Wayland doesn't allow direct window inspection for security.
	// We rely on IBus to give us the client info through D-Bus properties.

	// Try gdbus for GNOME Shell
	cmd := exec.Command("gdbus", "call", "--session",
		"--dest", "org.gnome.Shell",
		"--object-path", "/org/gnome/Shell",
		"--method", "org.gnome.Shell.Eval",
		"global.display.focus_window?.get_wm_class() || ''")

	output, err := cmd.Output()
	if err == nil {
		windowClass := parseGnomeShellOutput(string(output))
		if windowClass != "" {
			return &FocusInfo{
				AppID:       windowClass,
				WindowTitle: "",
				WindowClass: windowClass,
			}, nil
		}
	}

	// Fallback: check environment for app info
	appID := os.Getenv("GIO_LAUNCHED_DESKTOP_FILE")
	if appID == "" {
		appID = "unknown-wayland-app"
	}

	return &FocusInfo{
		AppID:       appID,
		WindowTitle: "Wayland",
		WindowClass: "unknown",
	}, nil
}

// parseGnomeShellOutput parses the output from GNOME Shell Eval.
func parseGnomeShellOutput(output string) string {
	// Output format: (true, "'ClassName'")
	output = strings.TrimSpace(output)
	if strings.HasPrefix(output, "(true,") {
		// Extract the class name
		start := strings.Index(output, "'")
		end := strings.LastIndex(output, "'")
		if start != -1 && end > start {
			return output[start+1 : end]
		}
	}
	return ""
}

// getAppIDFromClass tries to map window class to application ID.
func (f *FocusTracker) getAppIDFromClass(windowClass string) string {
	// Common mappings
	mappings := map[string]string{
		"Firefox":        "firefox",
		"firefox":        "firefox",
		"Google-chrome":  "google-chrome",
		"chromium":       "chromium",
		"Code":           "code",
		"code":           "visual-studio-code",
		"Gnome-terminal": "gnome-terminal",
		"konsole":        "konsole",
		"Gedit":          "gedit",
		"libreoffice":    "libreoffice",
		"Thunderbird":    "thunderbird",
		"Slack":          "slack",
		"discord":        "discord",
	}

	if appID, ok := mappings[windowClass]; ok {
		return appID
	}

	return strings.ToLower(windowClass)
}

// getAppIDFromPID tries to get application ID from process ID.
func (f *FocusTracker) getAppIDFromPID(pid int) string {
	if pid <= 0 {
		return ""
	}

	// Read process command line
	cmdPath := fmt.Sprintf("/proc/%d/comm", pid)
	data, err := os.ReadFile(cmdPath)
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(data))
}

// IPCMessage represents a message for IPC communication.
type IPCMessage struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

// IPCClient handles IPC communication with the witnessd daemon.
type IPCClient struct {
	mu        sync.Mutex
	conn      net.Conn
	path      string
	connected bool
	encoder   *json.Encoder
	decoder   *json.Decoder
}

// NewIPCClient creates a new IPC client.
func NewIPCClient(socketPath string) (*IPCClient, error) {
	client := &IPCClient{
		path: socketPath,
	}

	if err := client.Connect(); err != nil {
		return client, err
	}

	return client, nil
}

// Connect establishes connection to the daemon socket.
func (c *IPCClient) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected {
		return nil
	}

	conn, err := net.Dial("unix", c.path)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %w", c.path, err)
	}

	c.conn = conn
	c.encoder = json.NewEncoder(conn)
	c.decoder = json.NewDecoder(conn)
	c.connected = true

	return nil
}

// Close closes the IPC connection.
func (c *IPCClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.connected = false
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// IsConnected returns whether the client is connected.
func (c *IPCClient) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected
}

// Send sends a message to the daemon.
func (c *IPCClient) Send(msg IPCMessage) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return errors.New("not connected")
	}

	// Write message with length prefix
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	// Length-prefixed framing
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(data)))

	if _, err := c.conn.Write(lenBuf); err != nil {
		c.connected = false
		return err
	}

	if _, err := c.conn.Write(data); err != nil {
		c.connected = false
		return err
	}

	return nil
}

// Receive reads a message from the daemon.
func (c *IPCClient) Receive() (*IPCMessage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return nil, errors.New("not connected")
	}

	// Read length prefix
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(c.conn, lenBuf); err != nil {
		c.connected = false
		return nil, err
	}

	length := binary.BigEndian.Uint32(lenBuf)
	if length > 1024*1024 { // 1MB max
		return nil, errors.New("message too large")
	}

	// Read message
	data := make([]byte, length)
	if _, err := io.ReadFull(c.conn, data); err != nil {
		c.connected = false
		return nil, err
	}

	var msg IPCMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, err
	}

	return &msg, nil
}

// Reconnect attempts to reconnect to the daemon.
func (c *IPCClient) Reconnect() error {
	c.Close()
	return c.Connect()
}
