//go:build linux

package ime

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestKeyvalToRune tests the X11 keysym to rune conversion.
func TestKeyvalToRune(t *testing.T) {
	tests := []struct {
		name    string
		keyval  uint32
		want    rune
	}{
		// ASCII printable characters
		{"space", 0x20, ' '},
		{"letter A", 0x41, 'A'},
		{"letter a", 0x61, 'a'},
		{"letter Z", 0x5a, 'Z'},
		{"digit 0", 0x30, '0'},
		{"digit 9", 0x39, '9'},
		{"tilde", 0x7e, '~'},

		// Extended Latin
		{"euro sign", 0xa0, '\u00a0'},      // NBSP
		{"copyright", 0xa9, '\u00a9'},      // Not direct mapping
		{"pound", 0xa3, '\u00a3'},          // Pound sign

		// Unicode keysyms
		{"unicode euro", 0x010020ac, '\u20ac'},   // Euro sign via Unicode keysym
		{"unicode heart", 0x01002665, '\u2665'}, // Heart symbol

		// Non-character keys
		{"backspace", GDKBackSpace, 0},
		{"return", GDKReturn, 0},
		{"escape", GDKEscape, 0},
		{"function key", 0xffbe, 0}, // F1
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := keyvalToRune(tt.keyval)
			if got != tt.want {
				t.Errorf("keyvalToRune(0x%x) = %q, want %q", tt.keyval, got, tt.want)
			}
		})
	}
}

// TestIBusEngineKeycodeToZone tests keycode to zone mapping.
func TestIBusEngineKeycodeToZone(t *testing.T) {
	engine := &IBusEngineImpl{}

	tests := []struct {
		name    string
		keycode uint32
		char    rune
		want    int
	}{
		// Left pinky (zone 0)
		{"Q key", 24, 'q', 0},
		{"A key", 38, 'a', 0},
		{"Z key", 52, 'z', 0},

		// Left ring (zone 1)
		{"W key", 25, 'w', 1},
		{"S key", 39, 's', 1},
		{"X key", 53, 'x', 1},

		// Left middle (zone 2)
		{"E key", 26, 'e', 2},
		{"D key", 40, 'd', 2},
		{"C key", 54, 'c', 2},

		// Left index (zone 3)
		{"R key", 27, 'r', 3},
		{"T key", 28, 't', 3},
		{"F key", 41, 'f', 3},
		{"G key", 42, 'g', 3},
		{"V key", 55, 'v', 3},
		{"B key", 56, 'b', 3},

		// Right index (zone 4)
		{"Y key", 29, 'y', 4},
		{"U key", 30, 'u', 4},
		{"H key", 43, 'h', 4},
		{"J key", 44, 'j', 4},
		{"N key", 57, 'n', 4},
		{"M key", 58, 'm', 4},

		// Right middle (zone 5)
		{"I key", 31, 'i', 5},
		{"K key", 45, 'k', 5},
		{"comma", 59, ',', 5},

		// Right ring (zone 6)
		{"O key", 32, 'o', 6},
		{"L key", 46, 'l', 6},
		{"period", 60, '.', 6},

		// Right pinky (zone 7)
		{"P key", 33, 'p', 7},
		{"semicolon", 47, ';', 7},
		{"slash", 61, '/', 7},

		// Unknown keycode, fallback to char
		{"unknown with char", 255, 'e', 2},

		// Unknown keycode and char
		{"unknown all", 255, 0, -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := engine.keycodeToZone(tt.keycode, tt.char)
			if got != tt.want {
				t.Errorf("keycodeToZone(%d, %q) = %d, want %d", tt.keycode, tt.char, got, tt.want)
			}
		})
	}
}

// TestKeystrokeEventBatching tests keystroke batching.
func TestKeystrokeEventBatching(t *testing.T) {
	config := DefaultIBusConfig()
	config.BatchSize = 5

	// Use temp directory
	tmpDir := t.TempDir()
	config.DataDir = tmpDir

	engine, err := NewIBusEngine(config)
	if err != nil {
		t.Fatalf("NewIBusEngine failed: %v", err)
	}

	// Add keystrokes
	for i := 0; i < 3; i++ {
		engine.batchKeystroke(KeystrokeEvent{
			Timestamp: time.Now().UnixNano(),
			Keycode:   uint16(24 + i),
			Char:      'a' + rune(i),
		})
	}

	engine.batchMu.Lock()
	batchLen := len(engine.keystrokeBatch)
	engine.batchMu.Unlock()

	if batchLen != 3 {
		t.Errorf("Expected 3 keystrokes in batch, got %d", batchLen)
	}

	// Add more to trigger flush (batch size is 5)
	for i := 0; i < 3; i++ {
		engine.batchKeystroke(KeystrokeEvent{
			Timestamp: time.Now().UnixNano(),
			Keycode:   uint16(27 + i),
			Char:      'd' + rune(i),
		})
	}

	engine.batchMu.Lock()
	// After adding 6 total with batch size 5, should have flushed 5 and have 1 remaining
	newBatchLen := len(engine.keystrokeBatch)
	engine.batchMu.Unlock()

	if newBatchLen != 1 {
		t.Errorf("Expected 1 keystroke in batch after flush, got %d", newBatchLen)
	}
}

// TestFocusTracker tests focus tracking initialization.
func TestFocusTracker(t *testing.T) {
	tracker := NewFocusTracker()

	if tracker == nil {
		t.Fatal("NewFocusTracker returned nil")
	}

	// Check Wayland detection
	originalWayland := os.Getenv("WAYLAND_DISPLAY")
	defer os.Setenv("WAYLAND_DISPLAY", originalWayland)

	os.Setenv("WAYLAND_DISPLAY", "wayland-0")
	tracker = NewFocusTracker()
	if !tracker.isWayland {
		t.Error("Expected isWayland to be true when WAYLAND_DISPLAY is set")
	}

	os.Unsetenv("WAYLAND_DISPLAY")
	tracker = NewFocusTracker()
	if tracker.isWayland {
		t.Error("Expected isWayland to be false when WAYLAND_DISPLAY is not set")
	}
}

// TestFocusTrackerStartStop tests starting and stopping the focus tracker.
func TestFocusTrackerStartStop(t *testing.T) {
	tracker := NewFocusTracker()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := tracker.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	if !tracker.running {
		t.Error("Expected tracker to be running")
	}

	// Start again should be no-op
	if err := tracker.Start(ctx); err != nil {
		t.Fatalf("Second Start failed: %v", err)
	}

	tracker.Stop()

	if tracker.running {
		t.Error("Expected tracker to be stopped")
	}
}

// TestIBusEngineStats tests statistics tracking.
func TestIBusEngineStats(t *testing.T) {
	config := DefaultIBusConfig()
	config.DataDir = t.TempDir()

	engine, err := NewIBusEngine(config)
	if err != nil {
		t.Fatalf("NewIBusEngine failed: %v", err)
	}

	stats := engine.GetStats()

	if stats.TotalKeystrokes != 0 {
		t.Errorf("Expected 0 total keystrokes, got %d", stats.TotalKeystrokes)
	}

	if stats.SessionsStarted != 0 {
		t.Errorf("Expected 0 sessions started, got %d", stats.SessionsStarted)
	}
}

// TestParseXpropString tests xprop output parsing.
func TestParseXpropString(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		want   string
	}{
		{
			name:  "WM_NAME",
			input: "WM_NAME(STRING) = \"Firefox\"",
			want:  "Firefox",
		},
		{
			name:  "WM_CLASS",
			input: "WM_CLASS(STRING) = \"Navigator\", \"Firefox\"",
			want:  "Firefox",
		},
		{
			name:  "empty",
			input: "",
			want:  "",
		},
		{
			name:  "no equals",
			input: "WM_NAME(STRING)",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseXpropString(tt.input)
			if got != tt.want {
				t.Errorf("parseXpropString(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestParseGnomeShellOutput tests GNOME Shell output parsing.
func TestParseGnomeShellOutput(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		want   string
	}{
		{
			name:  "valid output",
			input: "(true, 'Firefox')",
			want:  "Firefox",
		},
		{
			name:  "false result",
			input: "(false, '')",
			want:  "",
		},
		{
			name:  "empty",
			input: "",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseGnomeShellOutput(tt.input)
			if got != tt.want {
				t.Errorf("parseGnomeShellOutput(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestDefaultIBusConfig tests default configuration values.
func TestDefaultIBusConfig(t *testing.T) {
	config := DefaultIBusConfig()

	if config.BatchSize != 50 {
		t.Errorf("Expected BatchSize 50, got %d", config.BatchSize)
	}

	if config.FlushInterval != 5*time.Second {
		t.Errorf("Expected FlushInterval 5s, got %v", config.FlushInterval)
	}

	if config.SocketPath == "" {
		t.Error("Expected non-empty SocketPath")
	}

	if config.DataDir == "" {
		t.Error("Expected non-empty DataDir")
	}
}

// TestIPCMessage tests IPC message serialization.
func TestIPCMessage(t *testing.T) {
	msg := IPCMessage{
		Type: "keystrokes",
		Data: []KeystrokeEvent{
			{
				Timestamp: 1234567890,
				Keycode:   24,
				Char:      'a',
				Zone:      0,
			},
		},
	}

	if msg.Type != "keystrokes" {
		t.Errorf("Expected type 'keystrokes', got %s", msg.Type)
	}

	data, ok := msg.Data.([]KeystrokeEvent)
	if !ok {
		t.Fatal("Expected Data to be []KeystrokeEvent")
	}

	if len(data) != 1 {
		t.Errorf("Expected 1 keystroke, got %d", len(data))
	}

	if data[0].Char != 'a' {
		t.Errorf("Expected char 'a', got %q", data[0].Char)
	}
}

// TestIBusEngineConfiguration tests engine configuration.
func TestIBusEngineConfiguration(t *testing.T) {
	tmpDir := t.TempDir()

	config := IBusConfig{
		SocketPath:    filepath.Join(tmpDir, "test.sock"),
		DataDir:       tmpDir,
		BatchSize:     10,
		FlushInterval: 1 * time.Second,
		Debug:         true,
	}

	engine, err := NewIBusEngine(config)
	if err != nil {
		t.Fatalf("NewIBusEngine failed: %v", err)
	}

	if engine.config.BatchSize != 10 {
		t.Errorf("Expected BatchSize 10, got %d", engine.config.BatchSize)
	}

	if engine.config.FlushInterval != 1*time.Second {
		t.Errorf("Expected FlushInterval 1s, got %v", engine.config.FlushInterval)
	}

	if !engine.config.Debug {
		t.Error("Expected Debug to be true")
	}
}

// TestIBusModifierMasks tests modifier mask constants.
func TestIBusModifierMasks(t *testing.T) {
	// Verify modifier masks are correct
	if IBusShiftMask != 1 {
		t.Errorf("Expected IBusShiftMask = 1, got %d", IBusShiftMask)
	}

	if IBusControlMask != 4 {
		t.Errorf("Expected IBusControlMask = 4, got %d", IBusControlMask)
	}

	if IBusMod1Mask != 8 {
		t.Errorf("Expected IBusMod1Mask (Alt) = 8, got %d", IBusMod1Mask)
	}

	if IBusReleaseMask != 1<<30 {
		t.Errorf("Expected IBusReleaseMask = 1<<30, got %d", IBusReleaseMask)
	}
}

// TestGDKKeySymbols tests GDK key symbol constants.
func TestGDKKeySymbols(t *testing.T) {
	if GDKBackSpace != 0xff08 {
		t.Errorf("Expected GDKBackSpace = 0xff08, got 0x%x", GDKBackSpace)
	}

	if GDKReturn != 0xff0d {
		t.Errorf("Expected GDKReturn = 0xff0d, got 0x%x", GDKReturn)
	}

	if GDKTab != 0xff09 {
		t.Errorf("Expected GDKTab = 0xff09, got 0x%x", GDKTab)
	}

	if GDKEscape != 0xff1b {
		t.Errorf("Expected GDKEscape = 0xff1b, got 0x%x", GDKEscape)
	}
}

// MockDBusConn is a mock for D-Bus connection testing.
type MockDBusConn struct {
	exported map[string]interface{}
}

// TestIBusFactory tests the IBus factory.
func TestIBusFactory(t *testing.T) {
	config := DefaultIBusConfig()
	config.DataDir = t.TempDir()

	engine, err := NewIBusEngine(config)
	if err != nil {
		t.Fatalf("NewIBusEngine failed: %v", err)
	}

	factory := &IBusFactory{engine: engine}

	// Test CreateEngine with correct name
	// Note: This won't actually work without a D-Bus connection,
	// but we can verify the logic

	if factory.engine == nil {
		t.Error("Expected factory.engine to be set")
	}
}

// BenchmarkKeyvalToRune benchmarks keysym conversion.
func BenchmarkKeyvalToRune(b *testing.B) {
	keyvals := []uint32{0x61, 0x41, 0x20, 0xff08, 0x010020ac}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, kv := range keyvals {
			keyvalToRune(kv)
		}
	}
}

// BenchmarkKeycodeToZone benchmarks keycode to zone mapping.
func BenchmarkKeycodeToZone(b *testing.B) {
	engine := &IBusEngineImpl{}
	keycodes := []uint32{24, 25, 26, 27, 29, 31, 32, 33, 255}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, kc := range keycodes {
			engine.keycodeToZone(kc, 'a')
		}
	}
}

// BenchmarkBatchKeystroke benchmarks keystroke batching.
func BenchmarkBatchKeystroke(b *testing.B) {
	config := DefaultIBusConfig()
	config.BatchSize = 100
	config.DataDir = b.TempDir()

	engine, err := NewIBusEngine(config)
	if err != nil {
		b.Fatalf("NewIBusEngine failed: %v", err)
	}

	event := KeystrokeEvent{
		Timestamp: time.Now().UnixNano(),
		Keycode:   24,
		Char:      'a',
		Zone:      0,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.batchKeystroke(event)
	}
}
