//go:build windows

package ime

import (
	"testing"
	"time"
)

// TestWindowsZoneMapping tests the Windows virtual key to zone mapping.
func TestWindowsZoneMapping(t *testing.T) {
	mapping := WindowsZoneMapping{}

	tests := []struct {
		name     string
		keyCode  uint16
		expected int
	}{
		// Zone 0: Left pinky (Q, A, Z)
		{"Q key", 0x51, 0},
		{"A key", 0x41, 0},
		{"Z key", 0x5A, 0},

		// Zone 1: Left ring (W, S, X)
		{"W key", 0x57, 1},
		{"S key", 0x53, 1},
		{"X key", 0x58, 1},

		// Zone 2: Left middle (E, D, C)
		{"E key", 0x45, 2},
		{"D key", 0x44, 2},
		{"C key", 0x43, 2},

		// Zone 3: Left index (R, T, F, G, V, B)
		{"R key", 0x52, 3},
		{"T key", 0x54, 3},
		{"F key", 0x46, 3},
		{"G key", 0x47, 3},
		{"V key", 0x56, 3},
		{"B key", 0x42, 3},

		// Zone 4: Right index (Y, U, H, J, N, M)
		{"Y key", 0x59, 4},
		{"U key", 0x55, 4},
		{"H key", 0x48, 4},
		{"J key", 0x4A, 4},
		{"N key", 0x4E, 4},
		{"M key", 0x4D, 4},

		// Zone 5: Right middle (I, K, comma)
		{"I key", 0x49, 5},
		{"K key", 0x4B, 5},
		{"Comma key", 0xBC, 5},

		// Zone 6: Right ring (O, L, period)
		{"O key", 0x4F, 6},
		{"L key", 0x4C, 6},
		{"Period key", 0xBE, 6},

		// Zone 7: Right pinky (P, semicolon, slash)
		{"P key", 0x50, 7},
		{"Semicolon key", 0xBA, 7},
		{"Slash key", 0xBF, 7},

		// Non-zone keys
		{"Escape key", 0x1B, -1},
		{"F1 key", 0x70, -1},
		{"Space key", 0x20, -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			zone := mapping.KeyCodeToZone(tt.keyCode)
			if zone != tt.expected {
				t.Errorf("KeyCodeToZone(%#x) = %d, want %d", tt.keyCode, zone, tt.expected)
			}
		})
	}
}

// TestWindowsZoneMappingChar tests character-based zone mapping.
func TestWindowsZoneMappingChar(t *testing.T) {
	mapping := WindowsZoneMapping{}

	tests := []struct {
		char     rune
		expected int
	}{
		// Zone 0
		{'q', 0}, {'Q', 0}, {'a', 0}, {'A', 0}, {'z', 0}, {'Z', 0},
		// Zone 1
		{'w', 1}, {'W', 1}, {'s', 1}, {'S', 1}, {'x', 1}, {'X', 1},
		// Zone 2
		{'e', 2}, {'E', 2}, {'d', 2}, {'D', 2}, {'c', 2}, {'C', 2},
		// Zone 3
		{'r', 3}, {'t', 3}, {'f', 3}, {'g', 3}, {'v', 3}, {'b', 3},
		// Zone 4
		{'y', 4}, {'u', 4}, {'h', 4}, {'j', 4}, {'n', 4}, {'m', 4},
		// Zone 5
		{'i', 5}, {'k', 5}, {',', 5},
		// Zone 6
		{'o', 6}, {'l', 6}, {'.', 6},
		// Zone 7
		{'p', 7}, {';', 7}, {'/', 7},
		// Non-zone
		{'1', -1}, {' ', -1}, {'\n', -1},
	}

	for _, tt := range tests {
		t.Run(string(tt.char), func(t *testing.T) {
			zone := mapping.CharToZone(tt.char)
			if zone != tt.expected {
				t.Errorf("CharToZone(%q) = %d, want %d", tt.char, zone, tt.expected)
			}
		})
	}
}

// TestWindowsPlatformConfig tests platform configuration.
func TestWindowsPlatformConfig(t *testing.T) {
	config := DefaultConfig()

	if config.BundleID != "com.witnessd.ime" {
		t.Errorf("BundleID = %q, want %q", config.BundleID, "com.witnessd.ime")
	}

	if config.DisplayName != "Witnessd" {
		t.Errorf("DisplayName = %q, want %q", config.DisplayName, "Witnessd")
	}
}

// TestWindowsPlatformName tests that the Windows platform has the correct name.
func TestWindowsPlatformName(t *testing.T) {
	engine := NewEngine()
	platform := NewWindowsPlatform(DefaultConfig(), engine)

	if platform.Name() != "windows" {
		t.Errorf("Name() = %q, want %q", platform.Name(), "windows")
	}
}

// TestWindowsPlatformAvailable tests platform availability check.
func TestWindowsPlatformAvailable(t *testing.T) {
	engine := NewEngine()
	platform := NewWindowsPlatform(DefaultConfig(), engine)

	// TSF should always be available on Windows
	if !platform.Available() {
		t.Error("Available() = false, want true on Windows")
	}
}

// MockTSFProvider mocks the TSF provider for testing.
type MockTSFProvider struct {
	keystrokes       []MockKeystroke
	focusChanges     []MockFocusChange
	compositionTexts []string
	isActive         bool
}

type MockKeystroke struct {
	VirtualKey uint16
	ScanCode   uint16
	Timestamp  time.Time
	IsKeyDown  bool
}

type MockFocusChange struct {
	AppName   string
	DocTitle  string
	Timestamp time.Time
}

func NewMockTSFProvider() *MockTSFProvider {
	return &MockTSFProvider{
		keystrokes:       make([]MockKeystroke, 0),
		focusChanges:     make([]MockFocusChange, 0),
		compositionTexts: make([]string, 0),
	}
}

func (m *MockTSFProvider) OnKeystroke(vk, sc uint16, isDown bool) {
	m.keystrokes = append(m.keystrokes, MockKeystroke{
		VirtualKey: vk,
		ScanCode:   sc,
		Timestamp:  time.Now(),
		IsKeyDown:  isDown,
	})
}

func (m *MockTSFProvider) OnFocusChange(appName, docTitle string) {
	m.focusChanges = append(m.focusChanges, MockFocusChange{
		AppName:   appName,
		DocTitle:  docTitle,
		Timestamp: time.Now(),
	})
}

func (m *MockTSFProvider) OnCompositionEnd(text string) {
	m.compositionTexts = append(m.compositionTexts, text)
}

func (m *MockTSFProvider) SetActive(active bool) {
	m.isActive = active
}

// TestMockTSFProviderKeystrokes tests mock provider keystroke handling.
func TestMockTSFProviderKeystrokes(t *testing.T) {
	mock := NewMockTSFProvider()

	// Simulate typing "hello"
	keystrokes := []struct {
		vk   uint16
		sc   uint16
		down bool
	}{
		{0x48, 0x23, true},  // H down
		{0x48, 0x23, false}, // H up
		{0x45, 0x12, true},  // E down
		{0x45, 0x12, false}, // E up
		{0x4C, 0x26, true},  // L down
		{0x4C, 0x26, false}, // L up
		{0x4C, 0x26, true},  // L down
		{0x4C, 0x26, false}, // L up
		{0x4F, 0x18, true},  // O down
		{0x4F, 0x18, false}, // O up
	}

	for _, ks := range keystrokes {
		mock.OnKeystroke(ks.vk, ks.sc, ks.down)
	}

	if len(mock.keystrokes) != 10 {
		t.Errorf("keystroke count = %d, want 10", len(mock.keystrokes))
	}

	// Check first keystroke
	if mock.keystrokes[0].VirtualKey != 0x48 {
		t.Errorf("first keystroke VK = %#x, want %#x", mock.keystrokes[0].VirtualKey, 0x48)
	}
}

// TestMockTSFProviderFocusChanges tests mock provider focus tracking.
func TestMockTSFProviderFocusChanges(t *testing.T) {
	mock := NewMockTSFProvider()

	// Simulate focus changes
	mock.OnFocusChange("notepad.exe", "Untitled - Notepad")
	mock.OnFocusChange("code.exe", "main.go - Visual Studio Code")

	if len(mock.focusChanges) != 2 {
		t.Errorf("focus change count = %d, want 2", len(mock.focusChanges))
	}

	if mock.focusChanges[0].AppName != "notepad.exe" {
		t.Errorf("first focus app = %q, want %q", mock.focusChanges[0].AppName, "notepad.exe")
	}

	if mock.focusChanges[1].DocTitle != "main.go - Visual Studio Code" {
		t.Errorf("second focus title = %q, want %q", mock.focusChanges[1].DocTitle, "main.go - Visual Studio Code")
	}
}

// TestMockTSFProviderComposition tests mock provider IME composition.
func TestMockTSFProviderComposition(t *testing.T) {
	mock := NewMockTSFProvider()

	// Simulate IME composition
	mock.OnCompositionEnd("你好")
	mock.OnCompositionEnd("世界")

	if len(mock.compositionTexts) != 2 {
		t.Errorf("composition count = %d, want 2", len(mock.compositionTexts))
	}

	if mock.compositionTexts[0] != "你好" {
		t.Errorf("first composition = %q, want %q", mock.compositionTexts[0], "你好")
	}
}

// TestEngineWithMockTSF tests the engine integration with mock TSF.
func TestEngineWithMockTSF(t *testing.T) {
	engine := NewEngine()
	mock := NewMockTSFProvider()

	// Start session
	err := engine.StartSession(SessionOptions{
		AppID: "test.app",
		DocID: "test.doc",
	})
	if err != nil {
		t.Fatalf("StartSession error: %v", err)
	}

	// Simulate keystrokes and process through engine
	keystrokes := []struct {
		vk   uint16
		char rune
	}{
		{0x48, 'h'},
		{0x45, 'e'},
		{0x4C, 'l'},
		{0x4C, 'l'},
		{0x4F, 'o'},
	}

	for _, ks := range keystrokes {
		mock.OnKeystroke(ks.vk, 0, true)

		key := NewKeyWithCode(ks.vk, ks.char)
		_, err := engine.OnKeyDown(key)
		if err != nil {
			t.Errorf("OnKeyDown error: %v", err)
		}

		err = engine.OnTextCommit(string(ks.char))
		if err != nil {
			t.Errorf("OnTextCommit error: %v", err)
		}
	}

	// Check sample count
	sampleCount := engine.GetSampleCount()
	if sampleCount != 5 {
		t.Errorf("sample count = %d, want 5", sampleCount)
	}

	// Check document content
	content := engine.GetDocumentContent()
	if string(content) != "hello" {
		t.Errorf("document content = %q, want %q", content, "hello")
	}

	// End session
	evidence, err := engine.EndSession()
	if err != nil {
		t.Fatalf("EndSession error: %v", err)
	}

	if evidence.TotalKeystrokes != 5 {
		t.Errorf("total keystrokes = %d, want 5", evidence.TotalKeystrokes)
	}
}

// TestVirtualKeyConstants tests that virtual key constants are correct.
func TestVirtualKeyConstants(t *testing.T) {
	// Windows VK_ constants
	const (
		VK_BACK      = 0x08
		VK_TAB       = 0x09
		VK_RETURN    = 0x0D
		VK_SHIFT     = 0x10
		VK_CONTROL   = 0x11
		VK_MENU      = 0x12 // Alt
		VK_ESCAPE    = 0x1B
		VK_SPACE     = 0x20
		VK_DELETE    = 0x2E
		VK_A         = 0x41
		VK_Z         = 0x5A
	)

	// Verify zone mapping for letter keys
	mapping := WindowsZoneMapping{}

	// A should be zone 0 (left pinky)
	if zone := mapping.KeyCodeToZone(VK_A); zone != 0 {
		t.Errorf("VK_A zone = %d, want 0", zone)
	}

	// Z should be zone 0 (left pinky)
	if zone := mapping.KeyCodeToZone(VK_Z); zone != 0 {
		t.Errorf("VK_Z zone = %d, want 0", zone)
	}

	// Backspace should not be a zone key
	if zone := mapping.KeyCodeToZone(VK_BACK); zone != -1 {
		t.Errorf("VK_BACK zone = %d, want -1", zone)
	}

	// Space should not be a zone key
	if zone := mapping.KeyCodeToZone(VK_SPACE); zone != -1 {
		t.Errorf("VK_SPACE zone = %d, want -1", zone)
	}
}

// BenchmarkZoneMapping benchmarks zone mapping performance.
func BenchmarkZoneMapping(b *testing.B) {
	mapping := WindowsZoneMapping{}

	// Mix of zone and non-zone keys
	keys := []uint16{
		0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
		0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
		0x08, 0x20, 0x1B, 0x0D,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mapping.KeyCodeToZone(keys[i%len(keys)])
	}
}

// BenchmarkCharToZone benchmarks character-based zone mapping.
func BenchmarkCharToZone(b *testing.B) {
	mapping := WindowsZoneMapping{}

	chars := []rune{
		'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
		'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
		'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
		'y', 'z', ' ', '1', '2', '\n',
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mapping.CharToZone(chars[i%len(chars)])
	}
}
