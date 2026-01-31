package ime

// Platform defines the interface that each platform IME must implement.
// The Go core (Engine) handles all cryptographic operations.
// Platform implementations handle system integration.
type Platform interface {
	// Name returns the platform name (e.g., "macos", "windows", "linux").
	Name() string

	// Available returns true if this platform implementation is available.
	Available() bool

	// Install installs the IME for the current user.
	// This typically involves copying files and registering with the system.
	Install() error

	// Uninstall removes the IME from the system.
	Uninstall() error

	// IsInstalled returns true if the IME is installed.
	IsInstalled() bool

	// IsActive returns true if the IME is currently the active input method.
	IsActive() bool

	// Activate makes this IME the active input method.
	Activate() error
}

// PlatformConfig contains platform-specific configuration.
type PlatformConfig struct {
	// DataDir is where witnessd stores session data.
	DataDir string

	// BundleID is the application identifier (macOS).
	BundleID string

	// DisplayName is shown to users in system preferences.
	DisplayName string

	// IconPath is the path to the IME icon.
	IconPath string
}

// DefaultConfig returns platform-appropriate default configuration.
func DefaultConfig() PlatformConfig {
	return PlatformConfig{
		BundleID:    "com.witnessd.ime",
		DisplayName: "Witnessd",
	}
}

// PlatformInfo describes the IME frameworks available on each platform.
type PlatformInfo struct {
	Name        string
	Framework   string
	Description string
	Permissions []string
}

// SupportedPlatforms lists all desktop platforms we support.
var SupportedPlatforms = []PlatformInfo{
	{
		Name:        "macOS",
		Framework:   "Input Method Kit (IMKit)",
		Description: "NSInputServiceProvider-based input method",
		Permissions: []string{"None - user explicitly selects input method"},
	},
	{
		Name:        "Windows",
		Framework:   "Text Services Framework (TSF)",
		Description: "ITfTextInputProcessor implementation",
		Permissions: []string{"None - user explicitly selects input method"},
	},
	{
		Name:        "Linux",
		Framework:   "IBus / Fcitx",
		Description: "IBusEngine-based input method",
		Permissions: []string{"None - user explicitly selects input method"},
	},
}

// ZoneMapping provides platform-specific keycode to zone mapping.
// Each platform has different virtual key codes.
type ZoneMapping interface {
	// KeyCodeToZone maps a platform-specific keycode to a zone (0-7).
	// Returns -1 for non-zone keys.
	KeyCodeToZone(keyCode uint16) int

	// CharToZone maps a character to a zone.
	// This is the fallback when keycode mapping isn't available.
	CharToZone(char rune) int
}

// DefaultZoneMapping uses the macOS key codes from the jitter package.
// Other platforms should provide their own mappings.
type DefaultZoneMapping struct{}

func (DefaultZoneMapping) KeyCodeToZone(keyCode uint16) int {
	// Delegate to jitter package (uses macOS keycodes)
	return zoneFromKeyCode(keyCode)
}

func (DefaultZoneMapping) CharToZone(char rune) int {
	// Delegate to jitter package
	return zoneFromChar(char)
}

// Platform-specific zone mapping implementations will be in:
// - platform_darwin.go
// - platform_windows.go
// - platform_linux.go

// zoneFromKeyCode wraps the jitter package function.
// This indirection allows platform-specific overrides.
var zoneFromKeyCode = func(keyCode uint16) int {
	// Default: use macOS keycodes
	switch keyCode {
	case 0x0C, 0x00, 0x06: // Q, A, Z
		return 0
	case 0x0D, 0x01, 0x07: // W, S, X
		return 1
	case 0x0E, 0x02, 0x08: // E, D, C
		return 2
	case 0x0F, 0x11, 0x03, 0x05, 0x09, 0x0B: // R, T, F, G, V, B
		return 3
	case 0x10, 0x20, 0x04, 0x26, 0x2D, 0x2E: // Y, U, H, J, N, M
		return 4
	case 0x22, 0x28, 0x2B: // I, K, comma
		return 5
	case 0x1F, 0x25, 0x2F: // O, L, period
		return 6
	case 0x23, 0x29, 0x2C: // P, semicolon, slash
		return 7
	default:
		return -1
	}
}

// zoneFromChar wraps the character-based zone lookup.
var zoneFromChar = func(c rune) int {
	switch c {
	case 'q', 'Q', 'a', 'A', 'z', 'Z':
		return 0
	case 'w', 'W', 's', 'S', 'x', 'X':
		return 1
	case 'e', 'E', 'd', 'D', 'c', 'C':
		return 2
	case 'r', 'R', 't', 'T', 'f', 'F', 'g', 'G', 'v', 'V', 'b', 'B':
		return 3
	case 'y', 'Y', 'u', 'U', 'h', 'H', 'j', 'J', 'n', 'N', 'm', 'M':
		return 4
	case 'i', 'I', 'k', 'K', ',', '<':
		return 5
	case 'o', 'O', 'l', 'L', '.', '>':
		return 6
	case 'p', 'P', ';', ':', '/', '?':
		return 7
	default:
		return -1
	}
}
