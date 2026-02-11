package theme

import (
	"image/color"
	"runtime"

	"gioui.org/unit"
	"gioui.org/widget/material"
)

// Palette defines the system colors.
type Palette struct {
	Background color.NRGBA
	Surface    color.NRGBA
	Panel      color.NRGBA
	Primary    color.NRGBA
	Text       color.NRGBA
	TextMuted  color.NRGBA
	Border     color.NRGBA
	Success    color.NRGBA
	Error      color.NRGBA
	Warning    color.NRGBA
}

// Config defines the system metrics.
type Config struct {
	CornerRadius unit.Dp
	Spacing      unit.Dp
	Padding      unit.Dp
	FontTitle    unit.Sp
	FontBody     unit.Sp
	FontCaption  unit.Sp
}

// Theme wraps the material theme with system-specific styling.
type Theme struct {
	*material.Theme
	Palette Palette
	Config  Config
}

// NewTheme creates a new theme based on the current OS.
func NewTheme(mtheme *material.Theme) *Theme {
	t := &Theme{
		Theme: mtheme,
	}

	if runtime.GOOS == "windows" {
		setupWindowsTheme(t)
	} else if runtime.GOOS == "darwin" {
		setupMacOSTheme(t)
	} else {
		setupDefaultTheme(t)
	}

	return t
}

func setupWindowsTheme(t *Theme) {
	// Fluent UI / Windows 11 inspired palette (Dark Mode focus)
	t.Palette = Palette{
		Background: color.NRGBA{R: 0x20, G: 0x20, B: 0x20, A: 0xFF}, // Mica-like
		Surface:    color.NRGBA{R: 0x2C, G: 0x2C, B: 0x2C, A: 0xFF},
		Panel:      color.NRGBA{R: 0x32, G: 0x32, B: 0x32, A: 0xFF},
		Primary:    color.NRGBA{R: 0x00, G: 0x78, B: 0xD4, A: 0xFF}, // Windows Blue
		Text:       color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF},
		TextMuted:  color.NRGBA{R: 0xA0, G: 0xA0, B: 0xA0, A: 0xFF},
		Border:     color.NRGBA{R: 0x40, G: 0x40, B: 0x40, A: 0xFF},
		Success:    color.NRGBA{R: 0x6B, G: 0xBC, B: 0x0F, A: 0xFF},
		Error:      color.NRGBA{R: 0xE8, G: 0x11, B: 0x23, A: 0xFF},
		Warning:    color.NRGBA{R: 0xFF, G: 0xB9, B: 0x00, A: 0xFF},
	}

	t.Config = Config{
		CornerRadius: unit.Dp(4), // Windows 11 rounded corners
		Spacing:      unit.Dp(8),
		Padding:      unit.Dp(16),
		FontTitle:    unit.Sp(20),
		FontBody:     unit.Sp(14),
		FontCaption:  unit.Sp(12),
	}
}

func setupMacOSTheme(t *Theme) {
	// macOS Ventura/Sonoma inspired palette (Dark Mode)
	t.Palette = Palette{
		Background: color.NRGBA{R: 0x1E, G: 0x1E, B: 0x1E, A: 0xFF},
		Surface:    color.NRGBA{R: 0x26, G: 0x26, B: 0x26, A: 0xFF},
		Panel:      color.NRGBA{R: 0x32, G: 0x32, B: 0x32, A: 0xFF},
		Primary:    color.NRGBA{R: 0x0A, G: 0x84, B: 0xFF, A: 0xFF}, // Apple Blue
		Text:       color.NRGBA{R: 0xF5, G: 0xF5, B: 0xF7, A: 0xFF},
		TextMuted:  color.NRGBA{R: 0x86, G: 0x86, B: 0x8B, A: 0xFF},
		Border:     color.NRGBA{R: 0x3A, G: 0x3A, B: 0x3C, A: 0xFF},
		Success:    color.NRGBA{R: 0x30, G: 0xD1, B: 0x58, A: 0xFF},
		Error:      color.NRGBA{R: 0xFF, G: 0x45, B: 0x3A, A: 0xFF},
		Warning:    color.NRGBA{R: 0xFF, G: 0x9F, B: 0x0A, A: 0xFF},
	}

	t.Config = Config{
		CornerRadius: unit.Dp(10), // macOS rounded corners are larger
		Spacing:      unit.Dp(10),
		Padding:      unit.Dp(20),
		FontTitle:    unit.Sp(22),
		FontBody:     unit.Sp(13), // macOS system font is slightly smaller than Win
		FontCaption:  unit.Sp(11),
	}
}

func setupDefaultTheme(t *Theme) {
	setupWindowsTheme(t) // Default to Windows-like for Linux/Other for now
}
