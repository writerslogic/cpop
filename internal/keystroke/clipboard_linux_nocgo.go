//go:build linux && !cgo

package keystroke

import (
	"os/exec"
	"strings"
)

// linuxClipboardAccessorNoCGO implements ClipboardAccessor for Linux without CGO.
// Uses xclip or xsel as fallback.
type linuxClipboardAccessorNoCGO struct{}

func newPlatformClipboardAccessor() ClipboardAccessor {
	return &linuxClipboardAccessorNoCGO{}
}

func (l *linuxClipboardAccessorNoCGO) GetText() (string, error) {
	// Try xclip first
	out, err := exec.Command("xclip", "-selection", "clipboard", "-o").Output()
	if err == nil {
		return string(out), nil
	}

	// Fall back to xsel
	out, err = exec.Command("xsel", "--clipboard", "--output").Output()
	if err == nil {
		return string(out), nil
	}

	// Try wl-paste for Wayland
	out, err = exec.Command("wl-paste", "--no-newline").Output()
	if err == nil {
		return string(out), nil
	}

	return "", err
}

func (l *linuxClipboardAccessorNoCGO) GetContentType() string {
	// Try to determine type using xclip -t
	out, err := exec.Command("xclip", "-selection", "clipboard", "-t", "TARGETS", "-o").Output()
	if err == nil {
		targets := string(out)
		if strings.Contains(targets, "text/plain") || strings.Contains(targets, "UTF8_STRING") {
			return "text"
		}
		if strings.Contains(targets, "image/") {
			return "image"
		}
		if strings.Contains(targets, "text/uri-list") {
			return "files"
		}
	}

	return "unknown"
}

func (l *linuxClipboardAccessorNoCGO) GetSourceApp() string {
	return ""
}
