//go:build linux

// Package sentinel Linux focus tracker implementation.
//
// Uses X11 _NET_ACTIVE_WINDOW property or Wayland protocols to detect
// which document/window has focus.
//
// Patent Pending: USPTO Application No. 19/460,364
package sentinel

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// linuxFocusTracker implements FocusTracker for Linux.
type linuxFocusTracker struct {
	*baseFocusTracker
	mu          sync.RWMutex
	running     bool
	current     *WindowInfo
	logger      *slog.Logger
	displayType string // "x11", "wayland", or "unknown"
}

// newPlatformFocusTracker creates a Linux-specific focus tracker.
func newPlatformFocusTracker(config FocusTrackerConfig) FocusTracker {
	return &linuxFocusTracker{
		baseFocusTracker: newBaseFocusTracker(config),
		logger:           slog.Default().With("component", "focus_tracker_linux"),
		displayType:      detectDisplay(),
	}
}

// detectDisplay determines the display server type.
func detectDisplay() string {
	// Check for Wayland
	if os.Getenv("WAYLAND_DISPLAY") != "" {
		// Could be running XWayland
		if os.Getenv("DISPLAY") != "" {
			return "x11" // XWayland
		}
		return "wayland"
	}

	// Check for X11
	if os.Getenv("DISPLAY") != "" {
		return "x11"
	}

	return "unknown"
}

// Start begins focus tracking.
func (t *linuxFocusTracker) Start(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.running {
		return ErrAlreadyRunning
	}

	t.ctx, t.cancel = context.WithCancel(ctx)
	t.running = true

	go t.pollLoop()

	t.logger.Info("linux focus tracker started",
		"display_type", t.displayType,
		"poll_interval", t.config.PollInterval,
	)

	return nil
}

// Stop stops focus tracking.
func (t *linuxFocusTracker) Stop() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.running {
		return nil
	}

	t.running = false

	if t.cancel != nil {
		t.cancel()
	}

	t.close()
	t.logger.Info("linux focus tracker stopped")

	return nil
}

// ActiveWindow returns the currently focused window info.
func (t *linuxFocusTracker) ActiveWindow() *WindowInfo {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.current == nil {
		return nil
	}

	// Return a copy
	info := *t.current
	return &info
}

// Available checks if focus tracking is available.
func (t *linuxFocusTracker) Available() (bool, string) {
	switch t.displayType {
	case "x11":
		// Check for xdotool
		if _, err := exec.LookPath("xdotool"); err == nil {
			return true, "X11 focus tracking available (xdotool)"
		}
		// Check for xprop
		if _, err := exec.LookPath("xprop"); err == nil {
			return true, "X11 focus tracking available (xprop)"
		}
		return false, "X11 detected but xdotool/xprop not found. Install: sudo apt install xdotool"

	case "wayland":
		return false, "Wayland detected. Focus tracking has limited support due to security restrictions."

	default:
		return false, "Unknown display server. Focus tracking requires X11."
	}
}

// pollLoop periodically checks the focused window.
func (t *linuxFocusTracker) pollLoop() {
	ticker := time.NewTicker(t.config.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-t.ctx.Done():
			return
		case <-ticker.C:
			t.checkFocus()
		}
	}
}

// checkFocus checks the currently focused window and emits events if changed.
func (t *linuxFocusTracker) checkFocus() {
	var info *WindowInfo
	var err error

	switch t.displayType {
	case "x11":
		info, err = t.getX11WindowInfo()
	case "wayland":
		info, err = t.getWaylandWindowInfo()
	default:
		return
	}

	if err != nil || info == nil {
		return
	}

	t.mu.Lock()
	t.current = info
	t.mu.Unlock()

	t.emit(*info)
}

// getX11WindowInfo gets window info using X11 tools.
func (t *linuxFocusTracker) getX11WindowInfo() (*WindowInfo, error) {
	// Try xdotool first (more reliable)
	if info, err := t.getX11InfoXdotool(); err == nil {
		return info, nil
	}

	// Fallback to xprop
	return t.getX11InfoXprop()
}

// getX11InfoXdotool uses xdotool to get window info.
func (t *linuxFocusTracker) getX11InfoXdotool() (*WindowInfo, error) {
	// Get active window ID
	out, err := exec.Command("xdotool", "getactivewindow").Output()
	if err != nil {
		return nil, err
	}
	windowID := strings.TrimSpace(string(out))

	info := &WindowInfo{
		Timestamp: time.Now(),
	}

	// Get window name
	if out, err := exec.Command("xdotool", "getwindowname", windowID).Output(); err == nil {
		info.Title = strings.TrimSpace(string(out))
	}

	// Get window PID
	if out, err := exec.Command("xdotool", "getwindowpid", windowID).Output(); err == nil {
		if pid, err := strconv.Atoi(strings.TrimSpace(string(out))); err == nil {
			info.PID = pid
			t.enrichFromProc(info)
		}
	}

	// Try to extract document path
	info.Path = t.parsePathFromTitle(info.Title, info.Application)
	if info.Path != "" {
		info.IsDocument = true
	}

	// Detect project root
	info.ProjectRoot = t.detectProjectRoot(info)

	return info, nil
}

// getX11InfoXprop uses xprop to get window info.
func (t *linuxFocusTracker) getX11InfoXprop() (*WindowInfo, error) {
	// Get active window
	out, err := exec.Command("xprop", "-root", "_NET_ACTIVE_WINDOW").Output()
	if err != nil {
		return nil, err
	}

	// Parse window ID from "window id # 0x12345"
	parts := strings.Fields(string(out))
	if len(parts) < 5 {
		return nil, errors.New("failed to parse xprop output")
	}
	windowID := parts[len(parts)-1]

	info := &WindowInfo{
		Timestamp: time.Now(),
	}

	// Get window properties
	if out, err := exec.Command("xprop", "-id", windowID, "WM_NAME", "WM_CLASS", "_NET_WM_PID").Output(); err == nil {
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "WM_NAME") {
				// WM_NAME(STRING) = "Document - App"
				if idx := strings.Index(line, "= \""); idx != -1 {
					end := strings.LastIndex(line, "\"")
					if end > idx+3 {
						info.Title = line[idx+3 : end]
					}
				}
			} else if strings.HasPrefix(line, "WM_CLASS") {
				// WM_CLASS(STRING) = "instance", "class"
				if idx := strings.Index(line, ", \""); idx != -1 {
					end := strings.LastIndex(line, "\"")
					if end > idx+3 {
						info.Application = line[idx+3 : end]
					}
				}
			} else if strings.HasPrefix(line, "_NET_WM_PID") {
				// _NET_WM_PID(CARDINAL) = 12345
				if idx := strings.Index(line, "= "); idx != -1 {
					if pid, err := strconv.Atoi(strings.TrimSpace(line[idx+2:])); err == nil {
						info.PID = pid
						t.enrichFromProc(info)
					}
				}
			}
		}
	}

	// Try to extract document path
	info.Path = t.parsePathFromTitle(info.Title, info.Application)
	if info.Path != "" {
		info.IsDocument = true
	}

	// Detect project root
	info.ProjectRoot = t.detectProjectRoot(info)

	return info, nil
}

// getWaylandWindowInfo attempts to get window info on Wayland.
func (t *linuxFocusTracker) getWaylandWindowInfo() (*WindowInfo, error) {
	// Wayland's security model limits window inspection.
	// Some compositors provide DBus interfaces:
	// - GNOME: org.gnome.Shell.Introspect (limited)
	// - KDE: org.kde.KWin (better support)

	// For now, try to use compositor-specific methods
	if info, err := t.getGnomeWindowInfo(); err == nil {
		return info, nil
	}

	if info, err := t.getKDEWindowInfo(); err == nil {
		return info, nil
	}

	return nil, errors.New("wayland focus detection not available")
}

// getGnomeWindowInfo tries to get window info via GNOME Shell DBus.
func (t *linuxFocusTracker) getGnomeWindowInfo() (*WindowInfo, error) {
	// This would use DBus to call org.gnome.Shell.Introspect
	// Implementation requires dbus library
	return nil, errors.New("GNOME introspection not implemented")
}

// getKDEWindowInfo tries to get window info via KWin DBus.
func (t *linuxFocusTracker) getKDEWindowInfo() (*WindowInfo, error) {
	// This would use DBus to call org.kde.KWin
	// Implementation requires dbus library
	return nil, errors.New("KDE introspection not implemented")
}

// enrichFromProc adds app info from /proc filesystem.
func (t *linuxFocusTracker) enrichFromProc(info *WindowInfo) {
	if info.PID <= 0 {
		return
	}

	// Get executable name
	exePath := fmt.Sprintf("/proc/%d/exe", info.PID)
	if target, err := os.Readlink(exePath); err == nil {
		if info.Application == "" {
			info.Application = filepath.Base(target)
		}
	}

	// Get comm (short process name)
	commPath := fmt.Sprintf("/proc/%d/comm", info.PID)
	if data, err := os.ReadFile(commPath); err == nil {
		comm := strings.TrimSpace(string(data))
		if info.Application == "" {
			info.Application = comm
		}
	}

	// Try to find document from open files
	fdDir := fmt.Sprintf("/proc/%d/fd", info.PID)
	if fds, err := os.ReadDir(fdDir); err == nil {
		for _, fd := range fds {
			linkPath := filepath.Join(fdDir, fd.Name())
			if target, err := os.Readlink(linkPath); err == nil {
				// Look for regular files that might be documents
				if fi, err := os.Stat(target); err == nil && fi.Mode().IsRegular() {
					ext := strings.ToLower(filepath.Ext(target))
					if isDocumentExt(ext) {
						info.Path = target
						info.IsDocument = true
						break
					}
				}
			}
		}
	}
}

// parsePathFromTitle extracts a file path from the window title.
func (t *linuxFocusTracker) parsePathFromTitle(title, app string) string {
	if title == "" {
		return ""
	}

	appLower := strings.ToLower(app)

	// VS Code: "filename.ext - FolderName - Visual Studio Code"
	if strings.Contains(appLower, "code") {
		parts := strings.Split(title, " - ")
		if len(parts) >= 2 {
			filename := strings.TrimSpace(parts[0])
			filename = strings.TrimPrefix(filename, "* ")
			if strings.HasPrefix(filename, "/") {
				return filename
			}
			return filename
		}
	}

	// Sublime Text: "filename.ext (path/to/folder) - Sublime Text"
	if strings.Contains(appLower, "sublime") {
		if idx := strings.Index(title, " ("); idx != -1 {
			if end := strings.Index(title[idx:], ")"); end != -1 {
				folder := title[idx+2 : idx+end]
				filename := title[:idx]
				return filepath.Join(folder, filename)
			}
		}
	}

	// Vim/Neovim: "filename.ext - VIM" or "filename.ext (+) - NVIM"
	if strings.Contains(appLower, "vim") || strings.Contains(appLower, "nvim") {
		parts := strings.Split(title, " - ")
		if len(parts) >= 1 {
			filename := strings.TrimSuffix(parts[0], " (+)")
			filename = strings.TrimSuffix(filename, " [+]")
			if strings.HasPrefix(filename, "/") {
				return filename
			}
			return filename
		}
	}

	// Gedit: "filename.ext - gedit"
	if strings.Contains(appLower, "gedit") {
		parts := strings.Split(title, " - ")
		if len(parts) >= 1 {
			return parts[0]
		}
	}

	// Kate: "filename.ext - Kate"
	if strings.Contains(appLower, "kate") {
		parts := strings.Split(title, " - ")
		if len(parts) >= 1 {
			return parts[0]
		}
	}

	// Emacs: "filename.ext"
	if strings.Contains(appLower, "emacs") {
		// Emacs might show buffer name or file path
		if strings.HasPrefix(title, "/") {
			if idx := strings.Index(title, " - "); idx != -1 {
				return title[:idx]
			}
			return title
		}
		return title
	}

	// Generic: if title looks like a path
	if strings.HasPrefix(title, "/") {
		if idx := strings.Index(title, " - "); idx != -1 {
			return title[:idx]
		}
		return title
	}

	// Generic: extract filename before separator
	if idx := strings.Index(title, " - "); idx != -1 {
		potential := strings.TrimSpace(title[:idx])
		if strings.Contains(potential, ".") && !strings.Contains(potential, " ") {
			return potential
		}
	}

	return ""
}

// detectProjectRoot attempts to detect the project/workspace root.
func (t *linuxFocusTracker) detectProjectRoot(info *WindowInfo) string {
	if info.Path == "" {
		return ""
	}

	// Walk up looking for project markers
	dir := filepath.Dir(info.Path)
	for dir != "/" && dir != "." {
		for _, marker := range []string{".git", "go.mod", "package.json", "Cargo.toml", "pom.xml", "Makefile"} {
			if _, err := os.Stat(filepath.Join(dir, marker)); err == nil {
				return dir
			}
		}
		dir = filepath.Dir(dir)
	}

	return ""
}

// isDocumentExt checks if a file extension is a known document type.
func isDocumentExt(ext string) bool {
	docExts := map[string]bool{
		".txt": true, ".md": true, ".rst": true, ".org": true, ".tex": true,
		".doc": true, ".docx": true, ".odt": true, ".rtf": true,
		".go": true, ".py": true, ".js": true, ".ts": true, ".rs": true,
		".c": true, ".cpp": true, ".h": true, ".java": true, ".rb": true,
		".sh": true, ".json": true, ".yaml": true, ".yml": true, ".toml": true,
		".xml": true, ".html": true, ".css": true, ".swift": true,
	}
	return docExts[ext]
}

// GetProcName returns the name of a process by PID.
func GetProcName(pid int) (string, error) {
	commPath := fmt.Sprintf("/proc/%d/comm", pid)
	data, err := os.ReadFile(commPath)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// GetProcCmdline returns the command line of a process by PID.
func GetProcCmdline(pid int) ([]string, error) {
	cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", pid)
	data, err := os.ReadFile(cmdlinePath)
	if err != nil {
		return nil, err
	}

	// Arguments are null-separated
	var args []string
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Split(func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		if atEOF && len(data) == 0 {
			return 0, nil, nil
		}
		for i, b := range data {
			if b == 0 {
				return i + 1, data[:i], nil
			}
		}
		if atEOF {
			return len(data), data, nil
		}
		return 0, nil, nil
	})
	for scanner.Scan() {
		args = append(args, scanner.Text())
	}

	return args, nil
}

// Ensure linuxFocusTracker implements FocusTracker
var _ FocusTracker = (*linuxFocusTracker)(nil)
