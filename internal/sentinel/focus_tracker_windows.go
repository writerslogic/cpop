//go:build windows

// Package sentinel Windows focus tracker implementation.
//
// Uses GetForegroundWindow, GetWindowText, and GetWindowThreadProcessId
// to detect which document/window has focus.
//
// Patent Pending: USPTO Application No. 19/460,364
package sentinel

import (
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var (
	user32                     = syscall.NewLazyDLL("user32.dll")
	kernel32                   = syscall.NewLazyDLL("kernel32.dll")
	psapi                      = syscall.NewLazyDLL("psapi.dll")
	procGetForegroundWindow    = user32.NewProc("GetForegroundWindow")
	procGetWindowTextW         = user32.NewProc("GetWindowTextW")
	procGetWindowTextLengthW   = user32.NewProc("GetWindowTextLengthW")
	procGetWindowThreadProcessId = user32.NewProc("GetWindowThreadProcessId")
	procOpenProcess            = kernel32.NewProc("OpenProcess")
	procCloseHandle            = kernel32.NewProc("CloseHandle")
	procGetModuleFileNameExW   = psapi.NewProc("GetModuleFileNameExW")
)

const (
	PROCESS_QUERY_INFORMATION = 0x0400
	PROCESS_VM_READ           = 0x0010
	MAX_PATH                  = 260
)

// windowsFocusTracker implements FocusTracker for Windows.
type windowsFocusTracker struct {
	*baseFocusTracker
	mu      sync.RWMutex
	running bool
	current *WindowInfo
	logger  *slog.Logger
}

// newPlatformFocusTracker creates a Windows-specific focus tracker.
func newPlatformFocusTracker(config FocusTrackerConfig) FocusTracker {
	return &windowsFocusTracker{
		baseFocusTracker: newBaseFocusTracker(config),
		logger:           slog.Default().With("component", "focus_tracker_windows"),
	}
}

// Start begins focus tracking.
func (t *windowsFocusTracker) Start(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.running {
		return ErrAlreadyRunning
	}

	t.ctx, t.cancel = context.WithCancel(ctx)
	t.running = true

	go t.pollLoop()

	t.logger.Info("windows focus tracker started",
		"poll_interval", t.config.PollInterval,
	)

	return nil
}

// Stop stops focus tracking.
func (t *windowsFocusTracker) Stop() error {
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
	t.logger.Info("windows focus tracker stopped")

	return nil
}

// ActiveWindow returns the currently focused window info.
func (t *windowsFocusTracker) ActiveWindow() *WindowInfo {
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
func (t *windowsFocusTracker) Available() (bool, string) {
	// Windows focus tracking is always available via Win32 API
	return true, "Windows focus tracking available via Win32 API"
}

// pollLoop periodically checks the focused window.
func (t *windowsFocusTracker) pollLoop() {
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
func (t *windowsFocusTracker) checkFocus() {
	info := t.getCurrentWindowInfo()
	if info == nil {
		return
	}

	t.mu.Lock()
	t.current = info
	t.mu.Unlock()

	t.emit(*info)
}

// getCurrentWindowInfo retrieves information about the currently focused window.
func (t *windowsFocusTracker) getCurrentWindowInfo() *WindowInfo {
	// Get foreground window handle
	hwnd, _, _ := procGetForegroundWindow.Call()
	if hwnd == 0 {
		return nil
	}

	info := &WindowInfo{
		Timestamp: time.Now(),
	}

	// Get window title
	info.Title = getWindowText(hwnd)

	// Get process ID
	var pid uint32
	procGetWindowThreadProcessId.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
	info.PID = int(pid)

	// Get process name/path
	if pid != 0 {
		info.Application = getProcessName(pid)
	}

	// Try to extract document path from title
	info.Path = t.parsePathFromTitle(info.Title, info.Application)
	if info.Path != "" {
		info.IsDocument = true
	}

	// Detect unsaved status from title
	if strings.HasPrefix(info.Title, "*") || strings.Contains(info.Title, " [Modified]") {
		info.IsUnsaved = true
	}

	// Detect project root
	info.ProjectRoot = t.detectProjectRoot(info)

	return info
}

// getWindowText retrieves the text of a window.
func getWindowText(hwnd uintptr) string {
	// Get text length
	length, _, _ := procGetWindowTextLengthW.Call(hwnd)
	if length == 0 {
		return ""
	}

	// Allocate buffer
	buf := make([]uint16, length+1)
	procGetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), length+1)

	return syscall.UTF16ToString(buf)
}

// getProcessName retrieves the executable name for a process.
func getProcessName(pid uint32) string {
	// Open process
	handle, _, _ := procOpenProcess.Call(
		PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,
		0,
		uintptr(pid),
	)
	if handle == 0 {
		return ""
	}
	defer procCloseHandle.Call(handle)

	// Get module filename
	buf := make([]uint16, MAX_PATH)
	length, _, _ := procGetModuleFileNameExW.Call(
		handle,
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		MAX_PATH,
	)

	if length == 0 {
		return ""
	}

	fullPath := syscall.UTF16ToString(buf)
	return filepath.Base(fullPath)
}

// parsePathFromTitle extracts a file path from the window title.
func (t *windowsFocusTracker) parsePathFromTitle(title, app string) string {
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
			// Check for full path
			if len(filename) > 2 && filename[1] == ':' {
				return filename
			}
			return filename
		}
	}

	// Sublime Text
	if strings.Contains(appLower, "sublime") {
		if idx := strings.Index(title, " - "); idx != -1 {
			filename := strings.TrimSpace(title[:idx])
			filename = strings.TrimPrefix(filename, "* ")
			return filename
		}
	}

	// Notepad++: "filename.ext - Notepad++"
	if strings.Contains(appLower, "notepad") {
		parts := strings.Split(title, " - ")
		if len(parts) >= 1 {
			filename := strings.TrimSpace(parts[0])
			filename = strings.TrimPrefix(filename, "*")
			return filename
		}
	}

	// Microsoft Word: "Document1 - Word"
	if strings.Contains(appLower, "winword") || strings.Contains(appLower, "word") {
		parts := strings.Split(title, " - ")
		if len(parts) >= 1 {
			return strings.TrimSpace(parts[0])
		}
	}

	// Visual Studio: "filename.ext - ProjectName - Microsoft Visual Studio"
	if strings.Contains(appLower, "devenv") {
		parts := strings.Split(title, " - ")
		if len(parts) >= 2 {
			return strings.TrimSpace(parts[0])
		}
	}

	// Generic Windows path detection
	if len(title) > 2 && title[1] == ':' && (title[2] == '\\' || title[2] == '/') {
		// Windows path like "C:\path\to\file.txt"
		if idx := strings.Index(title, " - "); idx != -1 {
			return title[:idx]
		}
		return title
	}

	// Generic: extract filename before separator
	if idx := strings.Index(title, " - "); idx != -1 {
		potential := strings.TrimSpace(title[:idx])
		potential = strings.TrimPrefix(potential, "*")
		if strings.Contains(potential, ".") && !strings.Contains(potential, " ") {
			return potential
		}
	}

	return ""
}

// detectProjectRoot attempts to detect the project/workspace root.
func (t *windowsFocusTracker) detectProjectRoot(info *WindowInfo) string {
	if info.Path == "" {
		return ""
	}

	// Normalize path separators
	path := filepath.Clean(info.Path)

	// Walk up looking for project markers
	dir := filepath.Dir(path)
	for {
		parent := filepath.Dir(dir)
		if parent == dir || dir == "" {
			break
		}

		// Check for project markers
		for _, marker := range []string{".git", ".vscode", ".vs", "go.mod", "package.json", "Cargo.toml", ".sln"} {
			markerPath := filepath.Join(dir, marker)
			if _, err := syscall.Stat(markerPath, nil); err == nil {
				return dir
			}
			// Also check with syscall.GetFileAttributes for better Windows compatibility
			p, _ := syscall.UTF16PtrFromString(markerPath)
			if attrs, err := syscall.GetFileAttributes(p); err == nil && attrs != syscall.INVALID_FILE_ATTRIBUTES {
				return dir
			}
		}

		dir = parent
	}

	return ""
}

// Ensure windowsFocusTracker implements FocusTracker
var _ FocusTracker = (*windowsFocusTracker)(nil)
