//go:build linux

// Package sentinel provides automatic document tracking for witnessd.
//
// Patent Pending: USPTO Application No. 19/460,364
package sentinel

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ============================================================================
// Linux Focus Detection
// ============================================================================
//
// On Linux, we use multiple mechanisms depending on the display server:
//
// X11 (most common):
//   - xprop/xdotool for active window detection
//   - _NET_ACTIVE_WINDOW property monitoring
//   - /proc filesystem for process info
//
// Wayland (newer, limited support):
//   - D-Bus for some compositors (GNOME, KDE)
//   - Compositor-specific protocols
//   - Note: Wayland's security model limits window inspection
//
// File monitoring:
//   - inotify for file change detection
//
// ============================================================================

// linuxFocusMonitor implements FocusMonitor for Linux.
type linuxFocusMonitor struct {
	mu           sync.RWMutex
	config       *Config
	ctx          context.Context
	cancel       context.CancelFunc
	running      bool
	focusEvents  chan FocusEvent
	changeEvents chan ChangeEvent

	// inotify state
	inotifyFd    int
	watchDescrs  map[int]string // wd -> path
	watchedDirs  map[string]int // path -> wd

	// Display server
	displayType string // "x11", "wayland", or "unknown"
}

// newFocusMonitor creates the platform-specific focus monitor.
func newFocusMonitor(cfg *Config) FocusMonitor {
	return &linuxFocusMonitor{
		config:       cfg,
		focusEvents:  make(chan FocusEvent, 100),
		changeEvents: make(chan ChangeEvent, 100),
		watchDescrs:  make(map[int]string),
		watchedDirs:  make(map[string]int),
	}
}

// Start begins monitoring for focus changes.
func (m *linuxFocusMonitor) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return ErrAlreadyRunning
	}

	m.ctx, m.cancel = context.WithCancel(ctx)

	// Detect display server
	m.displayType = detectDisplayServer()

	// Initialize inotify
	fd, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		return fmt.Errorf("inotify_init: %w", err)
	}
	m.inotifyFd = fd

	// Add watch paths
	for _, path := range m.config.WatchPaths {
		if err := m.addWatchPath(path); err != nil {
			// Log but don't fail
		}
	}

	m.running = true

	// Start monitoring goroutines
	go m.focusLoop()
	go m.inotifyLoop()

	return nil
}

// Stop stops monitoring.
func (m *linuxFocusMonitor) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return nil
	}

	m.running = false

	if m.cancel != nil {
		m.cancel()
	}

	// Close inotify
	if m.inotifyFd > 0 {
		unix.Close(m.inotifyFd)
		m.inotifyFd = 0
	}

	close(m.focusEvents)
	close(m.changeEvents)

	return nil
}

// FocusEvents returns the channel of focus events.
func (m *linuxFocusMonitor) FocusEvents() <-chan FocusEvent {
	return m.focusEvents
}

// ChangeEvents returns the channel of change events.
func (m *linuxFocusMonitor) ChangeEvents() <-chan ChangeEvent {
	return m.changeEvents
}

// Available checks if focus monitoring is available.
func (m *linuxFocusMonitor) Available() (bool, string) {
	displayType := detectDisplayServer()

	switch displayType {
	case "x11":
		// Check if xprop/xdotool is available
		if _, err := exec.LookPath("xdotool"); err == nil {
			return true, "X11 focus monitoring available (xdotool)"
		}
		if _, err := exec.LookPath("xprop"); err == nil {
			return true, "X11 focus monitoring available (xprop)"
		}
		return false, "X11 detected but xdotool/xprop not found. Install xdotool: sudo apt install xdotool"

	case "wayland":
		// Wayland support is limited
		return false, "Wayland detected. Focus monitoring has limited support on Wayland due to security restrictions. Consider running under XWayland."

	default:
		return false, "Unknown display server. Focus monitoring requires X11 or limited Wayland support."
	}
}

// detectDisplayServer determines if we're running on X11 or Wayland.
func detectDisplayServer() string {
	// Check for Wayland
	if os.Getenv("WAYLAND_DISPLAY") != "" {
		// Could be XWayland
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

// focusLoop monitors for window focus changes.
func (m *linuxFocusMonitor) focusLoop() {
	ticker := time.NewTicker(time.Duration(m.config.DebounceDuration))
	defer ticker.Stop()

	var lastWindowID string
	var lastFocusEvent FocusEvent

	for {
		select {
		case <-m.ctx.Done():
			return

		case <-ticker.C:
			// Get current focus
			windowID, info, err := m.getActiveWindowInfo()
			if err != nil {
				continue
			}

			// Check if focus changed
			if windowID != lastWindowID {
				// Emit focus lost for previous
				if lastWindowID != "" && lastFocusEvent.Path != "" {
					lostEvent := FocusEvent{
						Type:        FocusLost,
						Path:        lastFocusEvent.Path,
						AppBundleID: lastFocusEvent.AppBundleID,
						AppName:     lastFocusEvent.AppName,
					}
					m.emitFocusEvent(lostEvent)
				}

				// Emit focus gained for new
				if info != nil {
					event := FocusEvent{
						Type:        FocusGained,
						Path:        info.documentPath,
						AppBundleID: info.appID,
						AppName:     info.appName,
						WindowTitle: info.windowTitle,
					}
					m.emitFocusEvent(event)
					lastFocusEvent = event
				}

				lastWindowID = windowID
			}
		}
	}
}

// windowInfo holds information about a window.
type windowInfo struct {
	windowID     string
	windowTitle  string
	appName      string
	appID        string
	pid          int
	documentPath string
}

// getActiveWindowInfo gets information about the currently focused window.
func (m *linuxFocusMonitor) getActiveWindowInfo() (string, *windowInfo, error) {
	switch m.displayType {
	case "x11":
		return m.getActiveWindowX11()
	case "wayland":
		return m.getActiveWindowWayland()
	default:
		return "", nil, errors.New("unsupported display server")
	}
}

// getActiveWindowX11 gets active window info using X11 tools.
func (m *linuxFocusMonitor) getActiveWindowX11() (string, *windowInfo, error) {
	// Try xdotool first (more reliable)
	if windowID, info, err := m.getActiveWindowXdotool(); err == nil {
		return windowID, info, nil
	}

	// Fallback to xprop
	return m.getActiveWindowXprop()
}

// getActiveWindowXdotool uses xdotool to get window info.
func (m *linuxFocusMonitor) getActiveWindowXdotool() (string, *windowInfo, error) {
	// Get active window ID
	out, err := exec.Command("xdotool", "getactivewindow").Output()
	if err != nil {
		return "", nil, err
	}
	windowID := strings.TrimSpace(string(out))

	info := &windowInfo{windowID: windowID}

	// Get window name
	if out, err := exec.Command("xdotool", "getwindowname", windowID).Output(); err == nil {
		info.windowTitle = strings.TrimSpace(string(out))
	}

	// Get window PID
	if out, err := exec.Command("xdotool", "getwindowpid", windowID).Output(); err == nil {
		if pid, err := strconv.Atoi(strings.TrimSpace(string(out))); err == nil {
			info.pid = pid
			// Get app info from /proc
			m.enrichFromProc(info)
		}
	}

	// Try to extract document path from window title
	info.documentPath = m.parseDocumentPath(info.windowTitle, info.appName)

	return windowID, info, nil
}

// getActiveWindowXprop uses xprop to get window info.
func (m *linuxFocusMonitor) getActiveWindowXprop() (string, *windowInfo, error) {
	// Get active window
	out, err := exec.Command("xprop", "-root", "_NET_ACTIVE_WINDOW").Output()
	if err != nil {
		return "", nil, err
	}

	// Parse window ID from "window id # 0x12345"
	parts := strings.Fields(string(out))
	if len(parts) < 5 {
		return "", nil, errors.New("failed to parse xprop output")
	}
	windowID := parts[len(parts)-1]

	info := &windowInfo{windowID: windowID}

	// Get window properties
	if out, err := exec.Command("xprop", "-id", windowID, "WM_NAME", "WM_CLASS", "_NET_WM_PID").Output(); err == nil {
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "WM_NAME") {
				// WM_NAME(STRING) = "Document - App"
				if idx := strings.Index(line, "= \""); idx != -1 {
					end := strings.LastIndex(line, "\"")
					if end > idx+3 {
						info.windowTitle = line[idx+3 : end]
					}
				}
			} else if strings.HasPrefix(line, "WM_CLASS") {
				// WM_CLASS(STRING) = "instance", "class"
				if idx := strings.Index(line, ", \""); idx != -1 {
					end := strings.LastIndex(line, "\"")
					if end > idx+3 {
						info.appName = line[idx+3 : end]
					}
				}
			} else if strings.HasPrefix(line, "_NET_WM_PID") {
				// _NET_WM_PID(CARDINAL) = 12345
				if idx := strings.Index(line, "= "); idx != -1 {
					if pid, err := strconv.Atoi(strings.TrimSpace(line[idx+2:])); err == nil {
						info.pid = pid
						m.enrichFromProc(info)
					}
				}
			}
		}
	}

	info.documentPath = m.parseDocumentPath(info.windowTitle, info.appName)

	return windowID, info, nil
}

// getActiveWindowWayland attempts to get window info on Wayland.
func (m *linuxFocusMonitor) getActiveWindowWayland() (string, *windowInfo, error) {
	// Wayland doesn't provide a standard way to get window info
	// due to security/privacy design. This is a known limitation.
	//
	// Some compositors provide DBus interfaces:
	// - GNOME: org.gnome.Shell.Introspect
	// - KDE: org.kde.KWin
	//
	// For now, we return an error indicating limited support.

	return "", nil, errors.New("wayland focus detection not implemented")
}

// enrichFromProc adds app info from /proc filesystem.
func (m *linuxFocusMonitor) enrichFromProc(info *windowInfo) {
	if info.pid <= 0 {
		return
	}

	// Get executable name
	exePath := fmt.Sprintf("/proc/%d/exe", info.pid)
	if target, err := os.Readlink(exePath); err == nil {
		info.appID = target
		if info.appName == "" {
			info.appName = filepath.Base(target)
		}
	}

	// Try to get working directory (might help with document path)
	cwdPath := fmt.Sprintf("/proc/%d/cwd", info.pid)
	if cwd, err := os.Readlink(cwdPath); err == nil {
		// Could use this to resolve relative paths in window title
		_ = cwd
	}

	// Try to get open files (might contain document path)
	fdDir := fmt.Sprintf("/proc/%d/fd", info.pid)
	if fds, err := os.ReadDir(fdDir); err == nil {
		for _, fd := range fds {
			linkPath := filepath.Join(fdDir, fd.Name())
			if target, err := os.Readlink(linkPath); err == nil {
				// Look for regular files that might be documents
				if fi, err := os.Stat(target); err == nil && fi.Mode().IsRegular() {
					// Check if it's a common document extension
					ext := strings.ToLower(filepath.Ext(target))
					if isDocumentExtension(ext) {
						info.documentPath = target
						break
					}
				}
			}
		}
	}
}

// parseDocumentPath extracts document path from window title.
func (m *linuxFocusMonitor) parseDocumentPath(title, appName string) string {
	if title == "" {
		return ""
	}

	appLower := strings.ToLower(appName)

	// VS Code: "filename.ext - FolderName - Visual Studio Code"
	if strings.Contains(appLower, "code") || strings.Contains(appLower, "vscode") {
		parts := strings.Split(title, " - ")
		if len(parts) >= 2 {
			filename := parts[0]
			// If it looks like a path, use it
			if strings.HasPrefix(filename, "/") {
				return filename
			}
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
	if strings.Contains(appLower, "vim") {
		parts := strings.Split(title, " - ")
		if len(parts) >= 1 {
			filename := strings.TrimSuffix(parts[0], " (+)")
			filename = strings.TrimSuffix(filename, " [+]")
			if strings.HasPrefix(filename, "/") {
				return filename
			}
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

	// Generic: if title looks like a path
	if strings.HasPrefix(title, "/") {
		// Take the path part
		if idx := strings.Index(title, " - "); idx != -1 {
			return title[:idx]
		}
		return title
	}

	return ""
}

// isDocumentExtension checks if a file extension is a known document type.
func isDocumentExtension(ext string) bool {
	docExts := map[string]bool{
		".txt":  true,
		".md":   true,
		".rst":  true,
		".org":  true,
		".tex":  true,
		".doc":  true,
		".docx": true,
		".odt":  true,
		".rtf":  true,
		".go":   true,
		".py":   true,
		".js":   true,
		".ts":   true,
		".rs":   true,
		".c":    true,
		".cpp":  true,
		".h":    true,
		".java": true,
		".rb":   true,
		".sh":   true,
		".json": true,
		".yaml": true,
		".yml":  true,
		".toml": true,
		".xml":  true,
		".html": true,
		".css":  true,
	}
	return docExts[ext]
}

// emitFocusEvent sends a focus event to the channel.
func (m *linuxFocusMonitor) emitFocusEvent(event FocusEvent) {
	event.Timestamp = time.Now()
	select {
	case m.focusEvents <- event:
	default:
		// Channel full
	}
}

// ============================================================================
// inotify File Monitoring
// ============================================================================

// addWatchPath adds a directory to inotify monitoring.
func (m *linuxFocusMonitor) addWatchPath(path string) error {
	// Check if it's a directory
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}

	if fi.IsDir() {
		// Watch directory
		wd, err := unix.InotifyAddWatch(m.inotifyFd, path,
			unix.IN_MODIFY|unix.IN_CREATE|unix.IN_DELETE|unix.IN_CLOSE_WRITE|unix.IN_MOVED_TO)
		if err != nil {
			return err
		}
		m.watchDescrs[wd] = path
		m.watchedDirs[path] = wd

		// Optionally watch subdirectories
		if m.config.RecursiveWatch {
			filepath.Walk(path, func(subpath string, info os.FileInfo, err error) error {
				if err != nil || !info.IsDir() || subpath == path {
					return nil
				}
				m.addWatchPath(subpath)
				return nil
			})
		}
	} else {
		// Watch parent directory for file
		dir := filepath.Dir(path)
		wd, err := unix.InotifyAddWatch(m.inotifyFd, dir,
			unix.IN_MODIFY|unix.IN_CREATE|unix.IN_DELETE|unix.IN_CLOSE_WRITE|unix.IN_MOVED_TO)
		if err != nil {
			return err
		}
		m.watchDescrs[wd] = dir
		m.watchedDirs[dir] = wd
	}

	return nil
}

// inotifyLoop reads and processes inotify events.
func (m *linuxFocusMonitor) inotifyLoop() {
	buf := make([]byte, 4096)

	for {
		select {
		case <-m.ctx.Done():
			return
		default:
		}

		n, err := unix.Read(m.inotifyFd, buf)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EINTR {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			return
		}

		if n < unix.SizeofInotifyEvent {
			continue
		}

		// Parse events
		offset := 0
		for offset < n {
			event := (*unix.InotifyEvent)(unsafe.Pointer(&buf[offset]))

			// Get filename from event
			var filename string
			if event.Len > 0 {
				nameBytes := buf[offset+unix.SizeofInotifyEvent : offset+unix.SizeofInotifyEvent+int(event.Len)]
				// Find null terminator
				for i, b := range nameBytes {
					if b == 0 {
						filename = string(nameBytes[:i])
						break
					}
				}
			}

			// Get directory path
			m.mu.RLock()
			dirPath, ok := m.watchDescrs[int(event.Wd)]
			m.mu.RUnlock()

			if ok && filename != "" {
				fullPath := filepath.Join(dirPath, filename)
				m.handleInotifyEvent(fullPath, event.Mask)
			}

			offset += unix.SizeofInotifyEvent + int(event.Len)
		}
	}
}

// handleInotifyEvent processes a single inotify event.
func (m *linuxFocusMonitor) handleInotifyEvent(path string, mask uint32) {
	var eventType ChangeEventType

	switch {
	case mask&unix.IN_CREATE != 0 || mask&unix.IN_MOVED_TO != 0:
		eventType = ChangeCreated
	case mask&unix.IN_DELETE != 0:
		eventType = ChangeDeleted
	case mask&unix.IN_CLOSE_WRITE != 0:
		eventType = ChangeSaved
	case mask&unix.IN_MODIFY != 0:
		eventType = ChangeModified
	default:
		return
	}

	// Compute hash for modified/saved files
	var hash string
	var size int64
	if eventType == ChangeSaved || eventType == ChangeModified {
		if h, s, err := defaultHashFile(path); err == nil {
			hash = h
			size = s
		}
	}

	event := ChangeEvent{
		Type:      eventType,
		Path:      path,
		Hash:      hash,
		Size:      size,
		Timestamp: time.Now(),
	}

	select {
	case m.changeEvents <- event:
	default:
		// Channel full
	}
}

// ============================================================================
// Utility Functions
// ============================================================================

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
