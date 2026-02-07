// Package sentinel focus tracking interface and common types.
//
// This file defines the cross-platform interface for active window focus tracking.
// Platform-specific implementations are in focus_darwin.go, focus_linux.go, and
// focus_windows.go files.
//
// Patent Pending: USPTO Application No. 19/460,364
package sentinel

import (
	"context"
	"time"
)

// WindowInfo contains information about the currently focused window.
type WindowInfo struct {
	// Path is the resolved file path of the document (if available).
	Path string

	// Application is the application name or bundle ID.
	Application string

	// Title is the window title.
	Title string

	// PID is the process ID of the owning application.
	PID int

	// Timestamp is when this focus info was captured.
	Timestamp time.Time

	// IsDocument indicates if this appears to be a document window.
	IsDocument bool

	// IsUnsaved indicates if the document appears to be unsaved.
	IsUnsaved bool

	// ProjectRoot is the project/workspace root if detected (for IDEs).
	ProjectRoot string
}

// FocusTracker tracks which window/document currently has focus.
// Platform-specific implementations provide the actual window detection.
type FocusTracker interface {
	// Start begins focus tracking.
	Start(ctx context.Context) error

	// Stop stops focus tracking.
	Stop() error

	// ActiveWindow returns information about the currently focused window.
	// Returns nil if no window is focused or if focus info is unavailable.
	ActiveWindow() *WindowInfo

	// FocusChanges returns a channel that receives focus change notifications.
	// The channel is closed when tracking stops.
	FocusChanges() <-chan WindowInfo

	// Available returns whether focus tracking is available on this platform.
	// The string contains a description of availability status.
	Available() (bool, string)
}

// FocusTrackerConfig configures the focus tracker behavior.
type FocusTrackerConfig struct {
	// PollInterval is how often to poll for focus changes (for polling-based implementations).
	PollInterval time.Duration

	// DebounceInterval is the minimum time between focus change events.
	DebounceInterval time.Duration

	// IgnoredApplications is a list of application IDs/names to ignore.
	IgnoredApplications []string

	// IgnoredTitles is a list of window title patterns to ignore.
	IgnoredTitles []string
}

// DefaultFocusTrackerConfig returns default configuration.
func DefaultFocusTrackerConfig() FocusTrackerConfig {
	return FocusTrackerConfig{
		PollInterval:     100 * time.Millisecond,
		DebounceInterval: 200 * time.Millisecond,
		IgnoredApplications: []string{
			// System utilities
			"com.apple.finder",
			"com.apple.Spotlight",
			"com.apple.SystemPreferences",
			"explorer.exe",
			"nautilus",
			"dolphin",
		},
		IgnoredTitles: nil,
	}
}

// baseFocusTracker provides common functionality for focus tracker implementations.
type baseFocusTracker struct {
	config      FocusTrackerConfig
	ctx         context.Context
	cancel      context.CancelFunc
	focusCh     chan WindowInfo
	lastFocus   *WindowInfo
	lastEmit    time.Time
}

// newBaseFocusTracker creates a new base focus tracker.
func newBaseFocusTracker(config FocusTrackerConfig) *baseFocusTracker {
	return &baseFocusTracker{
		config:  config,
		focusCh: make(chan WindowInfo, 50),
	}
}

// FocusChanges returns the focus change channel.
func (b *baseFocusTracker) FocusChanges() <-chan WindowInfo {
	return b.focusCh
}

// shouldEmit checks if a focus change event should be emitted (debouncing).
func (b *baseFocusTracker) shouldEmit(info WindowInfo) bool {
	// Check debounce interval
	if time.Since(b.lastEmit) < b.config.DebounceInterval {
		return false
	}

	// Check if this is actually a change
	if b.lastFocus != nil {
		if b.lastFocus.Path == info.Path &&
			b.lastFocus.Application == info.Application &&
			b.lastFocus.Title == info.Title {
			return false
		}
	}

	return true
}

// emit sends a focus change event if appropriate.
func (b *baseFocusTracker) emit(info WindowInfo) bool {
	if !b.shouldEmit(info) {
		return false
	}

	// Check if application is ignored
	for _, ignored := range b.config.IgnoredApplications {
		if info.Application == ignored {
			return false
		}
	}

	// Check if title matches ignored patterns
	for _, pattern := range b.config.IgnoredTitles {
		if matchWildcard(pattern, info.Title) {
			return false
		}
	}

	info.Timestamp = time.Now()

	// Send to channel (non-blocking)
	select {
	case b.focusCh <- info:
		copy := info
		b.lastFocus = &copy
		b.lastEmit = time.Now()
		return true
	default:
		// Channel full
		return false
	}
}

// close closes the focus channel.
func (b *baseFocusTracker) close() {
	if b.focusCh != nil {
		close(b.focusCh)
		b.focusCh = nil
	}
}

// matchWildcard does simple wildcard matching (supports * only).
func matchWildcard(pattern, s string) bool {
	if pattern == "" {
		return s == ""
	}
	if pattern == "*" {
		return true
	}
	// Simple implementation - for production use a proper glob library
	// This handles basic patterns like "*.tmp" or "Untitled*"
	if pattern[0] == '*' {
		// Match suffix
		suffix := pattern[1:]
		if len(s) >= len(suffix) {
			return s[len(s)-len(suffix):] == suffix
		}
		return false
	}
	if pattern[len(pattern)-1] == '*' {
		// Match prefix
		prefix := pattern[:len(pattern)-1]
		if len(s) >= len(prefix) {
			return s[:len(prefix)] == prefix
		}
		return false
	}
	// Exact match
	return pattern == s
}

// NewFocusTracker creates a platform-appropriate focus tracker.
func NewFocusTracker(pollInterval time.Duration) FocusTracker {
	config := DefaultFocusTrackerConfig()
	config.PollInterval = pollInterval
	return newPlatformFocusTracker(config)
}

// NewFocusTrackerWithConfig creates a focus tracker with custom configuration.
func NewFocusTrackerWithConfig(config FocusTrackerConfig) FocusTracker {
	return newPlatformFocusTracker(config)
}
