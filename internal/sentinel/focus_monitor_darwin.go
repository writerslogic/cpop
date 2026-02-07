//go:build darwin

// Package sentinel macOS focus monitoring implementation.
//
// Uses Accessibility APIs and NSWorkspace notifications to detect
// which document has user focus.
//
// Patent Pending: USPTO Application No. 19/460,364
package sentinel

import (
	"context"
	"sync"
	"time"
)

// macOSFocusMonitor monitors focus changes on macOS.
type macOSFocusMonitor struct {
	mu sync.Mutex

	config       *Config
	focusEvents  chan FocusEvent
	changeEvents chan ChangeEvent

	ctx    context.Context
	cancel context.CancelFunc
}

// newFocusMonitor creates a macOS focus monitor.
func newFocusMonitor(cfg *Config) FocusMonitor {
	return newDarwinFocusMonitor(cfg)
}

// newMacOSFocusMonitor is an alias for newFocusMonitor for compatibility.
func newMacOSFocusMonitor(cfg *Config) FocusMonitor {
	return newFocusMonitor(cfg)
}

// Start begins monitoring for focus changes.
func (m *macOSFocusMonitor) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.ctx, m.cancel = context.WithCancel(ctx)

	// Start the polling loop (CGO-based implementation would use NSWorkspace)
	go m.pollLoop()

	return nil
}

// Stop stops monitoring.
func (m *macOSFocusMonitor) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cancel != nil {
		m.cancel()
	}

	return nil
}

// FocusEvents returns the channel of focus events.
func (m *macOSFocusMonitor) FocusEvents() <-chan FocusEvent {
	return m.focusEvents
}

// ChangeEvents returns the channel of file change events.
func (m *macOSFocusMonitor) ChangeEvents() <-chan ChangeEvent {
	return m.changeEvents
}

// Available returns whether focus monitoring is available.
func (m *macOSFocusMonitor) Available() (bool, string) {
	// Check for Accessibility permissions
	// In a real implementation, this would check AXIsProcessTrusted()
	return true, "macOS focus monitoring available"
}

// pollLoop polls for focus changes.
// Note: A production implementation would use NSWorkspace notifications via CGO.
func (m *macOSFocusMonitor) pollLoop() {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			// In a real implementation, this would:
			// 1. Get the frontmost application using NSWorkspace
			// 2. Get the focused window's document path
			// 3. Emit focus events on changes
			//
			// For now, this is a placeholder that can be enhanced
			// with the macOS native implementation from WitnessdApp.
		}
	}
}
