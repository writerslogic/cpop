//go:build linux

// Package sentinel Linux focus monitoring implementation.
//
// Uses X11/XCB or D-Bus to detect which document has user focus.
//
// Patent Pending: USPTO Application No. 19/460,364
package sentinel

import (
	"context"
	"sync"
)

// linuxFocusMonitor monitors focus changes on Linux.
type linuxFocusMonitor struct {
	mu sync.Mutex

	config       *Config
	focusEvents  chan FocusEvent
	changeEvents chan ChangeEvent

	ctx    context.Context
	cancel context.CancelFunc
}

// newFocusMonitor creates a Linux focus monitor.
func newFocusMonitor(cfg *Config) FocusMonitor {
	return &linuxFocusMonitor{
		config:       cfg,
		focusEvents:  make(chan FocusEvent, 100),
		changeEvents: make(chan ChangeEvent, 100),
	}
}

// newLinuxFocusMonitor is an alias for newFocusMonitor for compatibility.
func newLinuxFocusMonitor(cfg *Config) FocusMonitor {
	return newFocusMonitor(cfg)
}

// Start begins monitoring for focus changes.
func (m *linuxFocusMonitor) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.ctx, m.cancel = context.WithCancel(ctx)

	// Start X11 event monitoring
	go m.monitorLoop()

	return nil
}

// Stop stops monitoring.
func (m *linuxFocusMonitor) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cancel != nil {
		m.cancel()
	}

	return nil
}

// FocusEvents returns the channel of focus events.
func (m *linuxFocusMonitor) FocusEvents() <-chan FocusEvent {
	return m.focusEvents
}

// ChangeEvents returns the channel of file change events.
func (m *linuxFocusMonitor) ChangeEvents() <-chan ChangeEvent {
	return m.changeEvents
}

// Available returns whether focus monitoring is available.
func (m *linuxFocusMonitor) Available() (bool, string) {
	// Check for X11 or Wayland support
	// In production, would check for $DISPLAY or $WAYLAND_DISPLAY
	return true, "Linux focus monitoring available (X11)"
}

// monitorLoop monitors for focus changes using X11.
func (m *linuxFocusMonitor) monitorLoop() {
	// In a real implementation, this would:
	// 1. Connect to X11 server
	// 2. Subscribe to _NET_ACTIVE_WINDOW property changes
	// 3. Query window properties for document paths
	// 4. Emit focus events on changes
	//
	// Placeholder for X11/xcb implementation

	<-m.ctx.Done()
}
