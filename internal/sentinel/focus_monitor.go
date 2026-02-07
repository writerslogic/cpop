//go:build !darwin && !linux && !windows

// Package sentinel focus monitoring interface.
//
// This file provides a null implementation for unsupported platforms.
// Platform-specific implementations are in focus_monitor_*.go files.
//
// Patent Pending: USPTO Application No. 19/460,364
package sentinel

import (
	"context"
	"runtime"
)

// newFocusMonitor creates a platform-specific focus monitor.
// This default implementation returns a null monitor for unsupported platforms.
func newFocusMonitor(cfg *Config) FocusMonitor {
	return &nullFocusMonitor{}
}

// nullFocusMonitor is a no-op implementation for unsupported platforms.
type nullFocusMonitor struct {
	focusEvents  chan FocusEvent
	changeEvents chan ChangeEvent
}

func (n *nullFocusMonitor) Start(ctx context.Context) error {
	n.focusEvents = make(chan FocusEvent, 10)
	n.changeEvents = make(chan ChangeEvent, 10)
	return nil
}

func (n *nullFocusMonitor) Stop() error {
	if n.focusEvents != nil {
		close(n.focusEvents)
	}
	if n.changeEvents != nil {
		close(n.changeEvents)
	}
	return nil
}

func (n *nullFocusMonitor) FocusEvents() <-chan FocusEvent {
	return n.focusEvents
}

func (n *nullFocusMonitor) ChangeEvents() <-chan ChangeEvent {
	return n.changeEvents
}

func (n *nullFocusMonitor) Available() (bool, string) {
	return false, "focus monitoring not available on " + runtime.GOOS
}
