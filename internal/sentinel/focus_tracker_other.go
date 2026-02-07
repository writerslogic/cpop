//go:build !darwin && !linux && !windows

// Package sentinel fallback focus tracker for unsupported platforms.
//
// Patent Pending: USPTO Application No. 19/460,364
package sentinel

import (
	"context"
	"runtime"
)

// otherFocusTracker is a no-op implementation for unsupported platforms.
type otherFocusTracker struct {
	*baseFocusTracker
}

// newPlatformFocusTracker creates a no-op focus tracker for unsupported platforms.
func newPlatformFocusTracker(config FocusTrackerConfig) FocusTracker {
	return &otherFocusTracker{
		baseFocusTracker: newBaseFocusTracker(config),
	}
}

// Start is a no-op on unsupported platforms.
func (t *otherFocusTracker) Start(ctx context.Context) error {
	t.ctx, t.cancel = context.WithCancel(ctx)
	return nil
}

// Stop is a no-op on unsupported platforms.
func (t *otherFocusTracker) Stop() error {
	if t.cancel != nil {
		t.cancel()
	}
	t.close()
	return nil
}

// ActiveWindow always returns nil on unsupported platforms.
func (t *otherFocusTracker) ActiveWindow() *WindowInfo {
	return nil
}

// Available returns false on unsupported platforms.
func (t *otherFocusTracker) Available() (bool, string) {
	return false, "focus tracking not available on " + runtime.GOOS
}

// Ensure otherFocusTracker implements FocusTracker
var _ FocusTracker = (*otherFocusTracker)(nil)
