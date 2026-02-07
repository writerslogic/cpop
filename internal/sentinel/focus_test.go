// Package sentinel focus tracker tests.
//
// Patent Pending: USPTO Application No. 19/460,364
package sentinel

import (
	"context"
	"testing"
	"time"
)

func TestWindowInfo(t *testing.T) {
	info := WindowInfo{
		Path:        "/test/document.txt",
		Application: "com.test.app",
		Title:       "document.txt - Test App",
		PID:         12345,
		Timestamp:   time.Now(),
		IsDocument:  true,
		IsUnsaved:   false,
		ProjectRoot: "/test",
	}

	if info.Path != "/test/document.txt" {
		t.Error("path mismatch")
	}
	if info.Application != "com.test.app" {
		t.Error("application mismatch")
	}
	if !info.IsDocument {
		t.Error("IsDocument should be true")
	}
	if info.IsUnsaved {
		t.Error("IsUnsaved should be false")
	}
}

func TestDefaultFocusTrackerConfig(t *testing.T) {
	config := DefaultFocusTrackerConfig()

	if config.PollInterval != 100*time.Millisecond {
		t.Errorf("unexpected poll interval: %v", config.PollInterval)
	}
	if config.DebounceInterval != 200*time.Millisecond {
		t.Errorf("unexpected debounce interval: %v", config.DebounceInterval)
	}
	if len(config.IgnoredApplications) == 0 {
		t.Error("expected some ignored applications")
	}
}

func TestBaseFocusTrackerShouldEmit(t *testing.T) {
	config := DefaultFocusTrackerConfig()
	config.DebounceInterval = 50 * time.Millisecond
	base := newBaseFocusTracker(config)

	info1 := WindowInfo{
		Path:        "/test/doc1.txt",
		Application: "TestApp",
		Title:       "doc1.txt",
	}

	// First emission should work
	if !base.shouldEmit(info1) {
		t.Error("first emission should be allowed")
	}

	// Simulate emission
	base.lastFocus = &info1
	base.lastEmit = time.Now()

	// Same info within debounce should not emit
	if base.shouldEmit(info1) {
		t.Error("same info within debounce should not emit")
	}

	// Wait for debounce
	time.Sleep(60 * time.Millisecond)

	// Different info should emit
	info2 := WindowInfo{
		Path:        "/test/doc2.txt",
		Application: "TestApp",
		Title:       "doc2.txt",
	}
	if !base.shouldEmit(info2) {
		t.Error("different info after debounce should emit")
	}
}

func TestBaseFocusTrackerEmit(t *testing.T) {
	config := DefaultFocusTrackerConfig()
	config.IgnoredApplications = []string{"ignored.app"}
	base := newBaseFocusTracker(config)

	// Test ignored application
	ignoredInfo := WindowInfo{
		Path:        "/test/doc.txt",
		Application: "ignored.app",
		Title:       "doc.txt",
	}

	if base.emit(ignoredInfo) {
		t.Error("ignored application should not emit")
	}

	// Test valid emission
	validInfo := WindowInfo{
		Path:        "/test/doc.txt",
		Application: "valid.app",
		Title:       "doc.txt",
	}

	if !base.emit(validInfo) {
		t.Error("valid info should emit")
	}

	// Verify it was received
	select {
	case info := <-base.focusCh:
		if info.Path != "/test/doc.txt" {
			t.Error("path mismatch")
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("expected to receive focus change")
	}
}

func TestMatchWildcard(t *testing.T) {
	tests := []struct {
		pattern string
		s       string
		want    bool
	}{
		{"*", "anything", true},
		{"*", "", true},
		{"", "", true},
		{"", "something", false},
		{"*.tmp", "file.tmp", true},
		{"*.tmp", "file.txt", false},
		{"Untitled*", "Untitled", true},
		{"Untitled*", "Untitled 1", true},
		{"Untitled*", "Document", false},
		{"exact", "exact", true},
		{"exact", "not exact", false},
	}

	for _, tc := range tests {
		got := matchWildcard(tc.pattern, tc.s)
		if got != tc.want {
			t.Errorf("matchWildcard(%q, %q) = %v, want %v", tc.pattern, tc.s, got, tc.want)
		}
	}
}

func TestNewFocusTracker(t *testing.T) {
	tracker := NewFocusTracker(100 * time.Millisecond)
	if tracker == nil {
		t.Fatal("NewFocusTracker returned nil")
	}

	// Check availability (varies by platform)
	available, msg := tracker.Available()
	t.Logf("Focus tracker available: %v (%s)", available, msg)
}

func TestNewFocusTrackerWithConfig(t *testing.T) {
	config := FocusTrackerConfig{
		PollInterval:        50 * time.Millisecond,
		DebounceInterval:    100 * time.Millisecond,
		IgnoredApplications: []string{"test.app"},
	}

	tracker := NewFocusTrackerWithConfig(config)
	if tracker == nil {
		t.Fatal("NewFocusTrackerWithConfig returned nil")
	}
}

// MockFocusTracker for testing
type MockFocusTracker struct {
	*baseFocusTracker
	running bool
	current *WindowInfo
}

func NewMockFocusTracker() *MockFocusTracker {
	return &MockFocusTracker{
		baseFocusTracker: newBaseFocusTracker(DefaultFocusTrackerConfig()),
	}
}

func (m *MockFocusTracker) Start(ctx context.Context) error {
	m.ctx, m.cancel = context.WithCancel(ctx)
	m.running = true
	return nil
}

func (m *MockFocusTracker) Stop() error {
	if m.cancel != nil {
		m.cancel()
	}
	m.running = false
	m.close()
	return nil
}

func (m *MockFocusTracker) ActiveWindow() *WindowInfo {
	return m.current
}

func (m *MockFocusTracker) Available() (bool, string) {
	return true, "mock focus tracker"
}

func (m *MockFocusTracker) SetActiveWindow(info *WindowInfo) {
	m.current = info
	if info != nil {
		m.emit(*info)
	}
}

func TestMockFocusTracker(t *testing.T) {
	mock := NewMockFocusTracker()

	// Test start/stop
	ctx := context.Background()
	if err := mock.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	if !mock.running {
		t.Error("expected running to be true")
	}

	// Test active window
	info := &WindowInfo{
		Path:        "/test/doc.txt",
		Application: "TestApp",
	}
	mock.SetActiveWindow(info)

	active := mock.ActiveWindow()
	if active == nil || active.Path != "/test/doc.txt" {
		t.Error("active window mismatch")
	}

	// Test availability
	available, msg := mock.Available()
	if !available {
		t.Error("mock should be available")
	}
	if msg != "mock focus tracker" {
		t.Error("unexpected availability message")
	}

	// Test stop
	if err := mock.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	if mock.running {
		t.Error("expected running to be false")
	}
}

func TestFocusChangesChannel(t *testing.T) {
	mock := NewMockFocusTracker()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := mock.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer mock.Stop()

	// Get the channel
	ch := mock.FocusChanges()
	if ch == nil {
		t.Fatal("FocusChanges returned nil")
	}

	// Send an event
	info := WindowInfo{
		Path:        "/test/doc.txt",
		Application: "TestApp",
	}
	mock.SetActiveWindow(&info)

	// Verify we receive it
	select {
	case received := <-ch:
		if received.Path != "/test/doc.txt" {
			t.Error("path mismatch")
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("expected to receive focus change")
	}
}

func BenchmarkFocusTrackerEmit(b *testing.B) {
	config := DefaultFocusTrackerConfig()
	config.DebounceInterval = 0 // Disable debounce for benchmark
	base := newBaseFocusTracker(config)

	info := WindowInfo{
		Path:        "/test/doc.txt",
		Application: "TestApp",
		Title:       "doc.txt",
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Change something to force emission
		info.Path = "/test/doc" + string(rune('0'+i%10)) + ".txt"
		base.emit(info)

		// Drain channel to prevent blocking
		select {
		case <-base.focusCh:
		default:
		}
	}
}
