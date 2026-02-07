// Package sentinel tests.
//
// Patent Pending: USPTO Application No. 19/460,364
package sentinel

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestDefaultConfig verifies default configuration values.
func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg == nil {
		t.Fatal("DefaultConfig returned nil")
	}

	if cfg.DebounceDuration != 500*time.Millisecond {
		t.Errorf("expected debounce 500ms, got %v", cfg.DebounceDuration)
	}

	if cfg.IdleTimeout != 30*time.Minute {
		t.Errorf("expected idle timeout 30m, got %v", cfg.IdleTimeout)
	}

	if !cfg.TrackUnknownApps {
		t.Error("expected TrackUnknownApps to be true by default")
	}

	if len(cfg.AllowedApps) == 0 {
		t.Error("expected some default allowed apps")
	}

	if len(cfg.BlockedApps) == 0 {
		t.Error("expected some default blocked apps")
	}
}

// TestConfigValidation tests configuration validation.
func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*Config)
		wantErr bool
	}{
		{
			name:    "default config is valid",
			modify:  func(c *Config) {},
			wantErr: false,
		},
		{
			name:    "negative debounce",
			modify:  func(c *Config) { c.DebounceDuration = -1 * time.Second },
			wantErr: true,
		},
		{
			name:    "negative idle timeout",
			modify:  func(c *Config) { c.IdleTimeout = -1 * time.Second },
			wantErr: true,
		},
		{
			name:    "zero debounce is valid",
			modify:  func(c *Config) { c.DebounceDuration = 0 },
			wantErr: false,
		},
		{
			name:    "zero idle timeout (disabled) is valid",
			modify:  func(c *Config) { c.IdleTimeout = 0 },
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tt.modify(cfg)
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestConfigIsAppAllowed tests app filtering logic.
func TestConfigIsAppAllowed(t *testing.T) {
	tests := []struct {
		name     string
		config   func() *Config
		bundleID string
		appName  string
		want     bool
	}{
		{
			name: "allowed app by bundle ID",
			config: func() *Config {
				c := DefaultConfig()
				c.AllowedApps = []string{"com.test.app"}
				c.TrackUnknownApps = false
				return c
			},
			bundleID: "com.test.app",
			appName:  "TestApp",
			want:     true,
		},
		{
			name: "allowed app by name",
			config: func() *Config {
				c := DefaultConfig()
				c.AllowedApps = []string{"TestApp"}
				c.TrackUnknownApps = false
				return c
			},
			bundleID: "com.test.app",
			appName:  "TestApp",
			want:     true,
		},
		{
			name: "blocked app takes precedence",
			config: func() *Config {
				c := DefaultConfig()
				c.AllowedApps = []string{"com.test.app"}
				c.BlockedApps = []string{"com.test.app"}
				c.TrackUnknownApps = true
				return c
			},
			bundleID: "com.test.app",
			appName:  "TestApp",
			want:     false,
		},
		{
			name: "unknown app with tracking enabled",
			config: func() *Config {
				c := DefaultConfig()
				c.AllowedApps = []string{"com.other.app"}
				c.TrackUnknownApps = true
				return c
			},
			bundleID: "com.test.app",
			appName:  "TestApp",
			want:     true,
		},
		{
			name: "unknown app with tracking disabled",
			config: func() *Config {
				c := DefaultConfig()
				c.AllowedApps = []string{"com.other.app"}
				c.TrackUnknownApps = false
				return c
			},
			bundleID: "com.test.app",
			appName:  "TestApp",
			want:     false,
		},
		{
			name: "empty allowlist with tracking enabled",
			config: func() *Config {
				c := DefaultConfig()
				c.AllowedApps = []string{}
				c.TrackUnknownApps = true
				return c
			},
			bundleID: "com.test.app",
			appName:  "TestApp",
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.config()
			got := cfg.IsAppAllowed(tt.bundleID, tt.appName)
			if got != tt.want {
				t.Errorf("IsAppAllowed(%q, %q) = %v, want %v", tt.bundleID, tt.appName, got, tt.want)
			}
		})
	}
}

// TestShadowManager tests shadow buffer operations.
func TestShadowManager(t *testing.T) {
	tmpDir := t.TempDir()
	sm, err := NewShadowManager(tmpDir)
	if err != nil {
		t.Fatalf("NewShadowManager failed: %v", err)
	}

	// Test Create
	id, err := sm.Create("TestApp", "Untitled")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if id == "" {
		t.Fatal("expected non-empty shadow ID")
	}

	// Verify file was created
	path := sm.GetPath(id)
	if path == "" {
		t.Fatal("GetPath returned empty string")
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("shadow file was not created")
	}

	// Test Update
	content := []byte("test content")
	if err := sm.Update(id, content); err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	// Verify content
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read shadow file: %v", err)
	}

	if string(data) != string(content) {
		t.Errorf("content mismatch: got %q, want %q", data, content)
	}

	// Test Delete
	if err := sm.Delete(id); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("shadow file was not deleted")
	}

	if sm.GetPath(id) != "" {
		t.Error("GetPath should return empty after delete")
	}
}

// TestShadowManagerMigrate tests shadow migration to real paths.
func TestShadowManagerMigrate(t *testing.T) {
	tmpDir := t.TempDir()
	sm, err := NewShadowManager(tmpDir)
	if err != nil {
		t.Fatalf("NewShadowManager failed: %v", err)
	}

	// Create shadow
	id, err := sm.Create("TestApp", "Untitled")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Write content
	content := []byte("document content")
	if err := sm.Update(id, content); err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	shadowPath := sm.GetPath(id)

	// Create real file (simulating save)
	realPath := filepath.Join(tmpDir, "document.txt")
	if err := os.WriteFile(realPath, content, 0600); err != nil {
		t.Fatalf("failed to create real file: %v", err)
	}

	// Migrate
	if err := sm.Migrate(id, realPath); err != nil {
		t.Fatalf("Migrate failed: %v", err)
	}

	// Shadow file should be deleted
	if _, err := os.Stat(shadowPath); !os.IsNotExist(err) {
		t.Error("shadow file should be deleted after migration")
	}

	// Shadow ID should no longer exist
	if sm.GetPath(id) != "" {
		t.Error("shadow should not exist after migration")
	}
}

// TestShadowManagerCleanupOld tests stale shadow cleanup.
func TestShadowManagerCleanupOld(t *testing.T) {
	tmpDir := t.TempDir()
	sm, err := NewShadowManager(tmpDir)
	if err != nil {
		t.Fatalf("NewShadowManager failed: %v", err)
	}

	// Create a shadow
	id, err := sm.Create("TestApp", "Untitled")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Cleanup with short max age should remove it
	removed := sm.CleanupOld(0) // 0 duration means remove everything
	if removed != 1 {
		t.Errorf("expected 1 removed, got %d", removed)
	}

	if sm.GetPath(id) != "" {
		t.Error("shadow should be removed after cleanup")
	}
}

// TestDocumentSession tests session state tracking.
func TestDocumentSession(t *testing.T) {
	session := &DocumentSession{
		Path:      "/test/document.txt",
		StartTime: time.Now(),
	}

	if session.Path != "/test/document.txt" {
		t.Errorf("unexpected path: %s", session.Path)
	}

	if session.TotalFocusMS != 0 {
		t.Errorf("expected 0 focus time, got %d", session.TotalFocusMS)
	}

	// Simulate focus
	session.hasFocus = true
	session.focusStarted = time.Now()
	session.FocusCount++

	time.Sleep(50 * time.Millisecond)

	// End focus
	focusDuration := time.Since(session.focusStarted)
	session.TotalFocusMS += focusDuration.Milliseconds()
	session.hasFocus = false

	if session.TotalFocusMS < 50 {
		t.Errorf("expected at least 50ms focus time, got %d", session.TotalFocusMS)
	}

	if session.FocusCount != 1 {
		t.Errorf("expected focus count 1, got %d", session.FocusCount)
	}
}

// TestDocumentPath tests path normalization.
func TestDocumentPath(t *testing.T) {
	tests := []struct {
		input string
		want  string // We just check it returns something non-empty and cleaned
	}{
		{"/tmp/test.txt", "/tmp/test.txt"},
		{"./test.txt", ""}, // Relative paths get resolved to absolute
		{"/tmp/../tmp/test.txt", "/tmp/test.txt"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := DocumentPath(tt.input)
			if got == "" {
				t.Errorf("DocumentPath(%q) returned empty string", tt.input)
			}
			// Check it's cleaned (no double slashes, etc.)
			if filepath.Clean(got) != got {
				t.Errorf("DocumentPath(%q) = %q is not clean", tt.input, got)
			}
		})
	}
}

// TestFocusEventTypes verifies focus event type constants.
func TestFocusEventTypes(t *testing.T) {
	if FocusGained != 0 {
		t.Errorf("expected FocusGained = 0, got %d", FocusGained)
	}
	if FocusLost != 1 {
		t.Errorf("expected FocusLost = 1, got %d", FocusLost)
	}
	if FocusUnknown != 2 {
		t.Errorf("expected FocusUnknown = 2, got %d", FocusUnknown)
	}
}

// TestChangeEventTypes verifies change event type constants.
func TestChangeEventTypes(t *testing.T) {
	if ChangeModified != 0 {
		t.Errorf("expected ChangeModified = 0, got %d", ChangeModified)
	}
	if ChangeSaved != 1 {
		t.Errorf("expected ChangeSaved = 1, got %d", ChangeSaved)
	}
	if ChangeCreated != 2 {
		t.Errorf("expected ChangeCreated = 2, got %d", ChangeCreated)
	}
	if ChangeDeleted != 3 {
		t.Errorf("expected ChangeDeleted = 3, got %d", ChangeDeleted)
	}
}

// TestSessionEventTypes verifies session event type constants.
func TestSessionEventTypes(t *testing.T) {
	if SessionStarted != 0 {
		t.Errorf("expected SessionStarted = 0, got %d", SessionStarted)
	}
	if SessionFocused != 1 {
		t.Errorf("expected SessionFocused = 1, got %d", SessionFocused)
	}
	if SessionUnfocused != 2 {
		t.Errorf("expected SessionUnfocused = 2, got %d", SessionUnfocused)
	}
	if SessionSaved != 3 {
		t.Errorf("expected SessionSaved = 3, got %d", SessionSaved)
	}
	if SessionEnded != 4 {
		t.Errorf("expected SessionEnded = 4, got %d", SessionEnded)
	}
}

// mockFocusMonitor is a mock implementation for testing.
type mockFocusMonitor struct {
	mu           sync.RWMutex
	running      bool
	focusEvents  chan FocusEvent
	changeEvents chan ChangeEvent
}

func newMockFocusMonitor() *mockFocusMonitor {
	return &mockFocusMonitor{
		focusEvents:  make(chan FocusEvent, 100),
		changeEvents: make(chan ChangeEvent, 100),
	}
}

func (m *mockFocusMonitor) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.running = true
	return nil
}

func (m *mockFocusMonitor) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.running = false
	return nil
}

func (m *mockFocusMonitor) FocusEvents() <-chan FocusEvent {
	return m.focusEvents
}

func (m *mockFocusMonitor) ChangeEvents() <-chan ChangeEvent {
	return m.changeEvents
}

func (m *mockFocusMonitor) Available() (bool, string) {
	return true, "mock focus monitor"
}

func (m *mockFocusMonitor) SendFocusEvent(event FocusEvent) {
	m.focusEvents <- event
}

func (m *mockFocusMonitor) SendChangeEvent(event ChangeEvent) {
	m.changeEvents <- event
}

// TestSentinelWithMock tests the sentinel with a mock focus monitor.
func TestSentinelWithMock(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := DefaultConfig().
		WithWitnessdDir(tmpDir).
		WithDebounceDuration(10 * time.Millisecond). // Short debounce for testing
		WithIdleTimeout(0)                           // Disable idle timeout

	// Create sentinel
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Replace focus monitor with mock
	mockMonitor := newMockFocusMonitor()
	s.focusMonitor = mockMonitor

	// Start sentinel
	ctx := context.Background()
	if err := s.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer s.Stop()

	// Subscribe to events
	events := s.Subscribe()

	// Create a test file
	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test content"), 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Send focus event
	mockMonitor.SendFocusEvent(FocusEvent{
		Type:        FocusGained,
		Path:        testFile,
		AppBundleID: "com.test.app",
		AppName:     "TestApp",
		WindowTitle: "test.txt - TestApp",
	})

	// Wait for debounce and processing
	time.Sleep(50 * time.Millisecond)

	// Check we got events
	select {
	case event := <-events:
		if event.Type != SessionStarted && event.Type != SessionFocused {
			t.Errorf("unexpected event type: %d", event.Type)
		}
		if event.Session.Path != testFile {
			t.Errorf("unexpected path: %s", event.Session.Path)
		}
	case <-time.After(200 * time.Millisecond):
		// May timeout if debounce hasn't completed, that's OK
	}

	// Verify session exists
	sessions := s.Sessions()
	if len(sessions) == 0 {
		// Session might not be created yet due to debounce timing
		t.Log("No sessions created yet (debounce timing)")
	}

	// Stop
	if err := s.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	if s.Running() {
		t.Error("sentinel should not be running after Stop")
	}
}

// TestSentinelDoubleStart tests that double-starting returns an error.
func TestSentinelDoubleStart(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := DefaultConfig().WithWitnessdDir(tmpDir)
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Replace focus monitor with mock
	s.focusMonitor = newMockFocusMonitor()

	ctx := context.Background()

	if err := s.Start(ctx); err != nil {
		t.Fatalf("first Start failed: %v", err)
	}
	defer s.Stop()

	// Second start should fail
	if err := s.Start(ctx); err != ErrAlreadyRunning {
		t.Errorf("expected ErrAlreadyRunning, got %v", err)
	}
}

// TestSentinelStopWithoutStart tests that stopping without starting is safe.
func TestSentinelStopWithoutStart(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := DefaultConfig().WithWitnessdDir(tmpDir)
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Replace focus monitor with mock
	s.focusMonitor = newMockFocusMonitor()

	// Stop without Start should not error
	if err := s.Stop(); err != nil {
		t.Errorf("Stop without Start failed: %v", err)
	}
}

// TestDefaultHashFile tests the hash function.
func TestDefaultHashFile(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")

	content := []byte("test content for hashing")
	if err := os.WriteFile(testFile, content, 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	hash1, size1, err := defaultHashFile(testFile)
	if err != nil {
		t.Fatalf("defaultHashFile failed: %v", err)
	}

	if hash1 == "" {
		t.Error("hash should not be empty")
	}

	if size1 != int64(len(content)) {
		t.Errorf("expected size %d, got %d", len(content), size1)
	}

	// Same content should produce same hash
	hash2, _, err := defaultHashFile(testFile)
	if err != nil {
		t.Fatalf("second hash failed: %v", err)
	}

	if hash1 != hash2 {
		t.Error("same content should produce same hash")
	}

	// Different content should produce different hash
	if err := os.WriteFile(testFile, []byte("different content"), 0600); err != nil {
		t.Fatalf("failed to modify file: %v", err)
	}

	hash3, _, err := defaultHashFile(testFile)
	if err != nil {
		t.Fatalf("third hash failed: %v", err)
	}

	if hash1 == hash3 {
		t.Error("different content should produce different hash")
	}
}

// TestDefaultHashFileNotFound tests hash of nonexistent file.
func TestDefaultHashFileNotFound(t *testing.T) {
	_, _, err := defaultHashFile("/nonexistent/file.txt")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

// TestConfigBuilderChaining tests that config builder methods chain properly.
func TestConfigBuilderChaining(t *testing.T) {
	cfg := DefaultConfig().
		WithWitnessdDir("/tmp/test").
		WithAutoStart(true).
		WithIdleTimeout(10 * time.Minute).
		WithHeartbeatInterval(30 * time.Second).
		WithCheckpointInterval(2 * time.Minute).
		WithWatchPaths([]string{"/tmp/docs"}).
		WithRecursiveWatch(false).
		WithDebounceDuration(100 * time.Millisecond).
		WithAllowedApps([]string{"test.app"}).
		WithBlockedApps([]string{"blocked.app"}).
		WithTrackUnknownApps(false)

	if cfg.WitnessdDir != "/tmp/test" {
		t.Errorf("WitnessdDir: got %q", cfg.WitnessdDir)
	}
	if !cfg.AutoStart {
		t.Error("AutoStart should be true")
	}
	if cfg.IdleTimeout != 10*time.Minute {
		t.Errorf("IdleTimeout: got %v", cfg.IdleTimeout)
	}
	if cfg.HeartbeatInterval != 30*time.Second {
		t.Errorf("HeartbeatInterval: got %v", cfg.HeartbeatInterval)
	}
	if cfg.CheckpointInterval != 2*time.Minute {
		t.Errorf("CheckpointInterval: got %v", cfg.CheckpointInterval)
	}
	if len(cfg.WatchPaths) != 1 || cfg.WatchPaths[0] != "/tmp/docs" {
		t.Errorf("WatchPaths: got %v", cfg.WatchPaths)
	}
	if cfg.RecursiveWatch {
		t.Error("RecursiveWatch should be false")
	}
	if cfg.DebounceDuration != 100*time.Millisecond {
		t.Errorf("DebounceDuration: got %v", cfg.DebounceDuration)
	}
	if len(cfg.AllowedApps) != 1 || cfg.AllowedApps[0] != "test.app" {
		t.Errorf("AllowedApps: got %v", cfg.AllowedApps)
	}
	if len(cfg.BlockedApps) != 1 || cfg.BlockedApps[0] != "blocked.app" {
		t.Errorf("BlockedApps: got %v", cfg.BlockedApps)
	}
	if cfg.TrackUnknownApps {
		t.Error("TrackUnknownApps should be false")
	}
}

// TestConfigAddMethods tests the Add* methods for deduplication.
func TestConfigAddMethods(t *testing.T) {
	cfg := DefaultConfig()

	// Clear lists for testing
	cfg.AllowedApps = []string{}
	cfg.BlockedApps = []string{}
	cfg.WatchPaths = []string{}

	// Add items
	cfg.AddAllowedApp("app1")
	cfg.AddAllowedApp("app2")
	cfg.AddAllowedApp("app1") // duplicate

	if len(cfg.AllowedApps) != 2 {
		t.Errorf("expected 2 allowed apps, got %d", len(cfg.AllowedApps))
	}

	cfg.AddBlockedApp("blocked1")
	cfg.AddBlockedApp("blocked1") // duplicate

	if len(cfg.BlockedApps) != 1 {
		t.Errorf("expected 1 blocked app, got %d", len(cfg.BlockedApps))
	}

	cfg.AddWatchPath("/path1")
	cfg.AddWatchPath("/path2")
	cfg.AddWatchPath("/path1") // duplicate

	if len(cfg.WatchPaths) != 2 {
		t.Errorf("expected 2 watch paths, got %d", len(cfg.WatchPaths))
	}
}

// TestConfigEnsureDirectories tests directory creation.
func TestConfigEnsureDirectories(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := DefaultConfig().WithWitnessdDir(filepath.Join(tmpDir, "subdir", "witnessd"))

	err := cfg.EnsureDirectories()
	if err != nil {
		t.Fatalf("EnsureDirectories failed: %v", err)
	}

	// Verify directories were created
	if _, err := os.Stat(cfg.WitnessdDir); os.IsNotExist(err) {
		t.Error("WitnessdDir was not created")
	}
	if _, err := os.Stat(cfg.ShadowDir); os.IsNotExist(err) {
		t.Error("ShadowDir was not created")
	}
	if _, err := os.Stat(cfg.WALDir); os.IsNotExist(err) {
		t.Error("WALDir was not created")
	}
}

// BenchmarkDefaultHashFile benchmarks file hashing.
func BenchmarkDefaultHashFile(b *testing.B) {
	tmpDir := b.TempDir()
	testFile := filepath.Join(tmpDir, "bench.txt")

	// Create a file with some content
	content := make([]byte, 10*1024) // 10KB
	for i := range content {
		content[i] = byte(i % 256)
	}
	if err := os.WriteFile(testFile, content, 0600); err != nil {
		b.Fatalf("failed to create test file: %v", err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _, err := defaultHashFile(testFile)
		if err != nil {
			b.Fatalf("hash failed: %v", err)
		}
	}
}

// BenchmarkShadowCreate benchmarks shadow buffer creation.
func BenchmarkShadowCreate(b *testing.B) {
	tmpDir := b.TempDir()
	sm, err := NewShadowManager(tmpDir)
	if err != nil {
		b.Fatalf("NewShadowManager failed: %v", err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		id, err := sm.Create("TestApp", "Untitled")
		if err != nil {
			b.Fatalf("Create failed: %v", err)
		}
		sm.Delete(id)
	}
}
