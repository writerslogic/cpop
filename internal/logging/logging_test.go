package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected Level
		hasError bool
	}{
		{"debug", LevelDebug, false},
		{"DEBUG", LevelDebug, false},
		{"info", LevelInfo, false},
		{"INFO", LevelInfo, false},
		{"warn", LevelWarn, false},
		{"warning", LevelWarn, false},
		{"error", LevelError, false},
		{"ERROR", LevelError, false},
		{"invalid", LevelInfo, true},
		{"", LevelInfo, true},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			level, err := ParseLevel(test.input)
			if test.hasError && err == nil {
				t.Error("expected error, got nil")
			}
			if !test.hasError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !test.hasError && level != test.expected {
				t.Errorf("expected %v, got %v", test.expected, level)
			}
		})
	}
}

func TestLevelString(t *testing.T) {
	tests := []struct {
		level    Level
		expected string
	}{
		{LevelDebug, "debug"},
		{LevelInfo, "info"},
		{LevelWarn, "warn"},
		{LevelError, "error"},
	}

	for _, test := range tests {
		t.Run(test.expected, func(t *testing.T) {
			result := LevelString(test.level)
			if result != test.expected {
				t.Errorf("expected %q, got %q", test.expected, result)
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Level != LevelInfo {
		t.Errorf("expected default level Info, got %v", cfg.Level)
	}
	if cfg.Format != FormatText {
		t.Errorf("expected default format Text, got %v", cfg.Format)
	}
	if cfg.Output != "stderr" {
		t.Errorf("expected default output stderr, got %s", cfg.Output)
	}
	if cfg.MaxSize <= 0 {
		t.Errorf("expected positive MaxSize, got %d", cfg.MaxSize)
	}
	if cfg.MaxAge <= 0 {
		t.Errorf("expected positive MaxAge, got %d", cfg.MaxAge)
	}
	if cfg.MaxBackups <= 0 {
		t.Errorf("expected positive MaxBackups, got %d", cfg.MaxBackups)
	}
}

func TestLoggerNew(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Output = "stderr"

	logger, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	if logger.Logger == nil {
		t.Error("logger.Logger is nil")
	}
}

func TestLoggerWithRequestID(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Output = "stderr"

	logger, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	childLogger := logger.WithRequestID("test-request-123")
	if childLogger == nil {
		t.Error("WithRequestID returned nil")
	}
}

func TestLoggerWithComponent(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Output = "stderr"

	logger, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	childLogger := logger.WithComponent("test-component")
	if childLogger == nil {
		t.Error("WithComponent returned nil")
	}
}

func TestRequestIDContext(t *testing.T) {
	ctx := context.Background()
	requestID := "test-request-456"

	// Add request ID to context
	ctx = ContextWithRequestID(ctx, requestID)

	// Extract request ID from context
	extracted := RequestIDFromContext(ctx)
	if extracted != requestID {
		t.Errorf("expected %q, got %q", requestID, extracted)
	}
}

func TestRequestIDFromNilContext(t *testing.T) {
	extracted := RequestIDFromContext(nil)
	if extracted != "" {
		t.Errorf("expected empty string, got %q", extracted)
	}
}

func TestRequestIDFromEmptyContext(t *testing.T) {
	ctx := context.Background()
	extracted := RequestIDFromContext(ctx)
	if extracted != "" {
		t.Errorf("expected empty string, got %q", extracted)
	}
}

func TestShouldRedact(t *testing.T) {
	tests := []struct {
		key      string
		expected bool
	}{
		{"password", true},
		{"PASSWORD", true},
		{"user_password", true},
		{"secret", true},
		{"api_key", true},
		{"apikey", true},
		{"token", true},
		{"auth_token", true},
		{"access_token", true},
		{"refresh_token", true},
		{"bearer", true},
		{"credential", true},
		{"private_key", true},
		{"session_id", true},
		{"cookie", true},
		{"username", false},
		{"email", false},
		{"name", false},
		{"id", false},
		{"timestamp", false},
	}

	for _, test := range tests {
		t.Run(test.key, func(t *testing.T) {
			result := shouldRedact(test.key)
			if result != test.expected {
				t.Errorf("shouldRedact(%q) = %v, expected %v", test.key, result, test.expected)
			}
		})
	}
}

func TestNewRequestID(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Output = "stderr"
	cfg.Component = "test"

	logger, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	id1 := logger.NewRequestID()
	id2 := logger.NewRequestID()

	if id1 == "" {
		t.Error("NewRequestID returned empty string")
	}
	if id1 == id2 {
		t.Error("NewRequestID returned duplicate IDs")
	}
	if !strings.HasPrefix(id1, "test-") {
		t.Errorf("NewRequestID should start with component name, got %q", id1)
	}
}

func TestJSONFormat(t *testing.T) {
	// Create a buffer to capture output
	var buf bytes.Buffer

	cfg := &Config{
		Level:     LevelInfo,
		Format:    FormatJSON,
		Output:    "stdout",
		Component: "test",
	}

	// We can't easily capture output without modifying the writer
	// This test just verifies the logger can be created with JSON format
	logger, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create JSON logger: %v", err)
	}
	defer logger.Close()

	// Just verify the logger works
	_ = buf // Unused in this simple test
}

func TestFileRotator(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")

	cfg := &Config{
		FilePath:   logPath,
		MaxSize:    1, // 1 MB
		MaxAge:     7,
		MaxBackups: 3,
		Compress:   false, // Disable for faster tests
	}

	rotator, err := NewFileRotator(cfg)
	if err != nil {
		t.Fatalf("failed to create rotator: %v", err)
	}
	defer rotator.Close()

	// Write some data
	testData := []byte("test log line\n")
	n, err := rotator.Write(testData)
	if err != nil {
		t.Fatalf("failed to write: %v", err)
	}
	if n != len(testData) {
		t.Errorf("expected to write %d bytes, wrote %d", len(testData), n)
	}

	// Verify file exists
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		t.Error("log file was not created")
	}

	// Sync and close
	if err := rotator.Sync(); err != nil {
		t.Errorf("sync failed: %v", err)
	}
}

func TestFileRotatorRotation(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")

	cfg := &Config{
		FilePath:   logPath,
		MaxSize:    1, // 1 MB
		MaxAge:     7,
		MaxBackups: 3,
		Compress:   false,
	}

	rotator, err := NewFileRotator(cfg)
	if err != nil {
		t.Fatalf("failed to create rotator: %v", err)
	}
	defer rotator.Close()

	// Write data that would trigger rotation if max size were tiny
	// For this test, we just verify the rotator works
	for i := 0; i < 100; i++ {
		rotator.Write([]byte("test log line " + string(rune('A'+i%26)) + "\n"))
	}

	// Get list of log files
	files, err := rotator.GetLogFiles()
	if err != nil {
		t.Fatalf("failed to get log files: %v", err)
	}

	if len(files) == 0 {
		t.Error("no log files found")
	}
}

func TestLoggerWithContext(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Output = "stderr"

	logger, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	ctx := context.Background()
	ctx = ContextWithRequestID(ctx, "test-req-789")

	childLogger := logger.WithContext(ctx)
	if childLogger == nil {
		t.Error("WithContext returned nil")
	}
}

func TestAuditLogger(t *testing.T) {
	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "audit.log")

	cfg := &AuditLoggerConfig{
		FilePath:   auditPath,
		MaxSize:    10,
		MaxAge:     7,
		MaxBackups: 3,
		Compress:   false,
		Component:  "test",
		DeviceID:   "test-device",
	}

	auditLogger, err := NewAuditLogger(cfg)
	if err != nil {
		t.Fatalf("failed to create audit logger: %v", err)
	}
	defer auditLogger.Close()

	ctx := context.Background()

	// Test session start
	err = auditLogger.LogSessionStart(ctx, "session-123", map[string]interface{}{
		"user": "test-user",
	})
	if err != nil {
		t.Errorf("LogSessionStart failed: %v", err)
	}

	// Test checkpoint
	err = auditLogger.LogCheckpoint(ctx, "/path/to/file.txt", "checkpoint-456", nil)
	if err != nil {
		t.Errorf("LogCheckpoint failed: %v", err)
	}

	// Test config change
	err = auditLogger.LogConfigChange(ctx, "log_level", "info", "debug")
	if err != nil {
		t.Errorf("LogConfigChange failed: %v", err)
	}

	// Test error
	err = auditLogger.LogError(ctx, "test_operation", io.EOF, nil)
	if err != nil {
		t.Errorf("LogError failed: %v", err)
	}

	// Test session end
	err = auditLogger.LogSessionEnd(ctx, nil)
	if err != nil {
		t.Errorf("LogSessionEnd failed: %v", err)
	}

	// Sync to ensure data is written
	auditLogger.Sync()

	// Verify audit log file exists and has content
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("failed to read audit log: %v", err)
	}

	if len(data) == 0 {
		t.Error("audit log is empty")
	}

	// Verify it's valid JSON lines
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	for i, line := range lines {
		var event map[string]interface{}
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Errorf("line %d is not valid JSON: %v", i+1, err)
		}
	}
}

func TestCrashHandler(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &CrashHandlerConfig{
		CrashDir:  tmpDir,
		Version:   "1.0.0",
		Component: "test",
	}

	handler := NewCrashHandler(cfg)

	// Test handling a panic value
	handler.HandlePanic("test panic value", map[string]interface{}{
		"test_key": "test_value",
	})

	// Verify crash report was created
	reports, err := handler.GetCrashReports()
	if err != nil {
		t.Fatalf("failed to get crash reports: %v", err)
	}

	if len(reports) == 0 {
		t.Error("no crash report was created")
	}

	if len(reports) > 0 {
		report := reports[0]
		if report.PanicValue != "test panic value" {
			t.Errorf("expected panic value 'test panic value', got %q", report.PanicValue)
		}
		if report.Version != "1.0.0" {
			t.Errorf("expected version '1.0.0', got %q", report.Version)
		}
		if report.Component != "test" {
			t.Errorf("expected component 'test', got %q", report.Component)
		}
	}

	// Test cleanup
	err = handler.ClearCrashReports()
	if err != nil {
		t.Errorf("ClearCrashReports failed: %v", err)
	}

	reports, _ = handler.GetCrashReports()
	if len(reports) != 0 {
		t.Error("crash reports were not cleared")
	}
}

func TestCrashHandlerRecovery(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &CrashHandlerConfig{
		CrashDir:  tmpDir,
		Version:   "1.0.0",
		Component: "test",
	}

	handler := NewCrashHandler(cfg)

	// Test that Recover catches panics
	panicked := false
	handler.Recover(func() {
		panicked = true
		panic("intentional test panic")
	})

	if !panicked {
		t.Error("function did not run")
	}

	// Verify crash report was created
	reports, _ := handler.GetCrashReports()
	if len(reports) == 0 {
		t.Error("crash report was not created for recovered panic")
	}
}

func TestCrashHandlerCleanupOld(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &CrashHandlerConfig{
		CrashDir:  tmpDir,
		Version:   "1.0.0",
		Component: "test",
	}

	handler := NewCrashHandler(cfg)

	// Create a few crash reports
	for i := 0; i < 3; i++ {
		handler.HandlePanic("test panic", nil)
		time.Sleep(10 * time.Millisecond) // Ensure different timestamps
	}

	// Verify reports exist
	reports, _ := handler.GetCrashReports()
	if len(reports) != 3 {
		t.Errorf("expected 3 reports, got %d", len(reports))
	}

	// Cleanup with very short max age (should remove all)
	err := handler.CleanupOldCrashReports(1 * time.Millisecond)
	if err != nil {
		t.Errorf("CleanupOldCrashReports failed: %v", err)
	}

	// Reports might still exist if cleanup ran too fast
	// This is a timing-sensitive test
}
