package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig returned nil")
	}

	// Verify defaults
	if cfg.Interval() != 5 {
		t.Errorf("expected interval 5, got %d", cfg.Interval())
	}
	if len(cfg.WatchPaths()) != 0 {
		t.Errorf("expected 0 watch paths, got %d", len(cfg.WatchPaths()))
	}


	// Check paths contain .witnessd
	if !strings.Contains(cfg.DatabasePath(), ".witnessd") {
		t.Errorf("database path should contain .witnessd: %s", cfg.DatabasePath())
	}
	if !strings.Contains(cfg.LogPath(), ".witnessd") {
		t.Errorf("log path should contain .witnessd: %s", cfg.LogPath())
	}
	if !strings.Contains(cfg.Storage.SignaturesPath, ".witnessd") {
		t.Errorf("signatures path should contain .witnessd: %s", cfg.Storage.SignaturesPath)
	}
	if !strings.Contains(cfg.Storage.EventStorePath, ".witnessd") {
		t.Errorf("event store path should contain .witnessd: %s", cfg.Storage.EventStorePath)
	}
}

func TestConfigPath(t *testing.T) {
	path := ConfigPath()
	if path == "" {
		t.Error("ConfigPath returned empty string")
	}
	if !strings.HasSuffix(path, "config.toml") {
		t.Errorf("expected path ending with config.toml, got %s", path)
	}
	if !strings.Contains(path, ".witnessd") {
		t.Errorf("config path should contain .witnessd: %s", path)
	}
}

func TestWitnessdDir(t *testing.T) {
	dir := WitnessdDir()
	if dir == "" {
		t.Error("WitnessdDir returned empty string")
	}
	if !strings.HasSuffix(dir, ".witnessd") {
		t.Errorf("expected dir ending with .witnessd, got %s", dir)
	}
}

func TestLoadNonexistent(t *testing.T) {
	// Load from nonexistent path should return default config
	cfg, err := Load("/nonexistent/path/config.toml")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg == nil {
		t.Fatal("Load returned nil config")
	}

	// Should have defaults
	if cfg.Interval() != 5 {
		t.Errorf("expected interval 5, got %d", cfg.Interval())
	}
}

func TestLoadDefaultPath(t *testing.T) {
	// Load with empty path should use default
	cfg, err := Load("")
	if err != nil {
		// May fail if default path doesn't exist, which is ok
		if !os.IsNotExist(err) {
			t.Fatalf("Load failed with unexpected error: %v", err)
		}
	}
	if cfg == nil && err == nil {
		t.Fatal("Load returned nil config without error")
	}
}

func TestLoadValidConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")

	content := `
watch_paths = ["/tmp/docs", "/tmp/notes"]
interval = 10
database_path = "/custom/path/mmr.db"
log_path = "/custom/path/witnessd.log"
signing_key_path = "/custom/path/key"
signatures_path = "/custom/path/sigs"
event_store_path = "/custom/path/events.db"
`
	if err := os.WriteFile(configPath, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if len(cfg.WatchPaths) != 2 {
		t.Errorf("expected 2 watch paths, got %d", len(cfg.WatchPaths))
	}
	if cfg.WatchPaths[0] != "/tmp/docs" {
		t.Errorf("expected first path /tmp/docs, got %s", cfg.WatchPaths[0])
	}
	if cfg.Interval != 10 {
		t.Errorf("expected interval 10, got %d", cfg.Interval)
	}
	if cfg.DatabasePath != "/custom/path/mmr.db" {
		t.Errorf("expected database path /custom/path/mmr.db, got %s", cfg.DatabasePath)
	}
	if cfg.LogPath != "/custom/path/witnessd.log" {
		t.Errorf("expected log path /custom/path/witnessd.log, got %s", cfg.LogPath)
	}
	if cfg.SigningKeyPath != "/custom/path/key" {
		t.Errorf("expected signing key path /custom/path/key, got %s", cfg.SigningKeyPath)
	}
	if cfg.Storage.SignaturesPath != "/custom/path/sigs" {
		t.Errorf("expected signatures path /custom/path/sigs, got %s", cfg.Storage.SignaturesPath)
	}
	if cfg.Storage.EventStorePath != "/custom/path/events.db" {
		t.Errorf("expected event store path /custom/path/events.db, got %s", cfg.Storage.EventStorePath)
	}
}

func TestLoadPartialConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")

	// Only set some values, rest should come from defaults
	content := `
interval = 15
`
	if err := os.WriteFile(configPath, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.Interval != 15 {
		t.Errorf("expected interval 15, got %d", cfg.Interval)
	}
	// Other fields should have defaults
	if !strings.Contains(cfg.DatabasePath, ".witnessd") {
		t.Errorf("database path should have default value")
	}
}

func TestLoadInvalidTOML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")

	content := `
this is not valid toml {{{
`
	if err := os.WriteFile(configPath, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(configPath)
	if err == nil {
		t.Error("expected error for invalid TOML")
	}
}

func TestValidate(t *testing.T) {
	cfg := DefaultConfig()
	err := cfg.Validate()
	if err != nil {
		t.Errorf("default config should be valid: %v", err)
	}
}

func TestValidateInvalidInterval(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Interval = 0
	err := cfg.Validate()
	if err == nil {
		t.Error("expected error for zero interval")
	}

	cfg.Interval = -1
	err = cfg.Validate()
	if err == nil {
		t.Error("expected error for negative interval")
	}
}

func TestValidateMissingDatabasePath(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DatabasePath = ""
	err := cfg.Validate()
	if err == nil {
		t.Error("expected error for missing database path")
	}
}

func TestValidateMissingSigningKeyPath(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SigningKeyPath = ""
	err := cfg.Validate()
	if err == nil {
		t.Error("expected error for missing signing key path")
	}
}

func TestEnsureDirectories(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := &Config{
		DatabasePath:   filepath.Join(tmpDir, "subdir1", "mmr.db"),
		LogPath:        filepath.Join(tmpDir, "subdir2", "witnessd.log"),
		SignaturesPath: filepath.Join(tmpDir, "subdir3", "sigs"),
	}

	err := cfg.EnsureDirectories()
	if err != nil {
		t.Fatalf("EnsureDirectories failed: %v", err)
	}

	// Verify directories were created
	if _, err := os.Stat(filepath.Join(tmpDir, "subdir1")); os.IsNotExist(err) {
		t.Error("subdir1 was not created")
	}
	if _, err := os.Stat(filepath.Join(tmpDir, "subdir2")); os.IsNotExist(err) {
		t.Error("subdir2 was not created")
	}
	if _, err := os.Stat(filepath.Join(tmpDir, "subdir3")); os.IsNotExist(err) {
		t.Error("subdir3 was not created")
	}
}

func TestEnsureDirectoriesEmptyPaths(t *testing.T) {
	cfg := &Config{
		DatabasePath:   "",
		LogPath:        "",
		SignaturesPath: "",
	}

	// Should not error with empty paths
	err := cfg.EnsureDirectories()
	if err != nil {
		t.Errorf("EnsureDirectories failed with empty paths: %v", err)
	}
}

func TestEnsureDirectoriesNestedPaths(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := &Config{
		DatabasePath:   filepath.Join(tmpDir, "a", "b", "c", "d", "mmr.db"),
		LogPath:        filepath.Join(tmpDir, "e", "f", "g", "witnessd.log"),
		SignaturesPath: filepath.Join(tmpDir, "h", "i", "j", "sigs"),
	}

	err := cfg.EnsureDirectories()
	if err != nil {
		t.Fatalf("EnsureDirectories failed with nested paths: %v", err)
	}

	// Verify nested directories were created
	if _, err := os.Stat(filepath.Join(tmpDir, "a", "b", "c", "d")); os.IsNotExist(err) {
		t.Error("nested directory for database was not created")
	}
}

func TestConfigWithComments(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")

	content := `
# This is a comment
watch_paths = ["/tmp/docs"] # inline comment
interval = 7 # another inline comment
# database_path = "/commented/out"
database_path = "/actual/path/mmr.db"
`
	if err := os.WriteFile(configPath, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.Interval != 7 {
		t.Errorf("expected interval 7, got %d", cfg.Interval)
	}
	if cfg.DatabasePath != "/actual/path/mmr.db" {
		t.Errorf("expected database path /actual/path/mmr.db, got %s", cfg.DatabasePath)
	}
}

func TestConfigEmptyWatchPaths(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")

	content := `
watch_paths = []
interval = 5
database_path = "/path/mmr.db"
signing_key_path = "/path/key"
`
	if err := os.WriteFile(configPath, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if len(cfg.WatchPaths()) != 0 {
		t.Errorf("expected 0 watch paths, got %d", len(cfg.WatchPaths()))
	}

}

func TestConfigMultipleWatchPaths(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")

	content := `
watch_paths = [
    "/path/one",
    "/path/two",
    "/path/three",
    "/path/four",
    "/path/five"
]
`
	if err := os.WriteFile(configPath, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if len(cfg.WatchPaths) != 5 {
		t.Errorf("expected 5 watch paths, got %d", len(cfg.WatchPaths))
	}
}
