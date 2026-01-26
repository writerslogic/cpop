// Package config handles configuration loading and validation for witnessd.
package config

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// Config holds the daemon configuration.
type Config struct {
	// WatchPaths is a list of directories to monitor for changes.
	WatchPaths []string `toml:"watch_paths"`

	// Interval is the debounce interval in seconds.
	// Files must be stable for this duration before witnessing.
	Interval int `toml:"interval"`

	// DatabasePath is the path to the MMR database file.
	DatabasePath string `toml:"database_path"`

	// LogPath is the path to the daemon log file.
	LogPath string `toml:"log_path"`

	// SigningKeyPath is the path to the Ed25519 private key.
	SigningKeyPath string `toml:"signing_key_path"`

	// SignaturesPath is the path to store signature mappings.
	SignaturesPath string `toml:"signatures_path"`

	// EventStorePath is the path to the SQLite event store database.
	EventStorePath string `toml:"event_store_path"`
}

// DefaultConfig returns a configuration with sensible defaults.
func DefaultConfig() *Config {
	homeDir, _ := os.UserHomeDir()
	witnessdDir := filepath.Join(homeDir, ".witnessd")

	return &Config{
		WatchPaths:     []string{},
		Interval:       5,
		DatabasePath:   filepath.Join(witnessdDir, "mmr.db"),
		LogPath:        filepath.Join(witnessdDir, "witnessd.log"),
		SigningKeyPath: filepath.Join(homeDir, ".ssh", "witnessd_signing_key"),
		SignaturesPath: filepath.Join(witnessdDir, "signatures.sigs"),
		EventStorePath: filepath.Join(witnessdDir, "events.db"),
	}
}

// ConfigPath returns the default configuration file path.
func ConfigPath() string {
	homeDir, _ := os.UserHomeDir()
	return filepath.Join(homeDir, ".witnessd", "config.toml")
}

// Load reads configuration from the specified path.
// If the file doesn't exist, returns default configuration.
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	if path == "" {
		path = ConfigPath()
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}

	if _, err := toml.Decode(string(data), cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Validate checks the configuration for errors.
func (c *Config) Validate() error {
	if c.Interval < 1 {
		return errors.New("config: interval must be at least 1 second")
	}

	if c.DatabasePath == "" {
		return errors.New("config: database_path is required")
	}

	if c.SigningKeyPath == "" {
		return errors.New("config: signing_key_path is required")
	}

	return nil
}

// EnsureDirectories creates all necessary directories for the daemon.
func (c *Config) EnsureDirectories() error {
	dirs := []string{
		filepath.Dir(c.DatabasePath),
		filepath.Dir(c.LogPath),
		filepath.Dir(c.SignaturesPath),
	}

	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}

	return nil
}

// WitnessdDir returns the base witnessd directory.
func WitnessdDir() string {
	homeDir, _ := os.UserHomeDir()
	return filepath.Join(homeDir, ".witnessd")
}
