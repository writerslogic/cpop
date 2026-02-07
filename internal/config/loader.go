// Package config handles configuration loading and validation for witnessd.
package config

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"
)

// Loader handles configuration loading, watching, and hot-reloading.
type Loader struct {
	path     string
	config   *Config
	mu       sync.RWMutex
	watcher  *fsnotify.Watcher
	onChange []func(*Config)
	ctx      context.Context
	cancel   context.CancelFunc
	errChan  chan error
}

// NewLoader creates a new configuration loader.
func NewLoader(path string) *Loader {
	ctx, cancel := context.WithCancel(context.Background())
	return &Loader{
		path:    path,
		errChan: make(chan error, 1),
		ctx:     ctx,
		cancel:  cancel,
	}
}

// Load reads and parses the configuration file.
func (l *Loader) Load() (*Config, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	cfg, err := loadConfigFromFile(l.path)
	if err != nil {
		return nil, err
	}

	// Apply environment overrides
	cfg.ApplyEnvOverrides()

	// Validate
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Check for migrations
	if cfg.Version < Version {
		result, err := MigrateConfig(cfg, l.path)
		if err != nil {
			return nil, fmt.Errorf("migration failed: %w", err)
		}
		if result != nil {
			// Save migration history
			_ = SaveMigrationHistory(result)
		}
	}

	l.config = cfg
	return cfg, nil
}

// Config returns the current configuration.
func (l *Loader) Config() *Config {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.config
}

// Watch starts watching the configuration file for changes.
// When changes are detected, the configuration is reloaded and
// registered callbacks are invoked.
func (l *Loader) Watch() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("create watcher: %w", err)
	}
	l.watcher = watcher

	// Watch the directory containing the config file
	dir := filepath.Dir(l.path)
	if err := watcher.Add(dir); err != nil {
		watcher.Close()
		return fmt.Errorf("watch directory: %w", err)
	}

	go l.watchLoop()

	return nil
}

// watchLoop handles file system events.
func (l *Loader) watchLoop() {
	// Debounce timer to avoid multiple reloads for rapid changes
	var debounceTimer *time.Timer
	debounceDelay := 100 * time.Millisecond

	for {
		select {
		case <-l.ctx.Done():
			return

		case event, ok := <-l.watcher.Events:
			if !ok {
				return
			}

			// Check if this event is for our config file
			if filepath.Base(event.Name) != filepath.Base(l.path) {
				continue
			}

			// Only reload on write/create events
			if event.Op&(fsnotify.Write|fsnotify.Create) == 0 {
				continue
			}

			// Debounce
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			debounceTimer = time.AfterFunc(debounceDelay, func() {
				l.reload()
			})

		case err, ok := <-l.watcher.Errors:
			if !ok {
				return
			}
			select {
			case l.errChan <- err:
			default:
			}
		}
	}
}

// reload attempts to reload the configuration.
func (l *Loader) reload() {
	newCfg, err := loadConfigFromFile(l.path)
	if err != nil {
		select {
		case l.errChan <- fmt.Errorf("reload config: %w", err):
		default:
		}
		return
	}

	// Apply environment overrides
	newCfg.ApplyEnvOverrides()

	// Validate before applying
	if err := newCfg.Validate(); err != nil {
		select {
		case l.errChan <- fmt.Errorf("validate new config: %w", err):
		default:
		}
		return
	}

	// Update the config
	l.mu.Lock()
	oldCfg := l.config
	l.config = newCfg
	l.mu.Unlock()

	// Notify listeners
	for _, cb := range l.onChange {
		cb(newCfg)
	}

	// Log the change (if old config existed)
	if oldCfg != nil {
		_ = oldCfg // Suppress unused warning
	}
}

// OnChange registers a callback to be invoked when the configuration changes.
func (l *Loader) OnChange(cb func(*Config)) {
	l.onChange = append(l.onChange, cb)
}

// Errors returns a channel for receiving errors that occur during watching.
func (l *Loader) Errors() <-chan error {
	return l.errChan
}

// Close stops the watcher and releases resources.
func (l *Loader) Close() error {
	l.cancel()
	if l.watcher != nil {
		return l.watcher.Close()
	}
	return nil
}

// loadConfigFromFile reads and parses a config file based on its extension.
func loadConfigFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Return defaults if no config file exists
			return DefaultConfig(), nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}

	cfg := DefaultConfig()

	// Parse based on extension
	ext := filepath.Ext(path)
	switch ext {
	case ".toml":
		if _, err := toml.Decode(string(data), cfg); err != nil {
			return nil, fmt.Errorf("decode TOML: %w", err)
		}
	case ".json":
		if err := json.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("decode JSON: %w", err)
		}
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("decode YAML: %w", err)
		}
	default:
		// Try to auto-detect format
		if err := autoDetectAndParse(data, cfg); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
	}

	return cfg, nil
}

// autoDetectAndParse attempts to parse the config in multiple formats.
func autoDetectAndParse(data []byte, cfg *Config) error {
	// Try TOML first (most common)
	if _, err := toml.Decode(string(data), cfg); err == nil {
		return nil
	}

	// Try JSON
	if err := json.Unmarshal(data, cfg); err == nil {
		return nil
	}

	// Try YAML
	if err := yaml.Unmarshal(data, cfg); err == nil {
		return nil
	}

	return fmt.Errorf("unable to parse config file (tried TOML, JSON, YAML)")
}

// LoadFromEnv creates a configuration primarily from environment variables.
// This is useful for containerized deployments.
func LoadFromEnv() *Config {
	cfg := DefaultConfig()
	cfg.ApplyEnvOverrides()
	return cfg
}

// LoadOrCreate loads the configuration from the specified path,
// creating a default configuration file if it doesn't exist.
func LoadOrCreate(path string) (*Config, bool, error) {
	if path == "" {
		path = ConfigPath()
	}

	// Check if file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		// Create default config
		cfg := DefaultConfig()
		if err := SaveConfig(cfg, path); err != nil {
			return nil, false, fmt.Errorf("create default config: %w", err)
		}
		return cfg, true, nil
	}

	// Load existing config
	loader := NewLoader(path)
	cfg, err := loader.Load()
	if err != nil {
		return nil, false, err
	}

	return cfg, false, nil
}

// Merge merges two configurations, with src overriding dst for non-zero values.
func Merge(dst, src *Config) *Config {
	result := dst.Clone()

	// Version
	if src.Version > 0 {
		result.Version = src.Version
	}

	// Watch
	if len(src.Watch.Paths) > 0 {
		result.Watch.Paths = src.Watch.Paths
	}
	if len(src.Watch.IncludePatterns) > 0 {
		result.Watch.IncludePatterns = src.Watch.IncludePatterns
	}
	if len(src.Watch.ExcludePatterns) > 0 {
		result.Watch.ExcludePatterns = src.Watch.ExcludePatterns
	}
	if src.Watch.DebounceMs > 0 {
		result.Watch.DebounceMs = src.Watch.DebounceMs
	}
	if src.Watch.CheckpointIntervalSec > 0 {
		result.Watch.CheckpointIntervalSec = src.Watch.CheckpointIntervalSec
	}
	if src.Watch.MaxFileSize > 0 {
		result.Watch.MaxFileSize = src.Watch.MaxFileSize
	}
	// Note: booleans are tricky - we can't distinguish "not set" from "false"
	// For explicit false, user should use the full config

	// Storage
	if src.Storage.Type != "" {
		result.Storage.Type = src.Storage.Type
	}
	if src.Storage.Path != "" {
		result.Storage.Path = src.Storage.Path
	}
	if src.Storage.MMRPath != "" {
		result.Storage.MMRPath = src.Storage.MMRPath
	}
	if src.Storage.EventStorePath != "" {
		result.Storage.EventStorePath = src.Storage.EventStorePath
	}
	if src.Storage.SignaturesPath != "" {
		result.Storage.SignaturesPath = src.Storage.SignaturesPath
	}
	if src.Storage.MaxConnections > 0 {
		result.Storage.MaxConnections = src.Storage.MaxConnections
	}
	if src.Storage.BusyTimeoutMs > 0 {
		result.Storage.BusyTimeoutMs = src.Storage.BusyTimeoutMs
	}

	// WAL
	if src.WAL.Path != "" {
		result.WAL.Path = src.WAL.Path
	}
	if src.WAL.MaxSizeBytes > 0 {
		result.WAL.MaxSizeBytes = src.WAL.MaxSizeBytes
	}
	if src.WAL.SyncMode != "" {
		result.WAL.SyncMode = src.WAL.SyncMode
	}
	if src.WAL.CheckpointThreshold > 0 {
		result.WAL.CheckpointThreshold = src.WAL.CheckpointThreshold
	}
	if src.WAL.RetentionHours > 0 {
		result.WAL.RetentionHours = src.WAL.RetentionHours
	}

	// Signing
	if src.Signing.KeyPath != "" {
		result.Signing.KeyPath = src.Signing.KeyPath
	}
	if src.Signing.PublicKeyPath != "" {
		result.Signing.PublicKeyPath = src.Signing.PublicKeyPath
	}
	if src.Signing.Algorithm != "" {
		result.Signing.Algorithm = src.Signing.Algorithm
	}
	if src.Signing.KeyRotationDays > 0 {
		result.Signing.KeyRotationDays = src.Signing.KeyRotationDays
	}

	// Hardware
	if src.Hardware.TPMPath != "" {
		result.Hardware.TPMPath = src.Hardware.TPMPath
	}
	if len(src.Hardware.TPMPCRs) > 0 {
		result.Hardware.TPMPCRs = src.Hardware.TPMPCRs
	}
	if src.Hardware.PUFSeedPath != "" {
		result.Hardware.PUFSeedPath = src.Hardware.PUFSeedPath
	}

	// Anchors
	if len(src.Anchors.Providers) > 0 {
		result.Anchors.Providers = src.Anchors.Providers
	}
	if src.Anchors.BatchIntervalSec > 0 {
		result.Anchors.BatchIntervalSec = src.Anchors.BatchIntervalSec
	}
	if src.Anchors.RetryAttempts > 0 {
		result.Anchors.RetryAttempts = src.Anchors.RetryAttempts
	}
	if src.Anchors.RetryDelayMs > 0 {
		result.Anchors.RetryDelayMs = src.Anchors.RetryDelayMs
	}

	// OpenTimestamps
	if len(src.Anchors.OpenTimestamps.Calendars) > 0 {
		result.Anchors.OpenTimestamps.Calendars = src.Anchors.OpenTimestamps.Calendars
	}
	if src.Anchors.OpenTimestamps.TimeoutSec > 0 {
		result.Anchors.OpenTimestamps.TimeoutSec = src.Anchors.OpenTimestamps.TimeoutSec
	}

	// RFC3161
	if src.Anchors.RFC3161.URL != "" {
		result.Anchors.RFC3161.URL = src.Anchors.RFC3161.URL
	}
	if src.Anchors.RFC3161.CertPath != "" {
		result.Anchors.RFC3161.CertPath = src.Anchors.RFC3161.CertPath
	}
	if src.Anchors.RFC3161.TimeoutSec > 0 {
		result.Anchors.RFC3161.TimeoutSec = src.Anchors.RFC3161.TimeoutSec
	}
	if src.Anchors.RFC3161.Username != "" {
		result.Anchors.RFC3161.Username = src.Anchors.RFC3161.Username
	}
	if src.Anchors.RFC3161.Password != "" {
		result.Anchors.RFC3161.Password = src.Anchors.RFC3161.Password
	}

	// Drand
	if src.Anchors.Drand.ChainHash != "" {
		result.Anchors.Drand.ChainHash = src.Anchors.Drand.ChainHash
	}
	if len(src.Anchors.Drand.URLs) > 0 {
		result.Anchors.Drand.URLs = src.Anchors.Drand.URLs
	}

	// Forensics
	if src.Forensics.SamplingRateMs > 0 {
		result.Forensics.SamplingRateMs = src.Forensics.SamplingRateMs
	}
	if src.Forensics.AnalysisDepth != "" {
		result.Forensics.AnalysisDepth = src.Forensics.AnalysisDepth
	}
	if src.Forensics.SessionGapMinutes > 0 {
		result.Forensics.SessionGapMinutes = src.Forensics.SessionGapMinutes
	}
	if src.Forensics.AnomalyThreshold > 0 {
		result.Forensics.AnomalyThreshold = src.Forensics.AnomalyThreshold
	}
	if src.Forensics.RetainProfilesDays > 0 {
		result.Forensics.RetainProfilesDays = src.Forensics.RetainProfilesDays
	}

	// VDF
	if src.VDF.IterationsPerSecond > 0 {
		result.VDF.IterationsPerSecond = src.VDF.IterationsPerSecond
	}
	if src.VDF.MinIterations > 0 {
		result.VDF.MinIterations = src.VDF.MinIterations
	}
	if src.VDF.MaxIterations > 0 {
		result.VDF.MaxIterations = src.VDF.MaxIterations
	}
	if src.VDF.DefaultDurationSec > 0 {
		result.VDF.DefaultDurationSec = src.VDF.DefaultDurationSec
	}

	// Presence
	if src.Presence.ChallengeIntervalSec > 0 {
		result.Presence.ChallengeIntervalSec = src.Presence.ChallengeIntervalSec
	}
	if src.Presence.ResponseWindowSec > 0 {
		result.Presence.ResponseWindowSec = src.Presence.ResponseWindowSec
	}
	if len(src.Presence.ChallengeTypes) > 0 {
		result.Presence.ChallengeTypes = src.Presence.ChallengeTypes
	}
	if src.Presence.MaxMissedChallenges > 0 {
		result.Presence.MaxMissedChallenges = src.Presence.MaxMissedChallenges
	}

	// Logging
	if src.Logging.Level != "" {
		result.Logging.Level = src.Logging.Level
	}
	if src.Logging.Format != "" {
		result.Logging.Format = src.Logging.Format
	}
	if src.Logging.Output != "" {
		result.Logging.Output = src.Logging.Output
	}
	if src.Logging.FilePath != "" {
		result.Logging.FilePath = src.Logging.FilePath
	}
	if src.Logging.MaxSizeMB > 0 {
		result.Logging.MaxSizeMB = src.Logging.MaxSizeMB
	}
	if src.Logging.MaxBackups > 0 {
		result.Logging.MaxBackups = src.Logging.MaxBackups
	}
	if src.Logging.MaxAgeDays > 0 {
		result.Logging.MaxAgeDays = src.Logging.MaxAgeDays
	}

	// IPC
	if src.IPC.SocketPath != "" {
		result.IPC.SocketPath = src.IPC.SocketPath
	}
	if src.IPC.Permissions != "" {
		result.IPC.Permissions = src.IPC.Permissions
	}
	if src.IPC.MaxConnections > 0 {
		result.IPC.MaxConnections = src.IPC.MaxConnections
	}
	if src.IPC.TimeoutSec > 0 {
		result.IPC.TimeoutSec = src.IPC.TimeoutSec
	}

	// Sentinel
	if src.Sentinel.HeartbeatSec > 0 {
		result.Sentinel.HeartbeatSec = src.Sentinel.HeartbeatSec
	}
	if src.Sentinel.CheckpointSec > 0 {
		result.Sentinel.CheckpointSec = src.Sentinel.CheckpointSec
	}
	if len(src.Sentinel.WatchedPaths) > 0 {
		result.Sentinel.WatchedPaths = src.Sentinel.WatchedPaths
	}
	if src.Sentinel.PidFile != "" {
		result.Sentinel.PidFile = src.Sentinel.PidFile
	}

	// KeyHierarchy
	if src.KeyHierarchy.Version > 0 {
		result.KeyHierarchy.Version = src.KeyHierarchy.Version
	}
	if src.KeyHierarchy.IdentityPath != "" {
		result.KeyHierarchy.IdentityPath = src.KeyHierarchy.IdentityPath
	}
	if src.KeyHierarchy.SessionKeyRotationHours > 0 {
		result.KeyHierarchy.SessionKeyRotationHours = src.KeyHierarchy.SessionKeyRotationHours
	}

	return result
}

// ConfigWatcher provides a simple interface for watching config changes.
type ConfigWatcher struct {
	loader    *Loader
	callbacks []func(*Config, *Config) // old, new
}

// NewConfigWatcher creates a new config watcher.
func NewConfigWatcher(path string) (*ConfigWatcher, error) {
	loader := NewLoader(path)
	if _, err := loader.Load(); err != nil {
		return nil, err
	}

	return &ConfigWatcher{
		loader: loader,
	}, nil
}

// Start begins watching for configuration changes.
func (w *ConfigWatcher) Start() error {
	// Track old config for diff callbacks
	oldCfg := w.loader.Config()

	w.loader.OnChange(func(newCfg *Config) {
		for _, cb := range w.callbacks {
			cb(oldCfg, newCfg)
		}
		oldCfg = newCfg
	})

	return w.loader.Watch()
}

// OnChange registers a callback for config changes.
// The callback receives both old and new configurations.
func (w *ConfigWatcher) OnChange(cb func(old, new *Config)) {
	w.callbacks = append(w.callbacks, cb)
}

// Config returns the current configuration.
func (w *ConfigWatcher) Config() *Config {
	return w.loader.Config()
}

// Stop stops watching for changes.
func (w *ConfigWatcher) Stop() error {
	return w.loader.Close()
}

// Reload forces a reload of the configuration.
func (w *ConfigWatcher) Reload() error {
	_, err := w.loader.Load()
	return err
}
