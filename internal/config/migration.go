// Package config handles configuration loading and validation for witnessd.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// MigrationResult contains the result of a configuration migration.
type MigrationResult struct {
	FromVersion int
	ToVersion   int
	Backup      string
	Changes     []string
	Warnings    []string
}

// MigrateConfig migrates a configuration from an older version to the current version.
// It automatically creates a backup before migration.
func MigrateConfig(cfg *Config, configPath string) (*MigrationResult, error) {
	if cfg.Version >= Version {
		return nil, nil // No migration needed
	}

	result := &MigrationResult{
		FromVersion: cfg.Version,
		ToVersion:   Version,
	}

	// Create backup before migration
	if configPath != "" {
		backup, err := backupConfig(configPath)
		if err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("could not create backup: %v", err))
		} else {
			result.Backup = backup
		}
	}

	// Apply migrations in sequence
	for cfg.Version < Version {
		changes, warnings, err := applyMigration(cfg)
		if err != nil {
			return result, fmt.Errorf("migration from v%d to v%d failed: %w", cfg.Version, cfg.Version+1, err)
		}
		result.Changes = append(result.Changes, changes...)
		result.Warnings = append(result.Warnings, warnings...)
	}

	return result, nil
}

// applyMigration applies a single version upgrade.
func applyMigration(cfg *Config) (changes []string, warnings []string, err error) {
	switch cfg.Version {
	case 1:
		changes, warnings = migrateV1ToV2(cfg)
	case 2:
		changes, warnings = migrateV2ToV3(cfg)
	case 3:
		changes, warnings = migrateV3ToV4(cfg)
	case 4:
		changes, warnings = migrateV4ToV5(cfg)
	default:
		return nil, nil, fmt.Errorf("unknown version %d", cfg.Version)
	}

	cfg.Version++
	return changes, warnings, nil
}

// migrateV1ToV2 migrates from version 1 to version 2.
// V1 was the original flat config structure.
func migrateV1ToV2(cfg *Config) (changes []string, warnings []string) {
	// V1 had flat watch_paths, interval, database_path, etc.
	// These are now nested in their respective sections.

	// The defaults are already set from DefaultConfig(), so we just need
	// to preserve any custom values that were in the old format.

	// If we detect old-style paths, migrate them
	dir := WitnessdDir()

	// Check for old-style paths and migrate
	if cfg.Storage.Path == "" {
		cfg.Storage.Path = filepath.Join(dir, "events.db")
		changes = append(changes, "set default storage.path")
	}

	if cfg.Storage.MMRPath == "" {
		cfg.Storage.MMRPath = filepath.Join(dir, "mmr.db")
		changes = append(changes, "set default storage.mmr_path")
	}

	if cfg.Signing.KeyPath == "" {
		cfg.Signing.KeyPath = filepath.Join(dir, "signing_key")
		changes = append(changes, "set default signing.key_path")
	}

	// Set secure storage as default
	if !cfg.Storage.Secure {
		cfg.Storage.Secure = true
		changes = append(changes, "enabled secure storage by default")
	}

	return changes, warnings
}

// migrateV2ToV3 migrates from version 2 to version 3.
// V3 added WAL configuration.
func migrateV2ToV3(cfg *Config) (changes []string, warnings []string) {
	dir := WitnessdDir()

	// Enable WAL by default
	if !cfg.WAL.Enabled {
		cfg.WAL.Enabled = true
		cfg.WAL.Path = filepath.Join(dir, "wal")
		changes = append(changes, "enabled WAL support")
	}

	// Set default WAL settings
	if cfg.WAL.MaxSizeBytes == 0 {
		cfg.WAL.MaxSizeBytes = 64 * 1024 * 1024
		changes = append(changes, "set WAL max size to 64MB")
	}

	if cfg.WAL.SyncMode == "" {
		cfg.WAL.SyncMode = "normal"
		changes = append(changes, "set WAL sync mode to normal")
	}

	return changes, warnings
}

// migrateV3ToV4 migrates from version 3 to version 4.
// V4 added key hierarchy configuration.
func migrateV3ToV4(cfg *Config) (changes []string, warnings []string) {
	dir := WitnessdDir()

	// Enable key hierarchy by default
	if !cfg.KeyHierarchy.Enabled {
		cfg.KeyHierarchy.Enabled = true
		cfg.KeyHierarchy.Version = 1
		cfg.KeyHierarchy.IdentityPath = filepath.Join(dir, "identity.json")
		cfg.KeyHierarchy.SessionKeyRotationHours = 24
		changes = append(changes, "enabled key hierarchy")
	}

	// Add sentinel configuration
	if cfg.Sentinel.HeartbeatSec == 0 {
		cfg.Sentinel.HeartbeatSec = 60
		cfg.Sentinel.CheckpointSec = 60
		cfg.Sentinel.PidFile = filepath.Join(dir, "sentinel.pid")
		changes = append(changes, "added sentinel configuration")
	}

	return changes, warnings
}

// migrateV4ToV5 migrates from version 4 to version 5.
// V5 added anchor and forensics configuration.
func migrateV4ToV5(cfg *Config) (changes []string, warnings []string) {
	// Enable forensics by default
	if !cfg.Forensics.Enabled {
		cfg.Forensics.Enabled = true
		cfg.Forensics.SamplingRateMs = 100
		cfg.Forensics.AnalysisDepth = "normal"
		cfg.Forensics.SessionGapMinutes = 30
		cfg.Forensics.AnomalyThreshold = 0.15
		cfg.Forensics.RetainProfilesDays = 90
		changes = append(changes, "enabled forensics analysis")
	}

	// Add default anchor configuration (disabled by default)
	if len(cfg.Anchors.OpenTimestamps.Calendars) == 0 {
		cfg.Anchors.OpenTimestamps.Calendars = []string{
			"https://a.pool.opentimestamps.org",
			"https://b.pool.opentimestamps.org",
		}
		cfg.Anchors.OpenTimestamps.TimeoutSec = 30
		changes = append(changes, "added OpenTimestamps configuration")
	}

	// Add drand configuration
	if cfg.Anchors.Drand.ChainHash == "" {
		cfg.Anchors.Drand.ChainHash = "8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce"
		cfg.Anchors.Drand.URLs = []string{
			"https://api.drand.sh",
			"https://drand.cloudflare.com",
		}
		changes = append(changes, "added drand configuration")
	}

	// Add IPC configuration
	if cfg.IPC.SocketPath == "" {
		cfg.IPC.Enabled = true
		cfg.IPC.SocketPath = defaultSocketPath()
		cfg.IPC.Permissions = "0600"
		cfg.IPC.MaxConnections = 10
		cfg.IPC.TimeoutSec = 30
		changes = append(changes, "added IPC configuration")
	}

	// Add presence configuration
	if cfg.Presence.ChallengeIntervalSec == 0 {
		cfg.Presence.ChallengeIntervalSec = 600
		cfg.Presence.ResponseWindowSec = 60
		cfg.Presence.ChallengeTypes = []string{"math", "word", "memory"}
		cfg.Presence.MaxMissedChallenges = 3
		changes = append(changes, "added presence verification configuration")
	}

	return changes, warnings
}

// backupConfig creates a backup of the config file.
func backupConfig(configPath string) (string, error) {
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return "", nil // No file to backup
	}

	// Read original
	data, err := os.ReadFile(configPath)
	if err != nil {
		return "", fmt.Errorf("read config: %w", err)
	}

	// Create backup with timestamp
	timestamp := time.Now().Format("20060102-150405")
	backupPath := configPath + ".backup-" + timestamp

	if err := os.WriteFile(backupPath, data, 0600); err != nil {
		return "", fmt.Errorf("write backup: %w", err)
	}

	return backupPath, nil
}

// MigrateLegacyConfig converts a legacy (pre-v5) configuration map to the new format.
// This handles configurations that were stored as JSON maps rather than proper structs.
func MigrateLegacyConfig(data map[string]interface{}) (*Config, error) {
	cfg := DefaultConfig()

	// Extract version
	if v, ok := data["version"].(float64); ok {
		cfg.Version = int(v)
	} else {
		cfg.Version = 1 // Assume version 1 if not specified
	}

	// Extract legacy flat fields
	if paths, ok := data["watch_paths"].([]interface{}); ok {
		for _, p := range paths {
			if s, ok := p.(string); ok {
				cfg.Watch.Paths = append(cfg.Watch.Paths, s)
			}
		}
	}

	if interval, ok := data["interval"].(float64); ok {
		cfg.Watch.DebounceMs = int(interval * 1000)
	}

	if dbPath, ok := data["database_path"].(string); ok {
		cfg.Storage.Path = dbPath
		cfg.Storage.MMRPath = dbPath
	}

	if logPath, ok := data["log_path"].(string); ok {
		cfg.Logging.FilePath = logPath
	}

	if keyPath, ok := data["signing_key_path"].(string); ok {
		cfg.Signing.KeyPath = keyPath
	}

	if sigsPath, ok := data["signatures_path"].(string); ok {
		cfg.Storage.SignaturesPath = sigsPath
	}

	if evPath, ok := data["event_store_path"].(string); ok {
		cfg.Storage.EventStorePath = evPath
	}

	// Extract nested sections from newer configs
	if storage, ok := data["storage"].(map[string]interface{}); ok {
		if t, ok := storage["type"].(string); ok {
			cfg.Storage.Type = t
		}
		if p, ok := storage["path"].(string); ok {
			cfg.Storage.Path = p
		}
		if s, ok := storage["secure"].(bool); ok {
			cfg.Storage.Secure = s
		}
	}

	if vdf, ok := data["vdf"].(map[string]interface{}); ok {
		if ips, ok := vdf["iterations_per_second"].(float64); ok {
			cfg.VDF.IterationsPerSecond = uint64(ips)
		}
		if min, ok := vdf["min_iterations"].(float64); ok {
			cfg.VDF.MinIterations = uint64(min)
		}
		if max, ok := vdf["max_iterations"].(float64); ok {
			cfg.VDF.MaxIterations = uint64(max)
		}
		if cal, ok := vdf["calibrated"].(bool); ok {
			cfg.VDF.Calibrated = cal
		}
	}

	if presence, ok := data["presence"].(map[string]interface{}); ok {
		if interval, ok := presence["challenge_interval_seconds"].(float64); ok {
			cfg.Presence.ChallengeIntervalSec = int(interval)
		}
		if window, ok := presence["response_window_seconds"].(float64); ok {
			cfg.Presence.ResponseWindowSec = int(window)
		}
	}

	if kh, ok := data["key_hierarchy"].(map[string]interface{}); ok {
		if enabled, ok := kh["enabled"].(bool); ok {
			cfg.KeyHierarchy.Enabled = enabled
		}
		if version, ok := kh["version"].(float64); ok {
			cfg.KeyHierarchy.Version = int(version)
		}
	}

	if sentinel, ok := data["sentinel"].(map[string]interface{}); ok {
		if autoStart, ok := sentinel["auto_start"].(bool); ok {
			cfg.Sentinel.AutoStart = autoStart
		}
		if heartbeat, ok := sentinel["heartbeat_seconds"].(float64); ok {
			cfg.Sentinel.HeartbeatSec = int(heartbeat)
		}
		if checkpoint, ok := sentinel["checkpoint_seconds"].(float64); ok {
			cfg.Sentinel.CheckpointSec = int(checkpoint)
		}
		if walEnabled, ok := sentinel["wal_enabled"].(bool); ok {
			cfg.WAL.Enabled = walEnabled
		}
	}

	return cfg, nil
}

// SaveConfig saves the configuration to a file.
func SaveConfig(cfg *Config, path string) error {
	// Determine format from extension
	ext := filepath.Ext(path)

	var data []byte
	var err error

	switch ext {
	case ".json":
		data, err = json.MarshalIndent(cfg, "", "  ")
	case ".toml":
		data, err = encodeToTOML(cfg)
	case ".yaml", ".yml":
		data, err = encodeToYAML(cfg)
	default:
		// Default to TOML
		data, err = encodeToTOML(cfg)
	}

	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}

	// Write with secure permissions
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	return nil
}

// encodeToTOML encodes the config to TOML format.
func encodeToTOML(cfg *Config) ([]byte, error) {
	// Use github.com/BurntSushi/toml encoder
	// For now, we'll generate a formatted string manually
	return []byte(generateTOML(cfg)), nil
}

// generateTOML generates a well-formatted TOML configuration file.
func generateTOML(cfg *Config) string {
	return fmt.Sprintf(`# witnessd configuration
# Version %d

version = %d

[watch]
paths = %s
include_patterns = %s
exclude_patterns = %s
debounce_ms = %d
checkpoint_interval_sec = %d
max_file_size = %d
follow_symlinks = %t
recursive = %t

[storage]
type = "%s"
path = "%s"
secure = %t
mmr_path = "%s"
event_store_path = "%s"
signatures_path = "%s"
max_connections = %d
busy_timeout_ms = %d

[wal]
enabled = %t
path = "%s"
max_size_bytes = %d
sync_mode = "%s"
checkpoint_threshold = %d
retention_hours = %d

[signing]
key_path = "%s"
public_key_path = "%s"
algorithm = "%s"
key_rotation_days = %d

[hardware]
tpm_enabled = %t
tpm_path = "%s"
tpm_pcrs = %s
secure_enclave_enabled = %t
puf_seed_path = "%s"

[anchors]
enabled = %t
providers = %s
batch_interval_sec = %d
retry_attempts = %d
retry_delay_ms = %d

[anchors.opentimestamps]
enabled = %t
calendars = %s
timeout_sec = %d

[anchors.rfc3161]
enabled = %t
url = "%s"
cert_path = "%s"
timeout_sec = %d
username = "%s"
# password = "" # Use WITNESSD_RFC3161_PASSWORD env var

[anchors.drand]
enabled = %t
chain_hash = "%s"
urls = %s

[forensics]
enabled = %t
sampling_rate_ms = %d
analysis_depth = "%s"
session_gap_minutes = %d
anomaly_threshold = %f
retain_profiles_days = %d

[vdf]
iterations_per_second = %d
min_iterations = %d
max_iterations = %d
calibrated = %t
default_duration_sec = %d

[presence]
enabled = %t
challenge_interval_sec = %d
response_window_sec = %d
challenge_types = %s
max_missed_challenges = %d

[logging]
level = "%s"
format = "%s"
output = "%s"
file_path = "%s"
max_size_mb = %d
max_backups = %d
max_age_days = %d
compress = %t

[ipc]
enabled = %t
socket_path = "%s"
permissions = "%s"
max_connections = %d
timeout_sec = %d

[sentinel]
auto_start = %t
heartbeat_sec = %d
checkpoint_sec = %d
watched_paths = %s
pid_file = "%s"

[key_hierarchy]
enabled = %t
version = %d
identity_path = "%s"
session_key_rotation_hours = %d
`,
		Version,
		cfg.Version,
		toTOMLArray(cfg.Watch.Paths),
		toTOMLArray(cfg.Watch.IncludePatterns),
		toTOMLArray(cfg.Watch.ExcludePatterns),
		cfg.Watch.DebounceMs,
		cfg.Watch.CheckpointIntervalSec,
		cfg.Watch.MaxFileSize,
		cfg.Watch.FollowSymlinks,
		cfg.Watch.Recursive,
		cfg.Storage.Type,
		cfg.Storage.Path,
		cfg.Storage.Secure,
		cfg.Storage.MMRPath,
		cfg.Storage.EventStorePath,
		cfg.Storage.SignaturesPath,
		cfg.Storage.MaxConnections,
		cfg.Storage.BusyTimeoutMs,
		cfg.WAL.Enabled,
		cfg.WAL.Path,
		cfg.WAL.MaxSizeBytes,
		cfg.WAL.SyncMode,
		cfg.WAL.CheckpointThreshold,
		cfg.WAL.RetentionHours,
		cfg.Signing.KeyPath,
		cfg.Signing.PublicKeyPath,
		cfg.Signing.Algorithm,
		cfg.Signing.KeyRotationDays,
		cfg.Hardware.TPMEnabled,
		cfg.Hardware.TPMPath,
		toTOMLIntArray(cfg.Hardware.TPMPCRs),
		cfg.Hardware.SecureEnclaveEnabled,
		cfg.Hardware.PUFSeedPath,
		cfg.Anchors.Enabled,
		toTOMLArray(cfg.Anchors.Providers),
		cfg.Anchors.BatchIntervalSec,
		cfg.Anchors.RetryAttempts,
		cfg.Anchors.RetryDelayMs,
		cfg.Anchors.OpenTimestamps.Enabled,
		toTOMLArray(cfg.Anchors.OpenTimestamps.Calendars),
		cfg.Anchors.OpenTimestamps.TimeoutSec,
		cfg.Anchors.RFC3161.Enabled,
		cfg.Anchors.RFC3161.URL,
		cfg.Anchors.RFC3161.CertPath,
		cfg.Anchors.RFC3161.TimeoutSec,
		cfg.Anchors.RFC3161.Username,
		cfg.Anchors.Drand.Enabled,
		cfg.Anchors.Drand.ChainHash,
		toTOMLArray(cfg.Anchors.Drand.URLs),
		cfg.Forensics.Enabled,
		cfg.Forensics.SamplingRateMs,
		cfg.Forensics.AnalysisDepth,
		cfg.Forensics.SessionGapMinutes,
		cfg.Forensics.AnomalyThreshold,
		cfg.Forensics.RetainProfilesDays,
		cfg.VDF.IterationsPerSecond,
		cfg.VDF.MinIterations,
		cfg.VDF.MaxIterations,
		cfg.VDF.Calibrated,
		cfg.VDF.DefaultDurationSec,
		cfg.Presence.Enabled,
		cfg.Presence.ChallengeIntervalSec,
		cfg.Presence.ResponseWindowSec,
		toTOMLArray(cfg.Presence.ChallengeTypes),
		cfg.Presence.MaxMissedChallenges,
		cfg.Logging.Level,
		cfg.Logging.Format,
		cfg.Logging.Output,
		cfg.Logging.FilePath,
		cfg.Logging.MaxSizeMB,
		cfg.Logging.MaxBackups,
		cfg.Logging.MaxAgeDays,
		cfg.Logging.Compress,
		cfg.IPC.Enabled,
		cfg.IPC.SocketPath,
		cfg.IPC.Permissions,
		cfg.IPC.MaxConnections,
		cfg.IPC.TimeoutSec,
		cfg.Sentinel.AutoStart,
		cfg.Sentinel.HeartbeatSec,
		cfg.Sentinel.CheckpointSec,
		toTOMLArray(cfg.Sentinel.WatchedPaths),
		cfg.Sentinel.PidFile,
		cfg.KeyHierarchy.Enabled,
		cfg.KeyHierarchy.Version,
		cfg.KeyHierarchy.IdentityPath,
		cfg.KeyHierarchy.SessionKeyRotationHours,
	)
}

func toTOMLArray(items []string) string {
	if len(items) == 0 {
		return "[]"
	}
	result := "["
	for i, item := range items {
		if i > 0 {
			result += ", "
		}
		result += fmt.Sprintf(`"%s"`, item)
	}
	result += "]"
	return result
}

func toTOMLIntArray(items []int) string {
	if len(items) == 0 {
		return "[]"
	}
	result := "["
	for i, item := range items {
		if i > 0 {
			result += ", "
		}
		result += fmt.Sprintf("%d", item)
	}
	result += "]"
	return result
}

// encodeToYAML encodes the config to YAML format.
func encodeToYAML(cfg *Config) ([]byte, error) {
	// For now, encode as JSON since YAML is a superset of JSON
	return json.MarshalIndent(cfg, "", "  ")
}

// GetMigrationHistory returns the migration history if stored in the config directory.
func GetMigrationHistory() ([]MigrationResult, error) {
	historyPath := filepath.Join(WitnessdDir(), "migration_history.json")

	data, err := os.ReadFile(historyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read migration history: %w", err)
	}

	var history []MigrationResult
	if err := json.Unmarshal(data, &history); err != nil {
		return nil, fmt.Errorf("parse migration history: %w", err)
	}

	return history, nil
}

// SaveMigrationHistory saves a migration result to the history file.
func SaveMigrationHistory(result *MigrationResult) error {
	historyPath := filepath.Join(WitnessdDir(), "migration_history.json")

	// Load existing history
	history, err := GetMigrationHistory()
	if err != nil {
		history = nil // Start fresh if error
	}

	// Append new result
	history = append(history, *result)

	// Save
	data, err := json.MarshalIndent(history, "", "  ")
	if err != nil {
		return fmt.Errorf("encode migration history: %w", err)
	}

	dir := filepath.Dir(historyPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	if err := os.WriteFile(historyPath, data, 0600); err != nil {
		return fmt.Errorf("write migration history: %w", err)
	}

	return nil
}
