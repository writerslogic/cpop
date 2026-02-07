// Package config handles configuration loading, validation, and management for witnessd.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
)

// Version is the current configuration schema version.
const Version = 5

// Config holds the complete daemon configuration.
type Config struct {
	// Version is the configuration schema version for migrations.
	Version int `toml:"version" json:"version" yaml:"version"`

	// Watch configuration for file monitoring.
	Watch WatchConfig `toml:"watch" json:"watch" yaml:"watch"`

	// Storage configuration for persistence.
	Storage StorageConfig `toml:"storage" json:"storage" yaml:"storage"`

	// WAL (Write-Ahead Log) configuration.
	WAL WALConfig `toml:"wal" json:"wal" yaml:"wal"`

	// Signing configuration for cryptographic operations.
	Signing SigningConfig `toml:"signing" json:"signing" yaml:"signing"`

	// TPM/hardware security configuration.
	Hardware HardwareConfig `toml:"hardware" json:"hardware" yaml:"hardware"`

	// Anchor configuration for external timestamp services.
	Anchors AnchorConfig `toml:"anchors" json:"anchors" yaml:"anchors"`

	// Forensics configuration for authorship analysis.
	Forensics ForensicsConfig `toml:"forensics" json:"forensics" yaml:"forensics"`

	// VDF (Verifiable Delay Function) configuration.
	VDF VDFConfig `toml:"vdf" json:"vdf" yaml:"vdf"`

	// Presence configuration for human verification.
	Presence PresenceConfig `toml:"presence" json:"presence" yaml:"presence"`

	// Logging configuration.
	Logging LoggingConfig `toml:"logging" json:"logging" yaml:"logging"`

	// IPC configuration for inter-process communication.
	IPC IPCConfig `toml:"ipc" json:"ipc" yaml:"ipc"`

	// Sentinel configuration for background daemon.
	Sentinel SentinelConfig `toml:"sentinel" json:"sentinel" yaml:"sentinel"`

	// KeyHierarchy configuration for ratcheting keys.
	KeyHierarchy KeyHierarchyConfig `toml:"key_hierarchy" json:"key_hierarchy" yaml:"key_hierarchy"`

	// mu protects concurrent access to the config.
	mu sync.RWMutex `toml:"-" json:"-" yaml:"-"`
}

// WatchConfig holds file watching configuration.
type WatchConfig struct {
	// Paths is a list of directories to monitor for changes.
	Paths []string `toml:"paths" json:"paths" yaml:"paths"`

	// IncludePatterns are glob patterns for files to include.
	// If empty, all files are included.
	IncludePatterns []string `toml:"include_patterns" json:"include_patterns" yaml:"include_patterns"`

	// ExcludePatterns are glob patterns for files to exclude.
	ExcludePatterns []string `toml:"exclude_patterns" json:"exclude_patterns" yaml:"exclude_patterns"`

	// DebounceMs is the debounce interval in milliseconds.
	// Files must be stable for this duration before witnessing.
	DebounceMs int `toml:"debounce_ms" json:"debounce_ms" yaml:"debounce_ms"`

	// CheckpointIntervalSec is the automatic checkpoint interval in seconds.
	// Set to 0 to disable automatic checkpoints.
	CheckpointIntervalSec int `toml:"checkpoint_interval_sec" json:"checkpoint_interval_sec" yaml:"checkpoint_interval_sec"`

	// MaxFileSize is the maximum file size to process in bytes.
	// Files larger than this are skipped.
	MaxFileSize int64 `toml:"max_file_size" json:"max_file_size" yaml:"max_file_size"`

	// FollowSymlinks determines whether to follow symbolic links.
	FollowSymlinks bool `toml:"follow_symlinks" json:"follow_symlinks" yaml:"follow_symlinks"`

	// Recursive determines whether to watch subdirectories.
	Recursive bool `toml:"recursive" json:"recursive" yaml:"recursive"`
}

// StorageConfig holds persistence configuration.
type StorageConfig struct {
	// Type is the storage backend type: "sqlite" or "memory".
	Type string `toml:"type" json:"type" yaml:"type"`

	// Path is the path to the database file (for sqlite).
	Path string `toml:"path" json:"path" yaml:"path"`

	// Secure enables tamper-evident storage with HMAC verification.
	Secure bool `toml:"secure" json:"secure" yaml:"secure"`

	// MMRPath is the path to the MMR (Merkle Mountain Range) database.
	MMRPath string `toml:"mmr_path" json:"mmr_path" yaml:"mmr_path"`

	// EventStorePath is the path to the event store database.
	EventStorePath string `toml:"event_store_path" json:"event_store_path" yaml:"event_store_path"`

	// SignaturesPath is the path to store signature mappings.
	SignaturesPath string `toml:"signatures_path" json:"signatures_path" yaml:"signatures_path"`

	// MaxConnections is the maximum number of database connections.
	MaxConnections int `toml:"max_connections" json:"max_connections" yaml:"max_connections"`

	// BusyTimeoutMs is the SQLite busy timeout in milliseconds.
	BusyTimeoutMs int `toml:"busy_timeout_ms" json:"busy_timeout_ms" yaml:"busy_timeout_ms"`
}

// WALConfig holds Write-Ahead Log configuration.
type WALConfig struct {
	// Enabled determines whether WAL is enabled.
	Enabled bool `toml:"enabled" json:"enabled" yaml:"enabled"`

	// Path is the path to the WAL directory.
	Path string `toml:"path" json:"path" yaml:"path"`

	// MaxSizeBytes is the maximum WAL file size before rotation.
	MaxSizeBytes int64 `toml:"max_size_bytes" json:"max_size_bytes" yaml:"max_size_bytes"`

	// SyncMode determines the sync behavior: "off", "normal", "full".
	SyncMode string `toml:"sync_mode" json:"sync_mode" yaml:"sync_mode"`

	// CheckpointThreshold is the number of frames before auto-checkpoint.
	CheckpointThreshold int `toml:"checkpoint_threshold" json:"checkpoint_threshold" yaml:"checkpoint_threshold"`

	// RetentionHours is how long to keep WAL segments.
	RetentionHours int `toml:"retention_hours" json:"retention_hours" yaml:"retention_hours"`
}

// SigningConfig holds cryptographic signing configuration.
type SigningConfig struct {
	// KeyPath is the path to the Ed25519 private key.
	KeyPath string `toml:"key_path" json:"key_path" yaml:"key_path"`

	// PublicKeyPath is the path to the Ed25519 public key.
	PublicKeyPath string `toml:"public_key_path" json:"public_key_path" yaml:"public_key_path"`

	// Algorithm is the signing algorithm: "ed25519" (default) or "ecdsa-p256".
	Algorithm string `toml:"algorithm" json:"algorithm" yaml:"algorithm"`

	// KeyRotationDays is the number of days before key rotation reminder.
	KeyRotationDays int `toml:"key_rotation_days" json:"key_rotation_days" yaml:"key_rotation_days"`
}

// HardwareConfig holds TPM and hardware security configuration.
type HardwareConfig struct {
	// TPMEnabled determines whether to use TPM for attestation.
	TPMEnabled bool `toml:"tpm_enabled" json:"tpm_enabled" yaml:"tpm_enabled"`

	// TPMPath is the path to the TPM device (Linux: /dev/tpm0, /dev/tpmrm0).
	TPMPath string `toml:"tpm_path" json:"tpm_path" yaml:"tpm_path"`

	// TPMPCRs is the list of PCR indices to include in attestation.
	TPMPCRs []int `toml:"tpm_pcrs" json:"tpm_pcrs" yaml:"tpm_pcrs"`

	// SecureEnclaveEnabled determines whether to use Secure Enclave (macOS/iOS).
	SecureEnclaveEnabled bool `toml:"secure_enclave_enabled" json:"secure_enclave_enabled" yaml:"secure_enclave_enabled"`

	// PUFSeedPath is the path to the software PUF seed file.
	PUFSeedPath string `toml:"puf_seed_path" json:"puf_seed_path" yaml:"puf_seed_path"`
}

// AnchorConfig holds external timestamp anchor configuration.
type AnchorConfig struct {
	// Enabled determines whether external anchoring is enabled.
	Enabled bool `toml:"enabled" json:"enabled" yaml:"enabled"`

	// Providers is the list of enabled anchor providers.
	Providers []string `toml:"providers" json:"providers" yaml:"providers"`

	// OpenTimestamps configuration.
	OpenTimestamps OpenTimestampsConfig `toml:"opentimestamps" json:"opentimestamps" yaml:"opentimestamps"`

	// RFC3161 configuration.
	RFC3161 RFC3161Config `toml:"rfc3161" json:"rfc3161" yaml:"rfc3161"`

	// Drand configuration.
	Drand DrandConfig `toml:"drand" json:"drand" yaml:"drand"`

	// BatchIntervalSec is the interval for batching multiple hashes.
	BatchIntervalSec int `toml:"batch_interval_sec" json:"batch_interval_sec" yaml:"batch_interval_sec"`

	// RetryAttempts is the number of retry attempts for failed anchors.
	RetryAttempts int `toml:"retry_attempts" json:"retry_attempts" yaml:"retry_attempts"`

	// RetryDelayMs is the delay between retry attempts.
	RetryDelayMs int `toml:"retry_delay_ms" json:"retry_delay_ms" yaml:"retry_delay_ms"`
}

// OpenTimestampsConfig holds OpenTimestamps-specific configuration.
type OpenTimestampsConfig struct {
	// Enabled determines whether OpenTimestamps is enabled.
	Enabled bool `toml:"enabled" json:"enabled" yaml:"enabled"`

	// Calendars is the list of calendar server URLs.
	Calendars []string `toml:"calendars" json:"calendars" yaml:"calendars"`

	// TimeoutSec is the timeout for calendar requests.
	TimeoutSec int `toml:"timeout_sec" json:"timeout_sec" yaml:"timeout_sec"`
}

// RFC3161Config holds RFC 3161 TSA configuration.
type RFC3161Config struct {
	// Enabled determines whether RFC 3161 is enabled.
	Enabled bool `toml:"enabled" json:"enabled" yaml:"enabled"`

	// URL is the TSA server URL.
	URL string `toml:"url" json:"url" yaml:"url"`

	// CertPath is the path to the TSA certificate for verification.
	CertPath string `toml:"cert_path" json:"cert_path" yaml:"cert_path"`

	// TimeoutSec is the timeout for TSA requests.
	TimeoutSec int `toml:"timeout_sec" json:"timeout_sec" yaml:"timeout_sec"`

	// Username for authenticated TSA services.
	Username string `toml:"username" json:"username" yaml:"username"`

	// Password for authenticated TSA services (use env var WITNESSD_RFC3161_PASSWORD).
	Password string `toml:"password" json:"password" yaml:"password"`
}

// DrandConfig holds drand randomness beacon configuration.
type DrandConfig struct {
	// Enabled determines whether drand anchoring is enabled.
	Enabled bool `toml:"enabled" json:"enabled" yaml:"enabled"`

	// ChainHash is the drand chain hash to use.
	ChainHash string `toml:"chain_hash" json:"chain_hash" yaml:"chain_hash"`

	// URLs is the list of drand HTTP endpoints.
	URLs []string `toml:"urls" json:"urls" yaml:"urls"`
}

// ForensicsConfig holds forensic analysis configuration.
type ForensicsConfig struct {
	// Enabled determines whether forensic analysis is enabled.
	Enabled bool `toml:"enabled" json:"enabled" yaml:"enabled"`

	// SamplingRateMs is the sampling interval for edit pattern analysis.
	SamplingRateMs int `toml:"sampling_rate_ms" json:"sampling_rate_ms" yaml:"sampling_rate_ms"`

	// AnalysisDepth determines how many events to analyze: "shallow", "normal", "deep".
	AnalysisDepth string `toml:"analysis_depth" json:"analysis_depth" yaml:"analysis_depth"`

	// SessionGapMinutes defines the gap that starts a new session.
	SessionGapMinutes int `toml:"session_gap_minutes" json:"session_gap_minutes" yaml:"session_gap_minutes"`

	// AnomalyThreshold is the threshold for flagging anomalies (0.0-1.0).
	AnomalyThreshold float64 `toml:"anomaly_threshold" json:"anomaly_threshold" yaml:"anomaly_threshold"`

	// RetainProfilesDays is how long to keep forensic profiles.
	RetainProfilesDays int `toml:"retain_profiles_days" json:"retain_profiles_days" yaml:"retain_profiles_days"`
}

// VDFConfig holds Verifiable Delay Function configuration.
type VDFConfig struct {
	// IterationsPerSecond is the calibrated iteration rate.
	IterationsPerSecond uint64 `toml:"iterations_per_second" json:"iterations_per_second" yaml:"iterations_per_second"`

	// MinIterations is the minimum iterations for any proof.
	MinIterations uint64 `toml:"min_iterations" json:"min_iterations" yaml:"min_iterations"`

	// MaxIterations is the maximum iterations (1 hour default).
	MaxIterations uint64 `toml:"max_iterations" json:"max_iterations" yaml:"max_iterations"`

	// Calibrated indicates whether VDF has been calibrated.
	Calibrated bool `toml:"calibrated" json:"calibrated" yaml:"calibrated"`

	// CalibratedAt is when calibration was performed.
	CalibratedAt time.Time `toml:"calibrated_at" json:"calibrated_at" yaml:"calibrated_at"`

	// DefaultDurationSec is the default VDF duration target.
	DefaultDurationSec int `toml:"default_duration_sec" json:"default_duration_sec" yaml:"default_duration_sec"`
}

// PresenceConfig holds human presence verification configuration.
type PresenceConfig struct {
	// Enabled determines whether presence verification is enabled.
	Enabled bool `toml:"enabled" json:"enabled" yaml:"enabled"`

	// ChallengeIntervalSec is the interval between challenges.
	ChallengeIntervalSec int `toml:"challenge_interval_sec" json:"challenge_interval_sec" yaml:"challenge_interval_sec"`

	// ResponseWindowSec is the time allowed to respond to a challenge.
	ResponseWindowSec int `toml:"response_window_sec" json:"response_window_sec" yaml:"response_window_sec"`

	// ChallengeTypes is the list of challenge types to use.
	ChallengeTypes []string `toml:"challenge_types" json:"challenge_types" yaml:"challenge_types"`

	// MaxMissedChallenges before session is marked failed.
	MaxMissedChallenges int `toml:"max_missed_challenges" json:"max_missed_challenges" yaml:"max_missed_challenges"`
}

// LoggingConfig holds logging configuration.
type LoggingConfig struct {
	// Level is the log level: "debug", "info", "warn", "error".
	Level string `toml:"level" json:"level" yaml:"level"`

	// Format is the log format: "text" or "json".
	Format string `toml:"format" json:"format" yaml:"format"`

	// Output is the log output: "stdout", "stderr", "file", or a file path.
	Output string `toml:"output" json:"output" yaml:"output"`

	// FilePath is the path to the log file (when Output is "file").
	FilePath string `toml:"file_path" json:"file_path" yaml:"file_path"`

	// MaxSizeMB is the maximum log file size before rotation.
	MaxSizeMB int `toml:"max_size_mb" json:"max_size_mb" yaml:"max_size_mb"`

	// MaxBackups is the number of old log files to keep.
	MaxBackups int `toml:"max_backups" json:"max_backups" yaml:"max_backups"`

	// MaxAgeDays is the maximum age of log files in days.
	MaxAgeDays int `toml:"max_age_days" json:"max_age_days" yaml:"max_age_days"`

	// Compress determines whether to compress rotated logs.
	Compress bool `toml:"compress" json:"compress" yaml:"compress"`
}

// IPCConfig holds inter-process communication configuration.
type IPCConfig struct {
	// Enabled determines whether IPC server is enabled.
	Enabled bool `toml:"enabled" json:"enabled" yaml:"enabled"`

	// SocketPath is the path to the Unix socket (or named pipe on Windows).
	SocketPath string `toml:"socket_path" json:"socket_path" yaml:"socket_path"`

	// Permissions is the Unix socket permissions (e.g., "0600").
	Permissions string `toml:"permissions" json:"permissions" yaml:"permissions"`

	// MaxConnections is the maximum concurrent connections.
	MaxConnections int `toml:"max_connections" json:"max_connections" yaml:"max_connections"`

	// TimeoutSec is the connection timeout.
	TimeoutSec int `toml:"timeout_sec" json:"timeout_sec" yaml:"timeout_sec"`
}

// SentinelConfig holds background daemon configuration.
type SentinelConfig struct {
	// AutoStart determines whether sentinel starts automatically.
	AutoStart bool `toml:"auto_start" json:"auto_start" yaml:"auto_start"`

	// HeartbeatSec is the heartbeat interval.
	HeartbeatSec int `toml:"heartbeat_sec" json:"heartbeat_sec" yaml:"heartbeat_sec"`

	// CheckpointSec is the automatic checkpoint interval.
	CheckpointSec int `toml:"checkpoint_sec" json:"checkpoint_sec" yaml:"checkpoint_sec"`

	// WatchedPaths is the list of paths to watch.
	WatchedPaths []string `toml:"watched_paths" json:"watched_paths" yaml:"watched_paths"`

	// PidFile is the path to the PID file.
	PidFile string `toml:"pid_file" json:"pid_file" yaml:"pid_file"`
}

// KeyHierarchyConfig holds ratcheting key hierarchy configuration.
type KeyHierarchyConfig struct {
	// Enabled determines whether key hierarchy is enabled.
	Enabled bool `toml:"enabled" json:"enabled" yaml:"enabled"`

	// Version is the key hierarchy protocol version.
	Version int `toml:"version" json:"version" yaml:"version"`

	// IdentityPath is the path to the master identity file.
	IdentityPath string `toml:"identity_path" json:"identity_path" yaml:"identity_path"`

	// SessionKeyRotationHours is how often to rotate session keys.
	SessionKeyRotationHours int `toml:"session_key_rotation_hours" json:"session_key_rotation_hours" yaml:"session_key_rotation_hours"`
}

// DefaultConfig returns a configuration with sensible defaults.
func DefaultConfig() *Config {
	dir := WitnessdDir()

	return &Config{
		Version: Version,
		Watch: WatchConfig{
			Paths:                 []string{},
			IncludePatterns:       []string{"*.txt", "*.md", "*.doc", "*.docx", "*.rtf", "*.tex"},
			ExcludePatterns:       []string{".*", "*~", "*.tmp", "*.swp"},
			DebounceMs:            5000,
			CheckpointIntervalSec: 0, // Disabled by default
			MaxFileSize:           100 * 1024 * 1024, // 100MB
			FollowSymlinks:        false,
			Recursive:             true,
		},
		Storage: StorageConfig{
			Type:           "sqlite",
			Path:           filepath.Join(dir, "events.db"),
			Secure:         true,
			MMRPath:        filepath.Join(dir, "mmr.db"),
			EventStorePath: filepath.Join(dir, "events.db"),
			SignaturesPath: filepath.Join(dir, "signatures.sigs"),
			MaxConnections: 5,
			BusyTimeoutMs:  5000,
		},
		WAL: WALConfig{
			Enabled:             true,
			Path:                filepath.Join(dir, "wal"),
			MaxSizeBytes:        64 * 1024 * 1024, // 64MB
			SyncMode:            "normal",
			CheckpointThreshold: 1000,
			RetentionHours:      168, // 1 week
		},
		Signing: SigningConfig{
			KeyPath:         filepath.Join(dir, "signing_key"),
			PublicKeyPath:   filepath.Join(dir, "signing_key.pub"),
			Algorithm:       "ed25519",
			KeyRotationDays: 365,
		},
		Hardware: HardwareConfig{
			TPMEnabled:           false,
			TPMPath:              defaultTPMPath(),
			TPMPCRs:              []int{0, 1, 2, 3, 7},
			SecureEnclaveEnabled: runtime.GOOS == "darwin",
			PUFSeedPath:          filepath.Join(dir, "puf_seed"),
		},
		Anchors: AnchorConfig{
			Enabled:          false,
			Providers:        []string{},
			BatchIntervalSec: 300, // 5 minutes
			RetryAttempts:    3,
			RetryDelayMs:     5000,
			OpenTimestamps: OpenTimestampsConfig{
				Enabled: false,
				Calendars: []string{
					"https://a.pool.opentimestamps.org",
					"https://b.pool.opentimestamps.org",
				},
				TimeoutSec: 30,
			},
			RFC3161: RFC3161Config{
				Enabled:    false,
				URL:        "",
				TimeoutSec: 30,
			},
			Drand: DrandConfig{
				Enabled:   false,
				ChainHash: "8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce",
				URLs: []string{
					"https://api.drand.sh",
					"https://drand.cloudflare.com",
				},
			},
		},
		Forensics: ForensicsConfig{
			Enabled:            true,
			SamplingRateMs:     100,
			AnalysisDepth:      "normal",
			SessionGapMinutes:  30,
			AnomalyThreshold:   0.15,
			RetainProfilesDays: 90,
		},
		VDF: VDFConfig{
			IterationsPerSecond: 1000000,
			MinIterations:       100000,
			MaxIterations:       3600000000, // 1 hour at 1M/sec
			Calibrated:          false,
			DefaultDurationSec:  1,
		},
		Presence: PresenceConfig{
			Enabled:              false,
			ChallengeIntervalSec: 600, // 10 minutes
			ResponseWindowSec:    60,
			ChallengeTypes:       []string{"math", "word", "memory"},
			MaxMissedChallenges:  3,
		},
		Logging: LoggingConfig{
			Level:      "info",
			Format:     "text",
			Output:     "file",
			FilePath:   filepath.Join(dir, "witnessd.log"),
			MaxSizeMB:  100,
			MaxBackups: 5,
			MaxAgeDays: 30,
			Compress:   true,
		},
		IPC: IPCConfig{
			Enabled:        true,
			SocketPath:     defaultSocketPath(),
			Permissions:    "0600",
			MaxConnections: 10,
			TimeoutSec:     30,
		},
		Sentinel: SentinelConfig{
			AutoStart:     false,
			HeartbeatSec:  60,
			CheckpointSec: 60,
			WatchedPaths:  []string{},
			PidFile:       filepath.Join(dir, "sentinel.pid"),
		},
		KeyHierarchy: KeyHierarchyConfig{
			Enabled:                 true,
			Version:                 1,
			IdentityPath:            filepath.Join(dir, "identity.json"),
			SessionKeyRotationHours: 24,
		},
	}
}

// ConfigPath returns the default configuration file path.
func ConfigPath() string {
	return filepath.Join(WitnessdDir(), "config.toml")
}

// Load reads configuration from the specified path.
// If the file doesn't exist, returns default configuration.
// Supports TOML, JSON, and YAML formats based on file extension.
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
		return nil, fmt.Errorf("read config file: %w", err)
	}

	// Determine format from extension
	ext := filepath.Ext(path)
	switch ext {
	case ".toml":
		if _, err := toml.Decode(string(data), cfg); err != nil {
			return nil, fmt.Errorf("decode TOML: %w", err)
		}
	case ".json":
		if err := decodeJSON(data, cfg); err != nil {
			return nil, fmt.Errorf("decode JSON: %w", err)
		}
	case ".yaml", ".yml":
		if err := decodeYAML(data, cfg); err != nil {
			return nil, fmt.Errorf("decode YAML: %w", err)
		}
	default:
		// Try TOML by default
		if _, err := toml.Decode(string(data), cfg); err != nil {
			return nil, fmt.Errorf("decode config (unknown format): %w", err)
		}
	}

	// Apply environment variable overrides
	cfg.ApplyEnvOverrides()

	return cfg, nil
}

// Validate checks the configuration for errors.
func (c *Config) Validate() error {
	return ValidateConfig(c)
}

// EnsureDirectories creates all necessary directories for the daemon.
func (c *Config) EnsureDirectories() error {
	dirs := []string{
		filepath.Dir(c.Storage.Path),
		filepath.Dir(c.Storage.MMRPath),
		filepath.Dir(c.Storage.EventStorePath),
		filepath.Dir(c.Storage.SignaturesPath),
		filepath.Dir(c.Signing.KeyPath),
		filepath.Dir(c.Logging.FilePath),
		c.WAL.Path,
	}

	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("create directory %s: %w", dir, err)
		}
	}

	return nil
}

// WitnessdDir returns the base witnessd directory.
// Uses platform-specific paths or WITNESSD_DATA_DIR environment override.
func WitnessdDir() string {
	// Check for override via environment variable (used by sandboxed macOS app)
	if envDir := os.Getenv("WITNESSD_DATA_DIR"); envDir != "" {
		return envDir
	}
	return PlatformDataDir()
}

// ApplyEnvOverrides applies environment variable overrides to the configuration.
// Environment variables are prefixed with WITNESSD_ and use underscores.
func (c *Config) ApplyEnvOverrides() {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Storage overrides
	if v := os.Getenv("WITNESSD_STORAGE_PATH"); v != "" {
		c.Storage.Path = v
	}
	if v := os.Getenv("WITNESSD_MMR_PATH"); v != "" {
		c.Storage.MMRPath = v
	}

	// Signing overrides
	if v := os.Getenv("WITNESSD_SIGNING_KEY_PATH"); v != "" {
		c.Signing.KeyPath = v
	}

	// Logging overrides
	if v := os.Getenv("WITNESSD_LOG_LEVEL"); v != "" {
		c.Logging.Level = v
	}
	if v := os.Getenv("WITNESSD_LOG_PATH"); v != "" {
		c.Logging.FilePath = v
	}

	// IPC overrides
	if v := os.Getenv("WITNESSD_SOCKET_PATH"); v != "" {
		c.IPC.SocketPath = v
	}

	// Anchor credentials from env (for security)
	if v := os.Getenv("WITNESSD_RFC3161_PASSWORD"); v != "" {
		c.Anchors.RFC3161.Password = v
	}

	// Hardware overrides
	if v := os.Getenv("WITNESSD_TPM_PATH"); v != "" {
		c.Hardware.TPMPath = v
	}
}

// Clone returns a deep copy of the configuration.
func (c *Config) Clone() *Config {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Create new config and copy values
	clone := *c

	// Deep copy slices
	clone.Watch.Paths = append([]string{}, c.Watch.Paths...)
	clone.Watch.IncludePatterns = append([]string{}, c.Watch.IncludePatterns...)
	clone.Watch.ExcludePatterns = append([]string{}, c.Watch.ExcludePatterns...)
	clone.Anchors.Providers = append([]string{}, c.Anchors.Providers...)
	clone.Anchors.OpenTimestamps.Calendars = append([]string{}, c.Anchors.OpenTimestamps.Calendars...)
	clone.Anchors.Drand.URLs = append([]string{}, c.Anchors.Drand.URLs...)
	clone.Hardware.TPMPCRs = append([]int{}, c.Hardware.TPMPCRs...)
	clone.Presence.ChallengeTypes = append([]string{}, c.Presence.ChallengeTypes...)
	clone.Sentinel.WatchedPaths = append([]string{}, c.Sentinel.WatchedPaths...)

	return &clone
}

// Helper functions

func defaultTPMPath() string {
	switch runtime.GOOS {
	case "linux":
		// Prefer the resource manager path
		if _, err := os.Stat("/dev/tpmrm0"); err == nil {
			return "/dev/tpmrm0"
		}
		return "/dev/tpm0"
	case "windows":
		return "" // Windows uses the TBS API
	default:
		return ""
	}
}

func defaultSocketPath() string {
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(os.Getenv("HOME"), "Library", "Application Support", "witnessd", "witnessd.sock")
	case "linux":
		// Prefer XDG_RUNTIME_DIR
		if xdgRuntime := os.Getenv("XDG_RUNTIME_DIR"); xdgRuntime != "" {
			return filepath.Join(xdgRuntime, "witnessd.sock")
		}
		return "/tmp/witnessd.sock"
	case "windows":
		return `\\.\pipe\witnessd`
	default:
		return "/tmp/witnessd.sock"
	}
}

// Legacy compatibility function - returns Interval in seconds from DebounceMs
func (c *Config) Interval() int {
	return c.Watch.DebounceMs / 1000
}

// Legacy compatibility - WatchPaths returns the watch paths
func (c *Config) WatchPaths() []string {
	return c.Watch.Paths
}

// Legacy compatibility - DatabasePath returns the storage path
func (c *Config) DatabasePath() string {
	return c.Storage.Path
}

// Legacy compatibility - LogPath returns the log file path
func (c *Config) LogPath() string {
	return c.Logging.FilePath
}

// Legacy compatibility - SigningKeyPath returns the signing key path
func (c *Config) SigningKeyPath() string {
	return c.Signing.KeyPath
}

// Placeholder for JSON decoder - implemented in loader.go
func decodeJSON(data []byte, cfg *Config) error {
	return errors.New("JSON config loading requires loader.go")
}

// Placeholder for YAML decoder - implemented in loader.go
func decodeYAML(data []byte, cfg *Config) error {
	return errors.New("YAML config loading requires loader.go")
}
