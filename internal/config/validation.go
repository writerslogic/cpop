// Package config handles configuration loading and validation for witnessd.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ValidationError represents a configuration validation error.
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("config: %s: %s", e.Field, e.Message)
}

// ValidationErrors is a collection of validation errors.
type ValidationErrors []ValidationError

func (e ValidationErrors) Error() string {
	if len(e) == 0 {
		return ""
	}
	var msgs []string
	for _, err := range e {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// ValidateConfig performs comprehensive validation of the configuration.
func ValidateConfig(c *Config) error {
	var errs ValidationErrors

	// Validate version
	if c.Version < 1 || c.Version > Version {
		errs = append(errs, ValidationError{
			Field:   "version",
			Message: fmt.Sprintf("unsupported version %d (current: %d)", c.Version, Version),
		})
	}

	// Validate watch configuration
	if watchErrs := validateWatch(&c.Watch); len(watchErrs) > 0 {
		errs = append(errs, watchErrs...)
	}

	// Validate storage configuration
	if storageErrs := validateStorage(&c.Storage); len(storageErrs) > 0 {
		errs = append(errs, storageErrs...)
	}

	// Validate WAL configuration
	if walErrs := validateWAL(&c.WAL); len(walErrs) > 0 {
		errs = append(errs, walErrs...)
	}

	// Validate signing configuration
	if signingErrs := validateSigning(&c.Signing); len(signingErrs) > 0 {
		errs = append(errs, signingErrs...)
	}

	// Validate hardware configuration
	if hwErrs := validateHardware(&c.Hardware); len(hwErrs) > 0 {
		errs = append(errs, hwErrs...)
	}

	// Validate anchors configuration
	if anchorErrs := validateAnchors(&c.Anchors); len(anchorErrs) > 0 {
		errs = append(errs, anchorErrs...)
	}

	// Validate forensics configuration
	if forensicsErrs := validateForensics(&c.Forensics); len(forensicsErrs) > 0 {
		errs = append(errs, forensicsErrs...)
	}

	// Validate VDF configuration
	if vdfErrs := validateVDF(&c.VDF); len(vdfErrs) > 0 {
		errs = append(errs, vdfErrs...)
	}

	// Validate presence configuration
	if presenceErrs := validatePresence(&c.Presence); len(presenceErrs) > 0 {
		errs = append(errs, presenceErrs...)
	}

	// Validate logging configuration
	if loggingErrs := validateLogging(&c.Logging); len(loggingErrs) > 0 {
		errs = append(errs, loggingErrs...)
	}

	// Validate IPC configuration
	if ipcErrs := validateIPC(&c.IPC); len(ipcErrs) > 0 {
		errs = append(errs, ipcErrs...)
	}

	// Validate sentinel configuration
	if sentinelErrs := validateSentinel(&c.Sentinel); len(sentinelErrs) > 0 {
		errs = append(errs, sentinelErrs...)
	}

	// Validate key hierarchy configuration
	if khErrs := validateKeyHierarchy(&c.KeyHierarchy); len(khErrs) > 0 {
		errs = append(errs, khErrs...)
	}

	if len(errs) > 0 {
		return errs
	}
	return nil
}

func validateWatch(w *WatchConfig) ValidationErrors {
	var errs ValidationErrors

	// Validate paths exist (warning only, they might be created later)
	for i, path := range w.Paths {
		expandedPath := expandPath(path)
		if expandedPath == "" {
			errs = append(errs, ValidationError{
				Field:   fmt.Sprintf("watch.paths[%d]", i),
				Message: "path cannot be empty",
			})
		}
	}

	// Validate debounce interval
	if w.DebounceMs < 100 {
		errs = append(errs, ValidationError{
			Field:   "watch.debounce_ms",
			Message: "debounce must be at least 100ms",
		})
	}
	if w.DebounceMs > 60000 {
		errs = append(errs, ValidationError{
			Field:   "watch.debounce_ms",
			Message: "debounce cannot exceed 60000ms (1 minute)",
		})
	}

	// Validate checkpoint interval
	if w.CheckpointIntervalSec < 0 {
		errs = append(errs, ValidationError{
			Field:   "watch.checkpoint_interval_sec",
			Message: "checkpoint interval cannot be negative",
		})
	}

	// Validate max file size
	if w.MaxFileSize < 0 {
		errs = append(errs, ValidationError{
			Field:   "watch.max_file_size",
			Message: "max file size cannot be negative",
		})
	}

	// Validate glob patterns are valid
	for i, pattern := range w.IncludePatterns {
		if !isValidGlobPattern(pattern) {
			errs = append(errs, ValidationError{
				Field:   fmt.Sprintf("watch.include_patterns[%d]", i),
				Message: fmt.Sprintf("invalid glob pattern: %s", pattern),
			})
		}
	}

	for i, pattern := range w.ExcludePatterns {
		if !isValidGlobPattern(pattern) {
			errs = append(errs, ValidationError{
				Field:   fmt.Sprintf("watch.exclude_patterns[%d]", i),
				Message: fmt.Sprintf("invalid glob pattern: %s", pattern),
			})
		}
	}

	return errs
}

func validateStorage(s *StorageConfig) ValidationErrors {
	var errs ValidationErrors

	// Validate storage type
	switch s.Type {
	case "sqlite", "memory":
		// Valid types
	default:
		errs = append(errs, ValidationError{
			Field:   "storage.type",
			Message: fmt.Sprintf("invalid storage type: %s (valid: sqlite, memory)", s.Type),
		})
	}

	// SQLite-specific validation
	if s.Type == "sqlite" {
		if s.Path == "" {
			errs = append(errs, ValidationError{
				Field:   "storage.path",
				Message: "database path is required for sqlite storage",
			})
		}

		// Check parent directory exists or can be created
		dir := filepath.Dir(expandPath(s.Path))
		if dir != "" && dir != "." {
			if info, err := os.Stat(dir); err != nil {
				if !os.IsNotExist(err) {
					errs = append(errs, ValidationError{
						Field:   "storage.path",
						Message: fmt.Sprintf("cannot access directory: %v", err),
					})
				}
				// Directory doesn't exist yet - that's OK, it will be created
			} else if !info.IsDir() {
				errs = append(errs, ValidationError{
					Field:   "storage.path",
					Message: fmt.Sprintf("parent path is not a directory: %s", dir),
				})
			}
		}
	}

	// Validate connection settings
	if s.MaxConnections < 1 {
		errs = append(errs, ValidationError{
			Field:   "storage.max_connections",
			Message: "max connections must be at least 1",
		})
	}
	if s.MaxConnections > 100 {
		errs = append(errs, ValidationError{
			Field:   "storage.max_connections",
			Message: "max connections cannot exceed 100",
		})
	}

	if s.BusyTimeoutMs < 0 {
		errs = append(errs, ValidationError{
			Field:   "storage.busy_timeout_ms",
			Message: "busy timeout cannot be negative",
		})
	}

	return errs
}

func validateWAL(w *WALConfig) ValidationErrors {
	var errs ValidationErrors

	if !w.Enabled {
		return errs // Skip validation if WAL is disabled
	}

	if w.Path == "" {
		errs = append(errs, ValidationError{
			Field:   "wal.path",
			Message: "WAL path is required when enabled",
		})
	}

	if w.MaxSizeBytes < 1024*1024 { // Minimum 1MB
		errs = append(errs, ValidationError{
			Field:   "wal.max_size_bytes",
			Message: "WAL max size must be at least 1MB",
		})
	}

	switch w.SyncMode {
	case "off", "normal", "full":
		// Valid modes
	default:
		errs = append(errs, ValidationError{
			Field:   "wal.sync_mode",
			Message: fmt.Sprintf("invalid sync mode: %s (valid: off, normal, full)", w.SyncMode),
		})
	}

	if w.CheckpointThreshold < 100 {
		errs = append(errs, ValidationError{
			Field:   "wal.checkpoint_threshold",
			Message: "checkpoint threshold must be at least 100",
		})
	}

	if w.RetentionHours < 1 {
		errs = append(errs, ValidationError{
			Field:   "wal.retention_hours",
			Message: "retention hours must be at least 1",
		})
	}

	return errs
}

func validateSigning(s *SigningConfig) ValidationErrors {
	var errs ValidationErrors

	if s.KeyPath == "" {
		errs = append(errs, ValidationError{
			Field:   "signing.key_path",
			Message: "signing key path is required",
		})
	}

	switch s.Algorithm {
	case "ed25519", "ecdsa-p256":
		// Valid algorithms
	default:
		errs = append(errs, ValidationError{
			Field:   "signing.algorithm",
			Message: fmt.Sprintf("invalid algorithm: %s (valid: ed25519, ecdsa-p256)", s.Algorithm),
		})
	}

	if s.KeyRotationDays < 0 {
		errs = append(errs, ValidationError{
			Field:   "signing.key_rotation_days",
			Message: "key rotation days cannot be negative",
		})
	}

	return errs
}

func validateHardware(h *HardwareConfig) ValidationErrors {
	var errs ValidationErrors

	if h.TPMEnabled {
		// Validate TPM PCRs
		for i, pcr := range h.TPMPCRs {
			if pcr < 0 || pcr > 23 {
				errs = append(errs, ValidationError{
					Field:   fmt.Sprintf("hardware.tpm_pcrs[%d]", i),
					Message: fmt.Sprintf("PCR index must be 0-23, got %d", pcr),
				})
			}
		}
	}

	return errs
}

func validateAnchors(a *AnchorConfig) ValidationErrors {
	var errs ValidationErrors

	if !a.Enabled {
		return errs // Skip validation if anchors are disabled
	}

	// Validate enabled providers
	validProviders := map[string]bool{
		"opentimestamps": true,
		"rfc3161":        true,
		"drand":          true,
		"keybase":        true,
	}

	for i, provider := range a.Providers {
		if !validProviders[provider] {
			errs = append(errs, ValidationError{
				Field:   fmt.Sprintf("anchors.providers[%d]", i),
				Message: fmt.Sprintf("unknown provider: %s", provider),
			})
		}
	}

	// Validate OpenTimestamps config
	if a.OpenTimestamps.Enabled {
		for i, calendar := range a.OpenTimestamps.Calendars {
			if !isValidURL(calendar) {
				errs = append(errs, ValidationError{
					Field:   fmt.Sprintf("anchors.opentimestamps.calendars[%d]", i),
					Message: fmt.Sprintf("invalid URL: %s", calendar),
				})
			}
		}
		if a.OpenTimestamps.TimeoutSec < 1 {
			errs = append(errs, ValidationError{
				Field:   "anchors.opentimestamps.timeout_sec",
				Message: "timeout must be at least 1 second",
			})
		}
	}

	// Validate RFC3161 config
	if a.RFC3161.Enabled {
		if a.RFC3161.URL == "" {
			errs = append(errs, ValidationError{
				Field:   "anchors.rfc3161.url",
				Message: "TSA URL is required when RFC3161 is enabled",
			})
		} else if !isValidURL(a.RFC3161.URL) {
			errs = append(errs, ValidationError{
				Field:   "anchors.rfc3161.url",
				Message: fmt.Sprintf("invalid URL: %s", a.RFC3161.URL),
			})
		}
	}

	// Validate Drand config
	if a.Drand.Enabled {
		if a.Drand.ChainHash == "" {
			errs = append(errs, ValidationError{
				Field:   "anchors.drand.chain_hash",
				Message: "chain hash is required when drand is enabled",
			})
		}
		for i, u := range a.Drand.URLs {
			if !isValidURL(u) {
				errs = append(errs, ValidationError{
					Field:   fmt.Sprintf("anchors.drand.urls[%d]", i),
					Message: fmt.Sprintf("invalid URL: %s", u),
				})
			}
		}
	}

	// Validate retry settings
	if a.RetryAttempts < 0 {
		errs = append(errs, ValidationError{
			Field:   "anchors.retry_attempts",
			Message: "retry attempts cannot be negative",
		})
	}
	if a.RetryDelayMs < 0 {
		errs = append(errs, ValidationError{
			Field:   "anchors.retry_delay_ms",
			Message: "retry delay cannot be negative",
		})
	}

	return errs
}

func validateForensics(f *ForensicsConfig) ValidationErrors {
	var errs ValidationErrors

	if !f.Enabled {
		return errs
	}

	if f.SamplingRateMs < 10 {
		errs = append(errs, ValidationError{
			Field:   "forensics.sampling_rate_ms",
			Message: "sampling rate must be at least 10ms",
		})
	}

	switch f.AnalysisDepth {
	case "shallow", "normal", "deep":
		// Valid depths
	default:
		errs = append(errs, ValidationError{
			Field:   "forensics.analysis_depth",
			Message: fmt.Sprintf("invalid analysis depth: %s (valid: shallow, normal, deep)", f.AnalysisDepth),
		})
	}

	if f.SessionGapMinutes < 1 {
		errs = append(errs, ValidationError{
			Field:   "forensics.session_gap_minutes",
			Message: "session gap must be at least 1 minute",
		})
	}

	if f.AnomalyThreshold < 0.0 || f.AnomalyThreshold > 1.0 {
		errs = append(errs, ValidationError{
			Field:   "forensics.anomaly_threshold",
			Message: "anomaly threshold must be between 0.0 and 1.0",
		})
	}

	if f.RetainProfilesDays < 1 {
		errs = append(errs, ValidationError{
			Field:   "forensics.retain_profiles_days",
			Message: "profile retention must be at least 1 day",
		})
	}

	return errs
}

func validateVDF(v *VDFConfig) ValidationErrors {
	var errs ValidationErrors

	if v.IterationsPerSecond < 1000 {
		errs = append(errs, ValidationError{
			Field:   "vdf.iterations_per_second",
			Message: "iterations per second must be at least 1000",
		})
	}

	if v.MinIterations < 1000 {
		errs = append(errs, ValidationError{
			Field:   "vdf.min_iterations",
			Message: "minimum iterations must be at least 1000",
		})
	}

	if v.MaxIterations < v.MinIterations {
		errs = append(errs, ValidationError{
			Field:   "vdf.max_iterations",
			Message: "maximum iterations must be >= minimum iterations",
		})
	}

	if v.DefaultDurationSec < 1 {
		errs = append(errs, ValidationError{
			Field:   "vdf.default_duration_sec",
			Message: "default duration must be at least 1 second",
		})
	}

	return errs
}

func validatePresence(p *PresenceConfig) ValidationErrors {
	var errs ValidationErrors

	if !p.Enabled {
		return errs
	}

	if p.ChallengeIntervalSec < 60 {
		errs = append(errs, ValidationError{
			Field:   "presence.challenge_interval_sec",
			Message: "challenge interval must be at least 60 seconds",
		})
	}

	if p.ResponseWindowSec < 10 {
		errs = append(errs, ValidationError{
			Field:   "presence.response_window_sec",
			Message: "response window must be at least 10 seconds",
		})
	}

	if p.ResponseWindowSec >= p.ChallengeIntervalSec {
		errs = append(errs, ValidationError{
			Field:   "presence.response_window_sec",
			Message: "response window must be less than challenge interval",
		})
	}

	validTypes := map[string]bool{
		"math": true, "word": true, "memory": true, "captcha": true,
	}
	for i, t := range p.ChallengeTypes {
		if !validTypes[t] {
			errs = append(errs, ValidationError{
				Field:   fmt.Sprintf("presence.challenge_types[%d]", i),
				Message: fmt.Sprintf("invalid challenge type: %s", t),
			})
		}
	}

	if p.MaxMissedChallenges < 1 {
		errs = append(errs, ValidationError{
			Field:   "presence.max_missed_challenges",
			Message: "max missed challenges must be at least 1",
		})
	}

	return errs
}

func validateLogging(l *LoggingConfig) ValidationErrors {
	var errs ValidationErrors

	switch l.Level {
	case "debug", "info", "warn", "error":
		// Valid levels
	default:
		errs = append(errs, ValidationError{
			Field:   "logging.level",
			Message: fmt.Sprintf("invalid log level: %s (valid: debug, info, warn, error)", l.Level),
		})
	}

	switch l.Format {
	case "text", "json":
		// Valid formats
	default:
		errs = append(errs, ValidationError{
			Field:   "logging.format",
			Message: fmt.Sprintf("invalid log format: %s (valid: text, json)", l.Format),
		})
	}

	switch l.Output {
	case "stdout", "stderr", "file":
		// Valid outputs
		if l.Output == "file" && l.FilePath == "" {
			errs = append(errs, ValidationError{
				Field:   "logging.file_path",
				Message: "file path is required when output is 'file'",
			})
		}
	default:
		// Assume it's a file path
		if l.Output == "" {
			errs = append(errs, ValidationError{
				Field:   "logging.output",
				Message: "log output is required",
			})
		}
	}

	if l.MaxSizeMB < 1 {
		errs = append(errs, ValidationError{
			Field:   "logging.max_size_mb",
			Message: "max size must be at least 1 MB",
		})
	}

	if l.MaxBackups < 0 {
		errs = append(errs, ValidationError{
			Field:   "logging.max_backups",
			Message: "max backups cannot be negative",
		})
	}

	if l.MaxAgeDays < 0 {
		errs = append(errs, ValidationError{
			Field:   "logging.max_age_days",
			Message: "max age cannot be negative",
		})
	}

	return errs
}

func validateIPC(i *IPCConfig) ValidationErrors {
	var errs ValidationErrors

	if !i.Enabled {
		return errs
	}

	if i.SocketPath == "" {
		errs = append(errs, ValidationError{
			Field:   "ipc.socket_path",
			Message: "socket path is required when IPC is enabled",
		})
	}

	// Validate permissions format (Unix only)
	if i.Permissions != "" {
		if matched, _ := regexp.MatchString(`^0[0-7]{3}$`, i.Permissions); !matched {
			errs = append(errs, ValidationError{
				Field:   "ipc.permissions",
				Message: fmt.Sprintf("invalid permissions format: %s (expected octal like 0600)", i.Permissions),
			})
		}
	}

	if i.MaxConnections < 1 {
		errs = append(errs, ValidationError{
			Field:   "ipc.max_connections",
			Message: "max connections must be at least 1",
		})
	}

	if i.TimeoutSec < 1 {
		errs = append(errs, ValidationError{
			Field:   "ipc.timeout_sec",
			Message: "timeout must be at least 1 second",
		})
	}

	return errs
}

func validateSentinel(s *SentinelConfig) ValidationErrors {
	var errs ValidationErrors

	if s.HeartbeatSec < 10 {
		errs = append(errs, ValidationError{
			Field:   "sentinel.heartbeat_sec",
			Message: "heartbeat interval must be at least 10 seconds",
		})
	}

	if s.CheckpointSec < 10 {
		errs = append(errs, ValidationError{
			Field:   "sentinel.checkpoint_sec",
			Message: "checkpoint interval must be at least 10 seconds",
		})
	}

	return errs
}

func validateKeyHierarchy(k *KeyHierarchyConfig) ValidationErrors {
	var errs ValidationErrors

	if !k.Enabled {
		return errs
	}

	if k.Version < 1 {
		errs = append(errs, ValidationError{
			Field:   "key_hierarchy.version",
			Message: "key hierarchy version must be at least 1",
		})
	}

	if k.SessionKeyRotationHours < 1 {
		errs = append(errs, ValidationError{
			Field:   "key_hierarchy.session_key_rotation_hours",
			Message: "session key rotation must be at least 1 hour",
		})
	}

	return errs
}

// Helper functions

func expandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return filepath.Join(home, path[2:])
	}
	return path
}

func isValidGlobPattern(pattern string) bool {
	// Basic validation - check for invalid characters
	if pattern == "" {
		return false
	}
	// Try to compile the pattern
	_, err := filepath.Match(pattern, "test")
	return err == nil
}

func isValidURL(rawURL string) bool {
	if rawURL == "" {
		return false
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return u.Scheme == "http" || u.Scheme == "https"
}

// IsWarning returns true if this is a non-fatal validation issue.
func (e *ValidationError) IsWarning() bool {
	// Some fields are warnings, not errors
	warningFields := []string{
		"watch.paths", // Paths might not exist yet
	}
	for _, f := range warningFields {
		if strings.HasPrefix(e.Field, f) {
			return true
		}
	}
	return false
}

// Warnings returns only warning-level validation errors.
func (e ValidationErrors) Warnings() ValidationErrors {
	var warnings ValidationErrors
	for _, err := range e {
		if err.IsWarning() {
			warnings = append(warnings, err)
		}
	}
	return warnings
}

// Errors returns only error-level validation errors.
func (e ValidationErrors) Errors() ValidationErrors {
	var errs ValidationErrors
	for _, err := range e {
		if !err.IsWarning() {
			errs = append(errs, err)
		}
	}
	return errs
}

// HasErrors returns true if there are any non-warning errors.
func (e ValidationErrors) HasErrors() bool {
	return len(e.Errors()) > 0
}

// RequiredFieldError creates a validation error for a required field.
func RequiredFieldError(field string) *ValidationError {
	return &ValidationError{
		Field:   field,
		Message: "required field is missing",
	}
}

// RangeError creates a validation error for an out-of-range value.
func RangeError(field string, min, max interface{}) *ValidationError {
	return &ValidationError{
		Field:   field,
		Message: fmt.Sprintf("value must be between %v and %v", min, max),
	}
}

// TypeError creates a validation error for an invalid type.
func TypeError(field, expected string) *ValidationError {
	return &ValidationError{
		Field:   field,
		Message: fmt.Sprintf("expected type %s", expected),
	}
}

// ErrInvalidConfig is returned when validation fails.
var ErrInvalidConfig = errors.New("invalid configuration")
