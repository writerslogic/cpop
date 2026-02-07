// Package logging provides structured logging with slog for witnessd.
package logging

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// AuditEventType represents the type of audit event.
type AuditEventType string

// Audit event types.
const (
	AuditEventSessionStart   AuditEventType = "session_start"
	AuditEventSessionEnd     AuditEventType = "session_end"
	AuditEventConfigChange   AuditEventType = "config_change"
	AuditEventKeyGenerated   AuditEventType = "key_generated"
	AuditEventKeyAccess      AuditEventType = "key_access"
	AuditEventCheckpoint     AuditEventType = "checkpoint"
	AuditEventVerification   AuditEventType = "verification"
	AuditEventExport         AuditEventType = "export"
	AuditEventAnchor         AuditEventType = "anchor"
	AuditEventError          AuditEventType = "error"
	AuditEventPermission     AuditEventType = "permission"
	AuditEventAuthentication AuditEventType = "authentication"
	AuditEventStartup        AuditEventType = "startup"
	AuditEventShutdown       AuditEventType = "shutdown"
)

// AuditEvent represents a security-relevant event.
type AuditEvent struct {
	Timestamp   time.Time              `json:"timestamp"`
	EventType   AuditEventType         `json:"event_type"`
	Component   string                 `json:"component"`
	SessionID   string                 `json:"session_id,omitempty"`
	UserID      string                 `json:"user_id,omitempty"`
	DeviceID    string                 `json:"device_id,omitempty"`
	Action      string                 `json:"action"`
	Resource    string                 `json:"resource,omitempty"`
	Result      string                 `json:"result"` // "success", "failure", "denied"
	Details     map[string]interface{} `json:"details,omitempty"`
	SourceIP    string                 `json:"source_ip,omitempty"`
	SourceFile  string                 `json:"source_file,omitempty"`
	SourceLine  int                    `json:"source_line,omitempty"`
	Error       string                 `json:"error,omitempty"`
	RequestID   string                 `json:"request_id,omitempty"`
}

// AuditLoggerConfig holds configuration for the audit logger.
type AuditLoggerConfig struct {
	// FilePath is the path to the audit log file.
	FilePath string

	// MaxSize is the maximum size in MB before rotation.
	MaxSize int64

	// MaxAge is the maximum age in days before deletion.
	MaxAge int

	// MaxBackups is the maximum number of rotated files to keep.
	MaxBackups int

	// Compress determines if rotated logs should be compressed.
	Compress bool

	// Component is the component name for audit events.
	Component string

	// DeviceID is the device identifier.
	DeviceID string
}

// DefaultAuditConfig returns default audit logger configuration.
func DefaultAuditConfig() *AuditLoggerConfig {
	return &AuditLoggerConfig{
		FilePath:   defaultAuditLogPath(),
		MaxSize:    50, // 50 MB
		MaxAge:     90, // 90 days
		MaxBackups: 10,
		Compress:   true,
		Component:  "witnessd",
	}
}

// defaultAuditLogPath returns the platform-specific default audit log path.
func defaultAuditLogPath() string {
	switch runtime.GOOS {
	case "darwin":
		homeDir, _ := os.UserHomeDir()
		return filepath.Join(homeDir, "Library", "Logs", "witnessd", "audit.log")
	case "windows":
		appData := os.Getenv("LOCALAPPDATA")
		if appData == "" {
			appData = os.Getenv("APPDATA")
		}
		return filepath.Join(appData, "witnessd", "logs", "audit.log")
	default:
		stateHome := os.Getenv("XDG_STATE_HOME")
		if stateHome == "" {
			homeDir, _ := os.UserHomeDir()
			stateHome = filepath.Join(homeDir, ".local", "state")
		}
		return filepath.Join(stateHome, "witnessd", "audit.log")
	}
}

// AuditLogger handles security audit logging.
type AuditLogger struct {
	config    *AuditLoggerConfig
	rotator   *FileRotator
	logger    *slog.Logger
	mu        sync.Mutex
	sessionID string
}

var (
	defaultAuditLogger *AuditLogger
	auditLoggerOnce    sync.Once
)

// DefaultAuditLogger returns the default global audit logger.
func DefaultAuditLogger() *AuditLogger {
	auditLoggerOnce.Do(func() {
		var err error
		defaultAuditLogger, err = NewAuditLogger(DefaultAuditConfig())
		if err != nil {
			// Create a fallback that writes to stderr
			defaultAuditLogger = &AuditLogger{
				config: DefaultAuditConfig(),
				logger: slog.Default(),
			}
		}
	})
	return defaultAuditLogger
}

// SetDefaultAuditLogger sets the default global audit logger.
func SetDefaultAuditLogger(l *AuditLogger) {
	defaultAuditLogger = l
}

// NewAuditLogger creates a new AuditLogger.
func NewAuditLogger(cfg *AuditLoggerConfig) (*AuditLogger, error) {
	if cfg == nil {
		cfg = DefaultAuditConfig()
	}

	// Create rotator config from audit config
	rotatorCfg := &Config{
		FilePath:   cfg.FilePath,
		MaxSize:    cfg.MaxSize,
		MaxAge:     cfg.MaxAge,
		MaxBackups: cfg.MaxBackups,
		Compress:   cfg.Compress,
		Format:     FormatJSON,
		Level:      LevelInfo,
	}

	rotator, err := NewFileRotator(rotatorCfg)
	if err != nil {
		return nil, fmt.Errorf("create audit rotator: %w", err)
	}

	opts := &slog.HandlerOptions{
		Level: LevelInfo,
	}

	handler := slog.NewJSONHandler(rotator, opts)
	logger := slog.New(handler)

	return &AuditLogger{
		config:  cfg,
		rotator: rotator,
		logger:  logger,
	}, nil
}

// SetSessionID sets the current session ID for audit events.
func (a *AuditLogger) SetSessionID(sessionID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sessionID = sessionID
}

// Log writes an audit event.
func (a *AuditLogger) Log(ctx context.Context, event AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Fill in defaults
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	if event.Component == "" {
		event.Component = a.config.Component
	}
	if event.SessionID == "" {
		event.SessionID = a.sessionID
	}
	if event.DeviceID == "" {
		event.DeviceID = a.config.DeviceID
	}
	if event.RequestID == "" {
		event.RequestID = RequestIDFromContext(ctx)
	}

	// Get source location
	if event.SourceFile == "" {
		_, file, line, ok := runtime.Caller(1)
		if ok {
			event.SourceFile = file
			event.SourceLine = line
		}
	}

	// Convert to JSON and write directly
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal audit event: %w", err)
	}

	data = append(data, '\n')
	if _, err := a.rotator.Write(data); err != nil {
		return fmt.Errorf("write audit event: %w", err)
	}

	return nil
}

// LogSessionStart logs a session start event.
func (a *AuditLogger) LogSessionStart(ctx context.Context, sessionID string, details map[string]interface{}) error {
	a.SetSessionID(sessionID)
	return a.Log(ctx, AuditEvent{
		EventType: AuditEventSessionStart,
		Action:    "session_started",
		Result:    "success",
		SessionID: sessionID,
		Details:   details,
	})
}

// LogSessionEnd logs a session end event.
func (a *AuditLogger) LogSessionEnd(ctx context.Context, details map[string]interface{}) error {
	event := AuditEvent{
		EventType: AuditEventSessionEnd,
		Action:    "session_ended",
		Result:    "success",
		Details:   details,
	}
	err := a.Log(ctx, event)
	a.SetSessionID("")
	return err
}

// LogConfigChange logs a configuration change.
func (a *AuditLogger) LogConfigChange(ctx context.Context, setting, oldValue, newValue string) error {
	return a.Log(ctx, AuditEvent{
		EventType: AuditEventConfigChange,
		Action:    "config_changed",
		Resource:  setting,
		Result:    "success",
		Details: map[string]interface{}{
			"old_value": oldValue,
			"new_value": newValue,
		},
	})
}

// LogKeyGenerated logs a key generation event.
func (a *AuditLogger) LogKeyGenerated(ctx context.Context, keyType, keyID string) error {
	return a.Log(ctx, AuditEvent{
		EventType: AuditEventKeyGenerated,
		Action:    "key_generated",
		Resource:  keyID,
		Result:    "success",
		Details: map[string]interface{}{
			"key_type": keyType,
		},
	})
}

// LogKeyAccess logs a key access event.
func (a *AuditLogger) LogKeyAccess(ctx context.Context, keyID, operation string, success bool) error {
	result := "success"
	if !success {
		result = "failure"
	}
	return a.Log(ctx, AuditEvent{
		EventType: AuditEventKeyAccess,
		Action:    operation,
		Resource:  keyID,
		Result:    result,
	})
}

// LogCheckpoint logs a checkpoint creation event.
func (a *AuditLogger) LogCheckpoint(ctx context.Context, filePath, checkpointID string, details map[string]interface{}) error {
	return a.Log(ctx, AuditEvent{
		EventType: AuditEventCheckpoint,
		Action:    "checkpoint_created",
		Resource:  filePath,
		Result:    "success",
		Details:   details,
	})
}

// LogVerification logs a verification event.
func (a *AuditLogger) LogVerification(ctx context.Context, resource string, success bool, details map[string]interface{}) error {
	result := "success"
	if !success {
		result = "failure"
	}
	return a.Log(ctx, AuditEvent{
		EventType: AuditEventVerification,
		Action:    "verification_performed",
		Resource:  resource,
		Result:    result,
		Details:   details,
	})
}

// LogExport logs an evidence export event.
func (a *AuditLogger) LogExport(ctx context.Context, filePath, outputPath string) error {
	return a.Log(ctx, AuditEvent{
		EventType: AuditEventExport,
		Action:    "evidence_exported",
		Resource:  filePath,
		Result:    "success",
		Details: map[string]interface{}{
			"output_path": outputPath,
		},
	})
}

// LogAnchor logs an anchoring event.
func (a *AuditLogger) LogAnchor(ctx context.Context, anchorType, resource string, success bool, details map[string]interface{}) error {
	result := "success"
	if !success {
		result = "failure"
	}
	return a.Log(ctx, AuditEvent{
		EventType: AuditEventAnchor,
		Action:    "anchor_created",
		Resource:  resource,
		Result:    result,
		Details: map[string]interface{}{
			"anchor_type": anchorType,
		},
	})
}

// LogError logs an error event.
func (a *AuditLogger) LogError(ctx context.Context, operation string, err error, details map[string]interface{}) error {
	if details == nil {
		details = make(map[string]interface{})
	}
	return a.Log(ctx, AuditEvent{
		EventType: AuditEventError,
		Action:    operation,
		Result:    "failure",
		Error:     err.Error(),
		Details:   details,
	})
}

// LogStartup logs a daemon startup event.
func (a *AuditLogger) LogStartup(ctx context.Context, version string, details map[string]interface{}) error {
	if details == nil {
		details = make(map[string]interface{})
	}
	details["version"] = version
	return a.Log(ctx, AuditEvent{
		EventType: AuditEventStartup,
		Action:    "daemon_started",
		Result:    "success",
		Details:   details,
	})
}

// LogShutdown logs a daemon shutdown event.
func (a *AuditLogger) LogShutdown(ctx context.Context, reason string) error {
	return a.Log(ctx, AuditEvent{
		EventType: AuditEventShutdown,
		Action:    "daemon_stopped",
		Result:    "success",
		Details: map[string]interface{}{
			"reason": reason,
		},
	})
}

// Close closes the audit logger.
func (a *AuditLogger) Close() error {
	if a.rotator != nil {
		return a.rotator.Close()
	}
	return nil
}

// Sync flushes any buffered audit events.
func (a *AuditLogger) Sync() error {
	if a.rotator != nil {
		return a.rotator.Sync()
	}
	return nil
}

// Convenience functions for the default audit logger.

// Audit logs an audit event using the default audit logger.
func Audit(ctx context.Context, event AuditEvent) error {
	return DefaultAuditLogger().Log(ctx, event)
}

// AuditSessionStart logs a session start using the default audit logger.
func AuditSessionStart(ctx context.Context, sessionID string, details map[string]interface{}) error {
	return DefaultAuditLogger().LogSessionStart(ctx, sessionID, details)
}

// AuditSessionEnd logs a session end using the default audit logger.
func AuditSessionEnd(ctx context.Context, details map[string]interface{}) error {
	return DefaultAuditLogger().LogSessionEnd(ctx, details)
}

// AuditCheckpoint logs a checkpoint using the default audit logger.
func AuditCheckpoint(ctx context.Context, filePath, checkpointID string, details map[string]interface{}) error {
	return DefaultAuditLogger().LogCheckpoint(ctx, filePath, checkpointID, details)
}

// AuditError logs an error using the default audit logger.
func AuditError(ctx context.Context, operation string, err error, details map[string]interface{}) error {
	return DefaultAuditLogger().LogError(ctx, operation, err, details)
}
