// Package logging provides structured logging with slog for witnessd.
//
// Features:
//   - JSON and text output formats
//   - Log levels (debug, info, warn, error)
//   - Contextual logging with request IDs
//   - Sensitive data redaction
//   - Log rotation support
//   - Platform-specific default paths
package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Level represents a logging level.
type Level = slog.Level

// Log levels.
const (
	LevelDebug = slog.LevelDebug
	LevelInfo  = slog.LevelInfo
	LevelWarn  = slog.LevelWarn
	LevelError = slog.LevelError
)

// Format represents the output format for logs.
type Format int

const (
	// FormatText outputs human-readable text logs.
	FormatText Format = iota
	// FormatJSON outputs JSON-structured logs.
	FormatJSON
)

// Config holds the logging configuration.
type Config struct {
	// Level is the minimum log level to output.
	Level Level

	// Format is the output format (text or JSON).
	Format Format

	// Output specifies where logs are written.
	// Can be "stdout", "stderr", "file", or "both".
	Output string

	// FilePath is the path to the log file when Output includes "file".
	FilePath string

	// MaxSize is the maximum size of a log file in megabytes before rotation.
	MaxSize int64

	// MaxAge is the maximum age of log files in days before deletion.
	MaxAge int

	// MaxBackups is the maximum number of rotated log files to keep.
	MaxBackups int

	// Compress determines if rotated logs should be gzip compressed.
	Compress bool

	// AddSource adds source file and line to log entries.
	AddSource bool

	// RedactPatterns are regex patterns for sensitive data to redact.
	RedactPatterns []string

	// Component is the name of the component using this logger.
	Component string
}

// DefaultConfig returns a default logging configuration.
func DefaultConfig() *Config {
	return &Config{
		Level:      LevelInfo,
		Format:     FormatText,
		Output:     "stderr",
		FilePath:   defaultLogPath(),
		MaxSize:    100, // 100 MB
		MaxAge:     30,  // 30 days
		MaxBackups: 5,
		Compress:   true,
		AddSource:  false,
		Component:  "witnessd",
	}
}

// defaultLogPath returns the platform-specific default log path.
func defaultLogPath() string {
	switch runtime.GOOS {
	case "darwin":
		homeDir, _ := os.UserHomeDir()
		return filepath.Join(homeDir, "Library", "Logs", "witnessd", "witnessd.log")
	case "windows":
		appData := os.Getenv("LOCALAPPDATA")
		if appData == "" {
			appData = os.Getenv("APPDATA")
		}
		return filepath.Join(appData, "witnessd", "logs", "witnessd.log")
	default: // Linux and other Unix
		// Check XDG_STATE_HOME first (for logs)
		stateHome := os.Getenv("XDG_STATE_HOME")
		if stateHome == "" {
			homeDir, _ := os.UserHomeDir()
			stateHome = filepath.Join(homeDir, ".local", "state")
		}
		return filepath.Join(stateHome, "witnessd", "witnessd.log")
	}
}

// Logger wraps slog.Logger with additional functionality.
type Logger struct {
	*slog.Logger
	config    *Config
	writers   []io.Writer
	rotator   *FileRotator
	mu        sync.RWMutex
	requestID atomic.Uint64
}

// global default logger
var (
	defaultLogger *Logger
	loggerOnce    sync.Once
)

// Default returns the default global logger.
func Default() *Logger {
	loggerOnce.Do(func() {
		var err error
		defaultLogger, err = New(DefaultConfig())
		if err != nil {
			// Fallback to stderr
			defaultLogger = &Logger{
				Logger: slog.Default(),
				config: DefaultConfig(),
			}
		}
	})
	return defaultLogger
}

// SetDefault sets the default global logger.
func SetDefault(l *Logger) {
	defaultLogger = l
	slog.SetDefault(l.Logger)
}

// New creates a new Logger with the given configuration.
func New(cfg *Config) (*Logger, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	l := &Logger{
		config:  cfg,
		writers: make([]io.Writer, 0),
	}

	// Set up output writers
	if err := l.setupWriters(); err != nil {
		return nil, fmt.Errorf("setup writers: %w", err)
	}

	// Create multi-writer
	var w io.Writer
	if len(l.writers) == 1 {
		w = l.writers[0]
	} else {
		w = io.MultiWriter(l.writers...)
	}

	// Create handler options
	opts := &slog.HandlerOptions{
		Level:     cfg.Level,
		AddSource: cfg.AddSource,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			// Redact sensitive data
			if shouldRedact(a.Key) {
				a.Value = slog.StringValue("[REDACTED]")
			}
			return a
		},
	}

	// Create handler based on format
	var handler slog.Handler
	switch cfg.Format {
	case FormatJSON:
		handler = slog.NewJSONHandler(w, opts)
	default:
		handler = slog.NewTextHandler(w, opts)
	}

	// Add component attribute if set
	if cfg.Component != "" {
		handler = handler.WithAttrs([]slog.Attr{
			slog.String("component", cfg.Component),
		})
	}

	l.Logger = slog.New(handler)
	return l, nil
}

// setupWriters configures the output writers based on config.
func (l *Logger) setupWriters() error {
	switch strings.ToLower(l.config.Output) {
	case "stdout":
		l.writers = append(l.writers, os.Stdout)
	case "stderr":
		l.writers = append(l.writers, os.Stderr)
	case "file":
		rotator, err := NewFileRotator(l.config)
		if err != nil {
			return err
		}
		l.rotator = rotator
		l.writers = append(l.writers, rotator)
	case "both":
		l.writers = append(l.writers, os.Stderr)
		rotator, err := NewFileRotator(l.config)
		if err != nil {
			return err
		}
		l.rotator = rotator
		l.writers = append(l.writers, rotator)
	default:
		l.writers = append(l.writers, os.Stderr)
	}
	return nil
}

// shouldRedact checks if an attribute key contains sensitive data.
func shouldRedact(key string) bool {
	sensitiveKeys := []string{
		"password", "secret", "token", "key", "credential",
		"private", "auth", "session", "cookie", "api_key",
		"apikey", "access_token", "refresh_token", "bearer",
	}

	keyLower := strings.ToLower(key)
	for _, sensitive := range sensitiveKeys {
		if strings.Contains(keyLower, sensitive) {
			return true
		}
	}
	return false
}

// WithRequestID returns a new logger with a request ID.
func (l *Logger) WithRequestID(id string) *Logger {
	return &Logger{
		Logger:  l.Logger.With(slog.String("request_id", id)),
		config:  l.config,
		writers: l.writers,
		rotator: l.rotator,
	}
}

// NewRequestID generates a new unique request ID.
func (l *Logger) NewRequestID() string {
	id := l.requestID.Add(1)
	return fmt.Sprintf("%s-%d-%d", l.config.Component, time.Now().UnixNano(), id)
}

// WithComponent returns a new logger with a different component name.
func (l *Logger) WithComponent(name string) *Logger {
	return &Logger{
		Logger:  l.Logger.With(slog.String("component", name)),
		config:  l.config,
		writers: l.writers,
		rotator: l.rotator,
	}
}

// WithContext returns a logger with context-derived attributes.
func (l *Logger) WithContext(ctx context.Context) *Logger {
	// Extract request ID from context if present
	if reqID := RequestIDFromContext(ctx); reqID != "" {
		return l.WithRequestID(reqID)
	}
	return l
}

// Close closes any open log files.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.rotator != nil {
		return l.rotator.Close()
	}
	return nil
}

// Sync flushes any buffered log entries.
func (l *Logger) Sync() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.rotator != nil {
		return l.rotator.Sync()
	}
	return nil
}

// Context key types for request ID.
type contextKey int

const (
	requestIDKey contextKey = iota
)

// ContextWithRequestID returns a new context with the request ID.
func ContextWithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDKey, requestID)
}

// RequestIDFromContext extracts the request ID from context.
func RequestIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if id, ok := ctx.Value(requestIDKey).(string); ok {
		return id
	}
	return ""
}

// Convenience functions for the default logger.

// Debug logs at debug level using the default logger.
func Debug(msg string, args ...any) {
	Default().Debug(msg, args...)
}

// Info logs at info level using the default logger.
func Info(msg string, args ...any) {
	Default().Info(msg, args...)
}

// Warn logs at warn level using the default logger.
func Warn(msg string, args ...any) {
	Default().Warn(msg, args...)
}

// Error logs at error level using the default logger.
func Error(msg string, args ...any) {
	Default().Error(msg, args...)
}

// DebugContext logs at debug level with context.
func DebugContext(ctx context.Context, msg string, args ...any) {
	Default().WithContext(ctx).DebugContext(ctx, msg, args...)
}

// InfoContext logs at info level with context.
func InfoContext(ctx context.Context, msg string, args ...any) {
	Default().WithContext(ctx).InfoContext(ctx, msg, args...)
}

// WarnContext logs at warn level with context.
func WarnContext(ctx context.Context, msg string, args ...any) {
	Default().WithContext(ctx).WarnContext(ctx, msg, args...)
}

// ErrorContext logs at error level with context.
func ErrorContext(ctx context.Context, msg string, args ...any) {
	Default().WithContext(ctx).ErrorContext(ctx, msg, args...)
}

// ParseLevel parses a string into a log level.
func ParseLevel(s string) (Level, error) {
	switch strings.ToLower(s) {
	case "debug":
		return LevelDebug, nil
	case "info":
		return LevelInfo, nil
	case "warn", "warning":
		return LevelWarn, nil
	case "error":
		return LevelError, nil
	default:
		return LevelInfo, fmt.Errorf("unknown log level: %s", s)
	}
}

// LevelString returns the string representation of a log level.
func LevelString(level Level) string {
	switch level {
	case LevelDebug:
		return "debug"
	case LevelInfo:
		return "info"
	case LevelWarn:
		return "warn"
	case LevelError:
		return "error"
	default:
		return "info"
	}
}
