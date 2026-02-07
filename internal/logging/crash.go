// Package logging provides structured logging with slog for witnessd.
package logging

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sync"
	"time"
)

// CrashReport represents information about a crash.
type CrashReport struct {
	Timestamp   time.Time              `json:"timestamp"`
	Version     string                 `json:"version"`
	BuildInfo   *debug.BuildInfo       `json:"build_info,omitempty"`
	GOOS        string                 `json:"goos"`
	GOARCH      string                 `json:"goarch"`
	NumCPU      int                    `json:"num_cpu"`
	NumGoroutine int                   `json:"num_goroutine"`
	MemStats    *runtime.MemStats      `json:"mem_stats,omitempty"`
	PanicValue  string                 `json:"panic_value"`
	StackTrace  string                 `json:"stack_trace"`
	Component   string                 `json:"component,omitempty"`
	SessionID   string                 `json:"session_id,omitempty"`
	RequestID   string                 `json:"request_id,omitempty"`
	Context     map[string]interface{} `json:"context,omitempty"`
}

// CrashHandler handles panic recovery and crash reporting.
type CrashHandler struct {
	mu            sync.Mutex
	crashDir      string
	version       string
	component     string
	sessionID     string
	telemetryFunc func(CrashReport) // Optional telemetry callback
	onCrash       func(CrashReport) // Called after crash is logged
}

// CrashHandlerConfig configures the crash handler.
type CrashHandlerConfig struct {
	// CrashDir is the directory to write crash dumps.
	CrashDir string

	// Version is the application version.
	Version string

	// Component is the component name.
	Component string

	// TelemetryFunc is an optional function to send crash telemetry.
	// This should only be enabled with user consent.
	TelemetryFunc func(CrashReport)

	// OnCrash is called after a crash is logged.
	OnCrash func(CrashReport)
}

// DefaultCrashDir returns the platform-specific default crash directory.
func DefaultCrashDir() string {
	switch runtime.GOOS {
	case "darwin":
		homeDir, _ := os.UserHomeDir()
		return filepath.Join(homeDir, "Library", "Logs", "DiagnosticReports", "witnessd")
	case "windows":
		appData := os.Getenv("LOCALAPPDATA")
		if appData == "" {
			appData = os.Getenv("APPDATA")
		}
		return filepath.Join(appData, "witnessd", "crashes")
	default:
		stateHome := os.Getenv("XDG_STATE_HOME")
		if stateHome == "" {
			homeDir, _ := os.UserHomeDir()
			stateHome = filepath.Join(homeDir, ".local", "state")
		}
		return filepath.Join(stateHome, "witnessd", "crashes")
	}
}

var (
	globalCrashHandler *CrashHandler
	crashHandlerOnce   sync.Once
)

// DefaultCrashHandler returns the default global crash handler.
func DefaultCrashHandler() *CrashHandler {
	crashHandlerOnce.Do(func() {
		globalCrashHandler = NewCrashHandler(&CrashHandlerConfig{
			CrashDir:  DefaultCrashDir(),
			Component: "witnessd",
		})
	})
	return globalCrashHandler
}

// SetDefaultCrashHandler sets the default global crash handler.
func SetDefaultCrashHandler(h *CrashHandler) {
	globalCrashHandler = h
}

// NewCrashHandler creates a new CrashHandler.
func NewCrashHandler(cfg *CrashHandlerConfig) *CrashHandler {
	if cfg == nil {
		cfg = &CrashHandlerConfig{}
	}
	if cfg.CrashDir == "" {
		cfg.CrashDir = DefaultCrashDir()
	}

	// Ensure crash directory exists
	os.MkdirAll(cfg.CrashDir, 0750)

	return &CrashHandler{
		crashDir:      cfg.CrashDir,
		version:       cfg.Version,
		component:     cfg.Component,
		telemetryFunc: cfg.TelemetryFunc,
		onCrash:       cfg.OnCrash,
	}
}

// SetVersion sets the application version.
func (h *CrashHandler) SetVersion(version string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.version = version
}

// SetSessionID sets the current session ID.
func (h *CrashHandler) SetSessionID(sessionID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sessionID = sessionID
}

// RecoverWithContext wraps a function with panic recovery and context.
func (h *CrashHandler) RecoverWithContext(contextInfo map[string]interface{}, fn func()) {
	defer h.recover(contextInfo)
	fn()
}

// Recover wraps a function with panic recovery.
func (h *CrashHandler) Recover(fn func()) {
	defer h.recover(nil)
	fn()
}

// RecoverGoroutine is designed to be called at the start of goroutines.
// Usage: go func() { defer crashHandler.RecoverGoroutine(); ... }()
func (h *CrashHandler) RecoverGoroutine() {
	h.recover(map[string]interface{}{"type": "goroutine"})
}

// recover handles the actual panic recovery.
func (h *CrashHandler) recover(contextInfo map[string]interface{}) {
	if r := recover(); r != nil {
		h.HandlePanic(r, contextInfo)
	}
}

// HandlePanic processes a panic and creates a crash report.
func (h *CrashHandler) HandlePanic(panicValue interface{}, contextInfo map[string]interface{}) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Create crash report
	report := CrashReport{
		Timestamp:    time.Now().UTC(),
		Version:      h.version,
		GOOS:         runtime.GOOS,
		GOARCH:       runtime.GOARCH,
		NumCPU:       runtime.NumCPU(),
		NumGoroutine: runtime.NumGoroutine(),
		PanicValue:   fmt.Sprintf("%v", panicValue),
		StackTrace:   string(debug.Stack()),
		Component:    h.component,
		SessionID:    h.sessionID,
		Context:      contextInfo,
	}

	// Get build info
	if bi, ok := debug.ReadBuildInfo(); ok {
		report.BuildInfo = bi
	}

	// Get memory stats
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	report.MemStats = &memStats

	// Write crash dump to file
	h.writeCrashDump(report)

	// Send telemetry if enabled and function provided
	if h.telemetryFunc != nil {
		// Run in goroutine to not block
		go func(r CrashReport) {
			defer func() { recover() }() // Don't let telemetry panic
			h.telemetryFunc(r)
		}(report)
	}

	// Call crash callback if set
	if h.onCrash != nil {
		h.onCrash(report)
	}

	// Log to stderr as well
	fmt.Fprintf(os.Stderr, "\n=== CRASH REPORT ===\n")
	fmt.Fprintf(os.Stderr, "Time: %s\n", report.Timestamp.Format(time.RFC3339))
	fmt.Fprintf(os.Stderr, "Panic: %s\n", report.PanicValue)
	fmt.Fprintf(os.Stderr, "Stack trace:\n%s\n", report.StackTrace)
	fmt.Fprintf(os.Stderr, "Crash dump written to: %s\n", h.crashDir)
}

// writeCrashDump writes the crash report to a file.
func (h *CrashHandler) writeCrashDump(report CrashReport) error {
	// Generate filename with timestamp
	filename := fmt.Sprintf("crash-%s-%s.json",
		report.Component,
		report.Timestamp.Format("20060102-150405"))
	filepath := filepath.Join(h.crashDir, filename)

	// Marshal report to JSON
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal crash report: %w", err)
	}

	// Write to file
	if err := os.WriteFile(filepath, data, 0640); err != nil {
		return fmt.Errorf("write crash report: %w", err)
	}

	return nil
}

// GetCrashReports returns a list of crash reports.
func (h *CrashHandler) GetCrashReports() ([]CrashReport, error) {
	files, err := filepath.Glob(filepath.Join(h.crashDir, "crash-*.json"))
	if err != nil {
		return nil, err
	}

	reports := make([]CrashReport, 0, len(files))
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		var report CrashReport
		if err := json.Unmarshal(data, &report); err != nil {
			continue
		}

		reports = append(reports, report)
	}

	return reports, nil
}

// CleanupOldCrashReports removes crash reports older than the specified duration.
func (h *CrashHandler) CleanupOldCrashReports(maxAge time.Duration) error {
	files, err := filepath.Glob(filepath.Join(h.crashDir, "crash-*.json"))
	if err != nil {
		return err
	}

	cutoff := time.Now().Add(-maxAge)
	for _, file := range files {
		info, err := os.Stat(file)
		if err != nil {
			continue
		}

		if info.ModTime().Before(cutoff) {
			os.Remove(file)
		}
	}

	return nil
}

// ClearCrashReports removes all crash reports.
func (h *CrashHandler) ClearCrashReports() error {
	files, err := filepath.Glob(filepath.Join(h.crashDir, "crash-*.json"))
	if err != nil {
		return err
	}

	for _, file := range files {
		os.Remove(file)
	}

	return nil
}

// Convenience functions.

// RecoverPanic is a convenience function for panic recovery.
// Usage: defer logging.RecoverPanic()
func RecoverPanic() {
	if r := recover(); r != nil {
		DefaultCrashHandler().HandlePanic(r, nil)
	}
}

// RecoverPanicWith is a convenience function for panic recovery with context.
// Usage: defer logging.RecoverPanicWith(map[string]interface{}{"op": "foo"})
func RecoverPanicWith(context map[string]interface{}) {
	if r := recover(); r != nil {
		DefaultCrashHandler().HandlePanic(r, context)
	}
}

// WrapPanic wraps a function with panic recovery.
func WrapPanic(fn func()) {
	DefaultCrashHandler().Recover(fn)
}

// WrapPanicWithContext wraps a function with panic recovery and context.
func WrapPanicWithContext(context map[string]interface{}, fn func()) {
	DefaultCrashHandler().RecoverWithContext(context, fn)
}
