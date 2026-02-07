// Package sentinel commit trigger detection.
//
// Triggers are events that cause keystroke evidence to be committed to the WAL.
// Supported triggers include:
//   - Save key detection (Cmd+S / Ctrl+S)
//   - File modification detection (FSEvents/inotify/ReadDirectoryChangesW)
//   - Heartbeat timer (configurable periodic commits)
//   - WAL size threshold
//   - Application quit detection
//
// Patent Pending: USPTO Application No. 19/460,364
package sentinel

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// CommitTrigger identifies what caused a commit.
type CommitTrigger int

const (
	// TriggerUnknown indicates an unknown trigger.
	TriggerUnknown CommitTrigger = iota

	// TriggerSaveKey indicates Cmd+S or Ctrl+S was detected.
	TriggerSaveKey

	// TriggerFileModified indicates the file was modified on disk.
	TriggerFileModified

	// TriggerHeartbeat indicates a periodic heartbeat timer fired.
	TriggerHeartbeat

	// TriggerWALThreshold indicates the WAL size exceeded the threshold.
	TriggerWALThreshold

	// TriggerAppQuit indicates the application is quitting.
	TriggerAppQuit

	// TriggerManual indicates a manual commit was requested.
	TriggerManual

	// TriggerShutdown indicates the sentinel is shutting down.
	TriggerShutdown

	// TriggerFocusLost indicates the document lost focus.
	TriggerFocusLost
)

// String returns a human-readable name for the trigger type.
func (t CommitTrigger) String() string {
	switch t {
	case TriggerSaveKey:
		return "save_key"
	case TriggerFileModified:
		return "file_modified"
	case TriggerHeartbeat:
		return "heartbeat"
	case TriggerWALThreshold:
		return "wal_threshold"
	case TriggerAppQuit:
		return "app_quit"
	case TriggerManual:
		return "manual"
	case TriggerShutdown:
		return "shutdown"
	case TriggerFocusLost:
		return "focus_lost"
	default:
		return "unknown"
	}
}

// TriggerEvent represents a commit trigger event.
type TriggerEvent struct {
	// Type is the type of trigger.
	Type CommitTrigger

	// FilePath is the file path associated with this trigger (if applicable).
	FilePath string

	// Timestamp is when the trigger occurred.
	Timestamp time.Time

	// Metadata contains additional trigger-specific data.
	Metadata map[string]interface{}
}

// TriggerConfig configures the trigger manager.
type TriggerConfig struct {
	// HeartbeatInterval is how often to trigger heartbeat commits (0 = disabled).
	HeartbeatInterval time.Duration

	// WALSizeThreshold triggers a commit when WAL size exceeds this (0 = disabled).
	WALSizeThreshold int64

	// SaveKeyDetection enables Cmd+S/Ctrl+S detection.
	SaveKeyDetection bool

	// FileWatchEnabled enables FSEvents/inotify file watching.
	FileWatchEnabled bool

	// AppQuitDetection enables application quit detection.
	AppQuitDetection bool

	// FocusLostCommit triggers a commit when a document loses focus.
	FocusLostCommit bool

	// FileDebounce is how long to wait after a file change before triggering.
	FileDebounce time.Duration
}

// DefaultTriggerConfig returns default trigger configuration.
func DefaultTriggerConfig() TriggerConfig {
	return TriggerConfig{
		HeartbeatInterval: 60 * time.Second,
		WALSizeThreshold:  10 * 1024, // 10KB
		SaveKeyDetection:  true,
		FileWatchEnabled:  true,
		AppQuitDetection:  true,
		FocusLostCommit:   false,
		FileDebounce:      500 * time.Millisecond,
	}
}

// TriggerManager manages commit triggers.
type TriggerManager struct {
	config TriggerConfig
	logger *slog.Logger

	// File watcher
	fsWatcher *fsnotify.Watcher

	// Tracked files
	mu           sync.RWMutex
	watchedFiles map[string]time.Time // path -> last trigger time (for debounce)

	// Output channel
	triggers chan TriggerEvent

	// WAL size tracking
	walSize int64

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewTriggerManager creates a new trigger manager.
func NewTriggerManager(config TriggerConfig, logger *slog.Logger) *TriggerManager {
	if logger == nil {
		logger = slog.Default()
	}

	return &TriggerManager{
		config:       config,
		logger:       logger.With("component", "trigger_manager"),
		watchedFiles: make(map[string]time.Time),
		triggers:     make(chan TriggerEvent, 100),
	}
}

// Start begins the trigger manager.
func (m *TriggerManager) Start(ctx context.Context) error {
	m.ctx, m.cancel = context.WithCancel(ctx)

	// Initialize file watcher if enabled
	if m.config.FileWatchEnabled {
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			m.logger.Warn("failed to create file watcher", "error", err)
		} else {
			m.fsWatcher = watcher
			m.wg.Add(1)
			go m.fileWatchLoop()
		}
	}

	// Start heartbeat if enabled
	if m.config.HeartbeatInterval > 0 {
		m.wg.Add(1)
		go m.heartbeatLoop()
	}

	m.logger.Info("trigger manager started",
		"heartbeat_interval", m.config.HeartbeatInterval,
		"file_watch", m.config.FileWatchEnabled,
		"save_key", m.config.SaveKeyDetection,
	)

	return nil
}

// Stop stops the trigger manager.
func (m *TriggerManager) Stop() error {
	if m.cancel != nil {
		m.cancel()
	}

	if m.fsWatcher != nil {
		m.fsWatcher.Close()
	}

	// Wait for goroutines with timeout
	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		m.logger.Warn("trigger manager stop timed out")
	}

	close(m.triggers)
	m.logger.Info("trigger manager stopped")

	return nil
}

// Triggers returns the channel of trigger events.
func (m *TriggerManager) Triggers() <-chan TriggerEvent {
	return m.triggers
}

// WatchFile adds a file to the watch list for modification detection.
func (m *TriggerManager) WatchFile(path string) error {
	if m.fsWatcher == nil {
		return nil
	}

	// Normalize path
	absPath, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if already watching
	if _, exists := m.watchedFiles[absPath]; exists {
		return nil
	}

	// Watch the directory containing the file
	dir := filepath.Dir(absPath)
	if err := m.fsWatcher.Add(dir); err != nil {
		return err
	}

	m.watchedFiles[absPath] = time.Time{}
	m.logger.Debug("watching file", "path", absPath)

	return nil
}

// UnwatchFile removes a file from the watch list.
func (m *TriggerManager) UnwatchFile(path string) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.watchedFiles, absPath)
	m.logger.Debug("unwatching file", "path", absPath)

	return nil
}

// TriggerSave triggers a save event for the given file.
// Call this when Cmd+S or Ctrl+S is detected.
func (m *TriggerManager) TriggerSave(path string) {
	if !m.config.SaveKeyDetection {
		return
	}

	m.emit(TriggerEvent{
		Type:      TriggerSaveKey,
		FilePath:  path,
		Timestamp: time.Now(),
	})
}

// TriggerManual triggers a manual commit.
func (m *TriggerManager) TriggerManual(path string) {
	m.emit(TriggerEvent{
		Type:      TriggerManual,
		FilePath:  path,
		Timestamp: time.Now(),
	})
}

// TriggerFocusLost triggers a commit due to focus loss.
func (m *TriggerManager) TriggerFocusLost(path string) {
	if !m.config.FocusLostCommit {
		return
	}

	m.emit(TriggerEvent{
		Type:      TriggerFocusLost,
		FilePath:  path,
		Timestamp: time.Now(),
	})
}

// TriggerAppQuit triggers a commit due to application quit.
func (m *TriggerManager) TriggerAppQuit(appName string) {
	if !m.config.AppQuitDetection {
		return
	}

	m.emit(TriggerEvent{
		Type:      TriggerAppQuit,
		Timestamp: time.Now(),
		Metadata: map[string]interface{}{
			"app_name": appName,
		},
	})
}

// UpdateWALSize updates the WAL size and triggers if threshold exceeded.
func (m *TriggerManager) UpdateWALSize(size int64) {
	m.walSize = size

	if m.config.WALSizeThreshold > 0 && size >= m.config.WALSizeThreshold {
		m.emit(TriggerEvent{
			Type:      TriggerWALThreshold,
			Timestamp: time.Now(),
			Metadata: map[string]interface{}{
				"wal_size":  size,
				"threshold": m.config.WALSizeThreshold,
			},
		})
	}
}

// emit sends a trigger event to the channel.
func (m *TriggerManager) emit(event TriggerEvent) {
	select {
	case m.triggers <- event:
		m.logger.Debug("trigger emitted",
			"type", event.Type,
			"path", event.FilePath,
		)
	default:
		m.logger.Warn("trigger channel full, dropping event",
			"type", event.Type,
		)
	}
}

// heartbeatLoop periodically triggers heartbeat commits.
func (m *TriggerManager) heartbeatLoop() {
	defer m.wg.Done()

	ticker := time.NewTicker(m.config.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.emit(TriggerEvent{
				Type:      TriggerHeartbeat,
				Timestamp: time.Now(),
			})
		}
	}
}

// fileWatchLoop handles file system events.
func (m *TriggerManager) fileWatchLoop() {
	defer m.wg.Done()

	// Debounce map
	pending := make(map[string]time.Time)
	debounceTimer := time.NewTicker(100 * time.Millisecond)
	defer debounceTimer.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return

		case event, ok := <-m.fsWatcher.Events:
			if !ok {
				return
			}

			// Only handle write/create events
			if event.Op&(fsnotify.Write|fsnotify.Create) == 0 {
				continue
			}

			// Check if we're watching this file
			m.mu.RLock()
			_, watching := m.watchedFiles[event.Name]
			m.mu.RUnlock()

			if watching {
				pending[event.Name] = time.Now()
			}

		case err, ok := <-m.fsWatcher.Errors:
			if !ok {
				return
			}
			m.logger.Error("file watcher error", "error", err)

		case <-debounceTimer.C:
			// Check for events that have passed the debounce period
			now := time.Now()
			for path, eventTime := range pending {
				if now.Sub(eventTime) >= m.config.FileDebounce {
					// Check if file still exists
					if _, err := os.Stat(path); err == nil {
						m.emit(TriggerEvent{
							Type:      TriggerFileModified,
							FilePath:  path,
							Timestamp: eventTime,
						})
					}
					delete(pending, path)
				}
			}
		}
	}
}

// SaveKeyDetector provides platform-specific save key detection.
type SaveKeyDetector interface {
	// Start begins monitoring for save key events.
	Start(ctx context.Context) error

	// Stop stops monitoring.
	Stop() error

	// SaveEvents returns a channel of save key events.
	SaveEvents() <-chan string // channel of file paths
}

// RegisterSaveKeyDetector registers a save key detector with the trigger manager.
func (m *TriggerManager) RegisterSaveKeyDetector(detector SaveKeyDetector) {
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()

		if err := detector.Start(m.ctx); err != nil {
			m.logger.Error("failed to start save key detector", "error", err)
			return
		}
		defer detector.Stop()

		for {
			select {
			case <-m.ctx.Done():
				return
			case path, ok := <-detector.SaveEvents():
				if !ok {
					return
				}
				m.TriggerSave(path)
			}
		}
	}()
}

// AppQuitDetector provides platform-specific application quit detection.
type AppQuitDetector interface {
	// Start begins monitoring for application quit events.
	Start(ctx context.Context) error

	// Stop stops monitoring.
	Stop() error

	// QuitEvents returns a channel of quit events (app bundle ID or name).
	QuitEvents() <-chan string
}

// RegisterAppQuitDetector registers an app quit detector with the trigger manager.
func (m *TriggerManager) RegisterAppQuitDetector(detector AppQuitDetector) {
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()

		if err := detector.Start(m.ctx); err != nil {
			m.logger.Error("failed to start app quit detector", "error", err)
			return
		}
		defer detector.Stop()

		for {
			select {
			case <-m.ctx.Done():
				return
			case appName, ok := <-detector.QuitEvents():
				if !ok {
					return
				}
				m.TriggerAppQuit(appName)
			}
		}
	}()
}
