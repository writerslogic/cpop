// Package wal implements the heartbeat timer system for periodic checkpoints.
//
// The heartbeat system triggers commits every 60 seconds (configurable)
// to ensure data is regularly committed to the MMR, minimizing data loss
// on crash while balancing system load.
//
// Patent Pending: USPTO Application No. 19/460,364
package wal

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// HeartbeatConfig configures the heartbeat system.
type HeartbeatConfig struct {
	// Interval between heartbeats (default: 60 seconds)
	Interval time.Duration

	// MinInterval is the minimum allowed interval (default: 10 seconds)
	MinInterval time.Duration

	// MaxInterval is the maximum allowed interval (default: 5 minutes)
	MaxInterval time.Duration

	// WALSoftLimit triggers commit when WAL exceeds this size (default: 10 MB)
	WALSoftLimit int64

	// WALHardLimit forces commit when WAL exceeds this size (default: 50 MB)
	WALHardLimit int64

	// OnCommit is called when a heartbeat triggers a commit
	OnCommit func(trigger string) error

	// OnError is called when a commit fails
	OnError func(err error)

	// Logger for heartbeat events
	Logger HeartbeatLogger
}

// DefaultHeartbeatConfig returns sensible defaults.
func DefaultHeartbeatConfig() HeartbeatConfig {
	return HeartbeatConfig{
		Interval:     60 * time.Second,
		MinInterval:  10 * time.Second,
		MaxInterval:  5 * time.Minute,
		WALSoftLimit: 10 * 1024 * 1024, // 10 MB
		WALHardLimit: 50 * 1024 * 1024, // 50 MB
		Logger:       &defaultHeartbeatLogger{},
	}
}

// HeartbeatLogger logs heartbeat events.
type HeartbeatLogger interface {
	Info(msg string, fields ...interface{})
	Warn(msg string, fields ...interface{})
	Error(msg string, fields ...interface{})
}

// defaultHeartbeatLogger is a no-op logger.
type defaultHeartbeatLogger struct{}

func (l *defaultHeartbeatLogger) Info(msg string, fields ...interface{})  {}
func (l *defaultHeartbeatLogger) Warn(msg string, fields ...interface{})  {}
func (l *defaultHeartbeatLogger) Error(msg string, fields ...interface{}) {}

// HeartbeatStats tracks heartbeat statistics.
type HeartbeatStats struct {
	// TotalHeartbeats is the total number of heartbeats fired
	TotalHeartbeats uint64

	// SuccessfulCommits is the number of successful commits
	SuccessfulCommits uint64

	// FailedCommits is the number of failed commits
	FailedCommits uint64

	// LastHeartbeat is the time of the last heartbeat
	LastHeartbeat time.Time

	// LastCommit is the time of the last successful commit
	LastCommit time.Time

	// LastError is the most recent error, if any
	LastError error

	// WALSizeCommits is the number of commits triggered by WAL size
	WALSizeCommits uint64

	// SemanticCommits is the number of commits triggered by semantic events
	SemanticCommits uint64
}

// Heartbeat manages periodic checkpoint commits.
type Heartbeat struct {
	mu     sync.RWMutex
	config HeartbeatConfig
	wal    *WAL

	// State
	running  atomic.Bool
	paused   atomic.Bool
	ticker   *time.Ticker
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup

	// Statistics
	stats HeartbeatStats

	// Counters since last commit
	keystrokesSinceCommit atomic.Uint64
	samplesSinceCommit    atomic.Uint64

	// Last commit debouncing
	lastCommitTime time.Time
	commitDebounce time.Duration
}

// NewHeartbeat creates a new heartbeat manager.
func NewHeartbeat(wal *WAL, config HeartbeatConfig) *Heartbeat {
	// Validate and clamp interval
	if config.Interval < config.MinInterval {
		config.Interval = config.MinInterval
	}
	if config.Interval > config.MaxInterval {
		config.Interval = config.MaxInterval
	}

	return &Heartbeat{
		config:         config,
		wal:            wal,
		commitDebounce: 500 * time.Millisecond,
	}
}

// Start begins the heartbeat timer.
func (h *Heartbeat) Start(ctx context.Context) error {
	if h.running.Load() {
		return nil
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	h.ctx, h.cancel = context.WithCancel(ctx)
	h.ticker = time.NewTicker(h.config.Interval)
	h.running.Store(true)

	h.wg.Add(1)
	go h.run()

	h.config.Logger.Info("Heartbeat started",
		"interval", h.config.Interval)

	return nil
}

// Stop stops the heartbeat timer.
func (h *Heartbeat) Stop() error {
	if !h.running.Load() {
		return nil
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	h.running.Store(false)
	if h.cancel != nil {
		h.cancel()
	}
	if h.ticker != nil {
		h.ticker.Stop()
	}

	h.wg.Wait()

	h.config.Logger.Info("Heartbeat stopped")

	return nil
}

// Pause temporarily pauses the heartbeat without stopping it.
// Useful when the document loses focus.
func (h *Heartbeat) Pause() {
	h.paused.Store(true)
	h.config.Logger.Info("Heartbeat paused")
}

// Resume resumes a paused heartbeat.
func (h *Heartbeat) Resume() {
	h.paused.Store(false)
	h.config.Logger.Info("Heartbeat resumed")
}

// IsPaused returns true if the heartbeat is paused.
func (h *Heartbeat) IsPaused() bool {
	return h.paused.Load()
}

// IsRunning returns true if the heartbeat is running.
func (h *Heartbeat) IsRunning() bool {
	return h.running.Load()
}

// SetInterval dynamically updates the heartbeat interval.
func (h *Heartbeat) SetInterval(interval time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Clamp to valid range
	if interval < h.config.MinInterval {
		interval = h.config.MinInterval
	}
	if interval > h.config.MaxInterval {
		interval = h.config.MaxInterval
	}

	h.config.Interval = interval
	if h.ticker != nil {
		h.ticker.Reset(interval)
	}

	h.config.Logger.Info("Heartbeat interval updated",
		"interval", interval)
}

// TriggerCommit triggers an immediate commit with the given trigger reason.
// This is used for semantic milestones like Cmd+S, file close, etc.
func (h *Heartbeat) TriggerCommit(trigger string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Debounce rapid triggers
	if time.Since(h.lastCommitTime) < h.commitDebounce {
		h.config.Logger.Info("Commit debounced",
			"trigger", trigger,
			"since_last", time.Since(h.lastCommitTime))
		return nil
	}

	return h.doCommit(trigger)
}

// RecordKeystrokes records keystrokes since last commit.
func (h *Heartbeat) RecordKeystrokes(count uint64) {
	h.keystrokesSinceCommit.Add(count)
}

// RecordSamples records jitter samples since last commit.
func (h *Heartbeat) RecordSamples(count uint64) {
	h.samplesSinceCommit.Add(count)
}

// Stats returns current heartbeat statistics.
func (h *Heartbeat) Stats() HeartbeatStats {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.stats
}

// run is the main heartbeat loop.
func (h *Heartbeat) run() {
	defer h.wg.Done()

	for {
		select {
		case <-h.ctx.Done():
			return

		case <-h.ticker.C:
			if h.paused.Load() {
				continue
			}

			h.mu.Lock()
			h.stats.TotalHeartbeats++
			h.stats.LastHeartbeat = time.Now()

			// Check WAL size first
			trigger := h.checkWALSize()
			if trigger == "" {
				trigger = "heartbeat"
			}

			// Record heartbeat to WAL
			h.recordHeartbeat()

			// Trigger commit
			if err := h.doCommit(trigger); err != nil {
				h.stats.FailedCommits++
				h.stats.LastError = err
				if h.config.OnError != nil {
					h.config.OnError(err)
				}
			} else {
				h.stats.SuccessfulCommits++
				h.stats.LastCommit = time.Now()
			}
			h.mu.Unlock()
		}
	}
}

// checkWALSize checks if WAL size triggers a commit.
// Must be called with lock held.
func (h *Heartbeat) checkWALSize() string {
	if h.wal == nil {
		return ""
	}

	size := h.wal.Size()

	if size > h.config.WALHardLimit {
		h.config.Logger.Warn("WAL exceeded hard limit, forcing checkpoint",
			"size", size,
			"limit", h.config.WALHardLimit)
		h.stats.WALSizeCommits++
		return "wal-overflow"
	}

	if size > h.config.WALSoftLimit {
		h.stats.WALSizeCommits++
		return "wal-threshold"
	}

	return ""
}

// recordHeartbeat writes a heartbeat entry to the WAL.
// Must be called with lock held.
func (h *Heartbeat) recordHeartbeat() {
	if h.wal == nil {
		return
	}

	payload := &HeartbeatPayload{
		Timestamp:       time.Now().UnixNano(),
		KeystrokesSince: h.keystrokesSinceCommit.Load(),
		SamplesSince:    h.samplesSinceCommit.Load(),
	}

	if err := h.wal.Append(EntryHeartbeat, payload.Serialize()); err != nil {
		h.config.Logger.Error("Failed to record heartbeat to WAL",
			"error", err)
	}
}

// doCommit performs the actual commit.
// Must be called with lock held.
func (h *Heartbeat) doCommit(trigger string) error {
	if h.config.OnCommit == nil {
		return nil
	}

	h.config.Logger.Info("Triggering commit",
		"trigger", trigger,
		"keystrokes_since", h.keystrokesSinceCommit.Load(),
		"samples_since", h.samplesSinceCommit.Load())

	err := h.config.OnCommit(trigger)
	if err == nil {
		// Reset counters on successful commit
		h.keystrokesSinceCommit.Store(0)
		h.samplesSinceCommit.Store(0)
		h.lastCommitTime = time.Now()
	}

	return err
}

// CommitTrigger represents different types of commit triggers.
type CommitTrigger string

const (
	// TriggerHeartbeat is a periodic heartbeat commit
	TriggerHeartbeat CommitTrigger = "heartbeat"

	// TriggerUserSave is a user-initiated save (Cmd+S)
	TriggerUserSave CommitTrigger = "user-save"

	// TriggerFileClose is triggered when the tracked file is closed
	TriggerFileClose CommitTrigger = "file-close"

	// TriggerAppSwitch is triggered when the user switches apps
	TriggerAppSwitch CommitTrigger = "app-switch"

	// TriggerSessionEnd is triggered when the session ends
	TriggerSessionEnd CommitTrigger = "session-end"

	// TriggerWALThreshold is triggered when WAL exceeds soft limit
	TriggerWALThreshold CommitTrigger = "wal-threshold"

	// TriggerWALOverflow is triggered when WAL exceeds hard limit
	TriggerWALOverflow CommitTrigger = "wal-overflow"

	// TriggerCrashRecovery is triggered during crash recovery
	TriggerCrashRecovery CommitTrigger = "crash-recovery"
)

// SemanticMilestoneHandler handles semantic milestone events
// that trigger immediate commits.
type SemanticMilestoneHandler struct {
	heartbeat *Heartbeat
	mu        sync.Mutex

	// Debounce tracking
	lastSaveTime  time.Time
	lastCloseTime time.Time
	saveDebounce  time.Duration
}

// NewSemanticMilestoneHandler creates a handler for semantic events.
func NewSemanticMilestoneHandler(heartbeat *Heartbeat) *SemanticMilestoneHandler {
	return &SemanticMilestoneHandler{
		heartbeat:    heartbeat,
		saveDebounce: 500 * time.Millisecond,
	}
}

// OnSaveDetected handles Cmd+S detection.
func (s *SemanticMilestoneHandler) OnSaveDetected(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Debounce rapid saves
	if time.Since(s.lastSaveTime) < s.saveDebounce {
		return nil
	}

	s.lastSaveTime = time.Now()
	return s.heartbeat.TriggerCommit(string(TriggerUserSave))
}

// OnFileClose handles file close detection.
func (s *SemanticMilestoneHandler) OnFileClose(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Debounce
	if time.Since(s.lastCloseTime) < s.saveDebounce {
		return nil
	}

	s.lastCloseTime = time.Now()
	return s.heartbeat.TriggerCommit(string(TriggerFileClose))
}

// OnAppSwitch handles application switch detection.
func (s *SemanticMilestoneHandler) OnAppSwitch(fromPath string) error {
	return s.heartbeat.TriggerCommit(string(TriggerAppSwitch))
}

// OnSessionEnd handles session termination.
func (s *SemanticMilestoneHandler) OnSessionEnd() error {
	return s.heartbeat.TriggerCommit(string(TriggerSessionEnd))
}
