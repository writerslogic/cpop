// Package wal provides WAL integration for tracking sessions.
//
// This file demonstrates how tracking sessions integrate with the WAL
// for crash recovery. The WAL provides durable storage for keystroke
// data, jitter samples, and document hashes between checkpoint commits.
//
// Integration Architecture:
//
//	┌─────────────────────────────────────────────────────────────────────────┐
//	│                         Tracking Session                                 │
//	│                                                                         │
//	│  ┌───────────────┐     ┌───────────────┐     ┌───────────────┐         │
//	│  │  Keystroke    │────▶│   RAM Buffer  │────▶│     WAL       │         │
//	│  │   Counter     │     │  (100ms flush)│     │  (durability) │         │
//	│  └───────────────┘     └───────────────┘     └───────────────┘         │
//	│                                                      │                  │
//	│  ┌───────────────┐     ┌───────────────┐            │                  │
//	│  │    Jitter     │────▶│  Sample Queue │────────────┤                  │
//	│  │   Sampler     │     └───────────────┘            │                  │
//	│  └───────────────┘                                  │                  │
//	│                                                      │                  │
//	│  ┌───────────────┐     ┌───────────────┐            ▼                  │
//	│  │   Document    │────▶│  Hash Cache   │────▶┌─────────────┐           │
//	│  │   Monitor     │     └───────────────┘     │  Heartbeat  │           │
//	│  └───────────────┘                           │   Timer     │           │
//	│                                              └──────┬──────┘           │
//	│                                                      │                  │
//	│                                                      ▼                  │
//	│                                              ┌─────────────┐           │
//	│                                              │ Checkpoint  │           │
//	│                                              │  (MMR/VDF)  │           │
//	│                                              └─────────────┘           │
//	└─────────────────────────────────────────────────────────────────────────┘
//
// Patent Pending: USPTO Application No. 19/460,364
package wal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sync"
	"time"
)

// TrackerWAL integrates WAL functionality with a tracking session.
type TrackerWAL struct {
	mu sync.RWMutex

	// WAL for this tracking session
	wal *WAL

	// Heartbeat manager
	heartbeat *Heartbeat

	// Semantic event handler
	milestoneHandler *SemanticMilestoneHandler

	// Session state
	sessionID    [32]byte
	documentPath string
	started      bool
	ctx          context.Context
	cancel       context.CancelFunc

	// Callbacks for integration
	onCheckpoint  func(trigger string) error
	onRecovery    func(data *RecoveredData) error
	onSessionEnd  func() error

	// Statistics
	keystrokesSinceFlush uint64
	samplesSinceFlush    uint64
	lastDocumentHash     [32]byte
	lastFlushTime        time.Time
}

// TrackerWALConfig configures the tracker WAL integration.
type TrackerWALConfig struct {
	// WAL directory (default: ~/.witnessd/wal/)
	WALDir string

	// Document path being tracked
	DocumentPath string

	// HMAC key for entry integrity
	HMACKey []byte

	// Session ID (generated if empty)
	SessionID [32]byte

	// Heartbeat configuration
	HeartbeatInterval time.Duration

	// Callbacks
	OnCheckpoint func(trigger string) error
	OnRecovery   func(data *RecoveredData) error
	OnSessionEnd func() error
}

// NewTrackerWAL creates a new WAL integration for a tracking session.
func NewTrackerWAL(config TrackerWALConfig) (*TrackerWAL, error) {
	// Generate session ID if not provided
	sessionID := config.SessionID
	if sessionID == [32]byte{} {
		sessionID = sha256.Sum256([]byte(fmt.Sprintf("%s-%d", config.DocumentPath, time.Now().UnixNano())))
	}

	// Generate WAL path from document path
	walPath := walPathForDocument(config.WALDir, config.DocumentPath)

	// Open or create WAL
	wal, err := Open(walPath, sessionID, config.HMACKey)
	if err != nil {
		return nil, fmt.Errorf("open WAL: %w", err)
	}

	// Configure heartbeat
	hbConfig := DefaultHeartbeatConfig()
	if config.HeartbeatInterval > 0 {
		hbConfig.Interval = config.HeartbeatInterval
	}

	tw := &TrackerWAL{
		wal:           wal,
		sessionID:     sessionID,
		documentPath:  config.DocumentPath,
		onCheckpoint:  config.OnCheckpoint,
		onRecovery:    config.OnRecovery,
		onSessionEnd:  config.OnSessionEnd,
		lastFlushTime: time.Now(),
	}

	// Set heartbeat commit callback
	hbConfig.OnCommit = tw.handleCommit

	tw.heartbeat = NewHeartbeat(wal, hbConfig)
	tw.milestoneHandler = NewSemanticMilestoneHandler(tw.heartbeat)

	return tw, nil
}

// walPathForDocument generates a WAL path from a document path.
func walPathForDocument(walDir, docPath string) string {
	// Hash the document path for consistent, filesystem-safe naming
	h := sha256.Sum256([]byte(docPath))
	return filepath.Join(walDir, hex.EncodeToString(h[:8])+".wal")
}

// Start begins the tracking session with WAL integration.
func (tw *TrackerWAL) Start(ctx context.Context) error {
	tw.mu.Lock()
	defer tw.mu.Unlock()

	if tw.started {
		return fmt.Errorf("tracker WAL already started")
	}

	tw.ctx, tw.cancel = context.WithCancel(ctx)

	// Check for crash recovery
	if err := tw.attemptRecovery(); err != nil {
		// Log but continue - recovery is best-effort
		// In production, you'd use a proper logger
		_ = err
	}

	// Write session start entry
	sessionStart := &SessionStartPayload{
		SessionID:    tw.sessionID,
		DocumentPath: tw.documentPath,
		StartTime:    time.Now().UnixNano(),
	}
	if err := tw.wal.Append(EntrySessionStart, sessionStart.Serialize()); err != nil {
		return fmt.Errorf("write session start: %w", err)
	}

	// Start heartbeat
	if err := tw.heartbeat.Start(tw.ctx); err != nil {
		return fmt.Errorf("start heartbeat: %w", err)
	}

	tw.started = true
	return nil
}

// Stop ends the tracking session with clean shutdown.
func (tw *TrackerWAL) Stop() error {
	tw.mu.Lock()
	defer tw.mu.Unlock()

	if !tw.started {
		return nil
	}

	// Stop heartbeat
	tw.heartbeat.Stop()

	// Final flush of any pending data
	if err := tw.flushPendingData(); err != nil {
		// Log but continue
		_ = err
	}

	// Trigger final checkpoint
	if tw.onSessionEnd != nil {
		if err := tw.onSessionEnd(); err != nil {
			// Log but continue
			_ = err
		}
	}

	// Write session end entry
	sessionEnd := &SessionEndPayload{
		SessionID:       tw.sessionID,
		EndTime:         time.Now().UnixNano(),
		TotalKeystrokes: tw.keystrokesSinceFlush,
		TotalSamples:    tw.samplesSinceFlush,
		Clean:           true,
	}
	if err := tw.wal.Append(EntrySessionEnd, sessionEnd.Serialize()); err != nil {
		return fmt.Errorf("write session end: %w", err)
	}

	// Cancel context
	if tw.cancel != nil {
		tw.cancel()
	}

	// Close WAL
	if err := tw.wal.Close(); err != nil {
		return fmt.Errorf("close WAL: %w", err)
	}

	tw.started = false
	return nil
}

// attemptRecovery checks for and processes any recoverable data.
func (tw *TrackerWAL) attemptRecovery() error {
	// Check if WAL has existing data
	entries, err := tw.wal.ReadAll()
	if err != nil || len(entries) == 0 {
		return nil // Nothing to recover
	}

	// Check if last entry indicates clean shutdown
	lastEntry := entries[len(entries)-1]
	if lastEntry.Type == EntrySessionEnd {
		// Clean shutdown - truncate WAL for fresh start
		return tw.wal.Truncate(lastEntry.Sequence + 1)
	}

	// Unclean shutdown - perform recovery
	config := DefaultRecoveryConfig(tw.wal.hmacKey)
	config.MaxTamperedEntries = 5 // Allow some tampering in recovery

	// Use existing WAL data for recovery
	recovery := &Recovery{
		config: config,
		wal:    tw.wal,
	}

	data, err := recovery.RecoverFromCrash()
	if err != nil {
		return fmt.Errorf("recovery failed: %w", err)
	}

	// Notify callback if significant data was recovered
	if data.IsSignificant() && tw.onRecovery != nil {
		if err := tw.onRecovery(data); err != nil {
			return fmt.Errorf("recovery callback failed: %w", err)
		}
	}

	// Truncate processed entries
	if data.LastCheckpointSeq > 0 {
		return tw.wal.Truncate(data.LastCheckpointSeq)
	}

	return nil
}

// RecordKeystrokeBatch records a batch of keystrokes to the WAL.
func (tw *TrackerWAL) RecordKeystrokeBatch(batch *KeystrokeBatchPayload) error {
	tw.mu.Lock()
	defer tw.mu.Unlock()

	if !tw.started {
		return fmt.Errorf("tracker WAL not started")
	}

	if err := tw.wal.Append(EntryKeystrokeBatch, batch.Serialize()); err != nil {
		return err
	}

	tw.keystrokesSinceFlush += uint64(batch.Count)
	tw.heartbeat.RecordKeystrokes(uint64(batch.Count))
	tw.lastDocumentHash = batch.DocumentHash

	return nil
}

// RecordDocumentHash records a document hash snapshot to the WAL.
func (tw *TrackerWAL) RecordDocumentHash(hash *DocumentHashPayload) error {
	tw.mu.Lock()
	defer tw.mu.Unlock()

	if !tw.started {
		return fmt.Errorf("tracker WAL not started")
	}

	if err := tw.wal.Append(EntryDocumentHash, hash.Serialize()); err != nil {
		return err
	}

	tw.lastDocumentHash = hash.Hash
	return nil
}

// RecordJitterSample records a jitter sample to the WAL.
func (tw *TrackerWAL) RecordJitterSample(sample *JitterSamplePayload) error {
	tw.mu.Lock()
	defer tw.mu.Unlock()

	if !tw.started {
		return fmt.Errorf("tracker WAL not started")
	}

	if err := tw.wal.Append(EntryJitterSample, sample.Serialize()); err != nil {
		return err
	}

	tw.samplesSinceFlush++
	tw.heartbeat.RecordSamples(1)

	return nil
}

// OnSaveDetected handles Cmd+S detection for immediate commit.
func (tw *TrackerWAL) OnSaveDetected(path string) error {
	return tw.milestoneHandler.OnSaveDetected(path)
}

// OnFileClose handles file close for immediate commit.
func (tw *TrackerWAL) OnFileClose(path string) error {
	return tw.milestoneHandler.OnFileClose(path)
}

// OnAppSwitch handles app switch for commit.
func (tw *TrackerWAL) OnAppSwitch(fromPath string) error {
	return tw.milestoneHandler.OnAppSwitch(fromPath)
}

// Pause pauses the heartbeat (when document loses focus).
func (tw *TrackerWAL) Pause() {
	tw.heartbeat.Pause()
}

// Resume resumes the heartbeat (when document gains focus).
func (tw *TrackerWAL) Resume() {
	tw.heartbeat.Resume()
}

// handleCommit is called by the heartbeat when a commit is triggered.
func (tw *TrackerWAL) handleCommit(trigger string) error {
	tw.mu.Lock()
	defer tw.mu.Unlock()

	// Flush any pending data first
	if err := tw.flushPendingData(); err != nil {
		return err
	}

	// Call the checkpoint callback
	if tw.onCheckpoint != nil {
		return tw.onCheckpoint(trigger)
	}

	return nil
}

// flushPendingData ensures all in-memory data is written to WAL.
func (tw *TrackerWAL) flushPendingData() error {
	// Record heartbeat marker with current stats
	heartbeat := &HeartbeatPayload{
		Timestamp:       time.Now().UnixNano(),
		KeystrokesSince: tw.keystrokesSinceFlush,
		SamplesSince:    tw.samplesSinceFlush,
	}

	if err := tw.wal.Append(EntryHeartbeat, heartbeat.Serialize()); err != nil {
		return err
	}

	tw.lastFlushTime = time.Now()
	return nil
}

// Stats returns current tracker WAL statistics.
func (tw *TrackerWAL) Stats() TrackerWALStats {
	tw.mu.RLock()
	defer tw.mu.RUnlock()

	hbStats := tw.heartbeat.Stats()

	return TrackerWALStats{
		SessionID:         tw.sessionID,
		DocumentPath:      tw.documentPath,
		Running:           tw.started,
		WALPath:           tw.wal.Path(),
		WALSize:           tw.wal.Size(),
		WALEntryCount:     tw.wal.EntryCount(),
		KeystrokesSinceCommit: tw.keystrokesSinceFlush,
		SamplesSinceCommit:    tw.samplesSinceFlush,
		LastFlushTime:     tw.lastFlushTime,
		HeartbeatStats:    hbStats,
	}
}

// TrackerWALStats contains tracker WAL statistics.
type TrackerWALStats struct {
	SessionID         [32]byte
	DocumentPath      string
	Running           bool
	WALPath           string
	WALSize           int64
	WALEntryCount     uint64
	KeystrokesSinceCommit uint64
	SamplesSinceCommit    uint64
	LastFlushTime     time.Time
	HeartbeatStats    HeartbeatStats
}

// MultiDocumentTracker manages WAL integration for multiple documents.
type MultiDocumentTracker struct {
	mu       sync.RWMutex
	trackers map[string]*TrackerWAL
	walDir   string
	hmacKey  []byte

	// Shared callbacks
	onCheckpoint func(docPath, trigger string) error
	onRecovery   func(docPath string, data *RecoveredData) error
}

// MultiDocumentTrackerConfig configures the multi-document tracker.
type MultiDocumentTrackerConfig struct {
	WALDir       string
	HMACKey      []byte
	OnCheckpoint func(docPath, trigger string) error
	OnRecovery   func(docPath string, data *RecoveredData) error
}

// NewMultiDocumentTracker creates a tracker for multiple documents.
func NewMultiDocumentTracker(config MultiDocumentTrackerConfig) *MultiDocumentTracker {
	return &MultiDocumentTracker{
		trackers:     make(map[string]*TrackerWAL),
		walDir:       config.WALDir,
		hmacKey:      config.HMACKey,
		onCheckpoint: config.OnCheckpoint,
		onRecovery:   config.OnRecovery,
	}
}

// StartTracking begins tracking a document.
func (mdt *MultiDocumentTracker) StartTracking(ctx context.Context, documentPath string) error {
	mdt.mu.Lock()
	defer mdt.mu.Unlock()

	// Check if already tracking
	if _, exists := mdt.trackers[documentPath]; exists {
		return fmt.Errorf("already tracking %s", documentPath)
	}

	// Create tracker WAL
	config := TrackerWALConfig{
		WALDir:       mdt.walDir,
		DocumentPath: documentPath,
		HMACKey:      mdt.hmacKey,
		OnCheckpoint: func(trigger string) error {
			if mdt.onCheckpoint != nil {
				return mdt.onCheckpoint(documentPath, trigger)
			}
			return nil
		},
		OnRecovery: func(data *RecoveredData) error {
			if mdt.onRecovery != nil {
				return mdt.onRecovery(documentPath, data)
			}
			return nil
		},
	}

	tracker, err := NewTrackerWAL(config)
	if err != nil {
		return err
	}

	if err := tracker.Start(ctx); err != nil {
		return err
	}

	mdt.trackers[documentPath] = tracker
	return nil
}

// StopTracking stops tracking a document.
func (mdt *MultiDocumentTracker) StopTracking(documentPath string) error {
	mdt.mu.Lock()
	defer mdt.mu.Unlock()

	tracker, exists := mdt.trackers[documentPath]
	if !exists {
		return fmt.Errorf("not tracking %s", documentPath)
	}

	if err := tracker.Stop(); err != nil {
		return err
	}

	delete(mdt.trackers, documentPath)
	return nil
}

// GetTracker returns the tracker for a document.
func (mdt *MultiDocumentTracker) GetTracker(documentPath string) (*TrackerWAL, bool) {
	mdt.mu.RLock()
	defer mdt.mu.RUnlock()
	tracker, exists := mdt.trackers[documentPath]
	return tracker, exists
}

// OnFocusChange handles document focus change.
func (mdt *MultiDocumentTracker) OnFocusChange(newDocPath string) {
	mdt.mu.RLock()
	defer mdt.mu.RUnlock()

	// Pause all other trackers
	for path, tracker := range mdt.trackers {
		if path != newDocPath {
			tracker.Pause()
		}
	}

	// Resume the focused tracker
	if tracker, exists := mdt.trackers[newDocPath]; exists {
		tracker.Resume()
	}
}

// StopAll stops all trackers.
func (mdt *MultiDocumentTracker) StopAll() error {
	mdt.mu.Lock()
	defer mdt.mu.Unlock()

	var lastErr error
	for path, tracker := range mdt.trackers {
		if err := tracker.Stop(); err != nil {
			lastErr = err
		}
		delete(mdt.trackers, path)
	}

	return lastErr
}

// RecoverAll attempts recovery on all WAL files in the directory.
func (mdt *MultiDocumentTracker) RecoverAll() ([]RecoveryInfo, error) {
	// This would scan the WAL directory and attempt recovery on each file
	// For production use, implement directory scanning
	return nil, nil
}
