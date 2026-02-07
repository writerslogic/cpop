// Package wal implements crash recovery for the Write-Ahead Log.
//
// The recovery system provides:
// - HMAC verification during recovery to detect tampering
// - Timestamp validation to detect clock manipulation
// - Graceful handling of corrupted WAL files
// - Recovery data aggregation for checkpoint creation
//
// Patent Pending: USPTO Application No. 19/460,364
package wal

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// Recovery errors
var (
	ErrRecoveryFailed        = errors.New("wal: recovery failed")
	ErrTimestampBackward     = errors.New("wal: timestamp went backward (possible clock manipulation)")
	ErrTimestampFuture       = errors.New("wal: timestamp in future (clock skew or manipulation)")
	ErrSuspiciousGap         = errors.New("wal: suspicious time gap detected")
	ErrTooManyCorrupted      = errors.New("wal: too many corrupted entries")
	ErrTooManyTampered       = errors.New("wal: too many tampered entries detected")
	ErrWALTooOld             = errors.New("wal: WAL file too old for recovery")
	ErrIncompleteCommit      = errors.New("wal: incomplete commit detected during recovery")
)

// RecoveryConfig configures the recovery process.
type RecoveryConfig struct {
	// HMACKey for verifying entry integrity
	HMACKey []byte

	// MaxWALAge is the maximum age of a WAL file to attempt recovery
	// Default: 168 hours (1 week)
	MaxWALAge time.Duration

	// MaxCorruptedEntries is the maximum number of corrupted entries
	// before aborting recovery. Default: 10
	MaxCorruptedEntries int

	// MaxTamperedEntries is the maximum tampered entries before
	// flagging the session as compromised. Default: 0 (strict)
	MaxTamperedEntries int

	// MaxTimeGap is the maximum time gap between entries before
	// logging a warning. Default: 24 hours
	MaxTimeGap time.Duration

	// AllowFutureTimestamps allows timestamps slightly in the future
	// (for clock skew tolerance). Default: 5 minutes
	FutureTimestampTolerance time.Duration

	// NotifyOnRecovery enables user notification for recovery events
	NotifyOnRecovery bool

	// Logger for recovery events
	Logger RecoveryLogger
}

// DefaultRecoveryConfig returns sensible defaults for recovery.
func DefaultRecoveryConfig(hmacKey []byte) RecoveryConfig {
	return RecoveryConfig{
		HMACKey:                  hmacKey,
		MaxWALAge:                168 * time.Hour, // 1 week
		MaxCorruptedEntries:      10,
		MaxTamperedEntries:       0, // Strict mode
		MaxTimeGap:               24 * time.Hour,
		FutureTimestampTolerance: 5 * time.Minute,
		NotifyOnRecovery:         true,
		Logger:                   &defaultLogger{},
	}
}

// RecoveryLogger logs recovery events.
type RecoveryLogger interface {
	Info(msg string, fields ...interface{})
	Warn(msg string, fields ...interface{})
	Error(msg string, fields ...interface{})
}

// defaultLogger is a no-op logger.
type defaultLogger struct{}

func (l *defaultLogger) Info(msg string, fields ...interface{})  {}
func (l *defaultLogger) Warn(msg string, fields ...interface{})  {}
func (l *defaultLogger) Error(msg string, fields ...interface{}) {}

// Recovery manages WAL crash recovery.
type Recovery struct {
	config RecoveryConfig
	wal    *WAL
}

// RecoveredData holds data recovered from WAL entries.
type RecoveredData struct {
	// Recovery metadata
	RecoveredAt      time.Time
	WALPath          string
	LastCheckpointSeq uint64

	// Entry statistics
	TotalEntries     uint64
	ValidEntries     uint64
	CorruptedEntries uint64
	TamperedEntries  uint64
	SkippedEntries   uint64

	// Recovered keystroke data
	KeystrokeBatches []*KeystrokeBatchPayload
	TotalKeystrokes  uint64

	// Recovered document hashes
	DocumentHashes []*DocumentHashPayload
	LastDocHash    [32]byte

	// Recovered jitter samples
	JitterSamples []*JitterSamplePayload
	TotalSamples  uint64

	// Session information
	SessionStart *SessionStartPayload
	SessionEnd   *SessionEndPayload

	// Heartbeat information
	Heartbeats        []*HeartbeatPayload
	IncompleteCommit  bool

	// Checkpoint information
	LastCheckpoint *CheckpointPayload

	// Warnings and limitations
	Warnings    []string
	Limitations []string

	// Time analysis
	FirstTimestamp int64
	LastTimestamp  int64
	TimeGaps       []TimeGap
}

// TimeGap represents a suspicious time gap between entries.
type TimeGap struct {
	BeforeSeq  uint64
	AfterSeq   uint64
	GapDuration time.Duration
}

// NewRecovery creates a new Recovery instance.
func NewRecovery(walPath string, config RecoveryConfig) (*Recovery, error) {
	// Check if WAL exists
	if !Exists(walPath) {
		return nil, fmt.Errorf("%w: WAL file does not exist", ErrRecoveryFailed)
	}

	// Open WAL file for reading
	wal, err := openForRecovery(walPath, config.HMACKey)
	if err != nil {
		return nil, fmt.Errorf("open WAL for recovery: %w", err)
	}

	return &Recovery{
		config: config,
		wal:    wal,
	}, nil
}

// openForRecovery opens a WAL file in read-only mode for recovery.
func openForRecovery(path string, hmacKey []byte) (*WAL, error) {
	file, err := os.OpenFile(path, os.O_RDONLY, 0600)
	if err != nil {
		return nil, err
	}

	w := &WAL{
		path:    path,
		file:    file,
		hmacKey: hmacKey,
	}

	// Read header
	if err := w.readHeader(); err != nil {
		file.Close()
		return nil, err
	}

	return w, nil
}

// RecoverFromCrash performs crash recovery on a WAL file.
// It reads all entries, validates their integrity, and returns
// recovered data that can be used to create a recovery checkpoint.
func (r *Recovery) RecoverFromCrash() (*RecoveredData, error) {
	r.config.Logger.Info("Starting crash recovery", "path", r.wal.path)

	// Check WAL age
	if err := r.checkWALAge(); err != nil {
		return nil, err
	}

	// Read and validate all entries
	data := &RecoveredData{
		RecoveredAt: time.Now(),
		WALPath:     r.wal.path,
	}

	// Read entries with validation
	entries, err := r.readAndValidateEntries(data)
	if err != nil {
		return nil, err
	}

	// Process recovered entries
	if err := r.processEntries(entries, data); err != nil {
		return nil, err
	}

	// Validate timestamps
	if err := r.validateTimestamps(entries, data); err != nil {
		// Log but don't fail - add to warnings
		data.Warnings = append(data.Warnings, err.Error())
	}

	// Set limitations based on recovery
	r.setLimitations(data)

	r.config.Logger.Info("Recovery complete",
		"valid_entries", data.ValidEntries,
		"corrupted", data.CorruptedEntries,
		"tampered", data.TamperedEntries,
		"keystrokes", data.TotalKeystrokes,
		"samples", data.TotalSamples)

	return data, nil
}

// checkWALAge verifies the WAL file isn't too old.
func (r *Recovery) checkWALAge() error {
	stat, err := os.Stat(r.wal.path)
	if err != nil {
		return err
	}

	age := time.Since(stat.ModTime())
	if age > r.config.MaxWALAge {
		r.config.Logger.Warn("WAL file too old for recovery",
			"age", age,
			"max_age", r.config.MaxWALAge)
		return fmt.Errorf("%w: age %v exceeds max %v", ErrWALTooOld, age, r.config.MaxWALAge)
	}

	return nil
}

// readAndValidateEntries reads all WAL entries with CRC and HMAC validation.
func (r *Recovery) readAndValidateEntries(data *RecoveredData) ([]Entry, error) {
	var entries []Entry
	var prevHash [32]byte
	offset := int64(HeaderSize)

	for {
		// Read entry length
		lenBuf := make([]byte, 4)
		_, err := r.wal.file.ReadAt(lenBuf, offset)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read entry length at offset %d: %w", offset, err)
		}

		entryLen := binary.BigEndian.Uint32(lenBuf)
		if entryLen == 0 {
			break
		}

		data.TotalEntries++

		// Read full entry
		entryBuf := make([]byte, entryLen)
		if _, err := r.wal.file.ReadAt(entryBuf, offset); err != nil {
			if err == io.EOF {
				// Partial entry at end - log and stop
				r.config.Logger.Warn("Partial entry at WAL end",
					"offset", offset,
					"expected_len", entryLen)
				data.CorruptedEntries++
				data.Warnings = append(data.Warnings, "Partial entry detected at WAL end")
				break
			}
			return nil, fmt.Errorf("read entry at offset %d: %w", offset, err)
		}

		entry, err := deserializeEntry(entryBuf)
		if err != nil {
			// Corrupted entry - log and continue
			r.config.Logger.Warn("Failed to deserialize entry",
				"offset", offset,
				"error", err)
			data.CorruptedEntries++
			offset += int64(entryLen)
			continue
		}

		// Verify CRC
		if entry.CRC32 != computeEntryCRC(entry) {
			r.config.Logger.Warn("CRC mismatch",
				"sequence", entry.Sequence,
				"expected", computeEntryCRC(entry),
				"got", entry.CRC32)
			data.CorruptedEntries++
			offset += int64(entryLen)
			continue
		}

		// Verify hash chain (skip for first entry)
		if entry.Sequence > 0 && entry.PrevHash != prevHash {
			r.config.Logger.Warn("Broken hash chain",
				"sequence", entry.Sequence)
			data.CorruptedEntries++
			// Don't skip - the entry data might still be valid
		}

		// Verify HMAC
		if !r.wal.VerifyHMAC(entry) {
			r.config.Logger.Warn("HMAC verification failed - possible tampering",
				"sequence", entry.Sequence,
				"type", entry.Type)
			data.TamperedEntries++

			// Check if we've exceeded tampered entry limit
			if r.config.MaxTamperedEntries >= 0 &&
				int(data.TamperedEntries) > r.config.MaxTamperedEntries {
				return nil, fmt.Errorf("%w: %d tampered entries detected",
					ErrTooManyTampered, data.TamperedEntries)
			}

			data.Warnings = append(data.Warnings,
				fmt.Sprintf("Tampered entry detected at sequence %d", entry.Sequence))
			offset += int64(entryLen)
			continue
		}

		// Entry is valid
		data.ValidEntries++
		entries = append(entries, *entry)
		prevHash = entry.Hash()
		offset += int64(entryLen)

		// Check corruption limit
		if int(data.CorruptedEntries) > r.config.MaxCorruptedEntries {
			return nil, fmt.Errorf("%w: %d corrupted entries",
				ErrTooManyCorrupted, data.CorruptedEntries)
		}
	}

	return entries, nil
}

// processEntries processes valid entries and aggregates recovered data.
func (r *Recovery) processEntries(entries []Entry, data *RecoveredData) error {
	for _, entry := range entries {
		// Track timestamps
		if data.FirstTimestamp == 0 {
			data.FirstTimestamp = entry.Timestamp
		}
		data.LastTimestamp = entry.Timestamp

		switch entry.Type {
		case EntryKeystrokeBatch:
			batch, err := DeserializeKeystrokeBatch(entry.Payload)
			if err != nil {
				r.config.Logger.Warn("Failed to deserialize keystroke batch",
					"sequence", entry.Sequence,
					"error", err)
				data.SkippedEntries++
				continue
			}
			data.KeystrokeBatches = append(data.KeystrokeBatches, batch)
			data.TotalKeystrokes += uint64(batch.Count)
			data.LastDocHash = batch.DocumentHash

		case EntryDocumentHash:
			docHash, err := DeserializeDocumentHash(entry.Payload)
			if err != nil {
				r.config.Logger.Warn("Failed to deserialize document hash",
					"sequence", entry.Sequence,
					"error", err)
				data.SkippedEntries++
				continue
			}
			data.DocumentHashes = append(data.DocumentHashes, docHash)
			data.LastDocHash = docHash.Hash

		case EntryJitterSample:
			sample, err := DeserializeJitterSample(entry.Payload)
			if err != nil {
				r.config.Logger.Warn("Failed to deserialize jitter sample",
					"sequence", entry.Sequence,
					"error", err)
				data.SkippedEntries++
				continue
			}
			data.JitterSamples = append(data.JitterSamples, sample)
			data.TotalSamples++

		case EntryHeartbeat:
			heartbeat, err := DeserializeHeartbeat(entry.Payload)
			if err != nil {
				r.config.Logger.Warn("Failed to deserialize heartbeat",
					"sequence", entry.Sequence,
					"error", err)
				data.SkippedEntries++
				continue
			}
			data.Heartbeats = append(data.Heartbeats, heartbeat)

		case EntrySessionStart:
			sessionStart, err := DeserializeSessionStart(entry.Payload)
			if err != nil {
				r.config.Logger.Warn("Failed to deserialize session start",
					"sequence", entry.Sequence,
					"error", err)
				data.SkippedEntries++
				continue
			}
			data.SessionStart = sessionStart

		case EntrySessionEnd:
			sessionEnd, err := DeserializeSessionEnd(entry.Payload)
			if err != nil {
				r.config.Logger.Warn("Failed to deserialize session end",
					"sequence", entry.Sequence,
					"error", err)
				data.SkippedEntries++
				continue
			}
			data.SessionEnd = sessionEnd

		case EntryCheckpoint:
			checkpoint, err := DeserializeCheckpoint(entry.Payload)
			if err != nil {
				r.config.Logger.Warn("Failed to deserialize checkpoint",
					"sequence", entry.Sequence,
					"error", err)
				data.SkippedEntries++
				continue
			}
			data.LastCheckpoint = checkpoint
			data.LastCheckpointSeq = checkpoint.WALSequence
		}
	}

	// Detect incomplete commit (heartbeat without subsequent checkpoint)
	if len(data.Heartbeats) > 0 && data.LastCheckpoint != nil {
		lastHeartbeat := data.Heartbeats[len(data.Heartbeats)-1]
		if lastHeartbeat.Timestamp > data.LastCheckpoint.Timestamp {
			data.IncompleteCommit = true
			data.Warnings = append(data.Warnings,
				"Incomplete commit detected - crash may have occurred during checkpoint creation")
		}
	} else if len(data.Heartbeats) > 0 && data.LastCheckpoint == nil {
		// Heartbeats but no checkpoint at all
		data.IncompleteCommit = true
	}

	return nil
}

// validateTimestamps checks for timestamp manipulation.
func (r *Recovery) validateTimestamps(entries []Entry, data *RecoveredData) error {
	if len(entries) == 0 {
		return nil
	}

	now := time.Now().UnixNano()
	futureLimit := now + r.config.FutureTimestampTolerance.Nanoseconds()

	var prevTimestamp int64
	var errs []error

	for _, entry := range entries {
		// Check for backward timestamp
		if entry.Timestamp < prevTimestamp {
			err := fmt.Errorf("%w: entry %d timestamp %d < previous %d",
				ErrTimestampBackward, entry.Sequence, entry.Timestamp, prevTimestamp)
			r.config.Logger.Warn("Timestamp went backward",
				"sequence", entry.Sequence,
				"timestamp", entry.Timestamp,
				"previous", prevTimestamp)
			errs = append(errs, err)
		}

		// Check for future timestamp
		if entry.Timestamp > futureLimit {
			err := fmt.Errorf("%w: entry %d timestamp %d > now %d",
				ErrTimestampFuture, entry.Sequence, entry.Timestamp, now)
			r.config.Logger.Warn("Timestamp in future",
				"sequence", entry.Sequence,
				"timestamp", entry.Timestamp,
				"now", now)
			errs = append(errs, err)
		}

		// Check for suspicious gaps
		if prevTimestamp > 0 {
			gap := time.Duration(entry.Timestamp - prevTimestamp)
			if gap > r.config.MaxTimeGap {
				r.config.Logger.Warn("Suspicious time gap",
					"sequence", entry.Sequence,
					"gap", gap)
				data.TimeGaps = append(data.TimeGaps, TimeGap{
					BeforeSeq:   entry.Sequence - 1,
					AfterSeq:    entry.Sequence,
					GapDuration: gap,
				})
			}
		}

		prevTimestamp = entry.Timestamp
	}

	if len(errs) > 0 {
		return fmt.Errorf("timestamp validation found %d issues", len(errs))
	}

	return nil
}

// setLimitations sets documented limitations based on recovery state.
func (r *Recovery) setLimitations(data *RecoveredData) {
	// Always add the standard recovery limitation
	data.Limitations = append(data.Limitations,
		"Session recovered from crash - some data may be incomplete")

	if data.CorruptedEntries > 0 {
		data.Limitations = append(data.Limitations,
			fmt.Sprintf("%d WAL entries were corrupted and skipped", data.CorruptedEntries))
	}

	if data.TamperedEntries > 0 {
		data.Limitations = append(data.Limitations,
			fmt.Sprintf("%d WAL entries failed HMAC verification (possible tampering)", data.TamperedEntries))
	}

	if data.IncompleteCommit {
		data.Limitations = append(data.Limitations,
			"Checkpoint commit was interrupted - VDF proof will be recomputed with different timestamp")
	}

	if len(data.TimeGaps) > 0 {
		data.Limitations = append(data.Limitations,
			fmt.Sprintf("%d suspicious time gaps detected", len(data.TimeGaps)))
	}

	// Estimate data loss
	if data.FirstTimestamp > 0 && data.LastTimestamp > 0 {
		duration := time.Duration(data.LastTimestamp - data.FirstTimestamp)
		data.Limitations = append(data.Limitations,
			fmt.Sprintf("Recovered data spans %v", duration.Round(time.Second)))
	}
}

// IsSignificant returns true if the recovered data is worth creating a checkpoint for.
func (data *RecoveredData) IsSignificant() bool {
	// Consider recovery significant if we have any of:
	// - Keystroke data
	// - Jitter samples
	// - Document hashes after the last checkpoint
	return data.TotalKeystrokes > 0 ||
		data.TotalSamples > 0 ||
		len(data.DocumentHashes) > 0
}

// Stats returns a summary of the recovered data.
func (data *RecoveredData) Stats() RecoveryInfo {
	var dataLoss string
	if data.FirstTimestamp > 0 && data.LastTimestamp > 0 {
		duration := time.Duration(data.LastTimestamp - data.FirstTimestamp)
		dataLoss = fmt.Sprintf("~%v of data recovered", duration.Round(time.Second))
	} else {
		dataLoss = "< 100ms"
	}

	return RecoveryInfo{
		RecoveredAt:         data.RecoveredAt,
		EntriesRecovered:    data.ValidEntries,
		LastCheckpointSeq:   data.LastCheckpointSeq,
		KeystrokesRecovered: data.TotalKeystrokes,
		SamplesRecovered:    data.TotalSamples,
		DataLossEstimate:    dataLoss,
		CorruptedEntries:    data.CorruptedEntries,
		TamperedEntries:     data.TamperedEntries,
	}
}

// Close closes the recovery WAL file.
func (r *Recovery) Close() error {
	if r.wal != nil {
		return r.wal.file.Close()
	}
	return nil
}

// StartFresh creates a backup of the corrupted WAL and prepares for a fresh start.
func StartFresh(walPath string) error {
	if !Exists(walPath) {
		return nil
	}

	// Create backup with timestamp
	backupPath := fmt.Sprintf("%s.corrupted.%d", walPath, time.Now().Unix())
	if err := os.Rename(walPath, backupPath); err != nil {
		return fmt.Errorf("backup corrupted WAL: %w", err)
	}

	return nil
}

// ValidateWAL performs a quick validation of a WAL file without full recovery.
// Returns nil if the WAL appears valid, or an error describing the issue.
func ValidateWAL(walPath string, hmacKey []byte) error {
	if !Exists(walPath) {
		return fmt.Errorf("WAL file does not exist")
	}

	file, err := os.OpenFile(walPath, os.O_RDONLY, 0600)
	if err != nil {
		return fmt.Errorf("open WAL: %w", err)
	}
	defer file.Close()

	// Read header
	headerBuf := make([]byte, HeaderSize)
	if _, err := file.ReadAt(headerBuf, 0); err != nil {
		return fmt.Errorf("read header: %w", err)
	}

	// Validate magic
	if string(headerBuf[0:4]) != Magic {
		return ErrInvalidMagic
	}

	// Validate version
	version := binary.BigEndian.Uint32(headerBuf[4:8])
	if version != Version {
		return fmt.Errorf("%w: got %d, expected %d", ErrInvalidVersion, version, Version)
	}

	// Quick scan of entries
	offset := int64(HeaderSize)
	var prevHash [32]byte
	w := &WAL{hmacKey: hmacKey}

	for {
		lenBuf := make([]byte, 4)
		_, err := file.ReadAt(lenBuf, offset)
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read entry at offset %d: %w", offset, err)
		}

		entryLen := binary.BigEndian.Uint32(lenBuf)
		if entryLen == 0 {
			break
		}

		entryBuf := make([]byte, entryLen)
		if _, err := file.ReadAt(entryBuf, offset); err != nil {
			return fmt.Errorf("read entry data: %w", err)
		}

		entry, err := deserializeEntry(entryBuf)
		if err != nil {
			return fmt.Errorf("deserialize entry at offset %d: %w", offset, err)
		}

		// Verify CRC
		if entry.CRC32 != computeEntryCRC(entry) {
			return fmt.Errorf("entry %d: %w", entry.Sequence, ErrCorruptedEntry)
		}

		// Verify hash chain (skip first entry)
		if entry.Sequence > 0 && entry.PrevHash != prevHash {
			return fmt.Errorf("entry %d: %w", entry.Sequence, ErrBrokenChain)
		}

		// Verify HMAC
		if !w.VerifyHMAC(entry) {
			return fmt.Errorf("entry %d: %w", entry.Sequence, ErrInvalidHMAC)
		}

		prevHash = entry.Hash()
		offset += int64(entryLen)
	}

	return nil
}
