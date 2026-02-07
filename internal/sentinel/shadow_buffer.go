// Package sentinel shadow buffer for keystroke accumulation.
//
// ShadowBuffer provides temporary storage for keystroke data before it is
// committed to the WAL. It supports:
//   - Configurable max size and TTL
//   - Memory-mapped file backing for crash resilience
//   - Automatic rotation when document changes
//   - Efficient append-only writes
//
// Patent Pending: USPTO Application No. 19/460,364
package sentinel

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// ShadowBufferConfig configures a shadow buffer.
type ShadowBufferConfig struct {
	// MaxSize is the maximum buffer size in bytes.
	MaxSize int

	// TTL is how long data can remain in the buffer before expiring.
	TTL time.Duration

	// BackingPath is the path to the memory-mapped backing file (optional).
	// If empty, buffer is memory-only.
	BackingPath string

	// SyncInterval is how often to sync to disk (if using mmap).
	SyncInterval time.Duration
}

// DefaultShadowBufferConfig returns sensible defaults.
func DefaultShadowBufferConfig() ShadowBufferConfig {
	return ShadowBufferConfig{
		MaxSize:      1 << 20, // 1MB
		TTL:          time.Hour,
		BackingPath:  "",
		SyncInterval: 5 * time.Second,
	}
}

// KeystrokeRecord represents a single keystroke entry in the shadow buffer.
type KeystrokeRecord struct {
	Timestamp time.Time
	Sequence  uint64
}

// ShadowBuffer accumulates keystroke data for a document.
type ShadowBuffer struct {
	config ShadowBufferConfig

	mu sync.RWMutex

	// In-memory buffer
	data []byte

	// Keystroke records (timestamps only, no content)
	records []KeystrokeRecord

	// Statistics
	keystrokeCount uint64
	bytesWritten   uint64
	createdAt      time.Time
	lastWrite      time.Time

	// Sequence counter for ordering
	sequence atomic.Uint64

	// Backing file (optional)
	backingFile *os.File
	closed      bool

	// Flush callback (called when buffer is flushed)
	onFlush func(data []byte, hash [32]byte)
}

// NewShadowBuffer creates a new shadow buffer.
func NewShadowBuffer(config ShadowBufferConfig) (*ShadowBuffer, error) {
	if config.MaxSize <= 0 {
		config.MaxSize = DefaultShadowBufferConfig().MaxSize
	}
	if config.TTL <= 0 {
		config.TTL = DefaultShadowBufferConfig().TTL
	}

	sb := &ShadowBuffer{
		config:    config,
		data:      make([]byte, 0, 4096), // Initial capacity
		records:   make([]KeystrokeRecord, 0, 1000),
		createdAt: time.Now(),
	}

	// Create backing file if path provided
	if config.BackingPath != "" {
		if err := sb.initBackingFile(); err != nil {
			return nil, fmt.Errorf("init backing file: %w", err)
		}
	}

	return sb, nil
}

// initBackingFile creates or opens the backing file.
func (sb *ShadowBuffer) initBackingFile() error {
	dir := filepath.Dir(sb.config.BackingPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	// Try to recover existing file
	if info, err := os.Stat(sb.config.BackingPath); err == nil && info.Size() > 0 {
		if err := sb.recoverFromFile(); err != nil {
			// Recovery failed, start fresh
			os.Remove(sb.config.BackingPath)
		}
	}

	// Open/create file
	f, err := os.OpenFile(sb.config.BackingPath, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return err
	}

	sb.backingFile = f
	return nil
}

// recoverFromFile attempts to recover data from the backing file.
func (sb *ShadowBuffer) recoverFromFile() error {
	f, err := os.Open(sb.config.BackingPath)
	if err != nil {
		return err
	}
	defer f.Close()

	// Read header
	var header shadowFileHeader
	if err := binary.Read(f, binary.LittleEndian, &header); err != nil {
		return err
	}

	// Validate header
	if header.Magic != shadowFileMagic {
		return errors.New("invalid shadow file magic")
	}

	// Read records
	for i := uint32(0); i < header.RecordCount; i++ {
		var record shadowFileRecord
		if err := binary.Read(f, binary.LittleEndian, &record); err != nil {
			break // Partial read, use what we have
		}
		sb.records = append(sb.records, KeystrokeRecord{
			Timestamp: time.Unix(0, record.TimestampNano),
			Sequence:  record.Sequence,
		})
	}

	if len(sb.records) > 0 {
		sb.keystrokeCount = uint64(len(sb.records))
		sb.sequence.Store(sb.records[len(sb.records)-1].Sequence)
	}

	return nil
}

// Shadow file format constants
const shadowFileMagic uint32 = 0x53484144 // "SHAD"

// shadowFileHeader is the header of a shadow buffer file.
type shadowFileHeader struct {
	Magic       uint32 // Magic number
	Version     uint16 // Format version
	Flags       uint16 // Flags
	RecordCount uint32 // Number of records
	Reserved    uint32 // Reserved for future use
}

// shadowFileRecord is a single record in the shadow file.
type shadowFileRecord struct {
	TimestampNano int64  // Timestamp in nanoseconds
	Sequence      uint64 // Sequence number
	Reserved      uint64 // Reserved for future use
}

// RecordKeystroke records a keystroke event.
func (sb *ShadowBuffer) RecordKeystroke(t time.Time) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if sb.closed {
		return
	}

	// Check buffer limits
	if len(sb.records) >= sb.config.MaxSize/24 { // ~24 bytes per record
		// Buffer full, need to rotate or discard old records
		sb.rotateOldRecords()
	}

	seq := sb.sequence.Add(1)
	record := KeystrokeRecord{
		Timestamp: t,
		Sequence:  seq,
	}

	sb.records = append(sb.records, record)
	sb.keystrokeCount++
	sb.lastWrite = time.Now()

	// Write to backing file if present
	if sb.backingFile != nil {
		sb.writeRecordToFile(record)
	}
}

// rotateOldRecords removes the oldest half of records when buffer is full.
func (sb *ShadowBuffer) rotateOldRecords() {
	if len(sb.records) < 2 {
		return
	}

	// Keep the newer half
	half := len(sb.records) / 2
	copy(sb.records, sb.records[half:])
	sb.records = sb.records[:len(sb.records)-half]

	// Rewrite backing file
	if sb.backingFile != nil {
		sb.rewriteBackingFile()
	}
}

// writeRecordToFile writes a single record to the backing file.
func (sb *ShadowBuffer) writeRecordToFile(record KeystrokeRecord) {
	if sb.backingFile == nil {
		return
	}

	// Seek to end
	sb.backingFile.Seek(0, io.SeekEnd)

	// Write record
	fileRecord := shadowFileRecord{
		TimestampNano: record.Timestamp.UnixNano(),
		Sequence:      record.Sequence,
	}
	binary.Write(sb.backingFile, binary.LittleEndian, &fileRecord)

	// Update header
	sb.updateFileHeader()
}

// rewriteBackingFile rewrites the entire backing file.
func (sb *ShadowBuffer) rewriteBackingFile() {
	if sb.backingFile == nil {
		return
	}

	// Truncate and rewrite
	sb.backingFile.Truncate(0)
	sb.backingFile.Seek(0, io.SeekStart)

	// Write header
	header := shadowFileHeader{
		Magic:       shadowFileMagic,
		Version:     1,
		RecordCount: uint32(len(sb.records)),
	}
	binary.Write(sb.backingFile, binary.LittleEndian, &header)

	// Write records
	for _, record := range sb.records {
		fileRecord := shadowFileRecord{
			TimestampNano: record.Timestamp.UnixNano(),
			Sequence:      record.Sequence,
		}
		binary.Write(sb.backingFile, binary.LittleEndian, &fileRecord)
	}

	sb.backingFile.Sync()
}

// updateFileHeader updates the record count in the file header.
func (sb *ShadowBuffer) updateFileHeader() {
	if sb.backingFile == nil {
		return
	}

	// Seek to record count offset
	sb.backingFile.Seek(8, io.SeekStart) // After magic, version, flags

	// Write record count
	binary.Write(sb.backingFile, binary.LittleEndian, uint32(len(sb.records)))
}

// Write appends data to the shadow buffer.
func (sb *ShadowBuffer) Write(p []byte) (n int, err error) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if sb.closed {
		return 0, errors.New("shadow buffer closed")
	}

	// Check size limit
	if len(sb.data)+len(p) > sb.config.MaxSize {
		return 0, errors.New("shadow buffer full")
	}

	sb.data = append(sb.data, p...)
	sb.bytesWritten += uint64(len(p))
	sb.lastWrite = time.Now()

	return len(p), nil
}

// Size returns the current buffer size.
func (sb *ShadowBuffer) Size() int {
	sb.mu.RLock()
	defer sb.mu.RUnlock()
	return len(sb.data) + len(sb.records)*24 // Approximate
}

// KeystrokeCount returns the number of keystrokes recorded.
func (sb *ShadowBuffer) KeystrokeCount() uint64 {
	sb.mu.RLock()
	defer sb.mu.RUnlock()
	return sb.keystrokeCount
}

// Records returns a copy of all keystroke records.
func (sb *ShadowBuffer) Records() []KeystrokeRecord {
	sb.mu.RLock()
	defer sb.mu.RUnlock()

	result := make([]KeystrokeRecord, len(sb.records))
	copy(result, sb.records)
	return result
}

// IsExpired checks if the buffer has exceeded its TTL.
func (sb *ShadowBuffer) IsExpired() bool {
	sb.mu.RLock()
	defer sb.mu.RUnlock()

	if sb.lastWrite.IsZero() {
		return time.Since(sb.createdAt) > sb.config.TTL
	}
	return time.Since(sb.lastWrite) > sb.config.TTL
}

// Flush extracts all data and clears the buffer.
// Returns the data and its SHA-256 hash.
func (sb *ShadowBuffer) Flush() ([]byte, [32]byte) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	// Serialize records to bytes
	var data []byte

	// Write record count
	countBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(countBytes, uint64(len(sb.records)))
	data = append(data, countBytes...)

	// Write each record
	for _, record := range sb.records {
		recordBytes := make([]byte, 16)
		binary.LittleEndian.PutUint64(recordBytes[0:8], uint64(record.Timestamp.UnixNano()))
		binary.LittleEndian.PutUint64(recordBytes[8:16], record.Sequence)
		data = append(data, recordBytes...)
	}

	// Add any raw data
	data = append(data, sb.data...)

	// Compute hash
	hash := sha256.Sum256(data)

	// Clear buffer
	sb.records = sb.records[:0]
	sb.data = sb.data[:0]
	sb.keystrokeCount = 0
	sb.bytesWritten = 0

	// Clear backing file
	if sb.backingFile != nil {
		sb.backingFile.Truncate(0)
		sb.backingFile.Seek(0, io.SeekStart)
	}

	// Call flush callback if set
	if sb.onFlush != nil {
		sb.onFlush(data, hash)
	}

	return data, hash
}

// Snapshot returns a copy of the current buffer contents without clearing.
func (sb *ShadowBuffer) Snapshot() ([]byte, [32]byte) {
	sb.mu.RLock()
	defer sb.mu.RUnlock()

	// Serialize records
	var data []byte

	countBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(countBytes, uint64(len(sb.records)))
	data = append(data, countBytes...)

	for _, record := range sb.records {
		recordBytes := make([]byte, 16)
		binary.LittleEndian.PutUint64(recordBytes[0:8], uint64(record.Timestamp.UnixNano()))
		binary.LittleEndian.PutUint64(recordBytes[8:16], record.Sequence)
		data = append(data, recordBytes...)
	}

	data = append(data, sb.data...)
	hash := sha256.Sum256(data)

	return data, hash
}

// SetFlushCallback sets a function to be called when the buffer is flushed.
func (sb *ShadowBuffer) SetFlushCallback(fn func(data []byte, hash [32]byte)) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	sb.onFlush = fn
}

// Stats returns buffer statistics.
func (sb *ShadowBuffer) Stats() ShadowBufferStats {
	sb.mu.RLock()
	defer sb.mu.RUnlock()

	return ShadowBufferStats{
		KeystrokeCount: sb.keystrokeCount,
		BytesWritten:   sb.bytesWritten,
		RecordCount:    len(sb.records),
		DataSize:       len(sb.data),
		CreatedAt:      sb.createdAt,
		LastWrite:      sb.lastWrite,
		TTL:            sb.config.TTL,
		MaxSize:        sb.config.MaxSize,
	}
}

// ShadowBufferStats contains buffer statistics.
type ShadowBufferStats struct {
	KeystrokeCount uint64
	BytesWritten   uint64
	RecordCount    int
	DataSize       int
	CreatedAt      time.Time
	LastWrite      time.Time
	TTL            time.Duration
	MaxSize        int
}

// Close closes the shadow buffer and cleans up resources.
func (sb *ShadowBuffer) Close() error {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if sb.closed {
		return nil
	}

	sb.closed = true

	if sb.backingFile != nil {
		sb.backingFile.Sync()
		err := sb.backingFile.Close()
		sb.backingFile = nil

		// Remove backing file
		if sb.config.BackingPath != "" {
			os.Remove(sb.config.BackingPath)
		}

		return err
	}

	return nil
}

// Reset clears the buffer without closing it.
func (sb *ShadowBuffer) Reset() {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	sb.records = sb.records[:0]
	sb.data = sb.data[:0]
	sb.keystrokeCount = 0
	sb.bytesWritten = 0
	sb.createdAt = time.Now()
	sb.lastWrite = time.Time{}

	if sb.backingFile != nil {
		sb.backingFile.Truncate(0)
		sb.backingFile.Seek(0, io.SeekStart)
	}
}
