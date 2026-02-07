// Package wal implements a Write-Ahead Log for crash recovery in witnessd.
//
// The WAL bridges high-frequency RAM capture and the 60-second checkpoint cycle.
// On crash, RAM buffer is lost (max 100ms of data) but WAL entries survive and
// are replayed on recovery.
//
// Patent Pending: USPTO Application No. 19/460,364
package wal

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Version and magic constants
const (
	Version    = 1
	Magic      = "WWAL"
	HeaderSize = 64
)

// Entry types
type EntryType uint8

const (
	EntryKeystrokeBatch EntryType = 1 // Batch of keystroke events
	EntryDocumentHash   EntryType = 2 // Document state snapshot
	EntryJitterSample   EntryType = 3 // Jitter seal sample
	EntryHeartbeat      EntryType = 4 // Periodic heartbeat marker
	EntrySessionStart   EntryType = 5 // Session initialization
	EntrySessionEnd     EntryType = 6 // Clean session termination
	EntryCheckpoint     EntryType = 7 // Checkpoint committed to MMR
)

// Errors
var (
	ErrInvalidMagic     = errors.New("wal: invalid magic number")
	ErrInvalidVersion   = errors.New("wal: unsupported version")
	ErrCorruptedEntry   = errors.New("wal: corrupted entry (CRC mismatch)")
	ErrBrokenChain      = errors.New("wal: broken hash chain")
	ErrInvalidHMAC      = errors.New("wal: HMAC verification failed")
	ErrWALClosed        = errors.New("wal: log is closed")
	ErrSequenceGap      = errors.New("wal: sequence number gap detected")
)

// Header is the WAL file header.
type Header struct {
	Magic             [4]byte
	Version           uint32
	SessionID         [32]byte
	CreatedAt         int64
	LastCheckpointSeq uint64
	Reserved          [8]byte
}

// Entry is a single WAL entry.
type Entry struct {
	// Length of the entire entry (for seeking)
	Length uint32

	// Monotonic sequence number
	Sequence uint64

	// Entry timestamp (UnixNano)
	Timestamp int64

	// Entry type discriminator
	Type EntryType

	// Type-specific payload
	Payload []byte

	// Hash of previous entry (chain link)
	PrevHash [32]byte

	// HMAC-SHA256 for integrity verification
	HMAC [32]byte

	// CRC32 for corruption detection
	CRC32 uint32
}

// WAL is a write-ahead log for crash recovery.
type WAL struct {
	mu sync.Mutex

	path      string
	file      *os.File
	sessionID [32]byte
	hmacKey   []byte

	nextSequence uint64
	lastHash     [32]byte
	closed       bool

	// Stats
	entryCount uint64
	byteCount  int64
}

// Open opens or creates a WAL file.
func Open(path string, sessionID [32]byte, hmacKey []byte) (*WAL, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create wal directory: %w", err)
	}

	// Try to open existing file
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, fmt.Errorf("open wal file: %w", err)
	}

	w := &WAL{
		path:      path,
		file:      file,
		sessionID: sessionID,
		hmacKey:   hmacKey,
	}

	// Check if file has content
	stat, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("stat wal file: %w", err)
	}

	if stat.Size() == 0 {
		// New file - write header
		if err := w.writeHeader(); err != nil {
			file.Close()
			return nil, fmt.Errorf("write header: %w", err)
		}
		w.byteCount = HeaderSize
		// Seek to end of header for appending
		if _, err := file.Seek(HeaderSize, 0); err != nil {
			file.Close()
			return nil, fmt.Errorf("seek after header: %w", err)
		}
	} else {
		// Existing file - read and validate header
		if err := w.readHeader(); err != nil {
			file.Close()
			return nil, fmt.Errorf("read header: %w", err)
		}

		// Scan to find last entry
		if err := w.scanToEnd(); err != nil {
			file.Close()
			return nil, fmt.Errorf("scan wal: %w", err)
		}
	}

	return w, nil
}

// writeHeader writes the WAL header to a new file.
func (w *WAL) writeHeader() error {
	header := Header{
		Version:   Version,
		SessionID: w.sessionID,
		CreatedAt: time.Now().UnixNano(),
	}
	copy(header.Magic[:], Magic)

	buf := make([]byte, HeaderSize)
	copy(buf[0:4], header.Magic[:])
	binary.BigEndian.PutUint32(buf[4:8], header.Version)
	copy(buf[8:40], header.SessionID[:])
	binary.BigEndian.PutUint64(buf[40:48], uint64(header.CreatedAt))
	binary.BigEndian.PutUint64(buf[48:56], header.LastCheckpointSeq)
	// Reserved bytes 56-64 are zero

	if _, err := w.file.WriteAt(buf, 0); err != nil {
		return err
	}

	return w.file.Sync()
}

// readHeader reads and validates the WAL header.
func (w *WAL) readHeader() error {
	buf := make([]byte, HeaderSize)
	if _, err := w.file.ReadAt(buf, 0); err != nil {
		return err
	}

	// Validate magic
	if string(buf[0:4]) != Magic {
		return ErrInvalidMagic
	}

	// Validate version
	version := binary.BigEndian.Uint32(buf[4:8])
	if version != Version {
		return fmt.Errorf("%w: got %d, expected %d", ErrInvalidVersion, version, Version)
	}

	// Read session ID
	copy(w.sessionID[:], buf[8:40])

	return nil
}

// scanToEnd scans the WAL to find the last entry and set up state.
func (w *WAL) scanToEnd() error {
	// Seek past header
	offset := int64(HeaderSize)

	for {
		// Try to read entry length
		lenBuf := make([]byte, 4)
		_, err := w.file.ReadAt(lenBuf, offset)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		entryLen := binary.BigEndian.Uint32(lenBuf)
		if entryLen == 0 {
			break
		}

		// Read full entry
		entryBuf := make([]byte, entryLen)
		if _, err := w.file.ReadAt(entryBuf, offset); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		entry, err := deserializeEntry(entryBuf)
		if err != nil {
			// Corrupted entry - truncate here
			break
		}

		// Verify CRC
		if entry.CRC32 != computeEntryCRC(entry) {
			break
		}

		// Update state
		w.nextSequence = entry.Sequence + 1
		w.lastHash = entry.Hash()
		w.entryCount++

		offset += int64(entryLen)
	}

	// Position file at end for appending
	w.byteCount = offset
	if _, err := w.file.Seek(offset, 0); err != nil {
		return err
	}

	return nil
}

// Append adds a new entry to the WAL.
func (w *WAL) Append(entryType EntryType, payload []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return ErrWALClosed
	}

	entry := &Entry{
		Sequence:  w.nextSequence,
		Timestamp: time.Now().UnixNano(),
		Type:      entryType,
		Payload:   payload,
		PrevHash:  w.lastHash,
	}

	// Compute HMAC
	entry.HMAC = w.computeHMAC(entry)

	// Compute CRC
	entry.CRC32 = computeEntryCRC(entry)

	// Serialize
	data := serializeEntry(entry)
	entry.Length = uint32(len(data))

	// Update length in serialized data
	binary.BigEndian.PutUint32(data[0:4], entry.Length)

	// Write to file
	if _, err := w.file.Write(data); err != nil {
		return fmt.Errorf("write entry: %w", err)
	}

	// Sync to disk
	if err := w.file.Sync(); err != nil {
		return fmt.Errorf("sync entry: %w", err)
	}

	// Update state
	w.lastHash = entry.Hash()
	w.nextSequence++
	w.entryCount++
	w.byteCount += int64(len(data))

	return nil
}

// ReadAll reads all entries from the WAL.
func (w *WAL) ReadAll() ([]Entry, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.readEntriesFrom(0)
}

// ReadAfter reads entries with sequence > afterSeq.
func (w *WAL) ReadAfter(afterSeq uint64) ([]Entry, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	entries, err := w.readEntriesFrom(0)
	if err != nil {
		return nil, err
	}

	// Filter to entries after the given sequence
	var result []Entry
	for _, e := range entries {
		if e.Sequence > afterSeq {
			result = append(result, e)
		}
	}

	return result, nil
}

// readEntriesFrom reads all entries starting from a given offset.
func (w *WAL) readEntriesFrom(startSeq uint64) ([]Entry, error) {
	var entries []Entry

	offset := int64(HeaderSize)
	var prevHash [32]byte

	for {
		// Read entry length
		lenBuf := make([]byte, 4)
		_, err := w.file.ReadAt(lenBuf, offset)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		entryLen := binary.BigEndian.Uint32(lenBuf)
		if entryLen == 0 {
			break
		}

		// Read full entry
		entryBuf := make([]byte, entryLen)
		if _, err := w.file.ReadAt(entryBuf, offset); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

		entry, err := deserializeEntry(entryBuf)
		if err != nil {
			return nil, fmt.Errorf("deserialize entry at offset %d: %w", offset, err)
		}

		// Verify CRC
		if entry.CRC32 != computeEntryCRC(entry) {
			return nil, fmt.Errorf("entry %d: %w", entry.Sequence, ErrCorruptedEntry)
		}

		// Verify hash chain (skip for first entry)
		if entry.Sequence > 0 && entry.PrevHash != prevHash {
			return nil, fmt.Errorf("entry %d: %w", entry.Sequence, ErrBrokenChain)
		}

		if entry.Sequence >= startSeq {
			entries = append(entries, *entry)
		}

		prevHash = entry.Hash()
		offset += int64(entryLen)
	}

	return entries, nil
}

// VerifyHMAC verifies an entry's HMAC.
func (w *WAL) VerifyHMAC(entry *Entry) bool {
	expected := w.computeHMAC(entry)
	return hmac.Equal(entry.HMAC[:], expected[:])
}

// computeHMAC computes the HMAC for an entry.
func (w *WAL) computeHMAC(entry *Entry) [32]byte {
	h := hmac.New(sha256.New, w.hmacKey)

	var seqBuf [8]byte
	binary.BigEndian.PutUint64(seqBuf[:], entry.Sequence)
	h.Write(seqBuf[:])

	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], uint64(entry.Timestamp))
	h.Write(tsBuf[:])

	h.Write([]byte{byte(entry.Type)})
	h.Write(entry.Payload)
	h.Write(entry.PrevHash[:])

	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// Hash computes the hash of an entry (for chain linking).
func (e *Entry) Hash() [32]byte {
	h := sha256.New()

	var seqBuf [8]byte
	binary.BigEndian.PutUint64(seqBuf[:], e.Sequence)
	h.Write(seqBuf[:])

	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], uint64(e.Timestamp))
	h.Write(tsBuf[:])

	h.Write([]byte{byte(e.Type)})
	h.Write(e.Payload)
	h.Write(e.PrevHash[:])

	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// computeEntryCRC computes the CRC32 for corruption detection.
func computeEntryCRC(entry *Entry) uint32 {
	crc := crc32.NewIEEE()

	var seqBuf [8]byte
	binary.BigEndian.PutUint64(seqBuf[:], entry.Sequence)
	crc.Write(seqBuf[:])

	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], uint64(entry.Timestamp))
	crc.Write(tsBuf[:])

	crc.Write([]byte{byte(entry.Type)})
	crc.Write(entry.Payload)
	crc.Write(entry.PrevHash[:])
	crc.Write(entry.HMAC[:])

	return crc.Sum32()
}

// serializeEntry serializes an entry to bytes.
func serializeEntry(entry *Entry) []byte {
	// Calculate size
	size := 4 + // length
		8 + // sequence
		8 + // timestamp
		1 + // type
		4 + // payload length
		len(entry.Payload) +
		32 + // prev hash
		32 + // hmac
		4 // crc

	buf := make([]byte, size)
	offset := 0

	// Length (placeholder, filled in later)
	offset += 4

	// Sequence
	binary.BigEndian.PutUint64(buf[offset:], entry.Sequence)
	offset += 8

	// Timestamp
	binary.BigEndian.PutUint64(buf[offset:], uint64(entry.Timestamp))
	offset += 8

	// Type
	buf[offset] = byte(entry.Type)
	offset++

	// Payload length + payload
	binary.BigEndian.PutUint32(buf[offset:], uint32(len(entry.Payload)))
	offset += 4
	copy(buf[offset:], entry.Payload)
	offset += len(entry.Payload)

	// Prev hash
	copy(buf[offset:], entry.PrevHash[:])
	offset += 32

	// HMAC
	copy(buf[offset:], entry.HMAC[:])
	offset += 32

	// CRC
	binary.BigEndian.PutUint32(buf[offset:], entry.CRC32)

	return buf
}

// deserializeEntry deserializes an entry from bytes.
func deserializeEntry(data []byte) (*Entry, error) {
	if len(data) < 4+8+8+1+4+32+32+4 {
		return nil, errors.New("entry too short")
	}

	entry := &Entry{}
	offset := 0

	// Length
	entry.Length = binary.BigEndian.Uint32(data[offset:])
	offset += 4

	// Sequence
	entry.Sequence = binary.BigEndian.Uint64(data[offset:])
	offset += 8

	// Timestamp
	entry.Timestamp = int64(binary.BigEndian.Uint64(data[offset:]))
	offset += 8

	// Type
	entry.Type = EntryType(data[offset])
	offset++

	// Payload
	payloadLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4

	if len(data) < offset+int(payloadLen)+32+32+4 {
		return nil, errors.New("entry truncated")
	}

	entry.Payload = make([]byte, payloadLen)
	copy(entry.Payload, data[offset:offset+int(payloadLen)])
	offset += int(payloadLen)

	// Prev hash
	copy(entry.PrevHash[:], data[offset:offset+32])
	offset += 32

	// HMAC
	copy(entry.HMAC[:], data[offset:offset+32])
	offset += 32

	// CRC
	entry.CRC32 = binary.BigEndian.Uint32(data[offset:])

	return entry, nil
}

// Truncate removes entries before the given checkpoint sequence.
func (w *WAL) Truncate(beforeSeq uint64) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Read all entries
	entries, err := w.readEntriesFrom(beforeSeq)
	if err != nil {
		return err
	}

	// Create new WAL file
	newPath := w.path + ".new"
	newFile, err := os.Create(newPath)
	if err != nil {
		return err
	}

	// Write header
	header := Header{
		Version:           Version,
		SessionID:         w.sessionID,
		CreatedAt:         time.Now().UnixNano(),
		LastCheckpointSeq: beforeSeq,
	}
	copy(header.Magic[:], Magic)

	buf := make([]byte, HeaderSize)
	copy(buf[0:4], header.Magic[:])
	binary.BigEndian.PutUint32(buf[4:8], header.Version)
	copy(buf[8:40], header.SessionID[:])
	binary.BigEndian.PutUint64(buf[40:48], uint64(header.CreatedAt))
	binary.BigEndian.PutUint64(buf[48:56], header.LastCheckpointSeq)

	if _, err := newFile.Write(buf); err != nil {
		newFile.Close()
		os.Remove(newPath)
		return err
	}

	// Write retained entries
	var lastHash [32]byte
	for _, entry := range entries {
		entry.PrevHash = lastHash
		entry.HMAC = w.computeHMAC(&entry)
		entry.CRC32 = computeEntryCRC(&entry)
		data := serializeEntry(&entry)
		binary.BigEndian.PutUint32(data[0:4], uint32(len(data)))

		if _, err := newFile.Write(data); err != nil {
			newFile.Close()
			os.Remove(newPath)
			return err
		}

		lastHash = entry.Hash()
	}

	if err := newFile.Sync(); err != nil {
		newFile.Close()
		os.Remove(newPath)
		return err
	}

	newFile.Close()

	// Close old file
	w.file.Close()

	// Atomic rename
	if err := os.Rename(newPath, w.path); err != nil {
		return err
	}

	// Reopen
	w.file, err = os.OpenFile(w.path, os.O_RDWR, 0600)
	if err != nil {
		return err
	}

	// Update state
	if len(entries) > 0 {
		w.nextSequence = entries[len(entries)-1].Sequence + 1
		w.lastHash = entries[len(entries)-1].Hash()
	} else {
		w.nextSequence = beforeSeq
		w.lastHash = [32]byte{}
	}
	w.entryCount = uint64(len(entries))

	return nil
}

// Size returns the current WAL file size in bytes.
func (w *WAL) Size() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.byteCount
}

// EntryCount returns the number of entries in the WAL.
func (w *WAL) EntryCount() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.entryCount
}

// LastSequence returns the last sequence number written.
func (w *WAL) LastSequence() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.nextSequence == 0 {
		return 0
	}
	return w.nextSequence - 1
}

// Close closes the WAL file.
func (w *WAL) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return nil
	}

	w.closed = true
	return w.file.Close()
}

// Path returns the WAL file path.
func (w *WAL) Path() string {
	return w.path
}

// Exists checks if a WAL file exists at the given path.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
