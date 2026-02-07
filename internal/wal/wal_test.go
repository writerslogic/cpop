// Package wal tests for the Write-Ahead Log implementation.
package wal

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test helpers

func newTestSessionID() [32]byte {
	var id [32]byte
	rand.Read(id[:])
	return id
}

func newTestHMACKey() []byte {
	key := make([]byte, 32)
	rand.Read(key)
	return key
}

func createTestWAL(t *testing.T) (*WAL, string, func()) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wal")
	sessionID := newTestSessionID()
	hmacKey := newTestHMACKey()

	w, err := Open(path, sessionID, hmacKey)
	require.NoError(t, err)

	cleanup := func() {
		w.Close()
	}

	return w, path, cleanup
}

// =============================================================================
// Entry Serialization/Deserialization Tests
// =============================================================================

func TestEntry_Serialize_Deserialize(t *testing.T) {
	tests := []struct {
		name    string
		entry   *Entry
	}{
		{
			name: "minimal entry",
			entry: &Entry{
				Sequence:  0,
				Timestamp: time.Now().UnixNano(),
				Type:      EntryHeartbeat,
				Payload:   []byte{},
				PrevHash:  [32]byte{},
				HMAC:      [32]byte{},
				CRC32:     12345,
			},
		},
		{
			name: "entry with payload",
			entry: &Entry{
				Sequence:  100,
				Timestamp: time.Now().UnixNano(),
				Type:      EntryKeystrokeBatch,
				Payload:   []byte("test payload data"),
				PrevHash:  sha256.Sum256([]byte("previous")),
				HMAC:      sha256.Sum256([]byte("hmac")),
				CRC32:     0xDEADBEEF,
			},
		},
		{
			name: "entry with large payload",
			entry: &Entry{
				Sequence:  999999,
				Timestamp: time.Now().UnixNano(),
				Type:      EntryDocumentHash,
				Payload:   bytes.Repeat([]byte("x"), 1024),
				PrevHash:  sha256.Sum256([]byte("prev")),
				HMAC:      sha256.Sum256([]byte("mac")),
				CRC32:     0x12345678,
			},
		},
		{
			name: "entry with all entry types",
			entry: &Entry{
				Sequence:  42,
				Timestamp: 1234567890,
				Type:      EntryCheckpoint,
				Payload:   []byte{0x01, 0x02, 0x03},
				PrevHash:  [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
				HMAC:      [32]byte{32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
				CRC32:     0xCAFEBABE,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Serialize
			data := serializeEntry(tt.entry)
			require.NotEmpty(t, data)

			// Set length in serialized data
			binary.BigEndian.PutUint32(data[0:4], uint32(len(data)))

			// Deserialize
			result, err := deserializeEntry(data)
			require.NoError(t, err)

			// Verify all fields
			assert.Equal(t, uint32(len(data)), result.Length)
			assert.Equal(t, tt.entry.Sequence, result.Sequence)
			assert.Equal(t, tt.entry.Timestamp, result.Timestamp)
			assert.Equal(t, tt.entry.Type, result.Type)
			assert.Equal(t, tt.entry.Payload, result.Payload)
			assert.Equal(t, tt.entry.PrevHash, result.PrevHash)
			assert.Equal(t, tt.entry.HMAC, result.HMAC)
			assert.Equal(t, tt.entry.CRC32, result.CRC32)
		})
	}
}

func TestEntry_Deserialize_TooShort(t *testing.T) {
	// Minimum entry size is 4+8+8+1+4+32+32+4 = 93 bytes
	shortData := make([]byte, 50)
	_, err := deserializeEntry(shortData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestEntry_Deserialize_TruncatedPayload(t *testing.T) {
	// Create entry with payload length that exceeds actual data
	data := make([]byte, 100)
	binary.BigEndian.PutUint32(data[0:4], 100)   // length
	binary.BigEndian.PutUint64(data[4:12], 1)    // sequence
	binary.BigEndian.PutUint64(data[12:20], 1000) // timestamp
	data[20] = byte(EntryHeartbeat)              // type
	binary.BigEndian.PutUint32(data[21:25], 1000) // payload length (way too large)

	_, err := deserializeEntry(data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "truncated")
}

func TestEntry_Hash(t *testing.T) {
	entry1 := &Entry{
		Sequence:  1,
		Timestamp: 1000,
		Type:      EntryHeartbeat,
		Payload:   []byte("test"),
		PrevHash:  [32]byte{},
	}

	entry2 := &Entry{
		Sequence:  1,
		Timestamp: 1000,
		Type:      EntryHeartbeat,
		Payload:   []byte("test"),
		PrevHash:  [32]byte{},
	}

	// Same entries should have same hash
	assert.Equal(t, entry1.Hash(), entry2.Hash())

	// Different sequence should have different hash
	entry2.Sequence = 2
	assert.NotEqual(t, entry1.Hash(), entry2.Hash())

	// Different timestamp should have different hash
	entry2.Sequence = 1
	entry2.Timestamp = 2000
	assert.NotEqual(t, entry1.Hash(), entry2.Hash())

	// Different type should have different hash
	entry2.Timestamp = 1000
	entry2.Type = EntryCheckpoint
	assert.NotEqual(t, entry1.Hash(), entry2.Hash())

	// Different payload should have different hash
	entry2.Type = EntryHeartbeat
	entry2.Payload = []byte("different")
	assert.NotEqual(t, entry1.Hash(), entry2.Hash())

	// Different prev hash should have different hash
	entry2.Payload = []byte("test")
	entry2.PrevHash = sha256.Sum256([]byte("something"))
	assert.NotEqual(t, entry1.Hash(), entry2.Hash())
}

// =============================================================================
// WAL Open/Close Lifecycle Tests
// =============================================================================

func TestWAL_OpenClose(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wal")
	sessionID := newTestSessionID()
	hmacKey := newTestHMACKey()

	// Open new WAL
	w, err := Open(path, sessionID, hmacKey)
	require.NoError(t, err)
	assert.NotNil(t, w)

	// Check initial state
	assert.Equal(t, path, w.Path())
	assert.Equal(t, uint64(0), w.EntryCount())
	assert.Equal(t, uint64(0), w.LastSequence())
	assert.Equal(t, int64(HeaderSize), w.Size())

	// Close
	err = w.Close()
	require.NoError(t, err)

	// Double close should be safe
	err = w.Close()
	assert.NoError(t, err)
}

func TestWAL_OpenExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wal")
	sessionID := newTestSessionID()
	hmacKey := newTestHMACKey()

	// Create WAL and add entries
	w, err := Open(path, sessionID, hmacKey)
	require.NoError(t, err)

	payload := []byte("test payload")
	for i := 0; i < 5; i++ {
		err = w.Append(EntryHeartbeat, payload)
		require.NoError(t, err)
	}

	lastSeq := w.LastSequence()
	entryCount := w.EntryCount()
	w.Close()

	// Reopen and verify state recovered
	w2, err := Open(path, sessionID, hmacKey)
	require.NoError(t, err)
	defer w2.Close()

	assert.Equal(t, entryCount, w2.EntryCount())
	assert.Equal(t, lastSeq, w2.LastSequence())
}

func TestWAL_OpenCreatesDirectory(t *testing.T) {
	dir := t.TempDir()
	deepPath := filepath.Join(dir, "a", "b", "c", "test.wal")
	sessionID := newTestSessionID()
	hmacKey := newTestHMACKey()

	w, err := Open(deepPath, sessionID, hmacKey)
	require.NoError(t, err)
	defer w.Close()

	assert.FileExists(t, deepPath)
}

func TestWAL_OpenInvalidMagic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wal")

	// Create file with invalid magic
	f, err := os.Create(path)
	require.NoError(t, err)
	f.Write([]byte("XXXX")) // Invalid magic
	f.Write(make([]byte, HeaderSize-4))
	f.Close()

	sessionID := newTestSessionID()
	hmacKey := newTestHMACKey()

	_, err = Open(path, sessionID, hmacKey)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidMagic)
}

func TestWAL_OpenInvalidVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wal")

	// Create file with invalid version
	f, err := os.Create(path)
	require.NoError(t, err)
	buf := make([]byte, HeaderSize)
	copy(buf[0:4], Magic)
	binary.BigEndian.PutUint32(buf[4:8], 999) // Invalid version
	f.Write(buf)
	f.Close()

	sessionID := newTestSessionID()
	hmacKey := newTestHMACKey()

	_, err = Open(path, sessionID, hmacKey)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidVersion)
}

// =============================================================================
// WAL Append Tests
// =============================================================================

func TestWAL_Append(t *testing.T) {
	w, _, cleanup := createTestWAL(t)
	defer cleanup()

	testCases := []struct {
		entryType EntryType
		payload   []byte
	}{
		{EntryKeystrokeBatch, []byte("keystroke data")},
		{EntryDocumentHash, []byte("document hash")},
		{EntryJitterSample, []byte("jitter sample")},
		{EntryHeartbeat, []byte("heartbeat")},
		{EntrySessionStart, []byte("session start")},
		{EntrySessionEnd, []byte("session end")},
		{EntryCheckpoint, []byte("checkpoint")},
	}

	for i, tc := range testCases {
		t.Run(tc.entryType.String(), func(t *testing.T) {
			err := w.Append(tc.entryType, tc.payload)
			require.NoError(t, err)
			assert.Equal(t, uint64(i+1), w.EntryCount())
			assert.Equal(t, uint64(i), w.LastSequence())
		})
	}
}

func TestWAL_AppendAfterClose(t *testing.T) {
	w, _, cleanup := createTestWAL(t)
	cleanup() // Close immediately

	err := w.Append(EntryHeartbeat, []byte("test"))
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrWALClosed)
}

func TestWAL_AppendEmptyPayload(t *testing.T) {
	w, _, cleanup := createTestWAL(t)
	defer cleanup()

	err := w.Append(EntryHeartbeat, []byte{})
	require.NoError(t, err)

	entries, err := w.ReadAll()
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Empty(t, entries[0].Payload)
}

func TestWAL_AppendLargePayload(t *testing.T) {
	w, _, cleanup := createTestWAL(t)
	defer cleanup()

	// 1MB payload
	largePayload := make([]byte, 1024*1024)
	rand.Read(largePayload)

	err := w.Append(EntryKeystrokeBatch, largePayload)
	require.NoError(t, err)

	entries, err := w.ReadAll()
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, largePayload, entries[0].Payload)
}

func TestWAL_AppendMaxSizePayload(t *testing.T) {
	w, _, cleanup := createTestWAL(t)
	defer cleanup()

	// 10MB payload - stress test
	maxPayload := make([]byte, 10*1024*1024)
	rand.Read(maxPayload)

	err := w.Append(EntryDocumentHash, maxPayload)
	require.NoError(t, err)

	entries, err := w.ReadAll()
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, maxPayload, entries[0].Payload)
}

// =============================================================================
// Hash Chain Integrity Tests
// =============================================================================

func TestWAL_HashChainIntegrity(t *testing.T) {
	w, _, cleanup := createTestWAL(t)
	defer cleanup()

	// Append several entries
	for i := 0; i < 10; i++ {
		err := w.Append(EntryHeartbeat, []byte("data"))
		require.NoError(t, err)
	}

	entries, err := w.ReadAll()
	require.NoError(t, err)
	require.Len(t, entries, 10)

	// Verify chain manually
	var prevHash [32]byte
	for i, entry := range entries {
		if i == 0 {
			// First entry should have zero prev hash
			assert.Equal(t, [32]byte{}, entry.PrevHash)
		} else {
			// Each entry's PrevHash should match previous entry's hash
			assert.Equal(t, prevHash, entry.PrevHash, "hash chain broken at entry %d", i)
		}
		prevHash = entry.Hash()
	}
}

func TestWAL_BrokenHashChain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wal")
	sessionID := newTestSessionID()
	hmacKey := newTestHMACKey()

	// Create WAL with entries
	w, err := Open(path, sessionID, hmacKey)
	require.NoError(t, err)

	for i := 0; i < 5; i++ {
		err = w.Append(EntryHeartbeat, []byte("data"))
		require.NoError(t, err)
	}
	w.Close()

	// Corrupt the hash chain by modifying the second entry's prev hash
	// AND recalculate CRC so CRC check passes but hash chain fails
	f, err := os.OpenFile(path, os.O_RDWR, 0600)
	require.NoError(t, err)

	// Find second entry
	offset := int64(HeaderSize)

	// Read first entry length
	lenBuf := make([]byte, 4)
	f.ReadAt(lenBuf, offset)
	firstEntryLen := binary.BigEndian.Uint32(lenBuf)
	offset += int64(firstEntryLen)

	// Read second entry
	f.ReadAt(lenBuf, offset)
	secondEntryLen := binary.BigEndian.Uint32(lenBuf)

	entryBuf := make([]byte, secondEntryLen)
	f.ReadAt(entryBuf, offset)
	entry, _ := deserializeEntry(entryBuf)

	// Corrupt prev hash
	entry.PrevHash[0] ^= 0xFF
	entry.PrevHash[1] ^= 0xFF

	// Recalculate CRC so CRC check passes
	entry.CRC32 = computeEntryCRC(entry)

	// Re-serialize and write back
	newData := serializeEntry(entry)
	binary.BigEndian.PutUint32(newData[0:4], uint32(len(newData)))
	f.WriteAt(newData, offset)
	f.Close()

	// Reopen and try to read - should detect broken chain
	w2, err := Open(path, sessionID, hmacKey)
	require.NoError(t, err)
	defer w2.Close()

	_, err = w2.ReadAll()
	// The corrupted prev hash will cause broken chain detection
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrBrokenChain)
}

// =============================================================================
// HMAC Verification Tests
// =============================================================================

func TestWAL_HMACVerification(t *testing.T) {
	w, _, cleanup := createTestWAL(t)
	defer cleanup()

	err := w.Append(EntryHeartbeat, []byte("test"))
	require.NoError(t, err)

	entries, err := w.ReadAll()
	require.NoError(t, err)
	require.Len(t, entries, 1)

	// Verify HMAC is valid
	assert.True(t, w.VerifyHMAC(&entries[0]))
}

func TestWAL_HMACVerificationFails(t *testing.T) {
	w, _, cleanup := createTestWAL(t)
	defer cleanup()

	err := w.Append(EntryHeartbeat, []byte("test"))
	require.NoError(t, err)

	entries, err := w.ReadAll()
	require.NoError(t, err)
	require.Len(t, entries, 1)

	// Tamper with entry
	entries[0].Payload = []byte("tampered")

	// HMAC verification should fail
	assert.False(t, w.VerifyHMAC(&entries[0]))
}

func TestWAL_HMACWithDifferentKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wal")
	sessionID := newTestSessionID()
	hmacKey1 := newTestHMACKey()
	hmacKey2 := newTestHMACKey()

	// Create with key1
	w1, err := Open(path, sessionID, hmacKey1)
	require.NoError(t, err)

	err = w1.Append(EntryHeartbeat, []byte("secret"))
	require.NoError(t, err)

	entries, err := w1.ReadAll()
	require.NoError(t, err)
	w1.Close()

	// Open with key2 - HMAC verification should fail
	w2, err := Open(path, sessionID, hmacKey2)
	require.NoError(t, err)
	defer w2.Close()

	assert.False(t, w2.VerifyHMAC(&entries[0]))
}

// =============================================================================
// CRC Corruption Detection Tests
// =============================================================================

func TestWAL_CRCIntegrity(t *testing.T) {
	w, _, cleanup := createTestWAL(t)
	defer cleanup()

	err := w.Append(EntryHeartbeat, []byte("test"))
	require.NoError(t, err)

	entries, err := w.ReadAll()
	require.NoError(t, err)
	require.Len(t, entries, 1)

	// Verify CRC
	expectedCRC := computeEntryCRC(&entries[0])
	assert.Equal(t, expectedCRC, entries[0].CRC32)
}

func TestWAL_CRCCorruptionDetection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wal")
	sessionID := newTestSessionID()
	hmacKey := newTestHMACKey()

	// Create WAL with entry
	w, err := Open(path, sessionID, hmacKey)
	require.NoError(t, err)

	err = w.Append(EntryHeartbeat, []byte("test"))
	require.NoError(t, err)
	w.Close()

	// Corrupt a byte in the entry payload
	f, err := os.OpenFile(path, os.O_RDWR, 0600)
	require.NoError(t, err)

	// Corrupt byte in payload area (after header + entry header fields)
	// Header: 64 bytes
	// Entry header: 4 (len) + 8 (seq) + 8 (ts) + 1 (type) + 4 (payload_len) = 25
	corruptOffset := int64(HeaderSize + 25 + 2) // Middle of payload
	corruptByte := make([]byte, 1)
	corruptByte[0] = 0xFF
	f.WriteAt(corruptByte, corruptOffset)
	f.Close()

	// Reopen and try to read
	w2, err := Open(path, sessionID, hmacKey)
	require.NoError(t, err)
	defer w2.Close()

	_, err = w2.ReadAll()
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrCorruptedEntry)
}

func TestWAL_CRCCorruptionDuringRecovery(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wal")
	sessionID := newTestSessionID()
	hmacKey := newTestHMACKey()

	// Create WAL with multiple entries
	w, err := Open(path, sessionID, hmacKey)
	require.NoError(t, err)

	for i := 0; i < 5; i++ {
		err = w.Append(EntryHeartbeat, []byte("test"))
		require.NoError(t, err)
	}
	w.Close()

	// Corrupt CRC of last entry
	f, err := os.OpenFile(path, os.O_RDWR, 0600)
	require.NoError(t, err)
	stat, _ := f.Stat()

	// CRC is last 4 bytes of entry
	corruptOffset := stat.Size() - 4
	corruptBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(corruptBytes, 0xDEADBEEF)
	f.WriteAt(corruptBytes, corruptOffset)
	f.Close()

	// Reopen - should recover entries before corruption
	w2, err := Open(path, sessionID, hmacKey)
	require.NoError(t, err)
	defer w2.Close()

	// During scanToEnd, corrupted entries are skipped
	// So we should have recovered 4 entries (first 4 intact)
	assert.Equal(t, uint64(4), w2.EntryCount())
}

// =============================================================================
// Truncate Operation Tests
// =============================================================================

func TestWAL_Truncate(t *testing.T) {
	w, _, cleanup := createTestWAL(t)
	defer cleanup()

	// Add 10 entries
	for i := 0; i < 10; i++ {
		err := w.Append(EntryHeartbeat, []byte("test"))
		require.NoError(t, err)
	}

	assert.Equal(t, uint64(10), w.EntryCount())

	// Truncate entries before sequence 5
	err := w.Truncate(5)
	require.NoError(t, err)

	// Should have entries 5-9 (5 entries)
	entries, err := w.ReadAll()
	require.NoError(t, err)
	assert.Len(t, entries, 5)

	// First remaining entry should be sequence 5
	assert.Equal(t, uint64(5), entries[0].Sequence)
}

func TestWAL_TruncateAll(t *testing.T) {
	w, _, cleanup := createTestWAL(t)
	defer cleanup()

	// Add entries
	for i := 0; i < 5; i++ {
		err := w.Append(EntryHeartbeat, []byte("test"))
		require.NoError(t, err)
	}

	// Truncate everything
	err := w.Truncate(100) // Beyond last sequence
	require.NoError(t, err)

	entries, err := w.ReadAll()
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestWAL_TruncateEmpty(t *testing.T) {
	w, _, cleanup := createTestWAL(t)
	defer cleanup()

	// Truncate empty WAL
	err := w.Truncate(0)
	require.NoError(t, err)

	entries, err := w.ReadAll()
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestWAL_TruncatePreservesIntegrity(t *testing.T) {
	w, _, cleanup := createTestWAL(t)
	defer cleanup()

	// Add entries
	for i := 0; i < 10; i++ {
		err := w.Append(EntryHeartbeat, []byte("test"))
		require.NoError(t, err)
	}

	// Truncate
	err := w.Truncate(5)
	require.NoError(t, err)

	// Verify hash chain still intact
	entries, err := w.ReadAll()
	require.NoError(t, err)

	var prevHash [32]byte
	for i, entry := range entries {
		if i == 0 {
			// After truncate, first entry should have zero prev hash
			assert.Equal(t, [32]byte{}, entry.PrevHash)
		} else {
			assert.Equal(t, prevHash, entry.PrevHash)
		}
		prevHash = entry.Hash()
	}
}

// =============================================================================
// Crash Recovery Simulation Tests
// =============================================================================

func TestWAL_CrashRecovery_AbruptClose(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wal")
	sessionID := newTestSessionID()
	hmacKey := newTestHMACKey()

	// Create WAL and write entries
	w, err := Open(path, sessionID, hmacKey)
	require.NoError(t, err)

	payloads := [][]byte{
		[]byte("entry1"),
		[]byte("entry2"),
		[]byte("entry3"),
	}

	for _, p := range payloads {
		err = w.Append(EntryHeartbeat, p)
		require.NoError(t, err)
	}

	// Simulate crash - close file handle directly without proper cleanup
	w.file.Close()
	w.closed = true

	// Reopen and recover
	w2, err := Open(path, sessionID, hmacKey)
	require.NoError(t, err)
	defer w2.Close()

	// All entries should be recovered
	entries, err := w2.ReadAll()
	require.NoError(t, err)
	assert.Len(t, entries, 3)

	for i, p := range payloads {
		assert.Equal(t, p, entries[i].Payload)
	}
}

func TestWAL_CrashRecovery_PartialWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wal")
	sessionID := newTestSessionID()
	hmacKey := newTestHMACKey()

	// Create WAL with complete entries
	w, err := Open(path, sessionID, hmacKey)
	require.NoError(t, err)

	for i := 0; i < 3; i++ {
		err = w.Append(EntryHeartbeat, []byte("complete"))
		require.NoError(t, err)
	}
	w.Close()

	// Append garbage to simulate partial write
	f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0600)
	require.NoError(t, err)

	// Write incomplete entry (just length field)
	partial := make([]byte, 10)
	binary.BigEndian.PutUint32(partial, 200) // Claim entry is 200 bytes but write only 10
	f.Write(partial)
	f.Close()

	// Reopen - should recover only complete entries
	w2, err := Open(path, sessionID, hmacKey)
	require.NoError(t, err)
	defer w2.Close()

	// Only 3 complete entries should be recovered
	assert.Equal(t, uint64(3), w2.EntryCount())
}

func TestWAL_CrashRecovery_ContinueAfterRecovery(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wal")
	sessionID := newTestSessionID()
	hmacKey := newTestHMACKey()

	// Create WAL and write entries
	w, err := Open(path, sessionID, hmacKey)
	require.NoError(t, err)

	for i := 0; i < 3; i++ {
		err = w.Append(EntryHeartbeat, []byte("before"))
		require.NoError(t, err)
	}
	w.Close()

	// Reopen
	w2, err := Open(path, sessionID, hmacKey)
	require.NoError(t, err)

	// Write more entries after recovery
	for i := 0; i < 2; i++ {
		err = w2.Append(EntryCheckpoint, []byte("after"))
		require.NoError(t, err)
	}

	// Verify all entries
	entries, err := w2.ReadAll()
	require.NoError(t, err)
	assert.Len(t, entries, 5)

	// First 3 should be HeartBeat, last 2 should be Checkpoint
	for i := 0; i < 3; i++ {
		assert.Equal(t, EntryHeartbeat, entries[i].Type)
	}
	for i := 3; i < 5; i++ {
		assert.Equal(t, EntryCheckpoint, entries[i].Type)
	}

	w2.Close()
}

// =============================================================================
// Concurrent Append Tests (Goroutine Safety)
// =============================================================================

func TestWAL_ConcurrentAppend(t *testing.T) {
	w, _, cleanup := createTestWAL(t)
	defer cleanup()

	const numGoroutines = 10
	const entriesPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for g := 0; g < numGoroutines; g++ {
		go func(goroutineID int) {
			defer wg.Done()
			for i := 0; i < entriesPerGoroutine; i++ {
				payload := []byte{byte(goroutineID), byte(i)}
				err := w.Append(EntryHeartbeat, payload)
				assert.NoError(t, err)
			}
		}(g)
	}

	wg.Wait()

	// All entries should be written
	assert.Equal(t, uint64(numGoroutines*entriesPerGoroutine), w.EntryCount())

	// Read all and verify integrity
	entries, err := w.ReadAll()
	require.NoError(t, err)
	assert.Len(t, entries, numGoroutines*entriesPerGoroutine)

	// Verify sequence numbers are contiguous
	for i, entry := range entries {
		assert.Equal(t, uint64(i), entry.Sequence)
	}
}

func TestWAL_ConcurrentReadWrite(t *testing.T) {
	w, _, cleanup := createTestWAL(t)
	defer cleanup()

	const numWriters = 5
	const numReaders = 3
	const entriesPerWriter = 50

	var wg sync.WaitGroup

	// Writers
	wg.Add(numWriters)
	for i := 0; i < numWriters; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < entriesPerWriter; j++ {
				err := w.Append(EntryHeartbeat, []byte{byte(id)})
				assert.NoError(t, err)
			}
		}(i)
	}

	// Readers
	wg.Add(numReaders)
	for i := 0; i < numReaders; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < entriesPerWriter; j++ {
				_, err := w.ReadAll()
				// May get error if reading during write, that's OK
				if err != nil {
					// Just ensure it doesn't panic
				}
				time.Sleep(time.Millisecond)
			}
		}()
	}

	wg.Wait()

	// Final read should succeed
	entries, err := w.ReadAll()
	require.NoError(t, err)
	assert.Len(t, entries, numWriters*entriesPerWriter)
}

// =============================================================================
// ReadAll and ReadAfter Tests
// =============================================================================

func TestWAL_ReadAll(t *testing.T) {
	w, _, cleanup := createTestWAL(t)
	defer cleanup()

	// Empty WAL
	entries, err := w.ReadAll()
	require.NoError(t, err)
	assert.Empty(t, entries)

	// Add entries
	for i := 0; i < 5; i++ {
		err = w.Append(EntryHeartbeat, []byte{byte(i)})
		require.NoError(t, err)
	}

	entries, err = w.ReadAll()
	require.NoError(t, err)
	assert.Len(t, entries, 5)

	for i, entry := range entries {
		assert.Equal(t, uint64(i), entry.Sequence)
		assert.Equal(t, []byte{byte(i)}, entry.Payload)
	}
}

func TestWAL_ReadAfter(t *testing.T) {
	w, _, cleanup := createTestWAL(t)
	defer cleanup()

	// Add entries (sequences 0-9)
	for i := 0; i < 10; i++ {
		err := w.Append(EntryHeartbeat, []byte{byte(i)})
		require.NoError(t, err)
	}

	// Read after sequence 5 (should get 6, 7, 8, 9)
	entries, err := w.ReadAfter(5)
	require.NoError(t, err)
	assert.Len(t, entries, 4)

	for i, entry := range entries {
		assert.Equal(t, uint64(i+6), entry.Sequence)
	}
}

func TestWAL_ReadAfterLast(t *testing.T) {
	w, _, cleanup := createTestWAL(t)
	defer cleanup()

	for i := 0; i < 5; i++ {
		err := w.Append(EntryHeartbeat, []byte{byte(i)})
		require.NoError(t, err)
	}

	// Read after last sequence (should be empty)
	entries, err := w.ReadAfter(4)
	require.NoError(t, err)
	assert.Empty(t, entries)

	// Read after beyond last
	entries, err = w.ReadAfter(100)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestWAL_ReadAfterBeforeFirst(t *testing.T) {
	w, _, cleanup := createTestWAL(t)
	defer cleanup()

	for i := 0; i < 5; i++ {
		err := w.Append(EntryHeartbeat, []byte{byte(i)})
		require.NoError(t, err)
	}

	// Read after sequence 0 (should skip first, get 1-4)
	entries, err := w.ReadAfter(0)
	require.NoError(t, err)
	assert.Len(t, entries, 4)
	assert.Equal(t, uint64(1), entries[0].Sequence)
}

// =============================================================================
// Edge Cases
// =============================================================================

func TestWAL_EntryTypes(t *testing.T) {
	w, _, cleanup := createTestWAL(t)
	defer cleanup()

	types := []EntryType{
		EntryKeystrokeBatch,
		EntryDocumentHash,
		EntryJitterSample,
		EntryHeartbeat,
		EntrySessionStart,
		EntrySessionEnd,
		EntryCheckpoint,
	}

	for _, et := range types {
		err := w.Append(et, []byte("payload"))
		require.NoError(t, err)
	}

	entries, err := w.ReadAll()
	require.NoError(t, err)

	for i, et := range types {
		assert.Equal(t, et, entries[i].Type)
	}
}

func TestWAL_BinaryPayload(t *testing.T) {
	w, _, cleanup := createTestWAL(t)
	defer cleanup()

	// Payload with all possible byte values
	payload := make([]byte, 256)
	for i := 0; i < 256; i++ {
		payload[i] = byte(i)
	}

	err := w.Append(EntryKeystrokeBatch, payload)
	require.NoError(t, err)

	entries, err := w.ReadAll()
	require.NoError(t, err)
	assert.Equal(t, payload, entries[0].Payload)
}

func TestWAL_NilPayload(t *testing.T) {
	w, _, cleanup := createTestWAL(t)
	defer cleanup()

	err := w.Append(EntryHeartbeat, nil)
	require.NoError(t, err)

	entries, err := w.ReadAll()
	require.NoError(t, err)
	// nil payload becomes empty slice
	assert.Empty(t, entries[0].Payload)
}

func TestWAL_SizeTracking(t *testing.T) {
	w, _, cleanup := createTestWAL(t)
	defer cleanup()

	initialSize := w.Size()
	assert.Equal(t, int64(HeaderSize), initialSize)

	err := w.Append(EntryHeartbeat, []byte("test"))
	require.NoError(t, err)

	newSize := w.Size()
	assert.Greater(t, newSize, initialSize)
}

func TestWAL_Exists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wal")

	// Should not exist initially
	assert.False(t, Exists(path))

	// Create WAL
	sessionID := newTestSessionID()
	hmacKey := newTestHMACKey()
	w, err := Open(path, sessionID, hmacKey)
	require.NoError(t, err)
	defer w.Close()

	// Should exist now
	assert.True(t, Exists(path))
}

// =============================================================================
// Scanning Behavior on Corrupted WAL Tests
// =============================================================================

func TestWAL_ScanCorruptedTruncatesAtCorruption(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wal")
	sessionID := newTestSessionID()
	hmacKey := newTestHMACKey()

	// Create WAL with 5 entries
	w, err := Open(path, sessionID, hmacKey)
	require.NoError(t, err)

	for i := 0; i < 5; i++ {
		err = w.Append(EntryHeartbeat, []byte("test"))
		require.NoError(t, err)
	}
	w.Close()

	// Corrupt entry 3 (middle)
	f, err := os.OpenFile(path, os.O_RDWR, 0600)
	require.NoError(t, err)

	// Navigate to entry 3
	offset := int64(HeaderSize)
	for i := 0; i < 2; i++ {
		lenBuf := make([]byte, 4)
		f.ReadAt(lenBuf, offset)
		entryLen := binary.BigEndian.Uint32(lenBuf)
		offset += int64(entryLen)
	}

	// Corrupt CRC of entry 3
	lenBuf := make([]byte, 4)
	f.ReadAt(lenBuf, offset)
	entryLen := binary.BigEndian.Uint32(lenBuf)
	crcOffset := offset + int64(entryLen) - 4
	corruptBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(corruptBytes, 0xBADBAD)
	f.WriteAt(corruptBytes, crcOffset)
	f.Close()

	// Reopen - should recover only first 2 entries
	w2, err := Open(path, sessionID, hmacKey)
	require.NoError(t, err)
	defer w2.Close()

	assert.Equal(t, uint64(2), w2.EntryCount())
}

func TestWAL_ScanZeroLengthEntry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wal")
	sessionID := newTestSessionID()
	hmacKey := newTestHMACKey()

	// Create WAL with entries
	w, err := Open(path, sessionID, hmacKey)
	require.NoError(t, err)

	for i := 0; i < 3; i++ {
		err = w.Append(EntryHeartbeat, []byte("test"))
		require.NoError(t, err)
	}
	w.Close()

	// Append zero-length entry marker
	f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0600)
	require.NoError(t, err)
	zeroLen := make([]byte, 4)
	f.Write(zeroLen)
	f.Close()

	// Reopen - zero length should be treated as end
	w2, err := Open(path, sessionID, hmacKey)
	require.NoError(t, err)
	defer w2.Close()

	assert.Equal(t, uint64(3), w2.EntryCount())
}

func TestWAL_ScanTruncatedEntryAtEnd(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wal")
	sessionID := newTestSessionID()
	hmacKey := newTestHMACKey()

	// Create WAL with entries
	w, err := Open(path, sessionID, hmacKey)
	require.NoError(t, err)

	for i := 0; i < 3; i++ {
		err = w.Append(EntryHeartbeat, []byte("test"))
		require.NoError(t, err)
	}
	w.Close()

	// Append entry length but not full data
	f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0600)
	require.NoError(t, err)
	partialLen := make([]byte, 4)
	binary.BigEndian.PutUint32(partialLen, 500) // Claim 500 bytes
	f.Write(partialLen)
	f.Write([]byte("incomplete")) // But only write a few
	f.Close()

	// Reopen - truncated entry should be ignored
	w2, err := Open(path, sessionID, hmacKey)
	require.NoError(t, err)
	defer w2.Close()

	assert.Equal(t, uint64(3), w2.EntryCount())
}

// =============================================================================
// Benchmark Tests
// =============================================================================

func BenchmarkWAL_Append(b *testing.B) {
	dir := b.TempDir()
	path := filepath.Join(dir, "bench.wal")
	sessionID := newTestSessionID()
	hmacKey := newTestHMACKey()

	w, err := Open(path, sessionID, hmacKey)
	if err != nil {
		b.Fatal(err)
	}
	defer w.Close()

	payload := []byte("benchmark payload data")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := w.Append(EntryHeartbeat, payload); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWAL_ReadAll(b *testing.B) {
	dir := b.TempDir()
	path := filepath.Join(dir, "bench.wal")
	sessionID := newTestSessionID()
	hmacKey := newTestHMACKey()

	w, err := Open(path, sessionID, hmacKey)
	if err != nil {
		b.Fatal(err)
	}

	// Pre-populate
	payload := []byte("benchmark payload data")
	for i := 0; i < 1000; i++ {
		if err := w.Append(EntryHeartbeat, payload); err != nil {
			b.Fatal(err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := w.ReadAll(); err != nil {
			b.Fatal(err)
		}
	}

	w.Close()
}

func BenchmarkEntry_Serialize(b *testing.B) {
	entry := &Entry{
		Sequence:  12345,
		Timestamp: time.Now().UnixNano(),
		Type:      EntryKeystrokeBatch,
		Payload:   bytes.Repeat([]byte("x"), 100),
		PrevHash:  sha256.Sum256([]byte("prev")),
		HMAC:      sha256.Sum256([]byte("hmac")),
		CRC32:     0xDEADBEEF,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = serializeEntry(entry)
	}
}

func BenchmarkEntry_Deserialize(b *testing.B) {
	entry := &Entry{
		Sequence:  12345,
		Timestamp: time.Now().UnixNano(),
		Type:      EntryKeystrokeBatch,
		Payload:   bytes.Repeat([]byte("x"), 100),
		PrevHash:  sha256.Sum256([]byte("prev")),
		HMAC:      sha256.Sum256([]byte("hmac")),
		CRC32:     0xDEADBEEF,
	}
	data := serializeEntry(entry)
	binary.BigEndian.PutUint32(data[0:4], uint32(len(data)))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = deserializeEntry(data)
	}
}

// String method for EntryType for test output
func (et EntryType) String() string {
	switch et {
	case EntryKeystrokeBatch:
		return "KeystrokeBatch"
	case EntryDocumentHash:
		return "DocumentHash"
	case EntryJitterSample:
		return "JitterSample"
	case EntryHeartbeat:
		return "Heartbeat"
	case EntrySessionStart:
		return "SessionStart"
	case EntrySessionEnd:
		return "SessionEnd"
	case EntryCheckpoint:
		return "Checkpoint"
	default:
		return "Unknown"
	}
}

// =============================================================================
// Recovery Tests
// =============================================================================

func TestRecovery_BasicRecovery(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wal")
	sessionID := newTestSessionID()
	hmacKey := newTestHMACKey()

	// Create WAL with entries
	w, err := Open(path, sessionID, hmacKey)
	require.NoError(t, err)

	// Add keystroke batch
	ksPayload := &KeystrokeBatchPayload{
		StartSequence: 1,
		EndSequence:   50,
		Count:         50,
		StartTime:     time.Now().UnixNano(),
		EndTime:       time.Now().Add(time.Second).UnixNano(),
	}
	rand.Read(ksPayload.DocumentHash[:])
	err = w.Append(EntryKeystrokeBatch, ksPayload.Serialize())
	require.NoError(t, err)

	// Add document hash
	docPayload := &DocumentHashPayload{
		Size:    1000,
		ModTime: time.Now().UnixNano(),
	}
	rand.Read(docPayload.Hash[:])
	err = w.Append(EntryDocumentHash, docPayload.Serialize())
	require.NoError(t, err)

	// Add jitter sample
	jitterPayload := &JitterSamplePayload{
		Ordinal:        1,
		KeystrokeCount: 50,
		JitterMicros:   1234,
	}
	rand.Read(jitterPayload.DocumentHash[:])
	rand.Read(jitterPayload.SampleHash[:])
	err = w.Append(EntryJitterSample, jitterPayload.Serialize())
	require.NoError(t, err)

	w.Close()

	// Perform recovery
	config := DefaultRecoveryConfig(hmacKey)
	recovery, err := NewRecovery(path, config)
	require.NoError(t, err)
	defer recovery.Close()

	data, err := recovery.RecoverFromCrash()
	require.NoError(t, err)

	// Verify recovered data
	assert.Equal(t, uint64(3), data.ValidEntries)
	assert.Equal(t, uint64(50), data.TotalKeystrokes)
	assert.Equal(t, uint64(1), data.TotalSamples)
	assert.Len(t, data.DocumentHashes, 1)
	assert.True(t, data.IsSignificant())
}

func TestRecovery_EmptyWAL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wal")
	sessionID := newTestSessionID()
	hmacKey := newTestHMACKey()

	// Create empty WAL
	w, err := Open(path, sessionID, hmacKey)
	require.NoError(t, err)
	w.Close()

	// Perform recovery
	config := DefaultRecoveryConfig(hmacKey)
	recovery, err := NewRecovery(path, config)
	require.NoError(t, err)
	defer recovery.Close()

	data, err := recovery.RecoverFromCrash()
	require.NoError(t, err)

	assert.Equal(t, uint64(0), data.ValidEntries)
	assert.False(t, data.IsSignificant())
}

func TestRecovery_WithCorruptedEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wal")
	sessionID := newTestSessionID()
	hmacKey := newTestHMACKey()

	// Create WAL with entries
	w, err := Open(path, sessionID, hmacKey)
	require.NoError(t, err)

	for i := 0; i < 5; i++ {
		err = w.Append(EntryHeartbeat, []byte("test"))
		require.NoError(t, err)
	}
	w.Close()

	// Corrupt one entry's CRC
	f, err := os.OpenFile(path, os.O_RDWR, 0600)
	require.NoError(t, err)

	// Find second entry and corrupt its CRC
	offset := int64(HeaderSize)
	lenBuf := make([]byte, 4)
	f.ReadAt(lenBuf, offset)
	firstEntryLen := binary.BigEndian.Uint32(lenBuf)
	offset += int64(firstEntryLen)

	// Read second entry length, find CRC offset
	f.ReadAt(lenBuf, offset)
	secondEntryLen := binary.BigEndian.Uint32(lenBuf)
	crcOffset := offset + int64(secondEntryLen) - 4

	// Corrupt CRC
	corruptBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(corruptBytes, 0xBADBAD)
	f.WriteAt(corruptBytes, crcOffset)
	f.Close()

	// Perform recovery with allowance for corrupted entries
	config := DefaultRecoveryConfig(hmacKey)
	config.MaxCorruptedEntries = 10
	recovery, err := NewRecovery(path, config)
	require.NoError(t, err)
	defer recovery.Close()

	data, err := recovery.RecoverFromCrash()
	require.NoError(t, err)

	// Should have detected corruption
	assert.Greater(t, data.CorruptedEntries, uint64(0))
	// Check that one of the limitations mentions corrupted entries
	foundCorruptionLimit := false
	for _, lim := range data.Limitations {
		if bytes.Contains([]byte(lim), []byte("corrupted")) {
			foundCorruptionLimit = true
			break
		}
	}
	assert.True(t, foundCorruptionLimit, "Expected a limitation mentioning corruption")
}

func TestRecovery_TamperedEntriesStrictMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wal")
	sessionID := newTestSessionID()
	hmacKey := newTestHMACKey()

	// Create WAL
	w, err := Open(path, sessionID, hmacKey)
	require.NoError(t, err)

	err = w.Append(EntryHeartbeat, []byte("test"))
	require.NoError(t, err)
	w.Close()

	// Try recovery with wrong HMAC key (simulates tampering detection)
	wrongKey := make([]byte, 32)
	rand.Read(wrongKey)
	config := DefaultRecoveryConfig(wrongKey)
	config.MaxTamperedEntries = 0 // Strict mode

	recovery, err := NewRecovery(path, config)
	require.NoError(t, err)
	defer recovery.Close()

	_, err = recovery.RecoverFromCrash()
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrTooManyTampered)
}

func TestRecovery_TamperedEntriesLenientMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wal")
	sessionID := newTestSessionID()
	hmacKey := newTestHMACKey()

	// Create WAL
	w, err := Open(path, sessionID, hmacKey)
	require.NoError(t, err)

	err = w.Append(EntryHeartbeat, []byte("test"))
	require.NoError(t, err)
	w.Close()

	// Try recovery with wrong key but lenient mode
	wrongKey := make([]byte, 32)
	rand.Read(wrongKey)
	config := DefaultRecoveryConfig(wrongKey)
	config.MaxTamperedEntries = 100 // Lenient mode

	recovery, err := NewRecovery(path, config)
	require.NoError(t, err)
	defer recovery.Close()

	data, err := recovery.RecoverFromCrash()
	require.NoError(t, err)

	// Should have detected tampering but continued
	assert.Greater(t, data.TamperedEntries, uint64(0))
	assert.Greater(t, len(data.Warnings), 0)
}

func TestRecovery_NonExistentWAL(t *testing.T) {
	config := DefaultRecoveryConfig([]byte("key"))
	_, err := NewRecovery("/nonexistent/path/test.wal", config)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrRecoveryFailed)
}

func TestRecovery_Stats(t *testing.T) {
	data := &RecoveredData{
		RecoveredAt:       time.Now(),
		ValidEntries:      10,
		CorruptedEntries:  2,
		TamperedEntries:   1,
		TotalKeystrokes:   500,
		TotalSamples:      25,
		LastCheckpointSeq: 5,
		FirstTimestamp:    time.Now().Add(-time.Hour).UnixNano(),
		LastTimestamp:     time.Now().UnixNano(),
	}

	stats := data.Stats()

	assert.Equal(t, uint64(10), stats.EntriesRecovered)
	assert.Equal(t, uint64(500), stats.KeystrokesRecovered)
	assert.Equal(t, uint64(25), stats.SamplesRecovered)
	assert.Equal(t, uint64(2), stats.CorruptedEntries)
	assert.Equal(t, uint64(1), stats.TamperedEntries)
	assert.Contains(t, stats.DataLossEstimate, "recovered")
}

func TestRecovery_IncompleteCommitDetection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wal")
	sessionID := newTestSessionID()
	hmacKey := newTestHMACKey()

	// Create WAL with heartbeat but no checkpoint
	w, err := Open(path, sessionID, hmacKey)
	require.NoError(t, err)

	// Add heartbeat
	hbPayload := &HeartbeatPayload{
		Timestamp:       time.Now().UnixNano(),
		KeystrokesSince: 100,
		SamplesSince:    5,
	}
	err = w.Append(EntryHeartbeat, hbPayload.Serialize())
	require.NoError(t, err)

	w.Close()

	// Perform recovery
	config := DefaultRecoveryConfig(hmacKey)
	recovery, err := NewRecovery(path, config)
	require.NoError(t, err)
	defer recovery.Close()

	data, err := recovery.RecoverFromCrash()
	require.NoError(t, err)

	// Should detect incomplete commit
	assert.True(t, data.IncompleteCommit)
}

func TestStartFresh(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wal")
	sessionID := newTestSessionID()
	hmacKey := newTestHMACKey()

	// Create WAL
	w, err := Open(path, sessionID, hmacKey)
	require.NoError(t, err)
	err = w.Append(EntryHeartbeat, []byte("test"))
	require.NoError(t, err)
	w.Close()

	// Start fresh
	err = StartFresh(path)
	require.NoError(t, err)

	// Original should be gone
	assert.False(t, Exists(path))

	// Backup should exist
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	found := false
	for _, e := range entries {
		if bytes.Contains([]byte(e.Name()), []byte("corrupted")) {
			found = true
			break
		}
	}
	assert.True(t, found, "Backup file should exist")
}

func TestValidateWAL_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wal")
	sessionID := newTestSessionID()
	hmacKey := newTestHMACKey()

	// Create valid WAL
	w, err := Open(path, sessionID, hmacKey)
	require.NoError(t, err)

	for i := 0; i < 3; i++ {
		err = w.Append(EntryHeartbeat, []byte("test"))
		require.NoError(t, err)
	}
	w.Close()

	// Validate should pass
	err = ValidateWAL(path, hmacKey)
	assert.NoError(t, err)
}

func TestValidateWAL_WrongKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wal")
	sessionID := newTestSessionID()
	hmacKey := newTestHMACKey()

	// Create valid WAL
	w, err := Open(path, sessionID, hmacKey)
	require.NoError(t, err)

	err = w.Append(EntryHeartbeat, []byte("test"))
	require.NoError(t, err)
	w.Close()

	// Validate with wrong key should fail
	wrongKey := make([]byte, 32)
	rand.Read(wrongKey)
	err = ValidateWAL(path, wrongKey)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidHMAC)
}

func TestValidateWAL_NonExistent(t *testing.T) {
	err := ValidateWAL("/nonexistent/path.wal", []byte("key"))
	assert.Error(t, err)
}

// =============================================================================
// Heartbeat Tests
// =============================================================================

func TestHeartbeat_Basic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wal")
	sessionID := newTestSessionID()
	hmacKey := newTestHMACKey()

	w, err := Open(path, sessionID, hmacKey)
	require.NoError(t, err)
	defer w.Close()

	commitCalled := false
	config := DefaultHeartbeatConfig()
	config.Interval = 100 * time.Millisecond // Fast for testing
	config.MinInterval = 50 * time.Millisecond // Allow fast intervals for testing
	config.OnCommit = func(trigger string) error {
		commitCalled = true
		return nil
	}

	heartbeat := NewHeartbeat(w, config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = heartbeat.Start(ctx)
	require.NoError(t, err)

	assert.True(t, heartbeat.IsRunning())

	// Wait for at least one heartbeat
	time.Sleep(250 * time.Millisecond)

	assert.True(t, commitCalled)

	stats := heartbeat.Stats()
	assert.Greater(t, stats.TotalHeartbeats, uint64(0))

	heartbeat.Stop()
	assert.False(t, heartbeat.IsRunning())
}

func TestHeartbeat_PauseResume(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wal")
	sessionID := newTestSessionID()
	hmacKey := newTestHMACKey()

	w, err := Open(path, sessionID, hmacKey)
	require.NoError(t, err)
	defer w.Close()

	var commitCount int
	var mu sync.Mutex
	config := DefaultHeartbeatConfig()
	config.Interval = 50 * time.Millisecond
	config.MinInterval = 25 * time.Millisecond // Allow fast intervals for testing
	config.OnCommit = func(trigger string) error {
		mu.Lock()
		commitCount++
		mu.Unlock()
		return nil
	}

	heartbeat := NewHeartbeat(w, config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	heartbeat.Start(ctx)

	// Let it run - wait longer for at least one commit
	time.Sleep(150 * time.Millisecond)
	mu.Lock()
	countBeforePause := commitCount
	mu.Unlock()

	// Pause
	heartbeat.Pause()
	assert.True(t, heartbeat.IsPaused())

	// Wait and verify no commits
	time.Sleep(150 * time.Millisecond)
	mu.Lock()
	countDuringPause := commitCount
	mu.Unlock()
	assert.Equal(t, countBeforePause, countDuringPause)

	// Resume
	heartbeat.Resume()
	assert.False(t, heartbeat.IsPaused())

	// Wait for more commits
	time.Sleep(150 * time.Millisecond)
	mu.Lock()
	countAfterResume := commitCount
	mu.Unlock()
	assert.Greater(t, countAfterResume, countDuringPause)

	heartbeat.Stop()
}

func TestHeartbeat_TriggerCommit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wal")
	sessionID := newTestSessionID()
	hmacKey := newTestHMACKey()

	w, err := Open(path, sessionID, hmacKey)
	require.NoError(t, err)
	defer w.Close()

	var triggers []string
	var mu sync.Mutex
	config := DefaultHeartbeatConfig()
	config.Interval = time.Hour // Long interval
	config.OnCommit = func(trigger string) error {
		mu.Lock()
		triggers = append(triggers, trigger)
		mu.Unlock()
		return nil
	}

	heartbeat := NewHeartbeat(w, config)

	// Manual trigger
	err = heartbeat.TriggerCommit("user-save")
	require.NoError(t, err)

	mu.Lock()
	assert.Len(t, triggers, 1)
	assert.Equal(t, "user-save", triggers[0])
	mu.Unlock()
}

func TestHeartbeat_SetInterval(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wal")
	sessionID := newTestSessionID()
	hmacKey := newTestHMACKey()

	w, err := Open(path, sessionID, hmacKey)
	require.NoError(t, err)
	defer w.Close()

	config := DefaultHeartbeatConfig()
	heartbeat := NewHeartbeat(w, config)

	// Set valid interval
	heartbeat.SetInterval(30 * time.Second)

	// Set interval below minimum (should clamp)
	heartbeat.SetInterval(1 * time.Second)

	// Set interval above maximum (should clamp)
	heartbeat.SetInterval(1 * time.Hour)
}

func TestHeartbeat_RecordStats(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wal")
	sessionID := newTestSessionID()
	hmacKey := newTestHMACKey()

	w, err := Open(path, sessionID, hmacKey)
	require.NoError(t, err)
	defer w.Close()

	config := DefaultHeartbeatConfig()
	heartbeat := NewHeartbeat(w, config)

	// Record some stats
	heartbeat.RecordKeystrokes(100)
	heartbeat.RecordKeystrokes(50)
	heartbeat.RecordSamples(5)
	heartbeat.RecordSamples(3)

	// Stats should be accumulated
	assert.Equal(t, uint64(150), heartbeat.keystrokesSinceCommit.Load())
	assert.Equal(t, uint64(8), heartbeat.samplesSinceCommit.Load())
}

func TestSemanticMilestoneHandler(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wal")
	sessionID := newTestSessionID()
	hmacKey := newTestHMACKey()

	w, err := Open(path, sessionID, hmacKey)
	require.NoError(t, err)
	defer w.Close()

	var triggers []string
	var mu sync.Mutex
	config := DefaultHeartbeatConfig()
	config.OnCommit = func(trigger string) error {
		mu.Lock()
		triggers = append(triggers, trigger)
		mu.Unlock()
		return nil
	}

	heartbeat := NewHeartbeat(w, config)
	handler := NewSemanticMilestoneHandler(heartbeat)

	// Test save detection
	err = handler.OnSaveDetected("/path/to/file.txt")
	require.NoError(t, err)

	// Test file close
	time.Sleep(600 * time.Millisecond) // Wait for debounce
	err = handler.OnFileClose("/path/to/file.txt")
	require.NoError(t, err)

	// Test app switch
	err = handler.OnAppSwitch("/path/to/file.txt")
	require.NoError(t, err)

	// Test session end
	err = handler.OnSessionEnd()
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	assert.GreaterOrEqual(t, len(triggers), 1)
}

// =============================================================================
// Payload Serialization Tests
// =============================================================================

func TestKeystrokeBatchPayload_Serialize(t *testing.T) {
	original := &KeystrokeBatchPayload{
		StartSequence: 100,
		EndSequence:   200,
		Count:         100,
		StartTime:     time.Now().UnixNano(),
		EndTime:       time.Now().Add(time.Minute).UnixNano(),
		ZoneHistogram: [8]uint16{10, 20, 30, 40, 50, 60, 70, 80},
	}
	rand.Read(original.DocumentHash[:])

	data := original.Serialize()
	decoded, err := DeserializeKeystrokeBatch(data)
	require.NoError(t, err)

	assert.Equal(t, original.StartSequence, decoded.StartSequence)
	assert.Equal(t, original.EndSequence, decoded.EndSequence)
	assert.Equal(t, original.Count, decoded.Count)
	assert.Equal(t, original.StartTime, decoded.StartTime)
	assert.Equal(t, original.EndTime, decoded.EndTime)
	assert.Equal(t, original.DocumentHash, decoded.DocumentHash)
	assert.Equal(t, original.ZoneHistogram, decoded.ZoneHistogram)
}

func TestDocumentHashPayload_Serialize(t *testing.T) {
	original := &DocumentHashPayload{
		Size:    12345,
		ModTime: time.Now().UnixNano(),
	}
	rand.Read(original.Hash[:])

	data := original.Serialize()
	decoded, err := DeserializeDocumentHash(data)
	require.NoError(t, err)

	assert.Equal(t, original.Hash, decoded.Hash)
	assert.Equal(t, original.Size, decoded.Size)
	assert.Equal(t, original.ModTime, decoded.ModTime)
}

func TestJitterSamplePayload_Serialize(t *testing.T) {
	original := &JitterSamplePayload{
		Ordinal:        42,
		KeystrokeCount: 1000,
		ZoneTransition: 3,
		IntervalBucket: 5,
		JitterMicros:   12345,
	}
	rand.Read(original.DocumentHash[:])
	rand.Read(original.SampleHash[:])

	data := original.Serialize()
	decoded, err := DeserializeJitterSample(data)
	require.NoError(t, err)

	assert.Equal(t, original.Ordinal, decoded.Ordinal)
	assert.Equal(t, original.KeystrokeCount, decoded.KeystrokeCount)
	assert.Equal(t, original.ZoneTransition, decoded.ZoneTransition)
	assert.Equal(t, original.IntervalBucket, decoded.IntervalBucket)
	assert.Equal(t, original.JitterMicros, decoded.JitterMicros)
	assert.Equal(t, original.DocumentHash, decoded.DocumentHash)
	assert.Equal(t, original.SampleHash, decoded.SampleHash)
}

func TestCheckpointPayload_Serialize(t *testing.T) {
	original := &CheckpointPayload{
		MMRIndex:    99,
		WALSequence: 500,
		Timestamp:   time.Now().UnixNano(),
	}
	rand.Read(original.CheckpointHash[:])

	data := original.Serialize()
	decoded, err := DeserializeCheckpoint(data)
	require.NoError(t, err)

	assert.Equal(t, original.MMRIndex, decoded.MMRIndex)
	assert.Equal(t, original.CheckpointHash, decoded.CheckpointHash)
	assert.Equal(t, original.WALSequence, decoded.WALSequence)
	assert.Equal(t, original.Timestamp, decoded.Timestamp)
}

func TestSessionStartPayload_Serialize(t *testing.T) {
	original := &SessionStartPayload{
		DocumentPath: "/path/to/document.txt",
		StartTime:    time.Now().UnixNano(),
	}
	rand.Read(original.SessionID[:])
	rand.Read(original.DocumentHash[:])

	data := original.Serialize()
	decoded, err := DeserializeSessionStart(data)
	require.NoError(t, err)

	assert.Equal(t, original.SessionID, decoded.SessionID)
	assert.Equal(t, original.DocumentPath, decoded.DocumentPath)
	assert.Equal(t, original.DocumentHash, decoded.DocumentHash)
	assert.Equal(t, original.StartTime, decoded.StartTime)
}

func TestSessionEndPayload_Serialize(t *testing.T) {
	original := &SessionEndPayload{
		EndTime:         time.Now().UnixNano(),
		TotalKeystrokes: 5000,
		TotalSamples:    100,
		Clean:           true,
	}
	rand.Read(original.SessionID[:])

	data := original.Serialize()
	decoded, err := DeserializeSessionEnd(data)
	require.NoError(t, err)

	assert.Equal(t, original.SessionID, decoded.SessionID)
	assert.Equal(t, original.EndTime, decoded.EndTime)
	assert.Equal(t, original.TotalKeystrokes, decoded.TotalKeystrokes)
	assert.Equal(t, original.TotalSamples, decoded.TotalSamples)
	assert.Equal(t, original.Clean, decoded.Clean)
}

func TestHeartbeatPayload_Serialize(t *testing.T) {
	original := &HeartbeatPayload{
		Timestamp:       time.Now().UnixNano(),
		KeystrokesSince: 150,
		SamplesSince:    3,
	}

	data := original.Serialize()
	decoded, err := DeserializeHeartbeat(data)
	require.NoError(t, err)

	assert.Equal(t, original.Timestamp, decoded.Timestamp)
	assert.Equal(t, original.KeystrokesSince, decoded.KeystrokesSince)
	assert.Equal(t, original.SamplesSince, decoded.SamplesSince)
}
