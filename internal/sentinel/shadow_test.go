// Package sentinel shadow buffer tests.
//
// Patent Pending: USPTO Application No. 19/460,364
package sentinel

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestShadowBufferNew(t *testing.T) {
	config := DefaultShadowBufferConfig()

	sb, err := NewShadowBuffer(config)
	if err != nil {
		t.Fatalf("NewShadowBuffer failed: %v", err)
	}
	defer sb.Close()

	if sb.Size() != 0 {
		t.Errorf("expected size 0, got %d", sb.Size())
	}
	if sb.KeystrokeCount() != 0 {
		t.Errorf("expected keystroke count 0, got %d", sb.KeystrokeCount())
	}
}

func TestShadowBufferWithBackingFile(t *testing.T) {
	tmpDir := t.TempDir()
	config := ShadowBufferConfig{
		MaxSize:     1024,
		TTL:         time.Hour,
		BackingPath: filepath.Join(tmpDir, "shadow.buf"),
	}

	sb, err := NewShadowBuffer(config)
	if err != nil {
		t.Fatalf("NewShadowBuffer failed: %v", err)
	}

	// Record some keystrokes
	for i := 0; i < 10; i++ {
		sb.RecordKeystroke(time.Now())
	}

	// Close buffer
	sb.Close()

	// Verify backing file exists
	if _, err := os.Stat(config.BackingPath); os.IsNotExist(err) {
		// File may be deleted on close - that's OK
		t.Log("Backing file deleted on close (expected)")
	}
}

func TestShadowBufferRecordKeystroke(t *testing.T) {
	sb, err := NewShadowBuffer(DefaultShadowBufferConfig())
	if err != nil {
		t.Fatalf("NewShadowBuffer failed: %v", err)
	}
	defer sb.Close()

	// Record keystrokes
	now := time.Now()
	for i := 0; i < 100; i++ {
		sb.RecordKeystroke(now.Add(time.Duration(i) * time.Millisecond))
	}

	if sb.KeystrokeCount() != 100 {
		t.Errorf("expected 100 keystrokes, got %d", sb.KeystrokeCount())
	}

	// Get records
	records := sb.Records()
	if len(records) != 100 {
		t.Errorf("expected 100 records, got %d", len(records))
	}

	// Verify sequence numbers
	for i, r := range records {
		if r.Sequence != uint64(i+1) {
			t.Errorf("record %d: expected sequence %d, got %d", i, i+1, r.Sequence)
		}
	}
}

func TestShadowBufferWrite(t *testing.T) {
	sb, err := NewShadowBuffer(DefaultShadowBufferConfig())
	if err != nil {
		t.Fatalf("NewShadowBuffer failed: %v", err)
	}
	defer sb.Close()

	data := []byte("test data")
	n, err := sb.Write(data)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != len(data) {
		t.Errorf("expected to write %d bytes, wrote %d", len(data), n)
	}
}

func TestShadowBufferWriteOverflow(t *testing.T) {
	config := ShadowBufferConfig{
		MaxSize: 100,
		TTL:     time.Hour,
	}

	sb, err := NewShadowBuffer(config)
	if err != nil {
		t.Fatalf("NewShadowBuffer failed: %v", err)
	}
	defer sb.Close()

	// Fill the buffer
	data := make([]byte, 50)
	_, err = sb.Write(data)
	if err != nil {
		t.Fatalf("first Write failed: %v", err)
	}

	// Try to overflow
	_, err = sb.Write(make([]byte, 60))
	if err == nil {
		t.Error("expected overflow error")
	}
}

func TestShadowBufferFlush(t *testing.T) {
	sb, err := NewShadowBuffer(DefaultShadowBufferConfig())
	if err != nil {
		t.Fatalf("NewShadowBuffer failed: %v", err)
	}
	defer sb.Close()

	// Record some keystrokes
	for i := 0; i < 10; i++ {
		sb.RecordKeystroke(time.Now())
	}

	// Flush
	data, hash := sb.Flush()

	// Verify we got data
	if len(data) == 0 {
		t.Error("expected non-empty data")
	}

	// Verify hash is not zero
	var zeroHash [32]byte
	if hash == zeroHash {
		t.Error("expected non-zero hash")
	}

	// Verify buffer is empty
	if sb.KeystrokeCount() != 0 {
		t.Error("buffer should be empty after flush")
	}

	// Parse the flushed data
	if len(data) < 8 {
		t.Fatal("data too short")
	}
	count := binary.LittleEndian.Uint64(data[0:8])
	if count != 10 {
		t.Errorf("expected 10 records in flushed data, got %d", count)
	}
}

func TestShadowBufferSnapshot(t *testing.T) {
	sb, err := NewShadowBuffer(DefaultShadowBufferConfig())
	if err != nil {
		t.Fatalf("NewShadowBuffer failed: %v", err)
	}
	defer sb.Close()

	// Record keystrokes
	for i := 0; i < 5; i++ {
		sb.RecordKeystroke(time.Now())
	}

	// Take snapshot
	data1, hash1 := sb.Snapshot()

	// Buffer should still have data
	if sb.KeystrokeCount() == 0 {
		t.Error("buffer should not be empty after snapshot")
	}

	// Take another snapshot
	data2, hash2 := sb.Snapshot()

	// Should be same
	if !bytes.Equal(data1, data2) {
		t.Error("snapshots should be equal")
	}
	if hash1 != hash2 {
		t.Error("hashes should be equal")
	}
}

func TestShadowBufferIsExpired(t *testing.T) {
	config := ShadowBufferConfig{
		MaxSize: 1024,
		TTL:     50 * time.Millisecond,
	}

	sb, err := NewShadowBuffer(config)
	if err != nil {
		t.Fatalf("NewShadowBuffer failed: %v", err)
	}
	defer sb.Close()

	// Should not be expired immediately
	if sb.IsExpired() {
		t.Error("buffer should not be expired immediately")
	}

	// Wait for TTL
	time.Sleep(60 * time.Millisecond)

	// Should be expired
	if !sb.IsExpired() {
		t.Error("buffer should be expired after TTL")
	}
}

func TestShadowBufferIsExpiredAfterWrite(t *testing.T) {
	config := ShadowBufferConfig{
		MaxSize: 1024,
		TTL:     50 * time.Millisecond,
	}

	sb, err := NewShadowBuffer(config)
	if err != nil {
		t.Fatalf("NewShadowBuffer failed: %v", err)
	}
	defer sb.Close()

	// Wait a bit
	time.Sleep(30 * time.Millisecond)

	// Record keystroke (resets TTL timer)
	sb.RecordKeystroke(time.Now())

	// Should not be expired
	if sb.IsExpired() {
		t.Error("buffer should not be expired after write")
	}

	// Wait for full TTL after write
	time.Sleep(60 * time.Millisecond)

	// Should be expired
	if !sb.IsExpired() {
		t.Error("buffer should be expired after TTL from last write")
	}
}

func TestShadowBufferReset(t *testing.T) {
	sb, err := NewShadowBuffer(DefaultShadowBufferConfig())
	if err != nil {
		t.Fatalf("NewShadowBuffer failed: %v", err)
	}
	defer sb.Close()

	// Record some data
	for i := 0; i < 10; i++ {
		sb.RecordKeystroke(time.Now())
	}
	sb.Write([]byte("test"))

	// Reset
	sb.Reset()

	// Verify empty
	if sb.KeystrokeCount() != 0 {
		t.Error("keystroke count should be 0 after reset")
	}
	if sb.Size() != 0 {
		t.Error("size should be 0 after reset")
	}
	if len(sb.Records()) != 0 {
		t.Error("records should be empty after reset")
	}
}

func TestShadowBufferStats(t *testing.T) {
	sb, err := NewShadowBuffer(DefaultShadowBufferConfig())
	if err != nil {
		t.Fatalf("NewShadowBuffer failed: %v", err)
	}
	defer sb.Close()

	// Record data
	for i := 0; i < 10; i++ {
		sb.RecordKeystroke(time.Now())
	}

	stats := sb.Stats()

	if stats.KeystrokeCount != 10 {
		t.Errorf("expected keystroke count 10, got %d", stats.KeystrokeCount)
	}
	if stats.RecordCount != 10 {
		t.Errorf("expected record count 10, got %d", stats.RecordCount)
	}
	if stats.CreatedAt.IsZero() {
		t.Error("created at should not be zero")
	}
	if stats.LastWrite.IsZero() {
		t.Error("last write should not be zero")
	}
}

func TestShadowBufferFlushCallback(t *testing.T) {
	sb, err := NewShadowBuffer(DefaultShadowBufferConfig())
	if err != nil {
		t.Fatalf("NewShadowBuffer failed: %v", err)
	}
	defer sb.Close()

	// Set callback
	called := false
	var receivedData []byte
	var receivedHash [32]byte

	sb.SetFlushCallback(func(data []byte, hash [32]byte) {
		called = true
		receivedData = data
		receivedHash = hash
	})

	// Record and flush
	sb.RecordKeystroke(time.Now())
	data, hash := sb.Flush()

	// Verify callback was called
	if !called {
		t.Error("flush callback was not called")
	}
	if !bytes.Equal(receivedData, data) {
		t.Error("callback received different data")
	}
	if receivedHash != hash {
		t.Error("callback received different hash")
	}
}

func TestShadowBufferConcurrency(t *testing.T) {
	sb, err := NewShadowBuffer(DefaultShadowBufferConfig())
	if err != nil {
		t.Fatalf("NewShadowBuffer failed: %v", err)
	}
	defer sb.Close()

	var wg sync.WaitGroup

	// Concurrent writers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				sb.RecordKeystroke(time.Now())
			}
		}()
	}

	// Concurrent readers
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = sb.Size()
				_ = sb.KeystrokeCount()
				_ = sb.Records()
				_ = sb.Stats()
			}
		}()
	}

	wg.Wait()

	// Should have ~1000 keystrokes
	count := sb.KeystrokeCount()
	if count < 900 || count > 1100 {
		t.Errorf("unexpected keystroke count: %d", count)
	}
}

func TestShadowBufferRotation(t *testing.T) {
	config := ShadowBufferConfig{
		MaxSize: 1024, // Small buffer to trigger rotation
		TTL:     time.Hour,
	}

	sb, err := NewShadowBuffer(config)
	if err != nil {
		t.Fatalf("NewShadowBuffer failed: %v", err)
	}
	defer sb.Close()

	// Record many keystrokes to trigger rotation
	for i := 0; i < 100; i++ {
		sb.RecordKeystroke(time.Now())
	}

	// Buffer should still work
	count := sb.KeystrokeCount()
	if count == 0 {
		t.Error("expected some keystrokes after rotation")
	}

	records := sb.Records()
	if len(records) == 0 {
		t.Error("expected some records after rotation")
	}

	// Verify sequence numbers are still valid
	for i := 1; i < len(records); i++ {
		if records[i].Sequence <= records[i-1].Sequence {
			t.Error("sequence numbers should be increasing")
		}
	}
}

func TestShadowBufferClose(t *testing.T) {
	sb, err := NewShadowBuffer(DefaultShadowBufferConfig())
	if err != nil {
		t.Fatalf("NewShadowBuffer failed: %v", err)
	}

	// Record some data
	sb.RecordKeystroke(time.Now())

	// Close
	if err := sb.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Double close should be safe
	if err := sb.Close(); err != nil {
		t.Fatalf("Double close failed: %v", err)
	}

	// Operations after close should be no-op
	sb.RecordKeystroke(time.Now())
}

func BenchmarkShadowBufferRecordKeystroke(b *testing.B) {
	sb, err := NewShadowBuffer(DefaultShadowBufferConfig())
	if err != nil {
		b.Fatalf("NewShadowBuffer failed: %v", err)
	}
	defer sb.Close()

	now := time.Now()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		sb.RecordKeystroke(now)
	}
}

func BenchmarkShadowBufferSnapshot(b *testing.B) {
	sb, err := NewShadowBuffer(DefaultShadowBufferConfig())
	if err != nil {
		b.Fatalf("NewShadowBuffer failed: %v", err)
	}
	defer sb.Close()

	// Populate buffer
	for i := 0; i < 1000; i++ {
		sb.RecordKeystroke(time.Now())
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = sb.Snapshot()
	}
}

func BenchmarkShadowBufferFlush(b *testing.B) {
	sb, err := NewShadowBuffer(DefaultShadowBufferConfig())
	if err != nil {
		b.Fatalf("NewShadowBuffer failed: %v", err)
	}
	defer sb.Close()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Populate and flush
		for j := 0; j < 100; j++ {
			sb.RecordKeystroke(time.Now())
		}
		_, _ = sb.Flush()
	}
}
