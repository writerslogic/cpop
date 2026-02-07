package wal

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// BenchmarkWALAppend benchmarks single entry append operations.
func BenchmarkWALAppend(b *testing.B) {
	tmpDir, err := os.MkdirTemp("", "wal_bench")
	if err != nil {
		b.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	walPath := filepath.Join(tmpDir, "bench.wal")
	sessionID := [32]byte{1, 2, 3, 4}
	hmacKey := []byte("test-hmac-key-for-benchmarking")

	wal, err := Open(walPath, sessionID, hmacKey)
	if err != nil {
		b.Fatalf("failed to open WAL: %v", err)
	}
	defer wal.Close()

	payload := make([]byte, 100) // Typical keystroke batch size
	for i := range payload {
		payload[i] = byte(i)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		if err := wal.Append(EntryKeystrokeBatch, payload); err != nil {
			b.Fatalf("append failed: %v", err)
		}
	}

	b.ReportMetric(float64(wal.Size())/float64(b.N), "bytes/op")
}

// BenchmarkWALAppendBatch benchmarks batch append operations (1000 entries).
func BenchmarkWALAppendBatch(b *testing.B) {
	sizes := []int{100, 500, 1000}

	for _, batchSize := range sizes {
		b.Run(fmt.Sprintf("batch_%d", batchSize), func(b *testing.B) {
			tmpDir, err := os.MkdirTemp("", "wal_batch_bench")
			if err != nil {
				b.Fatalf("failed to create temp dir: %v", err)
			}
			defer os.RemoveAll(tmpDir)

			payload := make([]byte, 100)
			for i := range payload {
				payload[i] = byte(i)
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				walPath := filepath.Join(tmpDir, fmt.Sprintf("bench_%d.wal", i))
				sessionID := [32]byte{1, 2, 3, byte(i)}
				hmacKey := []byte("test-hmac-key-for-benchmarking")

				wal, err := Open(walPath, sessionID, hmacKey)
				if err != nil {
					b.Fatalf("failed to open WAL: %v", err)
				}

				for j := 0; j < batchSize; j++ {
					if err := wal.Append(EntryKeystrokeBatch, payload); err != nil {
						b.Fatalf("append failed: %v", err)
					}
				}

				wal.Close()
				os.Remove(walPath)
			}

			b.ReportMetric(float64(batchSize), "entries/batch")
		})
	}
}

// BenchmarkWALAppendNoSync benchmarks append without sync (for comparison).
// Note: This is for analysis only - production code should always sync.
func BenchmarkWALAppendNoSync(b *testing.B) {
	tmpDir, err := os.MkdirTemp("", "wal_nosync_bench")
	if err != nil {
		b.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	walPath := filepath.Join(tmpDir, "bench_nosync.wal")
	sessionID := [32]byte{1, 2, 3, 4}
	hmacKey := []byte("test-hmac-key-for-benchmarking")

	wal, err := Open(walPath, sessionID, hmacKey)
	if err != nil {
		b.Fatalf("failed to open WAL: %v", err)
	}
	defer wal.Close()

	payload := make([]byte, 100)
	for i := range payload {
		payload[i] = byte(i)
	}

	b.ResetTimer()
	b.ReportAllocs()

	// Note: This benchmark directly writes to file without syncing
	// to measure the cost of sync operations
	for i := 0; i < b.N; i++ {
		entry := &Entry{
			Sequence:  uint64(i),
			Timestamp: 1234567890,
			Type:      EntryKeystrokeBatch,
			Payload:   payload,
			PrevHash:  [32]byte{},
		}
		entry.CRC32 = computeEntryCRC(entry)
		data := serializeEntry(entry)
		wal.file.Write(data)
	}
}

// BenchmarkWALRead benchmarks reading all entries from a WAL.
func BenchmarkWALRead(b *testing.B) {
	sizes := []int{100, 1000, 10000}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("entries_%d", size), func(b *testing.B) {
			tmpDir, err := os.MkdirTemp("", "wal_read_bench")
			if err != nil {
				b.Fatalf("failed to create temp dir: %v", err)
			}
			defer os.RemoveAll(tmpDir)

			walPath := filepath.Join(tmpDir, "bench.wal")
			sessionID := [32]byte{1, 2, 3, 4}
			hmacKey := []byte("test-hmac-key-for-benchmarking")

			// Pre-populate WAL
			wal, err := Open(walPath, sessionID, hmacKey)
			if err != nil {
				b.Fatalf("failed to open WAL: %v", err)
			}

			payload := make([]byte, 100)
			for i := 0; i < size; i++ {
				if err := wal.Append(EntryKeystrokeBatch, payload); err != nil {
					b.Fatalf("append failed: %v", err)
				}
			}
			wal.Close()

			// Benchmark read operations
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				wal, _ = Open(walPath, sessionID, hmacKey)
				entries, err := wal.ReadAll()
				if err != nil {
					b.Fatalf("read failed: %v", err)
				}
				if len(entries) != size {
					b.Fatalf("expected %d entries, got %d", size, len(entries))
				}
				wal.Close()
			}

			b.ReportMetric(float64(size), "entries/read")
		})
	}
}

// BenchmarkWALTruncate benchmarks truncation operations.
func BenchmarkWALTruncate(b *testing.B) {
	tmpDir, err := os.MkdirTemp("", "wal_truncate_bench")
	if err != nil {
		b.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	payload := make([]byte, 100)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		b.StopTimer()

		walPath := filepath.Join(tmpDir, fmt.Sprintf("bench_%d.wal", i))
		sessionID := [32]byte{1, 2, 3, byte(i)}
		hmacKey := []byte("test-hmac-key-for-benchmarking")

		wal, _ := Open(walPath, sessionID, hmacKey)

		// Add 1000 entries
		for j := 0; j < 1000; j++ {
			wal.Append(EntryKeystrokeBatch, payload)
		}

		b.StartTimer()

		// Truncate to keep only last 100 entries
		if err := wal.Truncate(900); err != nil {
			b.Fatalf("truncate failed: %v", err)
		}

		b.StopTimer()
		wal.Close()
		os.Remove(walPath)
		os.Remove(walPath + ".new")
	}
}

// BenchmarkWALMemoryAllocs measures memory allocations for WAL operations.
func BenchmarkWALMemoryAllocs(b *testing.B) {
	b.Run("Entry_Serialization", func(b *testing.B) {
		entry := &Entry{
			Sequence:  12345,
			Timestamp: 1234567890,
			Type:      EntryKeystrokeBatch,
			Payload:   make([]byte, 100),
			PrevHash:  [32]byte{1, 2, 3, 4},
		}

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			data := serializeEntry(entry)
			_ = data
		}
	})

	b.Run("Entry_Deserialization", func(b *testing.B) {
		entry := &Entry{
			Sequence:  12345,
			Timestamp: 1234567890,
			Type:      EntryKeystrokeBatch,
			Payload:   make([]byte, 100),
			PrevHash:  [32]byte{1, 2, 3, 4},
		}
		entry.CRC32 = computeEntryCRC(entry)
		data := serializeEntry(entry)

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_, err := deserializeEntry(data)
			if err != nil {
				b.Fatalf("deserialize failed: %v", err)
			}
		}
	})

	b.Run("CRC_Computation", func(b *testing.B) {
		entry := &Entry{
			Sequence:  12345,
			Timestamp: 1234567890,
			Type:      EntryKeystrokeBatch,
			Payload:   make([]byte, 100),
			PrevHash:  [32]byte{1, 2, 3, 4},
		}

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_ = computeEntryCRC(entry)
		}
	})

	b.Run("Entry_Hash", func(b *testing.B) {
		entry := &Entry{
			Sequence:  12345,
			Timestamp: 1234567890,
			Type:      EntryKeystrokeBatch,
			Payload:   make([]byte, 100),
			PrevHash:  [32]byte{1, 2, 3, 4},
		}

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_ = entry.Hash()
		}
	})
}

// BenchmarkWALPayloadSizes benchmarks append with different payload sizes.
func BenchmarkWALPayloadSizes(b *testing.B) {
	sizes := []int{32, 100, 500, 1000, 4096}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("payload_%d", size), func(b *testing.B) {
			tmpDir, err := os.MkdirTemp("", "wal_payload_bench")
			if err != nil {
				b.Fatalf("failed to create temp dir: %v", err)
			}
			defer os.RemoveAll(tmpDir)

			walPath := filepath.Join(tmpDir, "bench.wal")
			sessionID := [32]byte{1, 2, 3, 4}
			hmacKey := []byte("test-hmac-key-for-benchmarking")

			wal, err := Open(walPath, sessionID, hmacKey)
			if err != nil {
				b.Fatalf("failed to open WAL: %v", err)
			}
			defer wal.Close()

			payload := make([]byte, size)
			for i := range payload {
				payload[i] = byte(i)
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				if err := wal.Append(EntryKeystrokeBatch, payload); err != nil {
					b.Fatalf("append failed: %v", err)
				}
			}

			b.ReportMetric(float64(size), "payload_bytes")
		})
	}
}

// BenchmarkWALConcurrentReads benchmarks concurrent read operations.
func BenchmarkWALConcurrentReads(b *testing.B) {
	tmpDir, err := os.MkdirTemp("", "wal_concurrent_bench")
	if err != nil {
		b.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	walPath := filepath.Join(tmpDir, "bench.wal")
	sessionID := [32]byte{1, 2, 3, 4}
	hmacKey := []byte("test-hmac-key-for-benchmarking")

	// Pre-populate WAL
	wal, err := Open(walPath, sessionID, hmacKey)
	if err != nil {
		b.Fatalf("failed to open WAL: %v", err)
	}

	payload := make([]byte, 100)
	for i := 0; i < 1000; i++ {
		wal.Append(EntryKeystrokeBatch, payload)
	}
	wal.Close()

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		wal, _ := Open(walPath, sessionID, hmacKey)
		defer wal.Close()

		for pb.Next() {
			wal.ReadAll()
		}
	})
}

// BenchmarkWALHMAC benchmarks HMAC computation.
func BenchmarkWALHMAC(b *testing.B) {
	tmpDir, err := os.MkdirTemp("", "wal_hmac_bench")
	if err != nil {
		b.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	walPath := filepath.Join(tmpDir, "bench.wal")
	sessionID := [32]byte{1, 2, 3, 4}
	hmacKey := []byte("test-hmac-key-for-benchmarking")

	wal, err := Open(walPath, sessionID, hmacKey)
	if err != nil {
		b.Fatalf("failed to open WAL: %v", err)
	}
	defer wal.Close()

	entry := &Entry{
		Sequence:  12345,
		Timestamp: 1234567890,
		Type:      EntryKeystrokeBatch,
		Payload:   make([]byte, 100),
		PrevHash:  [32]byte{1, 2, 3, 4},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = wal.computeHMAC(entry)
	}
}

// BenchmarkWALRecoveryPerformance benchmarks WAL scan and recovery time.
func BenchmarkWALRecoveryPerformance(b *testing.B) {
	sizes := []int{100, 1000, 5000}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("entries_%d", size), func(b *testing.B) {
			tmpDir, err := os.MkdirTemp("", "wal_recovery_bench")
			if err != nil {
				b.Fatalf("failed to create temp dir: %v", err)
			}
			defer os.RemoveAll(tmpDir)

			walPath := filepath.Join(tmpDir, "bench.wal")
			sessionID := [32]byte{1, 2, 3, 4}
			hmacKey := []byte("test-hmac-key-for-benchmarking")

			// Pre-populate WAL
			wal, _ := Open(walPath, sessionID, hmacKey)
			payload := make([]byte, 100)
			for i := 0; i < size; i++ {
				wal.Append(EntryKeystrokeBatch, payload)
			}
			wal.Close()

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				// Simulate recovery by reopening WAL
				wal, err := Open(walPath, sessionID, hmacKey)
				if err != nil {
					b.Fatalf("failed to open WAL: %v", err)
				}
				if wal.EntryCount() != uint64(size) {
					b.Fatalf("expected %d entries, got %d", size, wal.EntryCount())
				}
				wal.Close()
			}

			b.ReportMetric(float64(size), "entries_recovered")
		})
	}
}
