package jitter

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// BenchmarkJitterSealComputation benchmarks the core jitter computation.
func BenchmarkJitterSealComputation(b *testing.B) {
	var seed [32]byte
	rand.Read(seed[:])

	var docHash [32]byte
	rand.Read(docHash[:])

	var prevJitter [32]byte
	params := DefaultParameters()
	timestamp := time.Now()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		jitter := ComputeJitterValue(seed[:], docHash, uint64(i), timestamp, prevJitter, params)
		_ = jitter
	}
}

// BenchmarkRecordKeystroke benchmarks keystroke recording with jitter sampling.
func BenchmarkRecordKeystroke(b *testing.B) {
	// Create a temporary document
	tmpDir, err := os.MkdirTemp("", "jitter_bench")
	if err != nil {
		b.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	docPath := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(docPath, []byte("initial content"), 0644); err != nil {
		b.Fatalf("failed to create test file: %v", err)
	}

	params := DefaultParameters()
	params.SampleInterval = 50 // Sample every 50 keystrokes

	session, err := NewSession(docPath, params)
	if err != nil {
		b.Fatalf("failed to create session: %v", err)
	}
	defer session.End()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		jitter, sampled := session.RecordKeystroke()
		_ = jitter
		_ = sampled
	}

	b.ReportMetric(float64(session.SampleCount()), "samples")
	b.ReportMetric(float64(session.KeystrokeCount()), "keystrokes")
}

// BenchmarkBatchProcessing benchmarks processing batches of keystrokes.
func BenchmarkBatchProcessing(b *testing.B) {
	batchSizes := []int{100, 500, 1000, 5000}

	for _, batchSize := range batchSizes {
		b.Run(fmt.Sprintf("batch_%d", batchSize), func(b *testing.B) {
			tmpDir, _ := os.MkdirTemp("", "jitter_batch")
			defer os.RemoveAll(tmpDir)

			docPath := filepath.Join(tmpDir, "test.txt")
			os.WriteFile(docPath, []byte("benchmark content"), 0644)

			params := DefaultParameters()
			params.SampleInterval = 50

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				b.StopTimer()
				session, _ := NewSession(docPath, params)
				b.StartTimer()

				for j := 0; j < batchSize; j++ {
					session.RecordKeystroke()
				}

				b.StopTimer()
				session.End()
			}

			b.ReportMetric(float64(batchSize), "keystrokes/batch")
		})
	}
}

// BenchmarkSampleChainVerification benchmarks verifying the sample chain.
func BenchmarkSampleChainVerification(b *testing.B) {
	chainLengths := []int{100, 500, 1000}

	for _, length := range chainLengths {
		b.Run(fmt.Sprintf("chain_%d", length), func(b *testing.B) {
			tmpDir, _ := os.MkdirTemp("", "jitter_verify")
			defer os.RemoveAll(tmpDir)

			docPath := filepath.Join(tmpDir, "test.txt")
			os.WriteFile(docPath, []byte("benchmark content"), 0644)

			params := DefaultParameters()
			params.SampleInterval = 1 // Sample every keystroke for this test

			session, _ := NewSession(docPath, params)

			// Generate sample chain
			for j := 0; j < length; j++ {
				session.RecordKeystroke()
			}

			evidence := session.Export()
			session.End()

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				err := evidence.Verify()
				if err != nil {
					b.Fatalf("verification failed: %v", err)
				}
			}

			b.ReportMetric(float64(length), "samples_verified")
		})
	}
}

// BenchmarkEvidenceExport benchmarks evidence export.
func BenchmarkEvidenceExport(b *testing.B) {
	tmpDir, _ := os.MkdirTemp("", "jitter_export")
	defer os.RemoveAll(tmpDir)

	docPath := filepath.Join(tmpDir, "test.txt")
	os.WriteFile(docPath, []byte("benchmark content"), 0644)

	params := DefaultParameters()
	params.SampleInterval = 10

	session, _ := NewSession(docPath, params)

	// Generate some samples
	for j := 0; j < 1000; j++ {
		session.RecordKeystroke()
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		evidence := session.Export()
		_ = evidence
	}

	session.End()
}

// BenchmarkEvidenceEncode benchmarks evidence JSON encoding.
func BenchmarkEvidenceEncode(b *testing.B) {
	tmpDir, _ := os.MkdirTemp("", "jitter_encode")
	defer os.RemoveAll(tmpDir)

	docPath := filepath.Join(tmpDir, "test.txt")
	os.WriteFile(docPath, []byte("benchmark content"), 0644)

	params := DefaultParameters()
	params.SampleInterval = 10

	session, _ := NewSession(docPath, params)
	for j := 0; j < 500; j++ {
		session.RecordKeystroke()
	}
	evidence := session.Export()
	session.End()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		data, err := evidence.Encode()
		if err != nil {
			b.Fatalf("encode failed: %v", err)
		}
		_ = data
	}
}

// BenchmarkEvidenceDecode benchmarks evidence JSON decoding.
func BenchmarkEvidenceDecode(b *testing.B) {
	tmpDir, _ := os.MkdirTemp("", "jitter_decode")
	defer os.RemoveAll(tmpDir)

	docPath := filepath.Join(tmpDir, "test.txt")
	os.WriteFile(docPath, []byte("benchmark content"), 0644)

	params := DefaultParameters()
	params.SampleInterval = 10

	session, _ := NewSession(docPath, params)
	for j := 0; j < 500; j++ {
		session.RecordKeystroke()
	}
	evidence := session.Export()
	session.End()

	encoded, _ := evidence.Encode()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		decoded, err := DecodeEvidence(encoded)
		if err != nil {
			b.Fatalf("decode failed: %v", err)
		}
		_ = decoded
	}
}

// BenchmarkJitterEngine benchmarks the zone-committed jitter engine.
func BenchmarkJitterEngine(b *testing.B) {
	var secret [32]byte
	rand.Read(secret[:])

	engine := NewJitterEngine(secret)

	var docHash [32]byte
	rand.Read(docHash[:])

	// Simulate typical key codes (alphanumeric keys)
	keyCodes := []uint16{30, 31, 32, 33, 34, 35, 36, 37, 38, 39} // A-J

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		keyCode := keyCodes[i%len(keyCodes)]
		jitter, sample := engine.OnKeystroke(keyCode, docHash)
		_ = jitter
		_ = sample
	}
}

// BenchmarkTypingProfileComparison benchmarks profile comparison.
func BenchmarkTypingProfileComparison(b *testing.B) {
	// Generate two profiles with some data
	profileA := TypingProfile{
		TotalTransitions: 1000,
		HandAlternation:  0.45,
	}
	profileB := TypingProfile{
		TotalTransitions: 1200,
		HandAlternation:  0.48,
	}

	// Fill histograms
	for i := 0; i < 10; i++ {
		profileA.SameFingerHist[i] = uint32(50 + i*5)
		profileA.SameHandHist[i] = uint32(100 + i*10)
		profileA.AlternatingHist[i] = uint32(200 + i*15)

		profileB.SameFingerHist[i] = uint32(55 + i*4)
		profileB.SameHandHist[i] = uint32(105 + i*9)
		profileB.AlternatingHist[i] = uint32(195 + i*16)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		similarity := CompareProfiles(profileA, profileB)
		_ = similarity
	}
}

// BenchmarkIsHumanPlausible benchmarks human plausibility check.
func BenchmarkIsHumanPlausible(b *testing.B) {
	// Generate a realistic profile
	profile := TypingProfile{
		TotalTransitions: 5000,
		HandAlternation:  0.42,
	}

	for i := 0; i < 10; i++ {
		profile.SameFingerHist[i] = uint32(100 + i*10)
		profile.SameHandHist[i] = uint32(300 + i*20)
		profile.AlternatingHist[i] = uint32(500 + i*30)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		plausible := IsHumanPlausible(profile)
		_ = plausible
	}
}

// BenchmarkProfileDistance benchmarks profile distance calculation.
func BenchmarkProfileDistance(b *testing.B) {
	profileA := TypingProfile{TotalTransitions: 1000, HandAlternation: 0.45}
	profileB := TypingProfile{TotalTransitions: 1200, HandAlternation: 0.48}

	for i := 0; i < 10; i++ {
		profileA.SameFingerHist[i] = uint32(50 + i*5)
		profileA.SameHandHist[i] = uint32(100 + i*10)
		profileA.AlternatingHist[i] = uint32(200 + i*15)

		profileB.SameFingerHist[i] = uint32(55 + i*4)
		profileB.SameHandHist[i] = uint32(105 + i*9)
		profileB.AlternatingHist[i] = uint32(195 + i*16)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		distance := ProfileDistance(profileA, profileB)
		_ = distance
	}
}

// BenchmarkIntervalToBucket benchmarks interval bucketing.
func BenchmarkIntervalToBucket(b *testing.B) {
	intervals := []time.Duration{
		10 * time.Millisecond,
		50 * time.Millisecond,
		100 * time.Millisecond,
		250 * time.Millisecond,
		500 * time.Millisecond,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		interval := intervals[i%len(intervals)]
		bucket := IntervalToBucket(interval)
		_ = bucket
	}
}

// BenchmarkSampleHash benchmarks sample hash computation.
func BenchmarkSampleHash(b *testing.B) {
	sample := Sample{
		Timestamp:      time.Now(),
		KeystrokeCount: 12345,
		JitterMicros:   1500,
	}
	rand.Read(sample.DocumentHash[:])
	rand.Read(sample.PreviousHash[:])

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		hash := sample.computeHash()
		_ = hash
	}
}

// BenchmarkSessionSaveLoad benchmarks session persistence.
func BenchmarkSessionSaveLoad(b *testing.B) {
	tmpDir, _ := os.MkdirTemp("", "jitter_persist")
	defer os.RemoveAll(tmpDir)

	docPath := filepath.Join(tmpDir, "test.txt")
	os.WriteFile(docPath, []byte("benchmark content"), 0644)

	params := DefaultParameters()
	params.SampleInterval = 10

	session, _ := NewSession(docPath, params)
	for j := 0; j < 200; j++ {
		session.RecordKeystroke()
	}

	savePath := filepath.Join(tmpDir, "session.json")

	b.Run("Save", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			err := session.Save(savePath)
			if err != nil {
				b.Fatalf("save failed: %v", err)
			}
		}
	})

	session.Save(savePath)
	session.End()

	b.Run("Load", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			loaded, err := LoadSession(savePath)
			if err != nil {
				b.Fatalf("load failed: %v", err)
			}
			_ = loaded
		}
	})
}

// BenchmarkHighKeystrokeRate simulates high typing rates (300+ WPM).
func BenchmarkHighKeystrokeRate(b *testing.B) {
	// 300 WPM = ~1500 chars/min = 25 chars/sec
	// We'll simulate processing at this rate

	tmpDir, _ := os.MkdirTemp("", "jitter_high_rate")
	defer os.RemoveAll(tmpDir)

	docPath := filepath.Join(tmpDir, "test.txt")
	os.WriteFile(docPath, []byte("benchmark content for high rate test"), 0644)

	params := DefaultParameters()
	params.SampleInterval = 50

	keystrokesPerBatch := 1500 // One minute at 300 WPM

	b.Run("300WPM_simulation", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			b.StopTimer()
			session, _ := NewSession(docPath, params)
			b.StartTimer()

			for j := 0; j < keystrokesPerBatch; j++ {
				session.RecordKeystroke()
			}

			b.StopTimer()
			session.End()
		}

		b.ReportMetric(float64(keystrokesPerBatch), "keystrokes/batch")
		b.ReportMetric(300.0, "simulated_wpm")
	})
}

// BenchmarkJitterEngineConcurrent benchmarks concurrent jitter engine usage.
func BenchmarkJitterEngineConcurrent(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		var secret [32]byte
		rand.Read(secret[:])

		engine := NewJitterEngine(secret)

		var docHash [32]byte
		rand.Read(docHash[:])

		keyCodes := []uint16{30, 31, 32, 33, 34}
		i := 0

		for pb.Next() {
			keyCode := keyCodes[i%len(keyCodes)]
			engine.OnKeystroke(keyCode, docHash)
			i++
		}
	})
}

// BenchmarkDocumentHashRead benchmarks document hashing (I/O component).
func BenchmarkDocumentHashRead(b *testing.B) {
	sizes := []int{1024, 10240, 102400} // 1KB, 10KB, 100KB

	for _, size := range sizes {
		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			tmpDir, _ := os.MkdirTemp("", "jitter_doc_hash")
			defer os.RemoveAll(tmpDir)

			docPath := filepath.Join(tmpDir, "test.txt")
			content := make([]byte, size)
			rand.Read(content)
			os.WriteFile(docPath, content, 0644)

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				data, _ := os.ReadFile(docPath)
				hash := sha256.Sum256(data)
				_ = hash
			}

			b.ReportMetric(float64(size), "document_bytes")
		})
	}
}

// BenchmarkMemoryUsage measures memory allocations for jitter operations.
func BenchmarkMemoryUsage(b *testing.B) {
	b.Run("Sample_Creation", func(b *testing.B) {
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			sample := Sample{
				Timestamp:      time.Now(),
				KeystrokeCount: uint64(i),
				JitterMicros:   1500,
			}
			_ = sample
		}
	})

	b.Run("JitterSample_Creation", func(b *testing.B) {
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			sample := JitterSample{
				Ordinal:        uint64(i),
				Timestamp:      time.Now(),
				ZoneTransition: 0x12,
				IntervalBucket: 5,
				JitterMicros:   1500,
			}
			_ = sample
		}
	})

	b.Run("TypingProfile_Creation", func(b *testing.B) {
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			profile := TypingProfile{
				TotalTransitions: uint64(i),
				HandAlternation:  0.45,
			}
			_ = profile
		}
	})
}
