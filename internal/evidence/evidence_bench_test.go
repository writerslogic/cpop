package evidence

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"witnessd/internal/checkpoint"
	"witnessd/internal/declaration"
	"witnessd/internal/jitter"
	"witnessd/internal/mmr"
	"witnessd/internal/vdf"
)

// createTestCheckpointChain creates a checkpoint chain for benchmarking.
func createTestCheckpointChain(numCheckpoints int, documentPath string) (*checkpoint.Chain, error) {
	params := vdf.DefaultParameters()
	// Use minimal VDF iterations for benchmarking
	params.MinIterations = 100
	params.IterationsPerSecond = 1000000

	chain := &checkpoint.Chain{
		DocumentPath: documentPath,
		VDFParams:    params,
		Checkpoints:  make([]*checkpoint.Checkpoint, 0, numCheckpoints),
	}

	var prevHash [32]byte
	for i := 0; i < numCheckpoints; i++ {
		var contentHash [32]byte
		rand.Read(contentHash[:])

		cp := &checkpoint.Checkpoint{
			Ordinal:      uint64(i),
			ContentHash:  contentHash,
			ContentSize:  int64(1000 + i*100),
			Timestamp:    time.Now().Add(time.Duration(i) * time.Minute),
			Message:      fmt.Sprintf("Checkpoint %d", i),
			PreviousHash: prevHash,
		}

		// Compute VDF proof (minimal iterations for benchmarking)
		var vdfInput [32]byte
		copy(vdfInput[:], contentHash[:])
		cp.VDF = vdf.ComputeIterations(vdfInput, 100)

		// Compute checkpoint hash
		h := sha256.New()
		h.Write(cp.ContentHash[:])
		h.Write(cp.PreviousHash[:])
		var buf [8]byte
		buf[0] = byte(cp.Ordinal)
		h.Write(buf[:])
		copy(cp.Hash[:], h.Sum(nil))

		chain.Checkpoints = append(chain.Checkpoints, cp)
		prevHash = cp.Hash
	}

	return chain, nil
}

// createBenchDeclaration creates a declaration for benchmarking.
func createBenchDeclaration() *declaration.Declaration {
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)

	// Create dummy hashes
	var docHash, chainHash [32]byte
	rand.Read(docHash[:])
	rand.Read(chainHash[:])

	decl, _ := declaration.NewDeclaration(docHash, chainHash, "Benchmark Document").
		AddModality(declaration.ModalityKeyboard, 100, "").
		WithStatement("Benchmark test declaration").
		Sign(privKey)

	return decl
}

// BenchmarkEndToEndCheckpoint benchmarks complete checkpoint creation.
func BenchmarkEndToEndCheckpoint(b *testing.B) {
	tmpDir, _ := os.MkdirTemp("", "evidence_bench")
	defer os.RemoveAll(tmpDir)

	documentPath := filepath.Join(tmpDir, "test.txt")
	os.WriteFile(documentPath, []byte("benchmark document content"), 0644)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		chain, err := createTestCheckpointChain(10, documentPath)
		if err != nil {
			b.Fatalf("failed to create chain: %v", err)
		}
		_ = chain
	}
}

// BenchmarkEvidenceExport benchmarks evidence packet creation.
func BenchmarkEvidenceExport(b *testing.B) {
	sizes := []int{10, 50, 100}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("checkpoints_%d", size), func(b *testing.B) {
			tmpDir, _ := os.MkdirTemp("", "evidence_export")
			defer os.RemoveAll(tmpDir)

			documentPath := filepath.Join(tmpDir, "test.txt")
			os.WriteFile(documentPath, []byte("benchmark document content"), 0644)

			chain, _ := createTestCheckpointChain(size, documentPath)
			decl := createBenchDeclaration()

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				builder := NewBuilder("Benchmark Document", chain)
				builder.WithDeclaration(decl)
				packet, err := builder.Build()
				if err != nil {
					b.Fatalf("build failed: %v", err)
				}
				_ = packet
			}
		})
	}
}

// BenchmarkVerification benchmarks evidence packet verification.
func BenchmarkVerification(b *testing.B) {
	sizes := []int{10, 50, 100}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("checkpoints_%d", size), func(b *testing.B) {
			tmpDir, _ := os.MkdirTemp("", "evidence_verify")
			defer os.RemoveAll(tmpDir)

			documentPath := filepath.Join(tmpDir, "test.txt")
			os.WriteFile(documentPath, []byte("benchmark document content"), 0644)

			chain, _ := createTestCheckpointChain(size, documentPath)
			decl := createBenchDeclaration()

			builder := NewBuilder("Benchmark Document", chain)
			builder.WithDeclaration(decl)
			packet, _ := builder.Build()

			params := vdf.DefaultParameters()
			params.MinIterations = 100

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				err := packet.Verify(params)
				if err != nil {
					b.Fatalf("verification failed: %v", err)
				}
			}

			b.ReportMetric(float64(size), "checkpoints_verified")
		})
	}
}

// BenchmarkEvidenceEncode benchmarks JSON encoding of evidence packets.
func BenchmarkEvidenceEncode(b *testing.B) {
	sizes := []int{10, 50, 100}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("checkpoints_%d", size), func(b *testing.B) {
			tmpDir, _ := os.MkdirTemp("", "evidence_encode")
			defer os.RemoveAll(tmpDir)

			documentPath := filepath.Join(tmpDir, "test.txt")
			os.WriteFile(documentPath, []byte("benchmark document content"), 0644)

			chain, _ := createTestCheckpointChain(size, documentPath)
			decl := createBenchDeclaration()

			builder := NewBuilder("Benchmark Document", chain)
			builder.WithDeclaration(decl)
			packet, _ := builder.Build()

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				data, err := packet.Encode()
				if err != nil {
					b.Fatalf("encode failed: %v", err)
				}
				_ = data
			}
		})
	}
}

// BenchmarkEvidenceDecode benchmarks JSON decoding of evidence packets.
func BenchmarkEvidenceDecode(b *testing.B) {
	sizes := []int{10, 50, 100}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("checkpoints_%d", size), func(b *testing.B) {
			tmpDir, _ := os.MkdirTemp("", "evidence_decode")
			defer os.RemoveAll(tmpDir)

			documentPath := filepath.Join(tmpDir, "test.txt")
			os.WriteFile(documentPath, []byte("benchmark document content"), 0644)

			chain, _ := createTestCheckpointChain(size, documentPath)
			decl := createBenchDeclaration()

			builder := NewBuilder("Benchmark Document", chain)
			builder.WithDeclaration(decl)
			packet, _ := builder.Build()
			encoded, _ := packet.Encode()

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				decoded, err := Decode(encoded)
				if err != nil {
					b.Fatalf("decode failed: %v", err)
				}
				_ = decoded
			}
		})
	}
}

// BenchmarkEvidenceHash benchmarks evidence packet hashing.
func BenchmarkEvidenceHash(b *testing.B) {
	tmpDir, _ := os.MkdirTemp("", "evidence_hash")
	defer os.RemoveAll(tmpDir)

	documentPath := filepath.Join(tmpDir, "test.txt")
	os.WriteFile(documentPath, []byte("benchmark document content"), 0644)

	chain, _ := createTestCheckpointChain(50, documentPath)
	decl := createBenchDeclaration()

	builder := NewBuilder("Benchmark Document", chain)
	builder.WithDeclaration(decl)
	packet, _ := builder.Build()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		hash := packet.Hash()
		_ = hash
	}
}

// BenchmarkTotalElapsedTime benchmarks elapsed time calculation.
func BenchmarkTotalElapsedTime(b *testing.B) {
	tmpDir, _ := os.MkdirTemp("", "evidence_elapsed")
	defer os.RemoveAll(tmpDir)

	documentPath := filepath.Join(tmpDir, "test.txt")
	os.WriteFile(documentPath, []byte("benchmark document content"), 0644)

	chain, _ := createTestCheckpointChain(100, documentPath)
	decl := createBenchDeclaration()

	builder := NewBuilder("Benchmark Document", chain)
	builder.WithDeclaration(decl)
	packet, _ := builder.Build()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		elapsed := packet.TotalElapsedTime()
		_ = elapsed
	}
}

// BenchmarkFullPipeline benchmarks the complete evidence creation pipeline.
func BenchmarkFullPipeline(b *testing.B) {
	tmpDir, _ := os.MkdirTemp("", "evidence_pipeline")
	defer os.RemoveAll(tmpDir)

	documentPath := filepath.Join(tmpDir, "test.txt")
	os.WriteFile(documentPath, []byte("benchmark document content for full pipeline test"), 0644)

	jitterParams := jitter.DefaultParameters()
	jitterParams.SampleInterval = 10

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// 1. Create checkpoint chain
		chain, _ := createTestCheckpointChain(20, documentPath)

		// 2. Create declaration
		decl := createBenchDeclaration()

		// 3. Create jitter evidence
		jitterSession, _ := jitter.NewSession(documentPath, jitterParams)
		for j := 0; j < 500; j++ {
			jitterSession.RecordKeystroke()
		}
		jitterEvidence := jitterSession.Export()
		jitterSession.End()

		// 4. Build evidence packet
		builder := NewBuilder("Pipeline Benchmark", chain)
		builder.WithDeclaration(decl)
		builder.WithKeystroke(&jitterEvidence)

		packet, err := builder.Build()
		if err != nil {
			b.Fatalf("build failed: %v", err)
		}

		// 5. Encode
		encoded, err := packet.Encode()
		if err != nil {
			b.Fatalf("encode failed: %v", err)
		}

		// 6. Verify
		params := vdf.DefaultParameters()
		params.MinIterations = 100
		if err := packet.Verify(params); err != nil {
			b.Fatalf("verify failed: %v", err)
		}

		b.ReportMetric(float64(len(encoded)), "packet_bytes")
	}
}

// BenchmarkWithKeystroke benchmarks adding keystroke evidence.
func BenchmarkWithKeystroke(b *testing.B) {
	tmpDir, _ := os.MkdirTemp("", "evidence_keystroke")
	defer os.RemoveAll(tmpDir)

	documentPath := filepath.Join(tmpDir, "test.txt")
	os.WriteFile(documentPath, []byte("benchmark document content"), 0644)

	chain, _ := createTestCheckpointChain(10, documentPath)
	decl := createBenchDeclaration()

	// Create jitter evidence
	jitterParams := jitter.DefaultParameters()
	jitterParams.SampleInterval = 10

	jitterSession, _ := jitter.NewSession(documentPath, jitterParams)
	for j := 0; j < 500; j++ {
		jitterSession.RecordKeystroke()
	}
	jitterEvidence := jitterSession.Export()
	jitterSession.End()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		builder := NewBuilder("Benchmark Document", chain)
		builder.WithDeclaration(decl)
		builder.WithKeystroke(&jitterEvidence)
		packet, _ := builder.Build()
		_ = packet
	}
}

// BenchmarkWithBehavioral benchmarks adding behavioral evidence.
func BenchmarkWithBehavioral(b *testing.B) {
	tmpDir, _ := os.MkdirTemp("", "evidence_behavioral")
	defer os.RemoveAll(tmpDir)

	documentPath := filepath.Join(tmpDir, "test.txt")
	os.WriteFile(documentPath, []byte("benchmark document content"), 0644)

	chain, _ := createTestCheckpointChain(10, documentPath)
	decl := createBenchDeclaration()

	// Create behavioral evidence
	regions := make([]EditRegion, 50)
	for i := 0; i < 50; i++ {
		regions[i] = EditRegion{
			StartPct:  float64(i) * 2.0,
			EndPct:    float64(i)*2.0 + 1.5,
			DeltaSign: i % 3,
			ByteCount: 100 + i*10,
		}
	}

	metrics := &ForensicMetrics{
		MonotonicAppendRatio:  0.75,
		EditEntropy:           4.5,
		MedianInterval:        2.5,
		PositiveNegativeRatio: 3.2,
		DeletionClustering:    0.15,
		Assessment:            "consistent",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		builder := NewBuilder("Benchmark Document", chain)
		builder.WithDeclaration(decl)
		builder.WithBehavioral(regions, metrics)
		packet, _ := builder.Build()
		_ = packet
	}
}

// BenchmarkWithProvenance benchmarks adding provenance information.
func BenchmarkWithProvenance(b *testing.B) {
	tmpDir, _ := os.MkdirTemp("", "evidence_provenance")
	defer os.RemoveAll(tmpDir)

	documentPath := filepath.Join(tmpDir, "test.txt")
	os.WriteFile(documentPath, []byte("benchmark document content"), 0644)

	chain, _ := createTestCheckpointChain(10, documentPath)
	decl := createBenchDeclaration()

	provenance := &RecordProvenance{
		DeviceID:      "benchmark-device-001",
		SigningPubkey: hex.EncodeToString(make([]byte, 32)),
		KeySource:     "file",
		Hostname:      "benchmark-host",
		OS:            "linux",
		Architecture:  "amd64",
		SessionID:     "bench-session-001",
		SessionStarted: time.Now(),
		InputDevices: []InputDeviceInfo{
			{
				VendorID:       0x046d,
				ProductID:      0xc534,
				ProductName:    "Benchmark Keyboard",
				ConnectionType: "USB",
				Fingerprint:    "abc123",
			},
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		builder := NewBuilder("Benchmark Document", chain)
		builder.WithDeclaration(decl)
		builder.WithProvenance(provenance)
		packet, _ := builder.Build()
		_ = packet
	}
}

// BenchmarkClaimGeneration benchmarks claim generation.
func BenchmarkClaimGeneration(b *testing.B) {
	tmpDir, _ := os.MkdirTemp("", "evidence_claims")
	defer os.RemoveAll(tmpDir)

	documentPath := filepath.Join(tmpDir, "test.txt")
	os.WriteFile(documentPath, []byte("benchmark document content"), 0644)

	chain, _ := createTestCheckpointChain(50, documentPath)
	decl := createBenchDeclaration()

	jitterParams := jitter.DefaultParameters()
	jitterParams.SampleInterval = 10

	jitterSession, _ := jitter.NewSession(documentPath, jitterParams)
	for j := 0; j < 200; j++ {
		jitterSession.RecordKeystroke()
	}
	jitterEvidence := jitterSession.Export()
	jitterSession.End()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		builder := NewBuilder("Benchmark Document", chain)
		builder.WithDeclaration(decl)
		builder.WithKeystroke(&jitterEvidence)
		packet, _ := builder.Build()
		_ = packet.Claims
	}
}

// BenchmarkPacketSize measures packet sizes at different scales.
func BenchmarkPacketSize(b *testing.B) {
	scales := []struct {
		checkpoints  int
		keystrokes   int
	}{
		{10, 100},
		{50, 500},
		{100, 1000},
	}

	for _, scale := range scales {
		b.Run(fmt.Sprintf("cp_%d_ks_%d", scale.checkpoints, scale.keystrokes), func(b *testing.B) {
			tmpDir, _ := os.MkdirTemp("", "evidence_size")
			defer os.RemoveAll(tmpDir)

			documentPath := filepath.Join(tmpDir, "test.txt")
			os.WriteFile(documentPath, []byte("benchmark document content"), 0644)

			chain, _ := createTestCheckpointChain(scale.checkpoints, documentPath)
			decl := createBenchDeclaration()

			jitterParams := jitter.DefaultParameters()
			jitterParams.SampleInterval = uint64(scale.keystrokes / 10)

			jitterSession, _ := jitter.NewSession(documentPath, jitterParams)
			for j := 0; j < scale.keystrokes; j++ {
				jitterSession.RecordKeystroke()
			}
			jitterEvidence := jitterSession.Export()
			jitterSession.End()

			builder := NewBuilder("Benchmark Document", chain)
			builder.WithDeclaration(decl)
			builder.WithKeystroke(&jitterEvidence)
			packet, _ := builder.Build()
			encoded, _ := packet.Encode()

			b.ReportMetric(float64(len(encoded)), "packet_bytes")
			b.ReportMetric(float64(scale.checkpoints), "checkpoints")
			b.ReportMetric(float64(scale.keystrokes), "keystrokes")
		})
	}
}

// BenchmarkMMRIntegration benchmarks MMR operations within evidence context.
func BenchmarkMMRIntegration(b *testing.B) {
	sizes := []int{100, 500, 1000}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("leaves_%d", size), func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				store := mmr.NewMemoryStore()
				m, _ := mmr.New(store)

				// Add leaves
				var lastIdx uint64
				for j := 0; j < size; j++ {
					data := []byte(fmt.Sprintf("checkpoint-%d", j))
					lastIdx, _ = m.Append(data)
				}

				// Generate proof for last leaf
				proof, _ := m.GenerateProof(lastIdx)

				// Verify proof
				data := []byte(fmt.Sprintf("checkpoint-%d", size-1))
				proof.Verify(data)
			}

			b.ReportMetric(float64(size), "mmr_leaves")
		})
	}
}

// BenchmarkConcurrentPacketCreation benchmarks concurrent packet creation.
func BenchmarkConcurrentPacketCreation(b *testing.B) {
	tmpDir, _ := os.MkdirTemp("", "evidence_concurrent")
	defer os.RemoveAll(tmpDir)

	documentPath := filepath.Join(tmpDir, "test.txt")
	os.WriteFile(documentPath, []byte("benchmark document content"), 0644)

	chain, _ := createTestCheckpointChain(10, documentPath)
	decl := createBenchDeclaration()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			builder := NewBuilder("Benchmark Document", chain)
			builder.WithDeclaration(decl)
			packet, err := builder.Build()
			if err != nil {
				b.Errorf("build failed: %v", err)
				return
			}
			_ = packet
		}
	})
}
