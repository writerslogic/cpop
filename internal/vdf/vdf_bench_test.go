package vdf

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"testing"
	"time"
)

// BenchmarkVDFCompute benchmarks VDF computation at various iteration counts.
func BenchmarkVDFCompute(b *testing.B) {
	iterations := []uint64{1000, 10000, 100000}

	for _, iters := range iterations {
		b.Run(fmt.Sprintf("iterations_%d", iters), func(b *testing.B) {
			var input [32]byte
			copy(input[:], []byte("benchmark-vdf-input"))

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				proof := ComputeIterations(input, iters)
				_ = proof
			}

			// Report iterations per nanosecond
			b.ReportMetric(float64(iters), "iterations")
		})
	}
}

// BenchmarkVDFVerify benchmarks VDF verification.
func BenchmarkVDFVerify(b *testing.B) {
	iterations := []uint64{1000, 10000, 50000}

	for _, iters := range iterations {
		b.Run(fmt.Sprintf("iterations_%d", iters), func(b *testing.B) {
			// Pre-compute a proof
			var input [32]byte
			copy(input[:], []byte("benchmark-vdf-input"))
			proof := ComputeIterations(input, iters)

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				valid := Verify(proof)
				if !valid {
					b.Fatalf("verification failed")
				}
			}

			b.ReportMetric(float64(iters), "iterations_verified")
		})
	}
}

// BenchmarkVDFComputeChain benchmarks the core hash chain computation.
func BenchmarkVDFComputeChain(b *testing.B) {
	iterations := []uint64{10000, 100000}

	for _, iters := range iterations {
		b.Run(fmt.Sprintf("iterations_%d", iters), func(b *testing.B) {
			var input [32]byte
			copy(input[:], []byte("benchmark-hash-chain"))

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				output := computeChain(input, iters)
				_ = output
			}

			// Verify O(T) complexity by measuring iterations per second
			elapsed := b.Elapsed()
			iterPerSec := float64(iters*uint64(b.N)) / elapsed.Seconds()
			b.ReportMetric(iterPerSec, "iterations/sec")
		})
	}
}

// BenchmarkVDFWithDuration benchmarks VDF compute for target durations.
func BenchmarkVDFWithDuration(b *testing.B) {
	durations := []time.Duration{
		100 * time.Millisecond,
		500 * time.Millisecond,
	}

	params := DefaultParameters()

	for _, duration := range durations {
		b.Run(fmt.Sprintf("duration_%s", duration), func(b *testing.B) {
			var input [32]byte
			copy(input[:], []byte("benchmark-vdf-duration"))

			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				proof, err := Compute(input, duration, params)
				if err != nil {
					b.Fatalf("compute failed: %v", err)
				}
				_ = proof
			}
		})
	}
}

// BenchmarkVDFCalibration benchmarks the calibration function.
func BenchmarkVDFCalibration(b *testing.B) {
	durations := []time.Duration{
		100 * time.Millisecond,
		500 * time.Millisecond,
	}

	for _, duration := range durations {
		b.Run(fmt.Sprintf("calibrate_%s", duration), func(b *testing.B) {
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				params, err := Calibrate(duration)
				if err != nil {
					b.Fatalf("calibration failed: %v", err)
				}
				_ = params
			}
		})
	}
}

// BenchmarkVDFBatchVerifier benchmarks batch verification of multiple proofs.
func BenchmarkVDFBatchVerifier(b *testing.B) {
	batchSizes := []int{4, 8, 16}
	iterations := uint64(10000)

	for _, batchSize := range batchSizes {
		b.Run(fmt.Sprintf("batch_%d", batchSize), func(b *testing.B) {
			// Pre-compute proofs
			proofs := make([]*Proof, batchSize)
			for i := 0; i < batchSize; i++ {
				var input [32]byte
				copy(input[:], fmt.Sprintf("input-%d", i))
				proofs[i] = ComputeIterations(input, iterations)
			}

			verifier := NewBatchVerifier(0) // Use default workers

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				results := verifier.VerifyAll(proofs)
				for _, r := range results {
					if !r.Valid {
						b.Fatalf("batch verification failed at index %d", r.Index)
					}
				}
			}

			b.ReportMetric(float64(batchSize), "proofs_verified")
		})
	}
}

// BenchmarkVDFProofEncodeDecode benchmarks proof serialization.
func BenchmarkVDFProofEncodeDecode(b *testing.B) {
	var input [32]byte
	copy(input[:], []byte("benchmark-encode-decode"))
	proof := ComputeIterations(input, 10000)

	b.Run("Encode", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			data := proof.Encode()
			_ = data
		}
	})

	encoded := proof.Encode()

	b.Run("Decode", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			decoded, err := DecodeProof(encoded)
			if err != nil {
				b.Fatalf("decode failed: %v", err)
			}
			_ = decoded
		}
	})
}

// BenchmarkVDFChainInput benchmarks the chain input generation.
func BenchmarkVDFChainInput(b *testing.B) {
	var contentHash, previousHash [32]byte
	copy(contentHash[:], []byte("content-hash-benchmark"))
	copy(previousHash[:], []byte("previous-hash-benchmark"))

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		input := ChainInput(contentHash, previousHash, uint64(i))
		_ = input
	}
}

// BenchmarkVDFVerifyWithProgress benchmarks verification with progress reporting.
func BenchmarkVDFVerifyWithProgress(b *testing.B) {
	var input [32]byte
	copy(input[:], []byte("benchmark-progress"))
	proof := ComputeIterations(input, 10000)

	b.Run("WithProgress", func(b *testing.B) {
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			progress := make(chan float64, 100)
			go func() {
				for range progress {
					// Drain progress channel
				}
			}()
			valid := VerifyWithProgress(proof, progress)
			if !valid {
				b.Fatalf("verification failed")
			}
		}
	})

	b.Run("WithoutProgress", func(b *testing.B) {
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			valid := VerifyWithProgress(proof, nil)
			if !valid {
				b.Fatalf("verification failed")
			}
		}
	})
}

// BenchmarkVDFComplexityAnalysis analyzes VDF time complexity.
// This benchmark verifies O(T) complexity by measuring how time scales with iterations.
func BenchmarkVDFComplexityAnalysis(b *testing.B) {
	// Different iteration counts to verify linear scaling
	iterationCounts := []uint64{1000, 2000, 4000, 8000, 16000}

	var input [32]byte
	copy(input[:], []byte("complexity-analysis"))

	results := make(map[uint64]time.Duration)

	for _, iters := range iterationCounts {
		b.Run(fmt.Sprintf("T=%d", iters), func(b *testing.B) {
			b.ResetTimer()

			start := time.Now()
			for i := 0; i < b.N; i++ {
				computeChain(input, iters)
			}
			elapsed := time.Since(start)
			avgTime := elapsed / time.Duration(b.N)
			results[iters] = avgTime

			// Report time per iteration (should be roughly constant if O(T))
			timePerIter := float64(avgTime.Nanoseconds()) / float64(iters)
			b.ReportMetric(timePerIter, "ns/iteration")
		})
	}

	// Final sub-benchmark to report scaling factor
	b.Run("scaling_analysis", func(b *testing.B) {
		if len(results) >= 2 {
			// Compare smallest and largest iteration counts
			small := iterationCounts[0]
			large := iterationCounts[len(iterationCounts)-1]

			if results[small] > 0 && results[large] > 0 {
				expectedRatio := float64(large) / float64(small)
				actualRatio := float64(results[large]) / float64(results[small])

				// For O(T), these ratios should be similar
				b.ReportMetric(expectedRatio, "expected_ratio")
				b.ReportMetric(actualRatio, "actual_ratio")
			}
		}
	})
}

// BenchmarkVDFMemoryAllocs focuses on memory allocation patterns.
func BenchmarkVDFMemoryAllocs(b *testing.B) {
	var input [32]byte
	copy(input[:], []byte("memory-benchmark"))

	b.Run("SingleHash", func(b *testing.B) {
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			output := sha256.Sum256(input[:])
			_ = output
		}
	})

	b.Run("ChainOf100", func(b *testing.B) {
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			output := computeChain(input, 100)
			_ = output
		}
	})

	b.Run("ProofStruct", func(b *testing.B) {
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			proof := &Proof{
				Input:      input,
				Output:     input,
				Iterations: 10000,
				Duration:   time.Second,
			}
			_ = proof
		}
	})
}

// BenchmarkPietrzakVDF benchmarks the Pietrzak VDF implementation.
func BenchmarkPietrzakVDF(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping Pietrzak VDF benchmark in short mode")
	}

	// Use small T values for benchmarking (real usage would be much larger)
	tValues := []uint64{1 << 10, 1 << 12, 1 << 14}

	for _, t := range tValues {
		b.Run(fmt.Sprintf("T=%d", t), func(b *testing.B) {
			params := PietrzakParams{
				N:                     new(big.Int).Set(defaultModulus),
				T:                     t,
				Lambda:                128,
				AllowUntrustedModulus: false,
			}

			vdf, err := NewPietrzakVDF(params)
			if err != nil {
				b.Fatalf("failed to create VDF: %v", err)
			}

			x := vdf.InputFromBytes([]byte("benchmark-pietrzak"))

			b.Run("Evaluate", func(b *testing.B) {
				b.ResetTimer()

				for i := 0; i < b.N; i++ {
					proof, err := vdf.Evaluate(x)
					if err != nil {
						b.Fatalf("evaluation failed: %v", err)
					}
					_ = proof
				}
			})
		})
	}
}

// BenchmarkPietrzakVerify benchmarks Pietrzak VDF verification (O(log T)).
func BenchmarkPietrzakVerify(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping Pietrzak verification benchmark in short mode")
	}

	tValues := []uint64{1 << 10, 1 << 12}

	for _, t := range tValues {
		b.Run(fmt.Sprintf("T=%d", t), func(b *testing.B) {
			params := PietrzakParams{
				N:                     new(big.Int).Set(defaultModulus),
				T:                     t,
				Lambda:                128,
				AllowUntrustedModulus: false,
			}

			vdf, err := NewPietrzakVDF(params)
			if err != nil {
				b.Fatalf("failed to create VDF: %v", err)
			}

			x := vdf.InputFromBytes([]byte("benchmark-pietrzak-verify"))
			proof, err := vdf.Evaluate(x)
			if err != nil {
				b.Fatalf("evaluation failed: %v", err)
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				valid := vdf.Verify(proof)
				if !valid {
					b.Fatalf("verification failed")
				}
			}

			b.ReportMetric(float64(len(proof.Intermediates)), "proof_levels")
			b.ReportMetric(float64(proof.VerificationOps()), "verification_ops")
		})
	}
}

// BenchmarkPietrzakProofSize measures proof size scaling with T.
func BenchmarkPietrzakProofSize(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping Pietrzak proof size benchmark in short mode")
	}

	tValues := []uint64{1 << 8, 1 << 10, 1 << 12}

	for _, t := range tValues {
		b.Run(fmt.Sprintf("T=%d", t), func(b *testing.B) {
			params := PietrzakParams{
				N:                     new(big.Int).Set(defaultModulus),
				T:                     t,
				Lambda:                128,
				AllowUntrustedModulus: false,
			}

			vdf, _ := NewPietrzakVDF(params)
			x := vdf.InputFromBytes([]byte("benchmark-proof-size"))
			proof, _ := vdf.Evaluate(x)

			// Encode to measure size
			encoded, _ := proof.Encode()

			b.ReportMetric(float64(len(encoded)), "proof_bytes")
			b.ReportMetric(float64(len(proof.Intermediates)), "intermediate_count")
			b.ReportMetric(float64(proof.PietrzakProofSize()), "estimated_size")
		})
	}
}

// BenchmarkSquaringsPerSecond calibrates squaring performance.
func BenchmarkSquaringsPerSecond(b *testing.B) {
	durations := []time.Duration{
		100 * time.Millisecond,
		500 * time.Millisecond,
	}

	for _, d := range durations {
		b.Run(fmt.Sprintf("duration_%s", d), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				rate, err := CalibrateSquaringsPerSecond(d)
				if err != nil {
					b.Fatalf("calibration failed: %v", err)
				}
				b.ReportMetric(float64(rate), "squarings/sec")
			}
		})
	}
}
