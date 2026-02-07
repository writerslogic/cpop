package mmr

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// BenchmarkMMRAppend measures single leaf append performance.
func BenchmarkMMRAppend(b *testing.B) {
	store := NewMemoryStore()
	mmr, _ := New(store)

	data := []byte("benchmark-checkpoint-data")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := mmr.Append(data)
		if err != nil {
			b.Fatalf("append failed: %v", err)
		}
	}

	b.ReportMetric(float64(mmr.Size()), "total_nodes")
	b.ReportMetric(float64(mmr.LeafCount()), "total_leaves")
}

// BenchmarkMMRAppendWithPersistence measures append with file-backed store.
func BenchmarkMMRAppendWithPersistence(b *testing.B) {
	tmpDir, err := os.MkdirTemp("", "mmr_bench")
	if err != nil {
		b.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	storePath := filepath.Join(tmpDir, "bench.mmr")
	store, _ := OpenFileStore(storePath)
	mmr, _ := New(store)

	data := []byte("benchmark-checkpoint-data")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := mmr.Append(data)
		if err != nil {
			b.Fatalf("append failed: %v", err)
		}
	}

	store.Sync()
	store.Close()
}

// BenchmarkMMRProofGeneration measures proof generation at various tree sizes.
func BenchmarkMMRProofGeneration(b *testing.B) {
	sizes := []int{100, 1000, 10000, 100000}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("leaves_%d", size), func(b *testing.B) {
			store := NewMemoryStore()
			mmr, _ := New(store)

			// Pre-populate
			var leafIndices []uint64
			for i := 0; i < size; i++ {
				idx, _ := mmr.Append([]byte{byte(i), byte(i >> 8)})
				// Store some indices to probe
				if i%100 == 0 {
					leafIndices = append(leafIndices, idx)
				}
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				idx := leafIndices[i%len(leafIndices)]
				_, err := mmr.GenerateProof(idx)
				if err != nil {
					b.Fatalf("proof generation failed: %v", err)
				}
			}

			b.ReportMetric(float64(size), "tree_size")
		})
	}
}

// BenchmarkMMRProofVerification measures proof verification time.
func BenchmarkMMRProofVerification(b *testing.B) {
	sizes := []int{100, 1000, 10000}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("leaves_%d", size), func(b *testing.B) {
			store := NewMemoryStore()
			mmr, _ := New(store)

			// Pre-populate with test data
			testData := make([][]byte, size)
			leafIndices := make([]uint64, size)
			for i := 0; i < size; i++ {
				testData[i] = []byte(fmt.Sprintf("checkpoint-%d", i))
				idx, _ := mmr.Append(testData[i])
				leafIndices[i] = idx
			}

			// Pre-generate proofs
			numProofs := 100
			proofs := make([]*InclusionProof, numProofs)
			for i := 0; i < numProofs; i++ {
				idx := i * (size / numProofs)
				proofs[i], _ = mmr.GenerateProof(leafIndices[idx])
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				proofIdx := i % numProofs
				dataIdx := proofIdx * (size / numProofs)
				err := proofs[proofIdx].Verify(testData[dataIdx])
				if err != nil {
					b.Fatalf("verification failed: %v", err)
				}
			}
		})
	}
}

// BenchmarkMMRLargeTree benchmarks operations on a tree with 1M leaves.
func BenchmarkMMRLargeTree(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping large tree benchmark in short mode")
	}

	store := NewMemoryStore()
	mmr, _ := New(store)

	// Build a large tree (1M leaves takes too long, use 100K)
	targetSize := 100000

	b.Run("Build", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			store := NewMemoryStore()
			mmr, _ := New(store)
			b.StartTimer()

			for j := 0; j < targetSize; j++ {
				mmr.Append([]byte{byte(j), byte(j >> 8), byte(j >> 16)})
			}
		}
	})

	// Build tree for subsequent benchmarks
	var leafIndices []uint64
	for i := 0; i < targetSize; i++ {
		idx, _ := mmr.Append([]byte{byte(i), byte(i >> 8), byte(i >> 16)})
		if i%10000 == 0 {
			leafIndices = append(leafIndices, idx)
		}
	}

	b.Run("GetRoot", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_, err := mmr.GetRoot()
			if err != nil {
				b.Fatalf("get root failed: %v", err)
			}
		}
	})

	b.Run("GenerateProof", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			idx := leafIndices[i%len(leafIndices)]
			_, err := mmr.GenerateProof(idx)
			if err != nil {
				b.Fatalf("proof generation failed: %v", err)
			}
		}
	})

	b.ReportMetric(float64(mmr.Size()), "total_nodes")
	b.ReportMetric(float64(mmr.LeafCount()), "total_leaves")
}

// BenchmarkMMRRangeProof benchmarks range proof generation and verification.
func BenchmarkMMRRangeProof(b *testing.B) {
	store := NewMemoryStore()
	mmr, _ := New(store)

	// Pre-populate
	numLeaves := 1000
	testData := make([][]byte, numLeaves)
	for i := 0; i < numLeaves; i++ {
		testData[i] = []byte(fmt.Sprintf("data-%d", i))
		mmr.Append(testData[i])
	}

	rangeSizes := []int{10, 50, 100, 200}

	for _, rangeSize := range rangeSizes {
		b.Run(fmt.Sprintf("generate_range_%d", rangeSize), func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				start := uint64(i % (numLeaves - rangeSize))
				end := start + uint64(rangeSize) - 1
				_, err := mmr.GenerateRangeProof(start, end)
				if err != nil {
					b.Fatalf("range proof generation failed: %v", err)
				}
			}
		})

		b.Run(fmt.Sprintf("verify_range_%d", rangeSize), func(b *testing.B) {
			start := uint64(0)
			end := uint64(rangeSize - 1)
			proof, _ := mmr.GenerateRangeProof(start, end)
			rangeData := testData[:rangeSize]

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				err := proof.Verify(rangeData)
				if err != nil {
					b.Fatalf("range proof verification failed: %v", err)
				}
			}
		})
	}
}

// BenchmarkMMRMemoryUsage measures memory consumption of MMR operations.
func BenchmarkMMRMemoryUsage(b *testing.B) {
	b.Run("Node_Allocation", func(b *testing.B) {
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			node := NewLeafNode(uint64(i), []byte("test-data"))
			_ = node
		}
	})

	b.Run("Internal_Node", func(b *testing.B) {
		leftNode := NewLeafNode(0, []byte("left"))
		rightNode := NewLeafNode(1, []byte("right"))

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			node := NewInternalNode(uint64(i), 1, leftNode, rightNode)
			_ = node
		}
	})

	b.Run("Hash_Operations", func(b *testing.B) {
		data := []byte("benchmark-data-for-hashing")

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_ = HashLeaf(data)
		}
	})
}

// BenchmarkMMRConcurrency measures concurrent access performance.
func BenchmarkMMRConcurrency(b *testing.B) {
	store := NewMemoryStore()
	mmr, _ := New(store)

	// Pre-populate
	for i := 0; i < 10000; i++ {
		mmr.Append([]byte{byte(i), byte(i >> 8)})
	}

	b.Run("Concurrent_GetRoot", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_, err := mmr.GetRoot()
				if err != nil {
					b.Fatalf("get root failed: %v", err)
				}
			}
		})
	})

	b.Run("Concurrent_GetPeaks", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_, err := mmr.GetPeaks()
				if err != nil {
					b.Fatalf("get peaks failed: %v", err)
				}
			}
		})
	})
}

// BenchmarkMMRGeometryFunctions benchmarks the MMR geometry helper functions.
func BenchmarkMMRGeometryFunctions(b *testing.B) {
	sizes := []uint64{100, 1000, 10000, 100000, 1000000}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("findPeaks_%d", size), func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				peaks := findPeaks(size)
				_ = peaks
			}
		})

		b.Run(fmt.Sprintf("leafCountFromSize_%d", size), func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				count := leafCountFromSize(size)
				_ = count
			}
		})

		b.Run(fmt.Sprintf("highestPeak_%d", size), func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				height := highestPeak(size)
				_ = height
			}
		})
	}
}

// BenchmarkMMRFileStoreScaling measures file store performance at different scales.
func BenchmarkMMRFileStoreScaling(b *testing.B) {
	sizes := []int{100, 1000, 5000}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("FileStore_Append_%d", size), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				tmpDir, _ := os.MkdirTemp("", "mmr_file_bench")
				storePath := filepath.Join(tmpDir, "bench.mmr")
				store, _ := OpenFileStore(storePath)
				mmr, _ := New(store)
				b.StartTimer()

				for j := 0; j < size; j++ {
					mmr.Append([]byte{byte(j), byte(j >> 8)})
				}

				b.StopTimer()
				store.Sync()
				store.Close()
				os.RemoveAll(tmpDir)
			}

			b.ReportMetric(float64(size), "leaves_appended")
		})
	}
}

// BenchmarkMMRStorageEfficiency reports storage overhead.
func BenchmarkMMRStorageEfficiency(b *testing.B) {
	tmpDir, err := os.MkdirTemp("", "mmr_efficiency")
	if err != nil {
		b.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	sizes := []int{100, 1000, 10000}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			avgDataSize := 64 // Typical checkpoint data size

			for i := 0; i < b.N; i++ {
				b.StopTimer()

				storePath := filepath.Join(tmpDir, fmt.Sprintf("efficiency_%d_%d.mmr", size, i))
				store, _ := OpenFileStore(storePath)
				mmr, _ := New(store)

				// Add data
				for j := 0; j < size; j++ {
					data := make([]byte, avgDataSize)
					for k := range data {
						data[k] = byte(j + k)
					}
					mmr.Append(data)
				}

				store.Sync()
				store.Close()

				b.StartTimer()

				// Measure file size
				info, _ := os.Stat(storePath)
				fileSize := info.Size()

				b.StopTimer()

				contentSize := int64(size * avgDataSize)
				overhead := float64(fileSize) / float64(contentSize)

				b.ReportMetric(float64(fileSize), "file_bytes")
				b.ReportMetric(float64(contentSize), "content_bytes")
				b.ReportMetric(overhead, "overhead_ratio")
				b.ReportMetric(float64(mmr.Size()), "total_nodes")

				os.Remove(storePath)
			}
		})
	}
}
