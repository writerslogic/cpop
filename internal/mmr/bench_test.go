package mmr

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// BenchmarkWritingSession simulates a 4-hour writing session
// with edits every 30 seconds (480 edits total).
func BenchmarkWritingSession(b *testing.B) {
	tmpDir, err := os.MkdirTemp("", "mmr_bench")
	if err != nil {
		b.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	storePath := filepath.Join(tmpDir, "bench.mmr")

	// Simulate 480 edits (4 hours * 2 edits/minute)
	editsPerSession := 480

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		store, _ := OpenFileStore(storePath)
		mmr, _ := New(store)

		for j := 0; j < editsPerSession; j++ {
			data := []byte(fmt.Sprintf("edit-%d-%d", i, j))
			mmr.Append(data)
		}

		store.Sync()
		store.Close()
		os.Remove(storePath)
	}

	b.ReportMetric(float64(editsPerSession), "edits/session")
}

// BenchmarkMMRScaling measures MMR performance at different scales.
func BenchmarkMMRScaling(b *testing.B) {
	sizes := []int{100, 1000, 10000}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("Append_%d", size), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				store := NewMemoryStore()
				mmr, _ := New(store)

				for j := 0; j < size; j++ {
					mmr.Append([]byte{byte(j), byte(j >> 8)})
				}
			}
		})
	}
}

// BenchmarkProofAtScale measures proof generation at different MMR sizes.
func BenchmarkProofAtScale(b *testing.B) {
	sizes := []int{100, 1000, 10000}

	for _, size := range sizes {
		store := NewMemoryStore()
		mmr, _ := New(store)

		// Pre-populate
		var leafIndices []uint64
		for i := 0; i < size; i++ {
			idx, _ := mmr.Append([]byte{byte(i), byte(i >> 8)})
			if i%100 == 0 {
				leafIndices = append(leafIndices, idx)
			}
		}

		b.Run(fmt.Sprintf("Proof_%d", size), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				idx := leafIndices[i%len(leafIndices)]
				mmr.GenerateProof(idx)
			}
		})
	}
}

// BenchmarkRootComputation measures root computation at different scales.
func BenchmarkRootComputation(b *testing.B) {
	sizes := []int{100, 1000, 10000}

	for _, size := range sizes {
		store := NewMemoryStore()
		mmr, _ := New(store)

		for i := 0; i < size; i++ {
			mmr.Append([]byte{byte(i), byte(i >> 8)})
		}

		b.Run(fmt.Sprintf("Root_%d", size), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				mmr.GetRoot()
			}
		})
	}
}

// BenchmarkStorageOverhead reports storage efficiency.
func BenchmarkStorageOverhead(b *testing.B) {
	tmpDir, err := os.MkdirTemp("", "mmr_overhead")
	if err != nil {
		b.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	edits := 1000
	avgEditSize := 100 // bytes of "content" per edit

	storePath := filepath.Join(tmpDir, "overhead.mmr")
	store, _ := OpenFileStore(storePath)
	mmr, _ := New(store)

	// Simulate edits
	for i := 0; i < edits; i++ {
		data := make([]byte, avgEditSize)
		for j := range data {
			data[j] = byte(i + j)
		}
		mmr.Append(data)
	}

	store.Sync()

	info, _ := os.Stat(storePath)
	dbSize := info.Size()
	contentSize := int64(edits * avgEditSize)

	overhead := float64(dbSize) / float64(contentSize)

	b.ReportMetric(float64(dbSize), "db_bytes")
	b.ReportMetric(float64(contentSize), "content_bytes")
	b.ReportMetric(overhead, "overhead_ratio")
	b.ReportMetric(float64(mmr.Size()), "total_nodes")
	b.ReportMetric(float64(mmr.LeafCount()), "leaves")

	store.Close()
}

// BenchmarkVerification measures proof verification time.
func BenchmarkVerification(b *testing.B) {
	store := NewMemoryStore()
	mmr, _ := New(store)

	// Create test data
	testData := make([][]byte, 1000)
	leafIndices := make([]uint64, 1000)

	for i := 0; i < 1000; i++ {
		testData[i] = []byte(fmt.Sprintf("document-v%d", i))
		idx, _ := mmr.Append(testData[i])
		leafIndices[i] = idx
	}

	// Generate proofs
	proofs := make([]*InclusionProof, 100)
	for i := 0; i < 100; i++ {
		proofs[i], _ = mmr.GenerateProof(leafIndices[i*10])
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		idx := i % 100
		proofs[idx].Verify(testData[idx*10])
	}
}
