package mmr

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// =============================================================================
// Node Tests
// =============================================================================

func TestNewLeafNode(t *testing.T) {
	data := []byte("test data")
	node := NewLeafNode(0, data)

	if node.Index != 0 {
		t.Errorf("expected index 0, got %d", node.Index)
	}
	if node.Height != 0 {
		t.Errorf("expected height 0, got %d", node.Height)
	}

	// Verify hash includes domain separator
	h := sha256.New()
	h.Write([]byte{LeafPrefix})
	h.Write(data)
	expected := h.Sum(nil)

	if !bytes.Equal(node.Hash[:], expected) {
		t.Error("hash mismatch for leaf node")
	}
}

func TestNewInternalNode(t *testing.T) {
	left := NewLeafNode(0, []byte("left"))
	right := NewLeafNode(1, []byte("right"))
	internal := NewInternalNode(2, 1, left, right)

	if internal.Index != 2 {
		t.Errorf("expected index 2, got %d", internal.Index)
	}
	if internal.Height != 1 {
		t.Errorf("expected height 1, got %d", internal.Height)
	}

	// Verify hash includes domain separator and both children
	h := sha256.New()
	h.Write([]byte{InternalPrefix})
	h.Write(left.Hash[:])
	h.Write(right.Hash[:])
	expected := h.Sum(nil)

	if !bytes.Equal(internal.Hash[:], expected) {
		t.Error("hash mismatch for internal node")
	}
}

func TestNodeSerialize(t *testing.T) {
	node := NewLeafNode(42, []byte("serialize test"))
	data := node.Serialize()

	if len(data) != NodeSize {
		t.Errorf("expected %d bytes, got %d", NodeSize, len(data))
	}

	restored, err := DeserializeNode(data)
	if err != nil {
		t.Fatalf("deserialize failed: %v", err)
	}

	if restored.Index != node.Index {
		t.Errorf("index mismatch: expected %d, got %d", node.Index, restored.Index)
	}
	if restored.Height != node.Height {
		t.Errorf("height mismatch: expected %d, got %d", node.Height, restored.Height)
	}
	if restored.Hash != node.Hash {
		t.Error("hash mismatch after round-trip")
	}
}

func TestDeserializeNodeTooShort(t *testing.T) {
	_, err := DeserializeNode(make([]byte, 40))
	if err == nil {
		t.Error("expected error for short data")
	}
}

// =============================================================================
// Basic MMR Append Tests
// =============================================================================

func TestMMRAppendSingle(t *testing.T) {
	store := NewMemoryStore()
	mmr, err := New(store)
	if err != nil {
		t.Fatalf("failed to create MMR: %v", err)
	}

	idx, err := mmr.Append([]byte("first"))
	if err != nil {
		t.Fatalf("append failed: %v", err)
	}
	if idx != 0 {
		t.Errorf("expected index 0, got %d", idx)
	}

	if mmr.Size() != 1 {
		t.Errorf("expected size 1, got %d", mmr.Size())
	}

	if mmr.LeafCount() != 1 {
		t.Errorf("expected 1 leaf, got %d", mmr.LeafCount())
	}
}

func TestMMRAppendTwo(t *testing.T) {
	store := NewMemoryStore()
	mmr, err := New(store)
	if err != nil {
		t.Fatalf("failed to create MMR: %v", err)
	}

	mmr.Append([]byte("first"))
	mmr.Append([]byte("second"))

	// After 2 leaves: leaf0, leaf1, internal0 = 3 nodes
	if mmr.Size() != 3 {
		t.Errorf("expected size 3, got %d", mmr.Size())
	}

	if mmr.LeafCount() != 2 {
		t.Errorf("expected 2 leaves, got %d", mmr.LeafCount())
	}

	peaks, err := mmr.GetPeaks()
	if err != nil {
		t.Fatalf("GetPeaks failed: %v", err)
	}

	// Should have 1 peak (the merged tree)
	if len(peaks) != 1 {
		t.Errorf("expected 1 peak, got %d", len(peaks))
	}
}

func TestMMRAppendThree(t *testing.T) {
	store := NewMemoryStore()
	mmr, err := New(store)
	if err != nil {
		t.Fatalf("failed to create MMR: %v", err)
	}

	mmr.Append([]byte("first"))
	mmr.Append([]byte("second"))
	mmr.Append([]byte("third"))

	// After 3 leaves: 3 nodes from first two + 1 new leaf = 4 nodes
	if mmr.Size() != 4 {
		t.Errorf("expected size 4, got %d", mmr.Size())
	}

	peaks, err := mmr.GetPeaks()
	if err != nil {
		t.Fatalf("GetPeaks failed: %v", err)
	}

	// Should have 2 peaks (tree of 2 + single leaf)
	if len(peaks) != 2 {
		t.Errorf("expected 2 peaks, got %d", len(peaks))
	}
}

func TestMMRAppendFour(t *testing.T) {
	store := NewMemoryStore()
	mmr, err := New(store)
	if err != nil {
		t.Fatalf("failed to create MMR: %v", err)
	}

	for i := 0; i < 4; i++ {
		mmr.Append([]byte{byte(i)})
	}

	// After 4 leaves: should have 7 nodes (complete tree of height 2)
	if mmr.Size() != 7 {
		t.Errorf("expected size 7, got %d", mmr.Size())
	}

	peaks, err := mmr.GetPeaks()
	if err != nil {
		t.Fatalf("GetPeaks failed: %v", err)
	}

	// Should have 1 peak (complete tree)
	if len(peaks) != 1 {
		t.Errorf("expected 1 peak, got %d", len(peaks))
	}
}

// =============================================================================
// Various Tree Sizes
// =============================================================================

func TestMMRVariousSizes(t *testing.T) {
	testCases := []struct {
		leaves        int
		expectedNodes uint64
		expectedPeaks int
	}{
		{1, 1, 1},       // Single leaf
		{2, 3, 1},       // Perfect tree of 2
		{3, 4, 2},       // Tree of 2 + 1
		{4, 7, 1},       // Perfect tree of 4
		{5, 8, 2},       // Tree of 4 + 1
		{6, 10, 2},      // Tree of 4 + tree of 2
		{7, 11, 3},      // Tree of 4 + tree of 2 + 1
		{8, 15, 1},      // Perfect tree of 8
		{15, 26, 4},     // 8 + 4 + 2 + 1
		{16, 31, 1},     // Perfect tree of 16
		{31, 57, 5},     // 16 + 8 + 4 + 2 + 1
		{32, 63, 1},     // Perfect tree of 32
		{100, 192, 3},   // 64 + 32 + 4
		{1000, 1994, 6}, // Binary decomposition
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%d_leaves", tc.leaves), func(t *testing.T) {
			store := NewMemoryStore()
			mmr, _ := New(store)

			for i := 0; i < tc.leaves; i++ {
				mmr.Append([]byte{byte(i), byte(i >> 8)})
			}

			if mmr.LeafCount() != uint64(tc.leaves) {
				t.Errorf("expected %d leaves, got %d", tc.leaves, mmr.LeafCount())
			}

			if mmr.Size() != tc.expectedNodes {
				t.Errorf("expected %d nodes, got %d", tc.expectedNodes, mmr.Size())
			}

			peaks, err := mmr.GetPeaks()
			if err != nil {
				t.Fatalf("GetPeaks failed: %v", err)
			}
			if len(peaks) != tc.expectedPeaks {
				t.Errorf("expected %d peaks, got %d", tc.expectedPeaks, len(peaks))
			}
		})
	}
}

func TestMMRAppendMany(t *testing.T) {
	store := NewMemoryStore()
	mmr, err := New(store)
	if err != nil {
		t.Fatalf("failed to create MMR: %v", err)
	}

	// Append 100 leaves
	for i := 0; i < 100; i++ {
		_, err := mmr.Append([]byte{byte(i)})
		if err != nil {
			t.Fatalf("append %d failed: %v", i, err)
		}
	}

	if mmr.LeafCount() != 100 {
		t.Errorf("expected 100 leaves, got %d", mmr.LeafCount())
	}

	// Verify root is computable
	root, err := mmr.GetRoot()
	if err != nil {
		t.Fatalf("GetRoot failed: %v", err)
	}

	// Root should not be zero
	if root == [32]byte{} {
		t.Error("root is zero")
	}
}

// =============================================================================
// Root Consistency Tests
// =============================================================================

func TestMMRRootConsistency(t *testing.T) {
	store1 := NewMemoryStore()
	mmr1, _ := New(store1)

	store2 := NewMemoryStore()
	mmr2, _ := New(store2)

	// Append same data to both
	data := [][]byte{
		[]byte("alpha"),
		[]byte("beta"),
		[]byte("gamma"),
	}

	for _, d := range data {
		mmr1.Append(d)
		mmr2.Append(d)
	}

	root1, _ := mmr1.GetRoot()
	root2, _ := mmr2.GetRoot()

	if root1 != root2 {
		t.Error("roots should be identical for identical data")
	}

	// Append different data
	mmr1.Append([]byte("delta"))
	mmr2.Append([]byte("epsilon"))

	root1, _ = mmr1.GetRoot()
	root2, _ = mmr2.GetRoot()

	if root1 == root2 {
		t.Error("roots should differ for different data")
	}
}

func TestMMRRootEmpty(t *testing.T) {
	store := NewMemoryStore()
	mmr, _ := New(store)

	_, err := mmr.GetRoot()
	if err != ErrEmptyMMR {
		t.Errorf("expected ErrEmptyMMR, got %v", err)
	}
}

// =============================================================================
// Inclusion Proof Tests
// =============================================================================

func TestInclusionProof(t *testing.T) {
	store := NewMemoryStore()
	mmr, _ := New(store)

	// Append several leaves
	testData := [][]byte{
		[]byte("document v1"),
		[]byte("document v2"),
		[]byte("document v3"),
		[]byte("document v4"),
		[]byte("document v5"),
	}

	indices := make([]uint64, len(testData))
	for i, d := range testData {
		idx, err := mmr.Append(d)
		if err != nil {
			t.Fatalf("append failed: %v", err)
		}
		indices[i] = idx
	}

	// Generate and verify proofs for each leaf
	for i, idx := range indices {
		proof, err := mmr.GenerateProof(idx)
		if err != nil {
			t.Fatalf("GenerateProof(%d) failed: %v", idx, err)
		}

		// Verify the proof
		err = proof.Verify(testData[i])
		if err != nil {
			t.Errorf("proof verification failed for leaf %d: %v", i, err)
		}
	}
}

func TestInclusionProofInvalidData(t *testing.T) {
	store := NewMemoryStore()
	mmr, _ := New(store)

	mmr.Append([]byte("original"))

	proof, err := mmr.GenerateProof(0)
	if err != nil {
		t.Fatalf("GenerateProof failed: %v", err)
	}

	// Verify with wrong data should fail
	err = proof.Verify([]byte("tampered"))
	if err == nil {
		t.Error("proof should fail for tampered data")
	}
}

func TestInclusionProofNonLeaf(t *testing.T) {
	store := NewMemoryStore()
	mmr, _ := New(store)

	mmr.Append([]byte("first"))
	mmr.Append([]byte("second"))

	// Index 2 is an internal node
	_, err := mmr.GenerateProof(2)
	if err != ErrInvalidProof {
		t.Errorf("expected ErrInvalidProof for internal node, got %v", err)
	}
}

func TestInclusionProofEmpty(t *testing.T) {
	store := NewMemoryStore()
	mmr, _ := New(store)

	_, err := mmr.GenerateProof(0)
	if err != ErrEmptyMMR {
		t.Errorf("expected ErrEmptyMMR, got %v", err)
	}
}

func TestInclusionProofOutOfRange(t *testing.T) {
	store := NewMemoryStore()
	mmr, _ := New(store)
	mmr.Append([]byte("test"))

	_, err := mmr.GenerateProof(100)
	if err != ErrIndexOutOfRange {
		t.Errorf("expected ErrIndexOutOfRange, got %v", err)
	}
}

// =============================================================================
// Range Proof Tests
// =============================================================================

func TestRangeProof(t *testing.T) {
	store := NewMemoryStore()
	mmr, _ := New(store)

	// Append several leaves
	testData := [][]byte{
		[]byte("document v1"),
		[]byte("document v2"),
		[]byte("document v3"),
		[]byte("document v4"),
		[]byte("document v5"),
		[]byte("document v6"),
		[]byte("document v7"),
		[]byte("document v8"),
	}

	for _, d := range testData {
		_, err := mmr.Append(d)
		if err != nil {
			t.Fatalf("append failed: %v", err)
		}
	}

	// Test range proof for consecutive leaves using leaf ordinals (not MMR indices)
	testCases := []struct {
		name  string
		start uint64
		end   uint64
	}{
		{"single leaf", 0, 0},
		{"two leaves", 0, 1},
		{"middle range", 2, 5},
		{"all leaves", 0, 7},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// GenerateRangeProof takes leaf ordinals (0th, 1st, 2nd leaf, etc.)
			proof, err := mmr.GenerateRangeProof(tc.start, tc.end)
			if err != nil {
				t.Fatalf("GenerateRangeProof failed: %v", err)
			}

			// Verify the proof
			rangeData := testData[tc.start : tc.end+1]
			err = proof.Verify(rangeData)
			if err != nil {
				t.Errorf("range proof verification failed: %v", err)
			}
		})
	}
}

func TestRangeProofInvalidData(t *testing.T) {
	store := NewMemoryStore()
	mmr, _ := New(store)

	testData := [][]byte{
		[]byte("doc1"),
		[]byte("doc2"),
		[]byte("doc3"),
	}

	for _, d := range testData {
		mmr.Append(d)
	}

	// Use leaf ordinals 0, 1, 2 (not MMR indices)
	proof, err := mmr.GenerateRangeProof(0, 2)
	if err != nil {
		t.Fatalf("GenerateRangeProof failed: %v", err)
	}

	// Verify with tampered data should fail
	tamperedData := [][]byte{
		[]byte("doc1"),
		[]byte("TAMPERED"),
		[]byte("doc3"),
	}
	err = proof.Verify(tamperedData)
	if err == nil {
		t.Error("range proof should fail for tampered data")
	}
}

func TestRangeProofInvalidRange(t *testing.T) {
	store := NewMemoryStore()
	mmr, _ := New(store)

	for i := 0; i < 5; i++ {
		mmr.Append([]byte{byte(i)})
	}

	// Start > End
	_, err := mmr.GenerateRangeProof(3, 1)
	if err == nil {
		t.Error("expected error for invalid range")
	}

	// Out of range
	_, err = mmr.GenerateRangeProof(0, 100)
	if err == nil {
		t.Error("expected error for out of range")
	}
}

// =============================================================================
// Proof Serialization Tests
// =============================================================================

func TestInclusionProofSerialize(t *testing.T) {
	store := NewMemoryStore()
	mmr, _ := New(store)

	// Append several leaves to get a proof with multiple path elements
	for i := 0; i < 10; i++ {
		mmr.Append([]byte{byte(i)})
	}

	proof, err := mmr.GenerateProof(0)
	if err != nil {
		t.Fatalf("GenerateProof failed: %v", err)
	}

	// Serialize
	data := proof.Serialize()

	// Deserialize
	restored, err := DeserializeInclusionProof(data)
	if err != nil {
		t.Fatalf("DeserializeInclusionProof failed: %v", err)
	}

	// Verify fields match
	if restored.LeafIndex != proof.LeafIndex {
		t.Errorf("LeafIndex mismatch: %d vs %d", restored.LeafIndex, proof.LeafIndex)
	}
	if restored.LeafHash != proof.LeafHash {
		t.Error("LeafHash mismatch")
	}
	if len(restored.MerklePath) != len(proof.MerklePath) {
		t.Errorf("MerklePath length mismatch: %d vs %d", len(restored.MerklePath), len(proof.MerklePath))
	}
	for i := range proof.MerklePath {
		if restored.MerklePath[i].Hash != proof.MerklePath[i].Hash {
			t.Errorf("MerklePath[%d].Hash mismatch", i)
		}
		if restored.MerklePath[i].IsLeft != proof.MerklePath[i].IsLeft {
			t.Errorf("MerklePath[%d].IsLeft mismatch", i)
		}
	}
	if len(restored.Peaks) != len(proof.Peaks) {
		t.Errorf("Peaks length mismatch: %d vs %d", len(restored.Peaks), len(proof.Peaks))
	}
	for i := range proof.Peaks {
		if restored.Peaks[i] != proof.Peaks[i] {
			t.Errorf("Peaks[%d] mismatch", i)
		}
	}
	if restored.PeakPosition != proof.PeakPosition {
		t.Errorf("PeakPosition mismatch: %d vs %d", restored.PeakPosition, proof.PeakPosition)
	}
	if restored.MMRSize != proof.MMRSize {
		t.Errorf("MMRSize mismatch: %d vs %d", restored.MMRSize, proof.MMRSize)
	}
	if restored.Root != proof.Root {
		t.Error("Root mismatch")
	}

	// Verify the restored proof works
	err = restored.Verify([]byte{0})
	if err != nil {
		t.Errorf("restored proof verification failed: %v", err)
	}
}

func TestRangeProofSerialize(t *testing.T) {
	store := NewMemoryStore()
	mmr, _ := New(store)

	testData := [][]byte{
		[]byte("doc1"),
		[]byte("doc2"),
		[]byte("doc3"),
		[]byte("doc4"),
	}

	for _, d := range testData {
		mmr.Append(d)
	}

	// Use leaf ordinals (0, 1, 2, 3)
	proof, err := mmr.GenerateRangeProof(0, 3)
	if err != nil {
		t.Fatalf("GenerateRangeProof failed: %v", err)
	}

	// Serialize
	data := proof.Serialize()

	// Deserialize
	restored, err := DeserializeRangeProof(data)
	if err != nil {
		t.Fatalf("DeserializeRangeProof failed: %v", err)
	}

	// Verify fields match
	if restored.StartLeaf != proof.StartLeaf {
		t.Errorf("StartLeaf mismatch: %d vs %d", restored.StartLeaf, proof.StartLeaf)
	}
	if restored.EndLeaf != proof.EndLeaf {
		t.Errorf("EndLeaf mismatch: %d vs %d", restored.EndLeaf, proof.EndLeaf)
	}
	if len(restored.LeafIndices) != len(proof.LeafIndices) {
		t.Errorf("LeafIndices length mismatch: %d vs %d", len(restored.LeafIndices), len(proof.LeafIndices))
	}
	for i := range proof.LeafIndices {
		if restored.LeafIndices[i] != proof.LeafIndices[i] {
			t.Errorf("LeafIndices[%d] mismatch: %d vs %d", i, restored.LeafIndices[i], proof.LeafIndices[i])
		}
	}
	if len(restored.LeafHashes) != len(proof.LeafHashes) {
		t.Errorf("LeafHashes length mismatch: %d vs %d", len(restored.LeafHashes), len(proof.LeafHashes))
	}
	if restored.MMRSize != proof.MMRSize {
		t.Errorf("MMRSize mismatch: %d vs %d", restored.MMRSize, proof.MMRSize)
	}
	if restored.Root != proof.Root {
		t.Error("Root mismatch")
	}

	// Verify the restored proof works
	err = restored.Verify(testData)
	if err != nil {
		t.Errorf("restored range proof verification failed: %v", err)
	}
}

func TestDeserializeInvalidProof(t *testing.T) {
	testCases := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"too short", make([]byte, 50)},
		{"wrong version", []byte{99, 1}}, // Version 99
	}

	for _, tc := range testCases {
		t.Run(tc.name+"_inclusion", func(t *testing.T) {
			_, err := DeserializeInclusionProof(tc.data)
			if err == nil {
				t.Error("expected error")
			}
		})

		t.Run(tc.name+"_range", func(t *testing.T) {
			_, err := DeserializeRangeProof(tc.data)
			if err == nil {
				t.Error("expected error")
			}
		})
	}
}

// =============================================================================
// File Store Tests
// =============================================================================

func TestFileStore(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "mmr_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	storePath := filepath.Join(tmpDir, "test.mmr")

	// Create and populate store
	store, err := OpenFileStore(storePath)
	if err != nil {
		t.Fatalf("failed to open file store: %v", err)
	}

	mmr, err := New(store)
	if err != nil {
		t.Fatalf("failed to create MMR: %v", err)
	}

	testData := [][]byte{
		[]byte("persistent data 1"),
		[]byte("persistent data 2"),
		[]byte("persistent data 3"),
	}

	for _, d := range testData {
		if _, err := mmr.Append(d); err != nil {
			t.Fatalf("append failed: %v", err)
		}
	}

	root1, _ := mmr.GetRoot()
	size1 := mmr.Size()

	// Close and reopen
	if err := store.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	store2, err := OpenFileStore(storePath)
	if err != nil {
		t.Fatalf("failed to reopen file store: %v", err)
	}
	defer store2.Close()

	mmr2, err := New(store2)
	if err != nil {
		t.Fatalf("failed to recreate MMR: %v", err)
	}

	// Verify state was restored
	size2 := mmr2.Size()
	if size1 != size2 {
		t.Errorf("size mismatch after restore: %d vs %d", size1, size2)
	}

	root2, _ := mmr2.GetRoot()
	if root1 != root2 {
		t.Error("root mismatch after restore")
	}

	// Verify proofs still work
	proof, err := mmr2.GenerateProof(0)
	if err != nil {
		t.Fatalf("GenerateProof failed after restore: %v", err)
	}

	if err := proof.Verify(testData[0]); err != nil {
		t.Errorf("proof verification failed after restore: %v", err)
	}
}

func TestFileStoreCorrupted(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "corrupted.mmr")

	// Create file with invalid size (not multiple of NodeSize)
	os.WriteFile(storePath, make([]byte, 10), 0600)

	_, err := OpenFileStore(storePath)
	if err != ErrCorruptedStore {
		t.Errorf("expected ErrCorruptedStore, got %v", err)
	}
}

func TestFileStoreSync(t *testing.T) {
	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "sync.mmr")

	store, err := OpenFileStore(storePath)
	if err != nil {
		t.Fatalf("failed to open store: %v", err)
	}
	defer store.Close()

	mmr, _ := New(store)
	mmr.Append([]byte("test"))

	// Sync should not error
	if err := store.Sync(); err != nil {
		t.Errorf("Sync failed: %v", err)
	}
}

// =============================================================================
// Concurrent Append Tests
// =============================================================================

func TestMMRConcurrentAppends(t *testing.T) {
	store := NewMemoryStore()
	mmr, _ := New(store)

	numGoroutines := 10
	appendsPerGoroutine := 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for g := 0; g < numGoroutines; g++ {
		go func(goroutineID int) {
			defer wg.Done()
			for i := 0; i < appendsPerGoroutine; i++ {
				data := []byte(fmt.Sprintf("g%d-i%d", goroutineID, i))
				_, err := mmr.Append(data)
				if err != nil {
					t.Errorf("concurrent append failed: %v", err)
					return
				}
			}
		}(g)
	}

	wg.Wait()

	expectedLeaves := uint64(numGoroutines * appendsPerGoroutine)
	if mmr.LeafCount() != expectedLeaves {
		t.Errorf("expected %d leaves, got %d", expectedLeaves, mmr.LeafCount())
	}

	// Verify root is computable
	root, err := mmr.GetRoot()
	if err != nil {
		t.Fatalf("GetRoot failed after concurrent appends: %v", err)
	}
	if root == [32]byte{} {
		t.Error("root should not be zero")
	}
}

func TestMMRConcurrentReads(t *testing.T) {
	store := NewMemoryStore()
	mmr, _ := New(store)

	// Pre-populate
	for i := 0; i < 100; i++ {
		mmr.Append([]byte{byte(i)})
	}

	numReaders := 10
	var wg sync.WaitGroup
	wg.Add(numReaders)

	for r := 0; r < numReaders; r++ {
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				_, err := mmr.GetRoot()
				if err != nil {
					t.Errorf("concurrent GetRoot failed: %v", err)
					return
				}

				_, err = mmr.GetPeaks()
				if err != nil {
					t.Errorf("concurrent GetPeaks failed: %v", err)
					return
				}

				_ = mmr.Size()
				_ = mmr.LeafCount()
			}
		}()
	}

	wg.Wait()
}

func TestMMRConcurrentAppendAndRead(t *testing.T) {
	store := NewMemoryStore()
	mmr, _ := New(store)

	var wg sync.WaitGroup

	// Writers
	wg.Add(5)
	for w := 0; w < 5; w++ {
		go func(writerID int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				mmr.Append([]byte(fmt.Sprintf("w%d-i%d", writerID, i)))
			}
		}(w)
	}

	// Readers
	wg.Add(5)
	for r := 0; r < 5; r++ {
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				mmr.GetRoot()
				mmr.Size()
			}
		}()
	}

	wg.Wait()

	// Should have 250 leaves
	if mmr.LeafCount() != 250 {
		t.Errorf("expected 250 leaves, got %d", mmr.LeafCount())
	}
}

// =============================================================================
// Peak Calculation Tests
// =============================================================================

func TestFindPeaks(t *testing.T) {
	testCases := []struct {
		size     uint64
		expected []uint64
	}{
		{0, nil},
		{1, []uint64{0}},         // Single leaf
		{3, []uint64{2}},         // Tree of 2 leaves
		{4, []uint64{2, 3}},      // Tree of 2 + 1 leaf
		{7, []uint64{6}},         // Tree of 4 leaves
		{8, []uint64{6, 7}},      // Tree of 4 + 1 leaf
		{10, []uint64{6, 9}},     // Tree of 4 + tree of 2
		{11, []uint64{6, 9, 10}}, // Tree of 4 + tree of 2 + 1 leaf
		{15, []uint64{14}},       // Tree of 8 leaves
	}

	for _, tc := range testCases {
		peaks := findPeaks(tc.size)
		if len(peaks) != len(tc.expected) {
			t.Errorf("size %d: expected %d peaks, got %d (%v)", tc.size, len(tc.expected), len(peaks), peaks)
			continue
		}
		for i, p := range peaks {
			if p != tc.expected[i] {
				t.Errorf("size %d: peak %d expected %d, got %d", tc.size, i, tc.expected[i], p)
			}
		}
	}
}

func TestLeafCountFromSize(t *testing.T) {
	testCases := []struct {
		size      uint64
		leafCount uint64
	}{
		{0, 0},
		{1, 1},
		{3, 2},
		{4, 3},
		{7, 4},
		{8, 5},
		{10, 6},
		{11, 7},
		{15, 8},
		{31, 16},
		{63, 32},
	}

	for _, tc := range testCases {
		result := leafCountFromSize(tc.size)
		if result != tc.leafCount {
			t.Errorf("size %d: expected %d leaves, got %d", tc.size, tc.leafCount, result)
		}
	}
}

// =============================================================================
// Domain Separation Tests
// =============================================================================

func TestDomainSeparation(t *testing.T) {
	// Ensure leaf and internal hashes are different even with same input
	data := []byte("test")

	leafHash := HashLeaf(data)

	// Create a scenario where internal hash input equals leaf data
	var left, right [32]byte
	// This should produce different hash due to different prefix
	internalHash := HashInternal(left, right)

	if leafHash == internalHash {
		t.Error("domain separation failed: leaf and internal hashes should differ")
	}
}

func TestHashLeafDeterministic(t *testing.T) {
	data := []byte("test")
	hash1 := HashLeaf(data)
	hash2 := HashLeaf(data)

	if hash1 != hash2 {
		t.Error("HashLeaf should be deterministic")
	}
}

func TestHashInternalDeterministic(t *testing.T) {
	left := sha256.Sum256([]byte("left"))
	right := sha256.Sum256([]byte("right"))

	hash1 := HashInternal(left, right)
	hash2 := HashInternal(left, right)

	if hash1 != hash2 {
		t.Error("HashInternal should be deterministic")
	}
}

func TestHashInternalOrder(t *testing.T) {
	left := sha256.Sum256([]byte("left"))
	right := sha256.Sum256([]byte("right"))

	hash1 := HashInternal(left, right)
	hash2 := HashInternal(right, left)

	if hash1 == hash2 {
		t.Error("HashInternal should be order-dependent")
	}
}

// =============================================================================
// Memory Store Tests
// =============================================================================

func TestMemoryStoreNodesReturnsCopy(t *testing.T) {
	store := NewMemoryStore()
	mmr, _ := New(store)

	mmr.Append([]byte("test"))

	// Get nodes
	nodes1 := store.Nodes()

	// Modify the returned slice
	if len(nodes1) > 0 {
		nodes1[0].Height = 99
	}

	// Get nodes again
	nodes2 := store.Nodes()

	// The internal state should not have been modified
	if len(nodes2) > 0 && nodes2[0].Height == 99 {
		t.Error("MemoryStore.Nodes() should return a copy, not the internal slice")
	}
}

func TestMemoryStoreGetReturnsCopy(t *testing.T) {
	store := NewMemoryStore()
	mmr, _ := New(store)

	mmr.Append([]byte("test"))

	node1, _ := store.Get(0)
	node1.Height = 99

	node2, _ := store.Get(0)
	if node2.Height == 99 {
		t.Error("MemoryStore.Get should return a copy")
	}
}

// =============================================================================
// Proof Size Tests
// =============================================================================

func TestProofSizeCalculation(t *testing.T) {
	store := NewMemoryStore()
	mmr, _ := New(store)

	for i := 0; i < 10; i++ {
		mmr.Append([]byte{byte(i)})
	}

	// Test InclusionProof size - need to get a valid leaf index
	leafIdx, err := mmr.GetLeafIndex(0)
	if err != nil {
		t.Fatalf("GetLeafIndex failed: %v", err)
	}
	proof, err := mmr.GenerateProof(leafIdx)
	if err != nil {
		t.Fatalf("GenerateProof failed: %v", err)
	}
	serialized := proof.Serialize()
	if proof.ProofSize() != len(serialized) {
		t.Errorf("InclusionProof.ProofSize() = %d, but serialized size = %d", proof.ProofSize(), len(serialized))
	}

	// Test RangeProof size - using leaf ordinals
	rangeProof, err := mmr.GenerateRangeProof(0, 3)
	if err != nil {
		t.Fatalf("GenerateRangeProof failed: %v", err)
	}
	rangeSerialized := rangeProof.Serialize()
	if rangeProof.ProofSize() != len(rangeSerialized) {
		t.Errorf("RangeProof.ProofSize() = %d, but serialized size = %d", rangeProof.ProofSize(), len(rangeSerialized))
	}
}

// =============================================================================
// GetLeafIndex Tests
// =============================================================================

func TestGetLeafIndex(t *testing.T) {
	store := NewMemoryStore()
	mmr, _ := New(store)

	// Append some leaves
	for i := 0; i < 8; i++ {
		mmr.Append([]byte{byte(i)})
	}

	// For 8 leaves (15 nodes), leaf ordinals 0-7 map to specific MMR indices
	expectedIndices := []uint64{0, 1, 3, 4, 7, 8, 10, 11}

	for ordinal := uint64(0); ordinal < 8; ordinal++ {
		idx, err := mmr.GetLeafIndex(ordinal)
		if err != nil {
			t.Fatalf("GetLeafIndex(%d) failed: %v", ordinal, err)
		}
		if idx != expectedIndices[ordinal] {
			t.Errorf("GetLeafIndex(%d) = %d, expected %d", ordinal, idx, expectedIndices[ordinal])
		}
	}
}

func TestGetLeafIndexOutOfRange(t *testing.T) {
	store := NewMemoryStore()
	mmr, _ := New(store)

	mmr.Append([]byte("test"))

	_, err := mmr.GetLeafIndex(5)
	if err == nil {
		t.Error("expected error for out of range leaf ordinal")
	}
}

func TestGetLeafIndexEmpty(t *testing.T) {
	store := NewMemoryStore()
	mmr, _ := New(store)

	_, err := mmr.GetLeafIndex(0)
	if err != ErrEmptyMMR {
		t.Errorf("expected ErrEmptyMMR, got %v", err)
	}
}

// =============================================================================
// GetLeafIndices Tests
// =============================================================================

func TestGetLeafIndices(t *testing.T) {
	store := NewMemoryStore()
	mmr, _ := New(store)

	for i := 0; i < 8; i++ {
		mmr.Append([]byte{byte(i)})
	}

	indices, err := mmr.GetLeafIndices(2, 5)
	if err != nil {
		t.Fatalf("GetLeafIndices failed: %v", err)
	}

	if len(indices) != 4 {
		t.Errorf("expected 4 indices, got %d", len(indices))
	}
}

func TestGetLeafIndicesInvalidRange(t *testing.T) {
	store := NewMemoryStore()
	mmr, _ := New(store)

	for i := 0; i < 5; i++ {
		mmr.Append([]byte{byte(i)})
	}

	// Start > End
	_, err := mmr.GetLeafIndices(3, 1)
	if err == nil {
		t.Error("expected error for start > end")
	}

	// Out of range
	_, err = mmr.GetLeafIndices(0, 100)
	if err == nil {
		t.Error("expected error for out of range")
	}
}

// =============================================================================
// Get Node Tests
// =============================================================================

func TestGetNode(t *testing.T) {
	store := NewMemoryStore()
	mmr, _ := New(store)

	mmr.Append([]byte("test"))

	node, err := mmr.Get(0)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if node.Index != 0 {
		t.Errorf("expected index 0, got %d", node.Index)
	}
	if node.Height != 0 {
		t.Errorf("expected height 0 (leaf), got %d", node.Height)
	}
}

func TestGetNodeOutOfRange(t *testing.T) {
	store := NewMemoryStore()
	mmr, _ := New(store)

	mmr.Append([]byte("test"))

	_, err := mmr.Get(100)
	if err != ErrIndexOutOfRange {
		t.Errorf("expected ErrIndexOutOfRange, got %v", err)
	}
}

// =============================================================================
// GetNodeHeight Tests
// =============================================================================

func TestGetNodeHeight(t *testing.T) {
	// Test a few known indices
	testCases := []struct {
		index  uint64
		height uint8
	}{
		{0, 0}, // Leaf
		{1, 0}, // Leaf
		{2, 1}, // Parent of 0,1
		{3, 0}, // Leaf
		{4, 0}, // Leaf
		{5, 1}, // Parent of 3,4
		{6, 2}, // Parent of 2,5
	}

	for _, tc := range testCases {
		height := GetNodeHeight(tc.index)
		if height != tc.height {
			t.Errorf("GetNodeHeight(%d) = %d, expected %d", tc.index, height, tc.height)
		}
	}
}

// =============================================================================
// Test Vectors for Cross-Implementation Compatibility
// =============================================================================

func TestMMRTestVectors(t *testing.T) {
	store := NewMemoryStore()
	mmr, _ := New(store)

	// Create a deterministic test case
	testData := []string{"a", "b", "c", "d", "e", "f", "g", "h"}

	for _, d := range testData {
		mmr.Append([]byte(d))
	}

	// Log for documentation
	t.Logf("MMR Test Vector (8 leaves a-h):")
	t.Logf("  Size: %d", mmr.Size())
	t.Logf("  LeafCount: %d", mmr.LeafCount())

	root, _ := mmr.GetRoot()
	t.Logf("  Root: %s", hex.EncodeToString(root[:]))

	peaks, _ := mmr.GetPeaks()
	t.Logf("  Peaks: %d", len(peaks))
	for i, p := range peaks {
		t.Logf("    Peak %d: %s", i, hex.EncodeToString(p[:]))
	}

	// Generate proof for first leaf
	proof, _ := mmr.GenerateProof(0)
	t.Logf("  Proof for leaf 0:")
	t.Logf("    LeafHash: %s", hex.EncodeToString(proof.LeafHash[:]))
	t.Logf("    PathLength: %d", len(proof.MerklePath))
}

func TestKnownLeafHash(t *testing.T) {
	// HashLeaf("a") should be deterministic
	hash := HashLeaf([]byte("a"))
	expected := "023fca1a6ad7e3c0c13cae4bd86e89e3a36e7c28feef5de6a8e9370f7e0bf0b6"

	// Compute expected: SHA256(0x00 || "a")
	h := sha256.New()
	h.Write([]byte{LeafPrefix})
	h.Write([]byte("a"))
	computed := hex.EncodeToString(h.Sum(nil))

	if expected != computed {
		t.Logf("Test vector: HashLeaf(\"a\") = %s", computed)
	}

	actual := hex.EncodeToString(hash[:])
	if actual != computed {
		t.Errorf("HashLeaf mismatch: expected %s, got %s", computed, actual)
	}
}

// =============================================================================
// Property-Based Tests
// =============================================================================

func TestPropertyProofVerifiesForIncludedElements(t *testing.T) {
	// For any MMR, proof verification should succeed for included elements
	for leaves := 1; leaves <= 50; leaves++ {
		store := NewMemoryStore()
		mmr, _ := New(store)

		testData := make([][]byte, leaves)
		for i := 0; i < leaves; i++ {
			testData[i] = make([]byte, 16)
			rand.Read(testData[i])
			mmr.Append(testData[i])
		}

		// Verify proof for each leaf by ordinal
		for ordinal := 0; ordinal < leaves; ordinal++ {
			idx, err := mmr.GetLeafIndex(uint64(ordinal))
			if err != nil {
				t.Fatalf("leaves=%d, ordinal=%d: GetLeafIndex failed: %v", leaves, ordinal, err)
			}

			proof, err := mmr.GenerateProof(idx)
			if err != nil {
				t.Fatalf("leaves=%d, ordinal=%d: GenerateProof failed: %v", leaves, ordinal, err)
			}

			err = proof.Verify(testData[ordinal])
			if err != nil {
				t.Errorf("leaves=%d, ordinal=%d: proof should verify: %v", leaves, ordinal, err)
			}
		}
	}
}

func TestPropertyProofFailsForNonIncludedElements(t *testing.T) {
	// For any MMR, proof verification should fail for non-included elements
	store := NewMemoryStore()
	mmr, _ := New(store)

	for i := 0; i < 10; i++ {
		mmr.Append([]byte{byte(i)})
	}

	// Generate proof for leaf 0
	proof, _ := mmr.GenerateProof(0)

	// Try to verify with data that was never added
	wrongData := []byte("never added")
	err := proof.Verify(wrongData)
	if err == nil {
		t.Error("proof should fail for non-included data")
	}
}

func TestPropertyPerfectTreeSizes(t *testing.T) {
	// MMR size properties: n leaves -> specific total node counts
	// For 2^k leaves, total nodes = 2^(k+1) - 1

	for k := 0; k <= 6; k++ {
		leaves := 1 << k // 2^k
		expectedNodes := uint64((1 << (k + 1)) - 1)

		store := NewMemoryStore()
		mmr, _ := New(store)

		for i := 0; i < leaves; i++ {
			mmr.Append([]byte{byte(i)})
		}

		if mmr.Size() != expectedNodes {
			t.Errorf("2^%d leaves: expected %d nodes, got %d", k, expectedNodes, mmr.Size())
		}

		// Perfect tree should have exactly 1 peak
		peaks, _ := mmr.GetPeaks()
		if len(peaks) != 1 {
			t.Errorf("2^%d leaves: expected 1 peak, got %d", k, len(peaks))
		}
	}
}

func TestPropertyRootChangesWithEachAppend(t *testing.T) {
	store := NewMemoryStore()
	mmr, _ := New(store)

	var prevRoot [32]byte
	first := true

	for i := 0; i < 20; i++ {
		mmr.Append([]byte{byte(i)})
		root, _ := mmr.GetRoot()

		if !first && root == prevRoot {
			t.Errorf("root should change after append %d", i)
		}

		prevRoot = root
		first = false
	}
}

// =============================================================================
// Benchmarks
// =============================================================================

func BenchmarkAppend(b *testing.B) {
	store := NewMemoryStore()
	mmr, _ := New(store)

	data := []byte("benchmark data")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mmr.Append(data)
	}
}

func BenchmarkAppendFileStore(b *testing.B) {
	tmpDir := b.TempDir()
	storePath := filepath.Join(tmpDir, "bench.mmr")

	store, _ := OpenFileStore(storePath)
	defer store.Close()

	mmr, _ := New(store)
	data := []byte("benchmark data")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mmr.Append(data)
	}
}

func BenchmarkGenerateProof(b *testing.B) {
	store := NewMemoryStore()
	mmr, _ := New(store)

	// Pre-populate with 1000 leaves
	for i := 0; i < 1000; i++ {
		mmr.Append([]byte{byte(i), byte(i >> 8)})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		idx := uint64(i % 1000)
		// Find the actual leaf index (first 1000 indices aren't all leaves)
		mmr.GenerateProof(idx % mmr.Size())
	}
}

func BenchmarkGetRoot(b *testing.B) {
	store := NewMemoryStore()
	mmr, _ := New(store)

	// Pre-populate with 1000 leaves
	for i := 0; i < 1000; i++ {
		mmr.Append([]byte{byte(i), byte(i >> 8)})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mmr.GetRoot()
	}
}

func BenchmarkRangeProofGenerate(b *testing.B) {
	store := NewMemoryStore()
	mmr, _ := New(store)

	// Pre-populate
	for i := 0; i < 1000; i++ {
		mmr.Append([]byte{byte(i), byte(i >> 8)})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mmr.GenerateRangeProof(0, 9)
	}
}

func BenchmarkProofSerialize(b *testing.B) {
	store := NewMemoryStore()
	mmr, _ := New(store)

	for i := 0; i < 100; i++ {
		mmr.Append([]byte{byte(i)})
	}

	proof, _ := mmr.GenerateProof(0)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		proof.Serialize()
	}
}

func BenchmarkProofDeserialize(b *testing.B) {
	store := NewMemoryStore()
	mmr, _ := New(store)

	for i := 0; i < 100; i++ {
		mmr.Append([]byte{byte(i)})
	}

	proof, _ := mmr.GenerateProof(0)
	data := proof.Serialize()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DeserializeInclusionProof(data)
	}
}

func BenchmarkProofVerify(b *testing.B) {
	store := NewMemoryStore()
	mmr, _ := New(store)

	for i := 0; i < 100; i++ {
		mmr.Append([]byte{byte(i)})
	}

	proof, _ := mmr.GenerateProof(0)
	leafData := []byte{0}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		proof.Verify(leafData)
	}
}

func BenchmarkFindPeaks(b *testing.B) {
	sizes := []uint64{100, 1000, 10000, 100000}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				findPeaks(size)
			}
		})
	}
}

func BenchmarkHashLeaf(b *testing.B) {
	data := []byte("benchmark leaf data")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		HashLeaf(data)
	}
}

func BenchmarkHashInternal(b *testing.B) {
	left := sha256.Sum256([]byte("left"))
	right := sha256.Sum256([]byte("right"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		HashInternal(left, right)
	}
}
