// Package internal provides integration tests for the witnessd cryptographic core.
//
// These tests verify the complete evidence verification pipeline:
// 1. Create document checkpoints with VDF proofs
// 2. Append checkpoint hashes to an MMR
// 3. Generate and verify inclusion proofs
// 4. Verify the complete evidence chain
package internal

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"witnessd/internal/checkpoint"
	"witnessd/internal/mmr"
	"witnessd/internal/vdf"
)

// =============================================================================
// INTEGRATION: Full Evidence Pipeline
// =============================================================================

// TestFullEvidencePipeline tests the complete flow from document creation
// through checkpoint commit, MMR storage, and proof verification.
func TestFullEvidencePipeline(t *testing.T) {
	tmpDir := t.TempDir()

	// Step 1: Create a document
	docPath := filepath.Join(tmpDir, "evidence.txt")
	initialContent := []byte("Initial document content - version 1")
	if err := os.WriteFile(docPath, initialContent, 0644); err != nil {
		t.Fatalf("Failed to create document: %v", err)
	}

	// Step 2: Create checkpoint chain with fast VDF params for testing
	vdfParams := vdf.Parameters{
		IterationsPerSecond: 1_000_000,
		MinIterations:       100,
		MaxIterations:       10_000,
	}

	chain, err := checkpoint.NewChain(docPath, vdfParams)
	if err != nil {
		t.Fatalf("Failed to create chain: %v", err)
	}

	// Step 3: Create MMR for storing checkpoint hashes
	mmrStore := mmr.NewMemoryStore()
	mmrTree, err := mmr.New(mmrStore)
	if err != nil {
		t.Fatalf("Failed to create MMR: %v", err)
	}

	// Step 4: Create first checkpoint and add to MMR
	cp1, err := chain.Commit("Initial version")
	if err != nil {
		t.Fatalf("Failed to create first checkpoint: %v", err)
	}

	leafIdx1, err := mmrTree.Append(cp1.Hash[:])
	if err != nil {
		t.Fatalf("Failed to append checkpoint to MMR: %v", err)
	}
	t.Logf("Checkpoint 1 added at MMR index %d", leafIdx1)

	// Step 5: Modify document and create second checkpoint
	updatedContent := []byte("Updated document content - version 2")
	if err := os.WriteFile(docPath, updatedContent, 0644); err != nil {
		t.Fatalf("Failed to update document: %v", err)
	}

	// Wait a small amount to ensure timestamp difference
	time.Sleep(10 * time.Millisecond)

	cp2, err := chain.CommitWithVDFDuration("Second version", 100*time.Millisecond)
	if err != nil {
		t.Fatalf("Failed to create second checkpoint: %v", err)
	}

	leafIdx2, err := mmrTree.Append(cp2.Hash[:])
	if err != nil {
		t.Fatalf("Failed to append second checkpoint to MMR: %v", err)
	}
	t.Logf("Checkpoint 2 added at MMR index %d", leafIdx2)

	// Step 6: Verify checkpoint chain integrity
	if err := chain.Verify(); err != nil {
		t.Fatalf("Checkpoint chain verification failed: %v", err)
	}
	t.Log("Checkpoint chain verified successfully")

	// Step 7: Generate inclusion proof for first checkpoint
	proof1, err := mmrTree.GenerateProof(leafIdx1)
	if err != nil {
		t.Fatalf("Failed to generate proof for checkpoint 1: %v", err)
	}

	// Step 8: Verify inclusion proof
	if err := proof1.Verify(cp1.Hash[:]); err != nil {
		t.Fatalf("Inclusion proof verification failed for checkpoint 1: %v", err)
	}
	t.Log("Checkpoint 1 inclusion proof verified")

	// Step 9: Generate and verify proof for second checkpoint
	proof2, err := mmrTree.GenerateProof(leafIdx2)
	if err != nil {
		t.Fatalf("Failed to generate proof for checkpoint 2: %v", err)
	}

	if err := proof2.Verify(cp2.Hash[:]); err != nil {
		t.Fatalf("Inclusion proof verification failed for checkpoint 2: %v", err)
	}
	t.Log("Checkpoint 2 inclusion proof verified")

	// Step 10: Verify VDF proofs
	if cp2.VDF == nil {
		t.Fatal("Second checkpoint should have VDF proof")
	}
	if !vdf.Verify(cp2.VDF) {
		t.Fatal("VDF proof verification failed")
	}
	t.Log("VDF proof verified")

	// Summary
	summary := chain.Summary()
	t.Logf("Chain Summary: %d checkpoints, valid=%v", summary.CheckpointCount, summary.ChainValid)
}

// TestMultiVersionDocumentEvidence tests creating evidence for multiple
// document versions and verifying the complete history.
func TestMultiVersionDocumentEvidence(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := filepath.Join(tmpDir, "manuscript.txt")

	// Fast VDF params for testing
	vdfParams := vdf.Parameters{
		IterationsPerSecond: 1_000_000,
		MinIterations:       100,
		MaxIterations:       10_000,
	}

	// Create initial document
	if err := os.WriteFile(docPath, []byte("Chapter 1: The Beginning"), 0644); err != nil {
		t.Fatalf("Failed to create document: %v", err)
	}

	chain, err := checkpoint.NewChain(docPath, vdfParams)
	if err != nil {
		t.Fatalf("Failed to create chain: %v", err)
	}

	mmrStore := mmr.NewMemoryStore()
	mmrTree, err := mmr.New(mmrStore)
	if err != nil {
		t.Fatalf("Failed to create MMR: %v", err)
	}

	// Simulate multiple editing sessions
	versions := []struct {
		content string
		message string
	}{
		{"Chapter 1: The Beginning", "Initial draft"},
		{"Chapter 1: The Beginning\nChapter 2: The Journey", "Added chapter 2"},
		{"Chapter 1: The Beginning\nChapter 2: The Journey\nChapter 3: The End", "Added chapter 3"},
		{"Chapter 1: The Beginning (Revised)\nChapter 2: The Journey\nChapter 3: The End", "Revised chapter 1"},
	}

	checkpoints := make([]*checkpoint.Checkpoint, 0)
	leafIndices := make([]uint64, 0)

	for i, v := range versions {
		// Write content
		if err := os.WriteFile(docPath, []byte(v.content), 0644); err != nil {
			t.Fatalf("Failed to write version %d: %v", i+1, err)
		}

		// Create checkpoint
		var cp *checkpoint.Checkpoint
		if i == 0 {
			cp, err = chain.Commit(v.message)
		} else {
			cp, err = chain.CommitWithVDFDuration(v.message, 50*time.Millisecond)
		}
		if err != nil {
			t.Fatalf("Failed to commit version %d: %v", i+1, err)
		}
		checkpoints = append(checkpoints, cp)

		// Add to MMR
		leafIdx, err := mmrTree.Append(cp.Hash[:])
		if err != nil {
			t.Fatalf("Failed to append to MMR: %v", err)
		}
		leafIndices = append(leafIndices, leafIdx)

		t.Logf("Version %d: hash=%s, MMR index=%d", i+1, hex.EncodeToString(cp.Hash[:8]), leafIdx)
	}

	// Verify chain integrity
	if err := chain.Verify(); err != nil {
		t.Fatalf("Chain verification failed: %v", err)
	}

	// Verify all inclusion proofs
	for i, cp := range checkpoints {
		proof, err := mmrTree.GenerateProof(leafIndices[i])
		if err != nil {
			t.Fatalf("Failed to generate proof for version %d: %v", i+1, err)
		}

		if err := proof.Verify(cp.Hash[:]); err != nil {
			t.Fatalf("Proof verification failed for version %d: %v", i+1, err)
		}
	}

	// Generate and verify range proof for all versions
	rangeProof, err := mmrTree.GenerateRangeProof(0, uint64(len(versions)-1))
	if err != nil {
		t.Fatalf("Failed to generate range proof: %v", err)
	}

	leafData := make([][]byte, len(checkpoints))
	for i, cp := range checkpoints {
		leafData[i] = cp.Hash[:]
	}

	if err := rangeProof.Verify(leafData); err != nil {
		t.Fatalf("Range proof verification failed: %v", err)
	}
	t.Log("Range proof for all versions verified")

	// Verify total elapsed time
	totalTime := chain.TotalElapsedTime()
	t.Logf("Total VDF-proven elapsed time: %v", totalTime)
}

// TestCrossVerification tests that proofs generated from one MMR state
// remain valid and can be verified later.
func TestCrossVerification(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := filepath.Join(tmpDir, "doc.txt")

	vdfParams := vdf.Parameters{
		IterationsPerSecond: 1_000_000,
		MinIterations:       100,
		MaxIterations:       10_000,
	}

	if err := os.WriteFile(docPath, []byte("Content v1"), 0644); err != nil {
		t.Fatalf("Failed to create document: %v", err)
	}

	chain, err := checkpoint.NewChain(docPath, vdfParams)
	if err != nil {
		t.Fatalf("Failed to create chain: %v", err)
	}

	mmrStore := mmr.NewMemoryStore()
	mmrTree, err := mmr.New(mmrStore)
	if err != nil {
		t.Fatalf("Failed to create MMR: %v", err)
	}

	// Create first checkpoint
	cp1, _ := chain.Commit("v1")
	idx1, _ := mmrTree.Append(cp1.Hash[:])

	// Generate proof at this state
	proof1, err := mmrTree.GenerateProof(idx1)
	if err != nil {
		t.Fatalf("Failed to generate proof: %v", err)
	}

	// Store the root at this point
	root1, _ := mmrTree.GetRoot()

	// Add more checkpoints
	for i := 2; i <= 5; i++ {
		content := fmt.Sprintf("Content v%d", i)
		if err := os.WriteFile(docPath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to write: %v", err)
		}
		cp, _ := chain.CommitWithVDFDuration(fmt.Sprintf("v%d", i), 50*time.Millisecond)
		mmrTree.Append(cp.Hash[:])
	}

	// The old proof should still verify against its recorded root
	if err := proof1.Verify(cp1.Hash[:]); err != nil {
		t.Fatalf("Old proof should still verify: %v", err)
	}

	// Verify that the old root is still consistent with the proof
	if proof1.Root != root1 {
		t.Fatal("Proof root should match the MMR root at time of proof generation")
	}

	t.Log("Cross-verification successful: old proofs remain valid")
}

// =============================================================================
// INTEGRATION: Persistence and Recovery
// =============================================================================

// TestPersistenceAndRecovery tests saving and loading the complete
// evidence state (chain + MMR) from disk.
func TestPersistenceAndRecovery(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := filepath.Join(tmpDir, "persistent.txt")
	chainPath := filepath.Join(tmpDir, "chain.json")
	mmrPath := filepath.Join(tmpDir, "mmr.dat")

	vdfParams := vdf.Parameters{
		IterationsPerSecond: 1_000_000,
		MinIterations:       100,
		MaxIterations:       10_000,
	}

	// Phase 1: Create evidence
	if err := os.WriteFile(docPath, []byte("Persistent content"), 0644); err != nil {
		t.Fatalf("Failed to create document: %v", err)
	}

	chain1, err := checkpoint.NewChain(docPath, vdfParams)
	if err != nil {
		t.Fatalf("Failed to create chain: %v", err)
	}

	mmrStore1, err := mmr.NewFileStore(mmrPath)
	if err != nil {
		t.Fatalf("Failed to create MMR store: %v", err)
	}
	defer mmrStore1.Close()

	mmrTree1, err := mmr.New(mmrStore1)
	if err != nil {
		t.Fatalf("Failed to create MMR: %v", err)
	}

	cp1, _ := chain1.Commit("First commit")
	idx1, _ := mmrTree1.Append(cp1.Hash[:])

	// Generate proof before saving
	originalProof, _ := mmrTree1.GenerateProof(idx1)
	originalRoot, _ := mmrTree1.GetRoot()

	// Save chain
	if err := chain1.Save(chainPath); err != nil {
		t.Fatalf("Failed to save chain: %v", err)
	}

	// Sync and close MMR store
	if err := mmrStore1.Sync(); err != nil {
		t.Fatalf("Failed to sync MMR: %v", err)
	}
	mmrStore1.Close()

	// Phase 2: Reload and verify
	chain2, err := checkpoint.Load(chainPath)
	if err != nil {
		t.Fatalf("Failed to load chain: %v", err)
	}

	if err := chain2.Verify(); err != nil {
		t.Fatalf("Loaded chain verification failed: %v", err)
	}

	mmrStore2, err := mmr.NewFileStore(mmrPath)
	if err != nil {
		t.Fatalf("Failed to reopen MMR store: %v", err)
	}
	defer mmrStore2.Close()

	mmrTree2, err := mmr.New(mmrStore2)
	if err != nil {
		t.Fatalf("Failed to recreate MMR: %v", err)
	}

	// Verify root matches
	recoveredRoot, err := mmrTree2.GetRoot()
	if err != nil {
		t.Fatalf("Failed to get recovered root: %v", err)
	}

	if recoveredRoot != originalRoot {
		t.Fatal("Recovered MMR root does not match original")
	}

	// Generate new proof and compare
	recoveredProof, err := mmrTree2.GenerateProof(idx1)
	if err != nil {
		t.Fatalf("Failed to generate proof from recovered MMR: %v", err)
	}

	if recoveredProof.Root != originalProof.Root {
		t.Fatal("Recovered proof root does not match original proof root")
	}

	// Verify with loaded checkpoint
	loadedCP := chain2.Checkpoints[0]
	if err := recoveredProof.Verify(loadedCP.Hash[:]); err != nil {
		t.Fatalf("Proof verification failed after recovery: %v", err)
	}

	t.Log("Persistence and recovery verified successfully")
}

// =============================================================================
// INTEGRATION: Tamper Detection
// =============================================================================

// TestTamperDetectionCheckpoint tests that checkpoint tampering is detected.
func TestTamperDetectionCheckpoint(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := filepath.Join(tmpDir, "doc.txt")

	vdfParams := vdf.Parameters{
		IterationsPerSecond: 1_000_000,
		MinIterations:       100,
		MaxIterations:       10_000,
	}

	if err := os.WriteFile(docPath, []byte("Original"), 0644); err != nil {
		t.Fatalf("Failed to create document: %v", err)
	}

	chain, _ := checkpoint.NewChain(docPath, vdfParams)
	chain.Commit("First")

	if err := os.WriteFile(docPath, []byte("Modified"), 0644); err != nil {
		t.Fatalf("Failed to write: %v", err)
	}
	chain.CommitWithVDFDuration("Second", 50*time.Millisecond)

	// Tamper with checkpoint hash
	original := chain.Checkpoints[1].Hash
	chain.Checkpoints[1].Hash[0] ^= 0xFF

	err := chain.Verify()
	if err == nil {
		t.Fatal("Tampering with checkpoint hash should be detected")
	}
	t.Logf("Tampered hash detected: %v", err)

	// Restore and tamper with content hash
	chain.Checkpoints[1].Hash = original
	chain.Checkpoints[1].ContentHash[0] ^= 0xFF

	err = chain.Verify()
	if err == nil {
		t.Fatal("Tampering with content hash should be detected")
	}
	t.Logf("Tampered content hash detected: %v", err)
}

// TestTamperDetectionMMR tests that MMR proof tampering is detected.
func TestTamperDetectionMMR(t *testing.T) {
	mmrStore := mmr.NewMemoryStore()
	mmrTree, _ := mmr.New(mmrStore)

	// Add some data
	data1 := []byte("checkpoint-hash-1")
	data2 := []byte("checkpoint-hash-2")
	data3 := []byte("checkpoint-hash-3")

	idx1, _ := mmrTree.Append(data1)
	mmrTree.Append(data2)
	mmrTree.Append(data3)

	proof, _ := mmrTree.GenerateProof(idx1)

	// Original verification should pass
	if err := proof.Verify(data1); err != nil {
		t.Fatalf("Original proof should verify: %v", err)
	}

	// Tamper with leaf hash
	tamperedProof := *proof
	tamperedProof.LeafHash[0] ^= 0xFF
	if err := tamperedProof.Verify(data1); err == nil {
		t.Fatal("Tampered leaf hash should be detected")
	}

	// Tamper with Merkle path
	if len(proof.MerklePath) > 0 {
		tamperedProof2 := *proof
		tamperedProof2.MerklePath = make([]mmr.ProofElement, len(proof.MerklePath))
		copy(tamperedProof2.MerklePath, proof.MerklePath)
		tamperedProof2.MerklePath[0].Hash[0] ^= 0xFF
		if err := tamperedProof2.Verify(data1); err == nil {
			t.Fatal("Tampered Merkle path should be detected")
		}
	}

	// Tamper with root
	tamperedProof3 := *proof
	tamperedProof3.Root[0] ^= 0xFF
	if err := tamperedProof3.Verify(data1); err == nil {
		t.Fatal("Tampered root should be detected")
	}

	// Verify with wrong data
	wrongData := []byte("wrong-checkpoint-hash")
	if err := proof.Verify(wrongData); err == nil {
		t.Fatal("Wrong data should fail verification")
	}

	t.Log("All MMR tampering attempts detected")
}

// TestTamperDetectionVDF tests that VDF proof tampering is detected.
func TestTamperDetectionVDF(t *testing.T) {
	var input [32]byte
	copy(input[:], "test-input-for-vdf-tamper")

	proof := vdf.ComputeIterations(input, 1000)

	// Original should verify
	if !vdf.Verify(proof) {
		t.Fatal("Original VDF proof should verify")
	}

	// Tamper with input
	tamperedInput := *proof
	tamperedInput.Input[0] ^= 0xFF
	if vdf.Verify(&tamperedInput) {
		t.Fatal("Tampered input should be detected")
	}

	// Tamper with output
	tamperedOutput := *proof
	tamperedOutput.Output[0] ^= 0xFF
	if vdf.Verify(&tamperedOutput) {
		t.Fatal("Tampered output should be detected")
	}

	// Tamper with iterations
	tamperedIter := *proof
	tamperedIter.Iterations++
	if vdf.Verify(&tamperedIter) {
		t.Fatal("Tampered iterations should be detected")
	}

	t.Log("All VDF tampering attempts detected")
}

// =============================================================================
// INTEGRATION: Complete Evidence Bundle
// =============================================================================

// EvidenceBundle represents a complete evidence package that can be
// exported and verified independently.
type EvidenceBundle struct {
	DocumentHash     [32]byte            `json:"document_hash"`
	Checkpoint       *checkpoint.Checkpoint `json:"checkpoint"`
	InclusionProof   *mmr.InclusionProof    `json:"inclusion_proof"`
	MMRRoot          [32]byte              `json:"mmr_root"`
	ChainSummary     checkpoint.ChainSummary `json:"chain_summary"`
	GeneratedAt      time.Time             `json:"generated_at"`
}

// TestEvidenceBundleCreationAndVerification tests creating a complete
// evidence bundle and verifying it independently.
func TestEvidenceBundleCreationAndVerification(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := filepath.Join(tmpDir, "evidence-doc.txt")

	vdfParams := vdf.Parameters{
		IterationsPerSecond: 1_000_000,
		MinIterations:       100,
		MaxIterations:       10_000,
	}

	// Create document and evidence
	content := []byte("This document needs timestamped evidence")
	if err := os.WriteFile(docPath, content, 0644); err != nil {
		t.Fatalf("Failed to create document: %v", err)
	}

	chain, _ := checkpoint.NewChain(docPath, vdfParams)
	mmrStore := mmr.NewMemoryStore()
	mmrTree, _ := mmr.New(mmrStore)

	// Create checkpoints
	cp1, _ := chain.Commit("Initial")
	idx1, _ := mmrTree.Append(cp1.Hash[:])

	if err := os.WriteFile(docPath, append(content, []byte(" - updated")...), 0644); err != nil {
		t.Fatalf("Failed to update: %v", err)
	}
	cp2, _ := chain.CommitWithVDFDuration("Update", 50*time.Millisecond)
	idx2, _ := mmrTree.Append(cp2.Hash[:])

	// Create evidence bundle for the latest checkpoint
	proof, _ := mmrTree.GenerateProof(idx2)
	root, _ := mmrTree.GetRoot()

	bundle := EvidenceBundle{
		DocumentHash:   cp2.ContentHash,
		Checkpoint:     cp2,
		InclusionProof: proof,
		MMRRoot:        root,
		ChainSummary:   chain.Summary(),
		GeneratedAt:    time.Now(),
	}

	// Serialize bundle (simulating export)
	bundleJSON, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		t.Fatalf("Failed to serialize bundle: %v", err)
	}
	t.Logf("Evidence bundle size: %d bytes", len(bundleJSON))

	// Deserialize bundle (simulating import by verifier)
	var loadedBundle EvidenceBundle
	if err := json.Unmarshal(bundleJSON, &loadedBundle); err != nil {
		t.Fatalf("Failed to deserialize bundle: %v", err)
	}

	// Verify the bundle independently
	// 1. Verify checkpoint hash
	computedHash := loadedBundle.Checkpoint.Hash
	// (In a real implementation, we'd recompute from fields)

	// 2. Verify VDF proof
	if loadedBundle.Checkpoint.VDF != nil {
		if !vdf.Verify(loadedBundle.Checkpoint.VDF) {
			t.Fatal("VDF verification failed in bundle")
		}
	}

	// 3. Verify inclusion proof
	if err := loadedBundle.InclusionProof.Verify(computedHash[:]); err != nil {
		t.Fatalf("Inclusion proof verification failed: %v", err)
	}

	// 4. Verify root matches
	if loadedBundle.InclusionProof.Root != loadedBundle.MMRRoot {
		t.Fatal("Root mismatch in bundle")
	}

	t.Log("Evidence bundle verification complete")

	// Also test bundle for first checkpoint
	proof1, _ := mmrTree.GenerateProof(idx1)
	bundle1 := EvidenceBundle{
		DocumentHash:   cp1.ContentHash,
		Checkpoint:     cp1,
		InclusionProof: proof1,
		MMRRoot:        root,
		ChainSummary:   chain.Summary(),
		GeneratedAt:    time.Now(),
	}

	// First checkpoint has no VDF (it's the genesis)
	if bundle1.Checkpoint.VDF != nil {
		t.Fatal("First checkpoint should not have VDF")
	}

	if err := bundle1.InclusionProof.Verify(cp1.Hash[:]); err != nil {
		t.Fatalf("First checkpoint proof verification failed: %v", err)
	}

	t.Log("Both checkpoint bundles verified")
}

// =============================================================================
// INTEGRATION: Concurrent Operations
// =============================================================================

// TestConcurrentCheckpointsAndMMR tests thread-safety of the integration.
func TestConcurrentCheckpointsAndMMR(t *testing.T) {
	// Create multiple documents with their own chains
	tmpDir := t.TempDir()
	numDocs := 5
	checkpointsPerDoc := 10

	vdfParams := vdf.Parameters{
		IterationsPerSecond: 10_000_000, // Fast for testing
		MinIterations:       10,
		MaxIterations:       1_000,
	}

	// Shared MMR for all checkpoints
	mmrStore := mmr.NewMemoryStore()
	mmrTree, _ := mmr.New(mmrStore)

	type result struct {
		docID      int
		cpIndex    int
		mmrIndex   uint64
		hash       [32]byte
		err        error
	}

	results := make(chan result, numDocs*checkpointsPerDoc)

	// Create documents and chains
	for d := 0; d < numDocs; d++ {
		go func(docID int) {
			docPath := filepath.Join(tmpDir, fmt.Sprintf("doc%d.txt", docID))
			if err := os.WriteFile(docPath, []byte(fmt.Sprintf("Doc %d initial", docID)), 0644); err != nil {
				results <- result{docID: docID, err: err}
				return
			}

			chain, err := checkpoint.NewChain(docPath, vdfParams)
			if err != nil {
				results <- result{docID: docID, err: err}
				return
			}

			for i := 0; i < checkpointsPerDoc; i++ {
				content := fmt.Sprintf("Doc %d version %d", docID, i)
				if err := os.WriteFile(docPath, []byte(content), 0644); err != nil {
					results <- result{docID: docID, cpIndex: i, err: err}
					continue
				}

				var cp *checkpoint.Checkpoint
				if i == 0 {
					cp, err = chain.Commit(fmt.Sprintf("v%d", i))
				} else {
					cp, err = chain.CommitWithVDFDuration(fmt.Sprintf("v%d", i), 10*time.Millisecond)
				}
				if err != nil {
					results <- result{docID: docID, cpIndex: i, err: err}
					continue
				}

				// Add to shared MMR (thread-safe)
				idx, err := mmrTree.Append(cp.Hash[:])
				if err != nil {
					results <- result{docID: docID, cpIndex: i, err: err}
					continue
				}

				results <- result{
					docID:    docID,
					cpIndex:  i,
					mmrIndex: idx,
					hash:     cp.Hash,
				}
			}
		}(d)
	}

	// Collect results
	successCount := 0
	indexToHash := make(map[uint64][32]byte)

	for i := 0; i < numDocs*checkpointsPerDoc; i++ {
		r := <-results
		if r.err != nil {
			t.Errorf("Error for doc %d, cp %d: %v", r.docID, r.cpIndex, r.err)
			continue
		}
		successCount++
		indexToHash[r.mmrIndex] = r.hash
	}

	t.Logf("Concurrent operations: %d/%d succeeded", successCount, numDocs*checkpointsPerDoc)

	// Verify all entries in MMR
	for idx, hash := range indexToHash {
		proof, err := mmrTree.GenerateProof(idx)
		if err != nil {
			t.Errorf("Failed to generate proof for index %d: %v", idx, err)
			continue
		}

		if err := proof.Verify(hash[:]); err != nil {
			t.Errorf("Proof verification failed for index %d: %v", idx, err)
		}
	}

	t.Logf("All %d proofs verified after concurrent operations", len(indexToHash))
}

// =============================================================================
// INTEGRATION: Edge Cases
// =============================================================================

// TestEmptyDocumentEvidence tests evidence creation for empty documents.
func TestEmptyDocumentEvidence(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := filepath.Join(tmpDir, "empty.txt")

	vdfParams := vdf.Parameters{
		IterationsPerSecond: 1_000_000,
		MinIterations:       100,
		MaxIterations:       10_000,
	}

	// Create empty document
	if err := os.WriteFile(docPath, []byte{}, 0644); err != nil {
		t.Fatalf("Failed to create empty document: %v", err)
	}

	chain, _ := checkpoint.NewChain(docPath, vdfParams)
	mmrStore := mmr.NewMemoryStore()
	mmrTree, _ := mmr.New(mmrStore)

	// Create checkpoint for empty document
	cp, err := chain.Commit("Empty document")
	if err != nil {
		t.Fatalf("Failed to commit empty document: %v", err)
	}

	idx, _ := mmrTree.Append(cp.Hash[:])

	// Verify
	if err := chain.Verify(); err != nil {
		t.Fatalf("Chain verification failed: %v", err)
	}

	proof, _ := mmrTree.GenerateProof(idx)
	if err := proof.Verify(cp.Hash[:]); err != nil {
		t.Fatalf("Proof verification failed: %v", err)
	}

	// Content hash should be hash of empty input
	expectedHash := sha256.Sum256([]byte{})
	if cp.ContentHash != expectedHash {
		t.Fatal("Content hash mismatch for empty document")
	}

	t.Log("Empty document evidence verified")
}

// TestLargeDocumentEvidence tests evidence creation for large documents.
func TestLargeDocumentEvidence(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping large document test in short mode")
	}

	tmpDir := t.TempDir()
	docPath := filepath.Join(tmpDir, "large.txt")

	vdfParams := vdf.Parameters{
		IterationsPerSecond: 1_000_000,
		MinIterations:       100,
		MaxIterations:       10_000,
	}

	// Create 10MB document
	largeContent := make([]byte, 10*1024*1024)
	for i := range largeContent {
		largeContent[i] = byte(i % 256)
	}

	if err := os.WriteFile(docPath, largeContent, 0644); err != nil {
		t.Fatalf("Failed to create large document: %v", err)
	}

	chain, _ := checkpoint.NewChain(docPath, vdfParams)
	mmrStore := mmr.NewMemoryStore()
	mmrTree, _ := mmr.New(mmrStore)

	cp, err := chain.Commit("Large document")
	if err != nil {
		t.Fatalf("Failed to commit large document: %v", err)
	}

	idx, _ := mmrTree.Append(cp.Hash[:])

	// Verify
	if err := chain.Verify(); err != nil {
		t.Fatalf("Chain verification failed: %v", err)
	}

	proof, _ := mmrTree.GenerateProof(idx)
	if err := proof.Verify(cp.Hash[:]); err != nil {
		t.Fatalf("Proof verification failed: %v", err)
	}

	// Verify content size
	if cp.ContentSize != int64(len(largeContent)) {
		t.Fatalf("Content size mismatch: expected %d, got %d", len(largeContent), cp.ContentSize)
	}

	t.Logf("Large document (%d bytes) evidence verified", len(largeContent))
}

// TestBinaryDocumentEvidence tests evidence creation for binary documents.
func TestBinaryDocumentEvidence(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := filepath.Join(tmpDir, "binary.dat")

	vdfParams := vdf.Parameters{
		IterationsPerSecond: 1_000_000,
		MinIterations:       100,
		MaxIterations:       10_000,
	}

	// Create binary content with all byte values
	binaryContent := make([]byte, 256)
	for i := range binaryContent {
		binaryContent[i] = byte(i)
	}

	if err := os.WriteFile(docPath, binaryContent, 0644); err != nil {
		t.Fatalf("Failed to create binary document: %v", err)
	}

	chain, _ := checkpoint.NewChain(docPath, vdfParams)
	mmrStore := mmr.NewMemoryStore()
	mmrTree, _ := mmr.New(mmrStore)

	cp, _ := chain.Commit("Binary data")
	idx, _ := mmrTree.Append(cp.Hash[:])

	proof, _ := mmrTree.GenerateProof(idx)
	if err := proof.Verify(cp.Hash[:]); err != nil {
		t.Fatalf("Proof verification failed for binary document: %v", err)
	}

	t.Log("Binary document evidence verified")
}

// =============================================================================
// INTEGRATION: Test Vectors
// =============================================================================

// TestVectorIntegration provides deterministic test vectors for the
// complete integration pipeline.
func TestVectorIntegration(t *testing.T) {
	// Create a deterministic scenario
	tmpDir := t.TempDir()
	docPath := filepath.Join(tmpDir, "vector.txt")

	// Fixed VDF params
	vdfParams := vdf.Parameters{
		IterationsPerSecond: 1_000_000,
		MinIterations:       100,
		MaxIterations:       10_000,
	}

	// Fixed content
	content := []byte("Test vector content for cross-implementation testing")
	if err := os.WriteFile(docPath, content, 0644); err != nil {
		t.Fatalf("Failed to write: %v", err)
	}

	// Expected content hash
	expectedContentHash := sha256.Sum256(content)
	t.Logf("Content hash: %s", hex.EncodeToString(expectedContentHash[:]))

	chain, _ := checkpoint.NewChain(docPath, vdfParams)
	mmrStore := mmr.NewMemoryStore()
	mmrTree, _ := mmr.New(mmrStore)

	cp, _ := chain.Commit("Test vector")
	idx, _ := mmrTree.Append(cp.Hash[:])

	// Log values for test vector creation
	t.Logf("Checkpoint hash: %s", hex.EncodeToString(cp.Hash[:]))
	t.Logf("MMR leaf index: %d", idx)

	root, _ := mmrTree.GetRoot()
	t.Logf("MMR root: %s", hex.EncodeToString(root[:]))

	// Verify content hash matches expected
	if cp.ContentHash != expectedContentHash {
		t.Fatalf("Content hash mismatch")
	}

	// Generate and log proof
	proof, _ := mmrTree.GenerateProof(idx)
	t.Logf("Proof peak position: %d", proof.PeakPosition)
	t.Logf("Proof path length: %d", len(proof.MerklePath))

	// Verify
	if err := proof.Verify(cp.Hash[:]); err != nil {
		t.Fatalf("Test vector proof verification failed: %v", err)
	}

	t.Log("Test vector integration verified")
}

// =============================================================================
// BENCHMARKS
// =============================================================================

// BenchmarkFullPipeline benchmarks the complete evidence creation pipeline.
func BenchmarkFullPipeline(b *testing.B) {
	tmpDir := b.TempDir()
	docPath := filepath.Join(tmpDir, "bench.txt")

	content := []byte("Benchmark content for evidence pipeline")
	if err := os.WriteFile(docPath, content, 0644); err != nil {
		b.Fatalf("Failed to write: %v", err)
	}

	vdfParams := vdf.Parameters{
		IterationsPerSecond: 10_000_000,
		MinIterations:       10,
		MaxIterations:       100,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		chain, _ := checkpoint.NewChain(docPath, vdfParams)
		mmrStore := mmr.NewMemoryStore()
		mmrTree, _ := mmr.New(mmrStore)

		cp, _ := chain.Commit("Benchmark")
		idx, _ := mmrTree.Append(cp.Hash[:])
		proof, _ := mmrTree.GenerateProof(idx)
		proof.Verify(cp.Hash[:])
	}
}

// BenchmarkProofGeneration benchmarks proof generation for various MMR sizes.
func BenchmarkProofGeneration(b *testing.B) {
	sizes := []int{10, 100, 1000}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
			mmrStore := mmr.NewMemoryStore()
			mmrTree, _ := mmr.New(mmrStore)

			// Populate MMR
			var lastIdx uint64
			for i := 0; i < size; i++ {
				data := []byte(fmt.Sprintf("checkpoint-hash-%d", i))
				lastIdx, _ = mmrTree.Append(data)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				mmrTree.GenerateProof(lastIdx)
			}
		})
	}
}

// BenchmarkProofVerification benchmarks proof verification.
func BenchmarkProofVerification(b *testing.B) {
	mmrStore := mmr.NewMemoryStore()
	mmrTree, _ := mmr.New(mmrStore)

	data := []byte("test-checkpoint-hash")
	idx, _ := mmrTree.Append(data)

	// Add more entries to create a non-trivial proof
	for i := 0; i < 100; i++ {
		mmrTree.Append([]byte(fmt.Sprintf("entry-%d", i)))
	}

	proof, _ := mmrTree.GenerateProof(idx)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		proof.Verify(data)
	}
}

// BenchmarkChainVerification benchmarks checkpoint chain verification.
func BenchmarkChainVerification(b *testing.B) {
	sizes := []int{5, 10, 20}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("checkpoints=%d", size), func(b *testing.B) {
			tmpDir := b.TempDir()
			docPath := filepath.Join(tmpDir, "bench.txt")

			vdfParams := vdf.Parameters{
				IterationsPerSecond: 100_000_000,
				MinIterations:       10,
				MaxIterations:       100,
			}

			os.WriteFile(docPath, []byte("initial"), 0644)
			chain, _ := checkpoint.NewChain(docPath, vdfParams)
			chain.Commit("First")

			for i := 1; i < size; i++ {
				os.WriteFile(docPath, []byte(fmt.Sprintf("v%d", i)), 0644)
				chain.CommitWithVDFDuration(fmt.Sprintf("v%d", i), time.Microsecond)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				chain.Verify()
			}
		})
	}
}
