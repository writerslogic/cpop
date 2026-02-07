package checkpoint

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"witnessd/internal/vdf"
)

// =============================================================================
// Helper functions
// =============================================================================

func createTestDocument(t *testing.T, dir, content string) string {
	t.Helper()
	path := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("failed to create test document: %v", err)
	}
	return path
}

func testVDFParams() vdf.Parameters {
	return vdf.Parameters{
		IterationsPerSecond: 100000,
		MinIterations:       100,
		MaxIterations:       1000000,
	}
}

// =============================================================================
// Tests for NewChain
// =============================================================================

func TestNewChain(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "test content")

	chain, err := NewChain(docPath, testVDFParams())
	if err != nil {
		t.Fatalf("NewChain failed: %v", err)
	}

	if chain.DocumentID == "" {
		t.Error("DocumentID should not be empty")
	}
	if chain.DocumentPath == "" {
		t.Error("DocumentPath should not be empty")
	}
	if chain.CreatedAt.IsZero() {
		t.Error("CreatedAt should not be zero")
	}
	if len(chain.Checkpoints) != 0 {
		t.Errorf("expected 0 checkpoints, got %d", len(chain.Checkpoints))
	}
}

func TestNewChainAbsolutePath(t *testing.T) {
	tmpDir := t.TempDir()
	createTestDocument(t, tmpDir, "test content")

	// Use relative path
	origDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	chain, err := NewChain("test.txt", testVDFParams())
	if err != nil {
		t.Fatalf("NewChain failed: %v", err)
	}

	// DocumentPath should be absolute
	if !filepath.IsAbs(chain.DocumentPath) {
		t.Errorf("DocumentPath should be absolute: %s", chain.DocumentPath)
	}
}

func TestNewChainSameDocumentID(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "test content")

	chain1, _ := NewChain(docPath, testVDFParams())
	chain2, _ := NewChain(docPath, testVDFParams())

	if chain1.DocumentID != chain2.DocumentID {
		t.Error("same document path should produce same document ID")
	}
}

func TestNewChainDifferentDocuments(t *testing.T) {
	tmpDir := t.TempDir()
	doc1 := filepath.Join(tmpDir, "doc1.txt")
	doc2 := filepath.Join(tmpDir, "doc2.txt")
	os.WriteFile(doc1, []byte("content1"), 0600)
	os.WriteFile(doc2, []byte("content2"), 0600)

	chain1, _ := NewChain(doc1, testVDFParams())
	chain2, _ := NewChain(doc2, testVDFParams())

	if chain1.DocumentID == chain2.DocumentID {
		t.Error("different documents should have different IDs")
	}
}

// =============================================================================
// Tests for Commit
// =============================================================================

func TestCommitFirst(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "test content")

	chain, _ := NewChain(docPath, testVDFParams())

	cp, err := chain.Commit("Initial commit")
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	if cp.Ordinal != 0 {
		t.Errorf("expected ordinal 0, got %d", cp.Ordinal)
	}
	if cp.PreviousHash != ([32]byte{}) {
		t.Error("first checkpoint should have zero previous hash")
	}
	if cp.Message != "Initial commit" {
		t.Errorf("expected message 'Initial commit', got %q", cp.Message)
	}
	if cp.VDF != nil {
		t.Error("first checkpoint should not have VDF proof")
	}
	if cp.Hash == ([32]byte{}) {
		t.Error("hash should not be zero")
	}

	// Check content hash
	content, _ := os.ReadFile(docPath)
	expectedHash := sha256.Sum256(content)
	if cp.ContentHash != expectedHash {
		t.Error("content hash mismatch")
	}
}

func TestCommitSecond(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "test content")

	chain, _ := NewChain(docPath, testVDFParams())

	cp1, _ := chain.Commit("First commit")

	// Modify document
	os.WriteFile(docPath, []byte("modified content"), 0600)

	cp2, err := chain.Commit("Second commit")
	if err != nil {
		t.Fatalf("Second commit failed: %v", err)
	}

	if cp2.Ordinal != 1 {
		t.Errorf("expected ordinal 1, got %d", cp2.Ordinal)
	}
	if cp2.PreviousHash != cp1.Hash {
		t.Error("second checkpoint should link to first")
	}
	if cp2.VDF == nil {
		t.Error("second checkpoint should have VDF proof")
	}
}

func TestCommitChain(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "v1")

	chain, _ := NewChain(docPath, testVDFParams())

	// Create a chain of commits
	for i := 0; i < 5; i++ {
		os.WriteFile(docPath, []byte("v"+string(rune('1'+i))), 0600)
		_, err := chain.Commit("Commit " + string(rune('1'+i)))
		if err != nil {
			t.Fatalf("Commit %d failed: %v", i, err)
		}
	}

	if len(chain.Checkpoints) != 5 {
		t.Errorf("expected 5 checkpoints, got %d", len(chain.Checkpoints))
	}
}

func TestCommitMissingDocument(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := filepath.Join(tmpDir, "nonexistent.txt")

	chain, _ := NewChain(docPath, testVDFParams())

	_, err := chain.Commit("should fail")
	if err == nil {
		t.Error("expected error for missing document")
	}
}

func TestCommitEmptyMessage(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "content")

	chain, _ := NewChain(docPath, testVDFParams())
	cp, err := chain.Commit("")

	if err != nil {
		t.Fatalf("Commit with empty message failed: %v", err)
	}
	if cp.Message != "" {
		t.Error("message should be empty")
	}
}

func TestCommitLargeMessage(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "content")

	chain, _ := NewChain(docPath, testVDFParams())

	// Create a long message
	longMessage := string(make([]byte, 10000))
	cp, err := chain.Commit(longMessage)

	if err != nil {
		t.Fatalf("Commit with large message failed: %v", err)
	}
	if len(cp.Message) != 10000 {
		t.Error("message length mismatch")
	}
}

// =============================================================================
// Tests for CommitWithVDFDuration
// =============================================================================

func TestCommitWithVDFDuration(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "test content")

	chain, _ := NewChain(docPath, testVDFParams())

	// First commit (no VDF)
	chain.Commit("First")

	// Modify and commit with specific duration
	os.WriteFile(docPath, []byte("modified"), 0600)
	cp, err := chain.CommitWithVDFDuration("Second", 10*time.Millisecond)
	if err != nil {
		t.Fatalf("CommitWithVDFDuration failed: %v", err)
	}

	if cp.VDF == nil {
		t.Error("expected VDF proof")
	}
}

func TestCommitWithVDFDurationFirst(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "content")

	chain, _ := NewChain(docPath, testVDFParams())

	// First commit should NOT have VDF even with duration specified
	cp, err := chain.CommitWithVDFDuration("First", 100*time.Millisecond)
	if err != nil {
		t.Fatalf("CommitWithVDFDuration failed: %v", err)
	}

	if cp.VDF != nil {
		t.Error("first checkpoint should not have VDF")
	}
}

func TestCommitWithVDFDurationExceedsMax(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "content")

	params := vdf.Parameters{
		IterationsPerSecond: 1000,
		MinIterations:       100,
		MaxIterations:       1000, // Very low max
	}

	chain, _ := NewChain(docPath, params)
	chain.Commit("First")

	os.WriteFile(docPath, []byte("modified"), 0600)

	// This should fail because duration exceeds max iterations
	_, err := chain.CommitWithVDFDuration("Second", time.Hour)
	if err == nil {
		t.Error("expected error when VDF duration exceeds max")
	}
}

// =============================================================================
// Tests for computeHash
// =============================================================================

func TestComputeHash(t *testing.T) {
	cp := &Checkpoint{
		Ordinal:     1,
		ContentHash: sha256.Sum256([]byte("content")),
		ContentSize: 7,
		Timestamp:   time.Now(),
	}

	hash1 := cp.computeHash()
	hash2 := cp.computeHash()

	if hash1 != hash2 {
		t.Error("computeHash should be deterministic")
	}

	if hash1 == ([32]byte{}) {
		t.Error("hash should not be zero")
	}
}

func TestComputeHashDifferentOrdinal(t *testing.T) {
	base := &Checkpoint{
		ContentHash: sha256.Sum256([]byte("content")),
		ContentSize: 7,
		Timestamp:   time.Now(),
	}

	cp1 := *base
	cp1.Ordinal = 1
	hash1 := cp1.computeHash()

	cp2 := *base
	cp2.Ordinal = 2
	hash2 := cp2.computeHash()

	if hash1 == hash2 {
		t.Error("different ordinals should produce different hashes")
	}
}

func TestComputeHashDifferentContent(t *testing.T) {
	ts := time.Now()

	cp1 := &Checkpoint{
		Ordinal:     1,
		ContentHash: sha256.Sum256([]byte("content1")),
		ContentSize: 8,
		Timestamp:   ts,
	}

	cp2 := &Checkpoint{
		Ordinal:     1,
		ContentHash: sha256.Sum256([]byte("content2")),
		ContentSize: 8,
		Timestamp:   ts,
	}

	if cp1.computeHash() == cp2.computeHash() {
		t.Error("different content should produce different hashes")
	}
}

func TestComputeHashWithVDF(t *testing.T) {
	ts := time.Now()
	input := sha256.Sum256([]byte("vdf"))
	vdfProof := vdf.ComputeIterations(input, 100)

	cp1 := &Checkpoint{
		Ordinal:     1,
		ContentHash: sha256.Sum256([]byte("content")),
		ContentSize: 7,
		Timestamp:   ts,
		VDF:         nil,
	}

	cp2 := &Checkpoint{
		Ordinal:     1,
		ContentHash: sha256.Sum256([]byte("content")),
		ContentSize: 7,
		Timestamp:   ts,
		VDF:         vdfProof,
	}

	if cp1.computeHash() == cp2.computeHash() {
		t.Error("checkpoint with VDF should have different hash")
	}
}

// =============================================================================
// Tests for Verify - Chain Validation
// =============================================================================

func TestVerifyValidChain(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "v1")

	chain, _ := NewChain(docPath, testVDFParams())

	for i := 0; i < 3; i++ {
		os.WriteFile(docPath, []byte("v"+string(rune('1'+i))), 0600)
		chain.Commit("Commit")
	}

	err := chain.Verify()
	if err != nil {
		t.Errorf("valid chain should verify: %v", err)
	}
}

func TestVerifyBrokenHash(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "content")

	chain, _ := NewChain(docPath, testVDFParams())
	chain.Commit("First")

	// Corrupt the hash
	chain.Checkpoints[0].Hash[0] ^= 0xff

	err := chain.Verify()
	if err == nil {
		t.Error("corrupted hash should fail verification")
	}
}

func TestVerifyBrokenChainLink(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "v1")

	chain, _ := NewChain(docPath, testVDFParams())
	chain.Commit("First")

	os.WriteFile(docPath, []byte("v2"), 0600)
	chain.Commit("Second")

	// Break the chain link
	chain.Checkpoints[1].PreviousHash[0] ^= 0xff

	err := chain.Verify()
	if err == nil {
		t.Error("broken chain link should fail verification")
	}
}

func TestVerifyFirstWithNonZeroPrevious(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "content")

	chain, _ := NewChain(docPath, testVDFParams())
	chain.Commit("First")

	// Set non-zero previous hash on first checkpoint
	chain.Checkpoints[0].PreviousHash = sha256.Sum256([]byte("fake"))
	// Recompute hash
	chain.Checkpoints[0].Hash = chain.Checkpoints[0].computeHash()

	err := chain.Verify()
	if err == nil {
		t.Error("first checkpoint with non-zero previous should fail")
	}
}

func TestVerifyEmptyChain(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "content")

	chain, _ := NewChain(docPath, testVDFParams())

	err := chain.Verify()
	if err != nil {
		t.Errorf("empty chain should verify: %v", err)
	}
}

func TestVerifyMissingVDF(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "v1")

	chain, _ := NewChain(docPath, testVDFParams())
	chain.Commit("First")

	os.WriteFile(docPath, []byte("v2"), 0600)
	chain.Commit("Second")

	// Remove VDF from second checkpoint (which should have it)
	chain.Checkpoints[1].VDF = nil
	// Recompute hash to match
	chain.Checkpoints[1].Hash = chain.Checkpoints[1].computeHash()

	err := chain.Verify()
	if err == nil {
		t.Error("chain with missing VDF should fail verification")
	}
}

func TestVerifyInvalidVDF(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "v1")

	chain, _ := NewChain(docPath, testVDFParams())
	chain.Commit("First")

	os.WriteFile(docPath, []byte("v2"), 0600)
	chain.Commit("Second")

	// Corrupt VDF output
	chain.Checkpoints[1].VDF.Output[0] ^= 0xff

	err := chain.Verify()
	if err == nil {
		t.Error("chain with invalid VDF should fail verification")
	}
}

func TestVerifyVDFInputMismatch(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "v1")

	chain, _ := NewChain(docPath, testVDFParams())
	chain.Commit("First")

	os.WriteFile(docPath, []byte("v2"), 0600)
	chain.Commit("Second")

	// Corrupt VDF input (while keeping output valid for different input)
	wrongInput := sha256.Sum256([]byte("wrong"))
	chain.Checkpoints[1].VDF.Input = wrongInput

	err := chain.Verify()
	if err == nil {
		t.Error("chain with VDF input mismatch should fail verification")
	}
}

// =============================================================================
// Tests for Tampering Detection
// =============================================================================

func TestDetectContentTampering(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "original")

	chain, _ := NewChain(docPath, testVDFParams())
	chain.Commit("First")

	// Save original hash
	originalHash := chain.Checkpoints[0].ContentHash

	// Tamper with content hash
	chain.Checkpoints[0].ContentHash = sha256.Sum256([]byte("tampered"))

	err := chain.Verify()
	if err == nil {
		t.Error("content tampering should be detected")
	}

	// Restore and verify fix
	chain.Checkpoints[0].ContentHash = originalHash
	chain.Checkpoints[0].Hash = chain.Checkpoints[0].computeHash()
	if err := chain.Verify(); err != nil {
		t.Errorf("restored chain should verify: %v", err)
	}
}

func TestDetectTimestampTampering(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "content")

	chain, _ := NewChain(docPath, testVDFParams())
	chain.Commit("First")

	// Tamper with timestamp (without updating hash)
	chain.Checkpoints[0].Timestamp = time.Now().Add(-24 * time.Hour)

	err := chain.Verify()
	if err == nil {
		t.Error("timestamp tampering should be detected via hash mismatch")
	}
}

func TestDetectOrdinalTampering(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "v1")

	chain, _ := NewChain(docPath, testVDFParams())
	chain.Commit("First")
	os.WriteFile(docPath, []byte("v2"), 0600)
	chain.Commit("Second")

	// Tamper with ordinal (without updating hash)
	chain.Checkpoints[1].Ordinal = 5

	err := chain.Verify()
	if err == nil {
		t.Error("ordinal tampering should be detected")
	}
}

func TestDetectReordering(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "v1")

	chain, _ := NewChain(docPath, testVDFParams())

	// Create 3 checkpoints
	for i := 0; i < 3; i++ {
		os.WriteFile(docPath, []byte("v"+string(rune('1'+i))), 0600)
		chain.Commit("Commit")
	}

	// Swap checkpoints 1 and 2
	chain.Checkpoints[1], chain.Checkpoints[2] = chain.Checkpoints[2], chain.Checkpoints[1]

	err := chain.Verify()
	if err == nil {
		t.Error("reordering should be detected")
	}
}

func TestDetectGaps(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "v1")

	chain, _ := NewChain(docPath, testVDFParams())

	// Create 3 checkpoints
	for i := 0; i < 3; i++ {
		os.WriteFile(docPath, []byte("v"+string(rune('1'+i))), 0600)
		chain.Commit("Commit")
	}

	// Remove middle checkpoint
	chain.Checkpoints = append(chain.Checkpoints[:1], chain.Checkpoints[2:]...)

	err := chain.Verify()
	if err == nil {
		t.Error("gap in chain should be detected")
	}
}

// =============================================================================
// Tests for TotalElapsedTime
// =============================================================================

func TestTotalElapsedTime(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "content")

	chain, _ := NewChain(docPath, testVDFParams())

	// First checkpoint (no VDF)
	chain.Commit("First")

	if chain.TotalElapsedTime() != 0 {
		t.Error("single checkpoint should have zero elapsed time")
	}

	// Add more commits
	os.WriteFile(docPath, []byte("v2"), 0600)
	chain.Commit("Second")

	elapsed := chain.TotalElapsedTime()
	if elapsed < 0 {
		t.Error("elapsed time should not be negative")
	}
}

func TestTotalElapsedTimeMultipleCheckpoints(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "content")

	chain, _ := NewChain(docPath, testVDFParams())

	// Create multiple checkpoints
	for i := 0; i < 5; i++ {
		os.WriteFile(docPath, []byte(string(rune('a'+i))), 0600)
		chain.CommitWithVDFDuration("Commit", 10*time.Millisecond)
	}

	// Should have elapsed time from all VDFs (4 total, first has none)
	elapsed := chain.TotalElapsedTime()
	if elapsed <= 0 {
		t.Error("should have positive elapsed time")
	}
}

// =============================================================================
// Tests for Summary
// =============================================================================

func TestSummary(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "content")

	chain, _ := NewChain(docPath, testVDFParams())
	chain.Commit("First")

	summary := chain.Summary()

	if summary.DocumentPath != chain.DocumentPath {
		t.Error("document path mismatch")
	}
	if summary.CheckpointCount != 1 {
		t.Errorf("expected 1 checkpoint, got %d", summary.CheckpointCount)
	}
	if summary.FirstCommit.IsZero() {
		t.Error("first commit should not be zero")
	}
	if summary.LastCommit.IsZero() {
		t.Error("last commit should not be zero")
	}
	if summary.FinalContentHash == "" {
		t.Error("final content hash should not be empty")
	}
	if !summary.ChainValid {
		t.Error("valid chain should have ChainValid=true")
	}
}

func TestSummaryEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "content")

	chain, _ := NewChain(docPath, testVDFParams())

	summary := chain.Summary()

	if summary.CheckpointCount != 0 {
		t.Errorf("expected 0 checkpoints, got %d", summary.CheckpointCount)
	}
	if summary.FinalContentHash != "" {
		t.Error("empty chain should have empty final hash")
	}
	if !summary.ChainValid {
		t.Error("empty chain should be valid")
	}
}

func TestSummaryInvalidChain(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "content")

	chain, _ := NewChain(docPath, testVDFParams())
	chain.Commit("First")

	// Corrupt the chain
	chain.Checkpoints[0].Hash[0] ^= 0xff

	summary := chain.Summary()
	if summary.ChainValid {
		t.Error("corrupted chain should have ChainValid=false")
	}
}

// =============================================================================
// Tests for Save and Load
// =============================================================================

func TestSaveAndLoad(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "content")
	chainPath := filepath.Join(tmpDir, "chain.json")

	chain, _ := NewChain(docPath, testVDFParams())
	chain.Commit("First")

	os.WriteFile(docPath, []byte("v2"), 0600)
	chain.Commit("Second")

	err := chain.Save(chainPath)
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	loaded, err := Load(chainPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if loaded.DocumentID != chain.DocumentID {
		t.Error("DocumentID mismatch")
	}
	if len(loaded.Checkpoints) != len(chain.Checkpoints) {
		t.Error("checkpoint count mismatch")
	}
	if loaded.storagePath != chainPath {
		t.Error("storage path not set on load")
	}
}

func TestSaveCreatesDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "content")
	chainPath := filepath.Join(tmpDir, "subdir", "chain.json")

	chain, _ := NewChain(docPath, testVDFParams())
	chain.Commit("First")

	err := chain.Save(chainPath)
	if err != nil {
		t.Fatalf("Save should create directory: %v", err)
	}

	if _, err := os.Stat(chainPath); os.IsNotExist(err) {
		t.Error("chain file was not created")
	}
}

func TestLoadNonexistent(t *testing.T) {
	_, err := Load("/nonexistent/chain.json")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestLoadInvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	chainPath := filepath.Join(tmpDir, "chain.json")

	os.WriteFile(chainPath, []byte("not valid json{{{"), 0600)

	_, err := Load(chainPath)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestLoadVerifiesAfterRestore(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "content")
	chainPath := filepath.Join(tmpDir, "chain.json")

	chain, _ := NewChain(docPath, testVDFParams())
	chain.Commit("First")
	os.WriteFile(docPath, []byte("v2"), 0600)
	chain.Commit("Second")

	chain.Save(chainPath)

	loaded, err := Load(chainPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Verify the loaded chain is valid
	if err := loaded.Verify(); err != nil {
		t.Errorf("loaded chain should be valid: %v", err)
	}
}

// =============================================================================
// Tests for FindChain
// =============================================================================

func TestFindChainExists(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "content")
	witnessdDir := filepath.Join(tmpDir, ".witnessd")

	chain, _ := NewChain(docPath, testVDFParams())

	// Compute expected chain path
	absPath, _ := filepath.Abs(docPath)
	pathHash := sha256.Sum256([]byte(absPath))
	docID := hex.EncodeToString(pathHash[:8])
	chainPath := filepath.Join(witnessdDir, "chains", docID+".json")

	chain.Save(chainPath)

	found, err := FindChain(docPath, witnessdDir)
	if err != nil {
		t.Fatalf("FindChain failed: %v", err)
	}
	if found != chainPath {
		t.Errorf("expected %s, got %s", chainPath, found)
	}
}

func TestFindChainNotExists(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "content")
	witnessdDir := filepath.Join(tmpDir, ".witnessd")

	_, err := FindChain(docPath, witnessdDir)
	if err == nil {
		t.Error("expected error for nonexistent chain")
	}
}

// =============================================================================
// Tests for GetOrCreateChain
// =============================================================================

func TestGetOrCreateChainNew(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "content")
	witnessdDir := filepath.Join(tmpDir, ".witnessd")

	chain, err := GetOrCreateChain(docPath, witnessdDir, testVDFParams())
	if err != nil {
		t.Fatalf("GetOrCreateChain failed: %v", err)
	}

	if chain.DocumentPath == "" {
		t.Error("chain should have document path")
	}
	if chain.StoragePath() == "" {
		t.Error("chain should have storage path")
	}
}

func TestGetOrCreateChainExisting(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "content")
	witnessdDir := filepath.Join(tmpDir, ".witnessd")

	// Create and save chain
	chain1, _ := GetOrCreateChain(docPath, witnessdDir, testVDFParams())
	chain1.Commit("First")
	chain1.Save(chain1.StoragePath())

	// Get existing chain
	chain2, err := GetOrCreateChain(docPath, witnessdDir, testVDFParams())
	if err != nil {
		t.Fatalf("GetOrCreateChain failed: %v", err)
	}

	if len(chain2.Checkpoints) != 1 {
		t.Errorf("expected 1 checkpoint from loaded chain, got %d", len(chain2.Checkpoints))
	}
}

// =============================================================================
// Tests for Latest and At
// =============================================================================

func TestLatest(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "content")

	chain, _ := NewChain(docPath, testVDFParams())

	if chain.Latest() != nil {
		t.Error("empty chain should return nil Latest")
	}

	cp1, _ := chain.Commit("First")
	if chain.Latest() != cp1 {
		t.Error("Latest should return first checkpoint")
	}

	os.WriteFile(docPath, []byte("v2"), 0600)
	cp2, _ := chain.Commit("Second")
	if chain.Latest() != cp2 {
		t.Error("Latest should return second checkpoint")
	}
}

func TestAt(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "content")

	chain, _ := NewChain(docPath, testVDFParams())
	cp0, _ := chain.Commit("First")

	os.WriteFile(docPath, []byte("v2"), 0600)
	cp1, _ := chain.Commit("Second")

	got0, err := chain.At(0)
	if err != nil {
		t.Fatalf("At(0) failed: %v", err)
	}
	if got0 != cp0 {
		t.Error("At(0) returned wrong checkpoint")
	}

	got1, err := chain.At(1)
	if err != nil {
		t.Fatalf("At(1) failed: %v", err)
	}
	if got1 != cp1 {
		t.Error("At(1) returned wrong checkpoint")
	}
}

func TestAtOutOfRange(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "content")

	chain, _ := NewChain(docPath, testVDFParams())
	chain.Commit("First")

	_, err := chain.At(5)
	if err == nil {
		t.Error("expected error for out of range ordinal")
	}
}

// =============================================================================
// Tests for StoragePath
// =============================================================================

func TestStoragePath(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := createTestDocument(t, tmpDir, "content")
	chainPath := filepath.Join(tmpDir, "chain.json")

	chain, _ := NewChain(docPath, testVDFParams())

	if chain.StoragePath() != "" {
		t.Error("new chain should have empty storage path")
	}

	chain.Save(chainPath)

	if chain.StoragePath() != chainPath {
		t.Errorf("storage path mismatch: expected %s, got %s", chainPath, chain.StoragePath())
	}
}

// =============================================================================
// Tests for JSON serialization
// =============================================================================

func TestCheckpointJSON(t *testing.T) {
	cp := &Checkpoint{
		Ordinal:      1,
		PreviousHash: sha256.Sum256([]byte("prev")),
		Hash:         sha256.Sum256([]byte("hash")),
		ContentHash:  sha256.Sum256([]byte("content")),
		ContentSize:  100,
		FilePath:     "/test/file.txt",
		Timestamp:    time.Now().UTC(),
		Message:      "Test commit",
	}

	data, err := json.Marshal(cp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded Checkpoint
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.Ordinal != cp.Ordinal {
		t.Error("ordinal mismatch")
	}
	if decoded.Message != cp.Message {
		t.Error("message mismatch")
	}
}

func TestChainSummaryJSON(t *testing.T) {
	summary := ChainSummary{
		DocumentPath:     "/test/doc.txt",
		CheckpointCount:  5,
		FirstCommit:      time.Now().Add(-24 * time.Hour),
		LastCommit:       time.Now(),
		TotalElapsedTime: 1 * time.Hour,
		FinalContentHash: "abc123",
		ChainValid:       true,
	}

	data, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded ChainSummary
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.CheckpointCount != 5 {
		t.Error("checkpoint count mismatch")
	}
	if !decoded.ChainValid {
		t.Error("chain valid mismatch")
	}
}

func TestTPMBindingJSON(t *testing.T) {
	binding := &TPMBinding{
		MonotonicCounter: 42,
		ClockInfo:        []byte{1, 2, 3},
		Attestation:      []byte{4, 5, 6},
		Signature:        []byte{7, 8, 9},
		PublicKey:        []byte{10, 11, 12},
	}

	data, err := json.Marshal(binding)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded TPMBinding
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.MonotonicCounter != 42 {
		t.Error("monotonic counter mismatch")
	}
}

// =============================================================================
// Tests with Real File Changes
// =============================================================================

func TestCommitWithRealFileChanges(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := filepath.Join(tmpDir, "document.txt")

	// Create initial file
	os.WriteFile(docPath, []byte("Hello, World!"), 0600)

	chain, _ := NewChain(docPath, testVDFParams())

	// Commit initial version
	cp1, _ := chain.Commit("Initial version")
	initialHash := cp1.ContentHash

	// Make actual file changes
	os.WriteFile(docPath, []byte("Hello, Universe!"), 0600)

	cp2, _ := chain.Commit("Changed World to Universe")

	// Verify hashes are different
	if cp1.ContentHash == cp2.ContentHash {
		t.Error("different content should have different hashes")
	}

	// Verify file size is tracked
	if cp2.ContentSize != 16 { // "Hello, Universe!"
		t.Errorf("expected size 16, got %d", cp2.ContentSize)
	}

	// Append content
	os.WriteFile(docPath, []byte("Hello, Universe! And beyond!"), 0600)

	cp3, _ := chain.Commit("Added more text")

	if cp3.ContentHash == cp2.ContentHash {
		t.Error("appended content should have different hash")
	}

	// Verify chain is valid
	if err := chain.Verify(); err != nil {
		t.Errorf("chain should be valid: %v", err)
	}

	// Verify initial hash is still what we recorded
	if cp1.ContentHash != initialHash {
		t.Error("initial hash should not change")
	}
}

func TestCommitWithBinaryFile(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := filepath.Join(tmpDir, "binary.bin")

	// Create binary file
	binaryData := make([]byte, 1024)
	for i := range binaryData {
		binaryData[i] = byte(i % 256)
	}
	os.WriteFile(docPath, binaryData, 0600)

	chain, _ := NewChain(docPath, testVDFParams())
	cp, err := chain.Commit("Binary file")

	if err != nil {
		t.Fatalf("Commit failed for binary file: %v", err)
	}

	if cp.ContentSize != 1024 {
		t.Errorf("expected size 1024, got %d", cp.ContentSize)
	}

	// Verify hash is correct
	expectedHash := sha256.Sum256(binaryData)
	if cp.ContentHash != expectedHash {
		t.Error("binary content hash mismatch")
	}
}

func TestCommitWithEmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := filepath.Join(tmpDir, "empty.txt")

	// Create empty file
	os.WriteFile(docPath, []byte{}, 0600)

	chain, _ := NewChain(docPath, testVDFParams())
	cp, err := chain.Commit("Empty file")

	if err != nil {
		t.Fatalf("Commit failed for empty file: %v", err)
	}

	if cp.ContentSize != 0 {
		t.Errorf("expected size 0, got %d", cp.ContentSize)
	}

	// Empty file hash
	expectedHash := sha256.Sum256([]byte{})
	if cp.ContentHash != expectedHash {
		t.Error("empty file hash mismatch")
	}
}

func TestCommitWithLargeFile(t *testing.T) {
	tmpDir := t.TempDir()
	docPath := filepath.Join(tmpDir, "large.txt")

	// Create 1MB file
	largeData := bytes.Repeat([]byte("A"), 1024*1024)
	os.WriteFile(docPath, largeData, 0600)

	chain, _ := NewChain(docPath, testVDFParams())
	cp, err := chain.Commit("Large file")

	if err != nil {
		t.Fatalf("Commit failed for large file: %v", err)
	}

	if cp.ContentSize != 1024*1024 {
		t.Errorf("expected size %d, got %d", 1024*1024, cp.ContentSize)
	}
}

// =============================================================================
// Test Vectors for Cross-Implementation Compatibility
// =============================================================================

func TestCheckpointHashVector(t *testing.T) {
	// Create a deterministic checkpoint for cross-implementation testing
	ts, _ := time.Parse(time.RFC3339, "2024-01-15T12:00:00Z")

	cp := &Checkpoint{
		Ordinal:      0,
		PreviousHash: [32]byte{},
		ContentHash:  sha256.Sum256([]byte("test content")),
		ContentSize:  12,
		Timestamp:    ts,
		Message:      "test",
	}

	hash := cp.computeHash()

	// Log for documentation
	t.Logf("Checkpoint hash vector:")
	t.Logf("  Ordinal: %d", cp.Ordinal)
	t.Logf("  PreviousHash: %s", hex.EncodeToString(cp.PreviousHash[:]))
	t.Logf("  ContentHash: %s", hex.EncodeToString(cp.ContentHash[:]))
	t.Logf("  ContentSize: %d", cp.ContentSize)
	t.Logf("  Timestamp: %s", ts.Format(time.RFC3339))
	t.Logf("  Message: %q", cp.Message)
	t.Logf("  Computed Hash: %s", hex.EncodeToString(hash[:]))

	// Verify hash is non-zero and deterministic
	if hash == ([32]byte{}) {
		t.Error("hash should not be zero")
	}

	hash2 := cp.computeHash()
	if hash != hash2 {
		t.Error("hash should be deterministic")
	}
}

// =============================================================================
// Benchmarks
// =============================================================================

func BenchmarkCommit(b *testing.B) {
	tmpDir := b.TempDir()
	docPath := filepath.Join(tmpDir, "bench.txt")
	os.WriteFile(docPath, []byte("benchmark content"), 0600)

	chain, _ := NewChain(docPath, testVDFParams())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		chain.Commit("Benchmark commit")
	}
}

func BenchmarkVerify(b *testing.B) {
	tmpDir := b.TempDir()
	docPath := filepath.Join(tmpDir, "bench.txt")
	os.WriteFile(docPath, []byte("benchmark content"), 0600)

	chain, _ := NewChain(docPath, testVDFParams())

	// Create 10 checkpoints
	for i := 0; i < 10; i++ {
		os.WriteFile(docPath, []byte(string(rune('a'+i))), 0600)
		chain.Commit("Commit")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		chain.Verify()
	}
}

func BenchmarkComputeHash(b *testing.B) {
	cp := &Checkpoint{
		Ordinal:     1,
		ContentHash: sha256.Sum256([]byte("content")),
		ContentSize: 7,
		Timestamp:   time.Now(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cp.computeHash()
	}
}

func BenchmarkSaveLoad(b *testing.B) {
	tmpDir := b.TempDir()
	docPath := filepath.Join(tmpDir, "bench.txt")
	chainPath := filepath.Join(tmpDir, "chain.json")
	os.WriteFile(docPath, []byte("content"), 0600)

	chain, _ := NewChain(docPath, testVDFParams())
	for i := 0; i < 10; i++ {
		chain.Commit("Commit")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		chain.Save(chainPath)
		Load(chainPath)
	}
}
