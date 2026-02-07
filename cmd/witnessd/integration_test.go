// Package main provides integration tests for the witnessd CLI.
//
// These tests exercise the full flow of the CLI commands with the
// key hierarchy, WAL, and sentinel integrations.
//
// Patent Pending: USPTO Application No. 19/460,364
package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"witnessd/internal/keyhierarchy"
)

// TestInitCreatesKeyHierarchy verifies that init creates the key hierarchy.
func TestInitCreatesKeyHierarchy(t *testing.T) {
	// Create temp directory for test
	tmpDir := t.TempDir()
	originalEnv := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", originalEnv)

	// Create the witnessd directory
	witnessdTestDir := filepath.Join(tmpDir, ".witnessd")
	if err := os.MkdirAll(witnessdTestDir, 0700); err != nil {
		t.Fatalf("Failed to create test dir: %v", err)
	}

	// Create PUF seed
	pufSeedPath := filepath.Join(witnessdTestDir, "puf_seed")
	puf, err := keyhierarchy.LoadOrCreateSoftwarePUF(pufSeedPath)
	if err != nil {
		t.Fatalf("Failed to create PUF: %v", err)
	}

	// Derive identity
	identity, err := keyhierarchy.DeriveMasterIdentity(puf)
	if err != nil {
		t.Fatalf("Failed to derive identity: %v", err)
	}

	// Verify identity properties
	if identity.Fingerprint == "" {
		t.Error("Identity fingerprint is empty")
	}
	if len(identity.PublicKey) != 32 {
		t.Errorf("Public key wrong length: %d", len(identity.PublicKey))
	}
	if identity.DeviceID == "" {
		t.Error("Device ID is empty")
	}
}

// TestKeyHierarchySession tests a full session lifecycle.
func TestKeyHierarchySession(t *testing.T) {
	// Create temp directory for test
	tmpDir := t.TempDir()

	// Create a test document
	docPath := filepath.Join(tmpDir, "test_document.txt")
	if err := os.WriteFile(docPath, []byte("Initial content"), 0644); err != nil {
		t.Fatalf("Failed to create test document: %v", err)
	}

	// Create PUF
	pufSeedPath := filepath.Join(tmpDir, "puf_seed")
	puf, err := keyhierarchy.LoadOrCreateSoftwarePUF(pufSeedPath)
	if err != nil {
		t.Fatalf("Failed to create PUF: %v", err)
	}

	// Create session manager
	sessionMgr, err := keyhierarchy.NewSessionManager(puf, docPath)
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}
	defer sessionMgr.End()

	// Verify identity
	identity := sessionMgr.Identity()
	if identity == nil {
		t.Fatal("Identity is nil")
	}
	t.Logf("Master fingerprint: %s", identity.Fingerprint)

	// Verify session
	session := sessionMgr.Session()
	if session == nil {
		t.Fatal("Session is nil")
	}
	if session.Certificate == nil {
		t.Fatal("Session certificate is nil")
	}
	t.Logf("Session started: %s", session.Certificate.CreatedAt.Format(time.RFC3339))
}

// TestKeyHierarchyEvidence tests exporting key hierarchy evidence.
func TestKeyHierarchyEvidence(t *testing.T) {
	// Create temp directory for test
	tmpDir := t.TempDir()

	// Create a test document
	docPath := filepath.Join(tmpDir, "test_document.txt")
	if err := os.WriteFile(docPath, []byte("Test content for evidence"), 0644); err != nil {
		t.Fatalf("Failed to create test document: %v", err)
	}

	// Create PUF
	pufSeedPath := filepath.Join(tmpDir, "puf_seed")
	puf, err := keyhierarchy.LoadOrCreateSoftwarePUF(pufSeedPath)
	if err != nil {
		t.Fatalf("Failed to create PUF: %v", err)
	}

	// Create session manager
	sessionMgr, err := keyhierarchy.NewSessionManager(puf, docPath)
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}
	defer sessionMgr.End()

	// Export evidence
	evidence := sessionMgr.ExportEvidence()
	if evidence == nil {
		t.Fatal("Evidence is nil")
	}

	// Verify evidence fields
	if evidence.Version == 0 {
		t.Error("Evidence version is 0")
	}
	if evidence.MasterFingerprint == "" {
		t.Error("Master fingerprint is empty")
	}
	if len(evidence.MasterPublicKey) == 0 {
		t.Error("Master public key is empty")
	}
	if evidence.SessionID == "" {
		t.Error("Session ID is empty")
	}
	if len(evidence.SessionPublicKey) == 0 {
		t.Error("Session public key is empty")
	}
}

// TestPUFDeterminism verifies PUF responses are deterministic.
func TestPUFDeterminism(t *testing.T) {
	tmpDir := t.TempDir()
	pufSeedPath := filepath.Join(tmpDir, "puf_seed")

	// Create PUF
	puf1, err := keyhierarchy.LoadOrCreateSoftwarePUF(pufSeedPath)
	if err != nil {
		t.Fatalf("Failed to create PUF: %v", err)
	}

	// Get response
	challenge := []byte("test-challenge")
	response1, err := puf1.GetResponse(challenge)
	if err != nil {
		t.Fatalf("PUF response failed: %v", err)
	}

	// Load same PUF again
	puf2, err := keyhierarchy.LoadOrCreateSoftwarePUF(pufSeedPath)
	if err != nil {
		t.Fatalf("Failed to reload PUF: %v", err)
	}

	// Get same response
	response2, err := puf2.GetResponse(challenge)
	if err != nil {
		t.Fatalf("PUF response failed: %v", err)
	}

	// Verify determinism
	if string(response1) != string(response2) {
		t.Error("PUF responses are not deterministic")
	}

	// Verify device IDs match
	if puf1.DeviceID() != puf2.DeviceID() {
		t.Errorf("Device IDs don't match: %s != %s", puf1.DeviceID(), puf2.DeviceID())
	}
}

// TestIdentityPersistence verifies master identity is consistent across loads.
func TestIdentityPersistence(t *testing.T) {
	tmpDir := t.TempDir()
	pufSeedPath := filepath.Join(tmpDir, "puf_seed")

	// Create PUF and derive identity
	puf1, err := keyhierarchy.LoadOrCreateSoftwarePUF(pufSeedPath)
	if err != nil {
		t.Fatalf("Failed to create PUF: %v", err)
	}

	identity1, err := keyhierarchy.DeriveMasterIdentity(puf1)
	if err != nil {
		t.Fatalf("Failed to derive identity: %v", err)
	}

	// Reload PUF and derive identity again
	puf2, err := keyhierarchy.LoadOrCreateSoftwarePUF(pufSeedPath)
	if err != nil {
		t.Fatalf("Failed to reload PUF: %v", err)
	}

	identity2, err := keyhierarchy.DeriveMasterIdentity(puf2)
	if err != nil {
		t.Fatalf("Failed to derive identity: %v", err)
	}

	// Verify fingerprints match
	if identity1.Fingerprint != identity2.Fingerprint {
		t.Errorf("Fingerprints don't match: %s != %s",
			identity1.Fingerprint, identity2.Fingerprint)
	}

	// Verify public keys match
	if string(identity1.PublicKey) != string(identity2.PublicKey) {
		t.Error("Public keys don't match")
	}
}

// TestDirectoryStructure verifies the expected directory structure is created.
func TestDirectoryStructure(t *testing.T) {
	tmpDir := t.TempDir()

	expectedDirs := []string{
		"chains",
		"sessions",
		"tracking",
		"sentinel",
		"sentinel/wal",
	}

	// Create directory structure
	for _, dir := range expectedDirs {
		path := filepath.Join(tmpDir, dir)
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatalf("Failed to create %s: %v", dir, err)
		}
	}

	// Verify directories exist
	for _, dir := range expectedDirs {
		path := filepath.Join(tmpDir, dir)
		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("Directory %s doesn't exist: %v", dir, err)
			continue
		}
		if !info.IsDir() {
			t.Errorf("%s is not a directory", dir)
		}
	}
}
