package signer

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestSignAndVerify(t *testing.T) {
	// Generate a key pair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Sign a message
	message := []byte("test message to sign")
	sig := SignCommitment(privKey, message)

	if len(sig) != ed25519.SignatureSize {
		t.Errorf("expected signature size %d, got %d", ed25519.SignatureSize, len(sig))
	}

	// Verify the signature
	if !VerifyCommitment(pubKey, message, sig) {
		t.Error("signature verification failed")
	}

	// Verify with wrong message should fail
	if VerifyCommitment(pubKey, []byte("wrong message"), sig) {
		t.Error("verification should fail with wrong message")
	}

	// Verify with wrong signature should fail
	wrongSig := make([]byte, ed25519.SignatureSize)
	if VerifyCommitment(pubKey, message, wrongSig) {
		t.Error("verification should fail with wrong signature")
	}

	// Verify with short signature should fail
	if VerifyCommitment(pubKey, message, []byte("short")) {
		t.Error("verification should fail with short signature")
	}
}

func TestGetPublicKey(t *testing.T) {
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	pubKey := GetPublicKey(privKey)
	if len(pubKey) != ed25519.PublicKeySize {
		t.Errorf("expected public key size %d, got %d", ed25519.PublicKeySize, len(pubKey))
	}
}

func TestLoadRawSeed(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "signer_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a raw 32-byte seed
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("failed to generate seed: %v", err)
	}

	keyPath := filepath.Join(tmpDir, "test.key")
	if err := os.WriteFile(keyPath, seed, 0600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}

	privKey, err := LoadPrivateKey(keyPath)
	if err != nil {
		t.Fatalf("LoadPrivateKey failed: %v", err)
	}

	if len(privKey) != ed25519.PrivateKeySize {
		t.Errorf("expected private key size %d, got %d", ed25519.PrivateKeySize, len(privKey))
	}

	// Verify signing works
	sig := SignCommitment(privKey, []byte("test"))
	if len(sig) != ed25519.SignatureSize {
		t.Error("signing with loaded key failed")
	}
}

func TestLoadRawPrivateKey(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "signer_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate full private key (64 bytes)
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	keyPath := filepath.Join(tmpDir, "test.key")
	if err := os.WriteFile(keyPath, privKey, 0600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}

	loadedKey, err := LoadPrivateKey(keyPath)
	if err != nil {
		t.Fatalf("LoadPrivateKey failed: %v", err)
	}

	// Compare keys
	if !privKey.Equal(loadedKey) {
		t.Error("loaded key doesn't match original")
	}
}

func TestLoadOpenSSHKey(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "signer_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate a key pair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Convert to OpenSSH format using ssh package
	sshPubKey, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		t.Fatalf("failed to create SSH public key: %v", err)
	}

	// Write public key
	pubKeyPath := filepath.Join(tmpDir, "test.pub")
	pubKeyData := ssh.MarshalAuthorizedKey(sshPubKey)
	if err := os.WriteFile(pubKeyPath, pubKeyData, 0644); err != nil {
		t.Fatalf("failed to write public key: %v", err)
	}

	// Load public key
	loadedPubKey, err := LoadPublicKey(pubKeyPath)
	if err != nil {
		t.Fatalf("LoadPublicKey failed: %v", err)
	}

	if !pubKey.Equal(loadedPubKey) {
		t.Error("loaded public key doesn't match original")
	}

	// Test signing with original and verifying with loaded
	message := []byte("test message")
	sig := SignCommitment(privKey, message)

	if !VerifyCommitment(loadedPubKey, message, sig) {
		t.Error("verification with loaded public key failed")
	}
}

func TestLoadRawPublicKey(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "signer_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate a key pair
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Write raw 32-byte public key
	pubKeyPath := filepath.Join(tmpDir, "test.pub")
	if err := os.WriteFile(pubKeyPath, pubKey, 0644); err != nil {
		t.Fatalf("failed to write public key: %v", err)
	}

	loadedPubKey, err := LoadPublicKey(pubKeyPath)
	if err != nil {
		t.Fatalf("LoadPublicKey failed: %v", err)
	}

	if !pubKey.Equal(loadedPubKey) {
		t.Error("loaded public key doesn't match original")
	}
}

func TestLoadInvalidKey(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "signer_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Write invalid data
	keyPath := filepath.Join(tmpDir, "invalid.key")
	if err := os.WriteFile(keyPath, []byte("invalid key data"), 0600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}

	_, err = LoadPrivateKey(keyPath)
	if err == nil {
		t.Error("expected error for invalid key format")
	}
}

func TestLoadNonexistentKey(t *testing.T) {
	_, err := LoadPrivateKey("/nonexistent/key.pem")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func BenchmarkSign(b *testing.B) {
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)
	message := []byte("benchmark message for signing performance test")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SignCommitment(privKey, message)
	}
}

func BenchmarkVerify(b *testing.B) {
	pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
	message := []byte("benchmark message for verification performance test")
	sig := SignCommitment(privKey, message)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyCommitment(pubKey, message, sig)
	}
}
