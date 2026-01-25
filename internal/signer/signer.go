// Package signer handles Ed25519 signing for MMR root commitments.
package signer

import (
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

// Errors
var (
	ErrInvalidKeyFormat = errors.New("signer: invalid key format")
	ErrUnsupportedKey   = errors.New("signer: unsupported key type (expected Ed25519)")
	ErrKeyDecryption    = errors.New("signer: key is encrypted (passphrase required)")
)

// LoadPrivateKey reads an Ed25519 private key from file.
// Supports OpenSSH format (-----BEGIN OPENSSH PRIVATE KEY-----)
// and raw 32-byte seeds.
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}

	// Try raw seed first (32 bytes)
	if len(keyData) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(keyData), nil
	}

	// Try raw private key (64 bytes: seed + public)
	if len(keyData) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(keyData), nil
	}

	// Try OpenSSH format
	return parseOpenSSHKey(keyData)
}

// parseOpenSSHKey parses an OpenSSH private key file.
func parseOpenSSHKey(keyData []byte) (ed25519.PrivateKey, error) {
	// Check for PEM block
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, ErrInvalidKeyFormat
	}

	// Parse using golang.org/x/crypto/ssh
	parsedKey, err := ssh.ParseRawPrivateKey(keyData)
	if err != nil {
		// Check if it's a passphrase-protected key
		if _, ok := err.(*ssh.PassphraseMissingError); ok {
			return nil, ErrKeyDecryption
		}
		return nil, fmt.Errorf("parse key: %w", err)
	}

	// Extract Ed25519 key
	switch k := parsedKey.(type) {
	case *ed25519.PrivateKey:
		return *k, nil
	case ed25519.PrivateKey:
		return k, nil
	default:
		return nil, fmt.Errorf("%w: got %T", ErrUnsupportedKey, parsedKey)
	}
}

// LoadPrivateKeyWithPassphrase loads a passphrase-protected key.
func LoadPrivateKeyWithPassphrase(path string, passphrase []byte) (ed25519.PrivateKey, error) {
	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}

	parsedKey, err := ssh.ParseRawPrivateKeyWithPassphrase(keyData, passphrase)
	if err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}

	switch k := parsedKey.(type) {
	case *ed25519.PrivateKey:
		return *k, nil
	case ed25519.PrivateKey:
		return k, nil
	default:
		return nil, fmt.Errorf("%w: got %T", ErrUnsupportedKey, parsedKey)
	}
}

// LoadPublicKey reads an Ed25519 public key from file.
// Supports OpenSSH format (ssh-ed25519 ...).
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}

	// Try raw public key (32 bytes)
	if len(keyData) == ed25519.PublicKeySize {
		return ed25519.PublicKey(keyData), nil
	}

	// Try OpenSSH format
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	// Extract Ed25519 public key
	cryptoPubKey, ok := pubKey.(ssh.CryptoPublicKey)
	if !ok {
		return nil, ErrInvalidKeyFormat
	}

	ed25519PubKey, ok := cryptoPubKey.CryptoPublicKey().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: got %T", ErrUnsupportedKey, cryptoPubKey.CryptoPublicKey())
	}

	return ed25519PubKey, nil
}

// SignCommitment generates a 64-byte Ed25519 signature for a state hash.
func SignCommitment(privKey ed25519.PrivateKey, stateHash []byte) []byte {
	return ed25519.Sign(privKey, stateHash)
}

// VerifyCommitment verifies an Ed25519 signature.
func VerifyCommitment(pubKey ed25519.PublicKey, stateHash, signature []byte) bool {
	if len(signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pubKey, stateHash, signature)
}

// GetPublicKey extracts the public key from a private key.
func GetPublicKey(privKey ed25519.PrivateKey) ed25519.PublicKey {
	return privKey.Public().(ed25519.PublicKey)
}
