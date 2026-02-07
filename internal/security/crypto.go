package security

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Cryptographic errors
var (
	ErrInsufficientEntropy = errors.New("security: insufficient entropy")
	ErrWeakKey             = errors.New("security: key is too weak")
	ErrInvalidKeySize      = errors.New("security: invalid key size")
)

// MinKeySize is the minimum allowed key size in bytes.
const MinKeySize = 16 // 128 bits

// RecommendedKeySize is the recommended key size in bytes.
const RecommendedKeySize = 32 // 256 bits

// GenerateSecureRandom fills the given slice with cryptographically secure random bytes.
func GenerateSecureRandom(data []byte) error {
	n, err := rand.Read(data)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInsufficientEntropy, err)
	}
	if n != len(data) {
		return fmt.Errorf("%w: only got %d of %d bytes", ErrInsufficientEntropy, n, len(data))
	}
	return nil
}

// GenerateKey generates a cryptographically secure random key.
func GenerateKey(size int) ([]byte, error) {
	if size < MinKeySize {
		return nil, fmt.Errorf("%w: minimum %d bytes required", ErrInvalidKeySize, MinKeySize)
	}

	key := make([]byte, size)
	if err := GenerateSecureRandom(key); err != nil {
		return nil, err
	}

	return key, nil
}

// DeriveKey derives a key using HKDF with SHA-256.
// This is the recommended way to derive keys from a master key.
func DeriveKey(masterKey, salt, info []byte, keySize int) ([]byte, error) {
	if len(masterKey) < MinKeySize {
		return nil, fmt.Errorf("%w: master key is %d bytes, minimum %d required",
			ErrWeakKey, len(masterKey), MinKeySize)
	}

	if keySize < MinKeySize {
		return nil, fmt.Errorf("%w: minimum %d bytes required", ErrInvalidKeySize, MinKeySize)
	}

	// Use HKDF with SHA-256
	reader := hkdf.New(sha256.New, masterKey, salt, info)

	derivedKey := make([]byte, keySize)
	if _, err := io.ReadFull(reader, derivedKey); err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}

	return derivedKey, nil
}

// DeriveKeyWithLabel derives a key with a domain separation label.
// This prevents key reuse across different contexts.
func DeriveKeyWithLabel(masterKey []byte, label string, keySize int) ([]byte, error) {
	// Use label as info parameter for domain separation
	info := []byte("witnessd:" + label)
	return DeriveKey(masterKey, nil, info, keySize)
}

// SecureCompare performs a constant-time comparison of two byte slices.
// Returns true if they are equal.
func SecureCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// SecureCompareHash performs a constant-time comparison of two hash values.
func SecureCompareHash(a, b [32]byte) bool {
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// ValidateKeyStrength checks if a key meets minimum security requirements.
func ValidateKeyStrength(key []byte) error {
	if len(key) < MinKeySize {
		return fmt.Errorf("%w: key is %d bytes, minimum %d required",
			ErrWeakKey, len(key), MinKeySize)
	}

	// Check for all-zeros key
	var allZero = true
	for _, b := range key {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return fmt.Errorf("%w: key is all zeros", ErrWeakKey)
	}

	// Check for repeating pattern (simple check)
	if len(key) >= 4 {
		pattern := key[0]
		allSame := true
		for _, b := range key {
			if b != pattern {
				allSame = false
				break
			}
		}
		if allSame {
			return fmt.Errorf("%w: key has repeating pattern", ErrWeakKey)
		}
	}

	return nil
}

// HashDomainSeparated computes a SHA-256 hash with domain separation.
// The domain prefix prevents hash collisions across different uses.
func HashDomainSeparated(domain string, data ...[]byte) [32]byte {
	h := sha256.New()

	// Write domain prefix with length
	prefix := []byte(domain)
	h.Write([]byte{byte(len(prefix))})
	h.Write(prefix)

	// Write all data
	for _, d := range data {
		h.Write(d)
	}

	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// ConstantTimeSelect returns a if choice is 1, or b if choice is 0.
// This is done in constant time to prevent timing attacks.
func ConstantTimeSelect(choice int, a, b []byte) []byte {
	if len(a) != len(b) {
		// Lengths must match for constant-time operation
		return nil
	}

	result := make([]byte, len(a))
	subtle.ConstantTimeCopy(choice, result, a)
	subtle.ConstantTimeCopy(1-choice, result, b)
	return result
}

// ZeroizeOnPanic sets up a deferred function to wipe sensitive data on panic.
// Usage: defer ZeroizeOnPanic(key)()
func ZeroizeOnPanic(data []byte) func() {
	return func() {
		if r := recover(); r != nil {
			Wipe(data)
			panic(r) // Re-panic after cleanup
		}
	}
}

// SecureString wraps a sensitive string with automatic cleanup.
type SecureString struct {
	data []byte
}

// NewSecureString creates a secure string from a regular string.
// The original string cannot be wiped (Go strings are immutable).
func NewSecureString(s string) *SecureString {
	ss := &SecureString{
		data: make([]byte, len(s)),
	}
	copy(ss.data, s)
	return ss
}

// String returns the string value.
func (ss *SecureString) String() string {
	return string(ss.data)
}

// Bytes returns the underlying bytes.
func (ss *SecureString) Bytes() []byte {
	return ss.data
}

// Destroy wipes the secure string.
func (ss *SecureString) Destroy() {
	Wipe(ss.data)
	ss.data = nil
}

// Len returns the length of the secure string.
func (ss *SecureString) Len() int {
	return len(ss.data)
}
