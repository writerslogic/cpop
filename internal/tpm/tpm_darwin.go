//go:build darwin

// Platform-specific TPM implementation for macOS.
//
// macOS does not have traditional TPM support. Instead, Apple Silicon and
// T2-equipped Intel Macs have a Secure Enclave. This implementation provides
// a SecureEnclaveProvider that uses the Secure Enclave for:
// - Device identity (based on hardware)
// - Key storage and signing (using Secure Enclave keys)
//
// Limitations compared to TPM:
// - No PCR-like platform state measurement
// - No monotonic counter (uses file-based simulation)
// - No hardware attestation quotes
//
// The Secure Enclave provides strong security guarantees for key operations
// but cannot attest to platform state like a TPM can.

package tpm

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// SecureEnclaveProvider implements Provider using macOS Secure Enclave.
// This is a partial implementation - it provides device identity and
// key operations but not full TPM features like PCR attestation.
type SecureEnclaveProvider struct {
	mu          sync.Mutex
	isOpen      bool
	deviceID    []byte
	signingKey  *ecdsa.PrivateKey // In production, this would be Secure Enclave key
	counter     uint64
	counterFile string
	startTime   time.Time
}

// detectHardwareTPM on macOS checks for Secure Enclave availability.
// Returns a Provider - either real Secure Enclave or simulated fallback.
func detectHardwareTPM() Provider {
	// First, try to use real Secure Enclave (requires CGO)
	// This will return nil if Secure Enclave is not available or CGO is disabled
	if realSE := newRealSecureEnclaveProvider(); realSE != nil {
		return realSE
	}

	// Fall back to simulated Secure Enclave for development/testing
	// or when CGO is not available

	// Determine base directory - check for environment variable override
	// (used by sandboxed macOS app)
	baseDir := os.Getenv("WITNESSD_DATA_DIR")
	if baseDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil
		}
		baseDir = filepath.Join(home, ".witnessd")
	}

	counterFile := filepath.Join(baseDir, "se_counter")

	return &SecureEnclaveProvider{
		counterFile: counterFile,
	}
}

// Available returns true - Secure Enclave simulation is always available on macOS.
func (s *SecureEnclaveProvider) Available() bool {
	return true
}

// Open initializes the Secure Enclave provider.
func (s *SecureEnclaveProvider) Open() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.isOpen {
		return ErrTPMAlreadyOpen
	}

	// Generate device ID from hardware identifiers
	// In production, this would use IOKit to get hardware UUID
	s.deviceID = s.generateDeviceID()

	// Load or generate signing key
	// In production, this would create/load a Secure Enclave key
	if err := s.loadOrGenerateSigningKey(); err != nil {
		return fmt.Errorf("secure enclave: failed to load/generate key: %w", err)
	}

	// Load counter from file
	s.loadCounter()

	s.startTime = time.Now()
	s.isOpen = true
	return nil
}

// Close releases resources.
func (s *SecureEnclaveProvider) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isOpen {
		return nil
	}

	// Save counter
	s.saveCounter()

	s.isOpen = false
	s.signingKey = nil
	return nil
}

// DeviceID returns a unique device identifier.
func (s *SecureEnclaveProvider) DeviceID() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isOpen {
		return nil, ErrTPMNotOpen
	}

	result := make([]byte, len(s.deviceID))
	copy(result, s.deviceID)
	return result, nil
}

// PublicKey returns the signing key's public key.
func (s *SecureEnclaveProvider) PublicKey() (crypto.PublicKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isOpen {
		return nil, ErrTPMNotOpen
	}

	if s.signingKey == nil {
		return nil, errors.New("secure enclave: no signing key")
	}

	return &s.signingKey.PublicKey, nil
}

// IncrementCounter atomically increments and returns the counter.
func (s *SecureEnclaveProvider) IncrementCounter() (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isOpen {
		return 0, ErrTPMNotOpen
	}

	s.counter++
	s.saveCounter()
	return s.counter, nil
}

// GetCounter returns the current counter value.
func (s *SecureEnclaveProvider) GetCounter() (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isOpen {
		return 0, ErrTPMNotOpen
	}

	return s.counter, nil
}

// GetClock returns clock information.
func (s *SecureEnclaveProvider) GetClock() (*ClockInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isOpen {
		return nil, ErrTPMNotOpen
	}

	elapsed := time.Since(s.startTime)
	return &ClockInfo{
		Clock:        uint64(elapsed.Milliseconds()),
		ResetCount:   0,
		RestartCount: 0,
		Safe:         true,
	}, nil
}

// Quote creates an attestation over the given data.
// Note: This is not a true TPM quote - it's a signature over the data
// because Secure Enclave doesn't support platform state attestation.
func (s *SecureEnclaveProvider) Quote(data []byte) (*Attestation, error) {
	return s.QuoteWithPCRs(data, DefaultPCRSelection())
}

// QuoteWithPCRs creates an attestation. PCR selection is ignored on macOS
// as Secure Enclave doesn't support PCR-like platform state.
func (s *SecureEnclaveProvider) QuoteWithPCRs(data []byte, _ PCRSelection) (*Attestation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isOpen {
		return nil, ErrTPMNotOpen
	}

	if s.signingKey == nil {
		return nil, errors.New("secure enclave: no signing key")
	}

	// Get clock
	elapsed := time.Since(s.startTime)
	clockInfo := &ClockInfo{
		Clock:        uint64(elapsed.Milliseconds()),
		ResetCount:   0,
		RestartCount: 0,
		Safe:         true,
	}

	// Increment counter
	s.counter++
	s.saveCounter()

	// Create "quote" structure (hash of data + counter + timestamp)
	h := sha256.New()
	h.Write([]byte("witnessd-se-quote-v1"))
	h.Write(data)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], s.counter)
	h.Write(buf[:])
	binary.BigEndian.PutUint64(buf[:], clockInfo.Clock)
	h.Write(buf[:])
	quoteData := h.Sum(nil)

	// Sign the quote
	signature, err := ecdsa.SignASN1(rand.Reader, s.signingKey, quoteData)
	if err != nil {
		return nil, fmt.Errorf("secure enclave: signing failed: %w", err)
	}

	// Encode public key
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&s.signingKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("secure enclave: failed to marshal public key: %w", err)
	}

	return &Attestation{
		DeviceID:         s.deviceID,
		PublicKey:        pubKeyBytes,
		MonotonicCounter: s.counter,
		FirmwareVersion:  "SecureEnclave-1.0",
		ClockInfo:        *clockInfo,
		Data:             data,
		Signature:        signature,
		Quote:            quoteData,
		PCRValues:        nil, // Not supported
		PCRDigest:        nil, // Not supported
		CreatedAt:        time.Now(),
	}, nil
}

// ReadPCRs is not supported on Secure Enclave.
func (s *SecureEnclaveProvider) ReadPCRs(_ PCRSelection) (map[int][]byte, error) {
	// Secure Enclave doesn't have PCRs
	// Return empty map to indicate no PCR state
	return make(map[int][]byte), nil
}

// SealKey is a limited implementation - data is encrypted but not bound to platform state.
//
// SECURITY WARNING: This is a SOFTWARE SIMULATION of Secure Enclave sealing.
// Unlike real TPM/Secure Enclave sealing which binds data to hardware state:
// - The key is derived from device-specific data but is NOT hardware-protected
// - Anyone with access to the device ID and sealed data can unseal it
// - This provides defense-in-depth but NOT the security guarantees of true hardware sealing
//
// NOTE: Real Secure Enclave integration is implemented in secureenclave_darwin.go
// (CGO build) which provides hardware-backed key protection via Security.framework.
// This fallback is used when CGO is disabled or Secure Enclave is unavailable.
func (s *SecureEnclaveProvider) SealKey(data []byte, _ PCRSelection) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isOpen {
		return nil, ErrTPMNotOpen
	}

	// Derive a key from device-specific data instead of storing a random key
	// This provides some binding to this specific device, though not as strong
	// as true TPM/Secure Enclave sealing which uses hardware-protected keys.
	keyMaterial := sha256.New()
	keyMaterial.Write([]byte("witnessd-seal-key-v3"))
	keyMaterial.Write(s.deviceID)
	// Include counter to ensure different keys over time
	var counterBuf [8]byte
	binary.BigEndian.PutUint64(counterBuf[:], s.counter)
	keyMaterial.Write(counterBuf[:])
	key := keyMaterial.Sum(nil)

	// Create AES-GCM cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secure enclave: failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secure enclave: failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("secure enclave: failed to generate nonce: %w", err)
	}

	// Encrypt with authentication
	// Include counter as additional authenticated data
	ciphertext := gcm.Seal(nil, nonce, data, counterBuf[:])

	// Format: version(1) + counter(8) + nonce(12) + ciphertext(len+16 for tag)
	// Note: key is NOT stored - it's derived from device ID and counter
	sealed := make([]byte, 1+8+len(nonce)+len(ciphertext))
	sealed[0] = 3 // version 3 for derived-key AES-GCM
	copy(sealed[1:9], counterBuf[:])
	copy(sealed[9:9+len(nonce)], nonce)
	copy(sealed[9+len(nonce):], ciphertext)

	return sealed, nil
}

// UnsealKey decrypts previously sealed data.
func (s *SecureEnclaveProvider) UnsealKey(sealed []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isOpen {
		return nil, ErrTPMNotOpen
	}

	if len(sealed) < 2 {
		return nil, errors.New("secure enclave: sealed data too short")
	}

	version := sealed[0]

	switch version {
	case 1:
		// Legacy XOR format (for backward compatibility)
		if len(sealed) < 34 {
			return nil, errors.New("secure enclave: sealed data too short for v1")
		}
		key := sealed[1:33]
		data := make([]byte, len(sealed)-33)
		for i := range data {
			data[i] = sealed[33+i] ^ key[i%32]
		}
		return data, nil

	case 2:
		// AES-256-GCM format with stored key (legacy, less secure)
		// Format: version(1) + key(32) + nonce(12) + ciphertext
		const keySize = 32
		const nonceSize = 12
		minSize := 1 + keySize + nonceSize + 16 // at least tag size
		if len(sealed) < minSize {
			return nil, errors.New("secure enclave: sealed data too short for v2")
		}

		key := sealed[1 : 1+keySize]
		nonce := sealed[1+keySize : 1+keySize+nonceSize]
		ciphertext := sealed[1+keySize+nonceSize:]

		// Create AES-GCM cipher
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("secure enclave: failed to create cipher: %w", err)
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("secure enclave: failed to create GCM: %w", err)
		}

		// Decrypt and verify authentication tag
		plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return nil, fmt.Errorf("secure enclave: decryption failed (tampered or wrong key): %w", err)
		}

		return plaintext, nil

	case 3:
		// Derived-key AES-256-GCM format (more secure - key derived from device ID)
		// Format: version(1) + counter(8) + nonce(12) + ciphertext
		const counterSize = 8
		const nonceSize = 12
		minSize := 1 + counterSize + nonceSize + 16 // at least tag size
		if len(sealed) < minSize {
			return nil, errors.New("secure enclave: sealed data too short for v3")
		}

		counter := binary.BigEndian.Uint64(sealed[1:9])
		nonce := sealed[9 : 9+nonceSize]
		ciphertext := sealed[9+nonceSize:]

		// Derive the key from device ID and counter (same derivation as SealKey)
		keyMaterial := sha256.New()
		keyMaterial.Write([]byte("witnessd-seal-key-v3"))
		keyMaterial.Write(s.deviceID)
		var counterBuf [8]byte
		binary.BigEndian.PutUint64(counterBuf[:], counter)
		keyMaterial.Write(counterBuf[:])
		key := keyMaterial.Sum(nil)

		// Create AES-GCM cipher
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("secure enclave: failed to create cipher: %w", err)
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("secure enclave: failed to create GCM: %w", err)
		}

		// Decrypt and verify authentication tag (with counter as AAD)
		plaintext, err := gcm.Open(nil, nonce, ciphertext, counterBuf[:])
		if err != nil {
			return nil, fmt.Errorf("secure enclave: decryption failed (wrong device or tampered): %w", err)
		}

		return plaintext, nil

	default:
		return nil, fmt.Errorf("secure enclave: unsupported version: %d", version)
	}
}

// Manufacturer returns the provider type.
func (s *SecureEnclaveProvider) Manufacturer() string {
	return "Apple Secure Enclave (simulated)"
}

// FirmwareVersion returns the version.
func (s *SecureEnclaveProvider) FirmwareVersion() string {
	return "1.0.0"
}

// Helper methods

func (s *SecureEnclaveProvider) generateDeviceID() []byte {
	// In production, use IOKit to get hardware UUID
	// For now, generate a persistent ID based on hostname and user
	hostname, _ := os.Hostname()
	username := os.Getenv("USER")

	h := sha256.New()
	h.Write([]byte("witnessd-se-device-id"))
	h.Write([]byte(hostname))
	h.Write([]byte(username))

	// Add some persistent hardware-ish data
	if home, err := os.UserHomeDir(); err == nil {
		h.Write([]byte(home))
	}

	return h.Sum(nil)[:16]
}

func (s *SecureEnclaveProvider) loadCounter() {
	data, err := os.ReadFile(s.counterFile)
	if err != nil {
		s.counter = 0
		return
	}

	if len(data) >= 8 {
		s.counter = binary.BigEndian.Uint64(data)
	}
}

func (s *SecureEnclaveProvider) saveCounter() {
	// Ensure directory exists
	dir := filepath.Dir(s.counterFile)
	os.MkdirAll(dir, 0700)

	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, s.counter)
	os.WriteFile(s.counterFile, data, 0600)
}

// loadOrGenerateSigningKey loads an existing signing key or generates a new one.
// The key is persisted to disk to ensure consistency across restarts.
// SECURITY NOTE: In production, this should use Secure Enclave via Security.framework.
func (s *SecureEnclaveProvider) loadOrGenerateSigningKey() error {
	keyFile := filepath.Join(filepath.Dir(s.counterFile), "se_signing_key")

	// Try to load existing key
	data, err := os.ReadFile(keyFile)
	if err == nil && len(data) > 0 {
		// Parse the stored key (PEM-encoded PKCS#8 format)
		key, err := x509.ParseECPrivateKey(data)
		if err == nil {
			s.signingKey = key
			return nil
		}
		// Key file corrupted - regenerate
	}

	// Generate new key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}
	s.signingKey = key

	// Save the new key
	return s.saveSigningKey(keyFile)
}

// saveSigningKey persists the signing key to disk.
func (s *SecureEnclaveProvider) saveSigningKey(keyFile string) error {
	if s.signingKey == nil {
		return errors.New("no signing key to save")
	}

	// Ensure directory exists
	dir := filepath.Dir(keyFile)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	// Marshal the private key
	keyBytes, err := x509.MarshalECPrivateKey(s.signingKey)
	if err != nil {
		return fmt.Errorf("failed to marshal key: %w", err)
	}

	// Write with restrictive permissions
	return os.WriteFile(keyFile, keyBytes, 0600)
}

// Ensure SecureEnclaveProvider implements Provider
var _ Provider = (*SecureEnclaveProvider)(nil)

// NOTE: Real Secure Enclave integration is implemented in secureenclave_darwin.go
// (CGO build) which provides hardware-backed key protection via Security.framework.
// This SecureEnclaveProvider serves as a software fallback when CGO is disabled
// or Secure Enclave hardware is not available.

// DeviceInfo returns information about the Secure Enclave provider.
func (s *SecureEnclaveProvider) DeviceInfo() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isOpen {
		return "SecureEnclave: not open"
	}

	return fmt.Sprintf("SecureEnclave: device=%s counter=%d",
		hex.EncodeToString(s.deviceID[:8]), s.counter)
}
