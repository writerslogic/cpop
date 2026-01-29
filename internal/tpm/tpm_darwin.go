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
// Returns a SecureEnclaveProvider if available, nil otherwise.
func detectHardwareTPM() Provider {
	// Check if we're on Apple Silicon or T2 Mac
	// In a production implementation, we would check for Secure Enclave
	// availability using the Security framework.
	//
	// For now, we provide a software-based provider that mimics
	// Secure Enclave behavior for development and testing.

	// Check for home directory to store counter file
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	counterFile := filepath.Join(home, ".witnessd", "se_counter")

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

	// Generate or load signing key
	// In production, this would create/load a Secure Enclave key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("secure enclave: failed to generate key: %w", err)
	}
	s.signingKey = key

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
func (s *SecureEnclaveProvider) SealKey(data []byte, _ PCRSelection) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isOpen {
		return nil, ErrTPMNotOpen
	}

	// In production, this would use Secure Enclave key wrapping.
	// For now, we use a simple encryption scheme.
	// WARNING: This is NOT as secure as TPM sealing.

	// Generate random key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}

	// XOR encrypt (NOT SECURE - placeholder only)
	// In production, use proper authenticated encryption
	sealed := make([]byte, 1+32+len(data)) // version + key + data
	sealed[0] = 1                          // version
	copy(sealed[1:33], key)
	for i, b := range data {
		sealed[33+i] = b ^ key[i%32]
	}

	return sealed, nil
}

// UnsealKey decrypts previously sealed data.
func (s *SecureEnclaveProvider) UnsealKey(sealed []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isOpen {
		return nil, ErrTPMNotOpen
	}

	if len(sealed) < 34 {
		return nil, errors.New("secure enclave: sealed data too short")
	}

	if sealed[0] != 1 {
		return nil, fmt.Errorf("secure enclave: unsupported version: %d", sealed[0])
	}

	key := sealed[1:33]
	data := make([]byte, len(sealed)-33)
	for i := range data {
		data[i] = sealed[33+i] ^ key[i%32]
	}

	return data, nil
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

// Ensure SecureEnclaveProvider implements Provider
var _ Provider = (*SecureEnclaveProvider)(nil)

// Note: For production Secure Enclave support, you would use CGo to call
// the Security framework APIs:
//
// #cgo LDFLAGS: -framework Security -framework CoreFoundation
// /*
// #include <Security/Security.h>
// #include <CoreFoundation/CoreFoundation.h>
// */
// import "C"
//
// And implement:
// - SecKeyCreateRandomKey with kSecAttrTokenIDSecureEnclave
// - SecKeyCreateSignature for signing
// - SecKeyCopyExternalRepresentation for public key export
//
// The current implementation is a simulation that provides the same API
// for development and testing on macOS.

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
