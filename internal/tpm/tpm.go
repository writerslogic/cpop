// Package tpm implements Layer 3 Hardware Attestation via TPM 2.0.
//
// TPM (Trusted Platform Module) provides hardware-backed security:
// - Monotonic counter: Cannot be rolled back
// - Secure clock: Hardware time attestation
// - Platform attestation: Proves execution environment
// - Key sealing: Binds secrets to platform state (PCR values)
//
// Architecture (from tpm-policy.json):
// TPM 2.0 does not support Ed25519 natively, so we use a hybrid approach:
// 1. Ed25519 keypair is generated in software
// 2. Private key bytes are sealed to TPM (bound to PCRs 0, 4, 7)
// 3. On signing: unseal key from TPM (requires PCR match)
// 4. Perform Ed25519 signature in software with unsealed key
// 5. Zero unsealed key material from memory immediately after use
//
// This package provides both hardware TPM support (via go-tpm) and
// software fallbacks for development/testing.
package tpm

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Error definitions for TPM operations.
var (
	ErrTPMNotAvailable    = errors.New("tpm: hardware not available")
	ErrTPMNotOpen         = errors.New("tpm: device not open")
	ErrTPMAlreadyOpen     = errors.New("tpm: device already open")
	ErrCounterNotInit     = errors.New("tpm: monotonic counter not initialized")
	ErrPCRMismatch        = errors.New("tpm: PCR values do not match policy")
	ErrQuoteFailed        = errors.New("tpm: quote generation failed")
	ErrVerifyFailed       = errors.New("tpm: verification failed")
	ErrKeyNotSealed       = errors.New("tpm: key not sealed to TPM")
	ErrUnsealFailed       = errors.New("tpm: unseal operation failed")
	ErrInvalidSignature   = errors.New("tpm: invalid signature")
	ErrClockNotSafe       = errors.New("tpm: clock is not in safe state")
	ErrCounterRollback    = errors.New("tpm: monotonic counter rollback detected")
)

// PCRSelection specifies which PCRs to use for attestation and sealing.
// Default selection based on tpm-policy.json: PCRs 0, 4, 7 with SHA-256.
type PCRSelection struct {
	Hash   HashAlgorithm `json:"hash"`
	PCRs   []int         `json:"pcrs"`
}

// DefaultPCRSelection returns the recommended PCR selection for witnessd.
// - PCR 0: SRTM, BIOS, Platform Extensions (firmware integrity)
// - PCR 4: Boot Manager / MBR (bootloader integrity)
// - PCR 7: Secure Boot State (ensures Secure Boot is enabled)
func DefaultPCRSelection() PCRSelection {
	return PCRSelection{
		Hash: HashSHA256,
		PCRs: []int{0, 4, 7},
	}
}

// HashAlgorithm represents a TPM hash algorithm.
type HashAlgorithm uint16

const (
	HashSHA1   HashAlgorithm = 0x0004
	HashSHA256 HashAlgorithm = 0x000B
	HashSHA384 HashAlgorithm = 0x000C
	HashSHA512 HashAlgorithm = 0x000D
)

func (h HashAlgorithm) String() string {
	switch h {
	case HashSHA1:
		return "SHA-1"
	case HashSHA256:
		return "SHA-256"
	case HashSHA384:
		return "SHA-384"
	case HashSHA512:
		return "SHA-512"
	default:
		return fmt.Sprintf("Unknown(0x%04X)", uint16(h))
	}
}

// Attestation contains hardware attestation data.
type Attestation struct {
	// TPM identity
	DeviceID  []byte `json:"device_id"`
	PublicKey []byte `json:"public_key"`

	// Counters and time
	MonotonicCounter uint64    `json:"monotonic_counter"`
	FirmwareVersion  string    `json:"firmware_version,omitempty"`
	ClockInfo        ClockInfo `json:"clock_info"`

	// The attestation
	Data      []byte `json:"data"`      // What was attested (nonce/hash)
	Signature []byte `json:"signature"` // TPM signature over the quote
	Quote     []byte `json:"quote"`     // TPM quote structure (TPMS_ATTEST)

	// PCR values at quote time
	PCRValues map[int][]byte `json:"pcr_values,omitempty"`
	PCRDigest []byte         `json:"pcr_digest,omitempty"`

	// Metadata
	CreatedAt time.Time `json:"created_at"`
}

// ClockInfo contains TPM clock attestation.
type ClockInfo struct {
	// Clock value in milliseconds since TPM power-on
	Clock uint64 `json:"clock"`

	// Reset count (number of TPM resets since manufacture)
	ResetCount uint32 `json:"reset_count"`

	// Restart count (number of TPM restarts without reset)
	RestartCount uint32 `json:"restart_count"`

	// Safe flag (true if clock has not been set backwards)
	Safe bool `json:"safe"`
}

// Binding represents a TPM binding to a checkpoint.
type Binding struct {
	// The checkpoint this binds to
	CheckpointHash [32]byte `json:"checkpoint_hash"`

	// Attestation from TPM
	Attestation Attestation `json:"attestation"`

	// Previous binding (for chain verification)
	PreviousCounter uint64 `json:"previous_counter,omitempty"`
}

// Provider abstracts TPM operations.
// Implementations include HardwareProvider (real TPM), SoftwareProvider (testing),
// and NoOpProvider (unavailable fallback).
type Provider interface {
	// Available returns true if TPM is available and operational.
	Available() bool

	// Open initializes the TPM connection. Must be called before other operations.
	Open() error

	// Close releases TPM resources. Should be called when done.
	Close() error

	// DeviceID returns the TPM's unique identifier (EK certificate hash or similar).
	DeviceID() ([]byte, error)

	// PublicKey returns the TPM's attestation public key (AK public key).
	PublicKey() (crypto.PublicKey, error)

	// IncrementCounter atomically increments and returns the monotonic counter.
	// Uses NV storage to provide a persistent, non-rollbackable counter.
	IncrementCounter() (uint64, error)

	// GetCounter returns the current counter value without incrementing.
	GetCounter() (uint64, error)

	// GetClock returns the current TPM clock info.
	GetClock() (*ClockInfo, error)

	// Quote creates a TPM quote over the given data (typically a hash).
	// The quote proves the platform state (PCR values) at the time of attestation.
	Quote(data []byte) (*Attestation, error)

	// QuoteWithPCRs creates a quote using specific PCR selection.
	QuoteWithPCRs(data []byte, pcrs PCRSelection) (*Attestation, error)

	// ReadPCRs reads the specified PCR values.
	ReadPCRs(pcrs PCRSelection) (map[int][]byte, error)

	// SealKey seals data to the current PCR state.
	// The data can only be unsealed when PCRs match.
	SealKey(data []byte, pcrs PCRSelection) ([]byte, error)

	// UnsealKey unseals previously sealed data.
	// Returns ErrPCRMismatch if current PCR values don't match sealing state.
	UnsealKey(sealed []byte) ([]byte, error)

	// Manufacturer returns TPM manufacturer information.
	Manufacturer() string

	// FirmwareVersion returns the TPM firmware version.
	FirmwareVersion() string
}

// Binder creates TPM bindings for checkpoints.
type Binder struct {
	provider    Provider
	lastCounter uint64
	mu          sync.Mutex
}

// NewBinder creates a new TPM binder.
func NewBinder(provider Provider) *Binder {
	return &Binder{
		provider: provider,
	}
}

// Available returns true if TPM binding is available.
func (b *Binder) Available() bool {
	return b.provider != nil && b.provider.Available()
}

// Bind creates a TPM binding for a checkpoint.
func (b *Binder) Bind(checkpointHash [32]byte) (*Binding, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.Available() {
		return nil, ErrTPMNotAvailable
	}

	// Open TPM if not already open
	if err := b.provider.Open(); err != nil && !errors.Is(err, ErrTPMAlreadyOpen) {
		return nil, fmt.Errorf("tpm open: %w", err)
	}

	// Get attestation with quote
	attestation, err := b.provider.Quote(checkpointHash[:])
	if err != nil {
		return nil, fmt.Errorf("tpm quote: %w", err)
	}

	binding := &Binding{
		CheckpointHash:  checkpointHash,
		Attestation:     *attestation,
		PreviousCounter: b.lastCounter,
	}

	b.lastCounter = attestation.MonotonicCounter
	return binding, nil
}

// VerifyBinding checks a TPM binding.
// If trustedKeys is provided, verifies the quote signature cryptographically.
// If trustedKeys is nil or empty, performs structural verification only.
func VerifyBinding(binding *Binding, trustedKeys []crypto.PublicKey) error {
	// Input validation
	if binding == nil {
		return errors.New("tpm: binding is nil")
	}

	// Check for zero checkpoint hash (uninitialized)
	var zeroHash [32]byte
	if binding.CheckpointHash == zeroHash {
		return errors.New("tpm: checkpoint hash is zero")
	}

	// Verify counter is strictly increasing (prevents rollback)
	if binding.PreviousCounter > 0 && binding.Attestation.MonotonicCounter <= binding.PreviousCounter {
		return ErrCounterRollback
	}

	// Verify clock is safe (hasn't been set backwards)
	if !binding.Attestation.ClockInfo.Safe {
		return ErrClockNotSafe
	}

	// Verify signature exists
	if len(binding.Attestation.Signature) == 0 {
		return ErrInvalidSignature
	}

	// Verify quote structure exists
	if len(binding.Attestation.Quote) == 0 {
		return errors.New("tpm: quote data is empty")
	}

	// Verify the attestation covers the checkpoint hash
	if len(binding.Attestation.Data) < 32 {
		return errors.New("tpm: attestation data too short")
	}

	var attestedHash [32]byte
	copy(attestedHash[:], binding.Attestation.Data[:32])
	if attestedHash != binding.CheckpointHash {
		return errors.New("tpm: attestation does not match checkpoint")
	}

	// Verify device ID is present
	if len(binding.Attestation.DeviceID) == 0 {
		return errors.New("tpm: device ID is missing")
	}

	// Cryptographic signature verification if trusted keys are provided
	if len(trustedKeys) > 0 {
		verified := false
		for _, pubKey := range trustedKeys {
			if err := verifyQuoteSignature(binding, pubKey); err == nil {
				verified = true
				break
			}
		}
		if !verified {
			return errors.New("tpm: quote signature verification failed against all trusted keys")
		}
	}

	return nil
}

// verifyQuoteSignature verifies the TPM quote signature using the provided public key.
func verifyQuoteSignature(binding *Binding, pubKey crypto.PublicKey) error {
	if pubKey == nil {
		return errors.New("tpm: public key is nil")
	}

	// The signature is over the quote (TPMS_ATTEST structure)
	// Hash the quote data
	quoteHash := sha256.Sum256(binding.Attestation.Quote)

	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		// TPM RSA signatures use RSASSA-PKCS1-v1_5 with SHA-256
		// The signature blob from go-tpm includes the signature scheme info
		// For simplicity, we extract the raw signature if possible
		sig := binding.Attestation.Signature

		// TPM2B_SIGNATURE structure: 2 bytes scheme + signature data
		// Skip the scheme bytes if present (TPMT_SIGNATURE structure)
		if len(sig) > 256 && len(sig) < 512 {
			// Likely has scheme prefix, try to find the raw signature
			// RSASSA signature is typically 256 bytes for 2048-bit key
			rawSig := sig[len(sig)-256:]
			if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, quoteHash[:], rawSig); err == nil {
				return nil
			}
		}

		// Try the signature as-is (might be raw already)
		if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, quoteHash[:], sig); err != nil {
			return fmt.Errorf("RSA signature verification failed: %w", err)
		}
		return nil

	default:
		return fmt.Errorf("tpm: unsupported public key type: %T", pubKey)
	}
}

// VerifyBindingChain verifies a sequence of TPM bindings.
// trustedKeys can be nil for structural verification only, or contain
// crypto.PublicKey values for cryptographic signature verification.
func VerifyBindingChain(bindings []Binding, trustedKeys []crypto.PublicKey) error {
	if len(bindings) == 0 {
		return nil // Empty chain is valid
	}

	var prevCounter uint64

	for i, binding := range bindings {
		// Set expected previous counter
		if i > 0 {
			expectedPrev := bindings[i-1].Attestation.MonotonicCounter
			if binding.PreviousCounter != expectedPrev {
				return fmt.Errorf("tpm: binding %d: previous counter mismatch (expected %d, got %d)",
					i, expectedPrev, binding.PreviousCounter)
			}
		}

		// Verify this binding
		checkBinding := binding
		checkBinding.PreviousCounter = prevCounter
		if err := VerifyBinding(&checkBinding, trustedKeys); err != nil {
			return fmt.Errorf("tpm: binding %d: %w", i, err)
		}

		prevCounter = binding.Attestation.MonotonicCounter
	}

	return nil
}

// NoOpProvider is a fallback when no TPM is available.
type NoOpProvider struct{}

func (NoOpProvider) Available() bool                               { return false }
func (NoOpProvider) Open() error                                   { return ErrTPMNotAvailable }
func (NoOpProvider) Close() error                                  { return nil }
func (NoOpProvider) DeviceID() ([]byte, error)                     { return nil, ErrTPMNotAvailable }
func (NoOpProvider) PublicKey() (crypto.PublicKey, error)          { return nil, ErrTPMNotAvailable }
func (NoOpProvider) IncrementCounter() (uint64, error)             { return 0, ErrTPMNotAvailable }
func (NoOpProvider) GetCounter() (uint64, error)                   { return 0, ErrTPMNotAvailable }
func (NoOpProvider) GetClock() (*ClockInfo, error)                 { return nil, ErrTPMNotAvailable }
func (NoOpProvider) Quote([]byte) (*Attestation, error)            { return nil, ErrTPMNotAvailable }
func (NoOpProvider) QuoteWithPCRs([]byte, PCRSelection) (*Attestation, error) {
	return nil, ErrTPMNotAvailable
}
func (NoOpProvider) ReadPCRs(PCRSelection) (map[int][]byte, error) { return nil, ErrTPMNotAvailable }
func (NoOpProvider) SealKey([]byte, PCRSelection) ([]byte, error)  { return nil, ErrTPMNotAvailable }
func (NoOpProvider) UnsealKey([]byte) ([]byte, error)              { return nil, ErrTPMNotAvailable }
func (NoOpProvider) Manufacturer() string                          { return "none" }
func (NoOpProvider) FirmwareVersion() string                       { return "0.0" }

// SoftwareProvider simulates TPM for testing/development.
// WARNING: Provides no actual security guarantees. Use only for testing.
type SoftwareProvider struct {
	mu           sync.Mutex
	deviceID     []byte
	counter      uint64
	startTime    time.Time
	resetCount   uint32
	isOpen       bool
	sealedData   map[string][]byte // simulated sealed storage
	pcrValues    map[int][]byte    // simulated PCR values
}

// NewSoftwareProvider creates a simulated TPM for testing.
func NewSoftwareProvider() *SoftwareProvider {
	id := sha256.Sum256([]byte(time.Now().String()))

	// Initialize with simulated PCR values
	pcrValues := make(map[int][]byte)
	for _, pcr := range []int{0, 4, 7} {
		hash := sha256.Sum256([]byte(fmt.Sprintf("pcr%d-value", pcr)))
		pcrValues[pcr] = hash[:]
	}

	return &SoftwareProvider{
		deviceID:   id[:16],
		counter:    0,
		startTime:  time.Now(),
		sealedData: make(map[string][]byte),
		pcrValues:  pcrValues,
	}
}

func (s *SoftwareProvider) Available() bool { return true }

func (s *SoftwareProvider) Open() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.isOpen {
		return ErrTPMAlreadyOpen
	}
	s.isOpen = true
	return nil
}

func (s *SoftwareProvider) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.isOpen = false
	return nil
}

func (s *SoftwareProvider) DeviceID() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]byte, len(s.deviceID))
	copy(result, s.deviceID)
	return result, nil
}

func (s *SoftwareProvider) PublicKey() (crypto.PublicKey, error) {
	// Return nil for simulation - real impl would return AK public key
	return nil, nil
}

func (s *SoftwareProvider) IncrementCounter() (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.counter++
	return s.counter, nil
}

func (s *SoftwareProvider) GetCounter() (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.counter, nil
}

func (s *SoftwareProvider) GetClock() (*ClockInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	elapsed := time.Since(s.startTime)
	return &ClockInfo{
		Clock:        uint64(elapsed.Milliseconds()),
		ResetCount:   s.resetCount,
		RestartCount: 0,
		Safe:         true,
	}, nil
}

func (s *SoftwareProvider) Quote(data []byte) (*Attestation, error) {
	return s.QuoteWithPCRs(data, DefaultPCRSelection())
}

func (s *SoftwareProvider) QuoteWithPCRs(data []byte, pcrs PCRSelection) (*Attestation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Increment counter atomically with quote
	s.counter++
	clockInfo, _ := s.getClock()

	// Read PCR values
	pcrVals := make(map[int][]byte)
	for _, pcr := range pcrs.PCRs {
		if val, ok := s.pcrValues[pcr]; ok {
			pcrVals[pcr] = val
		}
	}

	// Compute PCR digest
	pcrDigest := s.computePCRDigest(pcrs)

	// Create simulated signature (HMAC with device ID as key)
	h := sha256.New()
	h.Write(data)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], s.counter)
	h.Write(buf[:])
	h.Write(pcrDigest)
	signature := h.Sum(nil)

	// Create simulated quote structure
	quote := s.createQuoteStructure(data, pcrDigest, clockInfo)

	return &Attestation{
		DeviceID:         s.deviceID,
		PublicKey:        nil,
		MonotonicCounter: s.counter,
		ClockInfo:        *clockInfo,
		Data:             data,
		Signature:        signature,
		Quote:            quote,
		PCRValues:        pcrVals,
		PCRDigest:        pcrDigest,
		CreatedAt:        time.Now(),
	}, nil
}

func (s *SoftwareProvider) ReadPCRs(pcrs PCRSelection) (map[int][]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := make(map[int][]byte)
	for _, pcr := range pcrs.PCRs {
		if val, ok := s.pcrValues[pcr]; ok {
			result[pcr] = val
		} else {
			// Return zero hash for uninitialized PCRs
			result[pcr] = make([]byte, 32)
		}
	}
	return result, nil
}

func (s *SoftwareProvider) SealKey(data []byte, pcrs PCRSelection) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Compute PCR digest as sealing policy
	pcrDigest := s.computePCRDigest(pcrs)

	// Serialize PCR selection for storage in sealed blob
	// Format: version(1) || num_pcrs(1) || pcr_indices(n) || hash_alg(2) || policy_digest(32) || encrypted_data
	pcrCount := len(pcrs.PCRs)
	headerLen := 1 + 1 + pcrCount + 2 + 32 // version + count + indices + hash + digest

	sealed := make([]byte, headerLen+len(data))
	sealed[0] = 1 // version
	sealed[1] = byte(pcrCount)
	for i, pcr := range pcrs.PCRs {
		sealed[2+i] = byte(pcr)
	}
	binary.BigEndian.PutUint16(sealed[2+pcrCount:], uint16(pcrs.Hash))
	copy(sealed[2+pcrCount+2:], pcrDigest)

	// Encrypt data (XOR with digest - NOT SECURE, simulation only)
	dataStart := headerLen
	for i, b := range data {
		sealed[dataStart+i] = b ^ pcrDigest[i%32]
	}

	return sealed, nil
}

func (s *SoftwareProvider) UnsealKey(sealed []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Minimum: version(1) + count(1) + at least one PCR(1) + hash(2) + digest(32) + 1 byte data
	if len(sealed) < 38 {
		return nil, errors.New("tpm: sealed data too short")
	}

	version := sealed[0]
	if version != 1 {
		return nil, fmt.Errorf("tpm: unsupported sealed data version: %d", version)
	}

	pcrCount := int(sealed[1])
	if pcrCount < 1 || pcrCount > 24 {
		return nil, errors.New("tpm: invalid PCR count in sealed data")
	}

	headerLen := 1 + 1 + pcrCount + 2 + 32
	if len(sealed) < headerLen+1 {
		return nil, errors.New("tpm: sealed data corrupted")
	}

	// Reconstruct PCR selection
	pcrs := PCRSelection{
		PCRs: make([]int, pcrCount),
		Hash: HashAlgorithm(binary.BigEndian.Uint16(sealed[2+pcrCount:])),
	}
	for i := 0; i < pcrCount; i++ {
		pcrs.PCRs[i] = int(sealed[2+i])
	}

	// Extract stored policy digest
	policyDigest := sealed[2+pcrCount+2 : 2+pcrCount+2+32]

	// Compute current PCR digest using the same PCR selection
	currentDigest := s.computePCRDigest(pcrs)

	// Check if PCRs match
	if !bytes.Equal(policyDigest, currentDigest) {
		return nil, ErrPCRMismatch
	}

	// Unseal
	dataStart := headerLen
	data := make([]byte, len(sealed)-dataStart)
	for i := range data {
		data[i] = sealed[dataStart+i] ^ currentDigest[i%32]
	}

	return data, nil
}

func (s *SoftwareProvider) Manufacturer() string     { return "Software Simulator" }
func (s *SoftwareProvider) FirmwareVersion() string  { return "1.0.0-sim" }

func (s *SoftwareProvider) getClock() (*ClockInfo, error) {
	elapsed := time.Since(s.startTime)
	return &ClockInfo{
		Clock:        uint64(elapsed.Milliseconds()),
		ResetCount:   s.resetCount,
		RestartCount: 0,
		Safe:         true,
	}, nil
}

func (s *SoftwareProvider) computePCRDigest(pcrs PCRSelection) []byte {
	h := sha256.New()
	for _, pcr := range pcrs.PCRs {
		if val, ok := s.pcrValues[pcr]; ok {
			h.Write(val)
		}
	}
	return h.Sum(nil)
}

func (s *SoftwareProvider) createQuoteStructure(data []byte, pcrDigest []byte, clock *ClockInfo) []byte {
	// Create a simulated TPMS_ATTEST structure
	// This is simplified - real TPM quote has a specific format
	h := sha256.New()
	h.Write([]byte("TPM2_QUOTE"))
	h.Write(data)
	h.Write(pcrDigest)

	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], clock.Clock)
	h.Write(buf[:])
	binary.BigEndian.PutUint32(buf[:4], clock.ResetCount)
	h.Write(buf[:4])

	return h.Sum(nil)
}

// DetectTPM attempts to detect and return an appropriate TPM provider.
// It checks for hardware TPM first, then falls back to NoOpProvider.
func DetectTPM() Provider {
	// Try hardware TPM detection (platform-specific)
	if hw := detectHardwareTPM(); hw != nil {
		return hw
	}

	// No TPM available
	return NoOpProvider{}
}

// detectHardwareTPM is implemented in platform-specific files
// (tpm_linux.go, tpm_darwin.go, etc.)

// Encode serializes a binding to JSON.
func (b *Binding) Encode() ([]byte, error) {
	return json.MarshalIndent(b, "", "  ")
}

// DecodeBinding deserializes a binding from JSON.
func DecodeBinding(data []byte) (*Binding, error) {
	var b Binding
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

// EncodeAttestation serializes an attestation to JSON.
func (a *Attestation) Encode() ([]byte, error) {
	return json.MarshalIndent(a, "", "  ")
}

// DecodeAttestation deserializes an attestation from JSON.
func DecodeAttestation(data []byte) (*Attestation, error) {
	var a Attestation
	if err := json.Unmarshal(data, &a); err != nil {
		return nil, err
	}
	return &a, nil
}

// Hash returns a unique hash of the attestation for verification.
func (a *Attestation) Hash() [32]byte {
	h := sha256.New()
	h.Write([]byte("witnessd-tpm-attestation-v1"))
	h.Write(a.DeviceID)
	h.Write(a.Data)
	h.Write(a.Signature)
	h.Write(a.Quote)

	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], a.MonotonicCounter)
	h.Write(buf[:])
	binary.BigEndian.PutUint64(buf[:], a.ClockInfo.Clock)
	h.Write(buf[:])

	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}
