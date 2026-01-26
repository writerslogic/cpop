// Package tpm implements Layer 3 Hardware Attestation via TPM 2.0.
//
// TPM (Trusted Platform Module) provides hardware-backed security:
// - Monotonic counter: Cannot be rolled back
// - Secure clock: Hardware time attestation
// - Platform attestation: Proves execution environment
//
// This package defines interfaces and a no-op fallback for systems without TPM.
// Real TPM integration requires platform-specific code (go-tpm library).
package tpm

import (
	"crypto"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"time"
)

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
	Data      []byte `json:"data"`      // What was attested
	Signature []byte `json:"signature"` // TPM signature
	Quote     []byte `json:"quote"`     // TPM quote structure

	// Metadata
	CreatedAt time.Time `json:"created_at"`
}

// ClockInfo contains TPM clock attestation.
type ClockInfo struct {
	// Clock value in milliseconds since TPM boot
	Clock uint64 `json:"clock"`

	// Reset count (number of TPM resets)
	ResetCount uint32 `json:"reset_count"`

	// Restart count (number of TPM restarts without reset)
	RestartCount uint32 `json:"restart_count"`

	// Safe flag (true if clock is reliable)
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
type Provider interface {
	// Available returns true if TPM is available.
	Available() bool

	// DeviceID returns the TPM's unique identifier.
	DeviceID() ([]byte, error)

	// PublicKey returns the TPM's attestation public key.
	PublicKey() (crypto.PublicKey, error)

	// IncrementCounter atomically increments and returns the monotonic counter.
	IncrementCounter() (uint64, error)

	// GetCounter returns the current counter value without incrementing.
	GetCounter() (uint64, error)

	// GetClock returns the current TPM clock info.
	GetClock() (*ClockInfo, error)

	// Quote creates a TPM quote over the given data.
	Quote(data []byte) (*Attestation, error)

	// Close releases TPM resources.
	Close() error
}

// Binder creates TPM bindings for checkpoints.
type Binder struct {
	provider Provider
	lastCounter uint64
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
	if !b.Available() {
		return nil, errors.New("TPM not available")
	}

	// Get attestation
	attestation, err := b.provider.Quote(checkpointHash[:])
	if err != nil {
		return nil, err
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
func VerifyBinding(binding *Binding, trustedKeys [][]byte) error {
	// Verify counter is strictly increasing
	if binding.Attestation.MonotonicCounter <= binding.PreviousCounter {
		return errors.New("monotonic counter not strictly increasing")
	}

	// Verify clock is safe
	if !binding.Attestation.ClockInfo.Safe {
		return errors.New("TPM clock is not in safe state")
	}

	// Verify signature against trusted keys
	// (This would verify the TPM quote signature in a real implementation)
	if len(binding.Attestation.Signature) == 0 {
		return errors.New("missing TPM signature")
	}

	// Verify the attestation covers the checkpoint hash
	if len(binding.Attestation.Data) < 32 {
		return errors.New("attestation data too short")
	}

	var attestedHash [32]byte
	copy(attestedHash[:], binding.Attestation.Data[:32])
	if attestedHash != binding.CheckpointHash {
		return errors.New("attestation does not match checkpoint")
	}

	return nil
}

// NoOpProvider is a fallback when no TPM is available.
type NoOpProvider struct{}

func (NoOpProvider) Available() bool                     { return false }
func (NoOpProvider) DeviceID() ([]byte, error)           { return nil, errors.New("no TPM") }
func (NoOpProvider) PublicKey() (crypto.PublicKey, error) { return nil, errors.New("no TPM") }
func (NoOpProvider) IncrementCounter() (uint64, error)   { return 0, errors.New("no TPM") }
func (NoOpProvider) GetCounter() (uint64, error)         { return 0, errors.New("no TPM") }
func (NoOpProvider) GetClock() (*ClockInfo, error)       { return nil, errors.New("no TPM") }
func (NoOpProvider) Quote([]byte) (*Attestation, error)  { return nil, errors.New("no TPM") }
func (NoOpProvider) Close() error                        { return nil }

// SoftwareProvider simulates TPM for testing/development.
// WARNING: Provides no actual security guarantees.
type SoftwareProvider struct {
	deviceID    []byte
	counter     uint64
	startTime   time.Time
	resetCount  uint32
}

// NewSoftwareProvider creates a simulated TPM.
func NewSoftwareProvider() *SoftwareProvider {
	id := sha256.Sum256([]byte(time.Now().String()))
	return &SoftwareProvider{
		deviceID:  id[:16],
		counter:   0,
		startTime: time.Now(),
	}
}

func (s *SoftwareProvider) Available() bool { return true }

func (s *SoftwareProvider) DeviceID() ([]byte, error) {
	return s.deviceID, nil
}

func (s *SoftwareProvider) PublicKey() (crypto.PublicKey, error) {
	// Return a dummy public key for simulation
	return nil, nil
}

func (s *SoftwareProvider) IncrementCounter() (uint64, error) {
	s.counter++
	return s.counter, nil
}

func (s *SoftwareProvider) GetCounter() (uint64, error) {
	return s.counter, nil
}

func (s *SoftwareProvider) GetClock() (*ClockInfo, error) {
	elapsed := time.Since(s.startTime)
	return &ClockInfo{
		Clock:        uint64(elapsed.Milliseconds()),
		ResetCount:   s.resetCount,
		RestartCount: 0,
		Safe:         true,
	}, nil
}

func (s *SoftwareProvider) Quote(data []byte) (*Attestation, error) {
	counter, _ := s.IncrementCounter()
	clockInfo, _ := s.GetClock()

	// Create attestation data
	h := sha256.New()
	h.Write(data)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	h.Write(buf[:])

	return &Attestation{
		DeviceID:         s.deviceID,
		PublicKey:        nil,
		MonotonicCounter: counter,
		ClockInfo:        *clockInfo,
		Data:             data,
		Signature:        h.Sum(nil), // Simulated "signature"
		Quote:            nil,
		CreatedAt:        time.Now(),
	}, nil
}

func (s *SoftwareProvider) Close() error { return nil }

// DetectTPM attempts to detect and open a TPM.
func DetectTPM() Provider {
	// Try to detect real TPM
	// For now, return NoOp. Real implementation would use go-tpm.
	return NoOpProvider{}
}

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
