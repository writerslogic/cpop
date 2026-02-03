//go:build darwin || linux || windows

package keystroke

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"witnessd/internal/tpm"
)

// TPMBindingConfig configures TPM integration for keystroke protection.
type TPMBindingConfig struct {
	// UseTPMCounter uses TPM hardware monotonic counter (prevents rollback)
	UseTPMCounter bool

	// UseTPMAttestation binds snapshots to TPM attestation quotes
	UseTPMAttestation bool

	// SealIntegrityKey seals the integrity key to platform state (PCRs)
	SealIntegrityKey bool

	// PCRs to bind to (default: 0, 1, 7 for firmware + boot + secure boot)
	PCRSelection []int

	// QuoteInterval is how often to create TPM-attested checkpoints
	QuoteInterval time.Duration
}

// DefaultTPMBindingConfig returns sensible defaults for TPM binding.
func DefaultTPMBindingConfig() TPMBindingConfig {
	return TPMBindingConfig{
		UseTPMCounter:     true,
		UseTPMAttestation: true,
		SealIntegrityKey:  true,
		PCRSelection:      []int{0, 1, 7}, // Boot chain
		QuoteInterval:     5 * time.Minute,
	}
}

// TPMBoundCounter extends HardenedCounter with TPM hardware protection.
// This provides the strongest possible integrity guarantees:
// - Hardware monotonic counter prevents replay/rollback
// - TPM attestation proves platform hasn't been tampered
// - Key sealing binds counter state to platform configuration
type TPMBoundCounter struct {
	*HardenedCounter

	mu      sync.RWMutex
	config  TPMBindingConfig
	tpmProv tpm.Provider
	tpmOpen bool

	// TPM state
	tpmCounter     uint64
	lastQuote      *tpm.Attestation
	lastQuoteTime  time.Time
	sealedKeyData  []byte
	deviceID       []byte

	// Binding chain - each update includes TPM counter
	bindingChain [32]byte
}

// TPMBoundSnapshot extends SealedSnapshot with TPM attestation.
type TPMBoundSnapshot struct {
	SealedSnapshot

	// TPM-specific fields
	TPMCounter    uint64           `json:"tpm_counter"`
	DeviceID      []byte           `json:"device_id"`
	Attestation   *tpm.Attestation `json:"attestation,omitempty"`
	BindingHash   [32]byte         `json:"binding_hash"`
	TPMAvailable  bool             `json:"tpm_available"`
}

// NewTPMBoundCounter creates a counter with TPM hardware protection.
// If TPM is unavailable, falls back to software-only HardenedCounter.
func NewTPMBoundCounter(config TPMBindingConfig) (*TPMBoundCounter, error) {
	// Create base hardened counter
	hardened, err := NewHardenedCounter()
	if err != nil {
		return nil, fmt.Errorf("failed to create hardened counter: %w", err)
	}

	tc := &TPMBoundCounter{
		HardenedCounter: hardened,
		config:          config,
	}

	// Try to open TPM
	tc.tpmProv = tpm.DetectTPM()
	if tc.tpmProv != nil && tc.tpmProv.Available() {
		if err := tc.tpmProv.Open(); err == nil {
			tc.tpmOpen = true

			// Get device ID
			if devID, err := tc.tpmProv.DeviceID(); err == nil {
				tc.deviceID = devID
			}

			// Get initial counter value
			if config.UseTPMCounter {
				if counter, err := tc.tpmProv.GetCounter(); err == nil {
					tc.tpmCounter = counter
				}
			}

			// Seal integrity key if configured
			if config.SealIntegrityKey {
				tc.sealIntegrityKey()
			}

			// Initialize binding chain with device ID
			tc.initBindingChain()
		}
	}

	return tc, nil
}

// initBindingChain creates the initial binding chain value.
func (tc *TPMBoundCounter) initBindingChain() {
	h := sha256.New()
	h.Write([]byte("witnessd-tpm-binding-v1"))
	h.Write(tc.deviceID)

	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], tc.tpmCounter)
	h.Write(buf[:])

	// Include random nonce
	nonce := make([]byte, 16)
	rand.Read(nonce)
	h.Write(nonce)

	copy(tc.bindingChain[:], h.Sum(nil))
}

// sealIntegrityKey seals the counter's integrity key to TPM state.
func (tc *TPMBoundCounter) sealIntegrityKey() error {
	if !tc.tpmOpen || !tc.config.SealIntegrityKey {
		return nil
	}

	// Get the integrity key from the underlying counter
	tc.HardenedCounter.mu.RLock()
	keyData := tc.HardenedCounter.integrityKey[:]
	tc.HardenedCounter.mu.RUnlock()

	// Seal to platform state
	pcrSel := tpm.PCRSelection{PCRs: tc.config.PCRSelection}
	sealed, err := tc.tpmProv.SealKey(keyData, pcrSel)
	if err != nil {
		return fmt.Errorf("failed to seal integrity key: %w", err)
	}

	tc.sealedKeyData = sealed
	return nil
}

// RecordKeystrokeWithTPM records a keystroke with TPM binding.
func (tc *TPMBoundCounter) RecordKeystrokeWithTPM() (legitimate bool, report AnomalyReport, err error) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	// Record in underlying hardened counter
	legit, reason := tc.HardenedCounter.RecordKeystroke()

	// Update binding chain with TPM counter
	if tc.tpmOpen && tc.config.UseTPMCounter {
		// Increment TPM counter (atomic, hardware-backed)
		newCounter, err := tc.tpmProv.IncrementCounter()
		if err == nil {
			tc.tpmCounter = newCounter
		}

		// Update binding chain
		tc.updateBindingChain()
	}

	// Check if we need a new TPM quote
	if tc.tpmOpen && tc.config.UseTPMAttestation {
		if time.Since(tc.lastQuoteTime) >= tc.config.QuoteInterval {
			tc.createQuote()
		}
	}

	return legit, tc.HardenedCounter.AnomalyReport(), errors.New(reason)
}

// updateBindingChain updates the TPM binding chain.
func (tc *TPMBoundCounter) updateBindingChain() {
	h := sha256.New()
	h.Write(tc.bindingChain[:])

	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], tc.tpmCounter)
	h.Write(buf[:])

	binary.BigEndian.PutUint64(buf[:], tc.HardenedCounter.validated.Count())
	h.Write(buf[:])

	binary.BigEndian.PutUint64(buf[:], uint64(time.Now().UnixNano()))
	h.Write(buf[:])

	copy(tc.bindingChain[:], h.Sum(nil))
}

// createQuote creates a TPM attestation quote.
func (tc *TPMBoundCounter) createQuote() {
	if !tc.tpmOpen {
		return
	}

	// Create data to attest
	attestData := tc.createAttestationData()

	// Get TPM quote
	pcrSel := tpm.PCRSelection{PCRs: tc.config.PCRSelection}
	quote, err := tc.tpmProv.QuoteWithPCRs(attestData, pcrSel)
	if err == nil {
		tc.lastQuote = quote
		tc.lastQuoteTime = time.Now()
	}
}

// createAttestationData creates the data to be attested by TPM.
func (tc *TPMBoundCounter) createAttestationData() []byte {
	h := sha256.New()
	h.Write([]byte("witnessd-keystroke-attestation-v1"))

	var buf [8]byte

	// Include counter state
	binary.BigEndian.PutUint64(buf[:], tc.HardenedCounter.validated.Count())
	h.Write(buf[:])

	// Include TPM counter
	binary.BigEndian.PutUint64(buf[:], tc.tpmCounter)
	h.Write(buf[:])

	// Include binding chain
	h.Write(tc.bindingChain[:])

	// Include timestamp
	binary.BigEndian.PutUint64(buf[:], uint64(time.Now().UnixNano()))
	h.Write(buf[:])

	return h.Sum(nil)
}

// SealWithTPM creates a TPM-bound snapshot.
func (tc *TPMBoundCounter) SealWithTPM() (TPMBoundSnapshot, error) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	// Get base snapshot
	baseSnap, err := tc.HardenedCounter.Seal()
	if err != nil {
		return TPMBoundSnapshot{}, err
	}

	snap := TPMBoundSnapshot{
		SealedSnapshot: baseSnap,
		TPMCounter:     tc.tpmCounter,
		DeviceID:       tc.deviceID,
		BindingHash:    tc.bindingChain,
		TPMAvailable:   tc.tpmOpen,
	}

	// Include attestation if available and recent
	if tc.tpmOpen && tc.config.UseTPMAttestation {
		// Create fresh quote for snapshot
		attestData := tc.createAttestationData()
		pcrSel := tpm.PCRSelection{PCRs: tc.config.PCRSelection}
		if quote, err := tc.tpmProv.QuoteWithPCRs(attestData, pcrSel); err == nil {
			snap.Attestation = quote
		}
	}

	return snap, nil
}

// VerifyTPMBoundSnapshot verifies a TPM-bound snapshot.
func (tc *TPMBoundCounter) VerifyTPMBoundSnapshot(snap TPMBoundSnapshot) error {
	// Verify base snapshot
	if !tc.HardenedCounter.VerifySnapshot(snap.SealedSnapshot) {
		return errors.New("base snapshot verification failed")
	}

	// If TPM was available, verify TPM-specific fields
	if snap.TPMAvailable {
		// Verify device ID matches
		if tc.tpmOpen && len(tc.deviceID) > 0 {
			if !hmacEqual(snap.DeviceID, tc.deviceID) {
				return errors.New("device ID mismatch")
			}
		}

		// Verify attestation if present
		if snap.Attestation != nil {
			if err := tc.verifyAttestation(snap); err != nil {
				return fmt.Errorf("attestation verification failed: %w", err)
			}
		}
	}

	return nil
}

// verifyAttestation verifies a TPM attestation quote.
func (tc *TPMBoundCounter) verifyAttestation(snap TPMBoundSnapshot) error {
	if snap.Attestation == nil {
		return nil
	}

	// Recreate expected attestation data
	h := sha256.New()
	h.Write([]byte("witnessd-keystroke-attestation-v1"))

	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], snap.Count)
	h.Write(buf[:])

	binary.BigEndian.PutUint64(buf[:], snap.TPMCounter)
	h.Write(buf[:])

	h.Write(snap.BindingHash[:])

	binary.BigEndian.PutUint64(buf[:], uint64(snap.Timestamp.UnixNano()))
	h.Write(buf[:])

	expectedData := h.Sum(nil)

	// Verify attestation data matches
	if !hmacEqual(snap.Attestation.Data, expectedData) {
		return errors.New("attestation data mismatch")
	}

	// Verify counter monotonicity
	if snap.Attestation.MonotonicCounter < snap.TPMCounter {
		return errors.New("TPM counter rollback detected")
	}

	return nil
}

// Close closes the TPM connection.
func (tc *TPMBoundCounter) Close() error {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	tc.HardenedCounter.Stop()

	if tc.tpmOpen && tc.tpmProv != nil {
		tc.tpmProv.Close()
		tc.tpmOpen = false
	}

	return nil
}

// TPMStatus returns the current TPM status.
func (tc *TPMBoundCounter) TPMStatus() TPMStatus {
	tc.mu.RLock()
	defer tc.mu.RUnlock()

	status := TPMStatus{
		Available:       tc.tpmOpen,
		Counter:         tc.tpmCounter,
		DeviceID:        tc.deviceID,
		LastQuoteTime:   tc.lastQuoteTime,
		SealedKey:       len(tc.sealedKeyData) > 0,
		BindingChain:    tc.bindingChain,
	}

	if tc.tpmOpen && tc.tpmProv != nil {
		status.Manufacturer = tc.tpmProv.Manufacturer()
		status.FirmwareVersion = tc.tpmProv.FirmwareVersion()
	}

	return status
}

// TPMStatus contains TPM status information.
type TPMStatus struct {
	Available       bool
	Manufacturer    string
	FirmwareVersion string
	Counter         uint64
	DeviceID        []byte
	LastQuoteTime   time.Time
	SealedKey       bool
	BindingChain    [32]byte
}

// ExportEvidenceWithTPM exports counter evidence with full TPM binding.
func (tc *TPMBoundCounter) ExportEvidenceWithTPM() (*TPMBoundEvidence, error) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	// Get all validation stats
	validStats := tc.HardenedCounter.ValidationStats()
	syntheticStats := tc.HardenedCounter.SyntheticEventStats()
	anomalyReport := tc.HardenedCounter.AnomalyReport()

	// Create final attestation
	var finalAttestation *tpm.Attestation
	if tc.tpmOpen && tc.config.UseTPMAttestation {
		attestData := tc.createAttestationData()
		pcrSel := tpm.PCRSelection{PCRs: tc.config.PCRSelection}
		if quote, err := tc.tpmProv.QuoteWithPCRs(attestData, pcrSel); err == nil {
			finalAttestation = quote
		}
	}

	evidence := &TPMBoundEvidence{
		ExportTime:        time.Now(),
		ValidatedCount:    tc.HardenedCounter.Count(),
		TPMCounter:        tc.tpmCounter,
		DeviceID:          tc.deviceID,
		BindingChain:      tc.bindingChain,
		ValidationStats:   validStats,
		SyntheticStats:    syntheticStats,
		AnomalyReport:     anomalyReport,
		Attestation:       finalAttestation,
		TPMAvailable:      tc.tpmOpen,
	}

	// Sign the evidence
	evidence.computeSignature(tc.HardenedCounter.integrityKey[:])

	return evidence, nil
}

// TPMBoundEvidence is the full evidence export with TPM binding.
type TPMBoundEvidence struct {
	ExportTime        time.Time             `json:"export_time"`
	ValidatedCount    uint64                `json:"validated_count"`
	TPMCounter        uint64                `json:"tpm_counter"`
	DeviceID          []byte                `json:"device_id"`
	BindingChain      [32]byte              `json:"binding_chain"`
	ValidationStats   ValidationStats       `json:"validation_stats"`
	SyntheticStats    SyntheticEventStats   `json:"synthetic_stats"`
	AnomalyReport     AnomalyReport         `json:"anomaly_report"`
	Attestation       *tpm.Attestation      `json:"attestation,omitempty"`
	TPMAvailable      bool                  `json:"tpm_available"`
	Signature         [32]byte              `json:"signature"`
}

// computeSignature computes the evidence signature.
func (e *TPMBoundEvidence) computeSignature(key []byte) {
	h := hmac.New(sha256.New, key)

	binary.Write(h, binary.BigEndian, e.ExportTime.UnixNano())
	binary.Write(h, binary.BigEndian, e.ValidatedCount)
	binary.Write(h, binary.BigEndian, e.TPMCounter)
	h.Write(e.DeviceID)
	h.Write(e.BindingChain[:])

	copy(e.Signature[:], h.Sum(nil))
}

// VerifySignature verifies the evidence signature.
func (e *TPMBoundEvidence) VerifySignature(key []byte) bool {
	h := hmac.New(sha256.New, key)

	binary.Write(h, binary.BigEndian, e.ExportTime.UnixNano())
	binary.Write(h, binary.BigEndian, e.ValidatedCount)
	binary.Write(h, binary.BigEndian, e.TPMCounter)
	h.Write(e.DeviceID)
	h.Write(e.BindingChain[:])

	expected := h.Sum(nil)
	return hmac.Equal(e.Signature[:], expected)
}

// JSON serialization
func (e *TPMBoundEvidence) JSON() ([]byte, error) {
	return json.MarshalIndent(e, "", "  ")
}

// hmacEqual compares two byte slices in constant time.
func hmacEqual(a, b []byte) bool {
	return hmac.Equal(a, b)
}
