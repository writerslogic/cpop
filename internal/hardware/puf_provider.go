// Package hardware provides unified PUF (Physically Unclonable Function) abstraction
// with auto-detection of available hardware security features.
//
// This file implements:
// - Unified PUFProvider interface for all platforms
// - Auto-detection of hardware security capabilities
// - Capability querying for attestation support
// - Graceful degradation from hardware to software PUF
//
// Security Level Hierarchy (highest to lowest):
// 1. TPM 2.0 with hardware protection
// 2. Apple Secure Enclave (macOS/iOS)
// 3. Windows Hello with Credential Guard
// 4. Software PUF (device fingerprinting fallback)
package hardware

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"
)

// PUF provider-related errors
var (
	ErrPUFProviderNotAvailable     = errors.New("hardware: no PUF provider available")
	ErrPUFProviderInitFailed       = errors.New("hardware: PUF provider initialization failed")
	ErrPUFProviderChallengeInvalid = errors.New("hardware: invalid PUF provider challenge")
	ErrPUFProviderResponseFailed   = errors.New("hardware: PUF provider response generation failed")
	ErrAttestationNotSupported     = errors.New("hardware: attestation not supported by this PUF")
)

// ProviderPUFType identifies the type of PUF provider implementation.
type ProviderPUFType int

const (
	ProviderPUFTypeUnknown ProviderPUFType = iota
	ProviderPUFTypeTPM            // TPM 2.0 hardware
	ProviderPUFTypeSecureEnclave  // Apple Secure Enclave
	ProviderPUFTypeWindowsHello   // Windows Hello
	ProviderPUFTypeSoftware       // Software-based fallback
)

// String returns a human-readable name for the PUF provider type.
func (t ProviderPUFType) String() string {
	switch t {
	case ProviderPUFTypeTPM:
		return "TPM 2.0"
	case ProviderPUFTypeSecureEnclave:
		return "Secure Enclave"
	case ProviderPUFTypeWindowsHello:
		return "Windows Hello"
	case ProviderPUFTypeSoftware:
		return "Software PUF"
	default:
		return "Unknown"
	}
}

// SecurityLevel indicates the security assurance level.
type SecurityLevel int

const (
	SecurityLevelNone SecurityLevel = iota
	SecurityLevelSoftware    // Software-only protection
	SecurityLevelTEE         // Trusted Execution Environment
	SecurityLevelHardware    // Dedicated hardware security
	SecurityLevelCertified   // FIPS/CC certified hardware
)

// String returns a human-readable security level description.
func (l SecurityLevel) String() string {
	switch l {
	case SecurityLevelNone:
		return "None"
	case SecurityLevelSoftware:
		return "Software"
	case SecurityLevelTEE:
		return "Trusted Execution Environment"
	case SecurityLevelHardware:
		return "Hardware"
	case SecurityLevelCertified:
		return "Certified Hardware"
	default:
		return "Unknown"
	}
}

// PUFProviderCapabilities describes what a PUF provider can do.
type PUFProviderCapabilities struct {
	// Type identifies the PUF implementation
	Type ProviderPUFType `json:"type"`

	// SecurityLevel indicates the security assurance
	SecurityLevel SecurityLevel `json:"security_level"`

	// SupportsAttestation indicates remote attestation support
	SupportsAttestation bool `json:"supports_attestation"`

	// SupportsBiometric indicates biometric protection support
	SupportsBiometric bool `json:"supports_biometric"`

	// SupportsKeyGeneration indicates in-hardware key generation
	SupportsKeyGeneration bool `json:"supports_key_generation"`

	// SupportsSealing indicates PCR/state-based sealing
	SupportsSealing bool `json:"supports_sealing"`

	// MaxChallengeSize is the maximum challenge size in bytes
	MaxChallengeSize int `json:"max_challenge_size"`

	// ResponseSize is the fixed response size in bytes
	ResponseSize int `json:"response_size"`

	// Description provides additional details
	Description string `json:"description"`

	// Manufacturer provides hardware manufacturer info (if available)
	Manufacturer string `json:"manufacturer,omitempty"`

	// FirmwareVersion provides firmware version (if available)
	FirmwareVersion string `json:"firmware_version,omitempty"`
}

// PUFProvider is the unified interface for all PUF provider implementations.
type PUFProvider interface {
	// Type returns the PUF provider implementation type.
	Type() ProviderPUFType

	// DeviceID returns a unique device identifier derived from the PUF.
	DeviceID() string

	// Challenge sends a challenge and returns the response.
	// The response is deterministic for the same challenge on the same device.
	Challenge(challenge []byte) ([]byte, error)

	// Capabilities returns the PUF provider's capabilities.
	Capabilities() PUFProviderCapabilities

	// Available returns whether the PUF provider is currently usable.
	Available() bool

	// Close releases any resources held by the PUF provider.
	Close() error
}

// AttestablePUFProvider extends PUFProvider with remote attestation capabilities.
type AttestablePUFProvider interface {
	PUFProvider

	// GetAttestation generates an attestation report for the given nonce.
	GetAttestation(nonce []byte) (*PUFProviderAttestation, error)

	// GetCertificateChain returns the certificate chain for verification.
	GetCertificateChain() ([][]byte, error)
}

// BiometricPUFProvider extends PUFProvider with biometric protection.
type BiometricPUFProvider interface {
	PUFProvider

	// SetBiometricRequired enables/disables biometric requirement.
	SetBiometricRequired(required bool) error

	// IsBiometricEnabled returns whether biometric is currently required.
	IsBiometricEnabled() bool
}

// PUFProviderAttestation contains attestation evidence from a PUF provider.
type PUFProviderAttestation struct {
	// Type identifies what generated this attestation
	Type ProviderPUFType `json:"type"`

	// Nonce is the challenge nonce that was used
	Nonce []byte `json:"nonce"`

	// Evidence is the raw attestation data (format depends on Type)
	Evidence []byte `json:"evidence"`

	// Signature is the signature over the evidence
	Signature []byte `json:"signature"`

	// Timestamp is when the attestation was generated
	Timestamp time.Time `json:"timestamp"`

	// PlatformState contains platform state at attestation time
	PlatformState map[string][]byte `json:"platform_state,omitempty"`

	// CertificateChain for verification (optional)
	CertificateChain [][]byte `json:"certificate_chain,omitempty"`
}

// PUFProviderManager manages PUF providers and handles auto-detection.
type PUFProviderManager struct {
	mu sync.RWMutex

	// Primary PUF provider
	primary PUFProvider

	// All available PUF providers
	providers []PUFProvider

	// Detection results
	detected    bool
	detectedAt  time.Time
	detectionErr error

	// Configuration
	preferredType ProviderPUFType
	allowSoftware bool
}

// PUFProviderManagerConfig configures the PUF provider manager.
type PUFProviderManagerConfig struct {
	// PreferredType specifies the preferred PUF type (0 for auto)
	PreferredType ProviderPUFType

	// AllowSoftware permits software PUF fallback
	AllowSoftware bool

	// RequireAttestation requires attestation support
	RequireAttestation bool

	// RequireBiometric requires biometric support
	RequireBiometric bool
}

// DefaultPUFProviderManagerConfig returns sensible defaults.
func DefaultPUFProviderManagerConfig() PUFProviderManagerConfig {
	return PUFProviderManagerConfig{
		PreferredType:      ProviderPUFTypeUnknown, // Auto-detect
		AllowSoftware:      true,
		RequireAttestation: false,
		RequireBiometric:   false,
	}
}

// NewPUFProviderManager creates a new PUF provider manager with auto-detection.
func NewPUFProviderManager(config PUFProviderManagerConfig) (*PUFProviderManager, error) {
	pm := &PUFProviderManager{
		providers:     make([]PUFProvider, 0),
		preferredType: config.PreferredType,
		allowSoftware: config.AllowSoftware,
	}

	// Detect available PUF providers
	if err := pm.detect(config); err != nil {
		return nil, err
	}

	return pm, nil
}

// detect discovers available PUF providers.
func (pm *PUFProviderManager) detect(config PUFProviderManagerConfig) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.detected = false
	pm.detectedAt = time.Now()

	// Platform-specific detection
	switch runtime.GOOS {
	case "darwin":
		// Try Secure Enclave first
		if se, err := NewSecureEnclavePUF(); err == nil {
			pm.providers = append(pm.providers, se)
		}

	case "linux":
		// Try TPM
		if tpm, err := NewTPMPUF(); err == nil {
			pm.providers = append(pm.providers, tpm)
		}

	case "windows":
		// Try Windows Hello first, then TPM
		if hello, err := NewWindowsHelloPUF(); err == nil {
			pm.providers = append(pm.providers, hello)
		}
		if tpm, err := NewTPMPUF(); err == nil {
			pm.providers = append(pm.providers, tpm)
		}
	}

	// Add software fallback if allowed
	if config.AllowSoftware {
		if sw, err := NewSoftwarePUF(); err == nil {
			pm.providers = append(pm.providers, sw)
		}
	}

	// Select primary provider
	if err := pm.selectPrimary(config); err != nil {
		pm.detectionErr = err
		return err
	}

	pm.detected = true
	return nil
}

// selectPrimary selects the best available PUF provider as primary.
func (pm *PUFProviderManager) selectPrimary(config PUFProviderManagerConfig) error {
	if len(pm.providers) == 0 {
		return ErrPUFProviderNotAvailable
	}

	// If specific type requested, try to find it
	if config.PreferredType != ProviderPUFTypeUnknown {
		for _, p := range pm.providers {
			if p.Type() == config.PreferredType && p.Available() {
				caps := p.Capabilities()

				// Check attestation requirement
				if config.RequireAttestation && !caps.SupportsAttestation {
					continue
				}

				// Check biometric requirement
				if config.RequireBiometric && !caps.SupportsBiometric {
					continue
				}

				pm.primary = p
				return nil
			}
		}
	}

	// Auto-select best available
	var bestProvider PUFProvider
	bestLevel := SecurityLevelNone

	for _, p := range pm.providers {
		if !p.Available() {
			continue
		}

		caps := p.Capabilities()

		// Check requirements
		if config.RequireAttestation && !caps.SupportsAttestation {
			continue
		}
		if config.RequireBiometric && !caps.SupportsBiometric {
			continue
		}

		// Select highest security level
		if caps.SecurityLevel > bestLevel {
			bestLevel = caps.SecurityLevel
			bestProvider = p
		}
	}

	if bestProvider == nil {
		return ErrPUFProviderNotAvailable
	}

	pm.primary = bestProvider
	return nil
}

// Primary returns the primary PUF provider.
func (pm *PUFProviderManager) Primary() PUFProvider {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.primary
}

// All returns all available PUF providers.
func (pm *PUFProviderManager) All() []PUFProvider {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	result := make([]PUFProvider, len(pm.providers))
	copy(result, pm.providers)
	return result
}

// DeviceID returns the device identifier from the primary PUF provider.
func (pm *PUFProviderManager) DeviceID() string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if pm.primary == nil {
		return ""
	}
	return pm.primary.DeviceID()
}

// Challenge sends a challenge to the primary PUF provider.
func (pm *PUFProviderManager) Challenge(challenge []byte) ([]byte, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if pm.primary == nil {
		return nil, ErrPUFProviderNotAvailable
	}
	return pm.primary.Challenge(challenge)
}

// Capabilities returns capabilities of the primary PUF provider.
func (pm *PUFProviderManager) Capabilities() PUFProviderCapabilities {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if pm.primary == nil {
		return PUFProviderCapabilities{}
	}
	return pm.primary.Capabilities()
}

// GetAttestation gets attestation from the primary PUF provider if supported.
func (pm *PUFProviderManager) GetAttestation(nonce []byte) (*PUFProviderAttestation, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if pm.primary == nil {
		return nil, ErrPUFProviderNotAvailable
	}

	attestable, ok := pm.primary.(AttestablePUFProvider)
	if !ok {
		return nil, ErrAttestationNotSupported
	}

	return attestable.GetAttestation(nonce)
}

// Status returns the detection status.
func (pm *PUFProviderManager) Status() PUFProviderStatus {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	status := PUFProviderStatus{
		Detected:       pm.detected,
		DetectedAt:     pm.detectedAt,
		ProviderCount:  len(pm.providers),
		Providers:      make([]PUFProviderInfo, 0, len(pm.providers)),
	}

	if pm.detectionErr != nil {
		status.Error = pm.detectionErr.Error()
	}

	for _, p := range pm.providers {
		caps := p.Capabilities()
		info := PUFProviderInfo{
			Type:          p.Type().String(),
			DeviceID:      p.DeviceID(),
			Available:     p.Available(),
			SecurityLevel: caps.SecurityLevel.String(),
			IsPrimary:     pm.primary != nil && p.DeviceID() == pm.primary.DeviceID(),
			Capabilities:  caps,
		}
		status.Providers = append(status.Providers, info)
	}

	return status
}

// Close releases all PUF provider resources.
func (pm *PUFProviderManager) Close() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	var lastErr error
	for _, p := range pm.providers {
		if err := p.Close(); err != nil {
			lastErr = err
		}
	}

	pm.providers = nil
	pm.primary = nil
	return lastErr
}

// PUFProviderStatus contains PUF provider detection and status information.
type PUFProviderStatus struct {
	Detected      bool              `json:"detected"`
	DetectedAt    time.Time         `json:"detected_at"`
	Error         string            `json:"error,omitempty"`
	ProviderCount int               `json:"provider_count"`
	Providers     []PUFProviderInfo `json:"providers"`
}

// PUFProviderInfo contains information about a PUF provider.
type PUFProviderInfo struct {
	Type          string          `json:"type"`
	DeviceID      string          `json:"device_id"`
	Available     bool            `json:"available"`
	SecurityLevel string          `json:"security_level"`
	IsPrimary     bool            `json:"is_primary"`
	Capabilities  PUFProviderCapabilities `json:"capabilities"`
}

// ComputeDeviceFingerprint generates a fingerprint from multiple device attributes.
func ComputeDeviceFingerprint(attributes map[string]string) string {
	h := sha256.New()
	h.Write([]byte("witnessd-device-fingerprint-v1"))

	// Sort keys for deterministic hashing
	keys := make([]string, 0, len(attributes))
	for k := range attributes {
		keys = append(keys, k)
	}
	// Simple sort
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[i] > keys[j] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}

	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte{0})
		h.Write([]byte(attributes[k]))
		h.Write([]byte{0})
	}

	hash := h.Sum(nil)
	return fmt.Sprintf("fp-%s", hex.EncodeToString(hash[:8]))
}

// GetPlatformSecurityInfo returns information about platform security features.
func GetPlatformSecurityInfo() PlatformSecurityInfo {
	info := PlatformSecurityInfo{
		Platform:    runtime.GOOS,
		Architecture: runtime.GOARCH,
	}

	switch runtime.GOOS {
	case "darwin":
		info.HasSecureEnclave = hasSecureEnclave()
		info.HasTPM = false // macOS doesn't have TPM
		info.HasBiometric = hasBiometricSupport()
		info.SecurityLevel = SecurityLevelTEE

	case "linux":
		info.HasTPM = hasTPMDevice()
		info.HasSecureEnclave = false
		info.HasBiometric = false
		if info.HasTPM {
			info.SecurityLevel = SecurityLevelHardware
		} else {
			info.SecurityLevel = SecurityLevelSoftware
		}

	case "windows":
		info.HasTPM = hasTPMDevice()
		info.HasWindowsHello = hasWindowsHello()
		info.HasSecureEnclave = false
		info.HasBiometric = info.HasWindowsHello
		if info.HasTPM || info.HasWindowsHello {
			info.SecurityLevel = SecurityLevelHardware
		} else {
			info.SecurityLevel = SecurityLevelSoftware
		}

	default:
		info.SecurityLevel = SecurityLevelSoftware
	}

	return info
}

// PlatformSecurityInfo contains platform security feature information.
type PlatformSecurityInfo struct {
	Platform        string        `json:"platform"`
	Architecture    string        `json:"architecture"`
	HasTPM          bool          `json:"has_tpm"`
	HasSecureEnclave bool         `json:"has_secure_enclave"`
	HasWindowsHello  bool         `json:"has_windows_hello"`
	HasBiometric     bool         `json:"has_biometric"`
	SecurityLevel    SecurityLevel `json:"security_level"`
}

// Platform-specific detection stubs (implemented in platform files)

func hasSecureEnclave() bool {
	// Implemented in secure_enclave_darwin.go
	return false
}

func hasTPMDevice() bool {
	// Implemented in platform-specific files
	return false
}

func hasBiometricSupport() bool {
	// Implemented in platform-specific files
	return false
}

func hasWindowsHello() bool {
	// Implemented in hello_windows.go
	return false
}

// NewTPMPUFProvider creates a TPM-based PUF provider (stub - implemented in platform files).
func NewTPMPUFProvider() (PUFProvider, error) {
	return nil, errors.New("TPM not available on this platform")
}

// NewSecureEnclavePUFProvider creates a Secure Enclave PUF provider (stub - implemented in secure_enclave_darwin.go).
func NewSecureEnclavePUFProvider() (PUFProvider, error) {
	return nil, errors.New("Secure Enclave not available on this platform")
}

// NewWindowsHelloPUFProvider creates a Windows Hello PUF provider (stub - implemented in hello_windows.go).
func NewWindowsHelloPUFProvider() (PUFProvider, error) {
	return nil, errors.New("Windows Hello not available on this platform")
}

// Legacy compatibility: TPMInterface adapter
// This adapts the new PUFProvider interface to the existing TPMInterface

// TPMPUFProviderAdapter adapts TPMInterface to PUFProvider interface.
type TPMPUFProviderAdapter struct {
	tpm      TPMInterface
	deviceID string
}

// NewTPMPUFProviderAdapter creates a PUFProvider adapter for an existing TPMInterface.
func NewTPMPUFProviderAdapter(tpm TPMInterface) (*TPMPUFProviderAdapter, error) {
	if tpm == nil || !tpm.Available() {
		return nil, ErrTPMNotAvailable
	}

	// Generate device ID from endorsement key
	ek, err := tpm.GetEndorsementKeyPublic()
	if err != nil {
		return nil, fmt.Errorf("failed to get EK: %w", err)
	}

	hash := sha256.Sum256(ek)
	deviceID := fmt.Sprintf("tpm-%s", hex.EncodeToString(hash[:8]))

	return &TPMPUFProviderAdapter{
		tpm:      tpm,
		deviceID: deviceID,
	}, nil
}

// Type implements PUFProvider.Type.
func (a *TPMPUFProviderAdapter) Type() ProviderPUFType {
	return ProviderPUFTypeTPM
}

// DeviceID implements PUFProvider.DeviceID.
func (a *TPMPUFProviderAdapter) DeviceID() string {
	return a.deviceID
}

// Challenge implements PUFProvider.Challenge using TPM quote.
func (a *TPMPUFProviderAdapter) Challenge(challenge []byte) ([]byte, error) {
	// Use TPM quote with the challenge as nonce
	quote, err := a.tpm.Quote(challenge, []int{0, 1, 2, 3, 4, 7})
	if err != nil {
		return nil, fmt.Errorf("TPM quote failed: %w", err)
	}

	// Combine quote data to form response
	h := sha256.New()
	h.Write(quote.RawQuote)
	h.Write(quote.Signature)
	return h.Sum(nil), nil
}

// Capabilities implements PUFProvider.Capabilities.
func (a *TPMPUFProviderAdapter) Capabilities() PUFProviderCapabilities {
	return PUFProviderCapabilities{
		Type:                 ProviderPUFTypeTPM,
		SecurityLevel:        SecurityLevelHardware,
		SupportsAttestation:  true,
		SupportsBiometric:    false,
		SupportsKeyGeneration: true,
		SupportsSealing:      true,
		MaxChallengeSize:     64,
		ResponseSize:         32,
		Description:          "TPM 2.0 Hardware Security Module",
	}
}

// Available implements PUFProvider.Available.
func (a *TPMPUFProviderAdapter) Available() bool {
	return a.tpm.Available()
}

// Close implements PUFProvider.Close.
func (a *TPMPUFProviderAdapter) Close() error {
	// TPMInterface doesn't have Close
	return nil
}

// GetAttestation implements AttestablePUFProvider.GetAttestation.
func (a *TPMPUFProviderAdapter) GetAttestation(nonce []byte) (*PUFProviderAttestation, error) {
	quote, err := a.tpm.Quote(nonce, []int{0, 1, 2, 3, 4, 7})
	if err != nil {
		return nil, fmt.Errorf("TPM quote failed: %w", err)
	}

	// Build platform state from PCR values
	platformState := make(map[string][]byte)
	for idx, val := range quote.PCRValues {
		platformState[fmt.Sprintf("pcr%d", idx)] = val
	}

	return &PUFProviderAttestation{
		Type:          ProviderPUFTypeTPM,
		Nonce:         nonce,
		Evidence:      quote.RawQuote,
		Signature:     quote.Signature,
		Timestamp:     quote.Timestamp,
		PlatformState: platformState,
	}, nil
}

// GetCertificateChain implements AttestablePUFProvider.GetCertificateChain.
func (a *TPMPUFProviderAdapter) GetCertificateChain() ([][]byte, error) {
	ek, err := a.tpm.GetEndorsementKeyPublic()
	if err != nil {
		return nil, err
	}
	// Return EK as the only certificate (in practice would include manufacturer certs)
	return [][]byte{ek}, nil
}
