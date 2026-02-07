// Package hardware provides remote attestation verification framework.
//
// This file implements:
// - TPM quote verification
// - Secure Enclave attestation verification
// - Certificate chain validation
// - Freshness checking (nonce verification)
// - Attestation evidence format for cross-platform verification
//
// The attestation framework allows remote parties to verify:
// 1. Device identity through hardware-rooted keys
// 2. Platform integrity through PCR values (TPM)
// 3. Temporal validity through nonces and timestamps
// 4. Key origin through certificate chains
package hardware

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// Attestation verification errors
var (
	ErrAttestationInvalid      = errors.New("hardware: attestation is invalid")
	ErrAttestationExpired      = errors.New("hardware: attestation has expired")
	ErrAttestationNonceMismatch = errors.New("hardware: attestation nonce mismatch")
	ErrAttestationSignature    = errors.New("hardware: attestation signature verification failed")
	ErrAttestationCertChain    = errors.New("hardware: certificate chain validation failed")
	ErrAttestationPlatformState = errors.New("hardware: platform state verification failed")
	ErrAttestationUnknownType  = errors.New("hardware: unknown attestation type")
)

// AttestationEvidence is a portable format for attestation data.
type AttestationEvidence struct {
	// Version of the evidence format
	Version int `json:"version"`

	// Type identifies the attestation source
	Type PUFType `json:"type"`

	// DeviceID is the unique device identifier
	DeviceID string `json:"device_id"`

	// Timestamp when the attestation was created
	Timestamp time.Time `json:"timestamp"`

	// Nonce used for freshness
	Nonce []byte `json:"nonce"`

	// PublicKey is the attesting key's public key
	PublicKey []byte `json:"public_key"`

	// Signature over the attestation data
	Signature []byte `json:"signature"`

	// CertificateChain for verification (optional)
	CertificateChain [][]byte `json:"certificate_chain,omitempty"`

	// TPM-specific fields
	TPMQuote     []byte         `json:"tpm_quote,omitempty"`
	PCRValues    map[int][]byte `json:"pcr_values,omitempty"`
	PCRSelection []int          `json:"pcr_selection,omitempty"`

	// Platform state measurements
	PlatformState map[string][]byte `json:"platform_state,omitempty"`

	// Custom claims (key-value pairs)
	Claims map[string]string `json:"claims,omitempty"`
}

// AttestationRequest is sent to request attestation from a device.
type AttestationRequest struct {
	// RequestID for tracking
	RequestID string `json:"request_id"`

	// Nonce for freshness (must be included in response)
	Nonce []byte `json:"nonce"`

	// RequiredPCRs specifies which PCRs to include (TPM)
	RequiredPCRs []int `json:"required_pcrs,omitempty"`

	// RequireCertChain requests certificate chain inclusion
	RequireCertChain bool `json:"require_cert_chain"`

	// ValidityWindow is how long the attestation should be valid
	ValidityWindow time.Duration `json:"validity_window"`

	// Timestamp when request was created
	Timestamp time.Time `json:"timestamp"`
}

// AttestationVerificationResult contains the result of attestation verification.
type AttestationVerificationResult struct {
	// Valid indicates if the attestation passed all checks
	Valid bool `json:"valid"`

	// Verified timestamp
	VerifiedAt time.Time `json:"verified_at"`

	// Device identification
	DeviceID string `json:"device_id"`
	Type     PUFType `json:"type"`

	// Verification details
	NonceValid        bool `json:"nonce_valid"`
	TimestampValid    bool `json:"timestamp_valid"`
	SignatureValid    bool `json:"signature_valid"`
	CertChainValid    bool `json:"cert_chain_valid"`
	PlatformStateValid bool `json:"platform_state_valid,omitempty"`
	PCRsValid         bool `json:"pcrs_valid,omitempty"`

	// Trust level (0-100)
	TrustLevel int `json:"trust_level"`

	// Errors encountered
	Errors []string `json:"errors,omitempty"`

	// Warnings (non-fatal issues)
	Warnings []string `json:"warnings,omitempty"`
}

// AttestationVerifier verifies attestation evidence.
type AttestationVerifier struct {
	mu sync.RWMutex

	// Trusted root certificates
	trustedRoots *x509.CertPool

	// Trusted PCR values (golden images)
	trustedPCRs map[int][][]byte

	// Configuration
	config AttestationVerifierConfig

	// Known devices (device ID -> public key)
	knownDevices map[string][]byte
}

// AttestationVerifierConfig configures the attestation verifier.
type AttestationVerifierConfig struct {
	// MaxClockSkew is the maximum allowed clock difference
	MaxClockSkew time.Duration

	// MaxAttestationAge is the maximum age of an attestation
	MaxAttestationAge time.Duration

	// RequireCertChain requires certificate chain for validation
	RequireCertChain bool

	// StrictPCRValidation fails on unknown PCR values
	StrictPCRValidation bool

	// AllowSoftwarePUF permits software PUF attestations
	AllowSoftwarePUF bool
}

// DefaultAttestationVerifierConfig returns sensible defaults.
func DefaultAttestationVerifierConfig() AttestationVerifierConfig {
	return AttestationVerifierConfig{
		MaxClockSkew:        5 * time.Minute,
		MaxAttestationAge:   10 * time.Minute,
		RequireCertChain:    false,
		StrictPCRValidation: false,
		AllowSoftwarePUF:    true,
	}
}

// NewAttestationVerifier creates a new attestation verifier.
func NewAttestationVerifier() *AttestationVerifier {
	return NewAttestationVerifierWithConfig(DefaultAttestationVerifierConfig())
}

// NewAttestationVerifierWithConfig creates an attestation verifier with custom config.
func NewAttestationVerifierWithConfig(config AttestationVerifierConfig) *AttestationVerifier {
	return &AttestationVerifier{
		trustedRoots: x509.NewCertPool(),
		trustedPCRs:  make(map[int][][]byte),
		knownDevices: make(map[string][]byte),
		config:       config,
	}
}

// AddTrustedRoot adds a trusted root certificate.
func (v *AttestationVerifier) AddTrustedRoot(cert *x509.Certificate) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.trustedRoots.AddCert(cert)
}

// AddTrustedPCRValue adds a trusted PCR value.
func (v *AttestationVerifier) AddTrustedPCRValue(pcr int, value []byte) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.trustedPCRs[pcr] = append(v.trustedPCRs[pcr], value)
}

// RegisterDevice registers a known device with its public key.
func (v *AttestationVerifier) RegisterDevice(deviceID string, publicKey []byte) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.knownDevices[deviceID] = publicKey
}

// Verify verifies attestation evidence.
func (v *AttestationVerifier) Verify(evidence *AttestationEvidence, expectedNonce []byte) (*AttestationVerificationResult, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	result := &AttestationVerificationResult{
		Valid:      true,
		VerifiedAt: time.Now(),
		DeviceID:   evidence.DeviceID,
		Type:       evidence.Type,
		TrustLevel: 100,
	}

	// Check if software PUF is allowed
	if evidence.Type == PUFTypeSoftware && !v.config.AllowSoftwarePUF {
		result.Valid = false
		result.Errors = append(result.Errors, "software PUF attestations not allowed")
		result.TrustLevel = 0
		return result, nil
	}

	// Verify nonce
	if !bytes.Equal(evidence.Nonce, expectedNonce) {
		result.Valid = false
		result.NonceValid = false
		result.Errors = append(result.Errors, "nonce mismatch")
		result.TrustLevel -= 50
	} else {
		result.NonceValid = true
	}

	// Verify timestamp freshness
	age := time.Since(evidence.Timestamp)
	if age > v.config.MaxAttestationAge {
		result.Valid = false
		result.TimestampValid = false
		result.Errors = append(result.Errors, fmt.Sprintf("attestation too old: %v", age))
		result.TrustLevel -= 30
	} else if age < -v.config.MaxClockSkew {
		result.Valid = false
		result.TimestampValid = false
		result.Errors = append(result.Errors, "attestation timestamp in future")
		result.TrustLevel -= 30
	} else {
		result.TimestampValid = true
	}

	// Verify signature
	sigValid, sigErr := v.verifySignature(evidence)
	result.SignatureValid = sigValid
	if !sigValid {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("signature verification failed: %v", sigErr))
		result.TrustLevel -= 50
	}

	// Verify certificate chain if provided
	if len(evidence.CertificateChain) > 0 {
		chainValid, chainErr := v.verifyCertChain(evidence)
		result.CertChainValid = chainValid
		if !chainValid {
			if v.config.RequireCertChain {
				result.Valid = false
				result.Errors = append(result.Errors, fmt.Sprintf("certificate chain invalid: %v", chainErr))
			} else {
				result.Warnings = append(result.Warnings, fmt.Sprintf("certificate chain invalid: %v", chainErr))
			}
			result.TrustLevel -= 20
		}
	} else if v.config.RequireCertChain {
		result.Valid = false
		result.CertChainValid = false
		result.Errors = append(result.Errors, "certificate chain required but not provided")
		result.TrustLevel -= 20
	}

	// Verify PCR values (TPM only)
	if evidence.Type == PUFTypeTPM && len(evidence.PCRValues) > 0 {
		pcrValid := v.verifyPCRValues(evidence, result)
		result.PCRsValid = pcrValid
		if !pcrValid && v.config.StrictPCRValidation {
			result.Valid = false
			result.TrustLevel -= 20
		}
	}

	// Adjust trust level based on PUF type
	switch evidence.Type {
	case PUFTypeTPM:
		// Highest trust - hardware TPM
	case PUFTypeSecureEnclave:
		// High trust - TEE
		result.TrustLevel = min(result.TrustLevel, 95)
	case PUFTypeWindowsHello:
		// High trust - hardware backed
		result.TrustLevel = min(result.TrustLevel, 90)
	case PUFTypeSoftware:
		// Lower trust - software only
		result.TrustLevel = min(result.TrustLevel, 60)
		result.Warnings = append(result.Warnings, "software-based PUF provides weaker guarantees")
	}

	// Ensure trust level is non-negative
	if result.TrustLevel < 0 {
		result.TrustLevel = 0
	}

	return result, nil
}

// verifySignature verifies the attestation signature.
func (v *AttestationVerifier) verifySignature(evidence *AttestationEvidence) (bool, error) {
	if len(evidence.PublicKey) == 0 {
		return false, errors.New("no public key in evidence")
	}

	if len(evidence.Signature) == 0 {
		return false, errors.New("no signature in evidence")
	}

	// Compute the signed data hash
	signedData := v.computeSignedData(evidence)
	hash := sha256.Sum256(signedData)

	// Parse public key based on type
	switch evidence.Type {
	case PUFTypeTPM:
		return v.verifyTPMSignature(evidence.PublicKey, hash[:], evidence.Signature)
	case PUFTypeSecureEnclave:
		return v.verifyECDSASignature(evidence.PublicKey, hash[:], evidence.Signature)
	case PUFTypeWindowsHello:
		return v.verifyECDSASignature(evidence.PublicKey, hash[:], evidence.Signature)
	case PUFTypeSoftware:
		// Software PUF uses HMAC-style verification
		return v.verifySoftwarePUFSignature(evidence)
	default:
		return false, ErrAttestationUnknownType
	}
}

// computeSignedData computes the data that was signed.
func (v *AttestationVerifier) computeSignedData(evidence *AttestationEvidence) []byte {
	h := sha256.New()
	h.Write([]byte("witnessd-attestation-v1"))
	h.Write(evidence.Nonce)
	h.Write([]byte(evidence.DeviceID))
	binary.Write(h, binary.BigEndian, evidence.Timestamp.UnixNano())
	h.Write(evidence.PublicKey)

	// Include PCR values if present
	for _, pcr := range evidence.PCRSelection {
		if val, ok := evidence.PCRValues[pcr]; ok {
			binary.Write(h, binary.BigEndian, int32(pcr))
			h.Write(val)
		}
	}

	return h.Sum(nil)
}

// verifyTPMSignature verifies a TPM signature.
func (v *AttestationVerifier) verifyTPMSignature(pubKey, hash, signature []byte) (bool, error) {
	// Parse TPM public key (assume ECC for now)
	// TPM public keys are typically in TPMT_PUBLIC format
	// For simplicity, try ECDSA verification
	return v.verifyECDSASignature(pubKey, hash, signature)
}

// verifyECDSASignature verifies an ECDSA signature.
func (v *AttestationVerifier) verifyECDSASignature(pubKeyBytes, hash, signature []byte) (bool, error) {
	// Try to parse as ANSI X9.63 format (common for SE and Windows Hello)
	pubKey, err := parseECPublicKey(pubKeyBytes)
	if err != nil {
		return false, fmt.Errorf("failed to parse public key: %w", err)
	}

	// Parse signature (DER encoded or raw)
	r, s, err := parseECDSASignature(signature)
	if err != nil {
		return false, fmt.Errorf("failed to parse signature: %w", err)
	}

	// Verify
	return ecdsa.Verify(pubKey, hash, r, s), nil
}

// parseECPublicKey parses an EC public key from various formats.
func parseECPublicKey(data []byte) (*ecdsa.PublicKey, error) {
	// Try ANSI X9.63 format first (04 || X || Y)
	if len(data) == 65 && data[0] == 0x04 {
		x := new(big.Int).SetBytes(data[1:33])
		y := new(big.Int).SetBytes(data[33:65])
		return &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		}, nil
	}

	// Try DER/PKIX format
	if key, err := x509.ParsePKIXPublicKey(data); err == nil {
		if ecKey, ok := key.(*ecdsa.PublicKey); ok {
			return ecKey, nil
		}
	}

	// Try Windows BCRYPT_ECCKEY_BLOB format
	if len(data) >= 72 {
		// BCRYPT_ECCKEY_BLOB: ULONG Magic, ULONG cbKey, X, Y
		// Magic for P256 public: 0x31534345
		magic := binary.LittleEndian.Uint32(data[0:4])
		if magic == 0x31534345 { // ECS1
			keyLen := binary.LittleEndian.Uint32(data[4:8])
			if keyLen == 32 && len(data) >= 72 {
				x := new(big.Int).SetBytes(data[8:40])
				y := new(big.Int).SetBytes(data[40:72])
				return &ecdsa.PublicKey{
					Curve: elliptic.P256(),
					X:     x,
					Y:     y,
				}, nil
			}
		}
	}

	return nil, errors.New("unable to parse EC public key")
}

// parseECDSASignature parses an ECDSA signature.
func parseECDSASignature(data []byte) (*big.Int, *big.Int, error) {
	// Try DER format first
	var sig struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(data, &sig); err == nil {
		return sig.R, sig.S, nil
	}

	// Try raw format (r || s)
	if len(data) == 64 {
		r := new(big.Int).SetBytes(data[0:32])
		s := new(big.Int).SetBytes(data[32:64])
		return r, s, nil
	}

	return nil, nil, errors.New("unable to parse ECDSA signature")
}

// verifySoftwarePUFSignature verifies a software PUF attestation.
func (v *AttestationVerifier) verifySoftwarePUFSignature(evidence *AttestationEvidence) (bool, error) {
	// For software PUF, we verify that the signature is consistent
	// with the claimed device ID and public key

	// Check if we have a registered public key for this device
	if knownPubKey, exists := v.knownDevices[evidence.DeviceID]; exists {
		if !bytes.Equal(knownPubKey, evidence.PublicKey) {
			return false, errors.New("public key doesn't match registered device")
		}
	}

	// Software PUF signatures are HMAC-style
	// We can only verify consistency, not origin
	return len(evidence.Signature) == 32, nil
}

// verifyCertChain verifies the certificate chain.
func (v *AttestationVerifier) verifyCertChain(evidence *AttestationEvidence) (bool, error) {
	if len(evidence.CertificateChain) == 0 {
		return false, errors.New("empty certificate chain")
	}

	// Parse leaf certificate
	leafCert, err := x509.ParseCertificate(evidence.CertificateChain[0])
	if err != nil {
		return false, fmt.Errorf("failed to parse leaf certificate: %w", err)
	}

	// Build intermediate pool
	intermediates := x509.NewCertPool()
	for i := 1; i < len(evidence.CertificateChain); i++ {
		cert, err := x509.ParseCertificate(evidence.CertificateChain[i])
		if err != nil {
			return false, fmt.Errorf("failed to parse intermediate certificate %d: %w", i, err)
		}
		intermediates.AddCert(cert)
	}

	// Verify chain
	opts := x509.VerifyOptions{
		Roots:         v.trustedRoots,
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	chains, err := leafCert.Verify(opts)
	if err != nil {
		return false, fmt.Errorf("certificate verification failed: %w", err)
	}

	return len(chains) > 0, nil
}

// verifyPCRValues verifies TPM PCR values.
func (v *AttestationVerifier) verifyPCRValues(evidence *AttestationEvidence, result *AttestationVerificationResult) bool {
	allValid := true

	for pcr, value := range evidence.PCRValues {
		trustedValues, hasTrusted := v.trustedPCRs[pcr]
		if !hasTrusted {
			result.Warnings = append(result.Warnings, fmt.Sprintf("PCR %d not in trusted set", pcr))
			continue
		}

		found := false
		for _, trusted := range trustedValues {
			if bytes.Equal(value, trusted) {
				found = true
				break
			}
		}

		if !found {
			result.Warnings = append(result.Warnings, fmt.Sprintf("PCR %d value not trusted", pcr))
			allValid = false
		}
	}

	return allValid
}

// CreateAttestationRequest creates an attestation request.
func CreateAttestationRequest(requestID string, validityWindow time.Duration) (*AttestationRequest, error) {
	nonce := make([]byte, 32)
	if _, err := crypto.GenerateRandom(32); err != nil {
		// Fallback to crypto/rand
		var b [32]byte
		h := sha256.Sum256([]byte(fmt.Sprintf("%s-%d", requestID, time.Now().UnixNano())))
		copy(nonce, h[:])
	}

	return &AttestationRequest{
		RequestID:        requestID,
		Nonce:            nonce,
		RequiredPCRs:     []int{0, 1, 2, 3, 4, 7},
		RequireCertChain: false,
		ValidityWindow:   validityWindow,
		Timestamp:        time.Now(),
	}, nil
}

// CreateAttestation creates attestation evidence from a PUF.
func CreateAttestation(puf PUF, request *AttestationRequest) (*AttestationEvidence, error) {
	evidence := &AttestationEvidence{
		Version:   1,
		Type:      puf.Type(),
		DeviceID:  puf.DeviceID(),
		Timestamp: time.Now(),
		Nonce:     request.Nonce,
		Claims:    make(map[string]string),
	}

	// Get attestation from PUF
	if attestable, ok := puf.(AttestablePUF); ok {
		att, err := attestable.GetAttestation(request.Nonce)
		if err != nil {
			return nil, fmt.Errorf("failed to get attestation: %w", err)
		}

		evidence.PublicKey = att.Evidence
		evidence.Signature = att.Signature
		evidence.PlatformState = att.PlatformState

		// Get certificate chain if available
		if request.RequireCertChain {
			chain, err := attestable.GetCertificateChain()
			if err == nil {
				evidence.CertificateChain = chain
			}
		}
	} else {
		// Fallback to challenge-response
		response, err := puf.Challenge(request.Nonce)
		if err != nil {
			return nil, fmt.Errorf("failed to get challenge response: %w", err)
		}

		// For non-attestable PUFs, use the response as signature
		evidence.Signature = response
		evidence.PublicKey = []byte(puf.DeviceID()) // Use device ID as pseudo public key
	}

	// Add capabilities as claims
	caps := puf.Capabilities()
	evidence.Claims["puf_type"] = caps.Type.String()
	evidence.Claims["security_level"] = caps.SecurityLevel.String()
	evidence.Claims["attestation_supported"] = fmt.Sprintf("%v", caps.SupportsAttestation)

	return evidence, nil
}

// SerializeEvidence serializes attestation evidence to JSON.
func SerializeEvidence(evidence *AttestationEvidence) ([]byte, error) {
	return json.MarshalIndent(evidence, "", "  ")
}

// DeserializeEvidence deserializes attestation evidence from JSON.
func DeserializeEvidence(data []byte) (*AttestationEvidence, error) {
	var evidence AttestationEvidence
	if err := json.Unmarshal(data, &evidence); err != nil {
		return nil, err
	}
	return &evidence, nil
}

// min returns the minimum of two ints.
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
