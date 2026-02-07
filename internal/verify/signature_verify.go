// Package verify provides key hierarchy signature verification.
package verify

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// Signature verification errors
var (
	ErrInvalidPublicKey       = errors.New("signature: invalid public key")
	ErrInvalidSignature       = errors.New("signature: invalid signature format")
	ErrSignatureMismatch      = errors.New("signature: signature does not match")
	ErrKeyChainBroken         = errors.New("signature: key chain is broken")
	ErrKeyExpired             = errors.New("signature: key has expired")
	ErrKeyNotYetValid         = errors.New("signature: key is not yet valid")
	ErrInsufficientKeyLevel   = errors.New("signature: insufficient key level for operation")
)

// KeyLevel represents the hierarchy level of a signing key.
type KeyLevel int

const (
	// KeyLevelRoot is the root key (highest trust)
	KeyLevelRoot KeyLevel = iota
	// KeyLevelDevice is a device-bound key
	KeyLevelDevice
	// KeyLevelSession is a session-ephemeral key
	KeyLevelSession
)

func (l KeyLevel) String() string {
	switch l {
	case KeyLevelRoot:
		return "root"
	case KeyLevelDevice:
		return "device"
	case KeyLevelSession:
		return "session"
	default:
		return "unknown"
	}
}

// KeyInfo contains metadata about a signing key.
type KeyInfo struct {
	PublicKey   ed25519.PublicKey `json:"public_key"`
	KeyID       string            `json:"key_id"`
	Level       KeyLevel          `json:"level"`
	ValidFrom   time.Time         `json:"valid_from"`
	ValidUntil  *time.Time        `json:"valid_until,omitempty"`
	ParentKeyID string            `json:"parent_key_id,omitempty"`
	Source      string            `json:"source"` // "file", "tpm", "secure_enclave"
}

// SignatureInfo contains metadata about a signature.
type SignatureInfo struct {
	Signature     []byte            `json:"signature"`
	SignerKeyID   string            `json:"signer_key_id"`
	SignedAt      time.Time         `json:"signed_at"`
	Algorithm     string            `json:"algorithm"`
	PublicKey     ed25519.PublicKey `json:"public_key,omitempty"`
}

// SignatureVerificationResult contains detailed signature verification results.
type SignatureVerificationResult struct {
	Valid           bool       `json:"valid"`
	SignerKeyID     string     `json:"signer_key_id"`
	SignerKeyLevel  string     `json:"signer_key_level"`
	Algorithm       string     `json:"algorithm"`
	SignedAt        time.Time  `json:"signed_at,omitempty"`
	KeyValidFrom    time.Time  `json:"key_valid_from,omitempty"`
	KeyValidUntil   *time.Time `json:"key_valid_until,omitempty"`
	ChainDepth      int        `json:"chain_depth"`
	RootKeyID       string     `json:"root_key_id,omitempty"`
	Error           string     `json:"error,omitempty"`
	Warnings        []string   `json:"warnings,omitempty"`
}

// SignatureVerifier provides signature verification with key hierarchy support.
type SignatureVerifier struct {
	trustedKeys   map[string]*KeyInfo
	keyChain      map[string]string // child -> parent mapping
	allowExpired  bool
	checkTime     time.Time
}

// NewSignatureVerifier creates a new signature verifier.
func NewSignatureVerifier() *SignatureVerifier {
	return &SignatureVerifier{
		trustedKeys: make(map[string]*KeyInfo),
		keyChain:    make(map[string]string),
		checkTime:   time.Now(),
	}
}

// AddTrustedKey adds a trusted key to the verifier.
func (v *SignatureVerifier) AddTrustedKey(key *KeyInfo) error {
	if len(key.PublicKey) != ed25519.PublicKeySize {
		return ErrInvalidPublicKey
	}

	if key.KeyID == "" {
		key.KeyID = computeKeyID(key.PublicKey)
	}

	v.trustedKeys[key.KeyID] = key

	if key.ParentKeyID != "" {
		v.keyChain[key.KeyID] = key.ParentKeyID
	}

	return nil
}

// AddTrustedPublicKey adds a public key as trusted at root level.
func (v *SignatureVerifier) AddTrustedPublicKey(pubKey ed25519.PublicKey) error {
	key := &KeyInfo{
		PublicKey: pubKey,
		KeyID:     computeKeyID(pubKey),
		Level:     KeyLevelRoot,
		ValidFrom: time.Time{}, // Always valid
		Source:    "trusted",
	}
	return v.AddTrustedKey(key)
}

// SetCheckTime sets the time used for validity checks (for testing).
func (v *SignatureVerifier) SetCheckTime(t time.Time) {
	v.checkTime = t
}

// AllowExpiredKeys permits verification of signatures made with expired keys.
func (v *SignatureVerifier) AllowExpiredKeys(allow bool) {
	v.allowExpired = allow
}

// VerifySignature verifies a signature against trusted keys.
func (v *SignatureVerifier) VerifySignature(
	message []byte,
	signature []byte,
	pubKey ed25519.PublicKey,
) (*SignatureVerificationResult, error) {
	result := &SignatureVerificationResult{
		Algorithm: "Ed25519",
	}

	// Validate inputs
	if len(pubKey) != ed25519.PublicKeySize {
		result.Error = "invalid public key size"
		return result, ErrInvalidPublicKey
	}

	if len(signature) != ed25519.SignatureSize {
		result.Error = "invalid signature size"
		return result, ErrInvalidSignature
	}

	// Compute key ID
	keyID := computeKeyID(pubKey)
	result.SignerKeyID = keyID

	// Check if key is trusted
	keyInfo, trusted := v.trustedKeys[keyID]
	if trusted {
		result.SignerKeyLevel = keyInfo.Level.String()
		result.KeyValidFrom = keyInfo.ValidFrom
		result.KeyValidUntil = keyInfo.ValidUntil

		// Check key validity
		if !keyInfo.ValidFrom.IsZero() && v.checkTime.Before(keyInfo.ValidFrom) {
			result.Error = "key not yet valid"
			return result, ErrKeyNotYetValid
		}

		if keyInfo.ValidUntil != nil && v.checkTime.After(*keyInfo.ValidUntil) {
			if !v.allowExpired {
				result.Error = "key has expired"
				return result, ErrKeyExpired
			}
			result.Warnings = append(result.Warnings, "key has expired but verification allowed")
		}

		// Trace key chain
		chainDepth, rootKeyID := v.traceKeyChain(keyID)
		result.ChainDepth = chainDepth
		result.RootKeyID = rootKeyID
	} else {
		result.Warnings = append(result.Warnings, "key is not in trusted set")
	}

	// Verify the signature
	if !ed25519.Verify(pubKey, message, signature) {
		result.Error = "signature verification failed"
		return result, ErrSignatureMismatch
	}

	result.Valid = true
	return result, nil
}

// VerifySignatureHex verifies a signature with hex-encoded inputs.
func (v *SignatureVerifier) VerifySignatureHex(
	message []byte,
	signatureHex string,
	pubKeyHex string,
) (*SignatureVerificationResult, error) {
	signature, err := hex.DecodeString(signatureHex)
	if err != nil {
		return &SignatureVerificationResult{
			Error: fmt.Sprintf("invalid signature hex: %v", err),
		}, ErrInvalidSignature
	}

	pubKey, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return &SignatureVerificationResult{
			Error: fmt.Sprintf("invalid public key hex: %v", err),
		}, ErrInvalidPublicKey
	}

	return v.VerifySignature(message, signature, pubKey)
}

// VerifyChain verifies a chain of signatures where each signature vouches for the next key.
func (v *SignatureVerifier) VerifyChain(chain []SignatureInfo, finalMessage []byte) (*SignatureVerificationResult, error) {
	if len(chain) == 0 {
		return nil, errors.New("empty signature chain")
	}

	result := &SignatureVerificationResult{
		Algorithm:  "Ed25519",
		ChainDepth: len(chain),
	}

	// Verify each link in the chain
	for i, sig := range chain {
		var message []byte
		if i == len(chain)-1 {
			// Last signature signs the final message
			message = finalMessage
		} else {
			// Earlier signatures sign the next key
			message = chain[i+1].PublicKey
		}

		// Verify this signature
		if !ed25519.Verify(sig.PublicKey, message, sig.Signature) {
			result.Error = fmt.Sprintf("chain broken at position %d", i)
			return result, ErrKeyChainBroken
		}
	}

	// First key in chain must be trusted
	firstKeyID := computeKeyID(chain[0].PublicKey)
	if _, trusted := v.trustedKeys[firstKeyID]; !trusted {
		result.Warnings = append(result.Warnings, "root of chain is not in trusted set")
	}

	result.Valid = true
	result.SignerKeyID = computeKeyID(chain[len(chain)-1].PublicKey)
	result.RootKeyID = firstKeyID

	return result, nil
}

// traceKeyChain follows the key chain to the root and returns depth and root key ID.
func (v *SignatureVerifier) traceKeyChain(keyID string) (int, string) {
	depth := 0
	currentID := keyID
	visited := make(map[string]bool)

	for {
		if visited[currentID] {
			// Cycle detected
			break
		}
		visited[currentID] = true

		parentID, hasParent := v.keyChain[currentID]
		if !hasParent {
			// Reached root
			return depth, currentID
		}

		currentID = parentID
		depth++

		// Safety limit
		if depth > 10 {
			break
		}
	}

	return depth, currentID
}

// computeKeyID creates a unique identifier for a public key.
func computeKeyID(pubKey ed25519.PublicKey) string {
	hash := sha256.Sum256(pubKey)
	return hex.EncodeToString(hash[:8]) // First 8 bytes
}

// VerifyDeclarationSignature verifies a declaration's signature.
func VerifyDeclarationSignature(
	documentHash [32]byte,
	chainHash [32]byte,
	signature []byte,
	pubKey ed25519.PublicKey,
) (*SignatureVerificationResult, error) {
	verifier := NewSignatureVerifier()
	verifier.AddTrustedPublicKey(pubKey)

	// Recreate the signing payload (must match declaration.signingPayload)
	// This is a simplified version - the actual payload includes all declaration fields
	h := sha256.New()
	h.Write([]byte("witnessd-declaration-v1"))
	h.Write(documentHash[:])
	h.Write(chainHash[:])
	payload := h.Sum(nil)

	return verifier.VerifySignature(payload, signature, pubKey)
}

// VerifyCommitmentSignature verifies an MMR root commitment signature.
func VerifyCommitmentSignature(
	rootHash [32]byte,
	signature []byte,
	pubKey ed25519.PublicKey,
) (*SignatureVerificationResult, error) {
	verifier := NewSignatureVerifier()
	verifier.AddTrustedPublicKey(pubKey)

	return verifier.VerifySignature(rootHash[:], signature, pubKey)
}

// BatchVerifySignatures verifies multiple signatures in parallel.
type SignatureTask struct {
	Message   []byte
	Signature []byte
	PublicKey ed25519.PublicKey
}

func BatchVerifySignatures(tasks []SignatureTask) []SignatureVerificationResult {
	results := make([]SignatureVerificationResult, len(tasks))
	verifier := NewSignatureVerifier()

	for i, task := range tasks {
		result, _ := verifier.VerifySignature(task.Message, task.Signature, task.PublicKey)
		if result != nil {
			results[i] = *result
		} else {
			results[i] = SignatureVerificationResult{
				Valid: false,
				Error: "nil result",
			}
		}
	}

	return results
}
