// Package verify provides external anchor verification.
package verify

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"witnessd/internal/evidence"
	"witnessd/pkg/anchors"
)

// Anchor verification errors
var (
	ErrAnchorNoRegistry      = errors.New("anchor: no registry configured")
	ErrAnchorProviderUnknown = errors.New("anchor: unknown provider")
	ErrAnchorHashMismatch    = errors.New("anchor: hash does not match")
	ErrAnchorExpired         = errors.New("anchor: proof has expired")
	ErrAnchorRevoked         = errors.New("anchor: proof has been revoked")
	ErrAnchorPending         = errors.New("anchor: proof is still pending")
	ErrAnchorNetworkError    = errors.New("anchor: network error during verification")
)

// AnchorVerificationResult contains detailed anchor verification results.
type AnchorVerificationResult struct {
	Valid           bool      `json:"valid"`
	Provider        string    `json:"provider"`
	ProviderType    string    `json:"provider_type"`
	LegalStanding   string    `json:"legal_standing"`
	Regions         []string  `json:"regions"`
	Hash            string    `json:"hash"`
	Timestamp       time.Time `json:"timestamp"`
	Status          string    `json:"status"`
	BlockchainInfo  *BlockchainVerificationInfo `json:"blockchain_info,omitempty"`
	CertificateInfo *CertificateVerificationInfo `json:"certificate_info,omitempty"`
	Error           string    `json:"error,omitempty"`
	Warnings        []string  `json:"warnings,omitempty"`
	VerificationTime time.Duration `json:"verification_time"`
}

// BlockchainVerificationInfo contains blockchain-specific verification details.
type BlockchainVerificationInfo struct {
	Chain         string    `json:"chain"`
	BlockHeight   uint64    `json:"block_height"`
	BlockHash     string    `json:"block_hash"`
	BlockTime     time.Time `json:"block_time"`
	Confirmations uint64    `json:"confirmations"`
	TxID          string    `json:"tx_id,omitempty"`
	MerkleRoot    string    `json:"merkle_root,omitempty"`
}

// CertificateVerificationInfo contains PKI certificate verification details.
type CertificateVerificationInfo struct {
	Issuer      string    `json:"issuer"`
	Subject     string    `json:"subject"`
	Serial      string    `json:"serial"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	IsQualified bool      `json:"is_qualified"`
	PolicyOIDs  []string  `json:"policy_oids,omitempty"`
	ChainValid  bool      `json:"chain_valid"`
}

// AnchorVerifier provides external anchor verification utilities.
type AnchorVerifier struct {
	registry *anchors.Registry
	timeout  time.Duration
	offline  bool // Skip network-dependent verification
}

// NewAnchorVerifier creates a new anchor verifier.
func NewAnchorVerifier(registry *anchors.Registry) *AnchorVerifier {
	return &AnchorVerifier{
		registry: registry,
		timeout:  30 * time.Second,
	}
}

// WithTimeout sets the verification timeout.
func (v *AnchorVerifier) WithTimeout(timeout time.Duration) *AnchorVerifier {
	v.timeout = timeout
	return v
}

// SetOffline enables offline verification mode (skips network checks).
func (v *AnchorVerifier) SetOffline(offline bool) *AnchorVerifier {
	v.offline = offline
	return v
}

// VerifyAnchorProof verifies a single anchor proof.
func (v *AnchorVerifier) VerifyAnchorProof(ctx context.Context, proof *evidence.AnchorProof) (*AnchorVerificationResult, error) {
	start := time.Now()
	result := &AnchorVerificationResult{
		Provider:      proof.Provider,
		LegalStanding: proof.LegalStanding,
		Regions:       proof.Regions,
		Hash:          proof.Hash,
		Timestamp:     proof.Timestamp,
		Status:        proof.Status,
	}

	defer func() {
		result.VerificationTime = time.Since(start)
	}()

	// Check if we have a registry
	if v.registry == nil {
		result.Error = "no anchor registry configured"
		return result, ErrAnchorNoRegistry
	}

	// Get the provider
	provider, ok := v.registry.Get(proof.Provider)
	if !ok {
		// Try to find by prefix
		for _, p := range v.registry.AllProviders() {
			if len(proof.Provider) > len(p.Name()) &&
			   proof.Provider[:len(p.Name())] == p.Name() {
				provider = p
				ok = true
				break
			}
		}
	}

	if !ok {
		result.Warnings = append(result.Warnings, "provider not registered, using structural verification only")
		return v.verifyStructural(result, proof)
	}

	result.ProviderType = string(provider.Type())

	// Offline mode - only structural verification
	if v.offline {
		result.Warnings = append(result.Warnings, "offline mode - network verification skipped")
		return v.verifyStructural(result, proof)
	}

	// Decode hash
	hashBytes, err := hex.DecodeString(proof.Hash)
	if err != nil {
		result.Error = fmt.Sprintf("invalid hash hex: %v", err)
		return result, ErrAnchorHashMismatch
	}

	var hash [32]byte
	copy(hash[:], hashBytes)

	// Decode raw proof
	rawProof, err := base64.StdEncoding.DecodeString(proof.RawProof)
	if err != nil {
		result.Warnings = append(result.Warnings, "could not decode raw proof")
	}

	// Create anchor proof for verification
	anchorProof := &anchors.Proof{
		Provider:  proof.Provider,
		Hash:      hash,
		Timestamp: proof.Timestamp,
		Status:    anchors.ProofStatus(proof.Status),
		RawProof:  rawProof,
		VerifyURL: proof.VerifyURL,
	}

	if proof.Blockchain != nil {
		anchorProof.BlockchainAnchor = &anchors.BlockchainAnchor{
			Chain:         proof.Blockchain.Chain,
			BlockHeight:   proof.Blockchain.BlockHeight,
			BlockHash:     proof.Blockchain.BlockHash,
			BlockTime:     proof.Blockchain.BlockTime,
			TransactionID: proof.Blockchain.TxID,
		}
	}

	// Verify with provider
	verifyCtx, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()

	verifyResult, err := provider.Verify(verifyCtx, anchorProof)
	if err != nil {
		result.Error = fmt.Sprintf("verification error: %v", err)
		return result, err
	}

	// Extract blockchain info
	if verifyResult.Chain != nil {
		result.BlockchainInfo = &BlockchainVerificationInfo{
			Chain:       verifyResult.Chain.Chain,
			BlockHeight: verifyResult.Chain.BlockHeight,
			BlockHash:   verifyResult.Chain.BlockHash,
			BlockTime:   verifyResult.Chain.BlockTime,
			TxID:        verifyResult.Chain.TransactionID,
			MerkleRoot:  verifyResult.Chain.MerkleRoot,
		}
	}

	// Extract certificate info
	if verifyResult.CertificateInfo != nil {
		result.CertificateInfo = &CertificateVerificationInfo{
			Issuer:      verifyResult.CertificateInfo.Issuer,
			Subject:     verifyResult.CertificateInfo.Subject,
			Serial:      verifyResult.CertificateInfo.Serial,
			NotBefore:   verifyResult.CertificateInfo.NotBefore,
			NotAfter:    verifyResult.CertificateInfo.NotAfter,
			IsQualified: verifyResult.CertificateInfo.IsQualified,
			PolicyOIDs:  verifyResult.CertificateInfo.PolicyOIDs,
		}
	}

	// Check status
	switch verifyResult.Status {
	case anchors.StatusConfirmed:
		result.Valid = true
		result.Status = "confirmed"
	case anchors.StatusPending:
		result.Status = "pending"
		result.Warnings = append(result.Warnings, "proof is still pending confirmation")
	case anchors.StatusExpired:
		result.Status = "expired"
		result.Error = "proof certificate has expired"
		return result, ErrAnchorExpired
	case anchors.StatusRevoked:
		result.Status = "revoked"
		result.Error = "proof has been revoked"
		return result, ErrAnchorRevoked
	case anchors.StatusFailed:
		result.Status = "failed"
		result.Error = "proof verification failed"
	}

	if verifyResult.Valid {
		result.Valid = true
	}

	result.Warnings = append(result.Warnings, verifyResult.Warnings...)

	return result, nil
}

// verifyStructural performs structural verification without network access.
func (v *AnchorVerifier) verifyStructural(result *AnchorVerificationResult, proof *evidence.AnchorProof) (*AnchorVerificationResult, error) {
	// Validate hash format
	hashBytes, err := hex.DecodeString(proof.Hash)
	if err != nil {
		result.Error = fmt.Sprintf("invalid hash hex: %v", err)
		return result, ErrAnchorHashMismatch
	}

	if len(hashBytes) != 32 {
		result.Error = "hash must be 32 bytes"
		return result, ErrAnchorHashMismatch
	}

	// Validate raw proof is present
	if proof.RawProof == "" {
		result.Warnings = append(result.Warnings, "no raw proof data present")
	} else {
		_, err := base64.StdEncoding.DecodeString(proof.RawProof)
		if err != nil {
			result.Warnings = append(result.Warnings, "raw proof is not valid base64")
		}
	}

	// Validate blockchain info if present
	if proof.Blockchain != nil {
		result.BlockchainInfo = &BlockchainVerificationInfo{
			Chain:       proof.Blockchain.Chain,
			BlockHeight: proof.Blockchain.BlockHeight,
			BlockHash:   proof.Blockchain.BlockHash,
			BlockTime:   proof.Blockchain.BlockTime,
			TxID:        proof.Blockchain.TxID,
		}

		if proof.Blockchain.BlockHeight == 0 {
			result.Warnings = append(result.Warnings, "block height is zero")
		}

		if proof.Blockchain.BlockHash == "" {
			result.Warnings = append(result.Warnings, "missing block hash")
		}
	}

	// Check status
	switch proof.Status {
	case "confirmed":
		result.Valid = true
	case "pending":
		result.Warnings = append(result.Warnings, "proof is pending - not yet confirmed")
		result.Valid = false
	case "failed":
		result.Error = "proof status is failed"
		result.Valid = false
	default:
		result.Warnings = append(result.Warnings, fmt.Sprintf("unknown status: %s", proof.Status))
	}

	return result, nil
}

// VerifyLegacyOTS verifies a legacy OpenTimestamps proof.
func (v *AnchorVerifier) VerifyLegacyOTS(ctx context.Context, proof *evidence.OTSProof) (*AnchorVerificationResult, error) {
	result := &AnchorVerificationResult{
		Provider:      "opentimestamps",
		ProviderType:  "blockchain",
		LegalStanding: "evidentiary",
		Regions:       []string{"GLOBAL"},
		Hash:          proof.ChainHash,
		Status:        proof.Status,
	}

	if proof.BlockHeight > 0 {
		result.BlockchainInfo = &BlockchainVerificationInfo{
			Chain:       "bitcoin",
			BlockHeight: proof.BlockHeight,
			BlockTime:   proof.BlockTime,
		}
	}

	// Decode the proof
	proofBytes, err := base64.StdEncoding.DecodeString(proof.Proof)
	if err != nil {
		result.Error = fmt.Sprintf("invalid proof encoding: %v", err)
		return result, errors.New("invalid OTS proof encoding")
	}

	if len(proofBytes) == 0 {
		result.Error = "empty proof data"
		return result, errors.New("empty OTS proof")
	}

	if proof.Status == "confirmed" && proof.BlockHeight > 0 {
		result.Valid = true
	}

	return result, nil
}

// VerifyLegacyRFC3161 verifies a legacy RFC 3161 proof.
func (v *AnchorVerifier) VerifyLegacyRFC3161(ctx context.Context, proof *evidence.RFC3161Proof) (*AnchorVerificationResult, error) {
	result := &AnchorVerificationResult{
		Provider:      "rfc3161",
		ProviderType:  "rfc3161",
		LegalStanding: "legal",
		Regions:       []string{"GLOBAL"},
		Hash:          proof.ChainHash,
		Timestamp:     proof.Timestamp,
		Status:        "confirmed",
	}

	// Decode the response
	responseBytes, err := base64.StdEncoding.DecodeString(proof.Response)
	if err != nil {
		result.Error = fmt.Sprintf("invalid response encoding: %v", err)
		return result, errors.New("invalid RFC 3161 response encoding")
	}

	if len(responseBytes) == 0 {
		result.Error = "empty response data"
		return result, errors.New("empty RFC 3161 response")
	}

	// For full verification, we would parse the ASN.1 DER and verify the signature
	// This is a structural check
	result.Valid = true
	result.Warnings = append(result.Warnings, "certificate chain not verified in structural mode")

	return result, nil
}

// VerifyAllAnchors verifies all external anchors in an evidence packet.
func (v *AnchorVerifier) VerifyAllAnchors(ctx context.Context, external *evidence.ExternalAnchors) (*AnchorBatchResult, error) {
	if external == nil {
		return &AnchorBatchResult{
			Valid: true,
		}, nil
	}

	result := &AnchorBatchResult{
		Results: make([]AnchorVerificationResult, 0),
	}

	// Verify new-format proofs
	for _, proof := range external.Proofs {
		anchorResult, _ := v.VerifyAnchorProof(ctx, &proof)
		if anchorResult != nil {
			result.Results = append(result.Results, *anchorResult)
			if anchorResult.Valid {
				result.Verified++
			} else if anchorResult.Status == "pending" {
				result.Pending++
			} else {
				result.Failed++
			}
		}
		result.Total++
	}

	// Verify legacy OTS proofs
	for _, proof := range external.OpenTimestamps {
		anchorResult, _ := v.VerifyLegacyOTS(ctx, &proof)
		if anchorResult != nil {
			result.Results = append(result.Results, *anchorResult)
			if anchorResult.Valid {
				result.Verified++
			} else {
				result.Failed++
			}
		}
		result.Total++
	}

	// Verify legacy RFC 3161 proofs
	for _, proof := range external.RFC3161 {
		anchorResult, _ := v.VerifyLegacyRFC3161(ctx, &proof)
		if anchorResult != nil {
			result.Results = append(result.Results, *anchorResult)
			if anchorResult.Valid {
				result.Verified++
			} else {
				result.Failed++
			}
		}
		result.Total++
	}

	result.Valid = result.Failed == 0
	return result, nil
}

// AnchorBatchResult contains results for verifying multiple anchors.
type AnchorBatchResult struct {
	Valid    bool                       `json:"valid"`
	Total    int                        `json:"total"`
	Verified int                        `json:"verified"`
	Failed   int                        `json:"failed"`
	Pending  int                        `json:"pending"`
	Results  []AnchorVerificationResult `json:"results"`
}

// GetBestAnchor returns the anchor with the highest legal standing.
func (r *AnchorBatchResult) GetBestAnchor() *AnchorVerificationResult {
	standingOrder := map[string]int{
		"qualified":   4,
		"legal":       3,
		"evidentiary": 2,
		"none":        1,
	}

	var best *AnchorVerificationResult
	bestScore := 0

	for i := range r.Results {
		result := &r.Results[i]
		if !result.Valid {
			continue
		}

		score := standingOrder[result.LegalStanding]
		if score > bestScore {
			best = result
			bestScore = score
		}
	}

	return best
}
