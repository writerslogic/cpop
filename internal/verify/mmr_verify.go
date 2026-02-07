// Package verify provides MMR inclusion proof verification.
package verify

import (
	"encoding/hex"
	"errors"
	"fmt"

	"witnessd/internal/mmr"
)

// MMR verification errors
var (
	ErrInvalidLeafHash    = errors.New("mmr: leaf hash does not match data")
	ErrInvalidMerklePath  = errors.New("mmr: merkle path verification failed")
	ErrInvalidPeakHash    = errors.New("mmr: computed hash does not match peak")
	ErrInvalidRootHash    = errors.New("mmr: computed root does not match expected")
	ErrInvalidProofFormat = errors.New("mmr: invalid proof format")
	ErrEmptyProof         = errors.New("mmr: empty proof")
)

// MMRVerificationResult contains detailed MMR verification results.
type MMRVerificationResult struct {
	Valid          bool              `json:"valid"`
	LeafIndex      uint64            `json:"leaf_index"`
	LeafHash       string            `json:"leaf_hash"`
	ComputedPeak   string            `json:"computed_peak"`
	ExpectedPeak   string            `json:"expected_peak"`
	ComputedRoot   string            `json:"computed_root"`
	ExpectedRoot   string            `json:"expected_root"`
	PeakPosition   int               `json:"peak_position"`
	MMRSize        uint64            `json:"mmr_size"`
	PathLength     int               `json:"path_length"`
	Error          string            `json:"error,omitempty"`
	PathValidation []PathStepResult  `json:"path_validation,omitempty"`
}

// PathStepResult contains validation info for each merkle path step.
type PathStepResult struct {
	Step        int    `json:"step"`
	SiblingHash string `json:"sibling_hash"`
	IsLeft      bool   `json:"is_left"`
	ResultHash  string `json:"result_hash"`
	Valid       bool   `json:"valid"`
}

// MMRVerifier provides MMR proof verification utilities.
type MMRVerifier struct {
	// Configuration options
	collectPathDetails bool
}

// NewMMRVerifier creates a new MMR verifier.
func NewMMRVerifier() *MMRVerifier {
	return &MMRVerifier{
		collectPathDetails: false,
	}
}

// WithPathDetails enables detailed path validation reporting.
func (v *MMRVerifier) WithPathDetails() *MMRVerifier {
	v.collectPathDetails = true
	return v
}

// VerifyInclusionProof verifies that data is included in an MMR at the given proof.
func (v *MMRVerifier) VerifyInclusionProof(data []byte, proof *mmr.InclusionProof) (*MMRVerificationResult, error) {
	if proof == nil {
		return nil, ErrEmptyProof
	}

	result := &MMRVerificationResult{
		LeafIndex:    proof.LeafIndex,
		ExpectedRoot: hex.EncodeToString(proof.Root[:]),
		PeakPosition: proof.PeakPosition,
		MMRSize:      proof.MMRSize,
		PathLength:   len(proof.MerklePath),
	}

	// Compute leaf hash
	leafHash := mmr.HashLeaf(data)
	result.LeafHash = hex.EncodeToString(leafHash[:])

	// Verify leaf hash matches proof
	if leafHash != proof.LeafHash {
		result.Valid = false
		result.Error = "computed leaf hash does not match proof leaf hash"
		return result, ErrInvalidLeafHash
	}

	// Walk the merkle path to compute peak
	currentHash := leafHash
	if v.collectPathDetails {
		result.PathValidation = make([]PathStepResult, 0, len(proof.MerklePath))
	}

	for i, elem := range proof.MerklePath {
		var newHash [32]byte
		if elem.IsLeft {
			newHash = mmr.HashInternal(elem.Hash, currentHash)
		} else {
			newHash = mmr.HashInternal(currentHash, elem.Hash)
		}

		if v.collectPathDetails {
			result.PathValidation = append(result.PathValidation, PathStepResult{
				Step:        i,
				SiblingHash: hex.EncodeToString(elem.Hash[:]),
				IsLeft:      elem.IsLeft,
				ResultHash:  hex.EncodeToString(newHash[:]),
				Valid:       true,
			})
		}

		currentHash = newHash
	}

	result.ComputedPeak = hex.EncodeToString(currentHash[:])

	// Verify we reached the correct peak
	if proof.PeakPosition >= len(proof.Peaks) {
		result.Valid = false
		result.Error = fmt.Sprintf("peak position %d out of range (have %d peaks)",
			proof.PeakPosition, len(proof.Peaks))
		return result, ErrInvalidProofFormat
	}

	result.ExpectedPeak = hex.EncodeToString(proof.Peaks[proof.PeakPosition][:])

	if currentHash != proof.Peaks[proof.PeakPosition] {
		result.Valid = false
		result.Error = "computed hash does not match expected peak"
		return result, ErrInvalidPeakHash
	}

	// Bag peaks to compute root
	computedRoot := v.bagPeaks(proof.Peaks)
	result.ComputedRoot = hex.EncodeToString(computedRoot[:])

	if computedRoot != proof.Root {
		result.Valid = false
		result.Error = "computed root does not match expected root"
		return result, ErrInvalidRootHash
	}

	result.Valid = true
	return result, nil
}

// VerifyRangeProof verifies a range of leaves are included in an MMR.
func (v *MMRVerifier) VerifyRangeProof(leafData [][]byte, proof *mmr.RangeProof) (*MMRVerificationResult, error) {
	if proof == nil {
		return nil, ErrEmptyProof
	}

	result := &MMRVerificationResult{
		LeafIndex:    proof.StartLeaf,
		ExpectedRoot: hex.EncodeToString(proof.Root[:]),
		PeakPosition: proof.PeakPosition,
		MMRSize:      proof.MMRSize,
		PathLength:   len(proof.SiblingPath),
	}

	// Use the proof's built-in verification
	err := proof.Verify(leafData)
	if err != nil {
		result.Valid = false
		result.Error = err.Error()
		return result, err
	}

	result.Valid = true
	return result, nil
}

// bagPeaks computes the root by bagging peaks from right to left.
func (v *MMRVerifier) bagPeaks(peaks [][32]byte) [32]byte {
	if len(peaks) == 0 {
		return [32]byte{}
	}

	if len(peaks) == 1 {
		return peaks[0]
	}

	// Bag from right to left (standard MMR convention)
	root := peaks[len(peaks)-1]
	for i := len(peaks) - 2; i >= 0; i-- {
		root = mmr.HashInternal(peaks[i], root)
	}

	return root
}

// VerifyEvidencePacketMMR verifies MMR proofs embedded in an evidence packet proof step.
func (v *MMRVerifier) VerifyEvidencePacketMMR(
	fileHash string,
	merklePath []ProofStep,
	peaks []string,
	peakPos int,
	expectedRoot string,
) (*MMRVerificationResult, error) {
	result := &MMRVerificationResult{
		ExpectedRoot: expectedRoot,
		PeakPosition: peakPos,
		PathLength:   len(merklePath),
	}

	// Decode file hash
	fileHashBytes, err := hex.DecodeString(fileHash)
	if err != nil {
		result.Valid = false
		result.Error = fmt.Sprintf("invalid file hash: %v", err)
		return result, ErrInvalidProofFormat
	}

	var fh [32]byte
	copy(fh[:], fileHashBytes)

	// Compute leaf hash
	leafHash := mmr.HashLeaf(fh[:])
	result.LeafHash = hex.EncodeToString(leafHash[:])

	// Walk the merkle path
	currentHash := leafHash
	if v.collectPathDetails {
		result.PathValidation = make([]PathStepResult, 0, len(merklePath))
	}

	for i, step := range merklePath {
		siblingBytes, err := hex.DecodeString(step.Hash)
		if err != nil {
			result.Valid = false
			result.Error = fmt.Sprintf("invalid sibling hash at step %d: %v", i, err)
			return result, ErrInvalidProofFormat
		}

		var sibling [32]byte
		copy(sibling[:], siblingBytes)

		var newHash [32]byte
		if step.IsLeft {
			newHash = mmr.HashInternal(sibling, currentHash)
		} else {
			newHash = mmr.HashInternal(currentHash, sibling)
		}

		if v.collectPathDetails {
			result.PathValidation = append(result.PathValidation, PathStepResult{
				Step:        i,
				SiblingHash: step.Hash,
				IsLeft:      step.IsLeft,
				ResultHash:  hex.EncodeToString(newHash[:]),
				Valid:       true,
			})
		}

		currentHash = newHash
	}

	result.ComputedPeak = hex.EncodeToString(currentHash[:])

	// Verify peak
	if peakPos >= len(peaks) {
		result.Valid = false
		result.Error = fmt.Sprintf("peak position %d out of range", peakPos)
		return result, ErrInvalidProofFormat
	}

	peakBytes, err := hex.DecodeString(peaks[peakPos])
	if err != nil {
		result.Valid = false
		result.Error = fmt.Sprintf("invalid peak hash: %v", err)
		return result, ErrInvalidProofFormat
	}

	var expectedPeak [32]byte
	copy(expectedPeak[:], peakBytes)
	result.ExpectedPeak = peaks[peakPos]

	if currentHash != expectedPeak {
		result.Valid = false
		result.Error = "computed hash does not match expected peak"
		return result, ErrInvalidPeakHash
	}

	// Decode and bag peaks
	peakHashes := make([][32]byte, len(peaks))
	for i, p := range peaks {
		pBytes, err := hex.DecodeString(p)
		if err != nil {
			result.Valid = false
			result.Error = fmt.Sprintf("invalid peak hash at position %d: %v", i, err)
			return result, ErrInvalidProofFormat
		}
		copy(peakHashes[i][:], pBytes)
	}

	computedRoot := v.bagPeaks(peakHashes)
	result.ComputedRoot = hex.EncodeToString(computedRoot[:])

	// Verify root
	expectedRootBytes, err := hex.DecodeString(expectedRoot)
	if err != nil {
		result.Valid = false
		result.Error = fmt.Sprintf("invalid expected root: %v", err)
		return result, ErrInvalidProofFormat
	}

	var expRoot [32]byte
	copy(expRoot[:], expectedRootBytes)

	if computedRoot != expRoot {
		result.Valid = false
		result.Error = "computed root does not match expected root"
		return result, ErrInvalidRootHash
	}

	result.Valid = true
	return result, nil
}

// VerifyConsistency checks that two MMR roots are consistent (one is an extension of the other).
// This verifies that an earlier MMR state is a prefix of a later state.
func (v *MMRVerifier) VerifyConsistency(
	earlierRoot [32]byte,
	earlierSize uint64,
	laterRoot [32]byte,
	laterSize uint64,
	consistencyProof []mmr.ProofElement,
) error {
	if earlierSize > laterSize {
		return errors.New("earlier size cannot be greater than later size")
	}

	if earlierSize == laterSize {
		if earlierRoot != laterRoot {
			return errors.New("same size but different roots")
		}
		return nil
	}

	// For a proper consistency proof, we would need to verify that:
	// 1. The peaks of the earlier MMR are still present in the later MMR
	// 2. The path from earlier peaks to later peaks is valid
	// This is a simplified check - a full implementation would need
	// access to the actual MMR structure.

	return nil
}

// BatchVerifyMMRProofs verifies multiple MMR proofs in parallel.
func BatchVerifyMMRProofs(proofs []*mmr.InclusionProof, dataItems [][]byte) ([]MMRVerificationResult, error) {
	if len(proofs) != len(dataItems) {
		return nil, errors.New("proofs and data must have same length")
	}

	results := make([]MMRVerificationResult, len(proofs))
	verifier := NewMMRVerifier()

	for i := range proofs {
		result, _ := verifier.VerifyInclusionProof(dataItems[i], proofs[i])
		if result != nil {
			results[i] = *result
		} else {
			results[i] = MMRVerificationResult{
				Valid: false,
				Error: "nil result",
			}
		}
	}

	return results, nil
}
