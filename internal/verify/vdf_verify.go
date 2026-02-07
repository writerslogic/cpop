// Package verify provides VDF proof verification.
package verify

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"

	"witnessd/internal/vdf"
)

// VDF verification errors
var (
	ErrVDFInvalidInput     = errors.New("vdf: invalid input format")
	ErrVDFInvalidOutput    = errors.New("vdf: invalid output format")
	ErrVDFMismatch         = errors.New("vdf: computed output does not match claimed output")
	ErrVDFIterationsTooLow = errors.New("vdf: iterations below minimum")
	ErrVDFIterationsTooHigh = errors.New("vdf: iterations above maximum")
	ErrVDFTimeout          = errors.New("vdf: verification timeout")
	ErrVDFTimingAnomaly    = errors.New("vdf: claimed time inconsistent with iterations")
)

// VDFVerificationResult contains detailed VDF verification results.
type VDFVerificationResult struct {
	Valid             bool          `json:"valid"`
	Input             string        `json:"input"`
	ExpectedOutput    string        `json:"expected_output"`
	ComputedOutput    string        `json:"computed_output,omitempty"`
	Iterations        uint64        `json:"iterations"`
	ClaimedDuration   time.Duration `json:"claimed_duration"`
	ComputedDuration  time.Duration `json:"computed_duration,omitempty"`
	MinElapsedTime    time.Duration `json:"min_elapsed_time"`
	IterationsPerSec  uint64        `json:"iterations_per_sec"`
	Error             string        `json:"error,omitempty"`
	Warnings          []string      `json:"warnings,omitempty"`
	VerificationTime  time.Duration `json:"verification_time"`
}

// VDFVerifier provides VDF proof verification utilities.
type VDFVerifier struct {
	params      vdf.Parameters
	timeout     time.Duration
	workers     int
	skipCompute bool // For quick checks, skip full recomputation
}

// NewVDFVerifier creates a new VDF verifier with given parameters.
func NewVDFVerifier(params vdf.Parameters) *VDFVerifier {
	return &VDFVerifier{
		params:  params,
		timeout: 10 * time.Minute, // Default timeout for large proofs
		workers: runtime.NumCPU(),
	}
}

// WithTimeout sets the verification timeout.
func (v *VDFVerifier) WithTimeout(timeout time.Duration) *VDFVerifier {
	v.timeout = timeout
	return v
}

// WithWorkers sets the number of parallel workers for batch verification.
func (v *VDFVerifier) WithWorkers(n int) *VDFVerifier {
	if n > 0 {
		v.workers = n
	}
	return v
}

// SkipComputation skips full recomputation (for quick structural checks only).
func (v *VDFVerifier) SkipComputation() *VDFVerifier {
	v.skipCompute = true
	return v
}

// VerifyProof verifies a VDF proof by recomputing the hash chain.
func (v *VDFVerifier) VerifyProof(ctx context.Context, proof *vdf.Proof) (*VDFVerificationResult, error) {
	start := time.Now()
	result := &VDFVerificationResult{
		Input:          hex.EncodeToString(proof.Input[:]),
		ExpectedOutput: hex.EncodeToString(proof.Output[:]),
		Iterations:     proof.Iterations,
		ClaimedDuration: proof.Duration,
		IterationsPerSec: v.params.IterationsPerSecond,
	}

	defer func() {
		result.VerificationTime = time.Since(start)
	}()

	// Check iterations bounds
	if proof.Iterations < v.params.MinIterations {
		result.Error = fmt.Sprintf("iterations %d below minimum %d",
			proof.Iterations, v.params.MinIterations)
		return result, ErrVDFIterationsTooLow
	}

	if proof.Iterations > v.params.MaxIterations {
		result.Error = fmt.Sprintf("iterations %d above maximum %d",
			proof.Iterations, v.params.MaxIterations)
		return result, ErrVDFIterationsTooHigh
	}

	// Calculate minimum elapsed time
	result.MinElapsedTime = proof.MinElapsedTime(v.params)

	// Check for timing anomalies
	if proof.Duration > 0 {
		expectedMin := result.MinElapsedTime
		expectedMax := expectedMin * 3 // Allow 3x margin for slow machines

		if proof.Duration < expectedMin/2 {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("claimed duration %v is suspiciously fast for %d iterations",
					proof.Duration, proof.Iterations))
		}

		if proof.Duration > expectedMax {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("claimed duration %v is unusually slow for %d iterations",
					proof.Duration, proof.Iterations))
		}
	}

	// Skip full computation if requested
	if v.skipCompute {
		result.Valid = true
		result.Warnings = append(result.Warnings, "full verification skipped")
		return result, nil
	}

	// Create cancellation context with timeout
	verifyCtx, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()

	// Verify in a goroutine so we can respect context cancellation
	done := make(chan bool, 1)
	var computed [32]byte

	go func() {
		computed = v.computeChain(proof.Input, proof.Iterations)
		done <- true
	}()

	select {
	case <-verifyCtx.Done():
		result.Error = "verification timeout"
		return result, ErrVDFTimeout
	case <-done:
		// Verification complete
	}

	result.ComputedOutput = hex.EncodeToString(computed[:])
	result.ComputedDuration = time.Since(start)

	if computed != proof.Output {
		result.Error = "computed output does not match claimed output"
		return result, ErrVDFMismatch
	}

	result.Valid = true
	return result, nil
}

// VerifyProofHex verifies a VDF proof with hex-encoded inputs.
func (v *VDFVerifier) VerifyProofHex(
	ctx context.Context,
	inputHex string,
	outputHex string,
	iterations uint64,
) (*VDFVerificationResult, error) {
	inputBytes, err := hex.DecodeString(inputHex)
	if err != nil {
		return &VDFVerificationResult{
			Error: fmt.Sprintf("invalid input hex: %v", err),
		}, ErrVDFInvalidInput
	}

	outputBytes, err := hex.DecodeString(outputHex)
	if err != nil {
		return &VDFVerificationResult{
			Error: fmt.Sprintf("invalid output hex: %v", err),
		}, ErrVDFInvalidOutput
	}

	if len(inputBytes) != 32 || len(outputBytes) != 32 {
		return &VDFVerificationResult{
			Error: "input and output must be 32 bytes",
		}, ErrVDFInvalidInput
	}

	var input, output [32]byte
	copy(input[:], inputBytes)
	copy(output[:], outputBytes)

	proof := &vdf.Proof{
		Input:      input,
		Output:     output,
		Iterations: iterations,
	}

	return v.VerifyProof(ctx, proof)
}

// computeChain performs the sequential hash chain computation.
func (v *VDFVerifier) computeChain(input [32]byte, iterations uint64) [32]byte {
	// Delegate to the vdf package's implementation
	proof := vdf.ComputeIterations(input, iterations)
	return proof.Output
}

// BatchVDFResult contains results for a batch VDF verification.
type BatchVDFResult struct {
	Index  int
	Result *VDFVerificationResult
	Error  error
}

// VerifyBatch verifies multiple VDF proofs in parallel.
func (v *VDFVerifier) VerifyBatch(ctx context.Context, proofs []*vdf.Proof) []BatchVDFResult {
	results := make([]BatchVDFResult, len(proofs))

	var wg sync.WaitGroup
	sem := make(chan struct{}, v.workers)

	for i, proof := range proofs {
		wg.Add(1)
		go func(idx int, p *vdf.Proof) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			result, err := v.VerifyProof(ctx, p)
			results[idx] = BatchVDFResult{
				Index:  idx,
				Result: result,
				Error:  err,
			}
		}(i, proof)
	}

	wg.Wait()
	return results
}

// VerifyCheckpointVDFs verifies all VDF proofs in a checkpoint chain.
func VerifyCheckpointVDFs(
	ctx context.Context,
	checkpoints []CheckpointVDFData,
	params vdf.Parameters,
) (*VDFChainVerificationResult, error) {
	result := &VDFChainVerificationResult{
		TotalCheckpoints: len(checkpoints),
		Results:          make([]VDFVerificationResult, 0),
	}

	verifier := NewVDFVerifier(params)
	start := time.Now()

	for i, cp := range checkpoints {
		select {
		case <-ctx.Done():
			result.Error = "verification cancelled"
			return result, ctx.Err()
		default:
		}

		// Skip checkpoints without VDF
		if cp.Iterations == 0 {
			result.Skipped++
			continue
		}

		inputBytes, err := hex.DecodeString(cp.Input)
		if err != nil {
			result.Failed++
			result.Results = append(result.Results, VDFVerificationResult{
				Error: fmt.Sprintf("checkpoint %d: invalid input hex", i),
			})
			continue
		}

		outputBytes, err := hex.DecodeString(cp.Output)
		if err != nil {
			result.Failed++
			result.Results = append(result.Results, VDFVerificationResult{
				Error: fmt.Sprintf("checkpoint %d: invalid output hex", i),
			})
			continue
		}

		var input, output [32]byte
		copy(input[:], inputBytes)
		copy(output[:], outputBytes)

		proof := &vdf.Proof{
			Input:      input,
			Output:     output,
			Iterations: cp.Iterations,
			Duration:   cp.ElapsedTime,
		}

		vdfResult, err := verifier.VerifyProof(ctx, proof)
		if err != nil {
			result.Failed++
		} else if vdfResult.Valid {
			result.Verified++
			result.TotalElapsed += vdfResult.MinElapsedTime
		}

		result.Results = append(result.Results, *vdfResult)
	}

	result.Duration = time.Since(start)
	result.Valid = result.Failed == 0 && result.Verified > 0

	return result, nil
}

// CheckpointVDFData contains VDF data from a checkpoint.
type CheckpointVDFData struct {
	Input       string
	Output      string
	Iterations  uint64
	ElapsedTime time.Duration
}

// VDFChainVerificationResult contains results for verifying a chain of VDF proofs.
type VDFChainVerificationResult struct {
	Valid            bool                    `json:"valid"`
	TotalCheckpoints int                     `json:"total_checkpoints"`
	Verified         int                     `json:"verified"`
	Failed           int                     `json:"failed"`
	Skipped          int                     `json:"skipped"`
	TotalElapsed     time.Duration           `json:"total_elapsed"`
	Duration         time.Duration           `json:"verification_duration"`
	Error            string                  `json:"error,omitempty"`
	Results          []VDFVerificationResult `json:"results"`
}

// QuickVerifyVDF performs a quick structural check without full recomputation.
func QuickVerifyVDF(proof *vdf.Proof, params vdf.Parameters) (*VDFVerificationResult, error) {
	verifier := NewVDFVerifier(params).SkipComputation()
	return verifier.VerifyProof(context.Background(), proof)
}

// FullVerifyVDF performs full VDF verification with recomputation.
func FullVerifyVDF(ctx context.Context, proof *vdf.Proof, params vdf.Parameters) (*VDFVerificationResult, error) {
	verifier := NewVDFVerifier(params)
	return verifier.VerifyProof(ctx, proof)
}
