// Package vdf implements Verifiable Delay Functions for proving elapsed time.
//
// A VDF proves that a minimum amount of sequential computation occurred.
// This is used to demonstrate that real wall-clock time passed between
// checkpoints, as the computation cannot be parallelized.
//
// This implementation uses iterated SHA-256 hashing. While verification
// requires recomputing the chain (unlike Wesolowski/Pietrzak VDFs), it is
// simple, auditable, and sufficient for proving minutes-to-hours of delay.
package vdf

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"
)

// Proof represents a VDF proof that demonstrates minimum elapsed time.
type Proof struct {
	Input      [32]byte // Starting hash
	Output     [32]byte // Final hash after iterations
	Iterations uint64   // Number of sequential hashes computed
	Duration   time.Duration // Claimed wall-clock duration
}

// Parameters defines VDF computation parameters.
type Parameters struct {
	// IterationsPerSecond is calibrated to the machine's performance.
	// This determines how many iterations represent one second of delay.
	IterationsPerSecond uint64

	// MinIterations is the minimum iterations for any proof.
	MinIterations uint64

	// MaxIterations caps the computation to prevent DoS.
	MaxIterations uint64
}

// DefaultParameters returns reasonable defaults for modern hardware.
// These should be calibrated per-machine using Calibrate().
func DefaultParameters() Parameters {
	return Parameters{
		IterationsPerSecond: 1_000_000, // ~1M SHA-256/sec on modern CPU
		MinIterations:       100_000,   // ~0.1 seconds minimum
		MaxIterations:       3_600_000_000, // ~1 hour maximum
	}
}

// Calibrate measures the machine's SHA-256 performance and returns
// calibrated parameters. Run this once during setup.
func Calibrate(duration time.Duration) (Parameters, error) {
	if duration < time.Millisecond*100 {
		return Parameters{}, errors.New("calibration duration too short")
	}

	// Use a fixed input for calibration
	var hash [32]byte
	copy(hash[:], "witnessd-calibration-input-v1")

	// Measure iterations over the duration
	iterations := uint64(0)
	start := time.Now()
	deadline := start.Add(duration)

	for time.Now().Before(deadline) {
		// Batch 1000 iterations to reduce time.Now() overhead
		for i := 0; i < 1000; i++ {
			hash = sha256.Sum256(hash[:])
			iterations++
		}
	}

	elapsed := time.Since(start)
	iterationsPerSecond := uint64(float64(iterations) / elapsed.Seconds())

	return Parameters{
		IterationsPerSecond: iterationsPerSecond,
		MinIterations:       iterationsPerSecond / 10,      // 0.1 second minimum
		MaxIterations:       iterationsPerSecond * 3600,    // 1 hour maximum
	}, nil
}

// Compute generates a VDF proof for the given input and duration.
// The computation takes approximately the specified duration.
func Compute(input [32]byte, targetDuration time.Duration, params Parameters) (*Proof, error) {
	iterations := uint64(targetDuration.Seconds() * float64(params.IterationsPerSecond))

	if iterations < params.MinIterations {
		iterations = params.MinIterations
	}
	if iterations > params.MaxIterations {
		return nil, fmt.Errorf("target duration exceeds maximum (%d iterations)", params.MaxIterations)
	}

	start := time.Now()
	output := computeChain(input, iterations)
	elapsed := time.Since(start)

	return &Proof{
		Input:      input,
		Output:     output,
		Iterations: iterations,
		Duration:   elapsed,
	}, nil
}

// ComputeIterations generates a VDF proof with exactly the specified iterations.
func ComputeIterations(input [32]byte, iterations uint64) *Proof {
	start := time.Now()
	output := computeChain(input, iterations)
	elapsed := time.Since(start)

	return &Proof{
		Input:      input,
		Output:     output,
		Iterations: iterations,
		Duration:   elapsed,
	}
}

// computeChain performs the sequential hash chain computation.
func computeChain(input [32]byte, iterations uint64) [32]byte {
	hash := input
	for i := uint64(0); i < iterations; i++ {
		hash = sha256.Sum256(hash[:])
	}
	return hash
}

// Verify checks that a VDF proof is valid.
// This requires recomputing the hash chain, so takes similar time to generation.
func Verify(proof *Proof) bool {
	computed := computeChain(proof.Input, proof.Iterations)
	return computed == proof.Output
}

// VerifyWithProgress verifies a proof and reports progress through a channel.
// Useful for long verifications where UI feedback is needed.
func VerifyWithProgress(proof *Proof, progress chan<- float64) bool {
	hash := proof.Input
	reportInterval := proof.Iterations / 100
	if reportInterval == 0 {
		reportInterval = 1
	}

	for i := uint64(0); i < proof.Iterations; i++ {
		hash = sha256.Sum256(hash[:])
		if progress != nil && i%reportInterval == 0 {
			select {
			case progress <- float64(i) / float64(proof.Iterations):
			default:
			}
		}
	}

	if progress != nil {
		close(progress)
	}

	return hash == proof.Output
}

// MinElapsedTime returns the minimum wall-clock time the proof represents,
// based on the given parameters.
func (p *Proof) MinElapsedTime(params Parameters) time.Duration {
	seconds := float64(p.Iterations) / float64(params.IterationsPerSecond)
	return time.Duration(seconds * float64(time.Second))
}

// Encode serializes a proof to bytes.
func (p *Proof) Encode() []byte {
	buf := make([]byte, 32+32+8+8)
	copy(buf[0:32], p.Input[:])
	copy(buf[32:64], p.Output[:])
	binary.BigEndian.PutUint64(buf[64:72], p.Iterations)
	binary.BigEndian.PutUint64(buf[72:80], uint64(p.Duration))
	return buf
}

// DecodeProof deserializes a proof from bytes.
func DecodeProof(data []byte) (*Proof, error) {
	if len(data) < 80 {
		return nil, errors.New("proof data too short")
	}

	p := &Proof{}
	copy(p.Input[:], data[0:32])
	copy(p.Output[:], data[32:64])
	p.Iterations = binary.BigEndian.Uint64(data[64:72])
	p.Duration = time.Duration(binary.BigEndian.Uint64(data[72:80]))

	return p, nil
}

// BatchVerifier allows parallel verification of multiple proofs.
// While individual VDF verification is sequential, multiple proofs
// can be verified concurrently.
type BatchVerifier struct {
	workers int
}

// NewBatchVerifier creates a verifier with the specified worker count.
// Use 0 for automatic (GOMAXPROCS).
func NewBatchVerifier(workers int) *BatchVerifier {
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	return &BatchVerifier{workers: workers}
}

// VerifyResult holds the result of verifying a single proof.
type VerifyResult struct {
	Index int
	Valid bool
	Error error
}

// VerifyAll verifies multiple proofs concurrently.
func (bv *BatchVerifier) VerifyAll(proofs []*Proof) []VerifyResult {
	results := make([]VerifyResult, len(proofs))

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, bv.workers)

	for i, proof := range proofs {
		wg.Add(1)
		go func(idx int, p *Proof) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			if p == nil {
				results[idx] = VerifyResult{Index: idx, Valid: false, Error: errors.New("nil proof")}
				return
			}

			valid := Verify(p)
			results[idx] = VerifyResult{Index: idx, Valid: valid}
		}(i, proof)
	}

	wg.Wait()
	return results
}

// ChainInput creates a deterministic VDF input from a checkpoint chain.
// This binds the VDF to the specific content being witnessed.
func ChainInput(contentHash [32]byte, previousHash [32]byte, ordinal uint64) [32]byte {
	h := sha256.New()
	h.Write([]byte("witnessd-vdf-v1"))
	h.Write(contentHash[:])
	h.Write(previousHash[:])
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], ordinal)
	h.Write(buf[:])

	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}
