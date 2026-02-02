// Package vdf provides a unified interface to Verifiable Delay Functions.
//
// This file provides a high-level API that uses the Pietrzak VDF by default,
// which offers O(log T) verification time compared to the hash-based VDF's O(T).
//
// Usage:
//
//	vdf := vdf.NewDefault()
//	proof, _ := vdf.ComputeForDuration(input, 5*time.Second)
//	valid := vdf.Verify(proof)
//
// The Pietrzak VDF uses repeated squaring in an RSA group with a recursive
// halving proof structure, providing succinct proofs that can be verified
// much faster than they were generated.
package vdf

import (
	"math/big"
	"time"
)

// VDF is the unified interface for all VDF implementations.
type VDF interface {
	// Compute evaluates the VDF and generates a proof.
	Compute(input *big.Int) (UnifiedProof, error)

	// ComputeForDuration evaluates the VDF for approximately the given duration.
	ComputeForDuration(input *big.Int, duration time.Duration) (UnifiedProof, error)

	// Verify checks that a proof is valid.
	Verify(proof UnifiedProof) bool

	// VerifyMinDuration verifies and checks minimum elapsed time.
	VerifyMinDuration(proof UnifiedProof, minDuration time.Duration) error
}

// UnifiedProof is the common interface for VDF proofs.
type UnifiedProof interface {
	// MinElapsedTime returns the minimum real time this proof represents.
	MinElapsedTime() time.Duration

	// ProofSize returns the size of the proof in bytes.
	ProofSize() int

	// VerificationOps returns the number of operations needed for verification.
	VerificationOps() int

	// Encode serializes the proof.
	Encode() ([]byte, error)

	// Type returns the proof type ("pietrzak" or "hash").
	Type() string
}

// Config configures the unified VDF.
type Config struct {
	// UsePietrzak selects Pietrzak VDF (true) or hash-based VDF (false).
	// Default: true (Pietrzak for O(log T) verification).
	UsePietrzak bool

	// SquaringsPerSecond calibrates Pietrzak VDF to this machine.
	// Default: 1,000,000 (calibrate with CalibrateSquaringsPerSecond for accuracy).
	SquaringsPerSecond uint64

	// DefaultT is the default time parameter for Pietrzak VDF.
	// This is the number of sequential squarings.
	// Default: 1,000,000 (~1 second at 1M squarings/sec).
	DefaultT uint64

	// HashIterationsPerSecond calibrates hash-based VDF.
	// Only used if UsePietrzak is false.
	HashIterationsPerSecond uint64
}

// DefaultConfig returns the default configuration using Pietrzak VDF.
func DefaultConfig() Config {
	return Config{
		UsePietrzak:             true,
		SquaringsPerSecond:      1_000_000,
		DefaultT:                1_000_000,
		HashIterationsPerSecond: 1_000_000,
	}
}

// UnifiedVDF implements the VDF interface.
type UnifiedVDF struct {
	config Config

	// Pietrzak VDF instance
	pietrzak *PietrzakVDF

	// Hash-based parameters (for backwards compatibility)
	hashParams Parameters
}

// NewDefault creates a VDF with default settings (Pietrzak).
func NewDefault() (*UnifiedVDF, error) {
	return New(DefaultConfig())
}

// New creates a VDF with the specified configuration.
func New(config Config) (*UnifiedVDF, error) {
	u := &UnifiedVDF{
		config: config,
	}

	if config.UsePietrzak {
		params := PietrzakParams{
			N:      defaultModulus,
			T:      config.DefaultT,
			Lambda: 128,
		}
		var err error
		u.pietrzak, err = NewPietrzakVDF(params)
		if err != nil {
			return nil, err
		}
	}

	u.hashParams = Parameters{
		IterationsPerSecond: config.HashIterationsPerSecond,
		MinIterations:       config.HashIterationsPerSecond / 10,
		MaxIterations:       config.HashIterationsPerSecond * 3600,
	}

	return u, nil
}

// Compute evaluates the VDF using the default time parameter.
func (u *UnifiedVDF) Compute(input *big.Int) (UnifiedProof, error) {
	if u.config.UsePietrzak {
		proof, err := u.pietrzak.Evaluate(input)
		if err != nil {
			return nil, err
		}
		return &pietrzakProofWrapper{
			proof:       proof,
			sqPerSecond: u.config.SquaringsPerSecond,
		}, nil
	}

	// Hash-based fallback
	var inputHash [32]byte
	copy(inputHash[:], input.Bytes())
	proof := ComputeIterations(inputHash, u.hashParams.MinIterations)
	return &hashProofWrapper{
		proof:  proof,
		params: u.hashParams,
	}, nil
}

// ComputeForDuration evaluates the VDF for approximately the given duration.
func (u *UnifiedVDF) ComputeForDuration(input *big.Int, duration time.Duration) (UnifiedProof, error) {
	if u.config.UsePietrzak {
		proof, err := u.pietrzak.ComputeWithDuration(input, duration, u.config.SquaringsPerSecond)
		if err != nil {
			return nil, err
		}
		return &pietrzakProofWrapper{
			proof:       proof,
			sqPerSecond: u.config.SquaringsPerSecond,
		}, nil
	}

	// Hash-based fallback
	var inputHash [32]byte
	copy(inputHash[:], input.Bytes())
	proof, err := Compute(inputHash, duration, u.hashParams)
	if err != nil {
		return nil, err
	}
	return &hashProofWrapper{
		proof:  proof,
		params: u.hashParams,
	}, nil
}

// Verify checks that a proof is valid.
func (u *UnifiedVDF) Verify(proof UnifiedProof) bool {
	switch p := proof.(type) {
	case *pietrzakProofWrapper:
		return u.pietrzak.Verify(p.proof)
	case *hashProofWrapper:
		return Verify(p.proof)
	default:
		return false
	}
}

// VerifyMinDuration verifies and checks minimum elapsed time.
func (u *UnifiedVDF) VerifyMinDuration(proof UnifiedProof, minDuration time.Duration) error {
	if !u.Verify(proof) {
		return ErrInvalidProof
	}

	if proof.MinElapsedTime() < minDuration {
		return ErrInvalidParameters
	}

	return nil
}

// InputFromBytes creates a VDF input from arbitrary bytes.
func (u *UnifiedVDF) InputFromBytes(data []byte) *big.Int {
	if u.config.UsePietrzak {
		return u.pietrzak.InputFromBytes(data)
	}

	// For hash-based, just return the data as a big.Int
	return new(big.Int).SetBytes(data)
}

// pietrzakProofWrapper wraps a Pietrzak proof to implement UnifiedProof.
type pietrzakProofWrapper struct {
	proof       *PietrzakProof
	sqPerSecond uint64
}

func (p *pietrzakProofWrapper) MinElapsedTime() time.Duration {
	return p.proof.MinElapsedTime(p.sqPerSecond)
}

func (p *pietrzakProofWrapper) ProofSize() int {
	return p.proof.PietrzakProofSize()
}

func (p *pietrzakProofWrapper) VerificationOps() int {
	return p.proof.VerificationOps()
}

func (p *pietrzakProofWrapper) Encode() ([]byte, error) {
	return p.proof.Encode()
}

func (p *pietrzakProofWrapper) Type() string {
	return "pietrzak"
}

// hashProofWrapper wraps a hash-based proof to implement UnifiedProof.
type hashProofWrapper struct {
	proof  *Proof
	params Parameters
}

func (p *hashProofWrapper) MinElapsedTime() time.Duration {
	return p.proof.MinElapsedTime(p.params)
}

func (p *hashProofWrapper) ProofSize() int {
	return 80 // Fixed size for hash-based proofs
}

func (p *hashProofWrapper) VerificationOps() int {
	return int(p.proof.Iterations) // O(T) for hash-based
}

func (p *hashProofWrapper) Encode() ([]byte, error) {
	return p.proof.Encode(), nil
}

func (p *hashProofWrapper) Type() string {
	return "hash"
}

// CompareVerificationEfficiency compares Pietrzak vs hash-based verification.
// Returns (pietrzakOps, hashOps) for the given time parameter.
func CompareVerificationEfficiency(t uint64) (int, int) {
	// Pietrzak: O(log T) operations
	pietrzakOps := 2 * bitLength(t) // 2 exponentiations per level

	// Hash-based: O(T) operations
	hashOps := int(t)

	return pietrzakOps, hashOps
}
