// Package checkpoint implements the Layer 0 content commit chain.
//
// Unlike the previous daemon-based approach, checkpoints are created
// explicitly by the author using `witnessd commit`. This is git-like:
// the author writes however they want, then commits when ready.
//
// Each checkpoint contains:
// - Content hash (what was written)
// - Previous checkpoint hash (chain integrity)
// - VDF proof (minimum time elapsed since last commit)
// - Optional TPM binding (hardware attestation)
package checkpoint

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"witnessd/internal/vdf"
)

// Checkpoint represents a single content commit in the chain.
type Checkpoint struct {
	// Chain position
	Ordinal      uint64    `json:"ordinal"`
	PreviousHash [32]byte  `json:"previous_hash"`
	Hash         [32]byte  `json:"hash"` // Hash of this checkpoint

	// Content commitment
	ContentHash [32]byte `json:"content_hash"`
	ContentSize int64    `json:"content_size"`
	FilePath    string   `json:"file_path"`

	// Timing
	Timestamp time.Time `json:"timestamp"`
	Message   string    `json:"message,omitempty"`

	// VDF proof of elapsed time since previous checkpoint
	VDF *vdf.Proof `json:"vdf,omitempty"`

	// Hardware binding (optional)
	TPMBinding *TPMBinding `json:"tpm_binding,omitempty"`

	// Key Hierarchy signature (optional, Layer 6)
	// Patent Pending: USPTO Application No. 19/460,364
	Signature []byte `json:"signature,omitempty"`
}

// TPMBinding contains TPM attestation data.
type TPMBinding struct {
	MonotonicCounter uint64   `json:"monotonic_counter"`
	ClockInfo        []byte   `json:"clock_info"`
	Attestation      []byte   `json:"attestation"`
	Signature        []byte   `json:"signature"`
	PublicKey        []byte   `json:"public_key"`
}

// Chain manages a sequence of checkpoints for a document.
type Chain struct {
	// Metadata
	DocumentID   string    `json:"document_id"`
	DocumentPath string    `json:"document_path"`
	CreatedAt    time.Time `json:"created_at"`

	// The checkpoint sequence
	Checkpoints []*Checkpoint `json:"checkpoints"`

	// VDF parameters for this chain
	VDFParams vdf.Parameters `json:"vdf_params"`

	// Storage path
	storagePath string
}

// NewChain creates a new checkpoint chain for a document.
func NewChain(documentPath string, vdfParams vdf.Parameters) (*Chain, error) {
	absPath, err := filepath.Abs(documentPath)
	if err != nil {
		return nil, fmt.Errorf("invalid document path: %w", err)
	}

	// Generate document ID from path hash
	pathHash := sha256.Sum256([]byte(absPath))
	docID := hex.EncodeToString(pathHash[:8])

	return &Chain{
		DocumentID:   docID,
		DocumentPath: absPath,
		CreatedAt:    time.Now(),
		Checkpoints:  make([]*Checkpoint, 0),
		VDFParams:    vdfParams,
	}, nil
}

// Commit creates a new checkpoint for the current document state.
func (c *Chain) Commit(message string) (*Checkpoint, error) {
	// Read and hash current content
	content, err := os.ReadFile(c.DocumentPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read document: %w", err)
	}

	contentHash := sha256.Sum256(content)
	ordinal := uint64(len(c.Checkpoints))

	// Determine previous hash
	var previousHash [32]byte
	var lastTimestamp time.Time
	if ordinal > 0 {
		prev := c.Checkpoints[ordinal-1]
		previousHash = prev.Hash
		lastTimestamp = prev.Timestamp
	}

	now := time.Now()

	// Create checkpoint
	cp := &Checkpoint{
		Ordinal:      ordinal,
		PreviousHash: previousHash,
		ContentHash:  contentHash,
		ContentSize:  int64(len(content)),
		FilePath:     c.DocumentPath,
		Timestamp:    now,
		Message:      message,
	}

	// Compute VDF proof (only if this isn't the first checkpoint)
	if ordinal > 0 {
		elapsed := now.Sub(lastTimestamp)
		vdfInput := vdf.ChainInput(contentHash, previousHash, ordinal)

		vdfProof, err := vdf.Compute(vdfInput, elapsed, c.VDFParams)
		if err != nil {
			return nil, fmt.Errorf("failed to compute VDF: %w", err)
		}
		cp.VDF = vdfProof
	}

	// Compute checkpoint hash
	cp.Hash = cp.computeHash()

	c.Checkpoints = append(c.Checkpoints, cp)
	return cp, nil
}

// CommitWithVDFDuration creates a checkpoint with a specific VDF duration.
// This is useful when you want to prove a specific amount of elapsed time
// rather than deriving it from timestamps.
func (c *Chain) CommitWithVDFDuration(message string, vdfDuration time.Duration) (*Checkpoint, error) {
	content, err := os.ReadFile(c.DocumentPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read document: %w", err)
	}

	contentHash := sha256.Sum256(content)
	ordinal := uint64(len(c.Checkpoints))

	var previousHash [32]byte
	if ordinal > 0 {
		previousHash = c.Checkpoints[ordinal-1].Hash
	}

	cp := &Checkpoint{
		Ordinal:      ordinal,
		PreviousHash: previousHash,
		ContentHash:  contentHash,
		ContentSize:  int64(len(content)),
		FilePath:     c.DocumentPath,
		Timestamp:    time.Now(),
		Message:      message,
	}

	// Compute VDF with specified duration
	if ordinal > 0 {
		vdfInput := vdf.ChainInput(contentHash, previousHash, ordinal)
		vdfProof, err := vdf.Compute(vdfInput, vdfDuration, c.VDFParams)
		if err != nil {
			return nil, fmt.Errorf("failed to compute VDF: %w", err)
		}
		cp.VDF = vdfProof
	}

	cp.Hash = cp.computeHash()
	c.Checkpoints = append(c.Checkpoints, cp)
	return cp, nil
}

// computeHash computes the checkpoint's binding hash.
func (cp *Checkpoint) computeHash() [32]byte {
	h := sha256.New()
	h.Write([]byte("witnessd-checkpoint-v1"))

	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], cp.Ordinal)
	h.Write(buf[:])

	h.Write(cp.PreviousHash[:])
	h.Write(cp.ContentHash[:])

	binary.BigEndian.PutUint64(buf[:], uint64(cp.ContentSize))
	h.Write(buf[:])

	binary.BigEndian.PutUint64(buf[:], uint64(cp.Timestamp.UnixNano()))
	h.Write(buf[:])

	if cp.VDF != nil {
		h.Write(cp.VDF.Encode())
	}

	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// Verify checks the integrity of the entire chain.
func (c *Chain) Verify() error {
	for i, cp := range c.Checkpoints {
		// Verify hash
		computed := cp.computeHash()
		if computed != cp.Hash {
			return fmt.Errorf("checkpoint %d: hash mismatch", i)
		}

		// Verify chain linkage
		if i > 0 {
			if cp.PreviousHash != c.Checkpoints[i-1].Hash {
				return fmt.Errorf("checkpoint %d: broken chain link", i)
			}
		} else if cp.PreviousHash != ([32]byte{}) {
			return fmt.Errorf("checkpoint 0: non-zero previous hash")
		}

		// Verify VDF (mandatory for all non-first checkpoints)
		if i > 0 {
			if cp.VDF == nil {
				return fmt.Errorf("checkpoint %d: missing VDF proof (required for time verification)", i)
			}
			expectedInput := vdf.ChainInput(cp.ContentHash, cp.PreviousHash, cp.Ordinal)
			if cp.VDF.Input != expectedInput {
				return fmt.Errorf("checkpoint %d: VDF input mismatch", i)
			}
			if !vdf.Verify(cp.VDF) {
				return fmt.Errorf("checkpoint %d: VDF verification failed", i)
			}
		}
	}

	return nil
}

// TotalElapsedTime returns the sum of all VDF-proven elapsed times.
func (c *Chain) TotalElapsedTime() time.Duration {
	var total time.Duration
	for _, cp := range c.Checkpoints {
		if cp.VDF != nil {
			total += cp.VDF.MinElapsedTime(c.VDFParams)
		}
	}
	return total
}

// Summary returns a human-readable summary of the chain.
type ChainSummary struct {
	DocumentPath      string        `json:"document_path"`
	CheckpointCount   int           `json:"checkpoint_count"`
	FirstCommit       time.Time     `json:"first_commit"`
	LastCommit        time.Time     `json:"last_commit"`
	TotalElapsedTime  time.Duration `json:"total_elapsed_time"`
	FinalContentHash  string        `json:"final_content_hash"`
	ChainValid        bool          `json:"chain_valid"`
}

func (c *Chain) Summary() ChainSummary {
	s := ChainSummary{
		DocumentPath:    c.DocumentPath,
		CheckpointCount: len(c.Checkpoints),
	}

	if len(c.Checkpoints) > 0 {
		s.FirstCommit = c.Checkpoints[0].Timestamp
		s.LastCommit = c.Checkpoints[len(c.Checkpoints)-1].Timestamp
		s.FinalContentHash = hex.EncodeToString(c.Checkpoints[len(c.Checkpoints)-1].ContentHash[:])
	}

	s.TotalElapsedTime = c.TotalElapsedTime()
	s.ChainValid = c.Verify() == nil

	return s
}

// Save persists the chain to disk.
func (c *Chain) Save(path string) error {
	c.storagePath = path

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal chain: %w", err)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write chain: %w", err)
	}

	return nil
}

// Load reads a chain from disk.
func Load(path string) (*Chain, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read chain: %w", err)
	}

	var c Chain
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("failed to unmarshal chain: %w", err)
	}

	c.storagePath = path
	return &c, nil
}

// FindChain locates the chain file for a document.
func FindChain(documentPath string, witnessdDir string) (string, error) {
	absPath, err := filepath.Abs(documentPath)
	if err != nil {
		return "", err
	}

	pathHash := sha256.Sum256([]byte(absPath))
	docID := hex.EncodeToString(pathHash[:8])

	chainPath := filepath.Join(witnessdDir, "chains", docID+".json")
	if _, err := os.Stat(chainPath); err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("no chain found for %s", documentPath)
		}
		return "", err
	}

	return chainPath, nil
}

// GetOrCreateChain loads an existing chain or creates a new one.
func GetOrCreateChain(documentPath string, witnessdDir string, vdfParams vdf.Parameters) (*Chain, error) {
	chainPath, err := FindChain(documentPath, witnessdDir)
	if err == nil {
		return Load(chainPath)
	}

	// Create new chain
	chain, err := NewChain(documentPath, vdfParams)
	if err != nil {
		return nil, err
	}

	// Set storage path
	absPath, _ := filepath.Abs(documentPath)
	pathHash := sha256.Sum256([]byte(absPath))
	docID := hex.EncodeToString(pathHash[:8])
	chain.storagePath = filepath.Join(witnessdDir, "chains", docID+".json")

	return chain, nil
}

// Latest returns the most recent checkpoint, or nil if empty.
func (c *Chain) Latest() *Checkpoint {
	if len(c.Checkpoints) == 0 {
		return nil
	}
	return c.Checkpoints[len(c.Checkpoints)-1]
}

// At returns the checkpoint at a specific ordinal.
func (c *Chain) At(ordinal uint64) (*Checkpoint, error) {
	if ordinal >= uint64(len(c.Checkpoints)) {
		return nil, errors.New("ordinal out of range")
	}
	return c.Checkpoints[ordinal], nil
}

// StoragePath returns where the chain is persisted.
func (c *Chain) StoragePath() string {
	return c.storagePath
}
