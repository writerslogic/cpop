// Package verify provides cryptographic verification for witnessed files.
package verify

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"witnessd/internal/mmr"
	"witnessd/internal/signer"
	"witnessd/internal/watcher"
)

// Errors
var (
	ErrFileNotFound     = errors.New("verify: file not found in witness database")
	ErrHashMismatch     = errors.New("verify: file hash does not match witnessed hash")
	ErrProofInvalid     = errors.New("verify: inclusion proof is invalid")
	ErrSignatureInvalid = errors.New("verify: signature verification failed")
)

// Result contains the verification result for a file.
type Result struct {
	Path          string    `json:"path"`
	CurrentHash   string    `json:"current_hash"`
	WitnessedHash string    `json:"witnessed_hash"`
	MMRIndex      uint64    `json:"mmr_index"`
	MMRRoot       string    `json:"mmr_root"`
	Timestamp     time.Time `json:"timestamp,omitempty"`
	Valid         bool      `json:"valid"`
	Error         string    `json:"error,omitempty"`
}

// EvidencePacket is a self-contained proof bundle.
type EvidencePacket struct {
	Version     int       `json:"version"`
	GeneratedAt time.Time `json:"generated_at"`

	// File information
	FilePath string `json:"file_path"`
	FileHash string `json:"file_hash"`
	FileSize int64  `json:"file_size"`

	// MMR proof
	MMRIndex   uint64      `json:"mmr_index"`
	MMRSize    uint64      `json:"mmr_size"`
	MMRRoot    string      `json:"mmr_root"`
	MerklePath []ProofStep `json:"merkle_path"`
	Peaks      []string    `json:"peaks"`
	PeakPos    int         `json:"peak_position"`

	// Signature
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`

	// Optional: external anchors
	Anchors []AnchorProof `json:"anchors,omitempty"`
}

// ProofStep represents a single step in the Merkle path.
type ProofStep struct {
	Hash   string `json:"hash"`
	IsLeft bool   `json:"is_left"`
}

// AnchorProof represents an external timestamp proof.
type AnchorProof struct {
	Type      string    `json:"type"` // "ots" or "rfc3161"
	Timestamp time.Time `json:"timestamp"`
	Proof     string    `json:"proof"` // hex-encoded proof data
}

// Verifier provides file verification against the MMR.
type Verifier struct {
	mmr        *mmr.MMR
	store      mmr.Store
	pubKey     ed25519.PublicKey
	sigEntries []SignatureEntry
}

// SignatureEntry represents a signed root commitment.
type SignatureEntry struct {
	Timestamp time.Time
	Root      [32]byte
	Signature []byte
	Size      uint64
}

// NewVerifier creates a new verifier.
func NewVerifier(dbPath, pubKeyPath, sigsPath string) (*Verifier, error) {
	store, err := mmr.OpenFileStore(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}

	m, err := mmr.New(store)
	if err != nil {
		store.Close()
		return nil, fmt.Errorf("init mmr: %w", err)
	}

	pubKey, err := signer.LoadPublicKey(pubKeyPath)
	if err != nil {
		store.Close()
		return nil, fmt.Errorf("load public key: %w", err)
	}

	v := &Verifier{
		mmr:    m,
		store:  store,
		pubKey: pubKey,
	}

	// Load signature entries if available
	if sigsPath != "" {
		if entries, err := loadSignatures(sigsPath); err == nil {
			v.sigEntries = entries
		}
	}

	return v, nil
}

// Close releases resources.
func (v *Verifier) Close() error {
	return v.store.Close()
}

// VerifyFile checks if a file exists in the MMR and produces a verification result.
func (v *Verifier) VerifyFile(path string) (*Result, error) {
	result := &Result{
		Path: path,
	}

	// Hash the current file
	hash, _, err := watcher.HashFile(path)
	if err != nil {
		result.Error = fmt.Sprintf("cannot read file: %v", err)
		return result, err
	}
	result.CurrentHash = hex.EncodeToString(hash[:])

	// Search for this hash in the MMR
	idx, found := v.findHash(hash)
	if !found {
		result.Error = "file hash not found in witness database"
		return result, ErrFileNotFound
	}

	result.MMRIndex = idx
	result.WitnessedHash = result.CurrentHash

	// Generate and verify proof
	proof, err := v.mmr.GenerateProof(idx)
	if err != nil {
		result.Error = fmt.Sprintf("proof generation failed: %v", err)
		return result, err
	}

	// The leaf data is the hash we stored
	leafData := mmr.HashLeaf(hash[:])
	if leafData != proof.LeafHash {
		result.Error = "leaf hash mismatch"
		return result, ErrProofInvalid
	}

	result.MMRRoot = hex.EncodeToString(proof.Root[:])
	result.Valid = true

	return result, nil
}

// findHash searches for a hash in the MMR leaves.
func (v *Verifier) findHash(hash [32]byte) (uint64, bool) {
	leafHash := mmr.HashLeaf(hash[:])

	size := v.mmr.Size()
	for i := uint64(0); i < size; i++ {
		node, err := v.mmr.Get(i)
		if err != nil {
			continue
		}
		if node.Height == 0 && node.Hash == leafHash {
			return i, true
		}
	}
	return 0, false
}

// ExportEvidence creates a self-contained evidence packet for a file.
func (v *Verifier) ExportEvidence(path string) (*EvidencePacket, error) {
	// Hash the file
	hash, size, err := watcher.HashFile(path)
	if err != nil {
		return nil, fmt.Errorf("hash file: %w", err)
	}

	// Find in MMR
	idx, found := v.findHash(hash)
	if !found {
		return nil, ErrFileNotFound
	}

	// Generate proof
	proof, err := v.mmr.GenerateProof(idx)
	if err != nil {
		return nil, fmt.Errorf("generate proof: %w", err)
	}

	// Convert proof path
	path_steps := make([]ProofStep, len(proof.MerklePath))
	for i, step := range proof.MerklePath {
		path_steps[i] = ProofStep{
			Hash:   hex.EncodeToString(step.Hash[:]),
			IsLeft: step.IsLeft,
		}
	}

	// Convert peaks
	peaks := make([]string, len(proof.Peaks))
	for i, peak := range proof.Peaks {
		peaks[i] = hex.EncodeToString(peak[:])
	}

	// Find matching signature
	var sigHex string
	root := proof.Root
	for _, entry := range v.sigEntries {
		if entry.Root == root {
			sigHex = hex.EncodeToString(entry.Signature)
			break
		}
	}

	packet := &EvidencePacket{
		Version:     1,
		GeneratedAt: time.Now().UTC(),
		FilePath:    path,
		FileHash:    hex.EncodeToString(hash[:]),
		FileSize:    size,
		MMRIndex:    idx,
		MMRSize:     v.mmr.Size(),
		MMRRoot:     hex.EncodeToString(root[:]),
		MerklePath:  path_steps,
		Peaks:       peaks,
		PeakPos:     proof.PeakPosition,
		PublicKey:   hex.EncodeToString(v.pubKey),
		Signature:   sigHex,
	}

	return packet, nil
}

// loadSignatures parses the signature log file.
func loadSignatures(path string) ([]SignatureEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var entries []SignatureEntry
	// Parse line by line: timestamp root signature size
	lines := splitLines(data)
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}

		var timestamp, rootHex, sigHex string
		var size uint64
		n, err := fmt.Sscanf(string(line), "%s %s %s %d", &timestamp, &rootHex, &sigHex, &size)
		if err != nil || n != 4 {
			continue
		}

		ts, err := time.Parse(time.RFC3339, timestamp)
		if err != nil {
			continue
		}

		rootBytes, err := hex.DecodeString(rootHex)
		if err != nil || len(rootBytes) != 32 {
			continue
		}

		sigBytes, err := hex.DecodeString(sigHex)
		if err != nil {
			continue
		}

		var root [32]byte
		copy(root[:], rootBytes)

		entries = append(entries, SignatureEntry{
			Timestamp: ts,
			Root:      root,
			Signature: sigBytes,
			Size:      size,
		})
	}

	return entries, nil
}

func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i := 0; i < len(data); i++ {
		if data[i] == '\n' {
			lines = append(lines, data[start:i])
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}

// SaveEvidence writes the evidence packet to a JSON file.
func SaveEvidence(packet *EvidencePacket, outputPath string) error {
	data, err := json.MarshalIndent(packet, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(outputPath, data, 0600)
}

// VerifyEvidence validates a standalone evidence packet.
func VerifyEvidence(packet *EvidencePacket, pubKey ed25519.PublicKey) error {
	// Verify signature if present
	if packet.Signature != "" {
		rootBytes, err := hex.DecodeString(packet.MMRRoot)
		if err != nil {
			return fmt.Errorf("invalid root hash: %w", err)
		}

		sigBytes, err := hex.DecodeString(packet.Signature)
		if err != nil {
			return fmt.Errorf("invalid signature: %w", err)
		}

		if !signer.VerifyCommitment(pubKey, rootBytes, sigBytes) {
			return ErrSignatureInvalid
		}
	}

	// Verify Merkle proof
	fileHashBytes, err := hex.DecodeString(packet.FileHash)
	if err != nil {
		return fmt.Errorf("invalid file hash: %w", err)
	}

	// Reconstruct the leaf hash
	var fileHash [32]byte
	copy(fileHash[:], fileHashBytes)
	leafHash := mmr.HashLeaf(fileHash[:])

	// Walk the Merkle path
	currentHash := leafHash
	for _, step := range packet.MerklePath {
		siblingBytes, err := hex.DecodeString(step.Hash)
		if err != nil {
			return fmt.Errorf("invalid sibling hash: %w", err)
		}
		var sibling [32]byte
		copy(sibling[:], siblingBytes)

		if step.IsLeft {
			currentHash = mmr.HashInternal(sibling, currentHash)
		} else {
			currentHash = mmr.HashInternal(currentHash, sibling)
		}
	}

	// Verify we reached the correct peak
	if packet.PeakPos >= len(packet.Peaks) {
		return ErrProofInvalid
	}

	peakBytes, err := hex.DecodeString(packet.Peaks[packet.PeakPos])
	if err != nil {
		return fmt.Errorf("invalid peak hash: %w", err)
	}
	var expectedPeak [32]byte
	copy(expectedPeak[:], peakBytes)

	if currentHash != expectedPeak {
		return ErrProofInvalid
	}

	// Bag peaks to get root
	if len(packet.Peaks) == 1 {
		rootBytes, _ := hex.DecodeString(packet.MMRRoot)
		var root [32]byte
		copy(root[:], rootBytes)
		if currentHash != root {
			return ErrProofInvalid
		}
		return nil
	}

	// Bag from right to left
	peaksHashes := make([][32]byte, len(packet.Peaks))
	for i, p := range packet.Peaks {
		pBytes, _ := hex.DecodeString(p)
		copy(peaksHashes[i][:], pBytes)
	}

	root := peaksHashes[len(peaksHashes)-1]
	for i := len(peaksHashes) - 2; i >= 0; i-- {
		root = mmr.HashInternal(peaksHashes[i], root)
	}

	rootBytes, _ := hex.DecodeString(packet.MMRRoot)
	var expectedRoot [32]byte
	copy(expectedRoot[:], rootBytes)

	if root != expectedRoot {
		return ErrProofInvalid
	}

	return nil
}
