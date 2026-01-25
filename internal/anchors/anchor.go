// Package anchors provides external timestamping services for MMR roots.
package anchors

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Anchor defines the interface for external timestamping services.
type Anchor interface {
	// Name returns the anchor type name (e.g., "ots", "rfc3161").
	Name() string

	// Commit submits a hash for timestamping and returns the proof.
	Commit(hash []byte) ([]byte, error)

	// Verify checks a timestamp proof against the original hash.
	Verify(hash, proof []byte) error
}

// Receipt represents a stored timestamp proof.
type Receipt struct {
	Type      string    `json:"type"`
	Hash      string    `json:"hash"`
	Proof     []byte    `json:"proof"`
	Timestamp time.Time `json:"timestamp"`
	Status    string    `json:"status"` // "pending", "confirmed", "failed"
}

// Registry manages multiple anchor backends.
type Registry struct {
	anchors     map[string]Anchor
	storagePath string
}

// NewRegistry creates a new anchor registry.
func NewRegistry(storagePath string) *Registry {
	return &Registry{
		anchors:     make(map[string]Anchor),
		storagePath: storagePath,
	}
}

// Register adds an anchor backend to the registry.
func (r *Registry) Register(anchor Anchor) {
	r.anchors[anchor.Name()] = anchor
}

// Get returns an anchor by name.
func (r *Registry) Get(name string) (Anchor, bool) {
	a, ok := r.anchors[name]
	return a, ok
}

// List returns all registered anchor names.
func (r *Registry) List() []string {
	names := make([]string, 0, len(r.anchors))
	for name := range r.anchors {
		names = append(names, name)
	}
	return names
}

// CommitAll submits a hash to all registered anchors.
func (r *Registry) CommitAll(hash []byte) ([]Receipt, error) {
	var receipts []Receipt

	for name, anchor := range r.anchors {
		proof, err := anchor.Commit(hash)
		status := "pending"
		if err != nil {
			status = "failed"
		}

		receipt := Receipt{
			Type:      name,
			Hash:      hex.EncodeToString(hash),
			Proof:     proof,
			Timestamp: time.Now().UTC(),
			Status:    status,
		}
		receipts = append(receipts, receipt)

		// Save receipt to disk
		if err := r.saveReceipt(receipt); err != nil {
			// Log but don't fail
			fmt.Fprintf(os.Stderr, "Warning: failed to save %s receipt: %v\n", name, err)
		}
	}

	return receipts, nil
}

// saveReceipt stores a receipt to disk.
func (r *Registry) saveReceipt(receipt Receipt) error {
	if r.storagePath == "" {
		return nil
	}

	// Create directory if needed
	if err := os.MkdirAll(r.storagePath, 0700); err != nil {
		return err
	}

	// Generate filename based on hash and type
	filename := fmt.Sprintf("%s_%s.%s",
		receipt.Timestamp.Format("20060102_150405"),
		receipt.Hash[:16],
		receipt.Type)

	path := filepath.Join(r.storagePath, filename)
	return os.WriteFile(path, receipt.Proof, 0600)
}

// LoadReceipts loads all receipts from storage.
func (r *Registry) LoadReceipts() ([]Receipt, error) {
	if r.storagePath == "" {
		return nil, nil
	}

	entries, err := os.ReadDir(r.storagePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var receipts []Receipt
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		path := filepath.Join(r.storagePath, entry.Name())
		proof, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		// Parse filename: timestamp_hash.type
		name := entry.Name()
		ext := filepath.Ext(name)
		if ext == "" {
			continue
		}

		receipt := Receipt{
			Type:   ext[1:], // Remove leading dot
			Proof:  proof,
			Status: "unknown",
		}
		receipts = append(receipts, receipt)
	}

	return receipts, nil
}
