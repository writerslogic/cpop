// Package keyhierarchy provides integration with checkpoint and evidence packages.
//
// Patent Pending: USPTO Application No. 19/460,364
package keyhierarchy

import (
	"crypto/sha256"
	"fmt"
	"os"
	"time"

	"witnessd/internal/checkpoint"
)

// SessionManager manages the key hierarchy for a writing session.
type SessionManager struct {
	session     *Session
	identity    *MasterIdentity
	puf         PUFProvider
	documentPath string
}

// NewSessionManager creates a session manager for a document.
func NewSessionManager(puf PUFProvider, documentPath string) (*SessionManager, error) {
	// Get or derive master identity
	identity, err := DeriveMasterIdentity(puf)
	if err != nil {
		return nil, fmt.Errorf("derive identity: %w", err)
	}

	// Hash the initial document state
	content, err := os.ReadFile(documentPath)
	if err != nil {
		return nil, fmt.Errorf("read document: %w", err)
	}
	docHash := sha256.Sum256(content)

	// Start a new session
	session, err := StartSession(puf, docHash)
	if err != nil {
		return nil, fmt.Errorf("start session: %w", err)
	}

	return &SessionManager{
		session:      session,
		identity:     identity,
		puf:          puf,
		documentPath: documentPath,
	}, nil
}

// SignCheckpoint signs a checkpoint and advances the ratchet.
func (sm *SessionManager) SignCheckpoint(cp *checkpoint.Checkpoint) error {
	sig, err := sm.session.SignCheckpoint(cp.Hash)
	if err != nil {
		return err
	}

	// Store signature directly in checkpoint
	cp.Signature = sig.Signature[:]
	return nil
}

// End terminates the session and wipes key material.
func (sm *SessionManager) End() {
	if sm.session != nil {
		sm.session.End()
	}
}

// Identity returns the master identity.
func (sm *SessionManager) Identity() *MasterIdentity {
	return sm.identity
}

// Session returns the current session (for certificate access).
func (sm *SessionManager) Session() *Session {
	return sm.session
}

// ExportEvidence creates the key hierarchy evidence for an evidence packet.
func (sm *SessionManager) ExportEvidence() *KeyHierarchyEvidence {
	return sm.session.Export(sm.identity)
}

// ChainSigner wraps a checkpoint.Chain to add signing capabilities.
type ChainSigner struct {
	chain   *checkpoint.Chain
	manager *SessionManager
}

// NewChainSigner creates a signer for a checkpoint chain.
func NewChainSigner(chain *checkpoint.Chain, puf PUFProvider) (*ChainSigner, error) {
	manager, err := NewSessionManager(puf, chain.DocumentPath)
	if err != nil {
		return nil, err
	}

	return &ChainSigner{
		chain:   chain,
		manager: manager,
	}, nil
}

// CommitAndSign creates a new checkpoint and signs it.
func (cs *ChainSigner) CommitAndSign(message string) (*checkpoint.Checkpoint, error) {
	// Create the checkpoint
	cp, err := cs.chain.Commit(message)
	if err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}

	// Sign it
	if err := cs.manager.SignCheckpoint(cp); err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	return cp, nil
}

// CommitAndSignWithDuration creates a checkpoint with specific VDF duration and signs it.
func (cs *ChainSigner) CommitAndSignWithDuration(message string, vdfDuration time.Duration) (*checkpoint.Checkpoint, error) {
	cp, err := cs.chain.CommitWithVDFDuration(message, vdfDuration)
	if err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}

	// Sign it
	if err := cs.manager.SignCheckpoint(cp); err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	return cp, nil
}

// End terminates the signing session.
func (cs *ChainSigner) End() {
	cs.manager.End()
}

// Chain returns the underlying checkpoint chain.
func (cs *ChainSigner) Chain() *checkpoint.Chain {
	return cs.chain
}

// SignedCheckpoints returns all checkpoints in the chain.
func (cs *ChainSigner) SignedCheckpoints() []*checkpoint.Checkpoint {
	return cs.chain.Checkpoints
}

// KeyHierarchyEvidence returns the key hierarchy evidence for export.
func (cs *ChainSigner) KeyHierarchyEvidence() *KeyHierarchyEvidence {
	return cs.manager.ExportEvidence()
}

// Identity returns the master identity.
func (cs *ChainSigner) Identity() *MasterIdentity {
	return cs.manager.Identity()
}

// LoadOrCreateSoftwarePUF loads or creates a software PUF seed.
// This is a convenience function that wraps NewSoftwarePUFWithPath.
func LoadOrCreateSoftwarePUF(seedPath string) (*SoftwarePUF, error) {
	return NewSoftwarePUFWithPath(seedPath)
}
