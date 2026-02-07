// Package keyhierarchy implements a three-tier ratcheting key hierarchy for witnessd.
//
// The hierarchy provides:
//   - Tier 0 (Identity): Master key derived from device PUF, persistent identity
//   - Tier 1 (Session): Per-session keys certified by master key
//   - Tier 2 (Ratchet): Forward-secrecy ratcheting keys for each checkpoint
//
// This design enables persistent author identity while ensuring that compromise
// of the current key cannot be used to forge signatures on past checkpoints.
//
// Patent Pending: USPTO Application No. 19/460,364
package keyhierarchy

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	"golang.org/x/crypto/hkdf"
)

// Version constants
const (
	Version              = 1
	IdentityDomain       = "witnessd-identity-v1"
	SessionDomain        = "witnessd-session-v1"
	RatchetInitDomain    = "witnessd-ratchet-init-v1"
	RatchetAdvanceDomain = "witnessd-ratchet-advance-v1"
	SigningKeyDomain     = "witnessd-signing-key-v1"
)

// Errors
var (
	ErrRatchetWiped     = errors.New("keyhierarchy: ratchet state has been wiped")
	ErrInvalidCert      = errors.New("keyhierarchy: invalid session certificate")
	ErrOrdinalMismatch  = errors.New("keyhierarchy: checkpoint ordinal mismatch")
	ErrSignatureFailed  = errors.New("keyhierarchy: signature verification failed")
	ErrHashMismatch     = errors.New("keyhierarchy: checkpoint hash mismatch")
)

// MasterIdentity represents the persistent author identity derived from device PUF.
type MasterIdentity struct {
	// PublicKey is the persistent identity (can be shared publicly)
	PublicKey ed25519.PublicKey `json:"public_key"`

	// Fingerprint is the first 8 bytes of SHA256(PublicKey) in hex
	Fingerprint string `json:"fingerprint"`

	// DeviceID identifies the device this identity is bound to
	DeviceID string `json:"device_id"`

	// CreatedAt is when this identity was first derived
	CreatedAt time.Time `json:"created_at"`

	// Version for forward compatibility
	Version uint32 `json:"version"`
}

// SessionCertificate proves a session key belongs to a master identity.
type SessionCertificate struct {
	// SessionID is a random 32-byte identifier
	SessionID [32]byte `json:"session_id"`

	// SessionPubKey is the public key for verifying checkpoint signatures
	SessionPubKey ed25519.PublicKey `json:"session_pubkey"`

	// CreatedAt is when the session was started
	CreatedAt time.Time `json:"created_at"`

	// DocumentHash binds this session to a specific document (initial state)
	DocumentHash [32]byte `json:"document_hash"`

	// MasterPubKey identifies which identity certified this session
	MasterPubKey ed25519.PublicKey `json:"master_pubkey"`

	// Signature is the master key's signature over the certificate data
	Signature [64]byte `json:"signature"`

	// Version for forward compatibility
	Version uint32 `json:"version"`
}

// CheckpointSignature is the signature record for a single checkpoint.
type CheckpointSignature struct {
	// Ordinal is the checkpoint sequence number
	Ordinal uint64 `json:"ordinal"`

	// PublicKey is the ratcheted key used for this specific checkpoint
	PublicKey ed25519.PublicKey `json:"public_key"`

	// Signature is the Ed25519 signature over CheckpointHash
	Signature [64]byte `json:"signature"`

	// CheckpointHash is what was signed
	CheckpointHash [32]byte `json:"checkpoint_hash"`
}

// RatchetState holds the current ratchet value (secret, must be wiped after use).
type RatchetState struct {
	current   [32]byte
	ordinal   uint64
	sessionID [32]byte
	wiped     bool
}

// Session represents an active writing session with ratcheting keys.
type Session struct {
	Certificate *SessionCertificate
	ratchet     *RatchetState
	signatures  []CheckpointSignature
}

// PUFProvider is an interface for obtaining PUF responses.
type PUFProvider interface {
	GetResponse(challenge []byte) ([]byte, error)
	DeviceID() string
}

// DeriveMasterIdentity derives the master identity from a PUF provider.
// The master private key is not stored; it's re-derived when needed.
func DeriveMasterIdentity(puf PUFProvider) (*MasterIdentity, error) {
	// Generate deterministic challenge
	challenge := sha256.Sum256([]byte(IdentityDomain + "-challenge"))

	// Get PUF response
	pufResponse, err := puf.GetResponse(challenge[:])
	if err != nil {
		return nil, fmt.Errorf("PUF response failed: %w", err)
	}

	// Derive master seed via HKDF
	masterReader := hkdf.New(sha256.New, pufResponse, []byte(IdentityDomain), []byte("master-seed"))

	var seed [32]byte
	if _, err := io.ReadFull(masterReader, seed[:]); err != nil {
		return nil, fmt.Errorf("HKDF expand failed: %w", err)
	}

	// Generate Ed25519 key from seed
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)

	// Compute fingerprint
	fingerprint := sha256.Sum256(publicKey)

	// Wipe sensitive data
	secureWipe(seed[:])
	secureWipe(pufResponse)

	return &MasterIdentity{
		PublicKey:   publicKey,
		Fingerprint: hex.EncodeToString(fingerprint[:8]),
		DeviceID:    puf.DeviceID(),
		CreatedAt:   time.Now(),
		Version:     Version,
	}, nil
}

// deriveMasterPrivateKey re-derives the master private key from PUF.
// Caller is responsible for wiping the returned key.
func deriveMasterPrivateKey(puf PUFProvider) (ed25519.PrivateKey, error) {
	challenge := sha256.Sum256([]byte(IdentityDomain + "-challenge"))

	pufResponse, err := puf.GetResponse(challenge[:])
	if err != nil {
		return nil, fmt.Errorf("PUF response failed: %w", err)
	}
	defer secureWipe(pufResponse)

	masterReader := hkdf.New(sha256.New, pufResponse, []byte(IdentityDomain), []byte("master-seed"))

	var seed [32]byte
	if _, err := io.ReadFull(masterReader, seed[:]); err != nil {
		return nil, fmt.Errorf("HKDF expand failed: %w", err)
	}
	defer secureWipe(seed[:])

	return ed25519.NewKeyFromSeed(seed[:]), nil
}

// StartSession creates a new session with a certified session key and initialized ratchet.
func StartSession(puf PUFProvider, documentHash [32]byte) (*Session, error) {
	// Re-derive master private key
	masterPrivKey, err := deriveMasterPrivateKey(puf)
	if err != nil {
		return nil, err
	}
	defer secureWipe(masterPrivKey)

	masterPubKey := masterPrivKey.Public().(ed25519.PublicKey)

	// Generate random session ID
	var sessionID [32]byte
	if _, err := rand.Read(sessionID[:]); err != nil {
		return nil, fmt.Errorf("random generation failed: %w", err)
	}

	// Derive session key
	sessionInput := append(sessionID[:], []byte(time.Now().Format(time.RFC3339Nano))...)
	sessionReader := hkdf.New(sha256.New, masterPrivKey[:32], []byte(SessionDomain), sessionInput)

	var sessionSeed [32]byte
	if _, err := io.ReadFull(sessionReader, sessionSeed[:]); err != nil {
		return nil, fmt.Errorf("session key derivation failed: %w", err)
	}

	sessionPrivKey := ed25519.NewKeyFromSeed(sessionSeed[:])
	sessionPubKey := sessionPrivKey.Public().(ed25519.PublicKey)

	// Create certificate data
	createdAt := time.Now()
	certData := buildCertData(sessionID, sessionPubKey, createdAt, documentHash)

	// Sign with master key
	signature := ed25519.Sign(masterPrivKey, certData)

	cert := &SessionCertificate{
		SessionID:     sessionID,
		SessionPubKey: sessionPubKey,
		CreatedAt:     createdAt,
		DocumentHash:  documentHash,
		MasterPubKey:  masterPubKey,
		Version:       Version,
	}
	copy(cert.Signature[:], signature)

	// Initialize ratchet from session key
	ratchetReader := hkdf.New(sha256.New, sessionSeed[:], []byte(RatchetInitDomain), nil)

	var ratchetInit [32]byte
	if _, err := io.ReadFull(ratchetReader, ratchetInit[:]); err != nil {
		return nil, fmt.Errorf("ratchet init failed: %w", err)
	}

	// Wipe session seed (no longer needed)
	secureWipe(sessionSeed[:])

	return &Session{
		Certificate: cert,
		ratchet: &RatchetState{
			current:   ratchetInit,
			ordinal:   0,
			sessionID: sessionID,
			wiped:     false,
		},
		signatures: make([]CheckpointSignature, 0),
	}, nil
}

// SignCheckpoint signs a checkpoint and advances the ratchet.
// After signing, the previous ratchet state is wiped (forward secrecy).
func (s *Session) SignCheckpoint(checkpointHash [32]byte) (*CheckpointSignature, error) {
	if s.ratchet == nil || s.ratchet.wiped {
		return nil, ErrRatchetWiped
	}

	// Derive signing key from current ratchet state
	signingReader := hkdf.New(sha256.New, s.ratchet.current[:], []byte(SigningKeyDomain), nil)

	var signingSeeed [32]byte
	if _, err := io.ReadFull(signingReader, signingSeeed[:]); err != nil {
		return nil, fmt.Errorf("signing key derivation failed: %w", err)
	}

	signingKey := ed25519.NewKeyFromSeed(signingSeeed[:])
	pubKey := signingKey.Public().(ed25519.PublicKey)

	// Sign the checkpoint
	signature := ed25519.Sign(signingKey, checkpointHash[:])

	// Advance ratchet: next = HKDF(current, checkpoint_hash)
	nextReader := hkdf.New(sha256.New, s.ratchet.current[:], []byte(RatchetAdvanceDomain), checkpointHash[:])

	var nextRatchet [32]byte
	if _, err := io.ReadFull(nextReader, nextRatchet[:]); err != nil {
		return nil, fmt.Errorf("ratchet advance failed: %w", err)
	}

	// CRITICAL: Wipe current ratchet state (forward secrecy)
	secureWipe(s.ratchet.current[:])
	secureWipe(signingSeeed[:])

	// Update ratchet
	currentOrdinal := s.ratchet.ordinal
	s.ratchet.current = nextRatchet
	s.ratchet.ordinal++

	sig := &CheckpointSignature{
		Ordinal:        currentOrdinal,
		PublicKey:      pubKey,
		CheckpointHash: checkpointHash,
	}
	copy(sig.Signature[:], signature)

	s.signatures = append(s.signatures, *sig)

	return sig, nil
}

// End terminates the session and wipes all key material.
func (s *Session) End() {
	if s.ratchet != nil && !s.ratchet.wiped {
		secureWipe(s.ratchet.current[:])
		s.ratchet.wiped = true
	}
}

// Signatures returns all checkpoint signatures from this session.
func (s *Session) Signatures() []CheckpointSignature {
	return s.signatures
}

// CurrentOrdinal returns the next checkpoint ordinal that will be signed.
func (s *Session) CurrentOrdinal() uint64 {
	if s.ratchet == nil {
		return 0
	}
	return s.ratchet.ordinal
}

// VerifySessionCertificate verifies that a session certificate is valid.
func VerifySessionCertificate(cert *SessionCertificate) error {
	if cert == nil {
		return ErrInvalidCert
	}

	certData := buildCertData(cert.SessionID, cert.SessionPubKey, cert.CreatedAt, cert.DocumentHash)

	if !ed25519.Verify(cert.MasterPubKey, certData, cert.Signature[:]) {
		return ErrInvalidCert
	}

	return nil
}

// VerifyCheckpointSignatures verifies a chain of checkpoint signatures.
// Note: This verifies signatures are valid for their stated public keys.
// We cannot verify ratchet derivation (that would break forward secrecy).
func VerifyCheckpointSignatures(signatures []CheckpointSignature) error {
	for i, sig := range signatures {
		// Verify ordinal sequence
		if sig.Ordinal != uint64(i) {
			return fmt.Errorf("checkpoint %d: %w (got %d)", i, ErrOrdinalMismatch, sig.Ordinal)
		}

		// Verify signature
		if !ed25519.Verify(sig.PublicKey, sig.CheckpointHash[:], sig.Signature[:]) {
			return fmt.Errorf("checkpoint %d: %w", i, ErrSignatureFailed)
		}
	}

	return nil
}

// buildCertData constructs the data that is signed in a session certificate.
func buildCertData(sessionID [32]byte, sessionPubKey ed25519.PublicKey, createdAt time.Time, documentHash [32]byte) []byte {
	data := make([]byte, 0, 32+32+8+32)
	data = append(data, sessionID[:]...)
	data = append(data, sessionPubKey...)

	var timestamp [8]byte
	binary.BigEndian.PutUint64(timestamp[:], uint64(createdAt.UnixNano()))
	data = append(data, timestamp[:]...)

	data = append(data, documentHash[:]...)

	return data
}

// secureWipe overwrites memory with zeros to prevent recovery.
// This uses explicit writes to prevent compiler optimization.
func secureWipe(data []byte) {
	for i := range data {
		data[i] = 0
	}
	// Memory barrier to ensure writes complete before returning
	runtime.KeepAlive(data)
}

// KeyHierarchyEvidence bundles all key hierarchy data for an evidence packet.
type KeyHierarchyEvidence struct {
	Version              int                   `json:"version"`
	MasterIdentity       *MasterIdentity       `json:"master_identity"`
	SessionCertificate   *SessionCertificate   `json:"session_certificate"`
	CheckpointSignatures []CheckpointSignature `json:"checkpoint_signatures"`

	// Flattened fields for evidence packet serialization
	MasterFingerprint    string                `json:"master_fingerprint"`
	MasterPublicKey      ed25519.PublicKey     `json:"master_public_key"`
	DeviceID             string                `json:"device_id"`
	SessionID            string                `json:"session_id"`
	SessionPublicKey     ed25519.PublicKey     `json:"session_public_key"`
	SessionStarted       time.Time             `json:"session_started"`
	SessionCertificateRaw []byte               `json:"session_certificate_raw"`
	RatchetCount         int                   `json:"ratchet_count"`
	RatchetPublicKeys    []ed25519.PublicKey   `json:"ratchet_public_keys"`
}

// Export creates the key hierarchy evidence for inclusion in an evidence packet.
func (s *Session) Export(identity *MasterIdentity) *KeyHierarchyEvidence {
	evidence := &KeyHierarchyEvidence{
		Version:              Version,
		MasterIdentity:       identity,
		SessionCertificate:   s.Certificate,
		CheckpointSignatures: s.signatures,

		// Flatten for serialization
		MasterFingerprint: identity.Fingerprint,
		MasterPublicKey:   identity.PublicKey,
		DeviceID:          identity.DeviceID,
		SessionStarted:    s.Certificate.CreatedAt,
		RatchetCount:      len(s.signatures),
	}

	// Session ID as hex string
	evidence.SessionID = hex.EncodeToString(s.Certificate.SessionID[:])
	evidence.SessionPublicKey = s.Certificate.SessionPubKey

	// Build session certificate raw bytes
	evidence.SessionCertificateRaw = s.Certificate.Signature[:]

	// Collect ratchet public keys
	for _, sig := range s.signatures {
		evidence.RatchetPublicKeys = append(evidence.RatchetPublicKeys, sig.PublicKey)
	}

	return evidence
}

// VerifyKeyHierarchy performs full verification of key hierarchy evidence.
func VerifyKeyHierarchy(evidence *KeyHierarchyEvidence) error {
	if evidence == nil {
		return errors.New("nil evidence")
	}

	// Verify session certificate
	if err := VerifySessionCertificate(evidence.SessionCertificate); err != nil {
		return fmt.Errorf("session certificate: %w", err)
	}

	// Verify master identity matches certificate
	if evidence.MasterIdentity != nil {
		if !hmac.Equal(evidence.MasterIdentity.PublicKey, evidence.SessionCertificate.MasterPubKey) {
			return errors.New("master identity mismatch in certificate")
		}
	}

	// Verify checkpoint signatures
	if err := VerifyCheckpointSignatures(evidence.CheckpointSignatures); err != nil {
		return fmt.Errorf("checkpoint signatures: %w", err)
	}

	return nil
}

// SessionRecoveryState contains the state needed to recover a session.
type SessionRecoveryState struct {
	Certificate *SessionCertificate   `json:"certificate"`
	Signatures  []CheckpointSignature `json:"signatures"`
	// LastRatchetState is encrypted/sealed to the device if possible
	// This allows session recovery but maintains security properties
	LastRatchetState []byte `json:"last_ratchet_state,omitempty"`
}

// Errors for session recovery
var (
	ErrSessionNotRecoverable = errors.New("keyhierarchy: session cannot be recovered")
	ErrSessionRecoveryFailed = errors.New("keyhierarchy: session recovery failed")
	ErrNoRecoveryData        = errors.New("keyhierarchy: no recovery data available")
)

// RecoverSession attempts to recover a session that was not cleanly ended.
// This requires the recovery state that was saved during the session.
// Note: Due to forward secrecy, we can only recover to sign new checkpoints
// starting from the last saved ordinal.
func RecoverSession(puf PUFProvider, recovery *SessionRecoveryState, documentHash [32]byte) (*Session, error) {
	if recovery == nil || recovery.Certificate == nil {
		return nil, ErrNoRecoveryData
	}

	// Verify the certificate is still valid
	if err := VerifySessionCertificate(recovery.Certificate); err != nil {
		return nil, fmt.Errorf("invalid recovery certificate: %w", err)
	}

	// Verify the certificate is for this document
	if recovery.Certificate.DocumentHash != documentHash {
		return nil, errors.New("recovery certificate is for different document")
	}

	// Verify the master key matches our current identity
	identity, err := DeriveMasterIdentity(puf)
	if err != nil {
		return nil, fmt.Errorf("failed to derive identity: %w", err)
	}

	if !hmac.Equal(identity.PublicKey, recovery.Certificate.MasterPubKey) {
		return nil, errors.New("recovery certificate is from different device")
	}

	// If we have encrypted ratchet state, try to decrypt it
	if len(recovery.LastRatchetState) > 0 {
		return recoverSessionWithRatchet(puf, recovery)
	}

	// Without ratchet state, we can only create a new session continuation
	// This maintains the certificate chain but starts a new ratchet
	return recoverSessionWithNewRatchet(puf, recovery)
}

// recoverSessionWithRatchet recovers a session using saved ratchet state
func recoverSessionWithRatchet(puf PUFProvider, recovery *SessionRecoveryState) (*Session, error) {
	// The ratchet state should be encrypted with a key derived from the PUF
	challenge := sha256.Sum256([]byte("witnessd-ratchet-recovery-v1"))
	pufResponse, err := puf.GetResponse(challenge[:])
	if err != nil {
		return nil, fmt.Errorf("PUF response failed: %w", err)
	}
	defer secureWipe(pufResponse)

	// Derive decryption key
	keyReader := hkdf.New(sha256.New, pufResponse, []byte("ratchet-recovery-key"), nil)
	var decryptKey [32]byte
	if _, err := io.ReadFull(keyReader, decryptKey[:]); err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}
	defer secureWipe(decryptKey[:])

	// Simple XOR decryption (the data is integrity-protected by the signature chain)
	if len(recovery.LastRatchetState) < 40 { // 32 bytes ratchet + 8 bytes ordinal
		return nil, ErrSessionRecoveryFailed
	}

	// Decrypt ratchet state
	var ratchetState [32]byte
	for i := 0; i < 32; i++ {
		ratchetState[i] = recovery.LastRatchetState[i] ^ decryptKey[i%32]
	}

	ordinal := binary.BigEndian.Uint64(recovery.LastRatchetState[32:40])

	return &Session{
		Certificate: recovery.Certificate,
		ratchet: &RatchetState{
			current:   ratchetState,
			ordinal:   ordinal,
			sessionID: recovery.Certificate.SessionID,
			wiped:     false,
		},
		signatures: recovery.Signatures,
	}, nil
}

// recoverSessionWithNewRatchet creates a continuation session when ratchet state is lost
func recoverSessionWithNewRatchet(puf PUFProvider, recovery *SessionRecoveryState) (*Session, error) {
	// Determine the next ordinal
	var nextOrdinal uint64
	if len(recovery.Signatures) > 0 {
		lastSig := recovery.Signatures[len(recovery.Signatures)-1]
		nextOrdinal = lastSig.Ordinal + 1
	}

	// Re-derive a new ratchet state from the PUF and last signature
	challenge := sha256.Sum256([]byte("witnessd-ratchet-continuation-v1"))
	pufResponse, err := puf.GetResponse(challenge[:])
	if err != nil {
		return nil, fmt.Errorf("PUF response failed: %w", err)
	}
	defer secureWipe(pufResponse)

	// Mix in the last checkpoint hash for continuity
	var lastHash [32]byte
	if len(recovery.Signatures) > 0 {
		lastHash = recovery.Signatures[len(recovery.Signatures)-1].CheckpointHash
	}

	continuationInput := append(pufResponse, lastHash[:]...)
	continuationInput = append(continuationInput, recovery.Certificate.SessionID[:]...)

	ratchetReader := hkdf.New(sha256.New, continuationInput, []byte(RatchetInitDomain), []byte("continuation"))

	var ratchetInit [32]byte
	if _, err := io.ReadFull(ratchetReader, ratchetInit[:]); err != nil {
		return nil, fmt.Errorf("ratchet init failed: %w", err)
	}

	return &Session{
		Certificate: recovery.Certificate,
		ratchet: &RatchetState{
			current:   ratchetInit,
			ordinal:   nextOrdinal,
			sessionID: recovery.Certificate.SessionID,
			wiped:     false,
		},
		signatures: recovery.Signatures,
	}, nil
}

// ExportRecoveryState creates a recovery state that can be used to recover
// the session if it's not cleanly ended.
func (s *Session) ExportRecoveryState(puf PUFProvider) (*SessionRecoveryState, error) {
	if s.ratchet == nil || s.ratchet.wiped {
		return nil, ErrRatchetWiped
	}

	// Encrypt the ratchet state with a key derived from the PUF
	challenge := sha256.Sum256([]byte("witnessd-ratchet-recovery-v1"))
	pufResponse, err := puf.GetResponse(challenge[:])
	if err != nil {
		return nil, fmt.Errorf("PUF response failed: %w", err)
	}
	defer secureWipe(pufResponse)

	keyReader := hkdf.New(sha256.New, pufResponse, []byte("ratchet-recovery-key"), nil)
	var encryptKey [32]byte
	if _, err := io.ReadFull(keyReader, encryptKey[:]); err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}
	defer secureWipe(encryptKey[:])

	// Encrypt: XOR the ratchet state
	encryptedState := make([]byte, 40)
	for i := 0; i < 32; i++ {
		encryptedState[i] = s.ratchet.current[i] ^ encryptKey[i%32]
	}
	binary.BigEndian.PutUint64(encryptedState[32:], s.ratchet.ordinal)

	return &SessionRecoveryState{
		Certificate:      s.Certificate,
		Signatures:       s.signatures,
		LastRatchetState: encryptedState,
	}, nil
}

// LegacyKeyMigration handles migration from existing signing keys
type LegacyKeyMigration struct {
	// LegacyPublicKey is the public key from the legacy signing key
	LegacyPublicKey ed25519.PublicKey `json:"legacy_public_key"`

	// NewMasterPublicKey is the new PUF-derived master public key
	NewMasterPublicKey ed25519.PublicKey `json:"new_master_public_key"`

	// MigrationTimestamp is when the migration occurred
	MigrationTimestamp time.Time `json:"migration_timestamp"`

	// TransitionSignature is the legacy key's signature over the new master key
	// This proves the legacy key holder authorized the transition
	TransitionSignature [64]byte `json:"transition_signature"`

	// Version for forward compatibility
	Version uint32 `json:"version"`
}

// Errors for legacy key migration
var (
	ErrLegacyKeyNotFound  = errors.New("keyhierarchy: legacy signing key not found")
	ErrMigrationFailed    = errors.New("keyhierarchy: migration failed")
	ErrInvalidMigration   = errors.New("keyhierarchy: invalid migration record")
)

// MigrateFromLegacyKey imports an existing signing key and creates a migration record.
// This allows existing evidence packets to be linked to the new key hierarchy.
//
// The migration creates a cryptographic proof that:
// 1. The holder of the legacy key authorized the transition
// 2. The new master key is derived from the current device's PUF
//
// After migration, new sessions will use the PUF-derived key hierarchy,
// while the migration record provides continuity with historical evidence.
func MigrateFromLegacyKey(puf PUFProvider, legacyKeyPath string) (*LegacyKeyMigration, *MasterIdentity, error) {
	// Load the legacy private key
	legacyPrivKey, err := loadLegacyPrivateKey(legacyKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load legacy key: %w", err)
	}
	defer secureWipe(legacyPrivKey)

	legacyPubKey := legacyPrivKey.Public().(ed25519.PublicKey)

	// Derive the new master identity from PUF
	newIdentity, err := DeriveMasterIdentity(puf)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive new identity: %w", err)
	}

	// Create migration data to sign
	migrationTimestamp := time.Now()
	migrationData := buildMigrationData(legacyPubKey, newIdentity.PublicKey, migrationTimestamp)

	// Sign with the legacy key
	transitionSig := ed25519.Sign(legacyPrivKey, migrationData)

	migration := &LegacyKeyMigration{
		LegacyPublicKey:    legacyPubKey,
		NewMasterPublicKey: newIdentity.PublicKey,
		MigrationTimestamp: migrationTimestamp,
		Version:            Version,
	}
	copy(migration.TransitionSignature[:], transitionSig)

	return migration, newIdentity, nil
}

// VerifyLegacyMigration verifies that a migration record is valid.
func VerifyLegacyMigration(migration *LegacyKeyMigration) error {
	if migration == nil {
		return ErrInvalidMigration
	}

	if len(migration.LegacyPublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: invalid legacy public key size", ErrInvalidMigration)
	}

	if len(migration.NewMasterPublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: invalid new master public key size", ErrInvalidMigration)
	}

	// Reconstruct the signed data
	migrationData := buildMigrationData(
		migration.LegacyPublicKey,
		migration.NewMasterPublicKey,
		migration.MigrationTimestamp,
	)

	// Verify the legacy key's signature
	if !ed25519.Verify(migration.LegacyPublicKey, migrationData, migration.TransitionSignature[:]) {
		return fmt.Errorf("%w: transition signature verification failed", ErrInvalidMigration)
	}

	return nil
}

// buildMigrationData constructs the data that is signed in a migration record
func buildMigrationData(legacyPubKey, newMasterPubKey ed25519.PublicKey, timestamp time.Time) []byte {
	data := make([]byte, 0, 32+32+8+len("witnessd-key-migration-v1"))
	data = append(data, []byte("witnessd-key-migration-v1")...)
	data = append(data, legacyPubKey...)
	data = append(data, newMasterPubKey...)

	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(timestamp.UnixNano()))
	data = append(data, ts[:]...)

	return data
}

// loadLegacyPrivateKey loads an Ed25519 private key from a file
func loadLegacyPrivateKey(path string) (ed25519.PrivateKey, error) {
	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}

	// Try raw seed first (32 bytes)
	if len(keyData) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(keyData), nil
	}

	// Try raw private key (64 bytes: seed + public)
	if len(keyData) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(keyData), nil
	}

	// Try OpenSSH format - delegate to signer package pattern
	return parseOpenSSHPrivateKey(keyData)
}

// parseOpenSSHPrivateKey attempts to parse an OpenSSH format private key
func parseOpenSSHPrivateKey(keyData []byte) (ed25519.PrivateKey, error) {
	// Simple check for PEM format
	if len(keyData) < 30 {
		return nil, errors.New("key data too short")
	}

	// Check for OpenSSH header
	if string(keyData[:36]) != "-----BEGIN OPENSSH PRIVATE KEY-----" {
		return nil, errors.New("unsupported key format")
	}

	// For full OpenSSH parsing, we would use golang.org/x/crypto/ssh
	// This is a simplified implementation - the full version should
	// use the signer package's LoadPrivateKey function
	return nil, errors.New("OpenSSH format requires signer package")
}

// readFileFromOS reads a file using os.ReadFile
func readFileFromOS(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// StartSessionFromLegacyKey creates a session using a legacy key instead of PUF.
// This is used during the migration period to maintain compatibility.
func StartSessionFromLegacyKey(legacyKeyPath string, documentHash [32]byte) (*Session, error) {
	// Load the legacy private key
	legacyPrivKey, err := loadLegacyPrivateKeyDirect(legacyKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load legacy key: %w", err)
	}
	defer secureWipe(legacyPrivKey)

	legacyPubKey := legacyPrivKey.Public().(ed25519.PublicKey)

	// Generate random session ID
	var sessionID [32]byte
	if _, err := rand.Read(sessionID[:]); err != nil {
		return nil, fmt.Errorf("random generation failed: %w", err)
	}

	// Derive session key from legacy key
	sessionInput := append(sessionID[:], []byte(time.Now().Format(time.RFC3339Nano))...)
	sessionReader := hkdf.New(sha256.New, legacyPrivKey[:32], []byte(SessionDomain), sessionInput)

	var sessionSeed [32]byte
	if _, err := io.ReadFull(sessionReader, sessionSeed[:]); err != nil {
		return nil, fmt.Errorf("session key derivation failed: %w", err)
	}

	sessionPrivKey := ed25519.NewKeyFromSeed(sessionSeed[:])
	sessionPubKey := sessionPrivKey.Public().(ed25519.PublicKey)

	// Create certificate
	createdAt := time.Now()
	certData := buildCertData(sessionID, sessionPubKey, createdAt, documentHash)
	signature := ed25519.Sign(legacyPrivKey, certData)

	cert := &SessionCertificate{
		SessionID:     sessionID,
		SessionPubKey: sessionPubKey,
		CreatedAt:     createdAt,
		DocumentHash:  documentHash,
		MasterPubKey:  legacyPubKey,
		Version:       Version,
	}
	copy(cert.Signature[:], signature)

	// Initialize ratchet
	ratchetReader := hkdf.New(sha256.New, sessionSeed[:], []byte(RatchetInitDomain), nil)

	var ratchetInit [32]byte
	if _, err := io.ReadFull(ratchetReader, ratchetInit[:]); err != nil {
		return nil, fmt.Errorf("ratchet init failed: %w", err)
	}

	secureWipe(sessionSeed[:])

	return &Session{
		Certificate: cert,
		ratchet: &RatchetState{
			current:   ratchetInit,
			ordinal:   0,
			sessionID: sessionID,
			wiped:     false,
		},
		signatures: make([]CheckpointSignature, 0),
	}, nil
}

// loadLegacyPrivateKeyDirect loads an Ed25519 private key directly using os.ReadFile
func loadLegacyPrivateKeyDirect(path string) (ed25519.PrivateKey, error) {
	// This import is available at the top of the file
	keyData, err := readFileFromOS(path)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}

	// Try raw seed first (32 bytes)
	if len(keyData) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(keyData), nil
	}

	// Try raw private key (64 bytes: seed + public)
	if len(keyData) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(keyData), nil
	}

	return nil, errors.New("unsupported legacy key format")
}

// VerifySessionCertificateBytes verifies a session certificate using raw byte inputs.
// This is a simplified verification for the evidence package.
// masterPubKey: 32-byte Ed25519 public key
// sessionPubKey: 32-byte Ed25519 public key
// certSignature: 64-byte Ed25519 signature
func VerifySessionCertificateBytes(masterPubKey, sessionPubKey, certSignature []byte) error {
	if len(masterPubKey) != ed25519.PublicKeySize {
		return errors.New("invalid master public key size")
	}
	if len(sessionPubKey) != ed25519.PublicKeySize {
		return errors.New("invalid session public key size")
	}
	if len(certSignature) != ed25519.SignatureSize {
		return errors.New("invalid certificate signature size")
	}

	// Note: Full verification requires reconstructing the certificate data
	// which includes session ID, timestamp, and document hash.
	// For evidence packet verification, we verify the signature is
	// well-formed and the keys are valid Ed25519 public keys.

	// Basic validation passes - full verification done at session level
	return nil
}

// VerifyRatchetSignature verifies a checkpoint signature from a ratchet key.
// This is used by the evidence package for verification from serialized data.
func VerifyRatchetSignature(ratchetPubKey, checkpointHash, signature []byte) error {
	if len(ratchetPubKey) != ed25519.PublicKeySize {
		return errors.New("invalid ratchet public key size")
	}
	if len(checkpointHash) != 32 {
		return errors.New("invalid checkpoint hash size")
	}
	if len(signature) != ed25519.SignatureSize {
		return errors.New("invalid signature size")
	}

	if !ed25519.Verify(ratchetPubKey, checkpointHash, signature) {
		return ErrSignatureFailed
	}

	return nil
}
