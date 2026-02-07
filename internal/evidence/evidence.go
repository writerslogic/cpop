// Package evidence implements the unified Evidence Packet format.
//
// An Evidence Packet is a self-contained proof of documented authorship.
// It combines cryptographic proofs, declarations, and optional attestations
// into a single exportable format.
//
// Evidence Strength Tiers:
// - Basic: Commits + Declaration (minimum viable evidence)
// - Standard: + Presence Verification
// - Enhanced: + Hardware Attestation (TPM)
// - Maximum: + Behavioral Data + External Anchors
package evidence

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"witnessd/internal/checkpoint"
	"witnessd/internal/declaration"
	"witnessd/internal/jitter"
	"witnessd/internal/keyhierarchy"
	"witnessd/internal/presence"
	"witnessd/internal/tpm"
	"witnessd/internal/vdf"
	"witnessd/pkg/anchors"
)

// Strength indicates the evidence tier.
type Strength int

const (
	Basic    Strength = 1 // Commits + declaration only
	Standard Strength = 2 // + presence verification
	Enhanced Strength = 3 // + hardware attestation
	Maximum  Strength = 4 // + behavioral + external anchors
)

func (s Strength) String() string {
	switch s {
	case Basic:
		return "basic"
	case Standard:
		return "standard"
	case Enhanced:
		return "enhanced"
	case Maximum:
		return "maximum"
	default:
		return "unknown"
	}
}

// Packet is a self-contained evidence export.
type Packet struct {
	// Metadata
	Version   int       `json:"version"`
	ExportedAt time.Time `json:"exported_at"`
	Strength  Strength  `json:"strength"`

	// Record Provenance (who, where, when)
	Provenance *RecordProvenance `json:"provenance,omitempty"`

	// The document
	Document DocumentInfo `json:"document"`

	// Layer 0: Checkpoint chain
	Checkpoints []CheckpointProof `json:"checkpoints"`
	VDFParams   vdf.Parameters    `json:"vdf_params"`
	ChainHash   string            `json:"chain_hash"`

	// Layer 1: Process Declaration (required)
	Declaration *declaration.Declaration `json:"declaration"`

	// Layer 2: Presence Verification (Standard+)
	Presence *presence.Evidence `json:"presence,omitempty"`

	// Layer 3: Hardware Attestation (Enhanced+)
	Hardware *HardwareEvidence `json:"hardware,omitempty"`

	// Layer 4a: Keystroke Evidence (Standard+)
	// Proves real keystrokes occurred without capturing content
	Keystroke *KeystrokeEvidence `json:"keystroke,omitempty"`

	// Layer 4b: Behavioral Data (Maximum only)
	Behavioral *BehavioralEvidence `json:"behavioral,omitempty"`

	// Layer 4c: Context Periods (runtime-tracked editing contexts)
	Contexts []ContextPeriod `json:"contexts,omitempty"`

	// Layer 5: External Anchors (Maximum only)
	External *ExternalAnchors `json:"external,omitempty"`

	// Layer 6: Key Hierarchy (cryptographic identity chain)
	// Patent Pending: USPTO Application No. 19/460,364
	KeyHierarchy *KeyHierarchyEvidencePacket `json:"key_hierarchy,omitempty"`

	// What this evidence claims
	Claims     []Claim  `json:"claims"`
	Limitations []string `json:"limitations"`
}

// KeyHierarchyEvidencePacket contains the key hierarchy evidence for an evidence packet.
// This provides persistent identity and forward secrecy through ratcheting keys.
//
// Patent Pending: USPTO Application No. 19/460,364
type KeyHierarchyEvidencePacket struct {
	// Version of the key hierarchy protocol
	Version int `json:"version"`

	// Master identity information (public)
	MasterFingerprint string `json:"master_fingerprint"`
	MasterPublicKey   string `json:"master_public_key"`
	DeviceID          string `json:"device_id"`

	// Session information
	SessionID      string    `json:"session_id"`
	SessionPublicKey string  `json:"session_public_key"`
	SessionStarted time.Time `json:"session_started"`

	// Session certificate (signed by master key)
	SessionCertificate string `json:"session_certificate"`

	// Ratchet chain evidence
	RatchetCount     int      `json:"ratchet_count"`
	RatchetPublicKeys []string `json:"ratchet_public_keys,omitempty"`

	// Checkpoint signatures (signed by ratchet keys)
	CheckpointSignatures []CheckpointSignature `json:"checkpoint_signatures,omitempty"`
}

// CheckpointSignature links a checkpoint to a ratcheting key.
type CheckpointSignature struct {
	Ordinal       uint64 `json:"ordinal"`
	CheckpointHash string `json:"checkpoint_hash"`
	RatchetIndex  int    `json:"ratchet_index"`
	Signature     string `json:"signature"`
}

// ContextPeriod represents a period of editing with declared context.
type ContextPeriod struct {
	Type      string    `json:"type"`       // "external", "assisted", "review"
	Note      string    `json:"note,omitempty"`
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
}

// DocumentInfo describes the witnessed document.
type DocumentInfo struct {
	Title       string `json:"title"`
	Path        string `json:"path"`
	FinalHash   string `json:"final_hash"`
	FinalSize   int64  `json:"final_size"`
}

// RecordProvenance documents who initiated the record and where it was generated.
type RecordProvenance struct {
	// Record initiator
	DeviceID       string `json:"device_id"`
	SigningPubkey  string `json:"signing_pubkey"`
	KeySource      string `json:"key_source"` // "file", "tpm", "secure_enclave"

	// System identification
	Hostname       string `json:"hostname"`
	OS             string `json:"os"`
	OSVersion      string `json:"os_version,omitempty"`
	Architecture   string `json:"architecture"`

	// Session identification
	SessionID      string    `json:"session_id"`
	SessionStarted time.Time `json:"session_started"`

	// Input device tracking (optional)
	InputDevices   []InputDeviceInfo `json:"input_devices,omitempty"`

	// Access control snapshot
	AccessControl  *AccessControlInfo `json:"access_control,omitempty"`
}

// InputDeviceInfo describes a keyboard or input device.
type InputDeviceInfo struct {
	VendorID       uint16 `json:"vendor_id"`
	ProductID      uint16 `json:"product_id"`
	ProductName    string `json:"product_name"`
	SerialNumber   string `json:"serial_number,omitempty"`
	ConnectionType string `json:"connection_type"` // "USB", "Bluetooth", "Internal", "Virtual"
	Fingerprint    string `json:"fingerprint"`
}

// AccessControlInfo documents who had/didn't have write access.
type AccessControlInfo struct {
	CapturedAt      time.Time `json:"captured_at"`
	FileOwnerUID    int       `json:"file_owner_uid"`
	FileOwnerName   string    `json:"file_owner_name,omitempty"`
	FilePermissions string    `json:"file_permissions"` // e.g., "0644"
	FileGroupGID    int       `json:"file_group_gid,omitempty"`
	FileGroupName   string    `json:"file_group_name,omitempty"`
	ProcessUID      int       `json:"process_uid"`
	ProcessEUID     int       `json:"process_euid"`
	ProcessUsername string    `json:"process_username,omitempty"`

	// Explicit limitations
	Limitations     []string `json:"limitations"`
}

// CheckpointProof is a checkpoint with verification data.
type CheckpointProof struct {
	Ordinal      uint64 `json:"ordinal"`
	ContentHash  string `json:"content_hash"`
	ContentSize  int64  `json:"content_size"`
	Timestamp    time.Time `json:"timestamp"`
	Message      string `json:"message,omitempty"`

	// VDF proof
	VDFInput      string `json:"vdf_input,omitempty"`
	VDFOutput     string `json:"vdf_output,omitempty"`
	VDFIterations uint64 `json:"vdf_iterations,omitempty"`
	ElapsedTime   time.Duration `json:"elapsed_time,omitempty"`

	// Chain linkage
	PreviousHash string `json:"previous_hash"`
	Hash         string `json:"hash"`

	// Key Hierarchy signature (optional)
	Signature string `json:"signature,omitempty"`
}

// HardwareEvidence contains TPM attestations.
type HardwareEvidence struct {
	Bindings []tpm.Binding `json:"bindings"`
	DeviceID string        `json:"device_id"`
}

// KeystrokeEvidence contains jitter-based keystroke evidence.
// This proves real keystrokes occurred without capturing content.
type KeystrokeEvidence struct {
	// Session metadata
	SessionID    string        `json:"session_id"`
	StartedAt    time.Time     `json:"started_at"`
	EndedAt      time.Time     `json:"ended_at"`
	Duration     time.Duration `json:"duration"`

	// Statistics
	TotalKeystrokes  uint64  `json:"total_keystrokes"`
	TotalSamples     int     `json:"total_samples"`
	KeystrokesPerMin float64 `json:"keystrokes_per_minute"`
	UniqueDocStates  int     `json:"unique_document_states"`

	// Verification
	ChainValid         bool `json:"chain_valid"`
	PlausibleHumanRate bool `json:"plausible_human_rate"`

	// The actual jitter samples (for full verification)
	Samples []jitter.Sample `json:"samples,omitempty"`
}

// BehavioralEvidence contains optional behavioral data.
// This is from the old Layer 4 and is opt-in only.
type BehavioralEvidence struct {
	EditTopology []EditRegion `json:"edit_topology,omitempty"`
	Metrics      *ForensicMetrics `json:"metrics,omitempty"`
}

// EditRegion describes where an edit occurred.
type EditRegion struct {
	StartPct  float64 `json:"start_pct"`
	EndPct    float64 `json:"end_pct"`
	DeltaSign int     `json:"delta_sign"` // 0=replace, 1=insert, 2=delete
	ByteCount int     `json:"byte_count"`
}

// ForensicMetrics from behavioral analysis.
type ForensicMetrics struct {
	MonotonicAppendRatio  float64 `json:"monotonic_append_ratio"`
	EditEntropy           float64 `json:"edit_entropy"`
	MedianInterval        float64 `json:"median_interval_seconds"`
	PositiveNegativeRatio float64 `json:"positive_negative_ratio"`
	DeletionClustering    float64 `json:"deletion_clustering"`
	Assessment            string  `json:"assessment,omitempty"`
	AnomalyCount          int     `json:"anomaly_count,omitempty"`
}

// ExternalAnchors contains third-party timestamp proofs.
type ExternalAnchors struct {
	// Legacy format (for backwards compatibility)
	OpenTimestamps []OTSProof     `json:"opentimestamps,omitempty"`
	RFC3161        []RFC3161Proof `json:"rfc3161,omitempty"`

	// New unified format using anchors package
	Proofs []AnchorProof `json:"proofs,omitempty"`
}

// OTSProof is an OpenTimestamps proof (legacy format).
type OTSProof struct {
	ChainHash   string    `json:"chain_hash"`
	Proof       string    `json:"proof"` // Base64-encoded OTS proof
	Status      string    `json:"status"` // pending, confirmed
	BlockHeight uint64    `json:"block_height,omitempty"`
	BlockTime   time.Time `json:"block_time,omitempty"`
}

// RFC3161Proof is an RFC 3161 timestamp proof (legacy format).
type RFC3161Proof struct {
	ChainHash   string    `json:"chain_hash"`
	TSAUrl      string    `json:"tsa_url"`
	Response    string    `json:"response"` // Base64-encoded TSR
	Timestamp   time.Time `json:"timestamp"`
}

// AnchorProof is a unified anchor proof format.
type AnchorProof struct {
	// Provider identifier (e.g., "opentimestamps", "rfc3161", "eidas")
	Provider string `json:"provider"`

	// Provider display name
	ProviderName string `json:"provider_name"`

	// Legal standing of this proof
	LegalStanding string `json:"legal_standing"`

	// Regions where this proof has legal recognition
	Regions []string `json:"regions"`

	// Hash that was anchored
	Hash string `json:"hash"`

	// Timestamp from the anchor
	Timestamp time.Time `json:"timestamp"`

	// Status: pending, confirmed, failed
	Status string `json:"status"`

	// Raw proof data (base64 encoded)
	RawProof string `json:"raw_proof"`

	// Blockchain anchor details (if applicable)
	Blockchain *BlockchainAnchorInfo `json:"blockchain,omitempty"`

	// Verification URL
	VerifyURL string `json:"verify_url,omitempty"`
}

// BlockchainAnchorInfo contains blockchain-specific details.
type BlockchainAnchorInfo struct {
	Chain       string    `json:"chain"`
	BlockHeight uint64    `json:"block_height"`
	BlockHash   string    `json:"block_hash,omitempty"`
	BlockTime   time.Time `json:"block_time"`
	TxID        string    `json:"tx_id,omitempty"`
}

// Claim describes what the evidence proves.
type Claim struct {
	Type        ClaimType `json:"type"`
	Description string    `json:"description"`
	Confidence  string    `json:"confidence"` // "cryptographic", "attestation", "statistical"
}

// ClaimType categorizes claims.
type ClaimType string

const (
	ClaimChainIntegrity      ClaimType = "chain_integrity"
	ClaimTimeElapsed         ClaimType = "time_elapsed"
	ClaimProcessDeclared     ClaimType = "process_declared"
	ClaimPresenceVerified    ClaimType = "presence_verified"
	ClaimKeystrokesVerified  ClaimType = "keystrokes_verified"
	ClaimHardwareAttested    ClaimType = "hardware_attested"
	ClaimBehaviorAnalyzed    ClaimType = "behavior_analyzed"
	ClaimContextsRecorded    ClaimType = "contexts_recorded"
	ClaimExternalAnchored    ClaimType = "external_anchored"
	ClaimKeyHierarchy        ClaimType = "key_hierarchy"      // Patent Pending: USPTO Application No. 19/460,364
)

// Builder constructs evidence packets.
type Builder struct {
	packet Packet
	errors []error
}

// NewBuilder starts building an evidence packet.
func NewBuilder(title string, chain *checkpoint.Chain) *Builder {
	b := &Builder{
		packet: Packet{
			Version:    1,
			ExportedAt: time.Now(),
			Strength:   Basic,
			VDFParams:  chain.VDFParams,
		},
	}

	// Set document info
	if latest := chain.Latest(); latest != nil {
		b.packet.Document = DocumentInfo{
			Title:     title,
			Path:      chain.DocumentPath,
			FinalHash: hex.EncodeToString(latest.ContentHash[:]),
			FinalSize: latest.ContentSize,
		}
	}

	// Convert checkpoints
	for _, cp := range chain.Checkpoints {
		proof := CheckpointProof{
			Ordinal:      cp.Ordinal,
			ContentHash:  hex.EncodeToString(cp.ContentHash[:]),
			ContentSize:  cp.ContentSize,
			Timestamp:    cp.Timestamp,
			Message:      cp.Message,
			PreviousHash: hex.EncodeToString(cp.PreviousHash[:]),
			Hash:         hex.EncodeToString(cp.Hash[:]),
		}

		if len(cp.Signature) > 0 {
			proof.Signature = hex.EncodeToString(cp.Signature)
		}

		if cp.VDF != nil {
			proof.VDFInput = hex.EncodeToString(cp.VDF.Input[:])
			proof.VDFOutput = hex.EncodeToString(cp.VDF.Output[:])
			proof.VDFIterations = cp.VDF.Iterations
			proof.ElapsedTime = cp.VDF.MinElapsedTime(chain.VDFParams)
		}

		b.packet.Checkpoints = append(b.packet.Checkpoints, proof)
	}

	// Compute chain hash
	if latest := chain.Latest(); latest != nil {
		b.packet.ChainHash = hex.EncodeToString(latest.Hash[:])
	}

	return b
}

// WithDeclaration adds the required process declaration.
func (b *Builder) WithDeclaration(decl *declaration.Declaration) *Builder {
	if decl == nil {
		b.errors = append(b.errors, errors.New("declaration is required"))
		return b
	}
	if !decl.Verify() {
		b.errors = append(b.errors, errors.New("declaration signature invalid"))
		return b
	}
	b.packet.Declaration = decl
	return b
}

// WithPresence adds presence verification evidence.
func (b *Builder) WithPresence(sessions []presence.Session) *Builder {
	if len(sessions) == 0 {
		return b
	}
	ev := presence.CompileEvidence(sessions)
	b.packet.Presence = &ev
	if b.packet.Strength < Standard {
		b.packet.Strength = Standard
	}
	return b
}

// WithHardware adds TPM attestation evidence.
func (b *Builder) WithHardware(bindings []tpm.Binding, deviceID string) *Builder {
	if len(bindings) == 0 {
		return b
	}
	b.packet.Hardware = &HardwareEvidence{
		Bindings: bindings,
		DeviceID: deviceID,
	}
	if b.packet.Strength < Enhanced {
		b.packet.Strength = Enhanced
	}
	return b
}

// WithKeystroke adds jitter-based keystroke evidence.
func (b *Builder) WithKeystroke(ev *jitter.Evidence) *Builder {
	if ev == nil || ev.Statistics.TotalKeystrokes == 0 {
		return b
	}

	// Verify the evidence
	if err := ev.Verify(); err != nil {
		b.errors = append(b.errors, fmt.Errorf("keystroke evidence invalid: %w", err))
		return b
	}

	b.packet.Keystroke = &KeystrokeEvidence{
		SessionID:        ev.SessionID,
		StartedAt:        ev.StartedAt,
		EndedAt:          ev.EndedAt,
		Duration:         ev.Statistics.Duration,
		TotalKeystrokes:  ev.Statistics.TotalKeystrokes,
		TotalSamples:     ev.Statistics.TotalSamples,
		KeystrokesPerMin: ev.Statistics.KeystrokesPerMin,
		UniqueDocStates:  ev.Statistics.UniqueDocHashes,
		ChainValid:       ev.Statistics.ChainValid,
		PlausibleHumanRate: ev.IsPlausibleHumanTyping(),
		Samples:          ev.Samples,
	}

	if b.packet.Strength < Standard {
		b.packet.Strength = Standard
	}
	return b
}

// WithBehavioral adds optional behavioral evidence.
func (b *Builder) WithBehavioral(regions []EditRegion, metrics *ForensicMetrics) *Builder {
	if len(regions) == 0 && metrics == nil {
		return b
	}
	b.packet.Behavioral = &BehavioralEvidence{
		EditTopology: regions,
		Metrics:      metrics,
	}
	if b.packet.Strength < Maximum {
		b.packet.Strength = Maximum
	}
	return b
}

// WithContexts adds runtime-tracked editing context periods.
// Context periods complement the declaration by providing runtime evidence
// of when external content, AI assistance, or review passes occurred.
func (b *Builder) WithContexts(contexts []ContextPeriod) *Builder {
	if len(contexts) == 0 {
		return b
	}
	b.packet.Contexts = contexts
	return b
}

// WithProvenance adds record provenance information.
// This documents who initiated the record, where it was generated,
// and access control information at the time of creation.
func (b *Builder) WithProvenance(prov *RecordProvenance) *Builder {
	if prov == nil {
		return b
	}
	b.packet.Provenance = prov
	return b
}

// WithExternalAnchors adds external timestamp proofs (legacy format).
func (b *Builder) WithExternalAnchors(ots []OTSProof, rfc []RFC3161Proof) *Builder {
	if len(ots) == 0 && len(rfc) == 0 {
		return b
	}
	b.packet.External = &ExternalAnchors{
		OpenTimestamps: ots,
		RFC3161:        rfc,
	}
	if b.packet.Strength < Maximum {
		b.packet.Strength = Maximum
	}
	return b
}

// WithAnchors adds external anchor proofs from the anchors package.
// This is the preferred method for adding external timestamps.
func (b *Builder) WithAnchors(proofs []*anchors.Proof) *Builder {
	if len(proofs) == 0 {
		return b
	}

	if b.packet.External == nil {
		b.packet.External = &ExternalAnchors{}
	}

	for _, proof := range proofs {
		anchorProof := convertAnchorProof(proof)
		b.packet.External.Proofs = append(b.packet.External.Proofs, anchorProof)
	}

	if b.packet.Strength < Maximum {
		b.packet.Strength = Maximum
	}
	return b
}

// WithKeyHierarchy adds key hierarchy evidence to the packet.
// This provides cryptographic proof of persistent author identity with
// forward secrecy through ratcheting keys.
//
// Patent Pending: USPTO Application No. 19/460,364
func (b *Builder) WithKeyHierarchy(evidence *keyhierarchy.KeyHierarchyEvidence) *Builder {
	if evidence == nil {
		return b
	}

	packet := &KeyHierarchyEvidencePacket{
		Version:           evidence.Version,
		MasterFingerprint: evidence.MasterFingerprint,
		MasterPublicKey:   hex.EncodeToString(evidence.MasterPublicKey),
		DeviceID:          evidence.DeviceID,
		SessionID:         evidence.SessionID,
		SessionPublicKey:  hex.EncodeToString(evidence.SessionPublicKey),
		SessionStarted:    evidence.SessionStarted,
		SessionCertificate: base64.StdEncoding.EncodeToString(evidence.SessionCertificateRaw),
		RatchetCount:      evidence.RatchetCount,
	}

	// Add ratchet public keys
	for _, key := range evidence.RatchetPublicKeys {
		packet.RatchetPublicKeys = append(packet.RatchetPublicKeys, hex.EncodeToString(key))
	}

	// Add checkpoint signatures
	for i, sig := range evidence.CheckpointSignatures {
		packet.CheckpointSignatures = append(packet.CheckpointSignatures, CheckpointSignature{
			Ordinal:        sig.Ordinal,
			CheckpointHash: hex.EncodeToString(sig.CheckpointHash[:]),
			RatchetIndex:   i, // Use index as ratchet index
			Signature:      base64.StdEncoding.EncodeToString(sig.Signature[:]),
		})
	}

	b.packet.KeyHierarchy = packet

	// Key hierarchy enhances evidence strength
	if b.packet.Strength < Enhanced {
		b.packet.Strength = Enhanced
	}

	return b
}

// convertAnchorProof converts an anchors.Proof to AnchorProof.
func convertAnchorProof(p *anchors.Proof) AnchorProof {
	ap := AnchorProof{
		Provider:      p.Provider,
		Hash:          hex.EncodeToString(p.Hash[:]),
		Timestamp:     p.Timestamp,
		Status:        string(p.Status),
		RawProof:      base64.StdEncoding.EncodeToString(p.RawProof),
		VerifyURL:     p.VerifyURL,
	}

	// Add blockchain details if present
	if p.BlockchainAnchor != nil {
		ap.Blockchain = &BlockchainAnchorInfo{
			Chain:       p.BlockchainAnchor.Chain,
			BlockHeight: p.BlockchainAnchor.BlockHeight,
			BlockHash:   p.BlockchainAnchor.BlockHash,
			BlockTime:   p.BlockchainAnchor.BlockTime,
			TxID:        p.BlockchainAnchor.TransactionID,
		}
	}

	return ap
}

// Build finalizes the evidence packet.
func (b *Builder) Build() (*Packet, error) {
	if len(b.errors) > 0 {
		return nil, fmt.Errorf("build errors: %v", b.errors)
	}

	if b.packet.Declaration == nil {
		return nil, errors.New("declaration is required")
	}

	// Generate claims based on included evidence
	b.generateClaims()
	b.generateLimitations()

	return &b.packet, nil
}

func (b *Builder) generateClaims() {
	// Always present: chain integrity
	b.packet.Claims = append(b.packet.Claims, Claim{
		Type:        ClaimChainIntegrity,
		Description: "Content states form an unbroken cryptographic chain",
		Confidence:  "cryptographic",
	})

	// VDF time elapsed
	var totalTime time.Duration
	for _, cp := range b.packet.Checkpoints {
		totalTime += cp.ElapsedTime
	}
	if totalTime > 0 {
		b.packet.Claims = append(b.packet.Claims, Claim{
			Type:        ClaimTimeElapsed,
			Description: fmt.Sprintf("At least %s elapsed during documented composition", totalTime.Round(time.Second)),
			Confidence:  "cryptographic",
		})
	}

	// Process declaration
	if b.packet.Declaration != nil {
		aiDesc := "No AI tools declared"
		if b.packet.Declaration.HasAIUsage() {
			aiDesc = fmt.Sprintf("AI assistance declared: %s extent", b.packet.Declaration.MaxAIExtent())
		}
		b.packet.Claims = append(b.packet.Claims, Claim{
			Type:        ClaimProcessDeclared,
			Description: fmt.Sprintf("Author signed declaration of creative process. %s", aiDesc),
			Confidence:  "attestation",
		})
	}

	// Presence verification
	if b.packet.Presence != nil {
		b.packet.Claims = append(b.packet.Claims, Claim{
			Type:        ClaimPresenceVerified,
			Description: fmt.Sprintf("Author presence verified %.0f%% of challenged sessions", b.packet.Presence.OverallRate*100),
			Confidence:  "cryptographic",
		})
	}

	// Keystroke evidence
	if b.packet.Keystroke != nil {
		desc := fmt.Sprintf("%d keystrokes recorded over %s (%.0f/min)",
			b.packet.Keystroke.TotalKeystrokes,
			b.packet.Keystroke.Duration.Round(time.Second),
			b.packet.Keystroke.KeystrokesPerMin)
		if b.packet.Keystroke.PlausibleHumanRate {
			desc += ", consistent with human typing"
		}
		b.packet.Claims = append(b.packet.Claims, Claim{
			Type:        ClaimKeystrokesVerified,
			Description: desc,
			Confidence:  "cryptographic",
		})
	}

	// Hardware attestation
	if b.packet.Hardware != nil {
		b.packet.Claims = append(b.packet.Claims, Claim{
			Type:        ClaimHardwareAttested,
			Description: "TPM attests chain was not rolled back or modified",
			Confidence:  "cryptographic",
		})
	}

	// Behavioral analysis
	if b.packet.Behavioral != nil {
		b.packet.Claims = append(b.packet.Claims, Claim{
			Type:        ClaimBehaviorAnalyzed,
			Description: "Edit patterns captured for forensic analysis",
			Confidence:  "statistical",
		})
	}

	// Context periods
	if len(b.packet.Contexts) > 0 {
		// Count context types
		typeCounts := make(map[string]int)
		for _, ctx := range b.packet.Contexts {
			typeCounts[ctx.Type]++
		}
		desc := fmt.Sprintf("%d context periods recorded", len(b.packet.Contexts))
		if typeCounts["assisted"] > 0 {
			desc += fmt.Sprintf(" (%d AI-assisted)", typeCounts["assisted"])
		}
		if typeCounts["external"] > 0 {
			desc += fmt.Sprintf(" (%d external)", typeCounts["external"])
		}
		b.packet.Claims = append(b.packet.Claims, Claim{
			Type:        ClaimContextsRecorded,
			Description: desc,
			Confidence:  "attestation",
		})
	}

	// External anchors
	if b.packet.External != nil {
		count := len(b.packet.External.OpenTimestamps) + len(b.packet.External.RFC3161) + len(b.packet.External.Proofs)
		b.packet.Claims = append(b.packet.Claims, Claim{
			Type:        ClaimExternalAnchored,
			Description: fmt.Sprintf("Chain anchored to %d external timestamp authorities", count),
			Confidence:  "cryptographic",
		})
	}

	// Key hierarchy (Patent Pending: USPTO Application No. 19/460,364)
	if b.packet.KeyHierarchy != nil {
		desc := fmt.Sprintf("Identity %s with %d ratchet generations",
			b.packet.KeyHierarchy.MasterFingerprint[:16]+"...",
			b.packet.KeyHierarchy.RatchetCount)
		if len(b.packet.KeyHierarchy.CheckpointSignatures) > 0 {
			desc += fmt.Sprintf(", %d checkpoint signatures", len(b.packet.KeyHierarchy.CheckpointSignatures))
		}
		b.packet.Claims = append(b.packet.Claims, Claim{
			Type:        ClaimKeyHierarchy,
			Description: desc,
			Confidence:  "cryptographic",
		})
	}
}

func (b *Builder) generateLimitations() {
	// Universal limitations
	b.packet.Limitations = append(b.packet.Limitations,
		"Cannot prove cognitive origin of ideas",
		"Cannot prove absence of AI involvement in ideation",
	)

	if b.packet.Presence == nil {
		b.packet.Limitations = append(b.packet.Limitations,
			"No presence verification - cannot confirm human was at keyboard")
	}

	if b.packet.Keystroke == nil {
		b.packet.Limitations = append(b.packet.Limitations,
			"No keystroke evidence - cannot verify real typing occurred")
	}

	if b.packet.Hardware == nil {
		b.packet.Limitations = append(b.packet.Limitations,
			"No hardware attestation - software-only security")
	}

	if b.packet.Declaration.HasAIUsage() {
		b.packet.Limitations = append(b.packet.Limitations,
			"Author declares AI tool usage - verify institutional policy compliance")
	}
}

// Verify checks the evidence packet integrity.
func (p *Packet) Verify(vdfParams vdf.Parameters) error {
	// Verify chain integrity
	var prevHash string
	for i, cp := range p.Checkpoints {
		if i == 0 {
			if cp.PreviousHash != hex.EncodeToString(make([]byte, 32)) {
				return fmt.Errorf("checkpoint 0: non-zero previous hash")
			}
		} else {
			if cp.PreviousHash != prevHash {
				return fmt.Errorf("checkpoint %d: broken chain link", i)
			}
		}
		prevHash = cp.Hash

		// Verify VDF
		if cp.VDFIterations > 0 {
			var input, output [32]byte
			inputBytes, _ := hex.DecodeString(cp.VDFInput)
			outputBytes, _ := hex.DecodeString(cp.VDFOutput)
			copy(input[:], inputBytes)
			copy(output[:], outputBytes)

			proof := &vdf.Proof{
				Input:      input,
				Output:     output,
				Iterations: cp.VDFIterations,
			}
			if !vdf.Verify(proof) {
				return fmt.Errorf("checkpoint %d: VDF verification failed", i)
			}
		}
	}

	// Verify declaration signature
	if p.Declaration != nil && !p.Declaration.Verify() {
		return errors.New("declaration signature invalid")
	}

	// Verify TPM bindings if present
	if p.Hardware != nil && len(p.Hardware.Bindings) > 0 {
		if err := tpm.VerifyBindingChain(p.Hardware.Bindings, nil); err != nil {
			return fmt.Errorf("hardware attestation invalid: %w", err)
		}
	}

	// Verify key hierarchy if present (Patent Pending: USPTO Application No. 19/460,364)
	if p.KeyHierarchy != nil {
		if err := p.verifyKeyHierarchy(); err != nil {
			return fmt.Errorf("key hierarchy verification failed: %w", err)
		}
	}

	return nil
}

// verifyKeyHierarchy verifies the key hierarchy evidence.
//
// Patent Pending: USPTO Application No. 19/460,364
func (p *Packet) verifyKeyHierarchy() error {
	kh := p.KeyHierarchy

	// Decode master public key
	masterPubKey, err := hex.DecodeString(kh.MasterPublicKey)
	if err != nil {
		return fmt.Errorf("invalid master public key: %w", err)
	}
	if len(masterPubKey) != 32 {
		return errors.New("master public key wrong length")
	}

	// Decode session public key
	sessionPubKey, err := hex.DecodeString(kh.SessionPublicKey)
	if err != nil {
		return fmt.Errorf("invalid session public key: %w", err)
	}
	if len(sessionPubKey) != 32 {
		return errors.New("session public key wrong length")
	}

	// Decode session certificate
	sessionCert, err := base64.StdEncoding.DecodeString(kh.SessionCertificate)
	if err != nil {
		return fmt.Errorf("invalid session certificate: %w", err)
	}

	// Verify session certificate is signed by master key
	if err := keyhierarchy.VerifySessionCertificateBytes(masterPubKey, sessionPubKey, sessionCert); err != nil {
		return fmt.Errorf("session certificate invalid: %w", err)
	}

	// Verify checkpoint signatures
	for _, sig := range kh.CheckpointSignatures {
		if sig.RatchetIndex < 0 || sig.RatchetIndex >= len(kh.RatchetPublicKeys) {
			return fmt.Errorf("checkpoint %d: invalid ratchet index %d", sig.Ordinal, sig.RatchetIndex)
		}

		ratchetPubKey, err := hex.DecodeString(kh.RatchetPublicKeys[sig.RatchetIndex])
		if err != nil {
			return fmt.Errorf("checkpoint %d: invalid ratchet key: %w", sig.Ordinal, err)
		}

		checkpointHash, err := hex.DecodeString(sig.CheckpointHash)
		if err != nil {
			return fmt.Errorf("checkpoint %d: invalid hash: %w", sig.Ordinal, err)
		}

		signature, err := base64.StdEncoding.DecodeString(sig.Signature)
		if err != nil {
			return fmt.Errorf("checkpoint %d: invalid signature: %w", sig.Ordinal, err)
		}

		if err := keyhierarchy.VerifyRatchetSignature(ratchetPubKey, checkpointHash, signature); err != nil {
			return fmt.Errorf("checkpoint %d: signature verification failed: %w", sig.Ordinal, err)
		}
	}

	return nil
}

// TotalElapsedTime returns the sum of all VDF-proven elapsed times.
func (p *Packet) TotalElapsedTime() time.Duration {
	var total time.Duration
	for _, cp := range p.Checkpoints {
		total += cp.ElapsedTime
	}
	return total
}

// Encode serializes the packet to JSON.
func (p *Packet) Encode() ([]byte, error) {
	return json.MarshalIndent(p, "", "  ")
}

// Decode deserializes a packet from JSON.
func Decode(data []byte) (*Packet, error) {
	var p Packet
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// Hash returns a unique hash of the evidence packet.
func (p *Packet) Hash() [32]byte {
	data, _ := p.Encode()
	return sha256.Sum256(data)
}
