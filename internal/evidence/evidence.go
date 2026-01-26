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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"witnessd/internal/checkpoint"
	"witnessd/internal/declaration"
	"witnessd/internal/presence"
	"witnessd/internal/tpm"
	"witnessd/internal/vdf"
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

	// Layer 4: Behavioral Data (Maximum only)
	Behavioral *BehavioralEvidence `json:"behavioral,omitempty"`

	// Layer 5: External Anchors (Maximum only)
	External *ExternalAnchors `json:"external,omitempty"`

	// What this evidence claims
	Claims     []Claim  `json:"claims"`
	Limitations []string `json:"limitations"`
}

// DocumentInfo describes the witnessed document.
type DocumentInfo struct {
	Title       string `json:"title"`
	Path        string `json:"path"`
	FinalHash   string `json:"final_hash"`
	FinalSize   int64  `json:"final_size"`
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
}

// HardwareEvidence contains TPM attestations.
type HardwareEvidence struct {
	Bindings []tpm.Binding `json:"bindings"`
	DeviceID string        `json:"device_id"`
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
	MonotonicAppendRatio float64 `json:"monotonic_append_ratio"`
	EditEntropy          float64 `json:"edit_entropy"`
	MedianInterval       float64 `json:"median_interval_seconds"`
	PositiveNegativeRatio float64 `json:"positive_negative_ratio"`
	DeletionClustering   float64 `json:"deletion_clustering"`
}

// ExternalAnchors contains third-party timestamp proofs.
type ExternalAnchors struct {
	OpenTimestamps []OTSProof     `json:"opentimestamps,omitempty"`
	RFC3161        []RFC3161Proof `json:"rfc3161,omitempty"`
}

// OTSProof is an OpenTimestamps proof.
type OTSProof struct {
	ChainHash   string    `json:"chain_hash"`
	Proof       string    `json:"proof"` // Base64-encoded OTS proof
	Status      string    `json:"status"` // pending, confirmed
	BlockHeight uint64    `json:"block_height,omitempty"`
	BlockTime   time.Time `json:"block_time,omitempty"`
}

// RFC3161Proof is an RFC 3161 timestamp proof.
type RFC3161Proof struct {
	ChainHash   string    `json:"chain_hash"`
	TSAUrl      string    `json:"tsa_url"`
	Response    string    `json:"response"` // Base64-encoded TSR
	Timestamp   time.Time `json:"timestamp"`
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
	ClaimChainIntegrity    ClaimType = "chain_integrity"
	ClaimTimeElapsed       ClaimType = "time_elapsed"
	ClaimProcessDeclared   ClaimType = "process_declared"
	ClaimPresenceVerified  ClaimType = "presence_verified"
	ClaimHardwareAttested  ClaimType = "hardware_attested"
	ClaimBehaviorAnalyzed  ClaimType = "behavior_analyzed"
	ClaimExternalAnchored  ClaimType = "external_anchored"
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

// WithExternalAnchors adds external timestamp proofs.
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

	// External anchors
	if b.packet.External != nil {
		count := len(b.packet.External.OpenTimestamps) + len(b.packet.External.RFC3161)
		b.packet.Claims = append(b.packet.Claims, Claim{
			Type:        ClaimExternalAnchored,
			Description: fmt.Sprintf("Chain anchored to %d external timestamp authorities", count),
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
