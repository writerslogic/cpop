// Package declaration implements Layer 1 Process Declarations.
//
// A Process Declaration is a signed attestation by the author describing
// how they created a document. This includes:
// - Input modalities (keyboard, dictation, etc.)
// - AI tools used (if any)
// - Collaborators involved
// - Free-form statement
//
// Unlike behavioral detection, declarations shift the burden to legal/social
// accountability. False declarations are fraud/perjury in appropriate contexts.
package declaration

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Declaration is a signed attestation of creative process.
type Declaration struct {
	// What document is this for?
	DocumentHash [32]byte `json:"document_hash"`
	ChainHash    [32]byte `json:"chain_hash"` // Hash of the checkpoint chain
	Title        string   `json:"title"`

	// How was content created?
	InputModalities []InputModality `json:"input_modalities"`

	// AI tools used (can be empty for "no AI")
	AITools []AIToolUsage `json:"ai_tools"`

	// Collaboration
	Collaborators []Collaborator `json:"collaborators,omitempty"`

	// Free-form attestation
	Statement string `json:"statement"`

	// Metadata
	CreatedAt time.Time `json:"created_at"`
	Version   int       `json:"version"` // Schema version

	// Cryptographic binding
	AuthorPublicKey ed25519.PublicKey `json:"author_public_key"`
	Signature       []byte            `json:"signature"`
}

// InputModality describes how content was physically created.
type InputModality struct {
	Type       ModalityType `json:"type"`
	Percentage float64      `json:"percentage"` // Estimated % of content
	Note       string       `json:"note,omitempty"`
}

// ModalityType enumerates input modalities.
type ModalityType string

const (
	ModalityKeyboard    ModalityType = "keyboard"
	ModalityDictation   ModalityType = "dictation"
	ModalityHandwriting ModalityType = "handwriting"
	ModalityPaste       ModalityType = "paste"
	ModalityImport      ModalityType = "import"
	ModalityMixed       ModalityType = "mixed"
	ModalityOther       ModalityType = "other"
)

// AIToolUsage describes how an AI tool was used.
type AIToolUsage struct {
	Tool        string       `json:"tool"`                  // "Claude", "GPT-4", "Copilot", etc.
	Version     string       `json:"version,omitempty"`     // If known
	Purpose     AIPurpose    `json:"purpose"`               // What was it used for?
	Interaction string       `json:"interaction,omitempty"` // How was it used?
	Extent      AIExtent     `json:"extent"`                // How much was it used?
	Sections    []string     `json:"sections,omitempty"`    // Which parts of document
}

// AIPurpose describes what an AI tool was used for.
type AIPurpose string

const (
	PurposeIdeation   AIPurpose = "ideation"
	PurposeOutline    AIPurpose = "outline"
	PurposeDrafting   AIPurpose = "drafting"
	PurposeFeedback   AIPurpose = "feedback"
	PurposeEditing    AIPurpose = "editing"
	PurposeResearch   AIPurpose = "research"
	PurposeFormatting AIPurpose = "formatting"
	PurposeOther      AIPurpose = "other"
)

// AIExtent describes the degree of AI involvement.
type AIExtent string

const (
	ExtentNone        AIExtent = "none"        // Used but rejected all output
	ExtentMinimal     AIExtent = "minimal"     // Minor suggestions accepted
	ExtentModerate    AIExtent = "moderate"    // Significant assistance
	ExtentSubstantial AIExtent = "substantial" // Major portions AI-influenced
)

// Collaborator describes a human collaborator.
type Collaborator struct {
	Name      string            `json:"name"`
	Role      CollaboratorRole  `json:"role"`
	Sections  []string          `json:"sections,omitempty"`
	PublicKey ed25519.PublicKey `json:"public_key,omitempty"` // If they have witnessd identity
}

// CollaboratorRole describes a collaborator's role.
type CollaboratorRole string

const (
	RoleCoAuthor          CollaboratorRole = "co-author"
	RoleEditor            CollaboratorRole = "editor"
	RoleResearchAssistant CollaboratorRole = "research_assistant"
	RoleReviewer          CollaboratorRole = "reviewer"
	RoleTranscriber       CollaboratorRole = "transcriber"
	RoleOther             CollaboratorRole = "other"
)

// Builder helps construct declarations with a fluent API.
type Builder struct {
	decl Declaration
	err  error
}

// NewDeclaration starts building a declaration.
func NewDeclaration(documentHash, chainHash [32]byte, title string) *Builder {
	return &Builder{
		decl: Declaration{
			DocumentHash: documentHash,
			ChainHash:    chainHash,
			Title:        title,
			CreatedAt:    time.Now(),
			Version:      1,
		},
	}
}

// AddModality adds an input modality.
func (b *Builder) AddModality(modType ModalityType, percentage float64, note string) *Builder {
	b.decl.InputModalities = append(b.decl.InputModalities, InputModality{
		Type:       modType,
		Percentage: percentage,
		Note:       note,
	})
	return b
}

// AddAITool adds an AI tool usage declaration.
func (b *Builder) AddAITool(tool, version string, purpose AIPurpose, interaction string, extent AIExtent) *Builder {
	b.decl.AITools = append(b.decl.AITools, AIToolUsage{
		Tool:        tool,
		Version:     version,
		Purpose:     purpose,
		Interaction: interaction,
		Extent:      extent,
	})
	return b
}

// AddCollaborator adds a collaborator.
func (b *Builder) AddCollaborator(name string, role CollaboratorRole, sections []string) *Builder {
	b.decl.Collaborators = append(b.decl.Collaborators, Collaborator{
		Name:     name,
		Role:     role,
		Sections: sections,
	})
	return b
}

// WithStatement sets the free-form statement.
func (b *Builder) WithStatement(statement string) *Builder {
	b.decl.Statement = statement
	return b
}

// Sign signs the declaration with the author's private key.
func (b *Builder) Sign(privateKey ed25519.PrivateKey) (*Declaration, error) {
	if b.err != nil {
		return nil, b.err
	}

	// Validate
	if err := b.validate(); err != nil {
		return nil, err
	}

	// Set public key
	b.decl.AuthorPublicKey = privateKey.Public().(ed25519.PublicKey)

	// Compute signing payload
	payload := b.decl.signingPayload()

	// Sign
	b.decl.Signature = ed25519.Sign(privateKey, payload)

	return &b.decl, nil
}

func (b *Builder) validate() error {
	if b.decl.DocumentHash == ([32]byte{}) {
		return errors.New("document hash is required")
	}
	if b.decl.ChainHash == ([32]byte{}) {
		return errors.New("chain hash is required")
	}
	if b.decl.Title == "" {
		return errors.New("title is required")
	}
	if len(b.decl.InputModalities) == 0 {
		return errors.New("at least one input modality is required")
	}
	if b.decl.Statement == "" {
		return errors.New("statement is required")
	}

	// Validate modality percentages sum to ~100%
	var total float64
	for _, m := range b.decl.InputModalities {
		if m.Percentage < 0 || m.Percentage > 100 {
			return errors.New("modality percentage must be 0-100")
		}
		total += m.Percentage
	}
	if total < 95 || total > 105 { // Allow 5% tolerance
		return fmt.Errorf("modality percentages sum to %.1f%%, expected ~100%%", total)
	}

	return nil
}

// signingPayload creates the canonical bytes to sign.
func (d *Declaration) signingPayload() []byte {
	h := sha256.New()
	h.Write([]byte("witnessd-declaration-v1"))

	h.Write(d.DocumentHash[:])
	h.Write(d.ChainHash[:])
	h.Write([]byte(d.Title))

	// Modalities
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(len(d.InputModalities)))
	h.Write(buf[:])
	for _, m := range d.InputModalities {
		h.Write([]byte(m.Type))
		binary.BigEndian.PutUint64(buf[:], uint64(m.Percentage*1000)) // Fixed-point
		h.Write(buf[:])
	}

	// AI tools
	binary.BigEndian.PutUint64(buf[:], uint64(len(d.AITools)))
	h.Write(buf[:])
	for _, ai := range d.AITools {
		h.Write([]byte(ai.Tool))
		h.Write([]byte(ai.Purpose))
		h.Write([]byte(ai.Extent))
	}

	// Statement
	h.Write([]byte(d.Statement))

	// Timestamp
	binary.BigEndian.PutUint64(buf[:], uint64(d.CreatedAt.UnixNano()))
	h.Write(buf[:])

	// Public key
	h.Write(d.AuthorPublicKey)

	return h.Sum(nil)
}

// Verify checks the declaration signature.
func (d *Declaration) Verify() bool {
	if len(d.AuthorPublicKey) != ed25519.PublicKeySize {
		return false
	}
	if len(d.Signature) != ed25519.SignatureSize {
		return false
	}

	payload := d.signingPayload()
	return ed25519.Verify(d.AuthorPublicKey, payload, d.Signature)
}

// HasAIUsage returns true if any AI tools are declared.
func (d *Declaration) HasAIUsage() bool {
	return len(d.AITools) > 0
}

// MaxAIExtent returns the highest AI extent declared.
func (d *Declaration) MaxAIExtent() AIExtent {
	max := ExtentNone
	for _, ai := range d.AITools {
		if extentRank(ai.Extent) > extentRank(max) {
			max = ai.Extent
		}
	}
	return max
}

func extentRank(e AIExtent) int {
	switch e {
	case ExtentNone:
		return 0
	case ExtentMinimal:
		return 1
	case ExtentModerate:
		return 2
	case ExtentSubstantial:
		return 3
	default:
		return 0
	}
}

// Encode serializes the declaration to JSON.
func (d *Declaration) Encode() ([]byte, error) {
	return json.MarshalIndent(d, "", "  ")
}

// Decode deserializes a declaration from JSON.
func Decode(data []byte) (*Declaration, error) {
	var d Declaration
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// Summary returns a human-readable summary.
type DeclarationSummary struct {
	Title         string   `json:"title"`
	AIUsage       bool     `json:"ai_usage"`
	AITools       []string `json:"ai_tools,omitempty"`
	MaxAIExtent   string   `json:"max_ai_extent"`
	Collaborators int      `json:"collaborators"`
	SignatureValid bool    `json:"signature_valid"`
}

func (d *Declaration) Summary() DeclarationSummary {
	s := DeclarationSummary{
		Title:          d.Title,
		AIUsage:        d.HasAIUsage(),
		MaxAIExtent:    string(d.MaxAIExtent()),
		Collaborators:  len(d.Collaborators),
		SignatureValid: d.Verify(),
	}

	for _, ai := range d.AITools {
		s.AITools = append(s.AITools, ai.Tool)
	}

	return s
}

// Templates for common declaration patterns.

// NoAIDeclaration creates a declaration asserting no AI usage.
func NoAIDeclaration(documentHash, chainHash [32]byte, title, statement string) *Builder {
	return NewDeclaration(documentHash, chainHash, title).
		AddModality(ModalityKeyboard, 100, "").
		WithStatement(statement)
}

// AIAssistedDeclaration creates a declaration with AI assistance.
func AIAssistedDeclaration(documentHash, chainHash [32]byte, title string) *Builder {
	return NewDeclaration(documentHash, chainHash, title)
}
