# Process Declaration Specification

**Version:** 1.0.0
**Status:** Draft
**Last Updated:** 2026-01-25

## Overview

A **Process Declaration** is a cryptographically signed attestation by an author describing how they created a document. Unlike behavioral detection (which attempts to infer process from artifacts), declarations shift the burden to legal and social accountability.

This specification defines:
- The structure and fields of a process declaration
- AI tool categories and extent levels
- Legal language and attestation semantics
- Signature and verification requirements

## Design Philosophy

### Documentation Over Detection

Traditional authorship verification attempts to *detect* AI involvement through statistical analysis. This approach faces fundamental limitations:

1. AI-generated text becomes indistinguishable from human text as models improve
2. Detection is an arms race that content generators will eventually win
3. False positives harm legitimate authors

Process declarations take a different approach: **document what cannot be detected, attest to what cannot be proven**. The author makes a cryptographically signed statement about their creative process. Verification shifts from technical detection to institutional accountability.

### Accountability Framework

A false declaration is:
- **Professional misconduct** in academic contexts
- **Breach of contract** in commercial contexts
- **Fraud** in legal contexts
- **Perjury** when made under oath

The declaration system assumes that most actors will provide honest attestations when:
1. The consequences of false statements are clear
2. There is no benefit to lying (honest AI usage is acceptable in many contexts)
3. The declaration is permanent and cryptographically bound

## Declaration Structure

### Top-Level Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `document_hash` | bytes[32] | Yes | SHA-256 hash of the document being declared |
| `chain_hash` | bytes[32] | Yes | Hash of the associated checkpoint chain |
| `title` | string | Yes | Human-readable document title |
| `input_modalities` | array | Yes | How content was physically created |
| `ai_tools` | array | No | AI tools used (empty = no AI) |
| `collaborators` | array | No | Human collaborators involved |
| `statement` | string | Yes | Free-form attestation (legal text) |
| `created_at` | timestamp | Yes | When declaration was made |
| `version` | integer | Yes | Schema version (currently 1) |
| `author_public_key` | bytes[32] | Yes | Ed25519 public key of declarant |
| `signature` | bytes[64] | Yes | Ed25519 signature over canonical payload |

### Input Modalities

Input modalities describe *how* content was physically created. At least one modality is required, and percentages must sum to approximately 100% (95-105% tolerance for rounding).

#### Modality Types

| Value | Description | Examples |
|-------|-------------|----------|
| `keyboard` | Direct keyboard typing | Standard typing, mechanical keyboard |
| `dictation` | Voice-to-text transcription | Dragon, Whisper, system dictation |
| `handwriting` | Digitized handwriting | Tablet stylus, scanned notes |
| `paste` | Content pasted from clipboard | Copy/paste from reference, quotes |
| `import` | Content imported from files | Include directives, file merges |
| `mixed` | Multiple methods interleaved | Cannot separate percentages |
| `other` | Unlisted input method | Specialized input devices |

#### Modality Structure

```yaml
input_modalities:
  - type: keyboard
    percentage: 85.0
    note: "Primary authoring method"
  - type: paste
    percentage: 15.0
    note: "Code snippets from documentation"
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | enum | Yes | One of the modality types above |
| `percentage` | float | Yes | Estimated percentage of content (0-100) |
| `note` | string | No | Optional clarification |

### AI Tool Usage

The `ai_tools` array documents any AI assistance. An empty array explicitly declares "no AI tools were used."

#### AI Tool Structure

```yaml
ai_tools:
  - tool: "Claude"
    version: "3.5 Sonnet"
    purpose: "feedback"
    interaction: "Asked for suggestions on argument structure"
    extent: "minimal"
    sections:
      - "Introduction"
      - "Conclusion"
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `tool` | string | Yes | Name of the AI tool |
| `version` | string | No | Version if known |
| `purpose` | enum | Yes | What the tool was used for |
| `interaction` | string | No | Description of how it was used |
| `extent` | enum | Yes | Degree of AI involvement |
| `sections` | array | No | Which document sections were affected |

#### AI Tool Categories

The `tool` field should use canonical names where possible:

| Category | Examples |
|----------|----------|
| **Chat assistants** | Claude, ChatGPT, Gemini, Llama, Mistral |
| **Code assistants** | GitHub Copilot, Cursor, Codeium, Tabnine |
| **Writing assistants** | Grammarly AI, Jasper, Copy.ai, Writesonic |
| **Image generators** | DALL-E, Midjourney, Stable Diffusion |
| **Search/Research** | Perplexity, You.com, Consensus |
| **Transcription** | Whisper, Otter.ai, Rev |
| **Translation** | DeepL, Google Translate (AI-powered) |

For less common tools, use the tool's official name.

#### AI Purpose Categories

| Value | Description | Typical Use |
|-------|-------------|-------------|
| `ideation` | Generating ideas or concepts | Brainstorming, topic exploration |
| `outline` | Structuring content | Creating document skeleton |
| `drafting` | Generating prose or code | Writing actual content |
| `feedback` | Reviewing and commenting | Getting suggestions, critique |
| `editing` | Improving existing content | Grammar, style, clarity fixes |
| `research` | Finding information | Fact-checking, source finding |
| `formatting` | Structural formatting | LaTeX, markdown, styling |
| `other` | Unlisted purpose | Document in `interaction` field |

#### AI Extent Levels

The extent level indicates the *degree* of AI involvement, not just whether AI was used:

| Value | Description | Guidance |
|-------|-------------|----------|
| `none` | Tool was used but all output rejected | Consulted AI but didn't use suggestions |
| `minimal` | Minor suggestions accepted | Grammar fixes, word suggestions, small edits |
| `moderate` | Significant assistance | Paragraph-level suggestions, structural changes |
| `substantial` | Major portions AI-influenced | Large sections generated or heavily revised |

**Important:** The extent level should reflect the *final document*, not the interaction. If you generated 10 paragraphs with AI but only kept 2 sentences, that's `minimal`, not `substantial`.

### Collaborators

Human collaborators are documented separately from AI tools:

```yaml
collaborators:
  - name: "Dr. Jane Smith"
    role: "co-author"
    sections:
      - "Methods"
      - "Results"
    public_key: "base64-encoded-ed25519-pubkey"
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Collaborator's name |
| `role` | enum | Yes | Their role in creation |
| `sections` | array | No | Which sections they contributed to |
| `public_key` | bytes[32] | No | Their witnessd public key (if they have one) |

#### Collaborator Roles

| Value | Description |
|-------|-------------|
| `co-author` | Joint authorship, shared creative responsibility |
| `editor` | Revised/improved author's work |
| `research_assistant` | Gathered sources, data, background |
| `reviewer` | Provided feedback (no direct writing) |
| `transcriber` | Converted author's dictation/handwriting |
| `other` | Document in name field or notes |

### Statement

The `statement` field contains the author's free-form attestation. This is the legally meaningful text.

#### Statement Requirements

1. **Must be substantive:** Cannot be empty or trivial
2. **Should be truthful:** False statements may constitute fraud
3. **Should be complete:** Omission of material facts may be deceptive

#### Example Statements

**No AI usage:**
```
I hereby declare that this document was authored entirely by me without
the assistance of any artificial intelligence tools. All ideas, research,
writing, and editing were performed by me personally. I understand that
making a false declaration may constitute academic misconduct and/or fraud.
```

**With AI assistance:**
```
I declare that I authored this document with assistance from Claude (Anthropic).
I used Claude to brainstorm initial ideas and to receive feedback on my draft
arguments. The final text was written and edited by me. Approximately 90% of
the content reflects my original writing; approximately 10% incorporates
suggestions from Claude that I reviewed, modified, and approved. I take full
responsibility for the accuracy and quality of this work.
```

**Collaborative work:**
```
This document was co-authored by myself and Dr. Jane Smith. I was primarily
responsible for the Introduction and Discussion sections. Dr. Smith authored
the Methods and Results sections. We jointly edited the entire document.
Neither of us used AI assistance in creating this work.
```

## Cryptographic Binding

### Signature Payload

The signature covers a canonical hash of declaration fields. The payload is computed deterministically to ensure cross-platform verification.

```go
// ComputeSigningPayload computes the canonical payload for signing a declaration.
// This payload is hashed and signed with Ed25519.
func ComputeSigningPayload(d *Declaration) ([]byte, error) {
    h := sha256.New()

    // Protocol prefix for domain separation
    h.Write([]byte("witnessd-declaration-v1"))

    // Document binding (32 bytes each, must be hex-decoded)
    docHash, err := hex.DecodeString(d.DocumentHash)
    if err != nil || len(docHash) != 32 {
        return nil, errors.New("invalid document_hash")
    }
    h.Write(docHash)

    chainHash, err := hex.DecodeString(d.ChainHash)
    if err != nil || len(chainHash) != 32 {
        return nil, errors.New("invalid chain_hash")
    }
    h.Write(chainHash)

    // Title (length-prefixed UTF-8)
    titleBytes := []byte(d.Title)
    var buf [8]byte
    binary.BigEndian.PutUint64(buf[:], uint64(len(titleBytes)))
    h.Write(buf[:])
    h.Write(titleBytes)

    // Input modalities (sorted by type for determinism)
    sorted := make([]InputModality, len(d.InputModalities))
    copy(sorted, d.InputModalities)
    sort.Slice(sorted, func(i, j int) bool {
        return sorted[i].Type < sorted[j].Type
    })

    binary.BigEndian.PutUint64(buf[:], uint64(len(sorted)))
    h.Write(buf[:])

    for _, m := range sorted {
        typeBytes := []byte(m.Type)
        binary.BigEndian.PutUint64(buf[:], uint64(len(typeBytes)))
        h.Write(buf[:])
        h.Write(typeBytes)

        // Percentage as fixed-point (multiply by 1000 for 3 decimal places)
        pctFixed := uint64(m.Percentage * 1000)
        binary.BigEndian.PutUint64(buf[:], pctFixed)
        h.Write(buf[:])
    }

    // AI tools (sorted by tool name for determinism)
    if d.AITools != nil {
        sortedAI := make([]AIToolUsage, len(d.AITools))
        copy(sortedAI, d.AITools)
        sort.Slice(sortedAI, func(i, j int) bool {
            return sortedAI[i].Tool < sortedAI[j].Tool
        })

        binary.BigEndian.PutUint64(buf[:], uint64(len(sortedAI)))
        h.Write(buf[:])

        for _, ai := range sortedAI {
            toolBytes := []byte(ai.Tool)
            binary.BigEndian.PutUint64(buf[:], uint64(len(toolBytes)))
            h.Write(buf[:])
            h.Write(toolBytes)

            purposeBytes := []byte(ai.Purpose)
            binary.BigEndian.PutUint64(buf[:], uint64(len(purposeBytes)))
            h.Write(buf[:])
            h.Write(purposeBytes)

            extentBytes := []byte(ai.Extent)
            binary.BigEndian.PutUint64(buf[:], uint64(len(extentBytes)))
            h.Write(buf[:])
            h.Write(extentBytes)
        }
    } else {
        // Explicit: no AI tools array (distinct from empty array)
        // Use max uint64 as sentinel for "not declared"
        binary.BigEndian.PutUint64(buf[:], ^uint64(0))
        h.Write(buf[:])
    }

    // Statement (length-prefixed UTF-8)
    stmtBytes := []byte(d.Statement)
    binary.BigEndian.PutUint64(buf[:], uint64(len(stmtBytes)))
    h.Write(buf[:])
    h.Write(stmtBytes)

    // Timestamp (Unix nanoseconds for precision)
    binary.BigEndian.PutUint64(buf[:], uint64(d.CreatedAt.UnixNano()))
    h.Write(buf[:])

    // Author public key (32 bytes)
    pubKey, err := base64.StdEncoding.DecodeString(d.AuthorPublicKey)
    if err != nil {
        // Try hex decoding as fallback
        pubKey, err = hex.DecodeString(d.AuthorPublicKey)
    }
    if err != nil || len(pubKey) != 32 {
        return nil, errors.New("invalid author_public_key")
    }
    h.Write(pubKey)

    return h.Sum(nil), nil
}

// SignDeclaration signs a declaration with the given Ed25519 private key.
func SignDeclaration(d *Declaration, privateKey ed25519.PrivateKey) error {
    payload, err := ComputeSigningPayload(d)
    if err != nil {
        return fmt.Errorf("computing payload: %w", err)
    }

    signature := ed25519.Sign(privateKey, payload)
    d.Signature = base64.StdEncoding.EncodeToString(signature)
    return nil
}

// VerifyDeclaration verifies a declaration's signature.
func VerifyDeclaration(d *Declaration) error {
    // Decode public key
    pubKey, err := base64.StdEncoding.DecodeString(d.AuthorPublicKey)
    if err != nil {
        pubKey, err = hex.DecodeString(d.AuthorPublicKey)
    }
    if err != nil || len(pubKey) != ed25519.PublicKeySize {
        return errors.New("invalid author_public_key: must be 32 bytes")
    }

    // Decode signature
    sig, err := base64.StdEncoding.DecodeString(d.Signature)
    if err != nil {
        sig, err = hex.DecodeString(d.Signature)
    }
    if err != nil || len(sig) != ed25519.SignatureSize {
        return errors.New("invalid signature: must be 64 bytes")
    }

    // Recompute payload
    payload, err := ComputeSigningPayload(d)
    if err != nil {
        return fmt.Errorf("computing payload: %w", err)
    }

    // Verify
    if !ed25519.Verify(pubKey, payload, sig) {
        return errors.New("signature verification failed")
    }

    return nil
}
```

### Payload Construction Rules

1. **Domain Separation**: Prefix with `"witnessd-declaration-v1"` to prevent cross-protocol attacks
2. **Determinism**: Sort arrays before hashing (modalities by type, AI tools by name)
3. **Length Prefixing**: All variable-length strings are prefixed with 8-byte big-endian length
4. **Fixed-Point**: Percentages stored as integer × 1000 (e.g., 95.5% → 95500)
5. **Sentinel Values**: Use `^uint64(0)` (max uint64) to distinguish "not declared" from empty array
6. **Encoding Flexibility**: Accept both base64 and hex for keys/signatures

### Verification

To verify a declaration:

1. Check `author_public_key` decodes to exactly 32 bytes (Ed25519 public key)
2. Check `signature` decodes to exactly 64 bytes (Ed25519 signature)
3. Recompute the signing payload using `ComputeSigningPayload`
4. Verify `ed25519.Verify(author_public_key, payload, signature)`

A valid signature proves:
- The declaration was made by the holder of the private key
- The declaration has not been modified since signing
- The declaration is bound to the specific document and chain hashes

## Legal Considerations

### Jurisdiction

Process declarations are designed to be legally meaningful across jurisdictions, but specific implications vary:

| Jurisdiction | Potential Framework |
|--------------|---------------------|
| United States | Contract law, fraud statutes, academic honor codes |
| European Union | National contract law, electronic signature regulations |
| United Kingdom | Fraud Act 2006, contract law |
| Academic | Institution-specific honor codes and policies |

### Recommended Legal Language

For maximum legal effect, consider including:

1. **Acknowledgment of consequences:**
   "I understand that making a false declaration may result in [specific consequences]."

2. **Explicit affirmation:**
   "I affirm under penalty of [perjury/disciplinary action/etc.] that the above is true."

3. **Jurisdiction selection:**
   "This declaration shall be governed by the laws of [jurisdiction]."

### Institutional Integration

Institutions should define:
- What level of AI assistance is acceptable
- What constitutes a material omission
- Consequences for false declarations
- Process for challenging declarations

## Versioning

### Schema Version

The `version` field indicates the schema version:
- **Version 1:** Current specification (this document)
- Future versions will maintain backwards compatibility where possible

### Forwards Compatibility

Implementations should:
- Ignore unknown fields (allow extension)
- Fail on unknown enum values (prevent misinterpretation)
- Require minimum version for security-critical features

## Examples

### Example 1: No AI, Solo Author

```json
{
  "document_hash": "a3f2b8c9d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1",
  "chain_hash": "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b",
  "title": "Analysis of Market Trends Q4 2025",
  "input_modalities": [
    {
      "type": "keyboard",
      "percentage": 100.0,
      "note": ""
    }
  ],
  "ai_tools": [],
  "collaborators": [],
  "statement": "I hereby declare that this document was authored entirely by me without any AI assistance. All analysis, writing, and conclusions are my own work.",
  "created_at": "2026-01-25T14:30:00Z",
  "version": 1,
  "author_public_key": "mC5qZ3JkYXNkZmFzZGZhc2RmYXNkZmFzZGZhc2Rm",
  "signature": "c2lnbmF0dXJlLi4u..."
}
```

### Example 2: AI-Assisted Academic Paper

```json
{
  "document_hash": "b4e3c2d1a0f9e8d7c6b5a4938271605f4e3d2c1b0a9f8e7d6c5b4a3928170",
  "chain_hash": "2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3",
  "title": "Machine Learning Applications in Climate Modeling",
  "input_modalities": [
    {
      "type": "keyboard",
      "percentage": 92.0,
      "note": "Primary writing"
    },
    {
      "type": "paste",
      "percentage": 8.0,
      "note": "Code snippets and citations"
    }
  ],
  "ai_tools": [
    {
      "tool": "Claude",
      "version": "3.5 Sonnet",
      "purpose": "feedback",
      "interaction": "Requested critique of argument structure in Discussion section",
      "extent": "minimal",
      "sections": ["Discussion"]
    },
    {
      "tool": "GitHub Copilot",
      "version": "",
      "purpose": "drafting",
      "interaction": "Code completion for Python data processing scripts",
      "extent": "moderate",
      "sections": ["Methods", "Appendix A"]
    }
  ],
  "collaborators": [
    {
      "name": "Dr. Sarah Chen",
      "role": "co-author",
      "sections": ["Methods", "Results"],
      "public_key": ""
    }
  ],
  "statement": "This paper was co-authored by myself and Dr. Sarah Chen. I was responsible for the Introduction, Discussion, and Conclusion. Dr. Chen authored the Methods and Results sections. We used Claude for feedback on argument structure (minimal use) and GitHub Copilot for code completion in our analysis scripts (moderate use). All scientific claims and interpretations are our own. We affirm this declaration is complete and accurate.",
  "created_at": "2026-01-25T16:45:00Z",
  "version": 1,
  "author_public_key": "dGhpc2lzYXB1YmxpY2tleWZvcnRlc3Rpbmc=",
  "signature": "c2lnbmF0dXJlZGF0YWhlcmU=..."
}
```

### Example 3: Substantial AI Assistance (Honest Declaration)

```json
{
  "document_hash": "c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6",
  "chain_hash": "3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c",
  "title": "Internal Process Documentation: API Integration Guide",
  "input_modalities": [
    {
      "type": "keyboard",
      "percentage": 40.0,
      "note": "Editing, customization, review"
    },
    {
      "type": "paste",
      "percentage": 60.0,
      "note": "AI-generated drafts"
    }
  ],
  "ai_tools": [
    {
      "tool": "Claude",
      "version": "Opus 4.5",
      "purpose": "drafting",
      "interaction": "Generated initial drafts of all sections based on my specifications and API documentation",
      "extent": "substantial",
      "sections": ["All sections"]
    }
  ],
  "collaborators": [],
  "statement": "This documentation was created with substantial AI assistance. I provided specifications, examples, and the API reference to Claude, which generated initial drafts. I then edited, verified, and customized all content. The technical accuracy has been verified through testing. This level of AI assistance is authorized for internal documentation per company policy.",
  "created_at": "2026-01-25T09:15:00Z",
  "version": 1,
  "author_public_key": "aW50ZXJuYWxkb2NzcHVibGlja2V5",
  "signature": "aW50ZXJuYWxkb2Nzc2lnbmF0dXJl..."
}
```

## Implementation Notes

### Validation Rules

1. `document_hash` and `chain_hash` must be exactly 32 bytes
2. `title` must be non-empty
3. `input_modalities` must have at least one entry
4. Modality percentages must sum to 95-105% (allow rounding tolerance)
5. Each modality percentage must be 0-100
6. `statement` must be non-empty
7. `version` must be a supported version number
8. `author_public_key` must be exactly 32 bytes (Ed25519)
9. `signature` must be exactly 64 bytes (Ed25519)

### Privacy Considerations

Process declarations may reveal:
- AI tools the author has access to
- Collaboration relationships
- Workflow patterns

For sensitive contexts, consider:
- Minimizing optional fields
- Using generic tool names where acceptable
- Keeping collaborator details vague if privacy is needed

## References

- Ed25519: RFC 8032, Edwards-Curve Digital Signature Algorithm
- SHA-256: FIPS 180-4, Secure Hash Standard
- ETSI EN 319 612: EU Trusted Lists format specification
- IEEE 2410-2019: Biometric Open Protocol Standard (for context on attestation)
