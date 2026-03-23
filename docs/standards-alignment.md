# CPOP Standards Alignment Map

This document maps CPOP's implementation to external standards and specifications,
documenting current alignment status, integration points, and identified gaps.

Last updated: 2026-03-18

## Alignment Summary

| Standard | Status | Integration Point |
|----------|--------|-------------------|
| IETF RATS (EAT/EAR/AR4SI) | **Strong** | Core appraisal framework |
| W3C DID Core 1.0 | **Strong** | Author identity (did:key, did:web) |
| W3C VC Data Model 2.0 | **Strong** | war/profiles/vc.rs projection |
| C2PA (ISO 19566-5) | **Good** | war/profiles/c2pa.rs assertion |
| CBOR/COSE (RFC 8949/9052) | **Strong** | Wire format + signatures |
| NIST AI RMF 1.0 | **Mapped** | war/profiles/standards.rs |
| NIST AI 100-4 | **Aligned** | Provenance metadata, watermarking |
| ISO/IEC 42001 | **Mapped** | war/profiles/standards.rs |
| IPTC Digital Source Type | **Implemented** | AiDisclosureLevel mapping |
| W3C AI Content Disclosure CG | **Implemented** | AiDisclosureLevel + HTML meta |
| WGA MBA / SAG-AFTRA | **Mapped** | CreativeRightsCompliance |
| WebAuthn/FIDO2 | Not applicable | User auth, not authorship proof |
| IEEE P3119 | Not applicable | Procurement standard, not metadata |
| NCCoE AI Agent Identity | **Partial** | DID-based author identity |

## 1. IETF RATS Working Group

### Specifications
- draft-ietf-rats-eat (Entity Attestation Token)
- draft-ietf-rats-ear (Entity Attestation Result)
- draft-ietf-rats-ar4si (Attestation Results for Secure Interactions)
- draft-condrey-rats-pop (Proof of Process — our draft)

### Implementation
- **EAT Profile URI**: `urn:ietf:params:rats:eat:profile:pop:1.0`
- **EAR Token**: Full implementation in `war/ear.rs`
- **AR4SI Trust Vector**: 8-component mapping in `war/appraisal.rs`
  - Instance Identity → hardware attestation tier
  - Configuration → declaration signature validity
  - Executables → binary attestation presence
  - File System → hash chain integrity (H1/H2/H3)
  - Hardware → TPM/Secure Enclave binding
  - Runtime Opaque → VDF proof strength + time plausibility
  - Storage Opaque → key hierarchy + session certificate
  - Sourced Data → behavioral entropy + jitter quality
- **Private-use CWT keys**: 70001-70009 for CPOP-specific claims
- **CBOR wire format**: Tagged per RFC 8949 with tags 0x43504F50 and 0x43574152

### Gap: None identified

## 2. W3C DID Core 1.0

### DID Methods Used
- `did:key:z6Mk...` — Self-sovereign Ed25519 identity (primary)
- `did:web:writerslogic.com` — Organizational issuer identity
- `did:web:writerslogic.com:authors:{id}` — API-anchored author identity

### Verification Relationships
- `assertionMethod` — Used for signing evidence packets and VCs
- `authentication` — Used for session binding (implicit via key hierarchy)

### Implementation
- DID generation in `cmd_identity.rs`
- Author DID in VC credential subject
- Verification method references in VC proof

### Gap: No formal DID Document generation/resolution

## 3. W3C Verifiable Credentials Data Model 2.0

### Implementation (`war/profiles/vc.rs`)
- `@context`: `["https://www.w3.org/ns/credentials/v2", "https://writerslogic.com/ns/pop/v1"]`
- Type: `["VerifiableCredential", "ProcessAttestationCredential"]`
- Issuer: `did:web:writerslogic.com`
- Data Integrity Proof: `eddsa-rdfc-2022` cryptosuite
- Evidence array with verifier identity
- Credential subject with author DID and process attestation

### Gap: Proof value is placeholder — actual signing at higher layer

## 4. C2PA (Content Credentials)

### Implementation (`war/profiles/c2pa.rs`)
- Assertion label: `com.writerslogic.pop-attestation.v1` (entity-specific per C2PA spec)
- Action: `c2pa.created` with IPTC `humanCreation` digital source type
- Trust vector, seal hashes, evidence reference in assertion data
- C2PA action for `c2pa.actions.v2` integration

### C2PA spec alignment (v2.3)
- **Cryptographic**: Ed25519 is in C2PA allowed algorithm list
- **Hash**: SHA-256 is in C2PA allowed hash list
- **CBOR**: Both use RFC 8949 deterministic encoding
- **Signing**: Both use COSE_Sign1 format

### Gaps
- No JUMBF container generation (C2PA manifests use JUMBF)
- No X.509 certificate chain (C2PA requires X.509)
- No hard binding (`c2pa.hash.data`) to document bytes
- No RFC 3161 time-stamp in COSE unprotected headers

### Integration path
CPOP is positioned as an **evidence source for C2PA**, not a C2PA replacement.
The assertion projection allows CPOP attestations to be consumed by C2PA manifest
generators (e.g., c2patool) as custom assertions.

## 5. CBOR/COSE (RFC 8949 / RFC 9052)

### Implementation
- **ciborium** crate for CBOR encoding (deterministic, RFC 8949 Section 4.2.1)
- **coset** crate for COSE signatures
- Custom CBOR tags: 0x43504F50 (evidence), 0x43574152 (attestation)
- Media types: `application/vnd.writersproof.cpop+cbor`, `application/vnd.writersproof.cwar+cbor`
- Ed25519 signatures via ed25519-dalek with zeroize

### Gap: None identified

## 6. NIST AI RMF 1.0 (AI 100-1) / AI 100-4

### Mapping (`war/profiles/standards.rs`)
| RMF Subcategory | CPOP Coverage |
|-----------------|---------------|
| GV-1.1 | Declaration with AI disclosure fields per EU AI Act Art. 50 |
| GV-1.2 | AR4SI trustworthiness vector (8 components) |
| MS-2.6 | Forensic assessment_score with 5 verdict levels |
| MS-2.11 | Biological plausibility ranges, not demographic profiling |
| MG-4.1 | Continuous sentinel monitoring with checkpoint chain |

### NIST AI 100-4 (Synthetic Content) alignment
- Provenance metadata: origin, timestamp, author, edit history (**implemented**)
- Watermarking: ZWC steganographic marks (**implemented**)
- Content authentication: cryptographic signatures (**implemented**)
- C2PA interoperability: assertion projection (**implemented**)

## 7. ISO/IEC 42001 (AI Management Systems)

### Mapping (`war/profiles/standards.rs`)
| Control | Topic | CPOP Coverage |
|---------|-------|---------------|
| A.6 | Data governance | HMAC chains, WAL, MMR append-only proofs |
| A.7 | System documentation | claim_generator_info with version, capabilities |
| A.8 | Transparency | Forensic verdict, confidence, limitations array |
| A.10 | Accountability | Key hierarchy ties actions to signing identity |

## 8. IPTC Digital Source Type

### Implementation (`war/profiles/standards.rs`)
| CPOP AiExtent | IPTC Source Type | W3C ai-disclosure |
|---------------|------------------|-------------------|
| None | `humanCreation` | `none` |
| Minimal | `compositeWithTrainedAlgorithmicMedia` | `ai-assisted` |
| Moderate | `compositeWithTrainedAlgorithmicMedia` | `ai-assisted` |
| Substantial | `trainedAlgorithmicMedia` | `ai-generated` |

Used in C2PA action entries via `digitalSourceType` field.

## 9. W3C AI Content Disclosure Community Group

### Implementation (`war/profiles/standards.rs`)
- `AiDisclosureLevel` enum: `none`, `ai-assisted`, `ai-generated`
- HTML meta tag generation: `<meta name="ai-disclosure" content="...">`
- Maps from CPOP declaration's `AiExtent` via `from_ai_extent()`

### Regulatory alignment
- EU AI Act Article 50 (effective August 2026): requires machine-readable
  disclosure of AI-generated content — CPOP's `AiDisclosureLevel` satisfies this

## 10. WGA MBA / SAG-AFTRA AI Provisions

### Implementation (`war/profiles/standards.rs`)
- `CreativeRightsCompliance` struct with:
  - `human_authored`: whether EAR appraisal affirms human authorship
  - `gai_source_disclosed`: whether AI tools are disclosed per WGA MBA Section 72
  - `wga_mba_compliant`: composite compliance check
  - `digital_source_type`: IPTC URI for cross-standard compatibility

### WGA MBA alignment
- "AI is not a writer": CPOP's behavioral attestation proves human authorship process
- Company disclosure obligation: CPOP's declaration records AI tool usage
- Writer consent: Declaration is author-signed, proving informed consent

### SAG-AFTRA alignment
- Content provenance chain distinguishes human-performed vs AI-generated
- Signing identity ties attestation to specific author

## 11. WebAuthn/FIDO2

### Status: Not applicable
WebAuthn proves **user presence** (button press, biometric) for authentication.
CPOP proves **authorship process** (keystrokes, timing, behavior) for content creation.
These are complementary but different concerns.

**Future opportunity**: WebAuthn assertions could supplement CPOP evidence as
additional human-presence proofs during authoring sessions.

## 12. IEEE P3119

### Status: Not applicable
IEEE P3119-2025 is a **procurement process standard** for acquiring AI systems.
It has no metadata fields or technical data structures to implement.
CPOP can reference P3119 compliance in procurement responses.

## 13. NCCoE AI Agent Identity

### Alignment
- CPOP uses DIDs for human author identity (NCCoE recommends distinguishing human/AI)
- CPOP's declaration includes `ai_tools` disclosure (distinguishes AI involvement)
- Key hierarchy with delegation supports the NCCoE's "delegation chain" model

### Gap: No explicit `author_type: human | ai_agent` field in evidence packet
(implicit via behavioral attestation — EAR verdict distinguishes human from synthetic)

---

## Code References

| Module | File | Purpose |
|--------|------|---------|
| EAR Token | `war/ear.rs` | IETF RATS EAR implementation |
| AR4SI Appraisal | `war/appraisal.rs` | Trust vector computation |
| C2PA Profile | `war/profiles/c2pa.rs` | C2PA assertion projection |
| VC Profile | `war/profiles/vc.rs` | W3C VC 2.0 projection |
| Standards Map | `war/profiles/standards.rs` | Multi-standard compliance |
| DID Identity | `cmd_identity.rs` | DID generation |
| Declaration | `declaration/types.rs` | AI disclosure (AiExtent, AiToolUsage) |
| Steganography | `steganography/` | ZWC watermarking (NIST AI 100-4) |
| Anchoring | `anchors/` | RFC 3161, OTS, blockchain timestamps |
