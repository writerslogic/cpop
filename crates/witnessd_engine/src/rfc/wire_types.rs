// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Spec-conformant wire format types for draft-condrey-rats-pop CDDL schema.
//!
//! This module implements ALL CDDL-defined types from the witnessd-pop.cddl schema
//! as Rust structs with serde + CBOR serialization. All map keys use integer encoding
//! per IETF CBOR conventions, matching the CDDL definitions exactly.
//!
//! These types are designed for wire-format serialization and are separate from the
//! internal types used by the engine. Conversion traits (`From`) bridge between
//! internal and wire representations.
//!
//! # CBOR Tags
//!
//! - Evidence Packet: `#6.1129336656` ("CPOP")
//! - Attestation Result: `#6.1129791826` ("CWAR")

use serde::{Deserialize, Serialize};

use crate::codec::{self, CodecError, CBOR_TAG_PPP, CBOR_TAG_WAR};

// ============================================================
// CBOR Tag Constants (re-exported for convenience)
// ============================================================

/// CBOR tag for Evidence Packets: 1129336656 (0x434F5050 = "CPOP")
pub const CBOR_TAG_EVIDENCE_PACKET: u64 = CBOR_TAG_PPP;

/// CBOR tag for Attestation Results: 1129791826 (0x43574152 = "CWAR")
pub const CBOR_TAG_ATTESTATION_RESULT: u64 = CBOR_TAG_WAR;

// ============================================================
// Enumerations
// ============================================================

/// Hash algorithm identifier per CDDL `hash-algorithm`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum HashAlgorithm {
    /// SHA-256 (32-byte digest)
    Sha256 = 1,
    /// SHA-384 (48-byte digest)
    Sha384 = 2,
    /// SHA-512 (64-byte digest)
    Sha512 = 3,
}

/// Attestation tier per CDDL `attestation-tier`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AttestationTier {
    /// T1: Software-only (AAL1)
    SoftwareOnly = 1,
    /// T2: Attested software (AAL2)
    AttestedSoftware = 2,
    /// T3: Hardware-bound (AAL3)
    HardwareBound = 3,
    /// T4: Hardware-hardened (LoA4)
    HardwareHardened = 4,
}

/// Content tier per CDDL `content-tier`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ContentTier {
    /// Core tier: minimal required evidence
    Core = 1,
    /// Enhanced tier: additional behavioral evidence
    Enhanced = 2,
    /// Maximum tier: full evidence including hardware
    Maximum = 3,
}

/// Proof algorithm identifier per CDDL `proof-algorithm`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ProofAlgorithm {
    /// Sequential work function using Argon2id
    SwfArgon2id = 20,
    /// Entangled sequential work function using Argon2id
    SwfArgon2idEntangled = 21,
}

/// Appraisal verdict per CDDL `verdict`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Verdict {
    /// Consistent with human authorship
    Authentic = 1,
    /// Insufficient evidence
    Inconclusive = 2,
    /// Anomalies detected
    Suspicious = 3,
    /// Chain broken or forged
    Invalid = 4,
}

/// Hash salt mode per CDDL `hash-salt-mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum HashSaltMode {
    /// No salt applied
    Unsalted = 0,
    /// Author-provided salt
    AuthorSalted = 1,
}

/// Cost unit for forgery estimates per CDDL `cost-unit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum CostUnit {
    /// US Dollars
    Usd = 1,
    /// CPU hours
    CpuHours = 2,
}

/// Absence claim type per CDDL `absence-type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AbsenceType {
    /// Verifiable from evidence alone
    ComputationallyBound = 1,
    /// Requires trust in AE monitoring
    MonitoringDependent = 2,
    /// Environmental assertions
    Environmental = 3,
}

/// Active probe type per CDDL `probe-type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ProbeType {
    /// Galton invariant challenge
    GaltonBoard = 1,
    /// Motor reflex timing gate
    ReflexGate = 2,
    /// Spatial accuracy challenge
    SpatialTarget = 3,
}

/// Channel binding type per CDDL `binding-type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum BindingType {
    /// TLS Exporter Key Material
    TlsExporter = 1,
}

// ============================================================
// Base Types
// ============================================================

/// Cryptographic hash value per CDDL `hash-value`.
///
/// ```cddl
/// hash-value = {
///     1 => hash-algorithm,
///     2 => bstr,
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashValue {
    /// Hash algorithm used
    #[serde(rename = "1")]
    pub algorithm: HashAlgorithm,

    /// Raw digest bytes
    #[serde(rename = "2", with = "serde_bytes")]
    pub digest: Vec<u8>,
}

impl HashValue {
    /// Create a new SHA-256 hash value from a 32-byte digest.
    pub fn sha256(digest: Vec<u8>) -> Self {
        Self {
            algorithm: HashAlgorithm::Sha256,
            digest,
        }
    }

    /// Create a new SHA-384 hash value from a 48-byte digest.
    pub fn sha384(digest: Vec<u8>) -> Self {
        Self {
            algorithm: HashAlgorithm::Sha384,
            digest,
        }
    }

    /// Create a new SHA-512 hash value from a 64-byte digest.
    pub fn sha512(digest: Vec<u8>) -> Self {
        Self {
            algorithm: HashAlgorithm::Sha512,
            digest,
        }
    }

    /// Create a zero-valued SHA-256 hash (for prev_hash of first checkpoint).
    pub fn zero_sha256() -> Self {
        Self {
            algorithm: HashAlgorithm::Sha256,
            digest: vec![0u8; 32],
        }
    }
}

/// Compact evidence reference per CDDL `compact-ref`.
///
/// ```cddl
/// compact-ref = {
///     1 => hash-algorithm,
///     2 => bstr .size (8..32),
///     3 => uint,
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactRef {
    /// Algorithm used for the full hash
    #[serde(rename = "1")]
    pub algorithm: HashAlgorithm,

    /// Truncated digest (8-32 bytes)
    #[serde(rename = "2", with = "serde_bytes")]
    pub truncated_digest: Vec<u8>,

    /// Prefix length (number of bytes from full digest)
    #[serde(rename = "3")]
    pub prefix_length: u64,
}

/// Time window per CDDL `time-window`.
///
/// ```cddl
/// time-window = {
///     1 => pop-timestamp,
///     2 => pop-timestamp,
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeWindow {
    /// Start timestamp (epoch milliseconds)
    #[serde(rename = "1")]
    pub start: u64,

    /// End timestamp (epoch milliseconds)
    #[serde(rename = "2")]
    pub end: u64,
}

// ============================================================
// Core Structures
// ============================================================

/// Document reference per CDDL `document-ref`.
///
/// ```cddl
/// document-ref = {
///     1 => hash-value,
///     ? 2 => tstr,
///     3 => uint,
///     4 => uint,
///     ? 5 => hash-salt-mode,
///     ? 6 => hash-digest,
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentRef {
    /// Content hash of the document
    #[serde(rename = "1")]
    pub content_hash: HashValue,

    /// Optional filename
    #[serde(rename = "2", default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,

    /// Total byte length of document
    #[serde(rename = "3")]
    pub byte_length: u64,

    /// Character count of document
    #[serde(rename = "4")]
    pub char_count: u64,

    /// Hash salting mode
    #[serde(rename = "5", default, skip_serializing_if = "Option::is_none")]
    pub salt_mode: Option<HashSaltMode>,

    /// Salt commitment (hash of author salt)
    #[serde(
        rename = "6",
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_bytes_opt"
    )]
    pub salt_commitment: Option<Vec<u8>>,
}

/// Edit delta per CDDL `edit-delta`.
///
/// ```cddl
/// edit-delta = {
///     1 => uint,
///     2 => uint,
///     3 => uint,
///     ? 4 => [* edit-position],
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditDelta {
    /// Characters added in this checkpoint interval
    #[serde(rename = "1")]
    pub chars_added: u64,

    /// Characters deleted in this checkpoint interval
    #[serde(rename = "2")]
    pub chars_deleted: u64,

    /// Number of edit operations
    #[serde(rename = "3")]
    pub op_count: u64,

    /// Optional position-change pairs (offset, change)
    #[serde(rename = "4", default, skip_serializing_if = "Option::is_none")]
    pub positions: Option<Vec<(u64, i64)>>,
}

/// Proof parameters per CDDL `proof-params`.
///
/// ```cddl
/// proof-params = {
///     1 => uint,  ; time-cost
///     2 => uint,  ; memory-cost (KiB)
///     3 => uint,  ; parallelism
///     4 => uint,  ; iterations
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofParams {
    /// Time cost parameter (t)
    #[serde(rename = "1")]
    pub time_cost: u64,

    /// Memory cost parameter (m, in KiB)
    #[serde(rename = "2")]
    pub memory_cost: u64,

    /// Parallelism parameter (p)
    #[serde(rename = "3")]
    pub parallelism: u64,

    /// Number of iterations
    #[serde(rename = "4")]
    pub iterations: u64,
}

/// Merkle proof per CDDL `merkle-proof`.
///
/// ```cddl
/// merkle-proof = {
///     1 => uint,
///     2 => [+ hash-digest],
///     3 => hash-digest,
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Index of the leaf in the Merkle tree
    #[serde(rename = "1")]
    pub leaf_index: u64,

    /// Sibling path hashes from leaf to root
    #[serde(rename = "2")]
    pub sibling_path: Vec<serde_bytes::ByteBuf>,

    /// The leaf value being proved
    #[serde(rename = "3", with = "serde_bytes")]
    pub leaf_value: Vec<u8>,
}

/// Sequential work function proof per CDDL `process-proof`.
///
/// ```cddl
/// process-proof = {
///     1 => proof-algorithm,
///     2 => proof-params,
///     3 => hash-digest,
///     4 => hash-digest,
///     5 => [+ merkle-proof],
///     6 => uint,
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessProof {
    /// Algorithm identifier
    #[serde(rename = "1")]
    pub algorithm: ProofAlgorithm,

    /// SWF parameters
    #[serde(rename = "2")]
    pub params: ProofParams,

    /// Input seed (hash digest)
    #[serde(rename = "3", with = "serde_bytes")]
    pub input: Vec<u8>,

    /// Merkle root of computation chain
    #[serde(rename = "4", with = "serde_bytes")]
    pub merkle_root: Vec<u8>,

    /// Sampled Merkle proofs for verification
    #[serde(rename = "5")]
    pub sampled_proofs: Vec<MerkleProof>,

    /// Claimed duration in milliseconds
    #[serde(rename = "6")]
    pub claimed_duration: u64,
}

/// Jitter binding (behavioral entropy) per CDDL `jitter-binding`.
///
/// ```cddl
/// jitter-binding = {
///     1 => [+ uint],
///     2 => uint,
///     3 => hash-digest,
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JitterBindingWire {
    /// Inter-keystroke intervals in milliseconds
    #[serde(rename = "1")]
    pub intervals: Vec<u64>,

    /// Entropy estimate in centibits
    #[serde(rename = "2")]
    pub entropy_estimate: u64,

    /// Jitter seal (HMAC commitment)
    #[serde(rename = "3", with = "serde_bytes")]
    pub jitter_seal: Vec<u8>,
}

/// Physical state binding per CDDL `physical-state`.
///
/// ```cddl
/// physical-state = {
///     1 => [+ int],
///     2 => int,
///     ? 3 => bstr .size 32,
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhysicalState {
    /// Thermal readings (relative, millidegrees)
    #[serde(rename = "1")]
    pub thermal: Vec<i64>,

    /// Entropy delta (signed)
    #[serde(rename = "2")]
    pub entropy_delta: i64,

    /// Optional kernel commitment (32 bytes)
    #[serde(
        rename = "3",
        default,
        skip_serializing_if = "Option::is_none",
        with = "fixed_bytes_32_opt"
    )]
    pub kernel_commitment: Option<[u8; 32]>,
}

/// Physical liveness markers per CDDL `physical-liveness`.
///
/// ```cddl
/// physical-liveness = {
///     1 => [+ thermal-sample],
///     2 => bstr .size 32,
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhysicalLiveness {
    /// Thermal trajectory samples (timestamp, temperature delta in millidegrees)
    #[serde(rename = "1")]
    pub thermal_trajectory: Vec<(u64, i64)>,

    /// Entropy anchor (32 bytes)
    #[serde(rename = "2", with = "fixed_bytes_32")]
    pub entropy_anchor: [u8; 32],
}

/// Presence challenge per CDDL `presence-challenge`.
///
/// ```cddl
/// presence-challenge = {
///     1 => bstr .size (16..256),
///     2 => bstr,
///     3 => pop-timestamp,
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresenceChallenge {
    /// Challenge nonce (128+ bits)
    #[serde(rename = "1", with = "serde_bytes")]
    pub challenge_nonce: Vec<u8>,

    /// Device signature (COSE_Sign1)
    #[serde(rename = "2", with = "serde_bytes")]
    pub device_signature: Vec<u8>,

    /// Response time (epoch milliseconds)
    #[serde(rename = "3")]
    pub response_time: u64,
}

/// Channel binding per CDDL `channel-binding`.
///
/// ```cddl
/// channel-binding = {
///     1 => binding-type,
///     2 => bstr .size 32,
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelBinding {
    /// Binding type
    #[serde(rename = "1")]
    pub binding_type: BindingType,

    /// Binding value (EKM output, 32 bytes)
    #[serde(rename = "2", with = "fixed_bytes_32")]
    pub binding_value: [u8; 32],
}

/// Self-receipt for cross-tool composition per CDDL `self-receipt`.
///
/// ```cddl
/// self-receipt = {
///     1 => tstr,
///     2 => hash-value / compact-ref,
///     3 => hash-value / compact-ref,
///     4 => pop-timestamp,
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfReceipt {
    /// Tool identifier (source environment)
    #[serde(rename = "1")]
    pub tool_id: String,

    /// Output commitment (hash of tool output)
    #[serde(rename = "2")]
    pub output_commit: HashValue,

    /// Evidence reference (hash of source evidence packet)
    #[serde(rename = "3")]
    pub evidence_ref: HashValue,

    /// Transfer time (epoch milliseconds)
    #[serde(rename = "4")]
    pub transfer_time: u64,
}

/// Active liveness probe per CDDL `active-probe`.
///
/// ```cddl
/// active-probe = {
///     1 => probe-type,
///     2 => pop-timestamp,
///     3 => pop-timestamp,
///     4 => bstr,
///     5 => bstr,
///     ? 6 => uint,
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveProbe {
    /// Challenge category
    #[serde(rename = "1")]
    pub probe_type: ProbeType,

    /// Stimulus delivery time (epoch milliseconds)
    #[serde(rename = "2")]
    pub stimulus_time: u64,

    /// Response capture time (epoch milliseconds)
    #[serde(rename = "3")]
    pub response_time: u64,

    /// Stimulus data (challenge payload)
    #[serde(rename = "4", with = "serde_bytes")]
    pub stimulus_data: Vec<u8>,

    /// Response data (captured response)
    #[serde(rename = "5", with = "serde_bytes")]
    pub response_data: Vec<u8>,

    /// Optional response latency in milliseconds
    #[serde(rename = "6", default, skip_serializing_if = "Option::is_none")]
    pub response_latency: Option<u64>,
}

/// Profile declaration per CDDL `profile-declaration`.
///
/// ```cddl
/// profile-declaration = {
///     1 => tstr,
///     2 => [+ uint],
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileDeclarationWire {
    /// Profile identifier URI
    #[serde(rename = "1")]
    pub profile_id: String,

    /// Feature flags (list of enabled feature IDs)
    #[serde(rename = "2")]
    pub feature_flags: Vec<u64>,
}

// ============================================================
// Checkpoint
// ============================================================

/// Wire-format checkpoint per CDDL `checkpoint`.
///
/// ```cddl
/// checkpoint = {
///     1 => uint,               ; sequence
///     2 => uuid,               ; checkpoint-id
///     3 => pop-timestamp,      ; timestamp
///     4 => hash-value,         ; content-hash
///     5 => uint,               ; char-count
///     6 => edit-delta,         ; delta
///     7 => hash-value,         ; prev-hash
///     8 => hash-value,         ; checkpoint-hash
///     9 => process-proof,      ; SWF proof
///     ? 10 => jitter-binding,
///     ? 11 => physical-state,
///     ? 12 => hash-digest,     ; entangled-mac
///     ? 13 => [+ self-receipt],
///     ? 14 => [+ active-probe],
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointWire {
    /// Monotonically increasing sequence number
    #[serde(rename = "1")]
    pub sequence: u64,

    /// Unique checkpoint identifier (UUID as 16-byte array)
    #[serde(rename = "2", with = "fixed_bytes_16")]
    pub checkpoint_id: [u8; 16],

    /// Local timestamp (epoch milliseconds)
    #[serde(rename = "3")]
    pub timestamp: u64,

    /// Hash of document content at this checkpoint
    #[serde(rename = "4")]
    pub content_hash: HashValue,

    /// Character count at this checkpoint
    #[serde(rename = "5")]
    pub char_count: u64,

    /// Edit delta since previous checkpoint
    #[serde(rename = "6")]
    pub delta: EditDelta,

    /// Hash of the previous checkpoint (zeros for first)
    #[serde(rename = "7")]
    pub prev_hash: HashValue,

    /// Hash of this checkpoint structure
    #[serde(rename = "8")]
    pub checkpoint_hash: HashValue,

    /// Sequential work function proof
    #[serde(rename = "9")]
    pub process_proof: ProcessProof,

    /// Behavioral entropy binding (ENHANCED+)
    #[serde(rename = "10", default, skip_serializing_if = "Option::is_none")]
    pub jitter_binding: Option<JitterBindingWire>,

    /// Physical state binding (ENHANCED+)
    #[serde(rename = "11", default, skip_serializing_if = "Option::is_none")]
    pub physical_state: Option<PhysicalState>,

    /// Entangled MAC (ENHANCED+)
    #[serde(
        rename = "12",
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_bytes_opt"
    )]
    pub entangled_mac: Option<Vec<u8>>,

    /// Cross-tool composition receipts
    #[serde(rename = "13", default, skip_serializing_if = "Option::is_none")]
    pub self_receipts: Option<Vec<SelfReceipt>>,

    /// Active liveness probes
    #[serde(rename = "14", default, skip_serializing_if = "Option::is_none")]
    pub active_probes: Option<Vec<ActiveProbe>>,
}

// ============================================================
// Evidence Packet
// ============================================================

/// Wire-format evidence packet per CDDL `evidence-packet`.
///
/// Wrapped with CBOR tag 1129336656 for transmission.
///
/// ```cddl
/// evidence-packet = {
///     1 => uint,                    ; version
///     2 => tstr,                    ; profile-uri
///     3 => uuid,                    ; packet-id
///     4 => pop-timestamp,           ; created
///     5 => document-ref,            ; document
///     6 => [3* checkpoint],         ; checkpoints (min 3)
///     ? 7 => attestation-tier,
///     ? 8 => [* tstr],              ; limitations
///     ? 9 => profile-declaration,
///     ? 10 => [+ presence-challenge],
///     ? 11 => channel-binding,
///     ? 13 => content-tier,
///     ? 14 => hash-value,           ; previous-packet-ref
///     ? 15 => uint,                 ; packet-sequence
///     ? 18 => physical-liveness,
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidencePacketWire {
    /// Schema version (MUST be 1)
    #[serde(rename = "1")]
    pub version: u64,

    /// Profile URI
    #[serde(rename = "2")]
    pub profile_uri: String,

    /// Packet identifier (UUID as 16-byte array)
    #[serde(rename = "3", with = "fixed_bytes_16")]
    pub packet_id: [u8; 16],

    /// Creation timestamp (epoch milliseconds)
    #[serde(rename = "4")]
    pub created: u64,

    /// Document reference
    #[serde(rename = "5")]
    pub document: DocumentRef,

    /// Checkpoint chain (minimum 3 required)
    #[serde(rename = "6")]
    pub checkpoints: Vec<CheckpointWire>,

    /// Attestation tier (T1-T4)
    #[serde(rename = "7", default, skip_serializing_if = "Option::is_none")]
    pub attestation_tier: Option<AttestationTier>,

    /// Known limitations
    #[serde(rename = "8", default, skip_serializing_if = "Option::is_none")]
    pub limitations: Option<Vec<String>>,

    /// Profile declaration
    #[serde(rename = "9", default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<ProfileDeclarationWire>,

    /// Presence challenges (QR/OOB proofs)
    #[serde(rename = "10", default, skip_serializing_if = "Option::is_none")]
    pub presence_challenges: Option<Vec<PresenceChallenge>>,

    /// Channel binding (TLS EKM)
    #[serde(rename = "11", default, skip_serializing_if = "Option::is_none")]
    pub channel_binding: Option<ChannelBinding>,

    /// Evidence content tier
    #[serde(rename = "13", default, skip_serializing_if = "Option::is_none")]
    pub content_tier: Option<ContentTier>,

    /// Reference to previous evidence packet in a chain
    #[serde(rename = "14", default, skip_serializing_if = "Option::is_none")]
    pub previous_packet_ref: Option<HashValue>,

    /// Sequence number within a packet chain (1-based)
    #[serde(rename = "15", default, skip_serializing_if = "Option::is_none")]
    pub packet_sequence: Option<u64>,

    /// Physical liveness markers
    #[serde(rename = "18", default, skip_serializing_if = "Option::is_none")]
    pub physical_liveness: Option<PhysicalLiveness>,
}

// ============================================================
// Attestation Result (WAR)
// ============================================================

/// Entropy assessment report per CDDL `entropy-report`.
///
/// ```cddl
/// entropy-report = {
///     1 => float32,
///     2 => float32,
///     3 => float32,
///     4 => bool,
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyReport {
    /// Timing entropy (bits/sample)
    #[serde(rename = "1")]
    pub timing_entropy: f32,

    /// Revision entropy (bits)
    #[serde(rename = "2")]
    pub revision_entropy: f32,

    /// Pause entropy (bits)
    #[serde(rename = "3")]
    pub pause_entropy: f32,

    /// Whether entropy meets the required threshold
    #[serde(rename = "4")]
    pub meets_threshold: bool,
}

/// Forgery cost estimate per CDDL `forgery-cost-estimate`.
///
/// ```cddl
/// forgery-cost-estimate = {
///     1 => float32,
///     2 => float32,
///     3 => float32,
///     4 => float32,
///     5 => cost-unit,
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForgeryCostEstimate {
    /// Cost to forge sequential work function
    #[serde(rename = "1")]
    pub c_swf: f32,

    /// Cost to forge entropy
    #[serde(rename = "2")]
    pub c_entropy: f32,

    /// Cost to forge hardware attestation
    #[serde(rename = "3")]
    pub c_hardware: f32,

    /// Total forgery cost
    #[serde(rename = "4")]
    pub c_total: f32,

    /// Currency unit
    #[serde(rename = "5")]
    pub currency: CostUnit,
}

/// Absence claim per CDDL `absence-claim`.
///
/// ```cddl
/// absence-claim = {
///     1 => absence-type,
///     2 => time-window,
///     3 => tstr,
///     ? 4 => any,
///     5 => bool,
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbsenceClaim {
    /// Proof category
    #[serde(rename = "1")]
    pub absence_type: AbsenceType,

    /// Claimed time window
    #[serde(rename = "2")]
    pub window: TimeWindow,

    /// Claim identifier
    #[serde(rename = "3")]
    pub claim_id: String,

    /// Optional threshold/parameter
    #[serde(rename = "4", default, skip_serializing_if = "Option::is_none")]
    pub threshold: Option<ciborium::Value>,

    /// Assertion result
    #[serde(rename = "5")]
    pub assertion: bool,
}

/// Individual forensic flag per CDDL `forensic-flag`.
///
/// ```cddl
/// forensic-flag = {
///     1 => tstr,
///     2 => bool,
///     3 => uint,
///     4 => uint,
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicFlag {
    /// Mechanism name (e.g., "SNR", "CLC")
    #[serde(rename = "1")]
    pub mechanism: String,

    /// Whether this flag was triggered
    #[serde(rename = "2")]
    pub triggered: bool,

    /// Number of affected windows
    #[serde(rename = "3")]
    pub affected_windows: u64,

    /// Total windows evaluated
    #[serde(rename = "4")]
    pub total_windows: u64,
}

/// Forensic assessment summary per CDDL `forensic-summary`.
///
/// ```cddl
/// forensic-summary = {
///     1 => uint,
///     2 => uint,
///     3 => uint,
///     4 => uint,
///     ? 5 => [+ forensic-flag],
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicSummary {
    /// Number of forensic flags triggered
    #[serde(rename = "1")]
    pub flags_triggered: u64,

    /// Total number of flags evaluated
    #[serde(rename = "2")]
    pub flags_evaluated: u64,

    /// Number of checkpoints with anomalies
    #[serde(rename = "3")]
    pub affected_checkpoints: u64,

    /// Total number of checkpoints analyzed
    #[serde(rename = "4")]
    pub total_checkpoints: u64,

    /// Per-flag detail (optional)
    #[serde(rename = "5", default, skip_serializing_if = "Option::is_none")]
    pub flags: Option<Vec<ForensicFlag>>,
}

/// Wire-format attestation result per CDDL `attestation-result`.
///
/// Wrapped with CBOR tag 1129791826 for transmission.
///
/// ```cddl
/// attestation-result = {
///     1 => uint,                    ; version
///     2 => hash-value,              ; evidence-ref
///     3 => verdict,                 ; appraisal verdict
///     4 => attestation-tier,        ; assessed assurance level
///     5 => uint,                    ; chain-length
///     6 => uint,                    ; chain-duration (seconds)
///     ? 7 => entropy-report,
///     ? 8 => forgery-cost-estimate,
///     ? 9 => [+ absence-claim],
///     ? 10 => [* tstr],             ; warnings
///     11 => bstr,                   ; verifier-signature
///     12 => pop-timestamp,          ; created
///     ? 13 => forensic-summary,
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationResultWire {
    /// Schema version (MUST be 1)
    #[serde(rename = "1")]
    pub version: u64,

    /// Reference to the evidence packet being appraised
    #[serde(rename = "2")]
    pub evidence_ref: HashValue,

    /// Appraisal verdict
    #[serde(rename = "3")]
    pub verdict: Verdict,

    /// Assessed attestation tier
    #[serde(rename = "4")]
    pub assessed_tier: AttestationTier,

    /// Number of checkpoints in the chain
    #[serde(rename = "5")]
    pub chain_length: u64,

    /// Total chain duration in seconds
    #[serde(rename = "6")]
    pub chain_duration: u64,

    /// Entropy assessment (omit for CORE tier)
    #[serde(rename = "7", default, skip_serializing_if = "Option::is_none")]
    pub entropy_report: Option<EntropyReport>,

    /// Quantified forgery cost
    #[serde(rename = "8", default, skip_serializing_if = "Option::is_none")]
    pub forgery_cost: Option<ForgeryCostEstimate>,

    /// Absence claims (must contain at least 1 when present)
    #[serde(rename = "9", default, skip_serializing_if = "Option::is_none")]
    pub absence_claims: Option<Vec<AbsenceClaim>>,

    /// Warning messages
    #[serde(rename = "10", default, skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<String>>,

    /// Verifier signature (COSE_Sign1)
    #[serde(rename = "11", with = "serde_bytes")]
    pub verifier_signature: Vec<u8>,

    /// Appraisal timestamp (epoch milliseconds)
    #[serde(rename = "12")]
    pub created: u64,

    /// Forensic assessment summary
    #[serde(rename = "13", default, skip_serializing_if = "Option::is_none")]
    pub forensic_summary: Option<ForensicSummary>,
}

// ============================================================
// CBOR Encoding/Decoding with Tags
// ============================================================

impl EvidencePacketWire {
    /// Encode this evidence packet to CBOR with the standard tag (1129336656).
    pub fn encode_cbor(&self) -> Result<Vec<u8>, CodecError> {
        codec::cbor::encode_tagged(self, CBOR_TAG_EVIDENCE_PACKET)
    }

    /// Decode an evidence packet from tagged CBOR bytes.
    pub fn decode_cbor(data: &[u8]) -> Result<Self, CodecError> {
        codec::cbor::decode_tagged(data, CBOR_TAG_EVIDENCE_PACKET)
    }

    /// Encode this evidence packet to untagged CBOR.
    pub fn encode_cbor_untagged(&self) -> Result<Vec<u8>, CodecError> {
        codec::cbor::encode(self)
    }

    /// Decode an evidence packet from untagged CBOR bytes.
    pub fn decode_cbor_untagged(data: &[u8]) -> Result<Self, CodecError> {
        codec::cbor::decode(data)
    }
}

impl AttestationResultWire {
    /// Encode this attestation result to CBOR with the standard tag (1129791826).
    pub fn encode_cbor(&self) -> Result<Vec<u8>, CodecError> {
        codec::cbor::encode_tagged(self, CBOR_TAG_ATTESTATION_RESULT)
    }

    /// Decode an attestation result from tagged CBOR bytes.
    pub fn decode_cbor(data: &[u8]) -> Result<Self, CodecError> {
        codec::cbor::decode_tagged(data, CBOR_TAG_ATTESTATION_RESULT)
    }

    /// Encode this attestation result to untagged CBOR.
    pub fn encode_cbor_untagged(&self) -> Result<Vec<u8>, CodecError> {
        codec::cbor::encode(self)
    }

    /// Decode an attestation result from untagged CBOR bytes.
    pub fn decode_cbor_untagged(data: &[u8]) -> Result<Self, CodecError> {
        codec::cbor::decode(data)
    }
}

// ============================================================
// Serde Helpers
// ============================================================

/// Serde helper for optional byte vectors with serde_bytes.
mod serde_bytes_opt {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(bytes) => serde_bytes::serialize(bytes, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<serde_bytes::ByteBuf> = Option::deserialize(deserializer)?;
        Ok(opt.map(|b| b.into_vec()))
    }
}

/// Serde helper for 32-byte fixed arrays.
mod fixed_bytes_32 {
    use serde::{de, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_bytes::serialize(bytes.as_slice(), serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let buf: serde_bytes::ByteBuf = Deserialize::deserialize(deserializer)?;
        buf.as_ref()
            .try_into()
            .map_err(|_| de::Error::custom(format!("expected 32 bytes, got {}", buf.len())))
    }
}

/// Serde helper for optional 32-byte fixed arrays.
mod fixed_bytes_32_opt {
    use serde::{de, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Option<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(bytes) => serde_bytes::serialize(bytes.as_slice(), serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<serde_bytes::ByteBuf> = Option::deserialize(deserializer)?;
        match opt {
            Some(buf) => {
                let arr: [u8; 32] = buf.as_ref().try_into().map_err(|_| {
                    de::Error::custom(format!("expected 32 bytes, got {}", buf.len()))
                })?;
                Ok(Some(arr))
            }
            None => Ok(None),
        }
    }
}

/// Serde helper for 16-byte fixed arrays (UUIDs).
mod fixed_bytes_16 {
    use serde::{de, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 16], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_bytes::serialize(bytes.as_slice(), serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 16], D::Error>
    where
        D: Deserializer<'de>,
    {
        let buf: serde_bytes::ByteBuf = Deserialize::deserialize(deserializer)?;
        buf.as_ref()
            .try_into()
            .map_err(|_| de::Error::custom(format!("expected 16 bytes, got {}", buf.len())))
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checkpoint_wire_cbor_roundtrip() {
        let content_hash = HashValue::sha256(vec![0xAA; 32]);
        let prev_hash = HashValue::zero_sha256();
        let checkpoint_hash = HashValue::sha256(vec![0xCC; 32]);

        let checkpoint = CheckpointWire {
            sequence: 0,
            checkpoint_id: [1u8; 16],
            timestamp: 1700000000000,
            content_hash,
            char_count: 5000,
            delta: EditDelta {
                chars_added: 5000,
                chars_deleted: 0,
                op_count: 150,
                positions: None,
            },
            prev_hash,
            checkpoint_hash,
            process_proof: ProcessProof {
                algorithm: ProofAlgorithm::SwfArgon2id,
                params: ProofParams {
                    time_cost: 3,
                    memory_cost: 65536,
                    parallelism: 1,
                    iterations: 1000,
                },
                input: vec![0x11; 32],
                merkle_root: vec![0x22; 32],
                sampled_proofs: vec![MerkleProof {
                    leaf_index: 0,
                    sibling_path: vec![serde_bytes::ByteBuf::from(vec![0x33; 32])],
                    leaf_value: vec![0x44; 32],
                }],
                claimed_duration: 30000,
            },
            jitter_binding: None,
            physical_state: None,
            entangled_mac: None,
            self_receipts: None,
            active_probes: None,
        };

        let encoded = codec::cbor::encode(&checkpoint).expect("encode checkpoint");
        let decoded: CheckpointWire = codec::cbor::decode(&encoded).expect("decode checkpoint");
        assert_eq!(decoded.sequence, 0);
        assert_eq!(decoded.char_count, 5000);
        assert_eq!(decoded.delta.chars_added, 5000);
    }

    /// Create a minimal test evidence packet.
    fn create_test_evidence_packet() -> EvidencePacketWire {
        let content_hash = HashValue::sha256(vec![0xAA; 32]);
        let prev_hash = HashValue::zero_sha256();
        let checkpoint_hash = HashValue::sha256(vec![0xCC; 32]);

        let checkpoint = CheckpointWire {
            sequence: 0,
            checkpoint_id: [1u8; 16],
            timestamp: 1700000000000,
            content_hash: content_hash.clone(),
            char_count: 5000,
            delta: EditDelta {
                chars_added: 5000,
                chars_deleted: 0,
                op_count: 150,
                positions: None,
            },
            prev_hash: prev_hash.clone(),
            checkpoint_hash: checkpoint_hash.clone(),
            process_proof: ProcessProof {
                algorithm: ProofAlgorithm::SwfArgon2id,
                params: ProofParams {
                    time_cost: 3,
                    memory_cost: 65536,
                    parallelism: 1,
                    iterations: 1000,
                },
                input: vec![0x11; 32],
                merkle_root: vec![0x22; 32],
                sampled_proofs: vec![MerkleProof {
                    leaf_index: 0,
                    sibling_path: vec![serde_bytes::ByteBuf::from(vec![0x33; 32])],
                    leaf_value: vec![0x44; 32],
                }],
                claimed_duration: 30000,
            },
            jitter_binding: None,
            physical_state: None,
            entangled_mac: None,
            self_receipts: None,
            active_probes: None,
        };

        // Build 3 checkpoints (minimum required)
        let mut checkpoints = vec![checkpoint.clone()];
        for i in 1..3 {
            let mut cp = checkpoint.clone();
            cp.sequence = i;
            cp.checkpoint_id = [(i + 1) as u8; 16];
            cp.prev_hash = checkpoint_hash.clone();
            checkpoints.push(cp);
        }

        EvidencePacketWire {
            version: 1,
            profile_uri: "urn:ietf:params:rats:pop:profile:core".to_string(),
            packet_id: [0xFF; 16],
            created: 1700000000000,
            document: DocumentRef {
                content_hash: content_hash.clone(),
                filename: Some("test_document.txt".to_string()),
                byte_length: 12500,
                char_count: 5000,
                salt_mode: None,
                salt_commitment: None,
            },
            checkpoints,
            attestation_tier: Some(AttestationTier::SoftwareOnly),
            limitations: None,
            profile: None,
            presence_challenges: None,
            channel_binding: None,
            content_tier: Some(ContentTier::Core),
            previous_packet_ref: None,
            packet_sequence: None,
            physical_liveness: None,
        }
    }

    /// Create a minimal test attestation result.
    fn create_test_attestation_result() -> AttestationResultWire {
        AttestationResultWire {
            version: 1,
            evidence_ref: HashValue::sha256(vec![0xBB; 32]),
            verdict: Verdict::Authentic,
            assessed_tier: AttestationTier::SoftwareOnly,
            chain_length: 10,
            chain_duration: 3600,
            entropy_report: Some(EntropyReport {
                timing_entropy: 3.5,
                revision_entropy: 2.8,
                pause_entropy: 4.1,
                meets_threshold: true,
            }),
            forgery_cost: Some(ForgeryCostEstimate {
                c_swf: 150.0,
                c_entropy: 50.0,
                c_hardware: 0.0,
                c_total: 200.0,
                currency: CostUnit::Usd,
            }),
            absence_claims: None,
            warnings: None,
            verifier_signature: vec![0xDD; 64],
            created: 1700000000000,
            forensic_summary: Some(ForensicSummary {
                flags_triggered: 0,
                flags_evaluated: 5,
                affected_checkpoints: 0,
                total_checkpoints: 10,
                flags: Some(vec![ForensicFlag {
                    mechanism: "SNR".to_string(),
                    triggered: false,
                    affected_windows: 0,
                    total_windows: 9,
                }]),
            }),
        }
    }

    #[test]
    fn test_evidence_packet_cbor_roundtrip() {
        let packet = create_test_evidence_packet();

        // Encode with tag
        let encoded = packet.encode_cbor().expect("encode should succeed");

        // Verify tag is present
        assert!(
            codec::cbor::has_tag(&encoded, CBOR_TAG_EVIDENCE_PACKET),
            "encoded packet should have CPOP tag"
        );

        // Decode back
        let decoded = EvidencePacketWire::decode_cbor(&encoded).expect("decode should succeed");

        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.profile_uri, packet.profile_uri);
        assert_eq!(decoded.packet_id, packet.packet_id);
        assert_eq!(decoded.created, packet.created);
        assert_eq!(decoded.checkpoints.len(), 3);
        assert_eq!(
            decoded.document.content_hash.algorithm,
            HashAlgorithm::Sha256
        );
        assert_eq!(decoded.document.byte_length, 12500);
        assert_eq!(decoded.document.char_count, 5000);
        assert_eq!(
            decoded.attestation_tier,
            Some(AttestationTier::SoftwareOnly)
        );
        assert_eq!(decoded.content_tier, Some(ContentTier::Core));
    }

    #[test]
    fn test_attestation_result_cbor_roundtrip() {
        let result = create_test_attestation_result();

        // Encode with tag
        let encoded = result.encode_cbor().expect("encode should succeed");

        // Verify tag is present
        assert!(
            codec::cbor::has_tag(&encoded, CBOR_TAG_ATTESTATION_RESULT),
            "encoded result should have CWAR tag"
        );

        // Decode back
        let decoded = AttestationResultWire::decode_cbor(&encoded).expect("decode should succeed");

        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.verdict, Verdict::Authentic);
        assert_eq!(decoded.assessed_tier, AttestationTier::SoftwareOnly);
        assert_eq!(decoded.chain_length, 10);
        assert_eq!(decoded.chain_duration, 3600);
        assert_eq!(decoded.verifier_signature.len(), 64);
        assert!(decoded.entropy_report.is_some());
        assert!(decoded.forgery_cost.is_some());
        assert!(decoded.forensic_summary.is_some());
    }

    #[test]
    fn test_correct_cbor_tag_values() {
        // Verify the tag constants match the CDDL spec
        assert_eq!(
            CBOR_TAG_EVIDENCE_PACKET, 1129336656,
            "Evidence packet tag should be 1129336656 (CPOP)"
        );
        assert_eq!(
            CBOR_TAG_ATTESTATION_RESULT, 1129791826,
            "Attestation result tag should be 1129791826 (CWAR)"
        );
    }

    #[test]
    fn test_wrong_tag_rejected() {
        let packet = create_test_evidence_packet();
        let encoded = packet.encode_cbor().expect("encode");

        // Try to decode as attestation result (wrong tag)
        let result = AttestationResultWire::decode_cbor(&encoded);
        assert!(result.is_err(), "should reject wrong tag");
    }

    #[test]
    fn test_enum_values() {
        // Hash algorithms
        assert_eq!(HashAlgorithm::Sha256 as u8, 1);
        assert_eq!(HashAlgorithm::Sha384 as u8, 2);
        assert_eq!(HashAlgorithm::Sha512 as u8, 3);

        // Attestation tiers
        assert_eq!(AttestationTier::SoftwareOnly as u8, 1);
        assert_eq!(AttestationTier::AttestedSoftware as u8, 2);
        assert_eq!(AttestationTier::HardwareBound as u8, 3);
        assert_eq!(AttestationTier::HardwareHardened as u8, 4);

        // Content tiers
        assert_eq!(ContentTier::Core as u8, 1);
        assert_eq!(ContentTier::Enhanced as u8, 2);
        assert_eq!(ContentTier::Maximum as u8, 3);

        // Proof algorithms
        assert_eq!(ProofAlgorithm::SwfArgon2id as u8, 20);
        assert_eq!(ProofAlgorithm::SwfArgon2idEntangled as u8, 21);

        // Verdicts
        assert_eq!(Verdict::Authentic as u8, 1);
        assert_eq!(Verdict::Inconclusive as u8, 2);
        assert_eq!(Verdict::Suspicious as u8, 3);
        assert_eq!(Verdict::Invalid as u8, 4);

        // Hash salt modes
        assert_eq!(HashSaltMode::Unsalted as u8, 0);
        assert_eq!(HashSaltMode::AuthorSalted as u8, 1);

        // Cost units
        assert_eq!(CostUnit::Usd as u8, 1);
        assert_eq!(CostUnit::CpuHours as u8, 2);

        // Absence types
        assert_eq!(AbsenceType::ComputationallyBound as u8, 1);
        assert_eq!(AbsenceType::MonitoringDependent as u8, 2);
        assert_eq!(AbsenceType::Environmental as u8, 3);

        // Probe types
        assert_eq!(ProbeType::GaltonBoard as u8, 1);
        assert_eq!(ProbeType::ReflexGate as u8, 2);
        assert_eq!(ProbeType::SpatialTarget as u8, 3);

        // Binding types
        assert_eq!(BindingType::TlsExporter as u8, 1);
    }

    #[test]
    fn test_untagged_cbor_roundtrip() {
        let packet = create_test_evidence_packet();

        // Encode without tag
        let encoded = packet
            .encode_cbor_untagged()
            .expect("untagged encode should succeed");

        // Verify no tag
        assert!(
            !codec::cbor::has_tag(&encoded, CBOR_TAG_EVIDENCE_PACKET),
            "untagged packet should not have tag"
        );

        // Decode without tag
        let decoded = EvidencePacketWire::decode_cbor_untagged(&encoded)
            .expect("untagged decode should succeed");
        assert_eq!(decoded.version, 1);
    }

    #[test]
    fn test_evidence_packet_with_optional_fields() {
        let mut packet = create_test_evidence_packet();

        // Add optional fields
        packet.limitations = Some(vec![
            "No hardware attestation available".to_string(),
            "Single device session".to_string(),
        ]);

        packet.profile = Some(ProfileDeclarationWire {
            profile_id: "urn:ietf:params:rats:pop:profile:enhanced".to_string(),
            feature_flags: vec![1, 3, 5],
        });

        packet.previous_packet_ref = Some(HashValue::sha256(vec![0xEE; 32]));
        packet.packet_sequence = Some(2);

        // Roundtrip
        let encoded = packet.encode_cbor().expect("encode");
        let decoded = EvidencePacketWire::decode_cbor(&encoded).expect("decode");

        assert_eq!(decoded.limitations.as_ref().unwrap().len(), 2);
        assert!(decoded.profile.is_some());
        assert_eq!(
            decoded.profile.as_ref().unwrap().feature_flags,
            vec![1, 3, 5]
        );
        assert!(decoded.previous_packet_ref.is_some());
        assert_eq!(decoded.packet_sequence, Some(2));
    }

    #[test]
    fn test_checkpoint_with_jitter_and_physical() {
        let mut packet = create_test_evidence_packet();

        // Add jitter binding to first checkpoint
        packet.checkpoints[0].jitter_binding = Some(JitterBindingWire {
            intervals: vec![120, 85, 200, 150, 95, 180, 110, 160],
            entropy_estimate: 350,
            jitter_seal: vec![0x55; 32],
        });

        // Add physical state to first checkpoint
        packet.checkpoints[0].physical_state = Some(PhysicalState {
            thermal: vec![45000, 45100, 45200, 45150],
            entropy_delta: -50,
            kernel_commitment: Some([0x66; 32]),
        });

        // Add entangled MAC
        packet.checkpoints[0].entangled_mac = Some(vec![0x77; 32]);

        // Roundtrip
        let encoded = packet.encode_cbor().expect("encode");
        let decoded = EvidencePacketWire::decode_cbor(&encoded).expect("decode");

        let cp0 = &decoded.checkpoints[0];
        assert!(cp0.jitter_binding.is_some());
        let jb = cp0.jitter_binding.as_ref().unwrap();
        assert_eq!(jb.intervals.len(), 8);
        assert_eq!(jb.entropy_estimate, 350);

        assert!(cp0.physical_state.is_some());
        let ps = cp0.physical_state.as_ref().unwrap();
        assert_eq!(ps.thermal.len(), 4);
        assert_eq!(ps.entropy_delta, -50);
        assert!(ps.kernel_commitment.is_some());

        assert!(cp0.entangled_mac.is_some());
    }

    #[test]
    fn test_attestation_result_with_absence_claims() {
        let mut result = create_test_attestation_result();

        result.absence_claims = Some(vec![AbsenceClaim {
            absence_type: AbsenceType::ComputationallyBound,
            window: TimeWindow {
                start: 1700000000000,
                end: 1700003600000,
            },
            claim_id: "swf-irreversibility".to_string(),
            threshold: None,
            assertion: true,
        }]);

        result.warnings = Some(vec!["Low entropy in first checkpoint".to_string()]);

        // Roundtrip
        let encoded = result.encode_cbor().expect("encode");
        let decoded = AttestationResultWire::decode_cbor(&encoded).expect("decode");

        assert!(decoded.absence_claims.is_some());
        let claims = decoded.absence_claims.unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].absence_type, AbsenceType::ComputationallyBound);
        assert!(claims[0].assertion);

        assert!(decoded.warnings.is_some());
        assert_eq!(decoded.warnings.unwrap().len(), 1);
    }

    #[test]
    fn test_checkpoint_with_active_probes() {
        let mut packet = create_test_evidence_packet();

        packet.checkpoints[0].active_probes = Some(vec![ActiveProbe {
            probe_type: ProbeType::GaltonBoard,
            stimulus_time: 1700000001000,
            response_time: 1700000001250,
            stimulus_data: vec![0x88; 16],
            response_data: vec![0x99; 32],
            response_latency: Some(250),
        }]);

        // Roundtrip
        let encoded = packet.encode_cbor().expect("encode");
        let decoded = EvidencePacketWire::decode_cbor(&encoded).expect("decode");

        let probes = decoded.checkpoints[0].active_probes.as_ref().unwrap();
        assert_eq!(probes.len(), 1);
        assert_eq!(probes[0].probe_type, ProbeType::GaltonBoard);
        assert_eq!(probes[0].response_latency, Some(250));
    }

    #[test]
    fn test_checkpoint_with_self_receipts() {
        let mut packet = create_test_evidence_packet();

        packet.checkpoints[0].self_receipts = Some(vec![SelfReceipt {
            tool_id: "vscode-witnessd".to_string(),
            output_commit: HashValue::sha256(vec![0xAA; 32]),
            evidence_ref: HashValue::sha256(vec![0xBB; 32]),
            transfer_time: 1700000002000,
        }]);

        // Roundtrip
        let encoded = packet.encode_cbor().expect("encode");
        let decoded = EvidencePacketWire::decode_cbor(&encoded).expect("decode");

        let receipts = decoded.checkpoints[0].self_receipts.as_ref().unwrap();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].tool_id, "vscode-witnessd");
    }

    #[test]
    fn test_evidence_packet_with_physical_liveness() {
        let mut packet = create_test_evidence_packet();

        packet.physical_liveness = Some(PhysicalLiveness {
            thermal_trajectory: vec![
                (1700000000000, 45000),
                (1700000001000, 45100),
                (1700000002000, 45200),
            ],
            entropy_anchor: [0xAB; 32],
        });

        // Roundtrip
        let encoded = packet.encode_cbor().expect("encode");
        let decoded = EvidencePacketWire::decode_cbor(&encoded).expect("decode");

        assert!(decoded.physical_liveness.is_some());
        let pl = decoded.physical_liveness.unwrap();
        assert_eq!(pl.thermal_trajectory.len(), 3);
        assert_eq!(pl.entropy_anchor, [0xAB; 32]);
    }

    #[test]
    fn test_evidence_packet_with_presence_and_channel() {
        let mut packet = create_test_evidence_packet();

        packet.presence_challenges = Some(vec![PresenceChallenge {
            challenge_nonce: vec![0x11; 32],
            device_signature: vec![0x22; 64],
            response_time: 1700000001500,
        }]);

        packet.channel_binding = Some(ChannelBinding {
            binding_type: BindingType::TlsExporter,
            binding_value: [0x33; 32],
        });

        // Roundtrip
        let encoded = packet.encode_cbor().expect("encode");
        let decoded = EvidencePacketWire::decode_cbor(&encoded).expect("decode");

        assert!(decoded.presence_challenges.is_some());
        let pc = decoded.presence_challenges.as_ref().unwrap();
        assert_eq!(pc.len(), 1);
        assert_eq!(pc[0].challenge_nonce.len(), 32);

        assert!(decoded.channel_binding.is_some());
        let cb = decoded.channel_binding.as_ref().unwrap();
        assert_eq!(cb.binding_type, BindingType::TlsExporter);
        assert_eq!(cb.binding_value, [0x33; 32]);
    }

    #[test]
    fn test_hash_value_constructors() {
        let h256 = HashValue::sha256(vec![1; 32]);
        assert_eq!(h256.algorithm, HashAlgorithm::Sha256);
        assert_eq!(h256.digest.len(), 32);

        let h384 = HashValue::sha384(vec![2; 48]);
        assert_eq!(h384.algorithm, HashAlgorithm::Sha384);
        assert_eq!(h384.digest.len(), 48);

        let h512 = HashValue::sha512(vec![3; 64]);
        assert_eq!(h512.algorithm, HashAlgorithm::Sha512);
        assert_eq!(h512.digest.len(), 64);

        let zero = HashValue::zero_sha256();
        assert_eq!(zero.algorithm, HashAlgorithm::Sha256);
        assert!(zero.digest.iter().all(|&b| b == 0));
    }
}
