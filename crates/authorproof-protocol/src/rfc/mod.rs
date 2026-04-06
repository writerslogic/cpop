// SPDX-License-Identifier: Apache-2.0

//! RFC-compliant data structures for Proof-of-Process evidence.
//!
//! This module implements the CDDL-defined structures from draft-condrey-rats-pop-01
//! and draft-condrey-rats-pop-schema-01. All structures support both CBOR and JSON
//! serialization for backwards compatibility.

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

pub mod biology;
pub mod checkpoint;
pub mod fixed_point;
pub mod jitter_binding;
pub mod packet;
pub(crate) mod serde_helpers;
pub mod time_evidence;
pub mod vdf;
pub mod wire_types;

pub use biology::{
    BiologyInvariantClaim, BiologyMeasurements, BiologyScoringParameters, ValidationStatus,
};
pub use checkpoint::{BioBinding, CheckpointRfc, SaVdfProof};
pub use fixed_point::{
    Centibits, DeciWpm, Decibits, Microdollars, Millibits, RhoMillibits, SlopeDecibits,
};
pub use jitter_binding::{
    ActiveProbes, BindingMac, EntropyCommitment, GaltonInvariant, JitterBinding, JitterSummary,
    LabyrinthStructure, ReflexGate, SourceDescriptor, SourceType, ValidationFinding,
    ValidationSeverity,
};
pub use packet::{
    ContentHashTree, CorrelationProof, EnclaveVise, ErrorTopology, JitterSealStructure,
    KeyRotationMetadata, PacketRfc, PrivacyBudgetCertificate, ProfileDeclaration, VdfStructure,
    ZkProcessVerdict,
};
pub use time_evidence::{
    BlockchainAnchor, RoughtimeSample, TimeBindingTier, TimeEvidence, TsaResponse,
};
pub use vdf::{CalibrationAttestation, VdfProofRfc};
pub use wire_types::{
    AttestationResultWire, CheckpointWire, EvidencePacketWire, CBOR_TAG_ATTESTATION_RESULT,
    CBOR_TAG_EVIDENCE_PACKET,
};

/// IANA Private Enterprise Number for WritersLogic Inc.
/// Registered under SMI Network Management Private Enterprise Codes.
pub const IANA_PEN: u32 = crate::codec::IANA_PEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u64)]
pub enum HashAlgorithm {
    /// SHA-256 (32-byte digest).
    Sha256 = 1,
    /// SHA-384 (48-byte digest).
    Sha384 = 2,
    /// SHA-512 (64-byte digest).
    Sha512 = 3,
}

/// Hardware attestation strength tier per draft-condrey-rats-pop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u64)]
pub enum AttestationTier {
    /// Pure software signing, no hardware root of trust.
    SoftwareOnly = 1,
    /// Software key with remote attestation evidence.
    AttestedSoftware = 2,
    /// Key bound to TPM/Secure Enclave.
    HardwareBound = 3,
    /// Hardware-hardened with anti-tamper protections.
    HardwareHardened = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u64)]
pub enum ContentTier {
    /// Minimal evidence (checkpoints and hashes only).
    Core = 1,
    /// Additional behavioral metrics included.
    Enhanced = 2,
    /// Full forensic payload with jitter and HID data.
    Maximum = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u64)]
pub enum ProofAlgorithm {
    SwfSha256 = 10,
    SwfArgon2id = 20,
    /// Argon2id with cross-checkpoint entanglement.
    SwfArgon2idEntangled = 21,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u64)]
pub enum Verdict {
    /// Evidence verified as authentic human authorship.
    Authentic = 1,
    /// Insufficient data to reach a definitive conclusion.
    Inconclusive = 2,
    /// Anomalies detected; manual review recommended.
    Suspicious = 3,
    /// Evidence is structurally or cryptographically invalid.
    Invalid = 4,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashValue {
    #[serde(rename = "1")]
    pub algorithm: HashAlgorithm,
    #[serde(rename = "2", with = "serde_bytes")]
    pub digest: Vec<u8>,
}

impl HashValue {
    /// Constant-time comparison to prevent timing side-channels on HMAC outputs.
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.algorithm == other.algorithm && self.digest.ct_eq(&other.digest).into()
    }

    pub fn expected_digest_len(&self) -> usize {
        match self.algorithm {
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
            HashAlgorithm::Sha512 => 64,
        }
    }

    pub fn validate(&self) -> bool {
        self.digest.len() == self.expected_digest_len() && self.digest.iter().any(|&b| b != 0)
    }
}

// PartialEq/Eq for non-security-critical uses (serialization, tests).
// Security-critical verification must use ct_eq().
impl PartialEq for HashValue {
    fn eq(&self, other: &Self) -> bool {
        self.algorithm == other.algorithm && self.digest == other.digest
    }
}

impl Eq for HashValue {}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DocumentRef {
    #[serde(rename = "1")]
    pub content_hash: HashValue,
    #[serde(rename = "2", default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(rename = "3")]
    pub byte_length: u64,
    #[serde(rename = "4")]
    pub char_count: u64,
}

/// Single checkpoint in the causality chain, binding content state to a timestamp.
///
/// **Algorithm assumption:** All hash fields (content_hash, prev_hash, checkpoint_hash,
/// jitter_hash) currently use SHA-256. The verifier in `evidence::Verifier` and the
/// causality lock computation in `crypto::compute_causality_lock*` hardcode HMAC-SHA-256.
/// If additional algorithms are added to `HashAlgorithm`, the verifier must be updated to
/// reject checkpoints where these fields use mismatched algorithms.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Checkpoint {
    #[serde(rename = "1")]
    pub sequence: u64,
    #[serde(rename = "2", with = "serde_bytes")]
    pub checkpoint_id: Vec<u8>,
    #[serde(rename = "3")]
    pub timestamp: u64,
    #[serde(rename = "4")]
    pub content_hash: HashValue,
    #[serde(rename = "5")]
    pub char_count: u64,
    // Key 6 (edit-delta) is intentionally skipped in this legacy checkpoint type;
    // the full edit-delta is only present in the wire-format CheckpointWire (key 6).
    #[serde(rename = "7")]
    pub prev_hash: HashValue,
    #[serde(rename = "8")]
    pub checkpoint_hash: HashValue,
    #[serde(rename = "9", default, skip_serializing_if = "Option::is_none")]
    pub jitter_hash: Option<HashValue>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidencePacket {
    #[serde(rename = "1")]
    pub version: u32,
    #[serde(rename = "2")]
    pub profile_uri: String,
    #[serde(rename = "3", with = "serde_bytes")]
    pub packet_id: Vec<u8>,
    #[serde(rename = "4")]
    pub created: u64,
    #[serde(rename = "5")]
    pub document: DocumentRef,
    #[serde(rename = "6")]
    pub checkpoints: Vec<Checkpoint>,
    #[serde(rename = "7", default, skip_serializing_if = "Option::is_none")]
    pub attestation_tier: Option<AttestationTier>,
    #[serde(rename = "19", default, skip_serializing_if = "Option::is_none")]
    pub baseline_verification: Option<crate::baseline::BaselineVerification>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttestationResult {
    #[serde(rename = "1")]
    pub version: u32,
    #[serde(rename = "2")]
    pub evidence_ref: HashValue,
    #[serde(rename = "3")]
    pub verdict: Verdict,
    #[serde(rename = "4")]
    pub attestation_tier: AttestationTier,
    #[serde(rename = "5")]
    pub chain_length: u64,
    #[serde(rename = "6")]
    pub chain_duration: u64,
    #[serde(rename = "12")]
    pub created: u64,
    /// None if no baseline verification was present in the evidence.
    #[serde(rename = "14", default, skip_serializing_if = "Option::is_none")]
    pub confidence_tier: Option<crate::baseline::ConfidenceTier>,
}
