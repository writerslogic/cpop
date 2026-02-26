// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use serde::{Deserialize, Serialize};

/// CBOR Tag for Evidence Packets.
pub const CBOR_TAG_EVIDENCE_PACKET: u64 = 1129336656;

/// CBOR Tag for Attestation Results (WAR).
pub const CBOR_TAG_ATTESTATION_RESULT: u64 = 1129791826;

/// Hash Algorithm enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u64)]
pub enum HashAlgorithm {
    Sha256 = 1,
    Sha384 = 2,
    Sha512 = 3,
}

/// Attestation Tier enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u64)]
pub enum AttestationTier {
    SoftwareOnly = 1,
    AttestedSoftware = 2,
    HardwareBound = 3,
    HardwareHardened = 4,
}

/// Content Tier enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u64)]
pub enum ContentTier {
    Core = 1,
    Enhanced = 2,
    Maximum = 3,
}

/// SWF Proof Algorithm enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u64)]
pub enum ProofAlgorithm {
    SwfArgon2id = 20,
    SwfArgon2idEntangled = 21,
}

/// Appraisal Verdict enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u64)]
pub enum Verdict {
    Authentic = 1,
    Inconclusive = 2,
    Suspicious = 3,
    Invalid = 4,
}

/// Hash Value structure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashValue {
    #[serde(rename = "1")]
    pub algorithm: HashAlgorithm,
    #[serde(rename = "2", with = "serde_bytes")]
    pub digest: Vec<u8>,
}

/// Document Reference structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentRef {
    #[serde(rename = "1")]
    pub content_hash: HashValue,
    #[serde(rename = "2", skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(rename = "3")]
    pub byte_length: u64,
    #[serde(rename = "4")]
    pub char_count: u64,
}

/// Checkpoint structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    #[serde(rename = "1")]
    pub sequence: u64,
    #[serde(rename = "2", with = "serde_bytes")]
    pub checkpoint_id: Vec<u8>, // UUID (16 bytes)
    #[serde(rename = "3")]
    pub timestamp: u64,
    #[serde(rename = "4")]
    pub content_hash: HashValue,
    #[serde(rename = "5")]
    pub char_count: u64,
    #[serde(rename = "7")]
    pub prev_hash: HashValue,
    #[serde(rename = "8")]
    pub checkpoint_hash: HashValue,
    #[serde(rename = "9", skip_serializing_if = "Option::is_none")]
    pub jitter_hash: Option<HashValue>,
    // Additional fields can be added here
}

/// Evidence Packet structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidencePacket {
    #[serde(rename = "1")]
    pub version: u32,
    #[serde(rename = "2")]
    pub profile_uri: String,
    #[serde(rename = "3", with = "serde_bytes")]
    pub packet_id: Vec<u8>, // UUID (16 bytes)
    #[serde(rename = "4")]
    pub created: u64,
    #[serde(rename = "5")]
    pub document: DocumentRef,
    #[serde(rename = "6")]
    pub checkpoints: Vec<Checkpoint>,
    #[serde(rename = "7", skip_serializing_if = "Option::is_none")]
    pub attestation_tier: Option<AttestationTier>,
}

/// Attestation Result (WAR) structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub chain_duration: u64, // seconds
    #[serde(rename = "12")]
    pub created: u64,
}
