// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Core evidence types: structs, enums, and trait implementations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::analysis::{BehavioralFingerprint, ForgeryAnalysis};
use crate::collaboration;
use crate::continuation;
use crate::declaration;
use crate::jitter;
use crate::presence;
use crate::provenance;
use crate::rfc::{BiologyInvariantClaim, JitterBinding, TimeEvidence};
use crate::tpm;
use crate::vdf;

use crate::platform::HIDDeviceInfo;

use super::serde_helpers::{
    deserialize_optional_nonce, deserialize_optional_pubkey, deserialize_optional_signature,
    serialize_optional_nonce, serialize_optional_pubkey, serialize_optional_signature,
};

/// Evidence strength level (based on evidence types present).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[repr(i32)]
pub enum Strength {
    Basic = 1,
    Standard = 2,
    Enhanced = 3,
    Maximum = 4,
}

/// Trust tier for evidence hardening level.
///
/// Indicates how well the evidence resists adversarial manipulation,
/// from local-only (easily forged) to externally attested (independently verifiable).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum TrustTier {
    /// No signature, no nonce. Evidence is self-reported.
    Local = 1,
    /// Signed by key hierarchy, but no verifier nonce.
    Signed = 2,
    /// Signed + verifier nonce proves freshness.
    NonceBound = 3,
    /// WritersProof certificate issued — independently verifiable.
    Attested = 4,
}

impl Strength {
    pub fn as_str(&self) -> &'static str {
        match self {
            Strength::Basic => "basic",
            Strength::Standard => "standard",
            Strength::Enhanced => "enhanced",
            Strength::Maximum => "maximum",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Packet {
    pub version: i32,
    pub exported_at: DateTime<Utc>,
    pub strength: Strength,
    pub provenance: Option<RecordProvenance>,
    pub document: DocumentInfo,
    pub checkpoints: Vec<CheckpointProof>,
    pub vdf_params: vdf::Parameters,
    pub chain_hash: String,
    pub declaration: Option<declaration::Declaration>,
    pub presence: Option<presence::Evidence>,
    pub hardware: Option<HardwareEvidence>,
    pub keystroke: Option<KeystrokeEvidence>,
    pub behavioral: Option<BehavioralEvidence>,
    pub contexts: Vec<ContextPeriod>,
    pub external: Option<ExternalAnchors>,
    pub key_hierarchy: Option<KeyHierarchyEvidencePacket>,
    /// RFC-compliant jitter binding (RFC Section: Jitter Binding).
    /// Contains entropy commitment, statistical summary, active probes, and labyrinth structure.
    pub jitter_binding: Option<JitterBinding>,
    /// RFC-compliant time evidence (RFC Section: Time Evidence).
    /// Contains TSA responses, blockchain anchors, and Roughtime samples.
    pub time_evidence: Option<TimeEvidence>,
    /// Cross-document provenance links (RFC Section: Provenance Links)
    pub provenance_links: Option<provenance::ProvenanceSection>,
    /// Multi-packet continuation info (RFC Section: Continuation Tokens)
    pub continuation: Option<continuation::ContinuationSection>,
    /// Collaborative authorship attestations (RFC Section: Collaborative Authorship)
    pub collaboration: Option<collaboration::CollaborationSection>,
    /// VDF aggregate proof for efficient verification (RFC Section: VDF Aggregation)
    pub vdf_aggregate: Option<vdf::VdfAggregateProof>,
    /// Verifier-provided 32-byte freshness nonce; prevents replay of old packets.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_nonce",
        deserialize_with = "deserialize_optional_nonce"
    )]
    pub verifier_nonce: Option<[u8; 32]>,
    /// Ed25519 signature over packet_hash (|| verifier_nonce if present).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_signature",
        deserialize_with = "deserialize_optional_signature"
    )]
    pub packet_signature: Option<[u8; 64]>,
    /// Public key used for packet signature verification.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_pubkey",
        deserialize_with = "deserialize_optional_pubkey"
    )]
    pub signing_public_key: Option<[u8; 32]>,
    /// RFC-compliant biology invariant claim (RFC Section: Biology Invariant).
    /// Contains behavioral biometric evidence with millibits scoring.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub biology_claim: Option<BiologyInvariantClaim>,
    /// Physical context evidence binding session to machine hardware signals.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub physical_context: Option<PhysicalContextEvidence>,
    /// Trust tier indicating evidence hardening level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_tier: Option<TrustTier>,
    /// MMR root hash covering all checkpoints (anti-deletion).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mmr_root: Option<String>,
    /// Serialized MMR range proof covering all checkpoints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mmr_proof: Option<String>,
    /// WritersProof attestation certificate ID (when externally attested).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub writersproof_certificate_id: Option<String>,
    /// Behavioral baseline verification data (PoP Zero-Trust Baseline).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline_verification: Option<wld_protocol::baseline::BaselineVerification>,
    pub claims: Vec<Claim>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyHierarchyEvidencePacket {
    pub version: i32,
    pub master_fingerprint: String,
    pub master_public_key: String,
    pub device_id: String,
    pub session_id: String,
    pub session_public_key: String,
    pub session_started: DateTime<Utc>,
    pub session_certificate: String,
    pub ratchet_count: i32,
    pub ratchet_public_keys: Vec<String>,
    pub checkpoint_signatures: Vec<CheckpointSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointSignature {
    pub ordinal: u64,
    pub checkpoint_hash: String,
    pub ratchet_index: i32,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextPeriod {
    #[serde(rename = "type")]
    pub period_type: String,
    pub note: Option<String>,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentInfo {
    pub title: String,
    pub path: String,
    pub final_hash: String,
    pub final_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordProvenance {
    pub device_id: String,
    pub signing_pubkey: String,
    pub key_source: String,
    pub hostname: String,
    pub os: String,
    pub os_version: Option<String>,
    pub architecture: String,
    pub session_id: String,
    pub session_started: DateTime<Utc>,
    pub input_devices: Vec<InputDeviceInfo>,
    pub access_control: Option<AccessControlInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputDeviceInfo {
    pub vendor_id: u16,
    pub product_id: u16,
    pub product_name: String,
    pub serial_number: Option<String>,
    pub connection_type: String,
    pub fingerprint: String,
}

impl From<&HIDDeviceInfo> for InputDeviceInfo {
    fn from(hid: &HIDDeviceInfo) -> Self {
        let transport = hid.transport_type();
        Self {
            vendor_id: hid.vendor_id as u16,
            product_id: hid.product_id as u16,
            product_name: hid.product_name.clone(),
            serial_number: hid.serial_number.clone(),
            connection_type: transport.as_str().to_string(),
            fingerprint: hid.fingerprint(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessControlInfo {
    pub captured_at: DateTime<Utc>,
    pub file_owner_uid: i32,
    pub file_owner_name: Option<String>,
    pub file_permissions: String,
    pub file_group_gid: Option<i32>,
    pub file_group_name: Option<String>,
    pub process_uid: i32,
    pub process_euid: i32,
    pub process_username: Option<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointProof {
    pub ordinal: u64,
    pub content_hash: String,
    pub content_size: u64,
    pub timestamp: DateTime<Utc>,
    pub message: Option<String>,
    pub vdf_input: Option<String>,
    pub vdf_output: Option<String>,
    pub vdf_iterations: Option<u64>,
    pub elapsed_time: Option<Duration>,
    pub previous_hash: String,
    pub hash: String,
    pub signature: Option<String>,
}

/// Hardware attestation evidence binding TPM/TEE state to session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareEvidence {
    pub bindings: Vec<tpm::Binding>,
    pub device_id: String,
    /// Session-bound nonce for TPM quote anti-replay.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_nonce",
        deserialize_with = "deserialize_optional_nonce"
    )]
    pub attestation_nonce: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystrokeEvidence {
    pub session_id: String,
    pub started_at: DateTime<Utc>,
    pub ended_at: DateTime<Utc>,
    pub duration: Duration,
    pub total_keystrokes: u64,
    pub total_samples: i32,
    pub keystrokes_per_minute: f64,
    pub unique_doc_states: i32,
    pub chain_valid: bool,
    pub plausible_human_rate: bool,
    pub samples: Vec<jitter::Sample>,
    /// Ratio of samples using hardware entropy (0.0..1.0, wld_jitter only).
    #[serde(default)]
    pub phys_ratio: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralEvidence {
    pub edit_topology: Vec<EditRegion>,
    pub metrics: Option<ForensicMetrics>,
    /// Behavioral fingerprint extracted from typing patterns.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<BehavioralFingerprint>,
    /// Forgery detection analysis results.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forgery_analysis: Option<ForgeryAnalysis>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditRegion {
    pub start_pct: f64,
    pub end_pct: f64,
    pub delta_sign: i32,
    pub byte_count: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicMetrics {
    pub monotonic_append_ratio: f64,
    pub edit_entropy: f64,
    pub median_interval_seconds: f64,
    pub positive_negative_ratio: f64,
    pub deletion_clustering: f64,
    pub assessment: Option<String>,
    pub anomaly_count: Option<i32>,
}

/// Physical environment evidence for machine binding and non-repudiation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhysicalContextEvidence {
    pub clock_skew: u64,
    pub thermal_proxy: u32,
    pub silicon_puf_hash: String,
    pub io_latency_ns: u64,
    pub combined_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalAnchors {
    pub opentimestamps: Vec<OTSProof>,
    pub rfc3161: Vec<RFC3161Proof>,
    pub proofs: Vec<AnchorProof>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OTSProof {
    pub chain_hash: String,
    pub proof: String,
    pub status: String,
    pub block_height: Option<u64>,
    pub block_time: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RFC3161Proof {
    pub chain_hash: String,
    pub tsa_url: String,
    pub response: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorProof {
    pub provider: String,
    pub provider_name: String,
    pub legal_standing: String,
    pub regions: Vec<String>,
    pub hash: String,
    pub timestamp: DateTime<Utc>,
    pub status: String,
    pub raw_proof: String,
    pub blockchain: Option<BlockchainAnchorInfo>,
    pub verify_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainAnchorInfo {
    pub chain: String,
    pub block_height: u64,
    pub block_hash: Option<String>,
    pub block_time: DateTime<Utc>,
    pub tx_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claim {
    #[serde(rename = "type")]
    pub claim_type: ClaimType,
    pub description: String,
    pub confidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClaimType {
    #[serde(rename = "chain_integrity")]
    ChainIntegrity,
    #[serde(rename = "time_elapsed")]
    TimeElapsed,
    #[serde(rename = "process_declared")]
    ProcessDeclared,
    #[serde(rename = "presence_verified")]
    PresenceVerified,
    #[serde(rename = "keystrokes_verified")]
    KeystrokesVerified,
    #[serde(rename = "hardware_attested")]
    HardwareAttested,
    #[serde(rename = "behavior_analyzed")]
    BehaviorAnalyzed,
    #[serde(rename = "contexts_recorded")]
    ContextsRecorded,
    #[serde(rename = "external_anchored")]
    ExternalAnchored,
    #[serde(rename = "key_hierarchy")]
    KeyHierarchy,
}
