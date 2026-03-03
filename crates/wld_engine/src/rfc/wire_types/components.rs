// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Evidence component types for wire-format structures.
//!
//! Implements `document-ref`, `edit-delta`, `proof-params`, `merkle-proof`,
//! `process-proof`, `jitter-binding`, `physical-state`, `physical-liveness`,
//! `presence-challenge`, `channel-binding`, `self-receipt`, `active-probe`,
//! and `profile-declaration` from the CDDL schema.

use serde::{Deserialize, Serialize};

use super::enums::{BindingType, HashSaltMode, ProbeType, ProofAlgorithm};
use super::hash::HashValue;
use super::serde_helpers::{fixed_bytes_32, fixed_bytes_32_opt, serde_bytes_opt};

/// Minimum ratio of claimed SWF duration to expected duration.
/// Per draft-condrey-rats-pop: a proof claiming less than 0.5x the
/// expected execution time is considered impossibly fast.
pub const SWF_MIN_DURATION_FACTOR: f64 = 0.5;

/// Maximum ratio of claimed SWF duration to expected duration.
/// Per draft-condrey-rats-pop: a proof claiming more than 3.0x the
/// expected execution time is considered suspiciously slow.
pub const SWF_MAX_DURATION_FACTOR: f64 = 3.0;

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
    #[serde(rename = "1")]
    pub content_hash: HashValue,

    #[serde(rename = "2", default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,

    #[serde(rename = "3")]
    pub byte_length: u64,

    #[serde(rename = "4")]
    pub char_count: u64,

    #[serde(rename = "5", default, skip_serializing_if = "Option::is_none")]
    pub salt_mode: Option<HashSaltMode>,

    /// Hash of the author-provided salt
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
    #[serde(rename = "1")]
    pub chars_added: u64,

    #[serde(rename = "2")]
    pub chars_deleted: u64,

    #[serde(rename = "3")]
    pub op_count: u64,

    /// (offset, delta) pairs
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
    #[serde(rename = "1")]
    pub time_cost: u64,

    /// In KiB
    #[serde(rename = "2")]
    pub memory_cost: u64,

    #[serde(rename = "3")]
    pub parallelism: u64,

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
    #[serde(rename = "1")]
    pub leaf_index: u64,

    /// Ordered leaf-to-root
    #[serde(rename = "2")]
    pub sibling_path: Vec<serde_bytes::ByteBuf>,

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
    #[serde(rename = "1")]
    pub algorithm: ProofAlgorithm,

    #[serde(rename = "2")]
    pub params: ProofParams,

    #[serde(rename = "3", with = "serde_bytes")]
    pub input: Vec<u8>,

    #[serde(rename = "4", with = "serde_bytes")]
    pub merkle_root: Vec<u8>,

    #[serde(rename = "5")]
    pub sampled_proofs: Vec<MerkleProof>,

    /// In milliseconds
    #[serde(rename = "6")]
    pub claimed_duration: u64,
}

impl ProcessProof {
    /// Returns `true` if `claimed_duration` falls within the IETF-mandated
    /// `[SWF_MIN_DURATION_FACTOR, SWF_MAX_DURATION_FACTOR]` range relative
    /// to `expected_duration_ms`.
    pub fn is_duration_within_bounds(&self, expected_duration_ms: u64) -> bool {
        if expected_duration_ms == 0 || self.claimed_duration == 0 {
            return false;
        }
        let ratio = self.claimed_duration as f64 / expected_duration_ms as f64;
        (SWF_MIN_DURATION_FACTOR..=SWF_MAX_DURATION_FACTOR).contains(&ratio)
    }
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
    /// In milliseconds
    #[serde(rename = "1")]
    pub intervals: Vec<u64>,

    /// In centibits
    #[serde(rename = "2")]
    pub entropy_estimate: u64,

    /// HMAC seal
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
    /// Relative millidegrees
    #[serde(rename = "1")]
    pub thermal: Vec<i64>,

    #[serde(rename = "2")]
    pub entropy_delta: i64,

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
    /// (timestamp, delta in millidegrees)
    #[serde(rename = "1")]
    pub thermal_trajectory: Vec<(u64, i64)>,

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
    /// >= 128 bits
    #[serde(rename = "1", with = "serde_bytes")]
    pub challenge_nonce: Vec<u8>,

    /// `COSE_Sign1`
    #[serde(rename = "2", with = "serde_bytes")]
    pub device_signature: Vec<u8>,

    /// Epoch ms
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
    #[serde(rename = "1")]
    pub binding_type: BindingType,

    /// TLS Exporter Key Material output
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
    #[serde(rename = "1")]
    pub tool_id: String,

    #[serde(rename = "2")]
    pub output_commit: HashValue,

    #[serde(rename = "3")]
    pub evidence_ref: HashValue,

    /// Epoch ms
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
    #[serde(rename = "1")]
    pub probe_type: ProbeType,

    /// Epoch ms
    #[serde(rename = "2")]
    pub stimulus_time: u64,

    /// Epoch ms
    #[serde(rename = "3")]
    pub response_time: u64,

    #[serde(rename = "4", with = "serde_bytes")]
    pub stimulus_data: Vec<u8>,

    #[serde(rename = "5", with = "serde_bytes")]
    pub response_data: Vec<u8>,

    /// In ms
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
    #[serde(rename = "1")]
    pub profile_id: String,

    #[serde(rename = "2")]
    pub feature_flags: Vec<u64>,
}
