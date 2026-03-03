// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Wire-format attestation result and forensic types per CDDL schema.
//!
//! Implements `entropy-report`, `forgery-cost-estimate`, `absence-claim`,
//! `forensic-flag`, `forensic-summary`, and `attestation-result`.

use serde::{Deserialize, Serialize};

use super::enums::{AbsenceType, AttestationTier, CostUnit, Verdict};
use super::hash::{HashValue, TimeWindow};
use super::CBOR_TAG_ATTESTATION_RESULT;
use crate::codec::{self, CodecError};

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

    /// Meets required threshold
    #[serde(rename = "4")]
    pub meets_threshold: bool,
}

impl EntropyReport {
    /// Check if all entropy values meet the draft-condrey-rats-pop-appraisal thresholds.
    pub fn validate_thresholds(&self) -> bool {
        self.timing_entropy >= 3.0 && self.revision_entropy >= 3.0 && self.pause_entropy >= 2.0
    }
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
    /// SWF forgery cost
    #[serde(rename = "1")]
    pub c_swf: f32,

    /// Entropy forgery cost
    #[serde(rename = "2")]
    pub c_entropy: f32,

    /// Hardware forgery cost
    #[serde(rename = "3")]
    pub c_hardware: f32,

    /// Total cost
    #[serde(rename = "4")]
    pub c_total: f32,

    /// Unit
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
    /// Absence type
    #[serde(rename = "1")]
    pub absence_type: AbsenceType,

    /// Time window
    #[serde(rename = "2")]
    pub window: TimeWindow,

    /// Claim identifier
    #[serde(rename = "3")]
    pub claim_id: String,

    /// Threshold/parameter
    #[serde(rename = "4", default, skip_serializing_if = "Option::is_none")]
    pub threshold: Option<ciborium::Value>,

    /// Assertion holds
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

    /// Triggered
    #[serde(rename = "2")]
    pub triggered: bool,

    /// Affected windows
    #[serde(rename = "3")]
    pub affected_windows: u64,

    /// Total windows
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
    /// Flags triggered
    #[serde(rename = "1")]
    pub flags_triggered: u64,

    /// Flags evaluated
    #[serde(rename = "2")]
    pub flags_evaluated: u64,

    /// Anomalous checkpoints
    #[serde(rename = "3")]
    pub affected_checkpoints: u64,

    /// Total checkpoints
    #[serde(rename = "4")]
    pub total_checkpoints: u64,

    /// Per-flag detail
    #[serde(rename = "5", default, skip_serializing_if = "Option::is_none")]
    pub flags: Option<Vec<ForensicFlag>>,
}

/// Wire-format attestation result per CDDL `attestation-result`.
///
/// Wrapped with CBOR tag 1463894560 for transmission.
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
    /// Schema version (must be 1)
    #[serde(rename = "1")]
    pub version: u64,

    /// Evidence packet reference
    #[serde(rename = "2")]
    pub evidence_ref: HashValue,

    /// Verdict
    #[serde(rename = "3")]
    pub verdict: Verdict,

    /// Assessed tier
    #[serde(rename = "4")]
    pub assessed_tier: AttestationTier,

    /// Chain length (checkpoints)
    #[serde(rename = "5")]
    pub chain_length: u64,

    /// Chain duration (seconds)
    #[serde(rename = "6")]
    pub chain_duration: u64,

    /// Entropy assessment (omitted for CORE)
    #[serde(rename = "7", default, skip_serializing_if = "Option::is_none")]
    pub entropy_report: Option<EntropyReport>,

    /// Forgery cost estimate
    #[serde(rename = "8", default, skip_serializing_if = "Option::is_none")]
    pub forgery_cost: Option<ForgeryCostEstimate>,

    /// Absence claims
    #[serde(rename = "9", default, skip_serializing_if = "Option::is_none")]
    pub absence_claims: Option<Vec<AbsenceClaim>>,

    /// Warnings
    #[serde(rename = "10", default, skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<String>>,

    /// Verifier signature (`COSE_Sign1`)
    #[serde(rename = "11", with = "serde_bytes")]
    pub verifier_signature: Vec<u8>,

    /// Appraisal timestamp (epoch ms)
    #[serde(rename = "12")]
    pub created: u64,

    /// Forensic summary
    #[serde(rename = "13", default, skip_serializing_if = "Option::is_none")]
    pub forensic_summary: Option<ForensicSummary>,
}

impl AttestationResultWire {
    /// Encode to tagged CBOR (tag 1463894560).
    pub fn encode_cbor(&self) -> Result<Vec<u8>, CodecError> {
        codec::cbor::encode_tagged(self, CBOR_TAG_ATTESTATION_RESULT)
    }

    /// Decode from tagged CBOR bytes.
    pub fn decode_cbor(data: &[u8]) -> Result<Self, CodecError> {
        codec::cbor::decode_tagged(data, CBOR_TAG_ATTESTATION_RESULT)
    }

    /// Encode to untagged CBOR.
    pub fn encode_cbor_untagged(&self) -> Result<Vec<u8>, CodecError> {
        codec::cbor::encode(self)
    }

    /// Decode from untagged CBOR bytes.
    pub fn decode_cbor_untagged(data: &[u8]) -> Result<Self, CodecError> {
        codec::cbor::decode(data)
    }
}
