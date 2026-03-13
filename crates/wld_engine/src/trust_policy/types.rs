// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustComputation {
    WeightedAverage,
    MinimumOfFactors,
    GeometricMean,
    /// Delegated to external implementation identified by `policy_uri`
    CustomFormula,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactorType {
    VdfDuration,
    CheckpointCount,
    JitterEntropy,
    ChainIntegrity,
    RevisionDepth,

    PresenceRate,
    PresenceResponseTime,

    HardwareAttestation,
    CalibrationAttestation,

    EditEntropy,
    MonotonicRatio,
    TypingRateConsistency,

    AnchorConfirmation,
    AnchorCount,

    CollaboratorAttestations,
    ContributionConsistency,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThresholdType {
    MinimumScore,
    MinimumFactor,
    RequiredFactor,
    MaximumCaveats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactorEvidence {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_value: Option<f32>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold_value: Option<f32>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub computation_notes: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_range: Option<(u32, u32)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustFactor {
    pub factor_name: String,
    pub factor_type: FactorType,
    pub weight: f32,
    pub observed_value: f32,
    pub normalized_score: f32,
    pub contribution: f32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<FactorEvidence>,
}

impl TrustFactor {
    pub fn new(
        name: impl Into<String>,
        factor_type: FactorType,
        weight: f32,
        observed: f32,
        normalized: f32,
    ) -> Self {
        Self {
            factor_name: name.into(),
            factor_type,
            weight,
            observed_value: observed,
            normalized_score: normalized,
            contribution: weight * normalized,
            evidence: None,
        }
    }

    pub fn with_evidence(mut self, evidence: FactorEvidence) -> Self {
        self.evidence = Some(evidence);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustThreshold {
    pub threshold_name: String,
    pub threshold_type: ThresholdType,
    pub required_value: f32,
    pub met: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
}

impl TrustThreshold {
    pub fn new(
        name: impl Into<String>,
        threshold_type: ThresholdType,
        required: f32,
        met: bool,
    ) -> Self {
        Self {
            threshold_name: name.into(),
            threshold_type,
            required_value: required,
            met,
            failure_reason: None,
        }
    }

    pub fn with_failure_reason(mut self, reason: impl Into<String>) -> Self {
        self.failure_reason = Some(reason.into());
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_authority: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_effective_date: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applicable_domains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppraisalPolicy {
    pub policy_uri: String,
    pub policy_version: String,
    pub computation_model: TrustComputation,
    pub factors: Vec<TrustFactor>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub thresholds: Vec<TrustThreshold>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<PolicyMetadata>,
}

impl AppraisalPolicy {
    pub fn new(uri: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            policy_uri: uri.into(),
            policy_version: version.into(),
            computation_model: TrustComputation::WeightedAverage,
            factors: Vec::new(),
            thresholds: Vec::new(),
            metadata: None,
        }
    }

    pub fn with_computation(mut self, model: TrustComputation) -> Self {
        self.computation_model = model;
        self
    }

    pub fn add_factor(mut self, factor: TrustFactor) -> Self {
        self.factors.push(factor);
        self
    }

    pub fn add_threshold(mut self, threshold: TrustThreshold) -> Self {
        self.thresholds.push(threshold);
        self
    }

    pub fn with_metadata(mut self, metadata: PolicyMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }
}

/// Metrics extracted from evidence for trust evaluation.
#[derive(Debug, Clone, Default)]
pub struct EvidenceMetrics {
    /// Checkpoint interval CoV (std/mean); higher = more natural timing
    pub checkpoint_interval_cov: f32,
    /// Fraction of checkpoints with monotonic character-count growth (0.0..1.0)
    pub monotonic_growth_ratio: f32,
    /// Typing-pattern entropy (0.0..1.0)
    pub behavioral_entropy: f32,
    /// 1=SoftwareOnly, 2=AttestedSoftware, 3=HardwareBound, 4=HardwareHardened
    pub attestation_tier_level: u32,
    pub chain_verified: bool,
    pub checkpoint_count: u32,
}
