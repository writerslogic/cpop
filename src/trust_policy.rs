//! Quantified Trust Policies
//!
//! This module implements the trust policy framework defined in the witnessd RFC.
//! Trust policies enable Relying Parties to customize how Evidence is evaluated
//! and to understand the basis for confidence scores.
//!
//! # Components
//!
//! - **Appraisal Policy**: The policy applied during verification
//! - **Trust Factor**: Individual factor contributing to overall score
//! - **Trust Threshold**: Pass/fail requirements
//! - **Trust Computation**: How factors are combined into a score
//!
//! # Computation Models
//!
//! - Weighted average: Sum of (factor * weight)
//! - Minimum of factors: Score limited by weakest factor
//! - Geometric mean: Balanced penalty for outliers

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// How the final trust score is computed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustComputation {
    /// Sum of (factor * weight), normalized
    WeightedAverage,
    /// Minimum across all factors
    MinimumOfFactors,
    /// Nth root of product of factors
    GeometricMean,
    /// Custom formula described in policy_uri
    CustomFormula,
}

/// Type of factor being evaluated
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactorType {
    // Chain-verifiable factors (1-9)
    VdfDuration,
    CheckpointCount,
    JitterEntropy,
    ChainIntegrity,
    RevisionDepth,

    // Presence factors (10-19)
    PresenceRate,
    PresenceResponseTime,

    // Hardware factors (20-29)
    HardwareAttestation,
    CalibrationAttestation,

    // Behavioral factors (30-39)
    EditEntropy,
    MonotonicRatio,
    TypingRateConsistency,

    // External factors (40-49)
    AnchorConfirmation,
    AnchorCount,

    // Collaboration factors (50-59)
    CollaboratorAttestations,
    ContributionConsistency,
}

/// Type of threshold requirement
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThresholdType {
    /// Overall score must be >= value
    MinimumScore,
    /// Named factor must be >= value
    MinimumFactor,
    /// Named factor must be present
    RequiredFactor,
    /// Caveat count must be <= value
    MaximumCaveats,
}

/// Evidence supporting a factor score
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactorEvidence {
    /// Raw observed value
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_value: Option<f32>,

    /// Threshold used for normalization
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold_value: Option<f32>,

    /// Notes about computation
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub computation_notes: Option<String>,

    /// Checkpoint range this factor applies to
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_range: Option<(u32, u32)>,
}

/// Individual factor in trust computation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustFactor {
    /// Human-readable factor name
    pub factor_name: String,

    /// Type of factor
    pub factor_type: FactorType,

    /// Weight in computation (0.0-1.0)
    pub weight: f32,

    /// Observed value
    pub observed_value: f32,

    /// Normalized score (0.0-1.0)
    pub normalized_score: f32,

    /// Contribution to final score (weight * normalized_score)
    pub contribution: f32,

    /// Supporting evidence
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<FactorEvidence>,
}

/// Threshold requirement for pass/fail determination
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustThreshold {
    /// Human-readable threshold name
    pub threshold_name: String,

    /// Type of threshold
    pub threshold_type: ThresholdType,

    /// Required value
    pub required_value: f32,

    /// Whether threshold was met
    pub met: bool,

    /// Reason for failure (if not met)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
}

/// Policy metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyMetadata {
    /// Human-readable policy name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_name: Option<String>,

    /// Description of policy
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_description: Option<String>,

    /// Authority that defined the policy
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_authority: Option<String>,

    /// When policy became effective
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_effective_date: Option<DateTime<Utc>>,

    /// Domains this policy applies to
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applicable_domains: Vec<String>,
}

/// Complete appraisal policy specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppraisalPolicy {
    /// URI identifying this policy
    pub policy_uri: String,

    /// Version of the policy
    pub policy_version: String,

    /// How factors are combined
    pub computation_model: TrustComputation,

    /// Factors evaluated
    pub factors: Vec<TrustFactor>,

    /// Threshold requirements
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub thresholds: Vec<TrustThreshold>,

    /// Policy metadata
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<PolicyMetadata>,
}

impl AppraisalPolicy {
    /// Create a new policy
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

    /// Set computation model
    pub fn with_computation(mut self, model: TrustComputation) -> Self {
        self.computation_model = model;
        self
    }

    /// Add a factor
    pub fn add_factor(mut self, factor: TrustFactor) -> Self {
        self.factors.push(factor);
        self
    }

    /// Add a threshold
    pub fn add_threshold(mut self, threshold: TrustThreshold) -> Self {
        self.thresholds.push(threshold);
        self
    }

    /// Set metadata
    pub fn with_metadata(mut self, metadata: PolicyMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Compute the final trust score based on factors and computation model
    pub fn compute_score(&self) -> f32 {
        if self.factors.is_empty() {
            return 0.0;
        }

        match self.computation_model {
            TrustComputation::WeightedAverage => {
                let total_weight: f32 = self.factors.iter().map(|f| f.weight).sum();
                if total_weight == 0.0 {
                    return 0.0;
                }
                let weighted_sum: f32 = self.factors.iter().map(|f| f.contribution).sum();
                weighted_sum / total_weight
            }
            TrustComputation::MinimumOfFactors => self
                .factors
                .iter()
                .map(|f| f.normalized_score)
                .fold(f32::INFINITY, f32::min),
            TrustComputation::GeometricMean => {
                let product: f32 = self.factors.iter().map(|f| f.normalized_score).product();
                product.powf(1.0 / self.factors.len() as f32)
            }
            TrustComputation::CustomFormula => {
                // Custom formulas require external implementation
                // Return weighted average as fallback
                let total_weight: f32 = self.factors.iter().map(|f| f.weight).sum();
                if total_weight == 0.0 {
                    return 0.0;
                }
                self.factors.iter().map(|f| f.contribution).sum::<f32>() / total_weight
            }
        }
    }

    /// Check all thresholds and return whether policy passes
    pub fn check_thresholds(&self) -> bool {
        self.thresholds.iter().all(|t| t.met)
    }

    /// Get list of failed thresholds
    pub fn failed_thresholds(&self) -> Vec<&TrustThreshold> {
        self.thresholds.iter().filter(|t| !t.met).collect()
    }
}

impl TrustFactor {
    /// Create a new trust factor
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

    /// Add supporting evidence
    pub fn with_evidence(mut self, evidence: FactorEvidence) -> Self {
        self.evidence = Some(evidence);
        self
    }
}

impl TrustThreshold {
    /// Create a new threshold
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

    /// Set failure reason
    pub fn with_failure_reason(mut self, reason: impl Into<String>) -> Self {
        self.failure_reason = Some(reason.into());
        self
    }
}

/// Predefined policy profiles
pub mod profiles {
    use super::*;

    /// Basic verification policy - chain integrity only
    pub fn basic() -> AppraisalPolicy {
        AppraisalPolicy::new("urn:ietf:params:pop:policy:basic", "1.0")
            .with_computation(TrustComputation::WeightedAverage)
            .add_factor(TrustFactor::new(
                "chain-integrity",
                FactorType::ChainIntegrity,
                1.0,
                0.0, // Placeholder
                0.0, // Placeholder
            ))
            .with_metadata(PolicyMetadata {
                policy_name: Some("Basic Verification".to_string()),
                policy_description: Some("Chain integrity verification only".to_string()),
                policy_authority: None,
                policy_effective_date: None,
                applicable_domains: vec!["general".to_string()],
            })
    }

    /// Academic submission policy - weighted average with presence required
    pub fn academic() -> AppraisalPolicy {
        AppraisalPolicy::new("urn:ietf:params:pop:policy:academic", "1.0")
            .with_computation(TrustComputation::WeightedAverage)
            .add_threshold(TrustThreshold::new(
                "minimum-overall",
                ThresholdType::MinimumScore,
                0.70,
                false, // Evaluated at runtime
            ))
            .add_threshold(TrustThreshold::new(
                "presence-required",
                ThresholdType::RequiredFactor,
                0.0,
                false,
            ))
            .with_metadata(PolicyMetadata {
                policy_name: Some("Academic Submission".to_string()),
                policy_description: Some(
                    "Policy for academic paper and thesis submissions".to_string(),
                ),
                policy_authority: None,
                policy_effective_date: None,
                applicable_domains: vec!["academic".to_string(), "education".to_string()],
            })
    }

    /// Legal proceedings policy - minimum model, hardware required
    pub fn legal() -> AppraisalPolicy {
        AppraisalPolicy::new("urn:ietf:params:pop:policy:legal", "1.0")
            .with_computation(TrustComputation::MinimumOfFactors)
            .add_threshold(TrustThreshold::new(
                "hardware-required",
                ThresholdType::RequiredFactor,
                0.0,
                false,
            ))
            .with_metadata(PolicyMetadata {
                policy_name: Some("Legal Proceedings".to_string()),
                policy_description: Some(
                    "High-assurance policy for legal and forensic use".to_string(),
                ),
                policy_authority: None,
                policy_effective_date: None,
                applicable_domains: vec!["legal".to_string(), "forensic".to_string()],
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_weighted_average() {
        let policy = AppraisalPolicy::new("test", "1.0")
            .with_computation(TrustComputation::WeightedAverage)
            .add_factor(TrustFactor::new(
                "f1",
                FactorType::VdfDuration,
                0.5,
                1.0,
                1.0,
            ))
            .add_factor(TrustFactor::new(
                "f2",
                FactorType::JitterEntropy,
                0.5,
                0.5,
                0.5,
            ));

        let score = policy.compute_score();
        // (0.5 * 1.0 + 0.5 * 0.5) / 1.0 = 0.75
        assert!((score - 0.75).abs() < 0.001);
    }

    #[test]
    fn test_minimum_of_factors() {
        let policy = AppraisalPolicy::new("test", "1.0")
            .with_computation(TrustComputation::MinimumOfFactors)
            .add_factor(TrustFactor::new(
                "f1",
                FactorType::VdfDuration,
                0.5,
                1.0,
                0.9,
            ))
            .add_factor(TrustFactor::new(
                "f2",
                FactorType::JitterEntropy,
                0.5,
                0.5,
                0.3,
            ));

        let score = policy.compute_score();
        assert!((score - 0.3).abs() < 0.001);
    }

    #[test]
    fn test_geometric_mean() {
        let policy = AppraisalPolicy::new("test", "1.0")
            .with_computation(TrustComputation::GeometricMean)
            .add_factor(TrustFactor::new(
                "f1",
                FactorType::VdfDuration,
                0.5,
                1.0,
                1.0,
            ))
            .add_factor(TrustFactor::new(
                "f2",
                FactorType::JitterEntropy,
                0.5,
                0.5,
                0.5,
            ));

        let score = policy.compute_score();
        // sqrt(1.0 * 0.5) = 0.707
        assert!((score - 0.707).abs() < 0.01);
    }

    #[test]
    fn test_threshold_checking() {
        let policy = AppraisalPolicy::new("test", "1.0")
            .add_threshold(TrustThreshold::new(
                "t1",
                ThresholdType::MinimumScore,
                0.5,
                true,
            ))
            .add_threshold(TrustThreshold::new(
                "t2",
                ThresholdType::MinimumScore,
                0.9,
                false,
            ));

        assert!(!policy.check_thresholds());
        assert_eq!(policy.failed_thresholds().len(), 1);
    }

    #[test]
    fn test_predefined_profiles() {
        let basic = profiles::basic();
        assert_eq!(basic.policy_uri, "urn:ietf:params:pop:policy:basic");

        let academic = profiles::academic();
        assert_eq!(
            academic.computation_model,
            TrustComputation::WeightedAverage
        );

        let legal = profiles::legal();
        assert_eq!(legal.computation_model, TrustComputation::MinimumOfFactors);
    }

    #[test]
    fn test_serialization() {
        let policy = AppraisalPolicy::new("urn:test:policy", "1.0.0").add_factor(TrustFactor::new(
            "test",
            FactorType::ChainIntegrity,
            1.0,
            1.0,
            1.0,
        ));

        let json = serde_json::to_string(&policy).unwrap();
        let parsed: AppraisalPolicy = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.policy_uri, "urn:test:policy");
    }
}
