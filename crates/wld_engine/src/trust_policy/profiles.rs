// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::types::{
    AppraisalPolicy, FactorType, PolicyMetadata, ThresholdType, TrustComputation, TrustFactor,
    TrustThreshold,
};

/// Chain integrity + timing + content + hardware attestation.
pub fn basic() -> AppraisalPolicy {
    AppraisalPolicy::new("urn:ietf:params:pop:policy:basic", "1.0")
        .with_computation(TrustComputation::WeightedAverage)
        .add_factor(TrustFactor::new(
            "chain-integrity",
            FactorType::ChainIntegrity,
            0.4,
            0.0,
            0.0,
        ))
        .add_factor(TrustFactor::new(
            "timing-regularity",
            FactorType::TypingRateConsistency,
            0.2,
            0.0,
            0.0,
        ))
        .add_factor(TrustFactor::new(
            "content-progression",
            FactorType::MonotonicRatio,
            0.2,
            0.0,
            0.0,
        ))
        .add_factor(TrustFactor::new(
            "hardware-attestation",
            FactorType::HardwareAttestation,
            0.2,
            0.0,
            0.0,
        ))
        .with_metadata(PolicyMetadata {
            policy_name: Some("Basic Verification".to_string()),
            policy_description: Some(
                "Chain integrity with timing and content analysis".to_string(),
            ),
            policy_authority: None,
            policy_effective_date: None,
            applicable_domains: vec!["general".to_string()],
        })
}

/// Weighted average, min score 0.70, presence required.
pub fn academic() -> AppraisalPolicy {
    AppraisalPolicy::new("urn:ietf:params:pop:policy:academic", "1.0")
        .with_computation(TrustComputation::WeightedAverage)
        .add_threshold(TrustThreshold::new(
            "minimum-overall",
            ThresholdType::MinimumScore,
            0.70,
            false,
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

/// Minimum-of-factors model, hardware attestation required.
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
