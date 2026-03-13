// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Forgery cost estimation for user-adversary threat model.
//!
//! Computes the estimated computational and temporal cost an adversary would
//! incur to fabricate each evidence component. The weakest-link score
//! identifies which component is cheapest to forge, guiding hardening efforts.
//!
//! Cost model: for each evidence dimension, estimate the adversary's cost
//! in CPU-seconds to produce a plausible forgery, then combine into an
//! overall difficulty score.

use serde::{Deserialize, Serialize};

/// Forgery cost estimation for a complete evidence packet.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ForgeryCostEstimate {
    /// Per-component forgery cost breakdown.
    pub components: Vec<ComponentCost>,
    /// Overall difficulty: geometric mean of component costs (log-scale).
    pub overall_difficulty: f64,
    /// Weakest component (lowest cost to forge).
    pub weakest_link: Option<String>,
    /// Estimated wall-clock time to forge entire packet (seconds).
    pub estimated_forge_time_sec: f64,
    /// Tier label for display.
    pub tier: ForgeryResistanceTier,
}

/// Cost estimate for a single evidence component.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentCost {
    pub name: String,
    /// Estimated CPU-seconds to forge this component.
    pub cost_cpu_sec: f64,
    /// Whether this component is present in the evidence.
    pub present: bool,
    /// Brief explanation of the cost basis.
    pub explanation: String,
}

/// Forgery resistance classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ForgeryResistanceTier {
    /// Trivial to forge (< 1 minute).
    #[default]
    Trivial,
    /// Low resistance (< 1 hour).
    Low,
    /// Moderate resistance (hours to days).
    Moderate,
    /// High resistance (days+ or requires hardware).
    High,
    /// Very high resistance (hardware-bound, cross-modal entangled).
    VeryHigh,
}

/// Input parameters for forgery cost estimation.
pub struct ForgeryCostInput {
    /// VDF iterations completed.
    pub vdf_iterations: u64,
    /// VDF iterations per second on this platform.
    pub vdf_rate: u64,
    /// Number of checkpoints in the chain.
    pub checkpoint_count: u64,
    /// Duration of the evidence chain (seconds).
    pub chain_duration_sec: u64,
    /// Whether jitter binding is present.
    pub has_jitter_binding: bool,
    /// Number of jitter samples.
    pub jitter_sample_count: u64,
    /// Whether hardware attestation (TPM/SE) is present.
    pub has_hardware_attestation: bool,
    /// Whether behavioral fingerprint is present.
    pub has_behavioral_fingerprint: bool,
    /// Whether cross-modal checks passed.
    pub cross_modal_consistent: bool,
    /// Number of cross-modal checks that passed.
    pub cross_modal_passed: usize,
    /// Total cross-modal checks run.
    pub cross_modal_total: usize,
    /// Whether the evidence has external time anchors (RFC3161, Roughtime).
    pub has_external_time_anchor: bool,
    /// Whether content-key entanglement is present.
    pub has_content_key_entanglement: bool,
}

/// Estimate the cost to forge a complete evidence packet.
pub fn estimate_forgery_cost(input: &ForgeryCostInput) -> ForgeryCostEstimate {
    let mut components = Vec::new();

    let vdf_cost = if input.vdf_iterations > 0 && input.vdf_rate > 0 {
        let sequential_seconds = input.vdf_iterations as f64 / input.vdf_rate as f64;
        // VDFs are inherently sequential -- parallelism doesn't help.
        // Adversary must spend at least this much wall-clock time.
        ComponentCost {
            name: "vdf_proof_chain".into(),
            cost_cpu_sec: sequential_seconds,
            present: true,
            explanation: format!(
                "{} iterations at {} iter/s = {:.0}s sequential work",
                input.vdf_iterations, input.vdf_rate, sequential_seconds
            ),
        }
    } else {
        ComponentCost {
            name: "vdf_proof_chain".into(),
            cost_cpu_sec: 0.0,
            present: false,
            explanation: "No VDF proofs present".into(),
        }
    };
    components.push(vdf_cost);

    let chain_cost = if input.checkpoint_count > 0 {
        let cost = input.chain_duration_sec as f64;
        ComponentCost {
            name: "checkpoint_chain".into(),
            cost_cpu_sec: cost,
            present: true,
            explanation: format!(
                "{} checkpoints over {}s; adversary must simulate elapsed time",
                input.checkpoint_count, input.chain_duration_sec
            ),
        }
    } else {
        ComponentCost {
            name: "checkpoint_chain".into(),
            cost_cpu_sec: 0.0,
            present: false,
            explanation: "No checkpoint chain".into(),
        }
    };
    components.push(chain_cost);

    let jitter_cost = if input.has_jitter_binding && input.jitter_sample_count > 0 {
        let cost = input.jitter_sample_count as f64 * 0.1;
        ComponentCost {
            name: "jitter_entropy".into(),
            cost_cpu_sec: cost,
            present: true,
            explanation: format!(
                "{} samples requiring statistically valid 1/f timing; \
                 adversary must model human keystroke dynamics",
                input.jitter_sample_count
            ),
        }
    } else {
        ComponentCost {
            name: "jitter_entropy".into(),
            cost_cpu_sec: 0.0,
            present: false,
            explanation: "No jitter binding".into(),
        }
    };
    components.push(jitter_cost);

    let hw_cost = if input.has_hardware_attestation {
        ComponentCost {
            name: "hardware_attestation".into(),
            cost_cpu_sec: f64::INFINITY,
            present: true,
            explanation: "Hardware-bound key; forgery requires physical device access".into(),
        }
    } else {
        ComponentCost {
            name: "hardware_attestation".into(),
            cost_cpu_sec: 1.0,
            present: false,
            explanation: "Software-only keys; extractable by device owner".into(),
        }
    };
    components.push(hw_cost);

    let behavioral_cost = if input.has_behavioral_fingerprint {
        ComponentCost {
            name: "behavioral_fingerprint".into(),
            cost_cpu_sec: 3600.0,
            present: true,
            explanation: "Must replicate typing dynamics (Hurst, 1/f, cadence)".into(),
        }
    } else {
        ComponentCost {
            name: "behavioral_fingerprint".into(),
            cost_cpu_sec: 0.0,
            present: false,
            explanation: "No behavioral fingerprint".into(),
        }
    };
    components.push(behavioral_cost);

    let cross_modal_cost = if input.cross_modal_total > 0 {
        let n = input.cross_modal_total as f64;
        let constraint_factor = n * (n - 1.0) / 2.0;
        let cost = if input.cross_modal_consistent {
            constraint_factor * 60.0
        } else {
            10.0
        };
        ComponentCost {
            name: "cross_modal_consistency".into(),
            cost_cpu_sec: cost,
            present: true,
            explanation: format!(
                "{}/{} checks passed; {} pairwise constraints",
                input.cross_modal_passed, input.cross_modal_total, constraint_factor as u64
            ),
        }
    } else {
        ComponentCost {
            name: "cross_modal_consistency".into(),
            cost_cpu_sec: 0.0,
            present: false,
            explanation: "No cross-modal checks performed".into(),
        }
    };
    components.push(cross_modal_cost);

    let time_cost = if input.has_external_time_anchor {
        ComponentCost {
            name: "external_time_anchor".into(),
            cost_cpu_sec: f64::INFINITY,
            present: true,
            explanation: "RFC3161/Roughtime timestamp; adversary cannot backdate".into(),
        }
    } else {
        ComponentCost {
            name: "external_time_anchor".into(),
            cost_cpu_sec: 0.0,
            present: false,
            explanation: "No external time anchor".into(),
        }
    };
    components.push(time_cost);

    let entangle_cost = if input.has_content_key_entanglement {
        let cost = input.chain_duration_sec as f64 * 2.0;
        ComponentCost {
            name: "content_key_entanglement".into(),
            cost_cpu_sec: cost,
            present: true,
            explanation: "Content hash entangled with VDF/jitter; \
                         modifying content requires full recomputation"
                .into(),
        }
    } else {
        ComponentCost {
            name: "content_key_entanglement".into(),
            cost_cpu_sec: 0.0,
            present: false,
            explanation: "No content-key entanglement".into(),
        }
    };
    components.push(entangle_cost);

    let finite_costs: Vec<f64> = components
        .iter()
        .filter(|c| c.present && c.cost_cpu_sec.is_finite() && c.cost_cpu_sec > 0.0)
        .map(|c| c.cost_cpu_sec)
        .collect();

    let has_infinite = components
        .iter()
        .any(|c| c.present && c.cost_cpu_sec.is_infinite());

    let overall_difficulty = if finite_costs.is_empty() {
        if has_infinite {
            f64::INFINITY
        } else {
            0.0
        }
    } else {
        let log_sum: f64 = finite_costs.iter().map(|c| c.ln()).sum();
        let geo_mean = (log_sum / finite_costs.len() as f64).exp();
        if has_infinite {
            geo_mean * 100.0
        } else {
            geo_mean
        }
    };

    let weakest_link = components
        .iter()
        .filter(|c| c.present)
        .min_by(|a, b| {
            a.cost_cpu_sec
                .partial_cmp(&b.cost_cpu_sec)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .map(|c| c.name.clone());

    let estimated_forge_time_sec = {
        let has_any_present = components.iter().any(|c| c.present);
        let all_infinite = has_any_present
            && components
                .iter()
                .filter(|c| c.present)
                .all(|c| c.cost_cpu_sec.is_infinite());
        if all_infinite {
            f64::INFINITY
        } else {
            components
                .iter()
                .filter(|c| c.present && c.cost_cpu_sec.is_finite())
                .map(|c| c.cost_cpu_sec)
                .fold(0.0_f64, f64::max)
        }
    };

    let tier = classify_tier(overall_difficulty, input.has_hardware_attestation);

    ForgeryCostEstimate {
        components,
        overall_difficulty,
        weakest_link,
        estimated_forge_time_sec,
        tier,
    }
}

fn classify_tier(difficulty: f64, has_hardware_attestation: bool) -> ForgeryResistanceTier {
    if has_hardware_attestation {
        return ForgeryResistanceTier::VeryHigh;
    }
    if difficulty.is_infinite() {
        return ForgeryResistanceTier::VeryHigh;
    }
    if difficulty > 86400.0 {
        ForgeryResistanceTier::High
    } else if difficulty > 3600.0 {
        ForgeryResistanceTier::Moderate
    } else if difficulty > 60.0 {
        ForgeryResistanceTier::Low
    } else {
        ForgeryResistanceTier::Trivial
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_minimal_evidence() {
        let input = ForgeryCostInput {
            vdf_iterations: 0,
            vdf_rate: 0,
            checkpoint_count: 5,
            chain_duration_sec: 300,
            has_jitter_binding: false,
            jitter_sample_count: 0,
            has_hardware_attestation: false,
            has_behavioral_fingerprint: false,
            cross_modal_consistent: false,
            cross_modal_passed: 0,
            cross_modal_total: 0,
            has_external_time_anchor: false,
            has_content_key_entanglement: false,
        };

        let result = estimate_forgery_cost(&input);
        assert!(matches!(
            result.tier,
            ForgeryResistanceTier::Trivial | ForgeryResistanceTier::Low
        ));
    }

    #[test]
    fn test_hardware_bound_evidence() {
        let input = ForgeryCostInput {
            vdf_iterations: 1_000_000,
            vdf_rate: 10_000,
            checkpoint_count: 50,
            chain_duration_sec: 3600,
            has_jitter_binding: true,
            jitter_sample_count: 5000,
            has_hardware_attestation: true,
            has_behavioral_fingerprint: true,
            cross_modal_consistent: true,
            cross_modal_passed: 5,
            cross_modal_total: 5,
            has_external_time_anchor: true,
            has_content_key_entanglement: true,
        };

        let result = estimate_forgery_cost(&input);
        assert_eq!(result.tier, ForgeryResistanceTier::VeryHigh);
    }

    #[test]
    fn test_weakest_link_identified() {
        let input = ForgeryCostInput {
            vdf_iterations: 100_000,
            vdf_rate: 10_000,
            checkpoint_count: 10,
            chain_duration_sec: 60,
            has_jitter_binding: true,
            jitter_sample_count: 100,
            has_hardware_attestation: false,
            has_behavioral_fingerprint: false,
            cross_modal_consistent: false,
            cross_modal_passed: 0,
            cross_modal_total: 0,
            has_external_time_anchor: false,
            has_content_key_entanglement: false,
        };

        let result = estimate_forgery_cost(&input);
        assert!(result.weakest_link.is_some());
        // VDF (100k/10k = 10s) and jitter (100*0.1 = 10s) tie; VDF is first
        assert_eq!(result.weakest_link.as_deref(), Some("vdf_proof_chain"));
    }
}
