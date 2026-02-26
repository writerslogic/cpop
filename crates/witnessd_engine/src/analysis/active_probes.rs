// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Active probe mechanisms for behavioral verification.
//!
//! Active probes are challenge-response mechanisms that test specific
//! aspects of human motor control and cognitive processing. Unlike passive
//! observation, active probes introduce controlled stimuli to measure
//! response characteristics.
//!
//! RFC draft-condrey-rats-pop-01 specifies two primary probe types:
//!
//! ## Galton Invariant (Absorption Coefficient)
//! Measures how quickly rhythmic patterns absorb perturbations.
//! Human motor control shows characteristic absorption rates that
//! differ from mechanical or scripted responses.
//!
//! ## Reflex Gate
//! Measures the reflexive return latency after an unexpected stimulus.
//! Human responses show neural pathway delays that are physiologically
//! constrained.

use serde::{Deserialize, Serialize};

/// Result of Galton Invariant probe.
///
/// The Galton Board analogy: balls falling through a grid of pegs
/// naturally produce a bell curve. Similarly, human timing naturally
/// absorbs perturbations back to a mean rhythm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GaltonInvariantResult {
    /// Absorption coefficient (α).
    /// Higher values indicate faster return to baseline rhythm.
    /// Human range: α ∈ [0.3, 0.8]
    pub absorption_coefficient: f64,

    /// Time constant τ for perturbation decay (milliseconds).
    /// How long perturbation effects persist.
    pub time_constant_ms: f64,

    /// Asymmetry factor.
    /// Ratio of recovery from acceleration vs. deceleration.
    /// Humans typically show slight asymmetry (~1.1-1.3).
    pub asymmetry_factor: f64,

    /// Standard error of the absorption estimate.
    pub std_error: f64,

    /// Whether the result passes RFC validation.
    pub is_valid: bool,

    /// Number of perturbations analyzed.
    pub perturbation_count: usize,
}

impl GaltonInvariantResult {
    /// RFC-compliant range for absorption coefficient.
    pub const MIN_VALID_ALPHA: f64 = 0.3;
    pub const MAX_VALID_ALPHA: f64 = 0.8;

    /// Check if absorption coefficient is biologically plausible.
    pub fn is_biologically_plausible(&self) -> bool {
        self.absorption_coefficient >= Self::MIN_VALID_ALPHA
            && self.absorption_coefficient <= Self::MAX_VALID_ALPHA
    }
}

/// Result of Reflex Gate probe.
///
/// Measures the neural pathway delay in responding to unexpected
/// stimuli. Human reflexes have physiological lower bounds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReflexGateResult {
    /// Minimum observed response latency (milliseconds).
    /// Below ~100ms is physiologically implausible for visual stimuli.
    pub min_latency_ms: f64,

    /// Mean response latency (milliseconds).
    pub mean_latency_ms: f64,

    /// Latency standard deviation.
    pub std_latency_ms: f64,

    /// Coefficient of variation (std/mean).
    /// Humans typically show CV ∈ [0.15, 0.40].
    pub coefficient_of_variation: f64,

    /// Sequential dependency (correlation with previous response).
    /// Humans show mild positive correlation (~0.2-0.5).
    pub sequential_dependency: f64,

    /// Whether the result passes RFC validation.
    pub is_valid: bool,

    /// Number of reflex responses analyzed.
    pub response_count: usize,
}

impl ReflexGateResult {
    /// Physiological minimum for visual stimulus response.
    pub const MIN_PHYSIOLOGICAL_LATENCY_MS: f64 = 100.0;

    /// Expected range for reflex latency CV.
    pub const MIN_VALID_CV: f64 = 0.15;
    pub const MAX_VALID_CV: f64 = 0.40;

    /// Check if reflex characteristics are physiologically plausible.
    pub fn is_biologically_plausible(&self) -> bool {
        self.min_latency_ms >= Self::MIN_PHYSIOLOGICAL_LATENCY_MS
            && self.coefficient_of_variation >= Self::MIN_VALID_CV
            && self.coefficient_of_variation <= Self::MAX_VALID_CV
    }

    /// Check if responses are impossibly fast.
    pub fn has_superhuman_responses(&self) -> bool {
        self.min_latency_ms < Self::MIN_PHYSIOLOGICAL_LATENCY_MS
    }
}

/// A timing sample with optional perturbation marker.
#[derive(Debug, Clone)]
pub struct ProbeSample {
    /// Timestamp in nanoseconds.
    pub timestamp_ns: i64,
    /// Inter-event interval in milliseconds.
    pub interval_ms: f64,
    /// Whether this sample was during a perturbation period.
    pub is_perturbed: bool,
    /// Response to a stimulus (for reflex gate).
    pub is_stimulus_response: bool,
}

/// Analyze Galton Invariant from timing data.
///
/// Detects natural perturbations in the rhythm and measures
/// how quickly the subject returns to baseline.
///
/// # Arguments
/// * `samples` - Timing samples with perturbation markers
/// * `baseline_interval_ms` - Expected baseline interval
///
/// # Returns
/// * `GaltonInvariantResult` with absorption characteristics
pub fn analyze_galton_invariant(
    samples: &[ProbeSample],
    baseline_interval_ms: f64,
) -> Result<GaltonInvariantResult, String> {
    if samples.len() < 20 {
        return Err("Insufficient samples for Galton analysis (minimum 20)".to_string());
    }

    // Find perturbation events (intervals significantly different from baseline)
    let threshold = baseline_interval_ms * 0.3; // 30% deviation threshold
    let mut perturbations: Vec<(usize, f64)> = Vec::new();

    for (i, sample) in samples.iter().enumerate() {
        let deviation = (sample.interval_ms - baseline_interval_ms).abs();
        if deviation > threshold || sample.is_perturbed {
            perturbations.push((i, sample.interval_ms - baseline_interval_ms));
        }
    }

    if perturbations.len() < 3 {
        return Err("Insufficient perturbations detected (minimum 3)".to_string());
    }

    // Analyze recovery after each perturbation
    let mut absorption_rates = Vec::new();
    let mut acceleration_recoveries = Vec::new();
    let mut deceleration_recoveries = Vec::new();

    for &(pert_idx, deviation) in &perturbations {
        // Track how quickly subsequent intervals return to baseline
        let mut recovery_samples = Vec::new();

        let end_idx = samples.len().min(pert_idx + 10);
        for sample in samples.iter().take(end_idx).skip(pert_idx + 1) {
            let subsequent_dev = sample.interval_ms - baseline_interval_ms;
            recovery_samples.push(subsequent_dev);
        }

        if recovery_samples.len() >= 3 {
            // Calculate exponential decay rate
            let decay_rate = estimate_decay_rate(&recovery_samples);
            absorption_rates.push(decay_rate);

            if deviation > 0.0 {
                deceleration_recoveries.push(decay_rate);
            } else {
                acceleration_recoveries.push(decay_rate);
            }
        }
    }

    if absorption_rates.is_empty() {
        return Err("Could not calculate absorption rates".to_string());
    }

    // Calculate mean absorption coefficient
    let absorption_coefficient: f64 =
        absorption_rates.iter().sum::<f64>() / absorption_rates.len() as f64;

    // Calculate time constant (τ = 1/α, scaled to ms)
    let time_constant_ms = if absorption_coefficient > 0.0 {
        baseline_interval_ms / absorption_coefficient
    } else {
        f64::INFINITY
    };

    // Calculate asymmetry factor
    let accel_mean = if !acceleration_recoveries.is_empty() {
        acceleration_recoveries.iter().sum::<f64>() / acceleration_recoveries.len() as f64
    } else {
        absorption_coefficient
    };

    let decel_mean = if !deceleration_recoveries.is_empty() {
        deceleration_recoveries.iter().sum::<f64>() / deceleration_recoveries.len() as f64
    } else {
        absorption_coefficient
    };

    let asymmetry_factor = if accel_mean > 0.0 {
        decel_mean / accel_mean
    } else {
        1.0
    };

    // Calculate standard error
    let variance: f64 = absorption_rates
        .iter()
        .map(|&r| (r - absorption_coefficient).powi(2))
        .sum::<f64>()
        / absorption_rates.len() as f64;
    let std_error = (variance / absorption_rates.len() as f64).sqrt();

    let is_valid = (GaltonInvariantResult::MIN_VALID_ALPHA
        ..=GaltonInvariantResult::MAX_VALID_ALPHA)
        .contains(&absorption_coefficient);

    Ok(GaltonInvariantResult {
        absorption_coefficient,
        time_constant_ms,
        asymmetry_factor,
        std_error,
        is_valid,
        perturbation_count: perturbations.len(),
    })
}

/// Estimate exponential decay rate from a sequence.
fn estimate_decay_rate(deviations: &[f64]) -> f64 {
    if deviations.len() < 2 {
        return 0.5;
    }

    // Simple exponential decay fit: y = y0 * exp(-α * t)
    // ln(y/y0) = -α * t
    let y0 = deviations[0].abs().max(0.001);
    let mut sum_rate = 0.0;
    let mut count = 0;

    for (i, &dev) in deviations.iter().enumerate().skip(1) {
        let y = dev.abs().max(0.001);
        let t = i as f64;
        let rate = -(y / y0).ln() / t;

        if rate.is_finite() && rate > 0.0 {
            sum_rate += rate;
            count += 1;
        }
    }

    if count > 0 {
        (sum_rate / count as f64).clamp(0.0, 2.0)
    } else {
        0.5
    }
}

/// Analyze Reflex Gate from stimulus-response data.
///
/// # Arguments
/// * `samples` - Samples with stimulus_response markers
///
/// # Returns
/// * `ReflexGateResult` with latency characteristics
pub fn analyze_reflex_gate(samples: &[ProbeSample]) -> Result<ReflexGateResult, String> {
    // Filter to stimulus responses only
    let responses: Vec<f64> = samples
        .iter()
        .filter(|s| s.is_stimulus_response)
        .map(|s| s.interval_ms)
        .collect();

    if responses.len() < 5 {
        return Err("Insufficient stimulus responses (minimum 5)".to_string());
    }

    let n = responses.len();

    // Calculate statistics
    let min_latency_ms = responses.iter().cloned().fold(f64::INFINITY, f64::min);
    let mean_latency_ms: f64 = responses.iter().sum::<f64>() / n as f64;

    let variance: f64 = responses
        .iter()
        .map(|&r| (r - mean_latency_ms).powi(2))
        .sum::<f64>()
        / n as f64;
    let std_latency_ms = variance.sqrt();

    let coefficient_of_variation = if mean_latency_ms > 0.0 {
        std_latency_ms / mean_latency_ms
    } else {
        0.0
    };

    // Calculate sequential dependency (lag-1 autocorrelation)
    let sequential_dependency = if responses.len() >= 3 {
        calculate_lag1_autocorrelation(&responses)
    } else {
        0.0
    };

    let is_valid = min_latency_ms >= ReflexGateResult::MIN_PHYSIOLOGICAL_LATENCY_MS
        && (ReflexGateResult::MIN_VALID_CV..=ReflexGateResult::MAX_VALID_CV)
            .contains(&coefficient_of_variation);

    Ok(ReflexGateResult {
        min_latency_ms,
        mean_latency_ms,
        std_latency_ms,
        coefficient_of_variation,
        sequential_dependency,
        is_valid,
        response_count: n,
    })
}

/// Calculate lag-1 autocorrelation.
fn calculate_lag1_autocorrelation(data: &[f64]) -> f64 {
    let n = data.len();
    if n < 3 {
        return 0.0;
    }

    let mean: f64 = data.iter().sum::<f64>() / n as f64;

    let mut numerator = 0.0;
    let mut denominator = 0.0;

    for i in 0..n - 1 {
        numerator += (data[i] - mean) * (data[i + 1] - mean);
    }

    for &x in data {
        denominator += (x - mean).powi(2);
    }

    if denominator > 0.0 {
        numerator / denominator
    } else {
        0.0
    }
}

/// Combined active probe results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveProbeResults {
    /// Galton Invariant analysis (if available).
    pub galton: Option<GaltonInvariantResult>,
    /// Reflex Gate analysis (if available).
    pub reflex: Option<ReflexGateResult>,
    /// Combined validation score (0-1).
    pub combined_score: f64,
    /// Whether all available probes passed validation.
    pub all_valid: bool,
}

impl ActiveProbeResults {
    /// Create combined results from individual probe analyses.
    pub fn combine(
        galton: Option<GaltonInvariantResult>,
        reflex: Option<ReflexGateResult>,
    ) -> Self {
        let mut score_sum = 0.0;
        let mut score_count = 0;
        let mut all_valid = true;

        if let Some(ref g) = galton {
            score_count += 1;
            if g.is_valid {
                score_sum += 1.0;
            } else {
                all_valid = false;
            }
        }

        if let Some(ref r) = reflex {
            score_count += 1;
            if r.is_valid {
                score_sum += 1.0;
            } else {
                all_valid = false;
            }
        }

        let combined_score = if score_count > 0 {
            score_sum / score_count as f64
        } else {
            0.0
        };

        Self {
            galton,
            reflex,
            combined_score,
            all_valid,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_rhythmic_samples(
        base_interval: f64,
        perturbations: &[(usize, f64)],
    ) -> Vec<ProbeSample> {
        let mut samples = Vec::new();
        let mut timestamp = 0i64;

        for i in 0..50 {
            let mut interval = base_interval;

            // Check if this is a perturbation
            for &(pert_idx, deviation) in perturbations {
                if i == pert_idx {
                    interval += deviation;
                } else if i > pert_idx && i < pert_idx + 5 {
                    // Decay of perturbation effect
                    let decay = deviation * (0.5_f64).powi((i - pert_idx) as i32);
                    interval += decay;
                }
            }

            timestamp += (interval * 1_000_000.0) as i64;
            samples.push(ProbeSample {
                timestamp_ns: timestamp,
                interval_ms: interval,
                is_perturbed: perturbations.iter().any(|&(idx, _)| idx == i),
                is_stimulus_response: false,
            });
        }

        samples
    }

    #[test]
    fn test_galton_invariant_basic() {
        // Create samples with some perturbations that decay
        let samples = create_rhythmic_samples(200.0, &[(10, 100.0), (25, -80.0), (40, 60.0)]);

        let result = analyze_galton_invariant(&samples, 200.0).unwrap();

        assert!(result.perturbation_count >= 3);
        assert!(result.absorption_coefficient > 0.0);
    }

    #[test]
    fn test_galton_insufficient_data() {
        let samples: Vec<ProbeSample> = (0..5)
            .map(|i| ProbeSample {
                timestamp_ns: i * 200_000_000,
                interval_ms: 200.0,
                is_perturbed: false,
                is_stimulus_response: false,
            })
            .collect();

        let result = analyze_galton_invariant(&samples, 200.0);
        assert!(result.is_err());
    }

    #[test]
    fn test_reflex_gate_basic() {
        // Create stimulus-response samples with realistic latencies
        let latencies = [150.0, 180.0, 165.0, 200.0, 175.0, 190.0, 160.0];
        let samples: Vec<ProbeSample> = latencies
            .iter()
            .enumerate()
            .map(|(i, &lat)| ProbeSample {
                timestamp_ns: i as i64 * 1_000_000_000,
                interval_ms: lat,
                is_perturbed: false,
                is_stimulus_response: true,
            })
            .collect();

        let result = analyze_reflex_gate(&samples).unwrap();

        assert_eq!(result.response_count, 7);
        assert!(result.min_latency_ms >= 150.0);
        assert!(result.mean_latency_ms > 150.0 && result.mean_latency_ms < 200.0);
    }

    #[test]
    fn test_reflex_gate_superhuman() {
        // Create samples with impossibly fast responses
        let latencies = [50.0, 60.0, 55.0, 70.0, 45.0];
        let samples: Vec<ProbeSample> = latencies
            .iter()
            .enumerate()
            .map(|(i, &lat)| ProbeSample {
                timestamp_ns: i as i64 * 1_000_000_000,
                interval_ms: lat,
                is_perturbed: false,
                is_stimulus_response: true,
            })
            .collect();

        let result = analyze_reflex_gate(&samples).unwrap();

        assert!(result.has_superhuman_responses());
        assert!(!result.is_valid);
    }

    #[test]
    fn test_combined_results() {
        let galton = GaltonInvariantResult {
            absorption_coefficient: 0.5,
            time_constant_ms: 400.0,
            asymmetry_factor: 1.1,
            std_error: 0.05,
            is_valid: true,
            perturbation_count: 5,
        };

        let reflex = ReflexGateResult {
            min_latency_ms: 120.0,
            mean_latency_ms: 180.0,
            std_latency_ms: 40.0,
            coefficient_of_variation: 0.22,
            sequential_dependency: 0.3,
            is_valid: true,
            response_count: 10,
        };

        let combined = ActiveProbeResults::combine(Some(galton), Some(reflex));

        assert!(combined.all_valid);
        assert!((combined.combined_score - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_lag1_autocorrelation() {
        // Perfectly correlated series (linear trend)
        let data = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let corr = calculate_lag1_autocorrelation(&data);
        // Linear series has high positive autocorrelation
        assert!(
            corr > 0.0,
            "Linear series should have positive autocorrelation, got {}",
            corr
        );

        // Alternating series (negative autocorrelation)
        let data2 = vec![1.0, -1.0, 1.0, -1.0, 1.0];
        let corr2 = calculate_lag1_autocorrelation(&data2);
        assert!(
            corr2 < 0.0,
            "Alternating series should have negative autocorrelation, got {}",
            corr2
        );
    }
}
