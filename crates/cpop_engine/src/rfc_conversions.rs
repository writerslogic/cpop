// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! `From` implementations bridging engine analysis types to protocol RFC types.
//!
//! These live in the engine because they depend on `crate::analysis::*` which
//! is engine-only. The pure data types live in `cpop_protocol::rfc`.

use cpop_protocol::rfc::biology::{
    AnomalyFlag, AnomalyType, BiologyInvariantClaim, BiologyMeasurements, BiologyScoringParameters,
    ErrorTopology, PinkNoiseAnalysis,
};
use cpop_protocol::rfc::jitter_binding::{
    ActiveProbes, GaltonInvariant, LabyrinthStructure, ReflexGate,
};

// --- Biology conversions ---

impl From<&crate::analysis::pink_noise::PinkNoiseAnalysis> for PinkNoiseAnalysis {
    fn from(analysis: &crate::analysis::pink_noise::PinkNoiseAnalysis) -> Self {
        Self {
            spectral_slope: analysis.spectral_slope,
            r_squared: analysis.r_squared,
            low_freq_power: 1.0,
            high_freq_power: if analysis.spectral_slope.is_finite() {
                10f64.powf(-analysis.spectral_slope)
            } else {
                0.0
            },
            within_human_range: analysis.is_valid,
        }
    }
}

impl From<&crate::analysis::error_topology::ErrorTopology> for ErrorTopology {
    fn from(topology: &crate::analysis::error_topology::ErrorTopology) -> Self {
        Self {
            gap_ratio: topology.gap_correlation,
            error_clustering: topology.error_hurst,
            adjacent_key_score: topology.adjacency_correlation,
            score: topology.score,
            passed: topology.is_valid,
        }
    }
}

impl From<&crate::analysis::hurst::HurstAnalysis> for Option<f64> {
    fn from(analysis: &crate::analysis::hurst::HurstAnalysis) -> Self {
        Some(analysis.exponent)
    }
}

// --- BiologyInvariantClaim extension ---

/// Extension trait adding `from_analysis` to `BiologyInvariantClaim`.
pub trait BiologyInvariantClaimExt {
    /// Build a scored claim from analysis results, auto-detecting anomalies.
    fn from_analysis(
        measurements: BiologyMeasurements,
        hurst: Option<&crate::analysis::hurst::HurstAnalysis>,
        pink_noise: Option<&crate::analysis::pink_noise::PinkNoiseAnalysis>,
        error_topology: Option<&crate::analysis::error_topology::ErrorTopology>,
    ) -> BiologyInvariantClaim;
}

impl BiologyInvariantClaimExt for BiologyInvariantClaim {
    fn from_analysis(
        measurements: BiologyMeasurements,
        hurst: Option<&crate::analysis::hurst::HurstAnalysis>,
        pink_noise: Option<&crate::analysis::pink_noise::PinkNoiseAnalysis>,
        error_topology: Option<&crate::analysis::error_topology::ErrorTopology>,
    ) -> BiologyInvariantClaim {
        let mut claim = Self::new(measurements, BiologyScoringParameters::default());

        if let Some(h) = hurst {
            claim.hurst_exponent = Some(h.exponent);

            if h.is_white_noise() {
                claim.add_anomaly(AnomalyFlag {
                    anomaly_type: AnomalyType::WhiteNoiseHurst,
                    description: format!("Hurst exponent {:.3} indicates white noise", h.exponent),
                    severity: 3,
                    timestamp_ms: None,
                });
            } else if h.is_suspiciously_predictable() {
                claim.add_anomaly(AnomalyFlag {
                    anomaly_type: AnomalyType::PredictableHurst,
                    description: format!("Hurst exponent {:.3} too predictable", h.exponent),
                    severity: 3,
                    timestamp_ms: None,
                });
            }
        }

        if let Some(pn) = pink_noise {
            claim.pink_noise = Some(pn.into());

            if !pn.is_biologically_plausible() {
                claim.add_anomaly(AnomalyFlag {
                    anomaly_type: AnomalyType::SpectralAnomaly,
                    description: format!(
                        "Spectral slope {:.3} outside human range",
                        pn.spectral_slope
                    ),
                    severity: 2,
                    timestamp_ms: None,
                });
            }
        }

        if let Some(et) = error_topology {
            claim.error_topology = Some(et.into());

            if !et.is_valid {
                claim.add_anomaly(AnomalyFlag {
                    anomaly_type: AnomalyType::ErrorTopologyFail,
                    description: format!("Error topology score {:.3} below threshold", et.score),
                    severity: 2,
                    timestamp_ms: None,
                });
            }
        }

        if claim.measurements.coefficient_of_variation < 0.15 {
            claim.add_anomaly(AnomalyFlag {
                anomaly_type: AnomalyType::RoboticCadence,
                description: format!(
                    "CV {:.3} too low (robotic)",
                    claim.measurements.coefficient_of_variation
                ),
                severity: 3,
                timestamp_ms: None,
            });
        }

        claim.compute_score();

        claim
    }
}

// --- Jitter binding conversions ---

impl From<&crate::analysis::active_probes::GaltonInvariantResult> for GaltonInvariant {
    fn from(result: &crate::analysis::active_probes::GaltonInvariantResult) -> Self {
        Self {
            absorption_coefficient: result.absorption_coefficient,
            stimulus_count: result.perturbation_count as u32,
            expected_absorption: 0.55, // RFC default baseline
            z_score: {
                let denom = result.std_error.max(0.001);
                if denom.is_finite() {
                    (result.absorption_coefficient - 0.55) / denom
                } else {
                    0.0
                }
            },
            passed: result.is_valid,
        }
    }
}

impl From<&crate::analysis::active_probes::ReflexGateResult> for ReflexGate {
    fn from(result: &crate::analysis::active_probes::ReflexGateResult) -> Self {
        let z_scores = [-1.28, -0.67, 0.0, 0.67, 1.28];
        let mean = result.mean_latency_ms;
        let std = result.std_latency_ms;
        Self {
            mean_latency_ms: mean,
            std_dev_ms: std,
            event_count: result.response_count as u32,
            percentiles: [
                (mean + z_scores[0] * std).max(0.0),
                (mean + z_scores[1] * std).max(0.0),
                mean,
                mean + z_scores[3] * std,
                mean + z_scores[4] * std,
            ],
            passed: result.is_valid,
        }
    }
}

impl From<&crate::analysis::active_probes::ActiveProbeResults> for ActiveProbes {
    fn from(results: &crate::analysis::active_probes::ActiveProbeResults) -> Self {
        Self {
            galton_invariant: results.galton.as_ref().map(|g| g.into()),
            reflex_gate: results.reflex.as_ref().map(|r| r.into()),
        }
    }
}

impl From<&crate::analysis::labyrinth::LabyrinthAnalysis> for LabyrinthStructure {
    fn from(analysis: &crate::analysis::labyrinth::LabyrinthAnalysis) -> Self {
        let attractor_points: Vec<Vec<f64>> = Vec::new();

        Self {
            embedding_dimension: analysis.embedding_dimension as u8,
            time_delay: analysis.optimal_delay as u16,
            attractor_points,
            betti_numbers: vec![
                analysis.betti_numbers[0] as u32,
                analysis.betti_numbers[1] as u32,
                analysis.betti_numbers[2] as u32,
            ],
            lyapunov_exponent: None,
            correlation_dimension: analysis.correlation_dimension,
        }
    }
}
