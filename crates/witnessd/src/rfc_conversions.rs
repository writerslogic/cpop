// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Bridge implementations between internal Engine Analysis and RFC Protocol types.
//!
//! These conversions transform high-fidelity engine results into the serialized 
//! structures required by the AuthorProof RFC specifications.

use authorproof_protocol::rfc::biology::{
    AnomalyFlag, AnomalyType, BiologyInvariantClaim, BiologyMeasurements, BiologyScoringParameters,
    ErrorTopology, PinkNoiseAnalysis,
};
use authorproof_protocol::rfc::jitter_binding::{
    ActiveProbes, GaltonInvariant, LabyrinthStructure, ReflexGate,
};

const GALTON_BASELINE_ABSORPTION: f64 = 0.55;
const ROBOTIC_CV_THRESHOLD: f64 = 0.15;
const STANDARD_Z_SCORES: [f64; 5] = [-1.2815, -0.6745, 0.0, 0.6745, 1.2815];

impl From<&crate::analysis::pink_noise::PinkNoiseAnalysis> for PinkNoiseAnalysis {
    fn from(analysis: &crate::analysis::pink_noise::PinkNoiseAnalysis) -> Self {
        Self {
            spectral_slope: analysis.spectral_slope,
            r_squared: analysis.r_squared,
            low_freq_power: 1.0, // Normalized baseline
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

pub trait BiologyInvariantClaimExt {
    fn from_analysis(
        measurements: BiologyMeasurements,
        hurst: Option<&crate::analysis::hurst::HurstAnalysis>,
        pink_noise: Option<&crate::analysis::pink_noise::PinkNoiseAnalysis>,
        error_topology: Option<&crate::analysis::error_topology::ErrorTopology>,
    ) -> BiologyInvariantClaim;
}

impl BiologyInvariantClaimExt for BiologyInvariantClaim {
    /// Constructs a protocol-ready Claim, automatically evaluating biometric anomalies.
    fn from_analysis(
        measurements: BiologyMeasurements,
        hurst: Option<&crate::analysis::hurst::HurstAnalysis>,
        pink_noise: Option<&crate::analysis::pink_noise::PinkNoiseAnalysis>,
        error_topology: Option<&crate::analysis::error_topology::ErrorTopology>,
    ) -> BiologyInvariantClaim {
        let mut claim = Self::new(measurements, BiologyScoringParameters::default());

        // 1. Hurst Exponent Evaluation
        if let Some(h) = hurst {
            claim.hurst_exponent = Some(h.exponent);
            if h.is_white_noise() {
                claim.push_anomaly(AnomalyType::WhiteNoiseHurst, 3, 
                    format!("Hurst {:.3}: stochastic white noise detected", h.exponent));
            } else if h.is_suspiciously_predictable() {
                claim.push_anomaly(AnomalyType::PredictableHurst, 3, 
                    format!("Hurst {:.3}: mechanical predictability detected", h.exponent));
            }
        }

        // 2. Pink Noise (Spectral) Evaluation
        if let Some(pn) = pink_noise {
            claim.pink_noise = Some(pn.into());
            if !pn.is_biologically_plausible() {
                claim.push_anomaly(AnomalyType::SpectralAnomaly, 2, 
                    format!("Spectral slope {:.3} is non-biological", pn.spectral_slope));
            }
        }

        // 3. Error Topology (Cadence Mapping) Evaluation
        if let Some(et) = error_topology {
            claim.error_topology = Some(et.into());
            if !et.is_valid {
                claim.push_anomaly(AnomalyType::ErrorTopologyFail, 2, 
                    format!("Error topology score {:.3} rejected", et.score));
            }
        }

        // 4. Global Robotic Detection (CV Analysis)
        if claim.measurements.coefficient_of_variation < ROBOTIC_CV_THRESHOLD {
            claim.push_anomaly(AnomalyType::RoboticCadence, 3, 
                format!("CV {:.3} indicates automated input", claim.measurements.coefficient_of_variation));
        }

        claim.compute_score();
        claim
    }
}

trait AnomalyHelper {
    fn push_anomaly(&mut self, kind: AnomalyType, severity: u8, desc: String);
}

impl AnomalyHelper for BiologyInvariantClaim {
    fn push_anomaly(&mut self, kind: AnomalyType, severity: u8, desc: String) {
        self.add_anomaly(AnomalyFlag {
            anomaly_type: kind,
            description: desc,
            severity,
            timestamp_ms: None,
        });
    }
}

impl From<&crate::analysis::active_probes::GaltonInvariantResult> for GaltonInvariant {
    fn from(result: &crate::analysis::active_probes::GaltonInvariantResult) -> Self {
        let abs_coeff = result.absorption_coefficient;
        Self {
            absorption_coefficient: abs_coeff,
            stimulus_count: result.perturbation_count as u32,
            expected_absorption: GALTON_BASELINE_ABSORPTION,
            z_score: if result.std_error > f64::EPSILON && result.std_error.is_finite() {
                (abs_coeff - GALTON_BASELINE_ABSORPTION) / result.std_error
            } else {
                0.0
            },
            passed: result.is_valid,
        }
    }
}

impl From<&crate::analysis::active_probes::ReflexGateResult> for ReflexGate {
    fn from(result: &crate::analysis::active_probes::ReflexGateResult) -> Self {
        let (m, s) = (result.mean_latency_ms, result.std_latency_ms);
        
        // Elite: Map percentiles using precise Z-scores in a single pass
        let mut percentiles = [0.0; 5];
        for (i, z) in STANDARD_Z_SCORES.iter().enumerate() {
            percentiles[i] = (m + z * s).max(0.0);
        }

        Self {
            mean_latency_ms: m,
            std_dev_ms: s,
            event_count: result.response_count as u32,
            percentiles,
            passed: result.is_valid,
        }
    }
}

impl From<&crate::analysis::active_probes::ActiveProbeResults> for ActiveProbes {
    fn from(results: &crate::analysis::active_probes::ActiveProbeResults) -> Self {
        Self {
            galton_invariant: results.galton.as_ref().map(Into::into),
            reflex_gate: results.reflex.as_ref().map(Into::into),
        }
    }
}

impl From<&crate::analysis::labyrinth::LabyrinthAnalysis> for LabyrinthStructure {
    fn from(analysis: &crate::analysis::labyrinth::LabyrinthAnalysis) -> Self {
        Self {
            embedding_dimension: analysis.embedding_dimension as u8,
            time_delay: analysis.optimal_delay as u16,
            attractor_points: Vec::new(),
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