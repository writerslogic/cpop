// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! RFC-compliant biology-invariant-claim structure.
//!
//! Implements the biology-invariant-claim CDDL structure from draft-condrey-rats-pop-01
//! for behavioral biometric validation with millibits scoring.

use serde::{Deserialize, Serialize};

/// Validation status for biology invariant claims.
///
/// CDDL Definition:
/// ```cddl
/// validation-status = &(
///   empirical: 1,      ; Validated against empirical data
///   theoretical: 2,    ; Theoretically sound but not empirically validated
///   unsupported: 3     ; Claim not validated
/// )
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
#[derive(Default)]
pub enum ValidationStatus {
    /// Validated against empirical data from user studies.
    #[serde(rename = "empirical")]
    Empirical = 1,

    /// Theoretically sound based on literature, but not empirically validated.
    #[serde(rename = "theoretical")]
    Theoretical = 2,

    /// Claim not validated - use with caution.
    #[serde(rename = "unsupported")]
    #[default]
    Unsupported = 3,
}

impl ValidationStatus {
    /// Returns the status name as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Empirical => "empirical",
            Self::Theoretical => "theoretical",
            Self::Unsupported => "unsupported",
        }
    }
}

/// RFC-compliant biology-invariant-claim structure.
///
/// This structure captures behavioral biometric evidence with scored
/// confidence in millibits (1/1000 of a bit of information).
///
/// CDDL Definition:
/// ```cddl
/// biology-invariant-claim = {
///   1: validation-status,                    ; How the claim was validated
///   2: uint,                                 ; Millibits score (0-10000)
///   3: tstr,                                 ; Parameter version string
///   4: biology-scoring-parameters,           ; Scoring parameters used
///   5: biology-measurements,                 ; Raw measurements
///   ? 6: float64,                            ; Hurst exponent (H_e)
///   ? 7: pink-noise-analysis,                ; 1/f spectral analysis
///   ? 8: error-topology,                     ; Error pattern scoring
///   ? 9: [* anomaly-flag]                    ; Detected anomalies
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiologyInvariantClaim {
    /// How the claim was validated (key 1).
    #[serde(rename = "1")]
    pub validation_status: ValidationStatus,

    /// Millibits score (0-10000) representing confidence (key 2).
    /// 1000 millibits = 1 bit of discriminating information.
    #[serde(rename = "2")]
    pub millibits: u16,

    /// Parameter version string for reproducibility (key 3).
    #[serde(rename = "3")]
    pub parameter_version: String,

    /// Scoring parameters used for this claim (key 4).
    #[serde(rename = "4")]
    pub parameters: BiologyScoringParameters,

    /// Raw behavioral measurements (key 5).
    #[serde(rename = "5")]
    pub measurements: BiologyMeasurements,

    /// Hurst exponent for long-range dependence (key 6).
    /// H_e ≈ 0.7 for human input; reject 0.5 (white noise) or 1.0 (predictable).
    #[serde(rename = "6", skip_serializing_if = "Option::is_none")]
    pub hurst_exponent: Option<f64>,

    /// Pink noise (1/f) spectral analysis (key 7).
    #[serde(rename = "7", skip_serializing_if = "Option::is_none")]
    pub pink_noise: Option<PinkNoiseAnalysis>,

    /// Error topology scoring (key 8).
    #[serde(rename = "8", skip_serializing_if = "Option::is_none")]
    pub error_topology: Option<ErrorTopology>,

    /// Detected anomaly flags (key 9).
    #[serde(rename = "9", skip_serializing_if = "Option::is_none")]
    pub anomaly_flags: Option<Vec<AnomalyFlag>>,
}

/// Scoring parameters for biology invariant calculation.
///
/// CDDL Definition:
/// ```cddl
/// biology-scoring-parameters = {
///   1: float64,        ; Hurst weight (w_H)
///   2: float64,        ; Pink noise weight (w_P)
///   3: float64,        ; Error topology weight (w_E)
///   4: float64,        ; Cadence weight (w_C)
///   5: float64,        ; Threshold for human classification
///   6: uint            ; Minimum sample count
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiologyScoringParameters {
    /// Weight for Hurst exponent in scoring (0.0-1.0).
    #[serde(rename = "1")]
    pub hurst_weight: f64,

    /// Weight for pink noise analysis in scoring (0.0-1.0).
    #[serde(rename = "2")]
    pub pink_noise_weight: f64,

    /// Weight for error topology in scoring (0.0-1.0).
    #[serde(rename = "3")]
    pub error_topology_weight: f64,

    /// Weight for cadence analysis in scoring (0.0-1.0).
    #[serde(rename = "4")]
    pub cadence_weight: f64,

    /// Threshold score for human classification (0.0-1.0).
    #[serde(rename = "5")]
    pub human_threshold: f64,

    /// Minimum number of samples required for valid scoring.
    #[serde(rename = "6")]
    pub min_samples: u32,
}

impl Default for BiologyScoringParameters {
    fn default() -> Self {
        Self {
            hurst_weight: 0.25,
            pink_noise_weight: 0.25,
            error_topology_weight: 0.25,
            cadence_weight: 0.25,
            human_threshold: 0.75,
            min_samples: 100,
        }
    }
}

/// Raw behavioral measurements.
///
/// CDDL Definition:
/// ```cddl
/// biology-measurements = {
///   1: uint,           ; Sample count
///   2: float64,        ; Mean inter-key interval (us)
///   3: float64,        ; Standard deviation (us)
///   4: float64,        ; Coefficient of variation
///   5: [5*float64],    ; Percentiles [10, 25, 50, 75, 90]
///   6: uint,           ; Burst count
///   7: uint,           ; Pause count (> 2 seconds)
///   8: float64         ; Typing rate (keys/minute)
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiologyMeasurements {
    /// Total number of samples analyzed.
    #[serde(rename = "1")]
    pub sample_count: u64,

    /// Mean inter-key interval in microseconds.
    #[serde(rename = "2")]
    pub mean_iki_us: f64,

    /// Standard deviation of intervals in microseconds.
    #[serde(rename = "3")]
    pub std_dev_us: f64,

    /// Coefficient of variation (std_dev / mean).
    #[serde(rename = "4")]
    pub coefficient_of_variation: f64,

    /// Percentile distribution [10th, 25th, 50th, 75th, 90th].
    #[serde(rename = "5")]
    pub percentiles: [f64; 5],

    /// Number of detected typing bursts.
    #[serde(rename = "6")]
    pub burst_count: u32,

    /// Number of pauses (> 2 seconds between keystrokes).
    #[serde(rename = "7")]
    pub pause_count: u32,

    /// Overall typing rate in keys per minute.
    #[serde(rename = "8")]
    pub typing_rate: f64,
}

/// Pink noise (1/f) spectral analysis.
///
/// Human typing exhibits characteristic 1/f noise patterns
/// with spectral slope α between 0.8 and 1.2.
///
/// CDDL Definition:
/// ```cddl
/// pink-noise-analysis = {
///   1: float64,        ; Spectral slope (α)
///   2: float64,        ; R² fit quality
///   3: float64,        ; Low frequency power
///   4: float64,        ; High frequency power
///   5: bool            ; Within human range (0.8 ≤ α ≤ 1.2)
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinkNoiseAnalysis {
    /// Spectral slope α from log-log regression.
    /// Human typing typically has α ∈ [0.8, 1.2].
    #[serde(rename = "1")]
    pub spectral_slope: f64,

    /// R² coefficient of determination for the fit.
    #[serde(rename = "2")]
    pub r_squared: f64,

    /// Power in low frequency band (long-term patterns).
    #[serde(rename = "3")]
    pub low_freq_power: f64,

    /// Power in high frequency band (short-term patterns).
    #[serde(rename = "4")]
    pub high_freq_power: f64,

    /// Whether the slope is within human range [0.8, 1.2].
    #[serde(rename = "5")]
    pub within_human_range: bool,
}

impl PinkNoiseAnalysis {
    /// Check if spectral slope indicates human-like typing.
    pub fn is_human_like(&self) -> bool {
        self.spectral_slope >= 0.8 && self.spectral_slope <= 1.2 && self.r_squared > 0.7
    }
}

/// Error topology analysis.
///
/// Scores error patterns based on physical plausibility:
/// S = 0.4×ρ_gap + 0.4×H + 0.2×adj_phys
///
/// CDDL Definition:
/// ```cddl
/// error-topology = {
///   1: float64,        ; Gap ratio (ρ_gap)
///   2: float64,        ; Error clustering (H) - like deletions
///   3: float64,        ; Adjacent key physical plausibility
///   4: float64,        ; Final score S
///   5: bool            ; Pass (S ≥ 0.75)
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorTopology {
    /// Gap ratio ρ_gap: proportion of errors with natural thinking gaps.
    #[serde(rename = "1")]
    pub gap_ratio: f64,

    /// Error clustering H: how clustered are correction events.
    /// Low values indicate revision passes (human-like).
    #[serde(rename = "2")]
    pub error_clustering: f64,

    /// Adjacent key physical plausibility score.
    /// Higher = errors more likely to be adjacent key typos.
    #[serde(rename = "3")]
    pub adjacent_key_score: f64,

    /// Final composite score: S = 0.4×ρ_gap + 0.4×H + 0.2×adj_phys.
    #[serde(rename = "4")]
    pub score: f64,

    /// Whether the score passes threshold (S ≥ 0.75).
    #[serde(rename = "5")]
    pub passed: bool,
}

impl ErrorTopology {
    /// Calculate the composite score from components.
    pub fn calculate_score(gap_ratio: f64, error_clustering: f64, adjacent_key_score: f64) -> f64 {
        0.4 * gap_ratio + 0.4 * error_clustering + 0.2 * adjacent_key_score
    }

    /// Create a new ErrorTopology with calculated score.
    pub fn new(gap_ratio: f64, error_clustering: f64, adjacent_key_score: f64) -> Self {
        let score = Self::calculate_score(gap_ratio, error_clustering, adjacent_key_score);
        Self {
            gap_ratio,
            error_clustering,
            adjacent_key_score,
            score,
            passed: score >= 0.75,
        }
    }
}

/// Anomaly flag indicating detected suspicious patterns.
///
/// CDDL Definition:
/// ```cddl
/// anomaly-flag = {
///   1: anomaly-type,   ; Type of anomaly
///   2: tstr,           ; Human-readable description
///   3: uint,           ; Severity (1=info, 2=warning, 3=alert)
///   ? 4: uint          ; Timestamp (Unix epoch ms) when detected
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyFlag {
    /// Type of anomaly detected.
    #[serde(rename = "1")]
    pub anomaly_type: AnomalyType,

    /// Human-readable description of the anomaly.
    #[serde(rename = "2")]
    pub description: String,

    /// Severity level: 1=info, 2=warning, 3=alert.
    #[serde(rename = "3")]
    pub severity: u8,

    /// Timestamp when anomaly was detected (Unix epoch ms).
    #[serde(rename = "4", skip_serializing_if = "Option::is_none")]
    pub timestamp_ms: Option<u64>,
}

/// Types of anomalies that can be detected.
///
/// CDDL Definition:
/// ```cddl
/// anomaly-type = &(
///   white-noise-hurst: 1,           ; H ≈ 0.5 (no long-range dependence)
///   predictable-hurst: 2,           ; H ≈ 1.0 (too predictable)
///   robotic-cadence: 3,             ; CV < 0.15 (too consistent)
///   spectral-anomaly: 4,            ; Pink noise outside [0.8, 1.2]
///   error-topology-fail: 5,         ; S < 0.75
///   insufficient-data: 6,           ; Not enough samples
///   temporal-discontinuity: 7,      ; Suspicious time gaps
///   velocity-anomaly: 8             ; Superhuman typing speed
/// )
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AnomalyType {
    /// Hurst exponent ≈ 0.5 (white noise, no long-range dependence).
    #[serde(rename = "white_noise_hurst")]
    WhiteNoiseHurst = 1,

    /// Hurst exponent ≈ 1.0 (too predictable, non-human).
    #[serde(rename = "predictable_hurst")]
    PredictableHurst = 2,

    /// Coefficient of variation < 0.15 (robotic consistency).
    #[serde(rename = "robotic_cadence")]
    RoboticCadence = 3,

    /// Pink noise spectral slope outside [0.8, 1.2].
    #[serde(rename = "spectral_anomaly")]
    SpectralAnomaly = 4,

    /// Error topology score < 0.75.
    #[serde(rename = "error_topology_fail")]
    ErrorTopologyFail = 5,

    /// Insufficient data for reliable analysis.
    #[serde(rename = "insufficient_data")]
    InsufficientData = 6,

    /// Suspicious temporal discontinuity.
    #[serde(rename = "temporal_discontinuity")]
    TemporalDiscontinuity = 7,

    /// Superhuman typing velocity detected.
    #[serde(rename = "velocity_anomaly")]
    VelocityAnomaly = 8,
}

impl BiologyInvariantClaim {
    /// Create a new claim with the given measurements.
    pub fn new(measurements: BiologyMeasurements, parameters: BiologyScoringParameters) -> Self {
        Self {
            validation_status: ValidationStatus::Unsupported,
            millibits: 0,
            parameter_version: "1.0.0".to_string(),
            parameters,
            measurements,
            hurst_exponent: None,
            pink_noise: None,
            error_topology: None,
            anomaly_flags: None,
        }
    }

    /// Add Hurst exponent analysis.
    pub fn with_hurst(mut self, h: f64) -> Self {
        self.hurst_exponent = Some(h);
        self
    }

    /// Add pink noise analysis.
    pub fn with_pink_noise(mut self, analysis: PinkNoiseAnalysis) -> Self {
        self.pink_noise = Some(analysis);
        self
    }

    /// Add error topology analysis.
    pub fn with_error_topology(mut self, topology: ErrorTopology) -> Self {
        self.error_topology = Some(topology);
        self
    }

    /// Add an anomaly flag.
    pub fn add_anomaly(&mut self, flag: AnomalyFlag) {
        if self.anomaly_flags.is_none() {
            self.anomaly_flags = Some(Vec::new());
        }
        self.anomaly_flags.as_mut().unwrap().push(flag);
    }

    /// Calculate and update the millibits score.
    pub fn calculate_score(&mut self) {
        let mut score = 0.0;
        let mut components = 0;

        // Hurst exponent contribution
        if let Some(h) = self.hurst_exponent {
            // Optimal H ≈ 0.7, score drops for H < 0.55 or H > 0.85
            let h_score = if (0.55..=0.85).contains(&h) {
                1.0 - ((h - 0.7).abs() / 0.15)
            } else {
                0.0
            };
            score += h_score * self.parameters.hurst_weight;
            components += 1;
        }

        // Pink noise contribution
        if let Some(ref pn) = self.pink_noise {
            let pn_score = if pn.is_human_like() {
                pn.r_squared
            } else {
                0.0
            };
            score += pn_score * self.parameters.pink_noise_weight;
            components += 1;
        }

        // Error topology contribution
        if let Some(ref et) = self.error_topology {
            score += et.score * self.parameters.error_topology_weight;
            components += 1;
        }

        // Cadence contribution (based on CV)
        let cv = self.measurements.coefficient_of_variation;
        let cv_score = if (0.15..=0.6).contains(&cv) {
            1.0 - ((cv - 0.35).abs() / 0.25).min(1.0)
        } else {
            0.0
        };
        score += cv_score * self.parameters.cadence_weight;
        components += 1;

        // Normalize if not all components present
        if components > 0 && components < 4 {
            let total_weight = if self.hurst_exponent.is_some() {
                self.parameters.hurst_weight
            } else {
                0.0
            } + if self.pink_noise.is_some() {
                self.parameters.pink_noise_weight
            } else {
                0.0
            } + if self.error_topology.is_some() {
                self.parameters.error_topology_weight
            } else {
                0.0
            } + self.parameters.cadence_weight;

            if total_weight > 0.0 {
                score /= total_weight;
            }
        }

        // Convert to millibits (0-10000 scale)
        // 1.0 score = 10 bits = 10000 millibits of discriminating information
        self.millibits = ((score * 10000.0).round() as u16).min(10000);

        // Update validation status based on components
        self.validation_status = if self.hurst_exponent.is_some()
            && self.pink_noise.is_some()
            && self.error_topology.is_some()
        {
            ValidationStatus::Empirical
        } else if components >= 2 {
            ValidationStatus::Theoretical
        } else {
            ValidationStatus::Unsupported
        };
    }

    /// Check if the claim passes human threshold.
    pub fn is_human_like(&self) -> bool {
        (self.millibits as f64 / 10000.0) >= self.parameters.human_threshold
    }

    /// Get anomaly count.
    pub fn anomaly_count(&self) -> usize {
        self.anomaly_flags.as_ref().map_or(0, |v| v.len())
    }

    /// Check if there are any alert-level anomalies.
    pub fn has_alerts(&self) -> bool {
        self.anomaly_flags
            .as_ref()
            .is_some_and(|flags| flags.iter().any(|f| f.severity >= 3))
    }

    /// Comprehensive validation of the BiologyInvariantClaim.
    ///
    /// Returns a list of validation errors, or empty if valid.
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        // Validate millibits range
        if self.millibits > 10000 {
            errors.push(format!("millibits {} exceeds max 10000", self.millibits));
        }

        // Validate parameter version
        if self.parameter_version.is_empty() {
            errors.push("parameter version is empty".into());
        }

        // Validate parameters
        let params = &self.parameters;
        let total_weight = params.hurst_weight
            + params.pink_noise_weight
            + params.error_topology_weight
            + params.cadence_weight;
        if (total_weight - 1.0).abs() > 0.01 && total_weight > 0.0 {
            // Allow 0.0 (no weights set) or 1.0 (normalized)
            errors.push(format!(
                "parameter weights sum to {} (expected 1.0)",
                total_weight
            ));
        }
        if params.human_threshold < 0.0 || params.human_threshold > 1.0 {
            errors.push(format!(
                "human threshold {} out of range [0, 1]",
                params.human_threshold
            ));
        }

        // Validate measurements
        let m = &self.measurements;
        if m.sample_count == 0 {
            errors.push("sample count is zero".into());
        }
        if m.mean_iki_us <= 0.0 {
            errors.push("mean inter-key interval is non-positive".into());
        }
        if m.std_dev_us < 0.0 {
            errors.push("standard deviation is negative".into());
        }
        if m.coefficient_of_variation < 0.0 {
            errors.push("coefficient of variation is negative".into());
        }
        if m.typing_rate < 0.0 {
            errors.push("typing rate is negative".into());
        }
        // Validate percentiles are monotonically increasing
        for i in 1..5 {
            if m.percentiles[i] < m.percentiles[i - 1] {
                errors.push(format!("percentiles not monotonic at index {}", i));
                break;
            }
        }

        // Validate Hurst exponent if present
        if let Some(h) = self.hurst_exponent {
            if !(0.0..=1.0).contains(&h) {
                errors.push(format!("Hurst exponent {} out of range [0, 1]", h));
            }
        }

        // Validate pink noise if present
        if let Some(pn) = &self.pink_noise {
            if pn.r_squared < 0.0 || pn.r_squared > 1.0 {
                errors.push(format!(
                    "pink noise R² {} out of range [0, 1]",
                    pn.r_squared
                ));
            }
        }

        // Validate error topology if present
        if let Some(et) = &self.error_topology {
            if et.score < 0.0 || et.score > 1.0 {
                errors.push(format!(
                    "error topology score {} out of range [0, 1]",
                    et.score
                ));
            }
        }

        errors
    }

    /// Check if the claim is valid (no validation errors).
    pub fn is_valid(&self) -> bool {
        self.validate().is_empty()
    }
}

// ============================================
// Conversion from analysis module types
// ============================================

impl From<&crate::analysis::pink_noise::PinkNoiseAnalysis> for PinkNoiseAnalysis {
    fn from(analysis: &crate::analysis::pink_noise::PinkNoiseAnalysis) -> Self {
        Self {
            spectral_slope: analysis.spectral_slope,
            r_squared: analysis.r_squared,
            // Estimate power distribution (simplified)
            low_freq_power: 1.0,                                   // Normalized
            high_freq_power: 10f64.powf(-analysis.spectral_slope), // Relative power at 10x frequency
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

/// Builder for creating BiologyInvariantClaim from analysis results.
impl BiologyInvariantClaim {
    /// Create a BiologyInvariantClaim from analysis module results.
    pub fn from_analysis(
        measurements: BiologyMeasurements,
        hurst: Option<&crate::analysis::hurst::HurstAnalysis>,
        pink_noise: Option<&crate::analysis::pink_noise::PinkNoiseAnalysis>,
        error_topology: Option<&crate::analysis::error_topology::ErrorTopology>,
    ) -> Self {
        let mut claim = Self::new(measurements, BiologyScoringParameters::default());

        if let Some(h) = hurst {
            claim.hurst_exponent = Some(h.exponent);

            // Add anomaly flags based on Hurst analysis
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

        // Check cadence
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

        // Calculate final score
        claim.calculate_score();

        claim
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_measurements() -> BiologyMeasurements {
        BiologyMeasurements {
            sample_count: 1000,
            mean_iki_us: 150000.0, // 150ms mean
            std_dev_us: 50000.0,   // 50ms std dev
            coefficient_of_variation: 0.33,
            percentiles: [50000.0, 80000.0, 140000.0, 200000.0, 300000.0],
            burst_count: 50,
            pause_count: 10,
            typing_rate: 60.0, // 60 WPM equivalent
        }
    }

    #[test]
    fn test_biology_claim_serialization() {
        let measurements = create_test_measurements();
        let claim = BiologyInvariantClaim::new(measurements, BiologyScoringParameters::default());

        let json = serde_json::to_string_pretty(&claim).unwrap();
        let decoded: BiologyInvariantClaim = serde_json::from_str(&json).unwrap();

        assert_eq!(
            claim.measurements.sample_count,
            decoded.measurements.sample_count
        );
    }

    #[test]
    fn test_error_topology_scoring() {
        let topology = ErrorTopology::new(0.8, 0.7, 0.9);

        // S = 0.4×0.8 + 0.4×0.7 + 0.2×0.9 = 0.32 + 0.28 + 0.18 = 0.78
        assert!((topology.score - 0.78).abs() < 0.01);
        assert!(topology.passed);

        let failing_topology = ErrorTopology::new(0.5, 0.5, 0.5);
        // S = 0.4×0.5 + 0.4×0.5 + 0.2×0.5 = 0.2 + 0.2 + 0.1 = 0.5
        assert!((failing_topology.score - 0.5).abs() < 0.01);
        assert!(!failing_topology.passed);
    }

    #[test]
    fn test_pink_noise_validation() {
        let good_pn = PinkNoiseAnalysis {
            spectral_slope: 1.0,
            r_squared: 0.85,
            low_freq_power: 100.0,
            high_freq_power: 10.0,
            within_human_range: true,
        };
        assert!(good_pn.is_human_like());

        let bad_pn = PinkNoiseAnalysis {
            spectral_slope: 0.3, // Too low (white noise)
            r_squared: 0.9,
            low_freq_power: 100.0,
            high_freq_power: 50.0,
            within_human_range: false,
        };
        assert!(!bad_pn.is_human_like());
    }

    #[test]
    fn test_score_calculation() {
        let measurements = create_test_measurements();
        let mut claim =
            BiologyInvariantClaim::new(measurements, BiologyScoringParameters::default())
                .with_hurst(0.72)
                .with_pink_noise(PinkNoiseAnalysis {
                    spectral_slope: 1.0,
                    r_squared: 0.85,
                    low_freq_power: 100.0,
                    high_freq_power: 10.0,
                    within_human_range: true,
                })
                .with_error_topology(ErrorTopology::new(0.8, 0.7, 0.9));

        claim.calculate_score();

        assert!(claim.millibits > 5000); // Should be reasonably high for human-like data
        assert_eq!(claim.validation_status, ValidationStatus::Empirical);
    }

    #[test]
    fn test_anomaly_flags() {
        let measurements = create_test_measurements();
        let mut claim =
            BiologyInvariantClaim::new(measurements, BiologyScoringParameters::default());

        claim.add_anomaly(AnomalyFlag {
            anomaly_type: AnomalyType::RoboticCadence,
            description: "CV too low".to_string(),
            severity: 2,
            timestamp_ms: Some(1700000000000),
        });

        assert_eq!(claim.anomaly_count(), 1);
        assert!(!claim.has_alerts());

        claim.add_anomaly(AnomalyFlag {
            anomaly_type: AnomalyType::VelocityAnomaly,
            description: "Superhuman speed".to_string(),
            severity: 3,
            timestamp_ms: None,
        });

        assert_eq!(claim.anomaly_count(), 2);
        assert!(claim.has_alerts());
    }
}
