// SPDX-License-Identifier: Apache-2.0

//! RFC-compliant biology-invariant-claim structure.
//!
//! Implements the biology-invariant-claim CDDL structure from draft-condrey-rats-pop-01
//! for behavioral biometric validation with millibits scoring.

use serde::{Deserialize, Serialize};

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
    /// Validated against empirical data.
    #[serde(rename = "empirical")]
    Empirical = 1,

    /// Theoretically sound but not empirically validated.
    #[serde(rename = "theoretical")]
    Theoretical = 2,

    /// Claim not validated.
    #[serde(rename = "unsupported")]
    #[default]
    Unsupported = 3,
}

impl ValidationStatus {
    /// Return the string representation of this status.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Empirical => "empirical",
            Self::Theoretical => "theoretical",
            Self::Unsupported => "unsupported",
        }
    }
}

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
    #[serde(rename = "1")]
    pub validation_status: ValidationStatus,

    /// 0-10000; 1000 = 1 bit of discriminating info
    #[serde(rename = "2")]
    pub millibits: u16,

    #[serde(rename = "3")]
    pub parameter_version: String,

    #[serde(rename = "4")]
    pub parameters: BiologyScoringParameters,

    #[serde(rename = "5")]
    pub measurements: BiologyMeasurements,

    /// H_e ~ 0.7 for human input; reject 0.5 (white noise) or 1.0 (predictable)
    #[serde(rename = "6", skip_serializing_if = "Option::is_none")]
    pub hurst_exponent: Option<f64>,

    #[serde(rename = "7", skip_serializing_if = "Option::is_none")]
    pub pink_noise: Option<PinkNoiseAnalysis>,

    #[serde(rename = "8", skip_serializing_if = "Option::is_none")]
    pub error_topology: Option<ErrorTopology>,

    #[serde(rename = "9", skip_serializing_if = "Option::is_none")]
    pub anomaly_flags: Option<Vec<AnomalyFlag>>,
}

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
    #[serde(rename = "1")]
    pub hurst_weight: f64,

    #[serde(rename = "2")]
    pub pink_noise_weight: f64,

    #[serde(rename = "3")]
    pub error_topology_weight: f64,

    #[serde(rename = "4")]
    pub cadence_weight: f64,

    #[serde(rename = "5")]
    pub human_threshold: f64,

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
    #[serde(rename = "1")]
    pub sample_count: u64,

    /// Microseconds
    #[serde(rename = "2")]
    pub mean_iki_us: f64,

    /// Microseconds
    #[serde(rename = "3")]
    pub std_dev_us: f64,

    #[serde(rename = "4")]
    pub coefficient_of_variation: f64,

    /// [10th, 25th, 50th, 75th, 90th]
    #[serde(rename = "5")]
    pub percentiles: [f64; 5],

    #[serde(rename = "6")]
    pub burst_count: u32,

    /// Pauses > 2s
    #[serde(rename = "7")]
    pub pause_count: u32,

    /// Keys per minute
    #[serde(rename = "8")]
    pub typing_rate: f64,
}

/// Human typing: 1/f noise with α ∈ [0.8, 1.2].
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
    /// Human typing: α ∈ [0.8, 1.2]
    #[serde(rename = "1")]
    pub spectral_slope: f64,

    #[serde(rename = "2")]
    pub r_squared: f64,

    #[serde(rename = "3")]
    pub low_freq_power: f64,

    #[serde(rename = "4")]
    pub high_freq_power: f64,

    #[serde(rename = "5")]
    pub within_human_range: bool,
}

impl PinkNoiseAnalysis {
    /// Return `true` if slope and fit quality fall within human typing ranges.
    pub fn is_human_like(&self) -> bool {
        self.spectral_slope >= 0.8 && self.spectral_slope <= 1.2 && self.r_squared > 0.7
    }
}

/// S = 0.4*ρ_gap + 0.4*H + 0.2*adj_phys
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
    #[serde(rename = "1")]
    pub gap_ratio: f64,

    #[serde(rename = "2")]
    pub error_clustering: f64,

    #[serde(rename = "3")]
    pub adjacent_key_score: f64,

    /// 0.4*gap_ratio + 0.4*error_clustering + 0.2*adjacent_key_score
    #[serde(rename = "4")]
    pub score: f64,

    /// score >= 0.75
    #[serde(rename = "5")]
    pub passed: bool,
}

impl ErrorTopology {
    /// Compute the weighted error topology score from component values.
    pub fn compute_score(gap_ratio: f64, error_clustering: f64, adjacent_key_score: f64) -> f64 {
        0.4 * gap_ratio + 0.4 * error_clustering + 0.2 * adjacent_key_score
    }

    /// Create a new topology with auto-calculated score and pass/fail.
    pub fn new(gap_ratio: f64, error_clustering: f64, adjacent_key_score: f64) -> Self {
        let score = Self::compute_score(gap_ratio, error_clustering, adjacent_key_score);
        Self {
            gap_ratio,
            error_clustering,
            adjacent_key_score,
            score,
            passed: score >= 0.75,
        }
    }
}

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
    #[serde(rename = "1")]
    pub anomaly_type: AnomalyType,

    #[serde(rename = "2")]
    pub description: String,

    /// 1=info, 2=warning, 3=alert
    #[serde(rename = "3")]
    pub severity: u8,

    /// Unix epoch ms
    #[serde(rename = "4", skip_serializing_if = "Option::is_none")]
    pub timestamp_ms: Option<u64>,
}

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
    /// H ~ 0.5 (no long-range dependence).
    #[serde(rename = "white_noise_hurst")]
    WhiteNoiseHurst = 1,
    /// H ~ 1.0 (too predictable).
    #[serde(rename = "predictable_hurst")]
    PredictableHurst = 2,
    /// CV < 0.15 (too consistent).
    #[serde(rename = "robotic_cadence")]
    RoboticCadence = 3,
    /// Pink noise slope outside [0.8, 1.2].
    #[serde(rename = "spectral_anomaly")]
    SpectralAnomaly = 4,
    /// Error topology score below 0.75.
    #[serde(rename = "error_topology_fail")]
    ErrorTopologyFail = 5,
    /// Not enough samples for analysis.
    #[serde(rename = "insufficient_data")]
    InsufficientData = 6,
    /// Suspicious time gaps detected.
    #[serde(rename = "temporal_discontinuity")]
    TemporalDiscontinuity = 7,
    /// Superhuman typing speed detected.
    #[serde(rename = "velocity_anomaly")]
    VelocityAnomaly = 8,
}

impl BiologyInvariantClaim {
    /// Create an unscored claim with default validation status.
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

    /// Attach a Hurst exponent measurement.
    pub fn with_hurst(mut self, h: f64) -> Self {
        self.hurst_exponent = Some(h);
        self
    }

    /// Attach a pink noise analysis result.
    pub fn with_pink_noise(mut self, analysis: PinkNoiseAnalysis) -> Self {
        self.pink_noise = Some(analysis);
        self
    }

    /// Attach an error topology analysis result.
    pub fn with_error_topology(mut self, topology: ErrorTopology) -> Self {
        self.error_topology = Some(topology);
        self
    }

    /// Append an anomaly flag, creating the list if needed.
    pub fn add_anomaly(&mut self, flag: AnomalyFlag) {
        self.anomaly_flags.get_or_insert_with(Vec::new).push(flag);
    }

    /// Compute millibits score and validation status from available components.
    pub fn compute_score(&mut self) {
        let mut score = 0.0;
        let mut components = 0;

        if let Some(h) = self.hurst_exponent {
            if h.is_finite() {
                // Optimal H ≈ 0.7, score drops for H < 0.55 or H > 0.85
                let h_score = if (0.55..=0.85).contains(&h) {
                    1.0 - ((h - 0.7).abs() / 0.15)
                } else {
                    0.0
                };
                score += h_score * self.parameters.hurst_weight;
                components += 1;
            }
        }

        if let Some(ref pn) = self.pink_noise {
            let pn_score = if pn.is_human_like() {
                pn.r_squared
            } else {
                0.0
            };
            if pn_score.is_finite() {
                score += pn_score * self.parameters.pink_noise_weight;
                components += 1;
            }
        }

        if let Some(ref et) = self.error_topology {
            if et.score.is_finite() {
                score += et.score * self.parameters.error_topology_weight;
                components += 1;
            }
        }

        let cv = self.measurements.coefficient_of_variation;
        let cv_score = if cv.is_finite() && (0.15..=0.6).contains(&cv) {
            1.0 - ((cv - 0.35).abs() / 0.25).min(1.0)
        } else {
            0.0
        };
        score += cv_score * self.parameters.cadence_weight;
        components += 1;

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

        // NaN.clamp() returns the lower bound, so this safely handles NaN/negative
        self.millibits = (score * 10000.0).round().clamp(0.0, 10000.0) as u16;

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

    /// Return `true` if the millibits score meets the human threshold.
    pub fn is_human_like(&self) -> bool {
        (self.millibits as f64 / 10000.0) >= self.parameters.human_threshold
    }

    /// Return the number of recorded anomaly flags.
    pub fn anomaly_count(&self) -> usize {
        self.anomaly_flags.as_ref().map_or(0, |v| v.len())
    }

    /// Return `true` if any anomaly has severity >= 3 (alert level).
    pub fn has_alerts(&self) -> bool {
        self.anomaly_flags
            .as_ref()
            .is_some_and(|flags| flags.iter().any(|f| f.severity >= 3))
    }

    /// Validate all fields and return a list of errors (empty if valid).
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        if self.millibits > 10000 {
            errors.push(format!("millibits {} exceeds max 10000", self.millibits));
        }

        if self.parameter_version.is_empty() {
            errors.push("parameter version is empty".into());
        }

        let params = &self.parameters;
        let weights = [
            params.hurst_weight,
            params.pink_noise_weight,
            params.error_topology_weight,
            params.cadence_weight,
        ];
        for (i, &w) in weights.iter().enumerate() {
            if !w.is_finite() {
                errors.push(format!("parameter weight[{}] is NaN or infinite", i));
            }
        }
        if !params.human_threshold.is_finite() {
            errors.push("human_threshold is NaN or infinite".into());
        }
        let total_weight = params.hurst_weight
            + params.pink_noise_weight
            + params.error_topology_weight
            + params.cadence_weight;
        const WEIGHT_SUM_TOLERANCE: f64 = 0.01;
        if (total_weight - 1.0).abs() > WEIGHT_SUM_TOLERANCE && total_weight > 0.0 {
            // Allow 0.0 (unset) or 1.0 (normalized)
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
        for i in 1..5 {
            if m.percentiles[i] < m.percentiles[i - 1] {
                errors.push(format!("percentiles not monotonic at index {}", i));
                break;
            }
        }

        if let Some(h) = self.hurst_exponent {
            if !(0.0..=1.0).contains(&h) {
                errors.push(format!("Hurst exponent {} out of range [0, 1]", h));
            }
        }

        if let Some(pn) = &self.pink_noise {
            if pn.r_squared < 0.0 || pn.r_squared > 1.0 {
                errors.push(format!(
                    "pink noise R² {} out of range [0, 1]",
                    pn.r_squared
                ));
            }
        }

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

    /// Return `true` if `validate()` produces no errors.
    pub fn is_valid(&self) -> bool {
        self.validate().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_measurements() -> BiologyMeasurements {
        BiologyMeasurements {
            sample_count: 1000,
            mean_iki_us: 150000.0,
            std_dev_us: 50000.0,
            coefficient_of_variation: 0.33,
            percentiles: [50000.0, 80000.0, 140000.0, 200000.0, 300000.0],
            burst_count: 50,
            pause_count: 10,
            typing_rate: 60.0,
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
            spectral_slope: 0.3,
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

        claim.compute_score();

        assert!(claim.millibits > 5000);
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
