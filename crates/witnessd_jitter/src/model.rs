// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Statistical model for human typing validation.
//!
//! Based on the Aalto 136M keystroke dataset for baseline human
//! inter-key interval (IKI) distributions.

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec, vec::Vec};

use serde::{Deserialize, Serialize};

/// Platform-independent square root function.
/// Uses std when available, falls back to libm for no_std.
#[inline]
fn sqrt(x: f64) -> f64 {
    #[cfg(feature = "std")]
    {
        x.sqrt()
    }
    #[cfg(not(feature = "std"))]
    {
        libm::sqrt(x)
    }
}

use crate::Jitter;

/// Minimum standard deviation threshold for human-like jitter.
/// Below this value, the sequence is flagged as automation.
const MIN_STD_DEV_THRESHOLD: f64 = 50.0;

/// Confidence penalty per detected anomaly.
const CONFIDENCE_PENALTY_PER_ANOMALY: f64 = 0.25;

/// Minimum confidence threshold for human classification.
const MIN_HUMAN_CONFIDENCE: f64 = 0.5;

/// Threshold ratio for repeating pattern detection (80%).
const REPEATING_PATTERN_THRESHOLD: f64 = 0.8;

/// Minimum checks required for pattern detection.
const MIN_PATTERN_CHECKS: usize = 2;

/// Minimum standard deviation threshold for human-like IKI values.
/// IKI values have higher natural variance than jitter, so this threshold is higher.
const MIN_IKI_STD_DEV_THRESHOLD: f64 = 5000.0;

/// Statistical model for validating jitter sequences against human typing patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HumanModel {
    /// Minimum inter-key interval in microseconds (for IKI validation, not jitter).
    /// Used by `validate_iki()` to check actual keystroke timing data.
    pub iki_min_us: u32,
    /// Maximum inter-key interval in microseconds (for IKI validation, not jitter).
    /// Used by `validate_iki()` to check actual keystroke timing data.
    pub iki_max_us: u32,
    /// Mean inter-key interval in microseconds (Aalto: ~200ms = 200,000μs).
    /// Used by `validate_iki()` for statistical analysis.
    pub iki_mean_us: u32,
    /// Standard deviation of IKI in microseconds.
    /// Used by `validate_iki()` for statistical analysis.
    pub iki_std_us: u32,
    /// Minimum jitter delay in microseconds.
    pub jitter_min_us: u32,
    /// Maximum jitter delay in microseconds.
    pub jitter_max_us: u32,
    /// Minimum sequence length for statistical validation.
    pub min_sequence_length: usize,
    /// Maximum allowed perfect-timing ratio (detects automation).
    pub max_perfect_ratio: f64,
}

impl Default for HumanModel {
    fn default() -> Self {
        // Based on Aalto 136M keystroke dataset analysis
        Self {
            iki_min_us: 30_000,      // 30ms minimum (very fast typist)
            iki_max_us: 2_000_000,   // 2s maximum (thinking pause)
            iki_mean_us: 200_000,    // 200ms mean
            iki_std_us: 80_000,      // 80ms std dev
            jitter_min_us: 500,      // Matches compute_jitter output minimum
            jitter_max_us: 3000,     // Matches compute_jitter output maximum
            min_sequence_length: 20, // Minimum keystrokes for validation
            max_perfect_ratio: 0.05, // Max 5% can be "perfect" timing
        }
    }
}

/// Result of validating a jitter sequence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    /// Whether the sequence appears human-generated.
    pub is_human: bool,
    /// Confidence score (0.0 to 1.0).
    pub confidence: f64,
    /// Detected anomalies.
    pub anomalies: Vec<Anomaly>,
    /// Statistics about the sequence.
    pub stats: SequenceStats,
}

/// Detected anomaly in jitter sequence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anomaly {
    /// Type of anomaly.
    pub kind: AnomalyKind,
    /// Position in sequence where anomaly was detected.
    pub position: usize,
    /// Additional context.
    pub detail: String,
}

/// Types of anomalies that can be detected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnomalyKind {
    /// Too many perfectly timed intervals.
    PerfectTiming,
    /// Interval outside human range.
    OutOfRange,
    /// Statistical distribution mismatch.
    DistributionMismatch,
    /// Repeating pattern detected.
    RepeatingPattern,
    /// Unnaturally low variance.
    LowVariance,
}

/// Statistics about a jitter sequence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequenceStats {
    /// Number of samples.
    pub count: usize,
    /// Mean jitter value.
    pub mean: f64,
    /// Standard deviation.
    pub std_dev: f64,
    /// Minimum value.
    pub min: Jitter,
    /// Maximum value.
    pub max: Jitter,
}

impl HumanModel {
    /// Load baseline model from embedded JSON (Aalto 136M keystroke dataset).
    #[cfg(feature = "std")]
    pub fn baseline() -> Self {
        const BASELINE: &str = include_str!("baseline.json");
        serde_json::from_str(BASELINE).expect("embedded baseline is valid")
    }

    /// Load model from JSON string.
    #[cfg(feature = "std")]
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Serialize model to JSON string.
    #[cfg(feature = "std")]
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Validate a sequence of jitter values against human typing patterns.
    pub fn validate(&self, jitters: &[Jitter]) -> ValidationResult {
        let mut anomalies = Vec::new();

        if jitters.len() < self.min_sequence_length {
            return ValidationResult {
                is_human: false,
                confidence: 0.0,
                anomalies: vec![Anomaly {
                    kind: AnomalyKind::DistributionMismatch,
                    position: 0,
                    detail: format!(
                        "Sequence too short: {} < {}",
                        jitters.len(),
                        self.min_sequence_length
                    ),
                }],
                stats: self.compute_stats(jitters),
            };
        }

        let stats = self.compute_stats(jitters);

        // Check for low variance (automation signal)
        if stats.std_dev < MIN_STD_DEV_THRESHOLD {
            anomalies.push(Anomaly {
                kind: AnomalyKind::LowVariance,
                position: 0,
                detail: format!("Variance too low: std_dev={:.2}", stats.std_dev),
            });
        }

        // Check for perfect timing (exact same values)
        let perfect_count = self.count_perfect_timing(jitters);
        let perfect_ratio = perfect_count as f64 / jitters.len() as f64;
        if perfect_ratio > self.max_perfect_ratio {
            anomalies.push(Anomaly {
                kind: AnomalyKind::PerfectTiming,
                position: 0,
                detail: format!("Too many perfect timings: {:.1}%", perfect_ratio * 100.0),
            });
        }

        // Check for repeating patterns
        if let Some(pattern_len) = self.detect_repeating_pattern(jitters) {
            anomalies.push(Anomaly {
                kind: AnomalyKind::RepeatingPattern,
                position: 0,
                detail: format!("Repeating pattern of length {}", pattern_len),
            });
        }

        // Check for out-of-range jitter values (summarize to avoid flooding)
        let out_of_range: Vec<usize> = jitters
            .iter()
            .enumerate()
            .filter(|(_, &j)| j < self.jitter_min_us || j > self.jitter_max_us)
            .map(|(i, _)| i)
            .collect();

        if !out_of_range.is_empty() {
            anomalies.push(Anomaly {
                kind: AnomalyKind::OutOfRange,
                position: out_of_range[0],
                detail: format!(
                    "{} jitter values outside [{}, {}]μs range",
                    out_of_range.len(),
                    self.jitter_min_us,
                    self.jitter_max_us
                ),
            });
        }

        // Calculate confidence based on anomalies
        let base_confidence = 1.0 - (anomalies.len() as f64 * CONFIDENCE_PENALTY_PER_ANOMALY);
        let confidence = base_confidence.clamp(0.0, 1.0);

        ValidationResult {
            is_human: anomalies.is_empty() && confidence > MIN_HUMAN_CONFIDENCE,
            confidence,
            anomalies,
            stats,
        }
    }

    /// Compute statistics for a jitter sequence.
    fn compute_stats(&self, jitters: &[Jitter]) -> SequenceStats {
        if jitters.is_empty() {
            return SequenceStats {
                count: 0,
                mean: 0.0,
                std_dev: 0.0,
                min: 0,
                max: 0,
            };
        }

        let count = jitters.len();
        let sum: u64 = jitters.iter().map(|&j| j as u64).sum();
        let mean = sum as f64 / count as f64;

        let variance: f64 = jitters
            .iter()
            .map(|&j| {
                let diff = j as f64 - mean;
                diff * diff
            })
            .sum::<f64>()
            / count as f64;

        let std_dev = sqrt(variance);
        let min = *jitters.iter().min().unwrap_or(&0);
        let max = *jitters.iter().max().unwrap_or(&0);

        SequenceStats {
            count,
            mean,
            std_dev,
            min,
            max,
        }
    }

    /// Count consecutive identical values (perfect timing).
    fn count_perfect_timing(&self, jitters: &[Jitter]) -> usize {
        jitters.windows(2).filter(|w| w[0] == w[1]).count()
    }

    /// Detect repeating patterns in jitter sequence.
    fn detect_repeating_pattern(&self, jitters: &[Jitter]) -> Option<usize> {
        if jitters.len() < 6 {
            return None;
        }

        // Check for patterns of length 2-5
        for pattern_len in 2..=5 {
            if jitters.len() < pattern_len * 3 {
                continue;
            }

            let pattern = &jitters[..pattern_len];
            let mut matches = 0;
            let mut checks = 0;

            for chunk in jitters.chunks(pattern_len) {
                if chunk.len() == pattern_len {
                    checks += 1;
                    if chunk == pattern {
                        matches += 1;
                    }
                }
            }

            // If >80% match the pattern, it's suspicious
            if checks > MIN_PATTERN_CHECKS
                && matches as f64 / checks as f64 > REPEATING_PATTERN_THRESHOLD
            {
                return Some(pattern_len);
            }
        }

        None
    }

    /// Validate actual inter-key intervals (not jitter values).
    ///
    /// Use this when you have real keystroke timing data, not computed jitter delays.
    /// IKI values are typically in the range of 30ms-2000ms for human typing.
    ///
    /// # Arguments
    ///
    /// * `intervals_us` - Slice of inter-key intervals in microseconds
    ///
    /// # Returns
    ///
    /// A `ValidationResult` indicating whether the timing appears human-generated.
    pub fn validate_iki(&self, intervals_us: &[u64]) -> ValidationResult {
        let mut anomalies = Vec::new();

        if intervals_us.len() < self.min_sequence_length {
            return ValidationResult {
                is_human: false,
                confidence: 0.0,
                anomalies: vec![Anomaly {
                    kind: AnomalyKind::DistributionMismatch,
                    position: 0,
                    detail: format!(
                        "Sequence too short: {} < {}",
                        intervals_us.len(),
                        self.min_sequence_length
                    ),
                }],
                stats: SequenceStats {
                    count: intervals_us.len(),
                    mean: 0.0,
                    std_dev: 0.0,
                    min: 0,
                    max: 0,
                },
            };
        }

        // Check for out-of-range IKI values
        let out_of_range: Vec<usize> = intervals_us
            .iter()
            .enumerate()
            .filter(|(_, &iki)| iki < self.iki_min_us as u64 || iki > self.iki_max_us as u64)
            .map(|(i, _)| i)
            .collect();

        if !out_of_range.is_empty() {
            anomalies.push(Anomaly {
                kind: AnomalyKind::OutOfRange,
                position: out_of_range[0],
                detail: format!(
                    "{} IKI values outside [{}, {}]μs range",
                    out_of_range.len(),
                    self.iki_min_us,
                    self.iki_max_us
                ),
            });
        }

        // Compute stats (convert to Jitter/u32 for stats, capping at u32::MAX)
        let capped: Vec<u32> = intervals_us
            .iter()
            .map(|&v| v.min(u32::MAX as u64) as u32)
            .collect();
        let stats = self.compute_stats(&capped);

        // Check for low variance (automation signal)
        // IKI values have higher natural variance than jitter, so use a higher threshold
        if stats.std_dev < MIN_IKI_STD_DEV_THRESHOLD {
            anomalies.push(Anomaly {
                kind: AnomalyKind::LowVariance,
                position: 0,
                detail: format!("IKI variance too low: std_dev={:.2}μs", stats.std_dev),
            });
        }

        // Check for perfect timing (exact same values)
        let perfect_count = self.count_perfect_timing(&capped);
        let perfect_ratio = perfect_count as f64 / capped.len() as f64;
        if perfect_ratio > self.max_perfect_ratio {
            anomalies.push(Anomaly {
                kind: AnomalyKind::PerfectTiming,
                position: 0,
                detail: format!(
                    "Too many perfect IKI timings: {:.1}%",
                    perfect_ratio * 100.0
                ),
            });
        }

        // Check for repeating patterns
        if let Some(pattern_len) = self.detect_repeating_pattern(&capped) {
            anomalies.push(Anomaly {
                kind: AnomalyKind::RepeatingPattern,
                position: 0,
                detail: format!("Repeating IKI pattern of length {}", pattern_len),
            });
        }

        let base_confidence = 1.0 - (anomalies.len() as f64 * CONFIDENCE_PENALTY_PER_ANOMALY);
        let confidence = base_confidence.clamp(0.0, 1.0);

        ValidationResult {
            is_human: anomalies.is_empty() && confidence > MIN_HUMAN_CONFIDENCE,
            confidence,
            anomalies,
            stats,
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn test_human_validation() {
        let model = HumanModel::default();

        // Simulate human-like jitter (varied values)
        let human_jitters: Vec<Jitter> = (0..50).map(|i| 500 + ((i * 37) % 2500) as u32).collect();

        let result = model.validate(&human_jitters);
        assert!(result.confidence > 0.5);
    }

    #[test]
    fn test_automation_detection() {
        let model = HumanModel::default();

        // Constant values (automation signal)
        let automated_jitters: Vec<Jitter> = vec![1000; 50];

        let result = model.validate(&automated_jitters);
        assert!(!result.is_human);
        assert!(result
            .anomalies
            .iter()
            .any(|a| matches!(a.kind, AnomalyKind::LowVariance)));
    }

    #[test]
    fn test_repeating_pattern_detection() {
        let model = HumanModel::default();

        // Repeating pattern
        let pattern_jitters: Vec<Jitter> = (0..50).map(|i| [1000, 1500, 2000][i % 3]).collect();

        let result = model.validate(&pattern_jitters);
        assert!(result
            .anomalies
            .iter()
            .any(|a| matches!(a.kind, AnomalyKind::RepeatingPattern)));
    }

    #[test]
    fn test_baseline_loading() {
        let model = HumanModel::baseline();
        assert_eq!(model.iki_mean_us, 200_000);
        assert_eq!(model.jitter_min_us, 500);
    }

    #[test]
    fn test_iki_validation_human() {
        let model = HumanModel::default();

        // Simulate human-like IKI values (varied values in 30ms-2000ms range)
        let human_iki: Vec<u64> = (0..50)
            .map(|i| 50_000 + ((i * 37_123) % 500_000) as u64)
            .collect();

        let result = model.validate_iki(&human_iki);
        assert!(result.confidence > 0.5);
        assert!(result.is_human);
    }

    #[test]
    fn test_iki_validation_automation() {
        let model = HumanModel::default();

        // Constant IKI values (automation signal)
        let automated_iki: Vec<u64> = vec![100_000; 50];

        let result = model.validate_iki(&automated_iki);
        assert!(!result.is_human);
        assert!(result
            .anomalies
            .iter()
            .any(|a| matches!(a.kind, AnomalyKind::LowVariance)));
    }

    #[test]
    fn test_iki_validation_out_of_range() {
        let model = HumanModel::default();

        // IKI values below minimum (too fast - automation)
        let fast_iki: Vec<u64> = (0..50)
            .map(|i| 10_000 + ((i * 1_000) % 15_000) as u64) // 10-25ms, below 30ms minimum
            .collect();

        let result = model.validate_iki(&fast_iki);
        assert!(!result.is_human);
        assert!(result
            .anomalies
            .iter()
            .any(|a| matches!(a.kind, AnomalyKind::OutOfRange)));
    }

    #[test]
    fn test_iki_validation_too_short() {
        let model = HumanModel::default();

        // Sequence too short
        let short_iki: Vec<u64> = vec![100_000, 150_000, 200_000];

        let result = model.validate_iki(&short_iki);
        assert!(!result.is_human);
        assert_eq!(result.confidence, 0.0);
        assert!(result
            .anomalies
            .iter()
            .any(|a| matches!(a.kind, AnomalyKind::DistributionMismatch)));
    }

    #[test]
    fn test_empty_jitter_sequence() {
        let model = HumanModel::default();
        let result = model.validate(&[]);
        assert!(!result.is_human);
        assert_eq!(result.stats.count, 0);
    }

    #[test]
    fn test_single_jitter_value() {
        let model = HumanModel::default();
        let result = model.validate(&[1500]);
        assert!(!result.is_human); // Too short
    }

    #[test]
    fn test_exactly_min_sequence_length() {
        let model = HumanModel::default();
        // Create exactly min_sequence_length varied values
        let jitters: Vec<Jitter> = (0..model.min_sequence_length)
            .map(|i| 500 + ((i * 123) % 2500) as u32)
            .collect();
        let result = model.validate(&jitters);
        assert!(result.confidence > 0.0);
    }
}
