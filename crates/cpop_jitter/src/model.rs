// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Statistical model for human typing validation (Aalto 136M keystroke baseline).

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec, vec::Vec};

use serde::{Deserialize, Serialize};

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

const MIN_STD_DEV_THRESHOLD: f64 = 50.0;
const MIN_IKI_STD_DEV_THRESHOLD: f64 = 5000.0;
const CONFIDENCE_PENALTY_PER_ANOMALY: f64 = 0.25;
const MIN_HUMAN_CONFIDENCE: f64 = 0.5;
const REPEATING_PATTERN_THRESHOLD: f64 = 0.8;
const MIN_PATTERN_CHECKS: usize = 2;

/// Statistical model of human typing patterns for automation detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HumanModel {
    /// Minimum expected inter-key interval in microseconds.
    pub iki_min_us: u32,
    /// Maximum expected inter-key interval in microseconds.
    pub iki_max_us: u32,
    /// Mean inter-key interval in microseconds (Aalto 136M baseline).
    pub iki_mean_us: u32,
    /// Standard deviation of inter-key intervals in microseconds.
    pub iki_std_us: u32,
    /// Minimum expected jitter value in microseconds.
    pub jitter_min_us: u32,
    /// Maximum expected jitter value in microseconds.
    pub jitter_max_us: u32,
    /// Minimum sequence length required for validation.
    pub min_sequence_length: usize,
    /// Maximum fraction of consecutive identical values before flagging.
    pub max_perfect_ratio: f64,
}

impl Default for HumanModel {
    fn default() -> Self {
        Self {
            iki_min_us: 30_000,
            iki_max_us: 2_000_000,
            iki_mean_us: 200_000,
            iki_std_us: 80_000,
            jitter_min_us: 500,
            jitter_max_us: 3000,
            min_sequence_length: 20,
            max_perfect_ratio: 0.05,
        }
    }
}

/// Result of validating a jitter or IKI sequence against the human model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    /// True if no anomalies detected and confidence exceeds threshold.
    pub is_human: bool,
    /// Confidence score from 0.0 (automated) to 1.0 (human).
    pub confidence: f64,
    /// Detected anomalies that reduced confidence.
    pub anomalies: Vec<Anomaly>,
    /// Descriptive statistics of the input sequence.
    pub stats: SequenceStats,
}

/// Single detected anomaly in a jitter or IKI sequence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anomaly {
    /// Classification of the anomaly.
    pub kind: AnomalyKind,
    /// Index of the first occurrence in the sequence.
    pub position: usize,
    /// Human-readable description of the anomaly.
    pub detail: String,
}

/// Classification of typing anomalies that suggest automation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnomalyKind {
    /// Too many consecutive identical timing values.
    PerfectTiming,
    /// Values outside the expected human range.
    OutOfRange,
    /// Sequence too short for meaningful analysis.
    DistributionMismatch,
    /// Detected a short repeating pattern (length 2-5).
    RepeatingPattern,
    /// Standard deviation below the minimum threshold.
    LowVariance,
}

/// Descriptive statistics for a sequence of timing values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequenceStats {
    /// Number of values in the sequence.
    pub count: usize,
    /// Arithmetic mean.
    pub mean: f64,
    /// Population standard deviation.
    pub std_dev: f64,
    /// Minimum value.
    pub min: Jitter,
    /// Maximum value.
    pub max: Jitter,
}

/// Single-pass out-of-range scan returning count and first position (no Vec allocation).
fn out_of_range_anomaly<T>(
    values: &[T],
    pred: impl Fn(&T) -> bool,
    min_label: u64,
    max_label: u64,
    name: &str,
) -> Option<Anomaly> {
    let mut count = 0usize;
    let mut first = 0usize;
    for (i, v) in values.iter().enumerate() {
        if pred(v) {
            if count == 0 {
                first = i;
            }
            count += 1;
        }
    }
    if count > 0 {
        Some(Anomaly {
            kind: AnomalyKind::OutOfRange,
            position: first,
            detail: format!(
                "{} {} values outside [{}, {}]\u{00b5}s range",
                count, name, min_label, max_label
            ),
        })
    } else {
        None
    }
}

impl HumanModel {
    /// Load the embedded Aalto 136M keystroke baseline model.
    #[cfg(feature = "std")]
    pub fn baseline() -> Self {
        const BASELINE: &str = include_str!("baseline.json");
        serde_json::from_str(BASELINE).expect("embedded baseline is valid")
    }

    /// Deserialize a model from JSON.
    #[cfg(feature = "std")]
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Serialize the model to pretty-printed JSON.
    #[cfg(feature = "std")]
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Validate a sequence of jitter values against human typing patterns.
    pub fn validate(&self, jitters: &[Jitter]) -> ValidationResult {
        let oor = out_of_range_anomaly(
            jitters,
            |&j| j < self.jitter_min_us || j > self.jitter_max_us,
            self.jitter_min_us as u64,
            self.jitter_max_us as u64,
            "jitter",
        );
        self.validate_inner(jitters, oor, MIN_STD_DEV_THRESHOLD)
    }

    /// Validate actual inter-key intervals (not jitter values).
    pub fn validate_iki(&self, intervals_us: &[u64]) -> ValidationResult {
        let oor = out_of_range_anomaly(
            intervals_us,
            |&iki| iki < self.iki_min_us as u64 || iki > self.iki_max_us as u64,
            self.iki_min_us as u64,
            self.iki_max_us as u64,
            "IKI",
        );
        let capped: Vec<u32> = intervals_us
            .iter()
            .map(|&v| v.min(u32::MAX as u64) as u32)
            .collect();
        self.validate_inner(&capped, oor, MIN_IKI_STD_DEV_THRESHOLD)
    }

    fn validate_inner(
        &self,
        values: &[Jitter],
        out_of_range: Option<Anomaly>,
        std_dev_threshold: f64,
    ) -> ValidationResult {
        if values.len() < self.min_sequence_length {
            return ValidationResult {
                is_human: false,
                confidence: 0.0,
                anomalies: vec![Anomaly {
                    kind: AnomalyKind::DistributionMismatch,
                    position: 0,
                    detail: format!(
                        "Sequence too short: {} < {}",
                        values.len(),
                        self.min_sequence_length
                    ),
                }],
                stats: self.compute_stats(values),
            };
        }

        let stats = self.compute_stats(values);
        let mut anomalies = Vec::new();

        if stats.std_dev < std_dev_threshold {
            anomalies.push(Anomaly {
                kind: AnomalyKind::LowVariance,
                position: 0,
                detail: format!("Variance too low: std_dev={:.2}", stats.std_dev),
            });
        }

        let perfect_count = values.windows(2).filter(|w| w[0] == w[1]).count();
        let perfect_ratio = perfect_count as f64 / values.len() as f64;
        if perfect_ratio > self.max_perfect_ratio {
            anomalies.push(Anomaly {
                kind: AnomalyKind::PerfectTiming,
                position: 0,
                detail: format!("Too many perfect timings: {:.1}%", perfect_ratio * 100.0),
            });
        }

        if let Some(pattern_len) = self.detect_repeating_pattern(values) {
            anomalies.push(Anomaly {
                kind: AnomalyKind::RepeatingPattern,
                position: 0,
                detail: format!("Repeating pattern of length {}", pattern_len),
            });
        }

        anomalies.extend(out_of_range);

        let base_confidence = 1.0 - (anomalies.len() as f64 * CONFIDENCE_PENALTY_PER_ANOMALY);
        let confidence = base_confidence.clamp(0.0, 1.0);

        ValidationResult {
            is_human: anomalies.is_empty() && confidence > MIN_HUMAN_CONFIDENCE,
            confidence,
            anomalies,
            stats,
        }
    }

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

        SequenceStats {
            count,
            mean,
            std_dev: sqrt(variance),
            min: *jitters.iter().min().unwrap_or(&0),
            max: *jitters.iter().max().unwrap_or(&0),
        }
    }

    fn detect_repeating_pattern(&self, jitters: &[Jitter]) -> Option<usize> {
        if jitters.len() < 6 {
            return None;
        }

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

            if checks > MIN_PATTERN_CHECKS
                && matches as f64 / checks as f64 > REPEATING_PATTERN_THRESHOLD
            {
                return Some(pattern_len);
            }
        }

        None
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn test_human_validation() {
        let model = HumanModel::default();
        let human_jitters: Vec<Jitter> = (0..50).map(|i| 500 + ((i * 37) % 2500) as u32).collect();
        let result = model.validate(&human_jitters);
        assert!(result.confidence > 0.5);
    }

    #[test]
    fn test_automation_detection() {
        let model = HumanModel::default();
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
        let fast_iki: Vec<u64> = (0..50)
            .map(|i| 10_000 + ((i * 1_000) % 15_000) as u64)
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
        assert!(!result.is_human);
    }

    #[test]
    fn test_exactly_min_sequence_length() {
        let model = HumanModel::default();
        let jitters: Vec<Jitter> = (0..model.min_sequence_length)
            .map(|i| 500 + ((i * 123) % 2500) as u32)
            .collect();
        let result = model.validate(&jitters);
        assert!(result.confidence > 0.0);
    }
}
