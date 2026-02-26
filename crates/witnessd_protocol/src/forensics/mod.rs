// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Forensic analysis engine for Proof-of-Process evidence.
//!
//! Implements the δ-Analysis and Adversarial Collapse detection algorithms
//! from arXiv:2601.17280. The core insight: human composition exhibits
//! characteristic timing entropy that synthetic or transcribed input cannot
//! replicate when bound to cryptographic causality locks.

pub mod transcription;

use serde::{Deserialize, Serialize};

/// Forensic verdict levels for PoP evidence appraisal.
///
/// V1-V2 trigger the "Verified Human" badge.
/// V3-V5 flag the document for review or re-attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ForensicVerdict {
    /// V1: High entropy, valid causality chain, non-linear composition confirmed.
    V1VerifiedHuman,
    /// V2: Valid timing with minor causality drift (e.g., clock skew).
    V2LikelyHuman,
    /// V3: Low entropy or high linearity — potential transcription.
    V3Suspicious,
    /// V4: Perfect timing uniformity — suggests histogram attack or bot.
    V4LikelySynthetic,
    /// V5: HMAC causality lock broken — confirmed evidence tampering.
    V5ConfirmedForgery,
}

impl ForensicVerdict {
    /// Returns the string label for this verdict.
    pub fn as_str(&self) -> &'static str {
        match self {
            ForensicVerdict::V1VerifiedHuman => "V1_VerifiedHuman",
            ForensicVerdict::V2LikelyHuman => "V2_LikelyHuman",
            ForensicVerdict::V3Suspicious => "V3_Suspicious",
            ForensicVerdict::V4LikelySynthetic => "V4_LikelySynthetic",
            ForensicVerdict::V5ConfirmedForgery => "V5_ConfirmedForgery",
        }
    }

    /// Whether this verdict should grant the "Verified Human" badge.
    pub fn is_verified(&self) -> bool {
        matches!(self, ForensicVerdict::V1VerifiedHuman | ForensicVerdict::V2LikelyHuman)
    }
}

/// Detailed forensic analysis result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicAnalysis {
    pub verdict: ForensicVerdict,
    /// Coefficient of Variation of inter-checkpoint intervals.
    /// Human composition: typically 0.25–0.70.
    /// Transcription: typically < 0.15.
    /// Bot noise injection: typically > 0.80.
    pub coefficient_of_variation: f64,
    /// Linearity score: ratio of net progress to total keystrokes.
    /// Composition: 0.60–0.80 (revisions lower the ratio).
    /// Transcription: > 0.92 (almost no backtracking).
    pub linearity_score: Option<f64>,
    /// Hurst exponent of timing intervals (if enough data).
    /// Human: 0.55–0.85 (persistent, pink-noise-like).
    /// Synthetic: ~0.50 (white noise) or >0.85 (scripted).
    pub hurst_exponent: Option<f64>,
    /// Number of checkpoints analyzed.
    pub checkpoint_count: usize,
    /// Total chain duration in seconds.
    pub chain_duration_secs: u64,
    /// Human-readable explanation of the verdict.
    pub explanation: String,
}

/// Core forensics engine for PoP evidence analysis.
pub struct ForensicsEngine {
    /// Inter-checkpoint timing intervals (seconds).
    pub inter_checkpoint_intervals: Vec<f64>,
    /// Whether the HMAC causality chain validated successfully.
    pub causality_chain_valid: bool,
    /// Optional transcription detection data.
    pub transcription_data: Option<transcription::TranscriptionData>,
}

impl ForensicsEngine {
    /// Creates a new engine from checkpoint timestamps.
    pub fn from_timestamps(timestamps: &[u64], causality_valid: bool) -> Self {
        let intervals: Vec<f64> = timestamps
            .windows(2)
            .map(|w| (w[1] as f64) - (w[0] as f64))
            .collect();

        Self {
            inter_checkpoint_intervals: intervals,
            causality_chain_valid: causality_valid,
            transcription_data: None,
        }
    }

    /// Attach transcription detection data for deeper analysis.
    pub fn with_transcription_data(mut self, data: transcription::TranscriptionData) -> Self {
        self.transcription_data = Some(data);
        self
    }

    /// Run the full forensic analysis pipeline.
    pub fn analyze(&self) -> ForensicAnalysis {
        let checkpoint_count = self.inter_checkpoint_intervals.len() + 1;

        let chain_duration_secs = self
            .inter_checkpoint_intervals
            .iter()
            .sum::<f64>() as u64;

        // Gate 1: Causality chain integrity
        if !self.causality_chain_valid {
            return ForensicAnalysis {
                verdict: ForensicVerdict::V5ConfirmedForgery,
                coefficient_of_variation: 0.0,
                linearity_score: None,
                hurst_exponent: None,
                checkpoint_count,
                chain_duration_secs,
                explanation: "HMAC causality lock broken — evidence has been tampered with"
                    .to_string(),
            };
        }

        // Gate 2: Insufficient data
        if self.inter_checkpoint_intervals.len() < 3 {
            return ForensicAnalysis {
                verdict: ForensicVerdict::V2LikelyHuman,
                coefficient_of_variation: 0.0,
                linearity_score: None,
                hurst_exponent: None,
                checkpoint_count,
                chain_duration_secs,
                explanation: "Insufficient checkpoints for full forensic analysis".to_string(),
            };
        }

        // Gate 3: δ-Analysis (Coefficient of Variation)
        let delta = self.calculate_coefficient_of_variation();

        // Gate 4: Adversarial Collapse — identical intervals
        if self.detect_adversarial_collapse() {
            return ForensicAnalysis {
                verdict: ForensicVerdict::V4LikelySynthetic,
                coefficient_of_variation: delta,
                linearity_score: None,
                hurst_exponent: None,
                checkpoint_count,
                chain_duration_secs,
                explanation: "Adversarial collapse: timing intervals are uniform (non-human)"
                    .to_string(),
            };
        }

        // Gate 5: CoV threshold analysis
        if delta < 0.15 {
            return ForensicAnalysis {
                verdict: ForensicVerdict::V4LikelySynthetic,
                coefficient_of_variation: delta,
                linearity_score: None,
                hurst_exponent: None,
                checkpoint_count,
                chain_duration_secs,
                explanation: format!(
                    "Timing entropy too low (δ={:.3}): consistent with automated generation",
                    delta
                ),
            };
        }

        if delta > 0.80 {
            return ForensicAnalysis {
                verdict: ForensicVerdict::V3Suspicious,
                coefficient_of_variation: delta,
                linearity_score: None,
                hurst_exponent: None,
                checkpoint_count,
                chain_duration_secs,
                explanation: format!(
                    "Timing entropy too high (δ={:.3}): potential bot noise injection",
                    delta
                ),
            };
        }

        // Gate 6: Hurst exponent (if enough data points)
        let hurst = if self.inter_checkpoint_intervals.len() >= 10 {
            Some(self.estimate_hurst_exponent())
        } else {
            None
        };

        if let Some(h) = hurst {
            if h < 0.45 {
                return ForensicAnalysis {
                    verdict: ForensicVerdict::V3Suspicious,
                    coefficient_of_variation: delta,
                    linearity_score: None,
                    hurst_exponent: Some(h),
                    checkpoint_count,
                    chain_duration_secs,
                    explanation: format!(
                        "White-noise timing (H={:.3}): inconsistent with human composition",
                        h
                    ),
                };
            }
            if h > 0.90 {
                return ForensicAnalysis {
                    verdict: ForensicVerdict::V3Suspicious,
                    coefficient_of_variation: delta,
                    linearity_score: None,
                    hurst_exponent: Some(h),
                    checkpoint_count,
                    chain_duration_secs,
                    explanation: format!(
                        "Highly predictable timing (H={:.3}): consistent with scripted input",
                        h
                    ),
                };
            }
        }

        // Gate 7: Transcription detection (if data available)
        let linearity_score = self.transcription_data.as_ref().map(|td| {
            let detector = transcription::TranscriptionDetector::from_data(td);
            detector.calculate_linearity_score()
        });

        if let Some(linearity) = linearity_score {
            if linearity > 0.92 {
                let avg_burst = self
                    .transcription_data
                    .as_ref()
                    .map(|td| td.avg_burst_length)
                    .unwrap_or(0.0);

                if avg_burst > 15.0 {
                    return ForensicAnalysis {
                        verdict: ForensicVerdict::V3Suspicious,
                        coefficient_of_variation: delta,
                        linearity_score: Some(linearity),
                        hurst_exponent: hurst,
                        checkpoint_count,
                        chain_duration_secs,
                        explanation: format!(
                            "High linearity ({:.3}) with long bursts ({:.1}): consistent with transcription",
                            linearity, avg_burst
                        ),
                    };
                }
            }
        }

        // Gate 8: Minor anomalies → V2
        let has_minor_anomalies = hurst.is_some_and(|h| h < 0.55 || h > 0.85)
            || linearity_score.is_some_and(|l| l > 0.85);

        if has_minor_anomalies {
            return ForensicAnalysis {
                verdict: ForensicVerdict::V2LikelyHuman,
                coefficient_of_variation: delta,
                linearity_score,
                hurst_exponent: hurst,
                checkpoint_count,
                chain_duration_secs,
                explanation: "Timing consistent with human composition, minor anomalies noted"
                    .to_string(),
            };
        }

        // All gates passed → V1
        ForensicAnalysis {
            verdict: ForensicVerdict::V1VerifiedHuman,
            coefficient_of_variation: delta,
            linearity_score,
            hurst_exponent: hurst,
            checkpoint_count,
            chain_duration_secs,
            explanation: "High entropy, valid causality, non-linear composition confirmed"
                .to_string(),
        }
    }

    /// Coefficient of Variation: std_dev / mean.
    /// Human δ is typically 2-4x higher than automated thresholds.
    fn calculate_coefficient_of_variation(&self) -> f64 {
        if self.inter_checkpoint_intervals.is_empty() {
            return 0.0;
        }
        let n = self.inter_checkpoint_intervals.len() as f64;
        let mean = self.inter_checkpoint_intervals.iter().sum::<f64>() / n;
        if mean == 0.0 {
            return 0.0;
        }
        let variance = self
            .inter_checkpoint_intervals
            .iter()
            .map(|&x| (x - mean).powi(2))
            .sum::<f64>()
            / n;
        variance.sqrt() / mean
    }

    /// Detects adversarial collapse: all intervals identical within tolerance.
    /// A bot replaying evidence will produce perfectly uniform timing.
    fn detect_adversarial_collapse(&self) -> bool {
        if self.inter_checkpoint_intervals.len() < 3 {
            return false;
        }

        let first = self.inter_checkpoint_intervals[0];
        // Allow 1% tolerance for floating-point comparison
        let tolerance = (first * 0.01).max(0.001);

        self.inter_checkpoint_intervals
            .iter()
            .all(|&x| (x - first).abs() < tolerance)
    }

    /// Rescaled Range (R/S) estimation of the Hurst exponent.
    /// H ≈ 0.5 → white noise (suspicious)
    /// H ∈ [0.55, 0.85] → persistent/pink noise (human)
    /// H > 0.85 → highly predictable (scripted)
    fn estimate_hurst_exponent(&self) -> f64 {
        let data = &self.inter_checkpoint_intervals;
        let n = data.len();

        if n < 10 {
            return 0.5; // Not enough data — assume neutral
        }

        // Use multiple block sizes for R/S analysis
        let mut log_n_values = Vec::new();
        let mut log_rs_values = Vec::new();

        let mut block_size = 4;
        while block_size <= n / 2 {
            let num_blocks = n / block_size;
            let mut rs_sum = 0.0;

            for b in 0..num_blocks {
                let block = &data[b * block_size..(b + 1) * block_size];
                let mean = block.iter().sum::<f64>() / block_size as f64;

                // Cumulative deviations
                let mut cumdev = Vec::with_capacity(block_size);
                let mut running = 0.0;
                for &val in block {
                    running += val - mean;
                    cumdev.push(running);
                }

                let range = cumdev.iter().cloned().fold(f64::NEG_INFINITY, f64::max)
                    - cumdev.iter().cloned().fold(f64::INFINITY, f64::min);

                let std_dev = (block.iter().map(|&x| (x - mean).powi(2)).sum::<f64>()
                    / block_size as f64)
                    .sqrt();

                if std_dev > 0.0 {
                    rs_sum += range / std_dev;
                }
            }

            if num_blocks > 0 {
                let avg_rs = rs_sum / num_blocks as f64;
                if avg_rs > 0.0 {
                    log_n_values.push((block_size as f64).ln());
                    log_rs_values.push(avg_rs.ln());
                }
            }

            block_size *= 2;
        }

        // Linear regression: log(R/S) = H * log(n) + c
        if log_n_values.len() < 2 {
            return 0.5;
        }

        let n_pts = log_n_values.len() as f64;
        let sum_x: f64 = log_n_values.iter().sum();
        let sum_y: f64 = log_rs_values.iter().sum();
        let sum_xy: f64 = log_n_values
            .iter()
            .zip(log_rs_values.iter())
            .map(|(x, y)| x * y)
            .sum();
        let sum_xx: f64 = log_n_values.iter().map(|x| x * x).sum();

        let denominator = n_pts * sum_xx - sum_x * sum_x;
        if denominator.abs() < f64::EPSILON {
            return 0.5;
        }

        let slope = (n_pts * sum_xy - sum_x * sum_y) / denominator;

        // Clamp to [0, 1] range
        slope.clamp(0.0, 1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_human_composition_passes() {
        // Irregular intervals typical of human writing
        let engine = ForensicsEngine {
            inter_checkpoint_intervals: vec![
                12.5, 8.3, 45.2, 3.1, 22.7, 15.8, 67.0, 5.4, 18.9, 30.2,
            ],
            causality_chain_valid: true,
            transcription_data: None,
        };
        let result = engine.analyze();
        assert!(result.verdict.is_verified());
    }

    #[test]
    fn test_bot_uniform_timing_fails() {
        // Perfectly uniform intervals — adversarial collapse
        let engine = ForensicsEngine {
            inter_checkpoint_intervals: vec![10.0, 10.0, 10.0, 10.0, 10.0],
            causality_chain_valid: true,
            transcription_data: None,
        };
        let result = engine.analyze();
        assert_eq!(result.verdict, ForensicVerdict::V4LikelySynthetic);
    }

    #[test]
    fn test_broken_causality_chain() {
        let engine = ForensicsEngine {
            inter_checkpoint_intervals: vec![12.5, 8.3, 45.2],
            causality_chain_valid: false,
            transcription_data: None,
        };
        let result = engine.analyze();
        assert_eq!(result.verdict, ForensicVerdict::V5ConfirmedForgery);
    }

    #[test]
    fn test_low_entropy_synthetic() {
        // Very low variation — bot with slight jitter
        let engine = ForensicsEngine {
            inter_checkpoint_intervals: vec![10.0, 10.1, 10.0, 9.9, 10.1, 10.0],
            causality_chain_valid: true,
            transcription_data: None,
        };
        let result = engine.analyze();
        assert_eq!(result.verdict, ForensicVerdict::V4LikelySynthetic);
    }
}
