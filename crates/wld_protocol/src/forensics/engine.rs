// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::forensics::transcription;
use serde::{Deserialize, Serialize};

/// Five-level forensic verdict from timing and causality analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ForensicVerdict {
    /// High entropy, valid causality, non-linear composition.
    V1VerifiedHuman,
    /// Valid timing with minor causality drift (e.g., clock skew).
    V2LikelyHuman,
    /// Low entropy or high linearity — potential transcription.
    V3Suspicious,
    /// Perfect timing uniformity — histogram attack or bot.
    V4LikelySynthetic,
    /// HMAC causality lock broken — confirmed tampering.
    V5ConfirmedForgery,
}

impl ForensicVerdict {
    /// Return the verdict as a stable string identifier (e.g., "V1_VerifiedHuman").
    pub fn as_str(&self) -> &'static str {
        match self {
            ForensicVerdict::V1VerifiedHuman => "V1_VerifiedHuman",
            ForensicVerdict::V2LikelyHuman => "V2_LikelyHuman",
            ForensicVerdict::V3Suspicious => "V3_Suspicious",
            ForensicVerdict::V4LikelySynthetic => "V4_LikelySynthetic",
            ForensicVerdict::V5ConfirmedForgery => "V5_ConfirmedForgery",
        }
    }

    /// Return true if the verdict indicates verified human authorship (V1 or V2).
    pub fn is_verified(&self) -> bool {
        matches!(
            self,
            ForensicVerdict::V1VerifiedHuman | ForensicVerdict::V2LikelyHuman
        )
    }
}

/// Complete forensic analysis result with verdict, metrics, and explanation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicAnalysis {
    pub verdict: ForensicVerdict,
    pub coefficient_of_variation: f64,
    pub linearity_score: Option<f64>,
    pub hurst_exponent: Option<f64>,
    pub checkpoint_count: usize,
    pub chain_duration_secs: u64,
    pub explanation: String,
}

impl ForensicAnalysis {
    fn new(
        verdict: ForensicVerdict,
        cv: f64,
        checkpoint_count: usize,
        chain_duration_secs: u64,
        explanation: impl Into<String>,
    ) -> Self {
        Self {
            verdict,
            coefficient_of_variation: cv,
            linearity_score: None,
            hurst_exponent: None,
            checkpoint_count,
            chain_duration_secs,
            explanation: explanation.into(),
        }
    }

    fn with_hurst(mut self, h: Option<f64>) -> Self {
        self.hurst_exponent = h;
        self
    }

    fn with_linearity(mut self, l: Option<f64>) -> Self {
        self.linearity_score = l;
        self
    }
}

/// Analyze checkpoint timing intervals for human-vs-synthetic authorship signals.
pub struct ForensicsEngine {
    pub inter_checkpoint_intervals: Vec<f64>,
    pub causality_chain_valid: bool,
    pub transcription_data: Option<transcription::TranscriptionData>,
}

impl ForensicsEngine {
    /// Build an engine from ordered timestamps and a pre-validated causality flag.
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

    /// Attach transcription detection data for linearity analysis.
    pub fn with_transcription_data(mut self, data: transcription::TranscriptionData) -> Self {
        self.transcription_data = Some(data);
        self
    }

    /// Run full forensic analysis and return a verdict with metrics.
    pub fn analyze(&self) -> ForensicAnalysis {
        let n = self.inter_checkpoint_intervals.len() + 1;
        let dur = self.inter_checkpoint_intervals.iter().sum::<f64>().max(0.0) as u64;
        let fa = |v, cv, msg: String| ForensicAnalysis::new(v, cv, n, dur, msg);

        if !self.causality_chain_valid {
            return fa(
                ForensicVerdict::V5ConfirmedForgery,
                0.0,
                "HMAC causality lock broken — evidence has been tampered with".into(),
            );
        }

        if self.inter_checkpoint_intervals.len() < 3 {
            return fa(
                ForensicVerdict::V2LikelyHuman,
                0.0,
                "Insufficient checkpoints for full forensic analysis".into(),
            );
        }

        let delta = self.calculate_coefficient_of_variation();

        if self.detect_adversarial_collapse() {
            return fa(
                ForensicVerdict::V4LikelySynthetic,
                delta,
                "Adversarial collapse: timing intervals are uniform (non-human)".into(),
            );
        }

        if delta < 0.15 {
            return fa(
                ForensicVerdict::V4LikelySynthetic,
                delta,
                format!(
                    "Timing entropy too low (δ={:.3}): consistent with automated generation",
                    delta
                ),
            );
        }

        if delta > 0.80 {
            return fa(
                ForensicVerdict::V3Suspicious,
                delta,
                format!(
                    "Timing entropy too high (δ={:.3}): potential bot noise injection",
                    delta
                ),
            );
        }

        let hurst = if self.inter_checkpoint_intervals.len() >= 10 {
            Some(self.estimate_hurst_exponent())
        } else {
            None
        };

        if let Some(h) = hurst {
            if h < 0.45 {
                return fa(
                    ForensicVerdict::V3Suspicious,
                    delta,
                    format!(
                        "White-noise timing (H={:.3}): inconsistent with human composition",
                        h
                    ),
                )
                .with_hurst(Some(h));
            }
            if h > 0.90 {
                return fa(
                    ForensicVerdict::V3Suspicious,
                    delta,
                    format!(
                        "Highly predictable timing (H={:.3}): consistent with scripted input",
                        h
                    ),
                )
                .with_hurst(Some(h));
            }
        }

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
                    return fa(
                        ForensicVerdict::V3Suspicious,
                        delta,
                        format!(
                            "High linearity ({:.3}) with long bursts ({:.1}): consistent with transcription",
                            linearity, avg_burst
                        ),
                    )
                    .with_hurst(hurst)
                    .with_linearity(Some(linearity));
                }
            }
        }

        let has_minor_anomalies = hurst.is_some_and(|h| !(0.55..=0.85).contains(&h))
            || linearity_score.is_some_and(|l| l > 0.85);

        if has_minor_anomalies {
            return fa(
                ForensicVerdict::V2LikelyHuman,
                delta,
                "Timing consistent with human composition, minor anomalies noted".into(),
            )
            .with_hurst(hurst)
            .with_linearity(linearity_score);
        }

        fa(
            ForensicVerdict::V1VerifiedHuman,
            delta,
            "High entropy, valid causality, non-linear composition confirmed".into(),
        )
        .with_hurst(hurst)
        .with_linearity(linearity_score)
    }

    fn calculate_coefficient_of_variation(&self) -> f64 {
        if self.inter_checkpoint_intervals.is_empty() {
            return 0.0;
        }
        let n = self.inter_checkpoint_intervals.len() as f64;
        let mean = self.inter_checkpoint_intervals.iter().sum::<f64>() / n;
        if mean == 0.0 || !mean.is_finite() {
            return 0.0;
        }
        let variance = self
            .inter_checkpoint_intervals
            .iter()
            .map(|&x| (x - mean).powi(2))
            .sum::<f64>()
            / n;
        let cv = variance.sqrt() / mean;
        // NaN/Inf from pathological inputs must not bypass downstream threshold checks
        if cv.is_finite() {
            cv
        } else {
            0.0
        }
    }

    fn detect_adversarial_collapse(&self) -> bool {
        if self.inter_checkpoint_intervals.len() < 3 {
            return false;
        }

        let first = self.inter_checkpoint_intervals[0];
        let tolerance = (first * 0.01).max(0.001);

        self.inter_checkpoint_intervals
            .iter()
            .all(|&x| (x - first).abs() < tolerance)
    }

    /// Rescaled range (R/S) method for Hurst exponent estimation.
    fn estimate_hurst_exponent(&self) -> f64 {
        let data = &self.inter_checkpoint_intervals;
        let n = data.len();

        if n < 10 {
            return 0.5;
        }

        let mut log_n_values = Vec::new();
        let mut log_rs_values = Vec::new();

        let mut block_size = 4;
        while block_size <= n / 2 {
            let num_blocks = n / block_size;
            let mut rs_sum = 0.0;

            for b in 0..num_blocks {
                let block = &data[b * block_size..(b + 1) * block_size];
                let mean = block.iter().sum::<f64>() / block_size as f64;

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
        if slope.is_finite() {
            slope.clamp(0.0, 1.0)
        } else {
            0.5
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_human_composition_passes() {
        let engine = ForensicsEngine {
            inter_checkpoint_intervals: vec![
                12.5, 8.3, 15.2, 6.1, 22.7, 15.8, 20.0, 9.4, 18.9, 14.2, 11.3, 25.1, 7.8, 19.6,
                13.4, 16.7, 10.2, 21.5, 8.9, 17.3,
            ],
            causality_chain_valid: true,
            transcription_data: None,
        };
        let result = engine.analyze();
        assert!(result.verdict.is_verified());
    }

    #[test]
    fn test_bot_uniform_timing_fails() {
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
        let engine = ForensicsEngine {
            inter_checkpoint_intervals: vec![10.0, 10.1, 10.0, 9.9, 10.1, 10.0],
            causality_chain_valid: true,
            transcription_data: None,
        };
        let result = engine.analyze();
        assert_eq!(result.verdict, ForensicVerdict::V4LikelySynthetic);
    }
}
