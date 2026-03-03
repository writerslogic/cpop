// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Generate unforgeable behavioral fingerprints from typing patterns

use crate::analysis::stats;
use crate::jitter::SimpleJitterSample;
use serde::{Deserialize, Serialize};

/// Features extracted from typing that are hard to fake
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralFingerprint {
    // Timing distributions (milliseconds)
    pub keystroke_interval_mean: f64,
    pub keystroke_interval_std: f64,
    pub keystroke_interval_skewness: f64,
    pub keystroke_interval_kurtosis: f64,

    // Note: We don't have key values in SimpleJitterSample, so we can't do digraphs yet.
    // We will use interval buckets instead.
    pub interval_buckets: Vec<f64>, // Histogram of intervals

    pub sentence_pause_mean: f64,
    pub paragraph_pause_mean: f64,
    pub thinking_pause_frequency: f64, // Pauses > 2 seconds

    pub burst_length_mean: f64,    // Characters between pauses
    pub burst_speed_variance: f64, // Speed changes within bursts
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForgeryAnalysis {
    pub is_suspicious: bool,
    pub confidence: f64,
    pub flags: Vec<ForgeryFlag>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ForgeryFlag {
    TooRegular { cv: f64 },
    WrongSkewness { skewness: f64 },
    MissingMicroPauses,
    SuperhumanSpeed { count: usize },
    NoFatiguePattern,
}

impl BehavioralFingerprint {
    /// Compute fingerprint from jitter samples
    pub fn from_samples(samples: &[SimpleJitterSample]) -> Self {
        if samples.len() < 2 {
            return Self::default();
        }

        // SimpleJitterSample has timestamp_ns
        let intervals: Vec<f64> = samples
            .windows(2)
            .map(|w| (w[1].timestamp_ns - w[0].timestamp_ns) as f64 / 1_000_000.0)
            .filter(|&i| i > 0.0 && i < 5000.0) // Filter outlier pauses > 5s
            .collect();

        if intervals.is_empty() {
            return Self::default();
        }

        let (mean, std) = stats::mean_and_std_dev(&intervals);

        let skewness = stats::skewness(&intervals, mean, std);
        let kurtosis = stats::kurtosis(&intervals, mean, std);

        let long_pauses = samples
            .windows(2)
            .map(|w| (w[1].timestamp_ns - w[0].timestamp_ns) as f64 / 1_000_000.0)
            .filter(|&i| i > 2000.0)
            .count();

        let thinking_freq = if !samples.is_empty() {
            long_pauses as f64 / samples.len() as f64
        } else {
            0.0
        };

        // Bursts: sequences separated by > 500ms
        let mut bursts = Vec::new();
        let mut current_burst_len = 0;
        for w in samples.windows(2) {
            let interval = (w[1].timestamp_ns - w[0].timestamp_ns) as f64 / 1_000_000.0;
            if interval > 500.0 {
                if current_burst_len > 0 {
                    bursts.push(current_burst_len as f64);
                }
                current_burst_len = 0;
            } else {
                current_burst_len += 1;
            }
        }

        let burst_mean = if !bursts.is_empty() {
            bursts.iter().sum::<f64>() / bursts.len() as f64
        } else {
            0.0
        };

        // Build interval histogram with bucket edges [0, 50, 100, 150, 200, 300, 500, 1000, 2000, ∞] ms
        let bucket_edges: &[f64] = &[0.0, 50.0, 100.0, 150.0, 200.0, 300.0, 500.0, 1000.0, 2000.0];
        let mut interval_buckets = vec![0.0f64; bucket_edges.len()];
        for &iv in &intervals {
            let mut placed = false;
            for i in (0..bucket_edges.len()).rev() {
                if iv >= bucket_edges[i] {
                    interval_buckets[i] += 1.0;
                    placed = true;
                    break;
                }
            }
            if !placed {
                interval_buckets[0] += 1.0;
            }
        }
        let total = intervals.len() as f64;
        if total > 0.0 {
            for b in &mut interval_buckets {
                *b /= total;
            }
        }

        let sentence_pauses: Vec<f64> = intervals.iter().copied().filter(|&i| i > 500.0).collect();
        let sentence_pause_mean = if !sentence_pauses.is_empty() {
            sentence_pauses.iter().sum::<f64>() / sentence_pauses.len() as f64
        } else {
            0.0
        };

        let paragraph_pauses: Vec<f64> =
            intervals.iter().copied().filter(|&i| i > 2000.0).collect();
        let paragraph_pause_mean = if !paragraph_pauses.is_empty() {
            paragraph_pauses.iter().sum::<f64>() / paragraph_pauses.len() as f64
        } else {
            0.0
        };

        // < 200ms = fast typing bursts
        let burst_intervals: Vec<f64> = intervals.iter().copied().filter(|&i| i < 200.0).collect();
        let burst_speed_variance = if burst_intervals.len() >= 2 {
            let burst_mean_val = burst_intervals.iter().sum::<f64>() / burst_intervals.len() as f64;
            burst_intervals
                .iter()
                .map(|&x| (x - burst_mean_val).powi(2))
                .sum::<f64>()
                / (burst_intervals.len() - 1) as f64
        } else {
            0.0
        };

        Self {
            keystroke_interval_mean: mean,
            keystroke_interval_std: std,
            keystroke_interval_skewness: skewness,
            keystroke_interval_kurtosis: kurtosis,
            interval_buckets,
            sentence_pause_mean,
            paragraph_pause_mean,
            thinking_pause_frequency: thinking_freq,
            burst_length_mean: burst_mean,
            burst_speed_variance,
        }
    }

    /// Detect if samples were likely generated artificially
    pub fn detect_forgery(samples: &[SimpleJitterSample]) -> ForgeryAnalysis {
        if samples.len() < 10 {
            return ForgeryAnalysis {
                is_suspicious: false,
                confidence: 0.0,
                flags: vec![],
            };
        }

        let intervals: Vec<f64> = samples
            .windows(2)
            .map(|w| (w[1].timestamp_ns - w[0].timestamp_ns) as f64 / 1_000_000.0)
            .filter(|&i| i > 0.0 && i < 5000.0)
            .collect();

        let mut flags = Vec::new();

        let (mean, std) = stats::mean_and_std_dev(&intervals);

        // Too regular (humans have high variance)
        if mean > 0.0 {
            let cv = std / mean; // Coefficient of variation
                                 // Threshold 0.2 is conservative for forgery detection. Human typing
                                 // typically > 0.3-0.4. The gap reduces false positives for slow/regular typists.
            if cv < 0.2 {
                flags.push(ForgeryFlag::TooRegular { cv });
            }
        }

        let skewness = stats::skewness(&intervals, mean, std);
        if skewness < 0.2 {
            // Human typing is usually positively skewed (long tail)
            flags.push(ForgeryFlag::WrongSkewness { skewness });
        }

        let micro_pauses = intervals
            .iter()
            .filter(|&&i| i > 150.0 && i < 500.0)
            .count();
        if (micro_pauses as f64 / intervals.len() as f64) < 0.05 {
            flags.push(ForgeryFlag::MissingMicroPauses);
        }

        // Impossible speeds: < 20ms implies script injection or mechanical rollover without debounce
        let impossibly_fast = intervals.iter().filter(|&&i| i < 20.0).count();
        if impossibly_fast > (intervals.len() / 10) {
            // >10% is suspicious
            flags.push(ForgeryFlag::SuperhumanSpeed {
                count: impossibly_fast,
            });
        }

        ForgeryAnalysis {
            is_suspicious: !flags.is_empty(),
            confidence: (flags.len() as f64 * 0.3).min(1.0),
            flags,
        }
    }
}

impl Default for BehavioralFingerprint {
    fn default() -> Self {
        Self {
            keystroke_interval_mean: 0.0,
            keystroke_interval_std: 0.0,
            keystroke_interval_skewness: 0.0,
            keystroke_interval_kurtosis: 0.0,
            interval_buckets: vec![],
            sentence_pause_mean: 0.0,
            paragraph_pause_mean: 0.0,
            thinking_pause_frequency: 0.0,
            burst_length_mean: 0.0,
            burst_speed_variance: 0.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_samples(intervals_ms: &[u64]) -> Vec<SimpleJitterSample> {
        let mut samples = Vec::new();
        let mut current_ns = 1_000_000_000u64;

        // First sample
        samples.push(SimpleJitterSample {
            timestamp_ns: current_ns as i64,
            duration_since_last_ns: 0,
            zone: 1,
        });

        for &interval in intervals_ms {
            let duration_ns = interval * 1_000_000;
            current_ns += duration_ns;
            samples.push(SimpleJitterSample {
                timestamp_ns: current_ns as i64,
                duration_since_last_ns: duration_ns,
                zone: 1,
            });
        }
        samples
    }

    #[test]
    fn test_fingerprint_from_insufficient_samples() {
        let samples = mock_samples(&[]);
        let fp = BehavioralFingerprint::from_samples(&samples);
        assert_eq!(fp.keystroke_interval_mean, 0.0);
    }

    #[test]
    fn test_fingerprint_human_like() {
        // Typical human intervals: 150-300ms with some variation
        let intervals = vec![200, 250, 180, 220, 400, 210, 190, 230, 220, 200];
        let samples = mock_samples(&intervals);
        let fp = BehavioralFingerprint::from_samples(&samples);

        assert!(fp.keystroke_interval_mean > 200.0 && fp.keystroke_interval_mean < 300.0);
        assert!(fp.keystroke_interval_std > 0.0);
        assert!(fp.keystroke_interval_skewness > 0.0); // Should be positively skewed by the 400ms interval
    }

    #[test]
    fn test_fingerprint_interval_buckets() {
        let intervals = vec![30, 80, 120, 180, 250, 400, 700, 1500, 3000, 150];
        let samples = mock_samples(&intervals);
        let fp = BehavioralFingerprint::from_samples(&samples);

        assert_eq!(fp.interval_buckets.len(), 9);
        // All buckets should sum to ~1.0
        let sum: f64 = fp.interval_buckets.iter().sum();
        assert!((sum - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_fingerprint_pause_means() {
        // Include some long pauses
        let intervals = vec![100, 150, 120, 800, 100, 130, 2500, 100, 3000, 150];
        let samples = mock_samples(&intervals);
        let fp = BehavioralFingerprint::from_samples(&samples);

        // sentence pauses > 500ms: 800, 2500, 3000 → mean ~2100
        assert!(fp.sentence_pause_mean > 500.0);
        // paragraph pauses > 2000ms: 2500, 3000 → mean 2750
        assert!(fp.paragraph_pause_mean > 2000.0);
    }

    #[test]
    fn test_fingerprint_burst_speed_variance() {
        // Burst intervals < 200ms with variance
        let intervals = vec![80, 120, 150, 90, 110, 130, 170, 500, 100, 140];
        let samples = mock_samples(&intervals);
        let fp = BehavioralFingerprint::from_samples(&samples);

        // Should have non-zero variance from the sub-200ms intervals
        assert!(fp.burst_speed_variance > 0.0);
    }

    #[test]
    fn test_detect_forgery_robotic() {
        // Exactly 200ms every time - very suspicious
        let intervals = vec![200; 20];
        let samples = mock_samples(&intervals);
        let analysis = BehavioralFingerprint::detect_forgery(&samples);

        assert!(analysis.is_suspicious);
        assert!(analysis
            .flags
            .iter()
            .any(|f| matches!(f, ForgeryFlag::TooRegular { .. })));
    }

    #[test]
    fn test_detect_forgery_human_plausible() {
        // Varied intervals, positive skew, micro-pauses
        let intervals = vec![
            180, 220, 190, 450, 210, 170, 230, 200, 190, 210, 500, 180, 220, 200, 190,
        ];
        let samples = mock_samples(&intervals);
        let analysis = BehavioralFingerprint::detect_forgery(&samples);

        assert!(!analysis.is_suspicious);
    }

    #[test]
    fn test_detect_forgery_superhuman() {
        // Very fast intervals < 20ms
        let mut intervals = vec![200; 15];
        intervals.extend(vec![10, 5, 10, 5, 10]); // Robotic/Superhuman burst
        let samples = mock_samples(&intervals);
        let analysis = BehavioralFingerprint::detect_forgery(&samples);

        assert!(analysis.is_suspicious);
        assert!(analysis
            .flags
            .iter()
            .any(|f| matches!(f, ForgeryFlag::SuperhumanSpeed { .. })));
    }
}
