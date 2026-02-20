//! Generate unforgeable behavioral fingerprints from typing patterns

use crate::jitter::SimpleJitterSample;
use serde::{Deserialize, Serialize};
use statrs::statistics::Statistics;

/// Features extracted from typing that are hard to fake
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralFingerprint {
    // Timing distributions (milliseconds)
    pub keystroke_interval_mean: f64,
    pub keystroke_interval_std: f64,
    pub keystroke_interval_skewness: f64,
    pub keystroke_interval_kurtosis: f64,

    // Digraph timings (specific key pairs)
    // Note: We don't have key values in SimpleJitterSample, so we can't do digraphs yet.
    // We will use interval buckets instead.
    pub interval_buckets: Vec<f64>, // Histogram of intervals

    // Pause patterns
    pub sentence_pause_mean: f64,
    pub paragraph_pause_mean: f64,
    pub thinking_pause_frequency: f64, // Pauses > 2 seconds

    // Session patterns
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

        // Calculate inter-key intervals (IKI) in milliseconds
        // SimpleJitterSample has timestamp_ns
        let intervals: Vec<f64> = samples
            .windows(2)
            .map(|w| (w[1].timestamp_ns - w[0].timestamp_ns) as f64 / 1_000_000.0)
            .filter(|&i| i > 0.0 && i < 5000.0) // Filter outlier pauses > 5s
            .collect();

        if intervals.is_empty() {
            return Self::default();
        }

        let mean = intervals.clone().mean();
        let std = intervals.clone().std_dev();

        // Skewness and Kurtosis require more complex calc, using simplified estimations or statrs if available
        // statrs::statistics::Distribution doesn't implement skewness directly on Vec<f64> usually,
        // but let's assume we implement a helper or use basic stats.
        let skewness = calculate_skewness(&intervals, mean, std);
        let kurtosis = calculate_kurtosis(&intervals, mean, std);

        // Analyze pauses (> 2000ms)
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

        // Burst analysis (sequences separated by > 500ms)
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
            bursts.clone().mean()
        } else {
            0.0
        };

        Self {
            keystroke_interval_mean: mean,
            keystroke_interval_std: std,
            keystroke_interval_skewness: skewness,
            keystroke_interval_kurtosis: kurtosis,
            interval_buckets: vec![],  // Placeholder
            sentence_pause_mean: 0.0,  // Needs key codes
            paragraph_pause_mean: 0.0, // Needs key codes
            thinking_pause_frequency: thinking_freq,
            burst_length_mean: burst_mean,
            burst_speed_variance: 0.0,
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
            .collect();

        let mut flags = Vec::new();

        // Basic stats
        let mean = intervals.clone().mean();
        let std = intervals.clone().std_dev();

        // Check 1: Too regular (humans have high variance)
        if mean > 0.0 {
            let cv = std / mean; // Coefficient of variation
            if cv < 0.2 {
                // Human typing usually > 0.3-0.4
                flags.push(ForgeryFlag::TooRegular { cv });
            }
        }

        // Check 2: Unnatural distribution shape
        let skewness = calculate_skewness(&intervals, mean, std);
        if skewness < 0.2 {
            // Human typing is usually positively skewed (long tail)
            flags.push(ForgeryFlag::WrongSkewness { skewness });
        }

        // Check 3: Missing micro-pauses (150-500ms)
        let micro_pauses = intervals
            .iter()
            .filter(|&&i| i > 150.0 && i < 500.0)
            .count();
        if (micro_pauses as f64 / intervals.len() as f64) < 0.05 {
            flags.push(ForgeryFlag::MissingMicroPauses);
        }

        // Check 4: Impossible speeds (< 30ms between keystrokes is superhuman/rollover)
        // High count of very low intervals implies script injection or mechanical rollover without debounce
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

// Helpers
fn calculate_skewness(data: &[f64], mean: f64, std: f64) -> f64 {
    if std == 0.0 {
        return 0.0;
    }
    let n = data.len() as f64;
    let sum_cubed_diff: f64 = data.iter().map(|&x| (x - mean).powi(3)).sum();
    (sum_cubed_diff / n) / std.powi(3)
}

fn calculate_kurtosis(data: &[f64], mean: f64, std: f64) -> f64 {
    if std == 0.0 {
        return 0.0;
    }
    let n = data.len() as f64;
    let sum_quad_diff: f64 = data.iter().map(|&x| (x - mean).powi(4)).sum();
    (sum_quad_diff / n) / std.powi(4) - 3.0 // Excess kurtosis
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
