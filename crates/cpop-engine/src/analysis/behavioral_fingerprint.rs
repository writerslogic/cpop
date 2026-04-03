// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Generate unforgeable behavioral fingerprints from typing patterns

use crate::analysis::stats;
use crate::jitter::SimpleJitterSample;
use serde::{Deserialize, Serialize};

/// Maximum interval in ms before filtering as an outlier pause (5 seconds).
const MAX_PAUSE_FILTER_MS: f64 = 5000.0;

/// Intervals above this threshold indicate paragraph-level pauses.
const PARAGRAPH_PAUSE_MS: f64 = 2000.0;

/// Intervals above this threshold separate typing bursts.
const BURST_SEPARATOR_MS: f64 = 500.0;

/// Intervals below this threshold count as fast typing within a burst.
const BURST_INTERVAL_MS: f64 = 200.0;

/// CV below this flags suspiciously regular (robotic) timing.
const CV_FORGERY_THRESHOLD: f64 = 0.2;

/// Skewness below this flags non-human timing distribution.
const SKEWNESS_FORGERY_THRESHOLD: f64 = 0.2;

/// Lower bound for micro-pause detection (ms).
const MICRO_PAUSE_MIN_MS: f64 = 150.0;

/// Upper bound for micro-pause detection (ms).
const MICRO_PAUSE_MAX_MS: f64 = 500.0;

/// Minimum fraction of micro-pauses expected in natural typing.
const MICRO_PAUSE_RATIO_THRESHOLD: f64 = 0.05;

/// Intervals below this are physically impossible for a single typist.
const IMPOSSIBLY_FAST_MS: f64 = 20.0;

/// Percentage of impossibly fast intervals that triggers a flag.
const SUSPICIOUS_FAST_PERCENT: usize = 10;

/// Minimum interval count required for fatigue analysis.
const MIN_FATIGUE_SAMPLES: usize = 40;

/// Last-quarter mean must exceed first-quarter mean by this ratio to show fatigue.
const FATIGUE_SLOWDOWN_RATIO: f64 = 1.05;

/// Per-flag confidence multiplier in forgery analysis.
const FORGERY_CONFIDENCE_PER_FLAG: f64 = 0.3;

/// Maximum number of samples processed for fingerprint/forgery analysis.
/// Limits memory allocation from untrusted IPC input.
const MAX_FINGERPRINT_SAMPLES: usize = 100_000;

/// Features extracted from typing that are hard to fake
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralFingerprint {
    /// Mean inter-keystroke interval in milliseconds.
    pub keystroke_interval_mean: f64,
    /// Standard deviation of inter-keystroke intervals.
    pub keystroke_interval_std: f64,
    /// Skewness of the interval distribution (positive = right-tailed).
    pub keystroke_interval_skewness: f64,
    /// Excess kurtosis of the interval distribution.
    pub keystroke_interval_kurtosis: f64,

    /// Normalized histogram of interval durations across fixed buckets.
    pub interval_buckets: Vec<f64>,

    /// Mean duration of sentence-level pauses (> 500ms).
    pub sentence_pause_mean: f64,
    /// Mean duration of paragraph-level pauses (> 2000ms).
    pub paragraph_pause_mean: f64,
    /// Fraction of keystrokes preceded by a thinking pause.
    pub thinking_pause_frequency: f64,

    /// Mean number of keystrokes per typing burst.
    pub burst_length_mean: f64,
    /// Variance of within-burst keystroke speeds.
    pub burst_speed_variance: f64,
}

/// Result of automated forgery detection on typing samples.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForgeryAnalysis {
    /// True if any forgery indicator was triggered.
    pub is_suspicious: bool,
    /// Confidence score (0.0 to 1.0) based on number of flags.
    pub confidence: f64,
    /// Individual forgery indicators that were triggered.
    pub flags: Vec<ForgeryFlag>,
}

/// Individual forgery indicator from behavioral analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ForgeryFlag {
    /// Coefficient of variation is suspiciously low (robotic regularity).
    TooRegular { cv: f64 },
    /// Skewness is too low for natural human timing distribution.
    WrongSkewness { skewness: f64 },
    /// Expected micro-pauses (150-500ms) are absent or too rare.
    MissingMicroPauses,
    /// Intervals below 20ms exceed plausible threshold.
    SuperhumanSpeed { count: usize },
    /// No detectable slowdown between first and last quarter (fatigue absent).
    NoFatiguePattern,
}

/// Convert a nanosecond timestamp difference to milliseconds.
fn interval_ms(a: &SimpleJitterSample, b: &SimpleJitterSample) -> f64 {
    b.timestamp_ns.saturating_sub(a.timestamp_ns).max(0) as f64 / 1_000_000.0
}

impl BehavioralFingerprint {
    /// Build a fingerprint from jitter samples, computing all statistical features.
    pub fn from_samples(samples: &[SimpleJitterSample]) -> Self {
        if samples.len() < 2 {
            return Self::default();
        }
        let samples = if samples.len() > MAX_FINGERPRINT_SAMPLES {
            &samples[..MAX_FINGERPRINT_SAMPLES]
        } else {
            samples
        };

        let intervals: Vec<f64> = samples
            .windows(2)
            .map(|w| interval_ms(&w[0], &w[1]))
            .filter(|&i| i > 0.0 && i < MAX_PAUSE_FILTER_MS)
            .collect();

        if intervals.is_empty() {
            return Self::default();
        }

        let (mean, std) = stats::mean_and_std_dev(&intervals);

        let skewness = stats::skewness(&intervals, mean, std);
        let kurtosis = stats::kurtosis(&intervals, mean, std);

        let long_pauses = intervals
            .iter()
            .filter(|&&i| i > PARAGRAPH_PAUSE_MS)
            .count();

        let thinking_freq = long_pauses as f64 / samples.len() as f64;

        let mut bursts = Vec::new();
        let mut current_burst_len = 0;
        for w in samples.windows(2) {
            let interval = interval_ms(&w[0], &w[1]);
            if interval > BURST_SEPARATOR_MS {
                if current_burst_len > 0 {
                    bursts.push(current_burst_len as f64);
                }
                current_burst_len = 0;
            } else {
                current_burst_len += 1;
            }
        }
        if current_burst_len > 0 {
            bursts.push(current_burst_len as f64);
        }

        let burst_mean = if !bursts.is_empty() {
            bursts.iter().sum::<f64>() / bursts.len() as f64
        } else {
            0.0
        };

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

        let sentence_pauses: Vec<f64> = intervals
            .iter()
            .copied()
            .filter(|&i| i > BURST_SEPARATOR_MS)
            .collect();
        let sentence_pause_mean = if !sentence_pauses.is_empty() {
            sentence_pauses.iter().sum::<f64>() / sentence_pauses.len() as f64
        } else {
            0.0
        };

        let paragraph_pauses: Vec<f64> = intervals
            .iter()
            .copied()
            .filter(|&i| i > PARAGRAPH_PAUSE_MS)
            .collect();
        let paragraph_pause_mean = if !paragraph_pauses.is_empty() {
            paragraph_pauses.iter().sum::<f64>() / paragraph_pauses.len() as f64
        } else {
            0.0
        };

        let burst_intervals: Vec<f64> = intervals
            .iter()
            .copied()
            .filter(|&i| i < BURST_INTERVAL_MS)
            .collect();
        let burst_speed_variance = if burst_intervals.len() >= 2 {
            let burst_mean_val = burst_intervals.iter().sum::<f64>() / burst_intervals.len() as f64;
            let v = burst_intervals
                .iter()
                .map(|&x| (x - burst_mean_val).powi(2))
                .sum::<f64>()
                / (burst_intervals.len() - 1) as f64;
            if v.is_finite() {
                v
            } else {
                0.0
            }
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

    /// Scan timing samples for statistical anomalies indicating synthetic input.
    pub fn detect_forgery(samples: &[SimpleJitterSample]) -> ForgeryAnalysis {
        if samples.len() < 10 {
            return ForgeryAnalysis {
                is_suspicious: false,
                confidence: 0.0,
                flags: vec![],
            };
        }
        let samples = if samples.len() > MAX_FINGERPRINT_SAMPLES {
            &samples[..MAX_FINGERPRINT_SAMPLES]
        } else {
            samples
        };

        let intervals: Vec<f64> = samples
            .windows(2)
            .map(|w| interval_ms(&w[0], &w[1]))
            .filter(|&i| i > 0.0 && i < MAX_PAUSE_FILTER_MS)
            .collect();

        let mut flags = Vec::new();

        let (mean, std) = stats::mean_and_std_dev(&intervals);

        if mean > 0.0 {
            let cv = std / mean;
            if cv.is_finite() && cv < CV_FORGERY_THRESHOLD {
                flags.push(ForgeryFlag::TooRegular { cv });
            }
        }

        let skewness = stats::skewness(&intervals, mean, std);
        if skewness < SKEWNESS_FORGERY_THRESHOLD {
            flags.push(ForgeryFlag::WrongSkewness { skewness });
        }

        let micro_pauses = intervals
            .iter()
            .filter(|&&i| i > MICRO_PAUSE_MIN_MS && i < MICRO_PAUSE_MAX_MS)
            .count();
        if !intervals.is_empty()
            && (micro_pauses as f64 / intervals.len() as f64) < MICRO_PAUSE_RATIO_THRESHOLD
        {
            flags.push(ForgeryFlag::MissingMicroPauses);
        }

        let impossibly_fast = intervals
            .iter()
            .filter(|&&i| i < IMPOSSIBLY_FAST_MS)
            .count();
        if impossibly_fast * SUSPICIOUS_FAST_PERCENT > intervals.len() {
            flags.push(ForgeryFlag::SuperhumanSpeed {
                count: impossibly_fast,
            });
        }

        if intervals.len() >= MIN_FATIGUE_SAMPLES {
            let quarter = intervals.len() / 4;
            let first_q = &intervals[..quarter];
            let last_q = &intervals[intervals.len() - quarter..];
            let first_mean = first_q.iter().sum::<f64>() / first_q.len() as f64;
            let last_mean = last_q.iter().sum::<f64>() / last_q.len() as f64;
            if first_mean > 0.0 && last_mean <= first_mean * FATIGUE_SLOWDOWN_RATIO {
                flags.push(ForgeryFlag::NoFatiguePattern);
            }
        }

        ForgeryAnalysis {
            is_suspicious: !flags.is_empty(),
            confidence: (flags.len() as f64 * FORGERY_CONFIDENCE_PER_FLAG).min(1.0),
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

        samples.push(SimpleJitterSample {
            timestamp_ns: current_ns as i64,
            duration_since_last_ns: 0,
            zone: 1,
            ..Default::default()
        });

        for &interval in intervals_ms {
            let duration_ns = interval * 1_000_000;
            current_ns += duration_ns;
            samples.push(SimpleJitterSample {
                timestamp_ns: current_ns as i64,
                duration_since_last_ns: duration_ns,
                zone: 1,
                ..Default::default()
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
        let intervals = vec![200, 250, 180, 220, 400, 210, 190, 230, 220, 200];
        let samples = mock_samples(&intervals);
        let fp = BehavioralFingerprint::from_samples(&samples);

        assert!(fp.keystroke_interval_mean > 200.0 && fp.keystroke_interval_mean < 300.0);
        assert!(fp.keystroke_interval_std > 0.0);
        assert!(fp.keystroke_interval_skewness > 0.0);
    }

    #[test]
    fn test_fingerprint_interval_buckets() {
        let intervals = vec![30, 80, 120, 180, 250, 400, 700, 1500, 3000, 150];
        let samples = mock_samples(&intervals);
        let fp = BehavioralFingerprint::from_samples(&samples);

        assert_eq!(fp.interval_buckets.len(), 9);
        let sum: f64 = fp.interval_buckets.iter().sum();
        assert!((sum - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_fingerprint_pause_means() {
        let intervals = vec![100, 150, 120, 800, 100, 130, 2500, 100, 3000, 150];
        let samples = mock_samples(&intervals);
        let fp = BehavioralFingerprint::from_samples(&samples);

        assert!(fp.sentence_pause_mean > 500.0);
        assert!(fp.paragraph_pause_mean > 2000.0);
    }

    #[test]
    fn test_fingerprint_burst_speed_variance() {
        let intervals = vec![80, 120, 150, 90, 110, 130, 170, 500, 100, 140];
        let samples = mock_samples(&intervals);
        let fp = BehavioralFingerprint::from_samples(&samples);

        assert!(fp.burst_speed_variance > 0.0);
    }

    #[test]
    fn test_detect_forgery_robotic() {
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
        let intervals = vec![
            180, 220, 190, 450, 210, 170, 230, 200, 190, 210, 500, 180, 220, 200, 190,
        ];
        let samples = mock_samples(&intervals);
        let analysis = BehavioralFingerprint::detect_forgery(&samples);

        assert!(!analysis.is_suspicious);
    }

    #[test]
    fn test_detect_forgery_superhuman() {
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

    #[test]
    fn test_fingerprint_single_sample_returns_default() {
        let samples = mock_samples(&[]);
        assert_eq!(samples.len(), 1); // only the initial sample
        let fp = BehavioralFingerprint::from_samples(&samples);
        assert_eq!(fp.keystroke_interval_mean, 0.0);
        assert_eq!(fp.burst_length_mean, 0.0);
    }

    #[test]
    fn test_detect_forgery_too_few_samples() {
        let samples = mock_samples(&[200, 180, 220]);
        let analysis = BehavioralFingerprint::detect_forgery(&samples);
        // < 10 samples -> not suspicious, no flags
        assert!(!analysis.is_suspicious);
        assert!(analysis.flags.is_empty());
        assert!((analysis.confidence - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_fingerprint_thinking_pause_frequency() {
        // Include several paragraph-level pauses (> 2000ms)
        let intervals = vec![150, 180, 2500, 160, 170, 3000, 140, 190, 200, 2100];
        let samples = mock_samples(&intervals);
        let fp = BehavioralFingerprint::from_samples(&samples);

        assert!(
            fp.thinking_pause_frequency > 0.0,
            "Should detect thinking pauses, got {}",
            fp.thinking_pause_frequency
        );
    }

    #[test]
    fn test_detect_forgery_no_fatigue_pattern() {
        // 50 perfectly uniform intervals -> should flag NoFatiguePattern
        let intervals = vec![200; 50];
        let samples = mock_samples(&intervals);
        let analysis = BehavioralFingerprint::detect_forgery(&samples);

        assert!(analysis.is_suspicious);
        assert!(analysis
            .flags
            .iter()
            .any(|f| matches!(f, ForgeryFlag::NoFatiguePattern)));
    }

    #[test]
    fn test_forgery_confidence_caps_at_one() {
        // Trigger as many flags as possible -> confidence should max at 1.0
        let mut intervals = vec![200; 50]; // uniform -> TooRegular, WrongSkewness, NoFatiguePattern, MissingMicroPauses
                                           // Add superhuman speeds
        for interval in &mut intervals[..10] {
            *interval = 5;
        }
        let samples = mock_samples(&intervals);
        let analysis = BehavioralFingerprint::detect_forgery(&samples);

        assert!(analysis.confidence <= 1.0);
    }
}
