// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Distribution types for typing dynamics analysis: IKI, zone profiles, pause signatures,
//! circadian patterns, and session signatures.

use crate::analysis::stats;
use crate::analysis::stats::{merge_histogram, normalize_histogram, relative_similarity};
use crate::jitter::SimpleJitterSample;
use serde::{Deserialize, Serialize};

use super::activity::{weighted_blend, WeightedDistribution};

/// 50ms buckets covering 0-2500ms
pub(super) const IKI_HISTOGRAM_BUCKETS: usize = 50;
const IKI_BUCKET_WIDTH_MS: f64 = 50.0;
/// 8x8 zone transition matrix
const ZONE_TRANSITIONS: usize = 64;
pub(super) const SENTENCE_PAUSE_MS: f64 = 400.0;
pub(super) const PARAGRAPH_PAUSE_MS: f64 = 1000.0;
pub(super) const THINKING_PAUSE_MS: f64 = 2000.0;

/// Inter-Key Interval distribution (milliseconds).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IkiDistribution {
    pub mean: f64,
    pub std_dev: f64,
    /// Human typing is typically right-skewed
    pub skewness: f64,
    /// Excess kurtosis (0 = normal)
    pub kurtosis: f64,
    /// [5th, 25th, 50th, 75th, 95th]
    pub percentiles: [f64; 5],
    /// Normalized 50ms-wide histogram buckets
    pub histogram: Vec<f64>,
}

impl Default for IkiDistribution {
    fn default() -> Self {
        Self {
            mean: 0.0,
            std_dev: 0.0,
            skewness: 0.0,
            kurtosis: 0.0,
            percentiles: [0.0; 5],
            histogram: vec![0.0; IKI_HISTOGRAM_BUCKETS],
        }
    }
}

impl IkiDistribution {
    /// Build from raw IKI values (ms).
    pub fn from_intervals(intervals: &[f64]) -> Self {
        if intervals.is_empty() {
            return Self::default();
        }

        let n = intervals.len() as f64;
        let mean = intervals.iter().sum::<f64>() / n;
        let variance = if n > 1.0 {
            intervals.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0)
        } else {
            0.0
        };
        let std_dev = if variance > 0.0 { variance.sqrt() } else { 0.0 };

        let skewness = stats::skewness(intervals, mean, std_dev);
        let kurtosis = stats::kurtosis(intervals, mean, std_dev);

        // O(n) percentile selection via select_nth_unstable
        let percentiles = {
            let mut buf = intervals.to_vec();
            let n = buf.len();
            let cmp = |a: &f64, b: &f64| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal);
            let pcts = [0.05, 0.25, 0.50, 0.75, 0.95];
            let mut vals = [0.0f64; 5];
            for (i, &p) in pcts.iter().enumerate() {
                let idx = (p * (n.saturating_sub(1)) as f64).round() as usize;
                let idx = idx.min(n.saturating_sub(1));
                buf.select_nth_unstable_by(idx, cmp);
                vals[i] = buf[idx];
            }
            vals
        };

        let mut histogram = vec![0.0; IKI_HISTOGRAM_BUCKETS];
        for &iki in intervals {
            let bucket = ((iki / IKI_BUCKET_WIDTH_MS) as usize).min(IKI_HISTOGRAM_BUCKETS - 1);
            histogram[bucket] += 1.0;
        }
        let total: f64 = histogram.iter().sum();
        if total > 0.0 {
            for h in &mut histogram {
                *h /= total;
            }
        }

        Self {
            mean,
            std_dev,
            skewness,
            kurtosis,
            percentiles,
            histogram,
        }
    }

    /// Weighted merge with another distribution.
    pub fn merge(&mut self, other: &IkiDistribution, self_weight: f64, other_weight: f64) {
        self.weighted_merge(other, self_weight, other_weight);
    }

    /// Similarity (0.0-1.0) via Bhattacharyya coefficient on histograms.
    pub fn similarity(&self, other: &IkiDistribution) -> f64 {
        <Self as WeightedDistribution>::similarity(self, other)
    }
}

impl WeightedDistribution for IkiDistribution {
    fn similarity(&self, other: &Self) -> f64 {
        let hist_sim =
            crate::analysis::stats::bhattacharyya_coefficient(&self.histogram, &other.histogram);

        let mean_sim = 1.0 - (self.mean - other.mean).abs() / (self.mean + other.mean + 1.0);
        let std_sim =
            1.0 - (self.std_dev - other.std_dev).abs() / (self.std_dev + other.std_dev + 1.0);

        (hist_sim * 0.6 + mean_sim * 0.2 + std_sim * 0.2).clamp(0.0, 1.0)
    }

    fn weighted_merge(&mut self, other: &Self, self_weight: f64, other_weight: f64) {
        self.mean = weighted_blend(self.mean, other.mean, self_weight, other_weight);
        self.std_dev = weighted_blend(self.std_dev, other.std_dev, self_weight, other_weight);
        self.skewness = weighted_blend(self.skewness, other.skewness, self_weight, other_weight);
        self.kurtosis = weighted_blend(self.kurtosis, other.kurtosis, self_weight, other_weight);

        for i in 0..5 {
            self.percentiles[i] = weighted_blend(
                self.percentiles[i],
                other.percentiles[i],
                self_weight,
                other_weight,
            );
        }

        merge_histogram(
            &mut self.histogram,
            &other.histogram,
            self_weight,
            other_weight,
        );
    }
}

/// Keyboard zone usage profile.
///
/// Zones 0-3: left hand (pinky to index), 4-7: right hand (index to pinky).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneProfile {
    pub zone_frequencies: [f64; 8],
    pub zone_transitions: Vec<f64>,
    pub same_finger_histogram: Vec<f64>,
    pub same_hand_histogram: Vec<f64>,
    pub alternating_histogram: Vec<f64>,
}

impl Default for ZoneProfile {
    fn default() -> Self {
        Self {
            zone_frequencies: [0.125; 8],
            zone_transitions: vec![0.0; ZONE_TRANSITIONS],
            same_finger_histogram: vec![0.0; 20],
            same_hand_histogram: vec![0.0; 20],
            alternating_histogram: vec![0.0; 20],
        }
    }
}

impl ZoneProfile {
    /// Build zone profile from jitter samples.
    pub fn from_samples(samples: &[SimpleJitterSample]) -> Self {
        let mut profile = Self::default();

        if samples.is_empty() {
            return profile;
        }

        // Single pass: accumulate zone counts, transitions, and IKI histograms
        let mut zone_counts = [0usize; 8];
        let mut transitions = vec![0usize; ZONE_TRANSITIONS];

        zone_counts[(samples[0].zone as usize).min(7)] += 1;
        for w in samples.windows(2) {
            let z0 = (w[0].zone as usize).min(7);
            let z1 = (w[1].zone as usize).min(7);
            zone_counts[z1] += 1;
            transitions[z0 * 8 + z1] += 1;

            let iki_ms = match w[1].timestamp_ns.checked_sub(w[0].timestamp_ns) {
                Some(d) if d > 0 => d as f64 / 1_000_000.0,
                _ => continue,
            };
            let bucket = ((iki_ms / 50.0) as usize).min(19);
            if z0 == z1 {
                profile.same_finger_histogram[bucket] += 1.0;
            } else if (z0 < 4) == (z1 < 4) {
                profile.same_hand_histogram[bucket] += 1.0;
            } else {
                profile.alternating_histogram[bucket] += 1.0;
            }
        }

        let total: usize = zone_counts.iter().sum();
        if total > 0 {
            for (i, &count) in zone_counts.iter().enumerate() {
                profile.zone_frequencies[i] = count as f64 / total as f64;
            }
        }
        let trans_total: usize = transitions.iter().sum();
        if trans_total > 0 {
            for (i, &count) in transitions.iter().enumerate() {
                profile.zone_transitions[i] = count as f64 / trans_total as f64;
            }
        }

        normalize_histogram(&mut profile.same_finger_histogram);
        normalize_histogram(&mut profile.same_hand_histogram);
        normalize_histogram(&mut profile.alternating_histogram);

        profile
    }

    /// Weighted merge with another profile.
    pub fn merge(&mut self, other: &ZoneProfile, self_weight: f64, other_weight: f64) {
        self.weighted_merge(other, self_weight, other_weight);
    }

    /// Similarity (0.0-1.0) based on zone frequencies and transitions.
    pub fn similarity(&self, other: &ZoneProfile) -> f64 {
        <Self as WeightedDistribution>::similarity(self, other)
    }

    /// Return the most frequently used zone as a human-readable string.
    pub fn dominant_zone(&self) -> String {
        let (zone_idx, freq) = self
            .zone_frequencies
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .unwrap_or((0, &0.0));

        let zone_names = [
            "Left Pinky",
            "Left Ring",
            "Left Middle",
            "Left Index",
            "Right Index",
            "Right Middle",
            "Right Ring",
            "Right Pinky",
        ];
        format!("{} ({:.0}%)", zone_names[zone_idx], freq * 100.0)
    }
}

impl WeightedDistribution for ZoneProfile {
    fn similarity(&self, other: &Self) -> f64 {
        let freq_sim: f64 = self
            .zone_frequencies
            .iter()
            .zip(other.zone_frequencies.iter())
            .map(|(a, b)| 1.0 - (a - b).abs())
            .sum::<f64>()
            / 8.0;

        let trans_sim: f64 = self
            .zone_transitions
            .iter()
            .zip(other.zone_transitions.iter())
            .map(|(a, b)| a.min(*b))
            .sum();

        (freq_sim * 0.4 + trans_sim * 0.6).clamp(0.0, 1.0)
    }

    fn weighted_merge(&mut self, other: &Self, self_weight: f64, other_weight: f64) {
        for i in 0..8 {
            self.zone_frequencies[i] = weighted_blend(
                self.zone_frequencies[i],
                other.zone_frequencies[i],
                self_weight,
                other_weight,
            );
        }

        merge_histogram(
            &mut self.zone_transitions,
            &other.zone_transitions,
            self_weight,
            other_weight,
        );
        merge_histogram(
            &mut self.same_finger_histogram,
            &other.same_finger_histogram,
            self_weight,
            other_weight,
        );
        merge_histogram(
            &mut self.same_hand_histogram,
            &other.same_hand_histogram,
            self_weight,
            other_weight,
        );
        merge_histogram(
            &mut self.alternating_histogram,
            &other.alternating_histogram,
            self_weight,
            other_weight,
        );
    }
}

/// Characteristic pause patterns (sentence / paragraph / thinking).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PauseSignature {
    /// Mean duration in ms for each pause tier
    pub sentence_pause_mean: f64,
    pub paragraph_pause_mean: f64,
    pub thinking_pause_mean: f64,
    /// Occurrences per 100 keystrokes
    pub sentence_pause_frequency: f64,
    pub paragraph_pause_frequency: f64,
    pub thinking_pause_frequency: f64,
}

impl Default for PauseSignature {
    fn default() -> Self {
        Self {
            sentence_pause_mean: 0.0,
            paragraph_pause_mean: 0.0,
            thinking_pause_mean: 0.0,
            sentence_pause_frequency: 0.0,
            paragraph_pause_frequency: 0.0,
            thinking_pause_frequency: 0.0,
        }
    }
}

impl PauseSignature {
    /// Build from IKI values, classifying pauses by duration tier.
    pub fn from_intervals(intervals: &[f64]) -> Self {
        if intervals.is_empty() {
            return Self::default();
        }

        let mut sentence_pauses = Vec::new();
        let mut paragraph_pauses = Vec::new();
        let mut thinking_pauses = Vec::new();

        for &iki in intervals {
            if iki >= THINKING_PAUSE_MS {
                thinking_pauses.push(iki);
            } else if iki >= PARAGRAPH_PAUSE_MS {
                paragraph_pauses.push(iki);
            } else if iki >= SENTENCE_PAUSE_MS {
                sentence_pauses.push(iki);
            }
        }

        let n = intervals.len() as f64;
        let per_100 = 100.0 / n;

        Self {
            sentence_pause_mean: stats::mean_or_zero(&sentence_pauses),
            paragraph_pause_mean: stats::mean_or_zero(&paragraph_pauses),
            thinking_pause_mean: stats::mean_or_zero(&thinking_pauses),
            sentence_pause_frequency: sentence_pauses.len() as f64 * per_100,
            paragraph_pause_frequency: paragraph_pauses.len() as f64 * per_100,
            thinking_pause_frequency: thinking_pauses.len() as f64 * per_100,
        }
    }

    /// Weighted merge with another signature.
    pub fn merge(&mut self, other: &PauseSignature, self_weight: f64, other_weight: f64) {
        self.weighted_merge(other, self_weight, other_weight);
    }

    /// Similarity (0.0-1.0) comparing mean durations and frequencies.
    pub fn similarity(&self, other: &PauseSignature) -> f64 {
        <Self as WeightedDistribution>::similarity(self, other)
    }
}

impl WeightedDistribution for PauseSignature {
    fn similarity(&self, other: &Self) -> f64 {
        let mean_sims = [
            relative_similarity(self.sentence_pause_mean, other.sentence_pause_mean),
            relative_similarity(self.paragraph_pause_mean, other.paragraph_pause_mean),
            relative_similarity(self.thinking_pause_mean, other.thinking_pause_mean),
        ];
        let freq_sims = [
            relative_similarity(
                self.sentence_pause_frequency,
                other.sentence_pause_frequency,
            ),
            relative_similarity(
                self.paragraph_pause_frequency,
                other.paragraph_pause_frequency,
            ),
            relative_similarity(
                self.thinking_pause_frequency,
                other.thinking_pause_frequency,
            ),
        ];

        let mean_sim: f64 = mean_sims.iter().sum::<f64>() / 3.0;
        let freq_sim: f64 = freq_sims.iter().sum::<f64>() / 3.0;

        (mean_sim * 0.5 + freq_sim * 0.5).clamp(0.0, 1.0)
    }

    fn weighted_merge(&mut self, other: &Self, self_weight: f64, other_weight: f64) {
        self.sentence_pause_mean = weighted_blend(
            self.sentence_pause_mean,
            other.sentence_pause_mean,
            self_weight,
            other_weight,
        );
        self.paragraph_pause_mean = weighted_blend(
            self.paragraph_pause_mean,
            other.paragraph_pause_mean,
            self_weight,
            other_weight,
        );
        self.thinking_pause_mean = weighted_blend(
            self.thinking_pause_mean,
            other.thinking_pause_mean,
            self_weight,
            other_weight,
        );
        self.sentence_pause_frequency = weighted_blend(
            self.sentence_pause_frequency,
            other.sentence_pause_frequency,
            self_weight,
            other_weight,
        );
        self.paragraph_pause_frequency = weighted_blend(
            self.paragraph_pause_frequency,
            other.paragraph_pause_frequency,
            self_weight,
            other_weight,
        );
        self.thinking_pause_frequency = weighted_blend(
            self.thinking_pause_frequency,
            other.thinking_pause_frequency,
            self_weight,
            other_weight,
        );
    }
}

/// Typing activity distribution by hour of day (0-23).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircadianPattern {
    pub hourly_activity: [f64; 24],
    pub total_samples: u64,
}

impl Default for CircadianPattern {
    fn default() -> Self {
        Self {
            hourly_activity: [0.0; 24],
            total_samples: 0,
        }
    }
}

impl CircadianPattern {
    /// Record a keystroke at the given hour (0-23).
    pub fn record(&mut self, hour: u8) {
        if hour < 24 {
            self.hourly_activity[hour as usize] += 1.0;
            self.total_samples += 1;
        }
    }

    /// Normalize to sum to 1.0.
    pub fn normalize(&mut self) {
        let total: f64 = self.hourly_activity.iter().sum();
        if total > 0.0 {
            for h in &mut self.hourly_activity {
                *h /= total;
            }
        }
    }

    /// Additive merge (re-normalize after merging).
    pub fn merge(&mut self, other: &CircadianPattern) {
        for i in 0..24 {
            self.hourly_activity[i] += other.hourly_activity[i];
        }
        self.total_samples += other.total_samples;
    }
}

/// Session-level typing characteristics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSignature {
    pub mean_session_duration: f64,
    /// Keystrokes per minute
    pub mean_typing_speed: f64,
    /// Speed decay over session duration
    pub fatigue_coefficient: f64,
    pub session_count: u32,
}

impl Default for SessionSignature {
    fn default() -> Self {
        Self {
            mean_session_duration: 0.0,
            mean_typing_speed: 0.0,
            fatigue_coefficient: 0.0,
            session_count: 0,
        }
    }
}

impl SessionSignature {
    /// Weighted merge by session count.
    pub fn merge(&mut self, other: &SessionSignature) {
        let total = self.session_count + other.session_count;
        if total == 0 {
            return;
        }
        let self_w = self.session_count as f64 / total as f64;
        let other_w = other.session_count as f64 / total as f64;

        self.mean_session_duration =
            self.mean_session_duration * self_w + other.mean_session_duration * other_w;
        self.mean_typing_speed =
            self.mean_typing_speed * self_w + other.mean_typing_speed * other_w;
        self.fatigue_coefficient =
            self.fatigue_coefficient * self_w + other.fatigue_coefficient * other_w;
        self.session_count = total;
    }
}
