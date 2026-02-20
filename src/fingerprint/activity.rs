//! Activity Fingerprint - Typing dynamics analysis
//!
//! This module captures *how* you type, not *what* you type:
//! - Inter-key intervals (IKI) distribution
//! - Keyboard zone usage patterns
//! - Pause signatures
//! - Circadian typing patterns
//! - Session characteristics
//!
//! This is enabled by DEFAULT as it doesn't capture content.

use crate::jitter::SimpleJitterSample;
use serde::{Deserialize, Serialize};
use statrs::statistics::Statistics;
use std::collections::VecDeque;

// =============================================================================
// Constants
// =============================================================================

/// Number of IKI histogram buckets (50ms each, 0-2500ms)
const IKI_HISTOGRAM_BUCKETS: usize = 50;
/// Bucket width in milliseconds
const IKI_BUCKET_WIDTH_MS: f64 = 50.0;
/// Number of zone transition pairs (8 zones * 8 zones)
const ZONE_TRANSITIONS: usize = 64;
/// Pause threshold for sentence pauses (ms)
const SENTENCE_PAUSE_MS: f64 = 400.0;
/// Pause threshold for paragraph pauses (ms)
const PARAGRAPH_PAUSE_MS: f64 = 1000.0;
/// Pause threshold for thinking pauses (ms)
const THINKING_PAUSE_MS: f64 = 2000.0;

// =============================================================================
// ActivityFingerprint
// =============================================================================

/// Activity-based fingerprint capturing typing dynamics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityFingerprint {
    /// Unique identifier
    pub id: String,
    /// Number of samples used to build this fingerprint
    pub sample_count: u64,
    /// Confidence level (0.0-1.0)
    pub confidence: f64,

    // --- Inter-Key Interval Distribution ---
    /// IKI distribution statistics
    pub iki_distribution: IkiDistribution,

    // --- Zone Patterns ---
    /// Keyboard zone usage profile
    pub zone_profile: ZoneProfile,

    // --- Pause Signature ---
    /// Characteristic pause patterns
    pub pause_signature: PauseSignature,

    // --- Temporal Patterns ---
    /// When user typically types (by hour)
    pub circadian_pattern: CircadianPattern,

    // --- Session Characteristics ---
    /// Session-level typing patterns
    pub session_signature: SessionSignature,

    // --- Hardware Entropy ---
    /// Ratio of samples using hardware entropy (0.0-1.0).
    /// Only set when physjitter feature is enabled and hardware entropy is available.
    /// Higher values indicate more samples came from verified hardware input.
    #[serde(default)]
    pub phys_ratio: Option<f64>,

    // --- Mouse Idle Jitter ---
    /// Mouse idle jitter statistics for fingerprinting.
    /// Captures micro-movements while user is typing (mouse stationary next to keyboard).
    #[serde(default)]
    pub mouse_idle_stats: Option<crate::platform::MouseIdleStats>,
}

impl Default for ActivityFingerprint {
    fn default() -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            sample_count: 0,
            confidence: 0.0,
            iki_distribution: IkiDistribution::default(),
            zone_profile: ZoneProfile::default(),
            pause_signature: PauseSignature::default(),
            circadian_pattern: CircadianPattern::default(),
            session_signature: SessionSignature::default(),
            phys_ratio: None,
            mouse_idle_stats: None,
        }
    }
}

impl ActivityFingerprint {
    /// Create a fingerprint from a collection of samples.
    pub fn from_samples(samples: &[SimpleJitterSample]) -> Self {
        if samples.len() < 2 {
            return Self {
                sample_count: samples.len() as u64,
                ..Self::default()
            };
        }

        let mut fp = Self {
            sample_count: samples.len() as u64,
            ..Self::default()
        };

        // Calculate IKIs
        let ikis: Vec<f64> = samples
            .windows(2)
            .map(|w| (w[1].timestamp_ns - w[0].timestamp_ns) as f64 / 1_000_000.0)
            .filter(|&i| i > 0.0 && i < 10000.0) // Filter extreme values
            .collect();

        if ikis.is_empty() {
            return fp;
        }

        // IKI distribution
        fp.iki_distribution = IkiDistribution::from_intervals(&ikis);

        // Zone profile
        fp.zone_profile = ZoneProfile::from_samples(samples);

        // Pause signature
        fp.pause_signature = PauseSignature::from_intervals(&ikis);

        // Update confidence
        fp.update_confidence();

        fp
    }

    /// Merge another fingerprint into this one.
    pub fn merge(&mut self, other: &ActivityFingerprint) {
        // Weighted merge based on sample counts
        let total = self.sample_count + other.sample_count;
        if total == 0 {
            return;
        }

        let self_weight = self.sample_count as f64 / total as f64;
        let other_weight = other.sample_count as f64 / total as f64;

        self.iki_distribution
            .merge(&other.iki_distribution, self_weight, other_weight);
        self.zone_profile
            .merge(&other.zone_profile, self_weight, other_weight);
        self.pause_signature
            .merge(&other.pause_signature, self_weight, other_weight);
        self.circadian_pattern.merge(&other.circadian_pattern);
        self.session_signature.merge(&other.session_signature);

        // Merge phys_ratio with weighted average
        self.phys_ratio = match (self.phys_ratio, other.phys_ratio) {
            (Some(a), Some(b)) => Some(a * self_weight + b * other_weight),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };

        // Merge mouse idle stats
        match (&mut self.mouse_idle_stats, &other.mouse_idle_stats) {
            (Some(ref mut self_stats), Some(other_stats)) => {
                self_stats.merge(other_stats);
            }
            (None, Some(other_stats)) => {
                self.mouse_idle_stats = Some(other_stats.clone());
            }
            _ => {}
        }

        self.sample_count = total;
        self.update_confidence();
    }

    /// Set the hardware entropy ratio.
    ///
    /// This should be called when using HybridJitterSession to track
    /// what fraction of samples used hardware entropy.
    pub fn set_phys_ratio(&mut self, ratio: f64) {
        self.phys_ratio = Some(ratio.clamp(0.0, 1.0));
    }

    /// Set mouse idle jitter statistics.
    ///
    /// This captures micro-movements while the user is typing,
    /// providing an additional biometric signal for author verification.
    pub fn set_mouse_idle_stats(&mut self, stats: crate::platform::MouseIdleStats) {
        self.mouse_idle_stats = Some(stats);
    }

    /// Get mouse idle jitter statistics if available.
    pub fn mouse_idle_stats(&self) -> Option<&crate::platform::MouseIdleStats> {
        self.mouse_idle_stats.as_ref()
    }

    /// Calculate similarity with another fingerprint (0.0-1.0).
    pub fn similarity(&self, other: &ActivityFingerprint) -> f64 {
        let iki_sim = self.iki_distribution.similarity(&other.iki_distribution);
        let zone_sim = self.zone_profile.similarity(&other.zone_profile);
        let pause_sim = self.pause_signature.similarity(&other.pause_signature);

        // Weighted combination
        (iki_sim * 0.4 + zone_sim * 0.35 + pause_sim * 0.25).clamp(0.0, 1.0)
    }

    /// Update confidence based on sample count.
    fn update_confidence(&mut self) {
        // Confidence increases with samples, asymptotic to 1.0
        self.confidence = 1.0 - 1.0 / (1.0 + self.sample_count as f64 / 500.0);
    }
}

// =============================================================================
// IKI Distribution
// =============================================================================

/// Inter-Key Interval distribution statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IkiDistribution {
    /// Mean IKI in milliseconds
    pub mean: f64,
    /// Standard deviation
    pub std_dev: f64,
    /// Skewness (human typing is typically right-skewed)
    pub skewness: f64,
    /// Kurtosis (excess kurtosis, 0 = normal)
    pub kurtosis: f64,
    /// Percentiles (5th, 25th, 50th, 75th, 95th)
    pub percentiles: [f64; 5],
    /// Histogram buckets (50ms each)
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
    /// Create distribution from interval data.
    pub fn from_intervals(intervals: &[f64]) -> Self {
        if intervals.is_empty() {
            return Self::default();
        }

        let mean = intervals.to_vec().mean();
        let std_dev = intervals.to_vec().std_dev();

        // Calculate skewness and kurtosis
        let skewness = calculate_skewness(intervals, mean, std_dev);
        let kurtosis = calculate_kurtosis(intervals, mean, std_dev);

        // Calculate percentiles
        let mut sorted = intervals.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let percentiles = [
            percentile(&sorted, 0.05),
            percentile(&sorted, 0.25),
            percentile(&sorted, 0.50),
            percentile(&sorted, 0.75),
            percentile(&sorted, 0.95),
        ];

        // Build histogram
        let mut histogram = vec![0.0; IKI_HISTOGRAM_BUCKETS];
        for &iki in intervals {
            let bucket = ((iki / IKI_BUCKET_WIDTH_MS) as usize).min(IKI_HISTOGRAM_BUCKETS - 1);
            histogram[bucket] += 1.0;
        }
        // Normalize
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

    /// Merge with another distribution.
    pub fn merge(&mut self, other: &IkiDistribution, self_weight: f64, other_weight: f64) {
        self.mean = self.mean * self_weight + other.mean * other_weight;
        self.std_dev = self.std_dev * self_weight + other.std_dev * other_weight;
        self.skewness = self.skewness * self_weight + other.skewness * other_weight;
        self.kurtosis = self.kurtosis * self_weight + other.kurtosis * other_weight;

        for i in 0..5 {
            self.percentiles[i] =
                self.percentiles[i] * self_weight + other.percentiles[i] * other_weight;
        }

        for i in 0..self.histogram.len().min(other.histogram.len()) {
            self.histogram[i] = self.histogram[i] * self_weight + other.histogram[i] * other_weight;
        }
    }

    /// Calculate similarity with another distribution.
    pub fn similarity(&self, other: &IkiDistribution) -> f64 {
        // Use histogram intersection (Bhattacharyya coefficient approximation)
        let hist_sim: f64 = self
            .histogram
            .iter()
            .zip(other.histogram.iter())
            .map(|(a, b)| (a * b).sqrt())
            .sum();

        // Combine with statistical moments similarity
        let mean_sim = 1.0 - (self.mean - other.mean).abs() / (self.mean + other.mean + 1.0);
        let std_sim =
            1.0 - (self.std_dev - other.std_dev).abs() / (self.std_dev + other.std_dev + 1.0);

        (hist_sim * 0.6 + mean_sim * 0.2 + std_sim * 0.2).clamp(0.0, 1.0)
    }
}

// =============================================================================
// Zone Profile
// =============================================================================

/// Keyboard zone usage profile.
///
/// Zones represent keyboard regions typed by different fingers:
/// - Zone 0-3: Left hand (pinky to index)
/// - Zone 4-7: Right hand (index to pinky)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneProfile {
    /// Zone frequency distribution (normalized)
    pub zone_frequencies: [f64; 8],
    /// Zone transition matrix (normalized)
    pub zone_transitions: Vec<f64>,
    /// Same-finger digraph histogram
    pub same_finger_histogram: Vec<f64>,
    /// Same-hand digraph histogram
    pub same_hand_histogram: Vec<f64>,
    /// Alternating-hand digraph histogram
    pub alternating_histogram: Vec<f64>,
}

impl Default for ZoneProfile {
    fn default() -> Self {
        Self {
            zone_frequencies: [0.125; 8], // Uniform default
            zone_transitions: vec![0.0; ZONE_TRANSITIONS],
            same_finger_histogram: vec![0.0; 20],
            same_hand_histogram: vec![0.0; 20],
            alternating_histogram: vec![0.0; 20],
        }
    }
}

impl ZoneProfile {
    /// Create profile from samples.
    pub fn from_samples(samples: &[SimpleJitterSample]) -> Self {
        let mut profile = Self::default();

        if samples.is_empty() {
            return profile;
        }

        // Zone frequencies
        let mut zone_counts = [0usize; 8];
        for sample in samples {
            let zone = (sample.zone as usize).min(7);
            zone_counts[zone] += 1;
        }
        let total: usize = zone_counts.iter().sum();
        if total > 0 {
            for (i, &count) in zone_counts.iter().enumerate() {
                profile.zone_frequencies[i] = count as f64 / total as f64;
            }
        }

        // Zone transitions
        let mut transitions = vec![0usize; ZONE_TRANSITIONS];
        for w in samples.windows(2) {
            let from = (w[0].zone as usize).min(7);
            let to = (w[1].zone as usize).min(7);
            transitions[from * 8 + to] += 1;
        }
        let trans_total: usize = transitions.iter().sum();
        if trans_total > 0 {
            for (i, &count) in transitions.iter().enumerate() {
                profile.zone_transitions[i] = count as f64 / trans_total as f64;
            }
        }

        // Hand analysis histograms
        for w in samples.windows(2) {
            let z1 = w[0].zone as usize;
            let z2 = w[1].zone as usize;
            let iki_ms = (w[1].timestamp_ns - w[0].timestamp_ns) as f64 / 1_000_000.0;
            let bucket = ((iki_ms / 50.0) as usize).min(19);

            if z1 == z2 {
                // Same finger
                profile.same_finger_histogram[bucket] += 1.0;
            } else if (z1 < 4) == (z2 < 4) {
                // Same hand
                profile.same_hand_histogram[bucket] += 1.0;
            } else {
                // Alternating hands
                profile.alternating_histogram[bucket] += 1.0;
            }
        }

        // Normalize histograms
        normalize_histogram(&mut profile.same_finger_histogram);
        normalize_histogram(&mut profile.same_hand_histogram);
        normalize_histogram(&mut profile.alternating_histogram);

        profile
    }

    /// Merge with another profile.
    pub fn merge(&mut self, other: &ZoneProfile, self_weight: f64, other_weight: f64) {
        for i in 0..8 {
            self.zone_frequencies[i] =
                self.zone_frequencies[i] * self_weight + other.zone_frequencies[i] * other_weight;
        }

        for i in 0..self
            .zone_transitions
            .len()
            .min(other.zone_transitions.len())
        {
            self.zone_transitions[i] =
                self.zone_transitions[i] * self_weight + other.zone_transitions[i] * other_weight;
        }

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

    /// Get the dominant zone (most frequently used).
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

    /// Calculate similarity with another profile.
    pub fn similarity(&self, other: &ZoneProfile) -> f64 {
        // Zone frequency similarity
        let freq_sim: f64 = self
            .zone_frequencies
            .iter()
            .zip(other.zone_frequencies.iter())
            .map(|(a, b)| 1.0 - (a - b).abs())
            .sum::<f64>()
            / 8.0;

        // Transition matrix similarity (histogram intersection)
        let trans_sim: f64 = self
            .zone_transitions
            .iter()
            .zip(other.zone_transitions.iter())
            .map(|(a, b)| a.min(*b))
            .sum();

        (freq_sim * 0.4 + trans_sim * 0.6).clamp(0.0, 1.0)
    }
}

// =============================================================================
// Pause Signature
// =============================================================================

/// Characteristic pause patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PauseSignature {
    /// Mean sentence pause duration (400-1000ms)
    pub sentence_pause_mean: f64,
    /// Mean paragraph pause duration (1000-2000ms)
    pub paragraph_pause_mean: f64,
    /// Mean thinking pause duration (>2000ms)
    pub thinking_pause_mean: f64,
    /// Frequency of sentence pauses (per 100 keystrokes)
    pub sentence_pause_frequency: f64,
    /// Frequency of paragraph pauses
    pub paragraph_pause_frequency: f64,
    /// Frequency of thinking pauses
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
    /// Create signature from interval data.
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
            sentence_pause_mean: mean_or_zero(&sentence_pauses),
            paragraph_pause_mean: mean_or_zero(&paragraph_pauses),
            thinking_pause_mean: mean_or_zero(&thinking_pauses),
            sentence_pause_frequency: sentence_pauses.len() as f64 * per_100,
            paragraph_pause_frequency: paragraph_pauses.len() as f64 * per_100,
            thinking_pause_frequency: thinking_pauses.len() as f64 * per_100,
        }
    }

    /// Merge with another signature.
    pub fn merge(&mut self, other: &PauseSignature, self_weight: f64, other_weight: f64) {
        self.sentence_pause_mean =
            self.sentence_pause_mean * self_weight + other.sentence_pause_mean * other_weight;
        self.paragraph_pause_mean =
            self.paragraph_pause_mean * self_weight + other.paragraph_pause_mean * other_weight;
        self.thinking_pause_mean =
            self.thinking_pause_mean * self_weight + other.thinking_pause_mean * other_weight;
        self.sentence_pause_frequency = self.sentence_pause_frequency * self_weight
            + other.sentence_pause_frequency * other_weight;
        self.paragraph_pause_frequency = self.paragraph_pause_frequency * self_weight
            + other.paragraph_pause_frequency * other_weight;
        self.thinking_pause_frequency = self.thinking_pause_frequency * self_weight
            + other.thinking_pause_frequency * other_weight;
    }

    /// Calculate similarity with another signature.
    pub fn similarity(&self, other: &PauseSignature) -> f64 {
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
}

// =============================================================================
// Circadian Pattern
// =============================================================================

/// Typing activity pattern by time of day.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircadianPattern {
    /// Activity level by hour (0-23)
    pub hourly_activity: [f64; 24],
    /// Total samples for this pattern
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
    /// Record activity for a given hour.
    pub fn record(&mut self, hour: u8) {
        if hour < 24 {
            self.hourly_activity[hour as usize] += 1.0;
            self.total_samples += 1;
        }
    }

    /// Normalize the pattern.
    pub fn normalize(&mut self) {
        let total: f64 = self.hourly_activity.iter().sum();
        if total > 0.0 {
            for h in &mut self.hourly_activity {
                *h /= total;
            }
        }
    }

    /// Merge with another pattern.
    pub fn merge(&mut self, other: &CircadianPattern) {
        for i in 0..24 {
            self.hourly_activity[i] += other.hourly_activity[i];
        }
        self.total_samples += other.total_samples;
    }
}

// =============================================================================
// Session Signature
// =============================================================================

/// Session-level typing characteristics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSignature {
    /// Mean session duration in seconds
    pub mean_session_duration: f64,
    /// Mean typing speed (keystrokes per minute)
    pub mean_typing_speed: f64,
    /// Fatigue indicator (speed change over session)
    pub fatigue_coefficient: f64,
    /// Number of sessions analyzed
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
    /// Merge with another signature.
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

// =============================================================================
// Activity Fingerprint Accumulator
// =============================================================================

/// Accumulator for building activity fingerprints from streaming samples.
pub struct ActivityFingerprintAccumulator {
    samples: VecDeque<SimpleJitterSample>,
    max_samples: usize,
    current_fingerprint: ActivityFingerprint,
    dirty: bool,
}

impl ActivityFingerprintAccumulator {
    /// Create a new accumulator.
    pub fn new() -> Self {
        Self::with_capacity(10000)
    }

    /// Create with specific capacity.
    pub fn with_capacity(max_samples: usize) -> Self {
        Self {
            samples: VecDeque::with_capacity(max_samples),
            max_samples,
            current_fingerprint: ActivityFingerprint::default(),
            dirty: false,
        }
    }

    /// Add a sample to the accumulator.
    pub fn add_sample(&mut self, sample: &SimpleJitterSample) {
        if self.samples.len() >= self.max_samples {
            self.samples.pop_front();
        }
        self.samples.push_back(sample.clone());
        self.dirty = true;
    }

    /// Get the current fingerprint.
    pub fn current_fingerprint(&self) -> ActivityFingerprint {
        if self.dirty || self.current_fingerprint.sample_count == 0 {
            let samples: Vec<_> = self.samples.iter().cloned().collect();
            ActivityFingerprint::from_samples(&samples)
        } else {
            self.current_fingerprint.clone()
        }
    }

    /// Get the number of samples in the accumulator.
    pub fn sample_count(&self) -> usize {
        self.samples.len()
    }

    /// Reset the accumulator.
    pub fn reset(&mut self) {
        self.samples.clear();
        self.current_fingerprint = ActivityFingerprint::default();
        self.dirty = false;
    }
}

impl Default for ActivityFingerprintAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

fn calculate_skewness(data: &[f64], mean: f64, std: f64) -> f64 {
    if std == 0.0 || data.is_empty() {
        return 0.0;
    }
    let n = data.len() as f64;
    let sum_cubed: f64 = data.iter().map(|&x| ((x - mean) / std).powi(3)).sum();
    sum_cubed / n
}

fn calculate_kurtosis(data: &[f64], mean: f64, std: f64) -> f64 {
    if std == 0.0 || data.is_empty() {
        return 0.0;
    }
    let n = data.len() as f64;
    let sum_fourth: f64 = data.iter().map(|&x| ((x - mean) / std).powi(4)).sum();
    sum_fourth / n - 3.0 // Excess kurtosis
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let index = (p * (sorted.len() - 1) as f64).round() as usize;
    sorted[index.min(sorted.len() - 1)]
}

fn normalize_histogram(hist: &mut [f64]) {
    let total: f64 = hist.iter().sum();
    if total > 0.0 {
        for h in hist {
            *h /= total;
        }
    }
}

fn merge_histogram(a: &mut [f64], b: &[f64], a_weight: f64, b_weight: f64) {
    for i in 0..a.len().min(b.len()) {
        a[i] = a[i] * a_weight + b[i] * b_weight;
    }
}

fn mean_or_zero(data: &[f64]) -> f64 {
    if data.is_empty() {
        0.0
    } else {
        data.iter().sum::<f64>() / data.len() as f64
    }
}

fn relative_similarity(a: f64, b: f64) -> f64 {
    if a == 0.0 && b == 0.0 {
        1.0
    } else {
        1.0 - (a - b).abs() / (a + b + 0.001)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_samples(intervals_ms: &[i64]) -> Vec<SimpleJitterSample> {
        let mut samples = Vec::new();
        let mut ts = 0i64;

        for (i, &interval) in intervals_ms.iter().enumerate() {
            samples.push(SimpleJitterSample {
                timestamp_ns: ts,
                duration_since_last_ns: if i == 0 {
                    0
                } else {
                    interval as u64 * 1_000_000
                },
                zone: (i % 8) as u8,
            });
            ts += interval * 1_000_000;
        }

        samples
    }

    #[test]
    fn test_activity_fingerprint_creation() {
        let samples = make_samples(&[0, 150, 200, 180, 220, 190, 210, 175, 195, 185]);
        let fp = ActivityFingerprint::from_samples(&samples);

        assert!(fp.iki_distribution.mean > 0.0);
        assert!(fp.sample_count > 0);
    }

    #[test]
    fn test_fingerprint_similarity() {
        let samples1 = make_samples(&[0, 150, 200, 180, 220, 190, 210, 175, 195, 185]);
        let samples2 = make_samples(&[0, 155, 195, 185, 215, 195, 205, 180, 190, 190]);
        let samples3 = make_samples(&[0, 50, 50, 50, 50, 50, 50, 50, 50, 50]); // Very different

        let fp1 = ActivityFingerprint::from_samples(&samples1);
        let fp2 = ActivityFingerprint::from_samples(&samples2);
        let fp3 = ActivityFingerprint::from_samples(&samples3);

        // Similar patterns should have high similarity
        let sim12 = fp1.similarity(&fp2);
        // Different patterns should have lower similarity
        let sim13 = fp1.similarity(&fp3);

        assert!(sim12 > sim13, "Similar patterns should be more similar");
    }

    #[test]
    fn test_iki_distribution() {
        let intervals = vec![100.0, 150.0, 200.0, 180.0, 120.0];
        let dist = IkiDistribution::from_intervals(&intervals);

        assert!(dist.mean > 0.0);
        assert!(dist.std_dev > 0.0);
    }

    #[test]
    fn test_accumulator() {
        let mut acc = ActivityFingerprintAccumulator::new();

        for i in 0..100 {
            acc.add_sample(&SimpleJitterSample {
                timestamp_ns: i * 200_000_000,
                duration_since_last_ns: 200_000_000,
                zone: (i % 8) as u8,
            });
        }

        assert_eq!(acc.sample_count(), 100);
        let fp = acc.current_fingerprint();
        assert!(fp.sample_count > 0);
    }
}
