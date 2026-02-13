//! Forensic authorship analysis module.
//!
//! Provides comprehensive analysis capabilities for detecting AI-generated content
//! and verifying human authorship through edit topology analysis, keystroke cadence
//! analysis, and profile correlation.

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use statrs::distribution::{ContinuousCDF, Normal};
use statrs::statistics::{Data, OrderStatistics};
use std::collections::HashMap;
use std::fmt;

use crate::analysis::{BehavioralFingerprint, ForgeryAnalysis};
use crate::jitter::SimpleJitterSample;
use crate::PhysicalContext;

// =============================================================================
// Constants
// =============================================================================

/// Default threshold for considering an edit as an "append" (at 95% of document).
pub const DEFAULT_APPEND_THRESHOLD: f32 = 0.95;

/// Default number of bins for edit entropy histogram.
pub const DEFAULT_HISTOGRAM_BINS: usize = 20;

/// Minimum events required for stable analysis.
pub const MIN_EVENTS_FOR_ANALYSIS: usize = 5;

/// Minimum events for assessment verdict.
pub const MIN_EVENTS_FOR_ASSESSMENT: usize = 10;

/// Default session gap threshold in seconds (30 minutes).
pub const DEFAULT_SESSION_GAP_SEC: f64 = 1800.0;

/// High monotonic append ratio threshold (suggests AI generation).
pub const THRESHOLD_MONOTONIC_APPEND: f64 = 0.85;

/// Low entropy threshold (suggests non-human editing).
pub const THRESHOLD_LOW_ENTROPY: f64 = 1.5;

/// High velocity threshold in bytes per second.
pub const THRESHOLD_HIGH_VELOCITY_BPS: f64 = 100.0;

/// Long gap threshold in hours.
pub const THRESHOLD_GAP_HOURS: f64 = 24.0;

/// Alert threshold for suspicious assessment.
pub const ALERT_THRESHOLD: usize = 2;

/// Coefficient of variation threshold for robotic typing detection.
pub const ROBOTIC_CV_THRESHOLD: f64 = 0.15;

/// Default edit ratio estimate (15% of keystrokes are deletions).
pub const DEFAULT_EDIT_RATIO: f64 = 0.15;

/// Suspicious discrepancy ratio threshold.
pub const SUSPICIOUS_RATIO_THRESHOLD: f64 = 0.3;

/// Inconsistent discrepancy ratio threshold.
pub const INCONSISTENT_RATIO_THRESHOLD: f64 = 0.5;

// =============================================================================
// Core Data Types
// =============================================================================

/// Minimal event data for forensic analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventData {
    pub id: i64,
    pub timestamp_ns: i64,
    pub file_size: i64,
    pub size_delta: i32,
    pub file_path: String,
}

/// Edit region data for topology analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionData {
    /// Start position as percentage of document (0.0 - 1.0).
    pub start_pct: f32,
    /// End position as percentage of document (0.0 - 1.0).
    pub end_pct: f32,
    /// Delta sign: +1 insertion, -1 deletion, 0 replacement.
    pub delta_sign: i8,
    /// Number of bytes affected.
    pub byte_count: i32,
}

/// Primary forensic metrics for authorship detection.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PrimaryMetrics {
    /// Fraction of edits at end of document (>0.95 position).
    pub monotonic_append_ratio: f64,
    /// Shannon entropy of edit position histogram (20 bins).
    pub edit_entropy: f64,
    /// Median inter-event interval in seconds.
    pub median_interval: f64,
    /// Insertions / (insertions + deletions).
    pub positive_negative_ratio: f64,
    /// Nearest-neighbor ratio for deletions.
    pub deletion_clustering: f64,
}

/// Keystroke cadence metrics for typing pattern analysis.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CadenceMetrics {
    /// Mean inter-keystroke interval in nanoseconds.
    pub mean_iki_ns: f64,
    /// Standard deviation of IKI in nanoseconds.
    pub std_dev_iki_ns: f64,
    /// Coefficient of variation (std_dev / mean).
    pub coefficient_of_variation: f64,
    /// Median IKI in nanoseconds.
    pub median_iki_ns: f64,
    /// Number of detected typing bursts.
    pub burst_count: usize,
    /// Number of detected pauses (>2 seconds).
    pub pause_count: usize,
    /// Average burst length in keystrokes.
    pub avg_burst_length: f64,
    /// Average pause duration in nanoseconds.
    pub avg_pause_duration_ns: f64,
    /// Whether pattern suggests robotic/synthetic typing.
    pub is_robotic: bool,
    /// Percentile distribution of IKIs (10th, 25th, 50th, 75th, 90th).
    pub percentiles: [f64; 5],
}

/// Complete forensic metrics combining all analysis dimensions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ForensicMetrics {
    /// Primary edit topology metrics.
    pub primary: PrimaryMetrics,
    /// Keystroke cadence metrics.
    pub cadence: CadenceMetrics,
    /// Behavioral fingerprint analysis.
    pub behavioral: Option<BehavioralFingerprint>,
    /// Forgery detection results.
    pub forgery_analysis: Option<ForgeryAnalysis>,
    /// Edit velocity metrics.
    pub velocity: VelocityMetrics,
    /// Session-level statistics.
    pub session_stats: SessionStats,
    /// Overall assessment score (0.0 - 1.0, higher = more human-like).
    pub assessment_score: f64,
    /// Steganographic confidence (validity of timing modulation).
    pub steg_confidence: f64,
    /// Number of detected anomalies.
    pub anomaly_count: usize,
    /// Risk level classification.
    pub risk_level: RiskLevel,
}

/// Edit velocity metrics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VelocityMetrics {
    /// Mean bytes per second.
    pub mean_bps: f64,
    /// Maximum bytes per second observed.
    pub max_bps: f64,
    /// Number of high-velocity bursts detected.
    pub high_velocity_bursts: usize,
    /// Estimated autocomplete characters.
    pub autocomplete_chars: i64,
}

/// Session-level statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionStats {
    /// Total number of editing sessions detected.
    pub session_count: usize,
    /// Average session duration in seconds.
    pub avg_session_duration_sec: f64,
    /// Total editing time in seconds.
    pub total_editing_time_sec: f64,
    /// Time between first and last event in seconds.
    pub time_span_sec: f64,
}

/// Risk level classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum RiskLevel {
    /// Low risk - consistent with human authorship.
    #[default]
    Low,
    /// Medium risk - some suspicious patterns.
    Medium,
    /// High risk - likely AI-generated or suspicious activity.
    High,
    /// Insufficient data for assessment.
    Insufficient,
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RiskLevel::Low => write!(f, "LOW"),
            RiskLevel::Medium => write!(f, "MEDIUM"),
            RiskLevel::High => write!(f, "HIGH"),
            RiskLevel::Insufficient => write!(f, "INSUFFICIENT DATA"),
        }
    }
}

// =============================================================================
// Authorship Profile
// =============================================================================

/// Complete authorship analysis profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorshipProfile {
    pub file_path: String,
    pub event_count: usize,
    pub time_span: ChronoDuration,
    pub session_count: usize,
    pub first_event: DateTime<Utc>,
    pub last_event: DateTime<Utc>,
    pub metrics: PrimaryMetrics,
    pub anomalies: Vec<Anomaly>,
    pub assessment: Assessment,
}

impl Default for AuthorshipProfile {
    fn default() -> Self {
        Self {
            file_path: String::new(),
            event_count: 0,
            time_span: ChronoDuration::zero(),
            session_count: 0,
            first_event: Utc::now(),
            last_event: Utc::now(),
            metrics: PrimaryMetrics::default(),
            anomalies: Vec::new(),
            assessment: Assessment::Insufficient,
        }
    }
}

/// Detected anomaly in editing patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anomaly {
    pub timestamp: Option<DateTime<Utc>>,
    pub anomaly_type: AnomalyType,
    pub description: String,
    pub severity: Severity,
    pub context: Option<String>,
}

/// Types of anomalies that can be detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnomalyType {
    /// Long gap between edits.
    Gap,
    /// High-velocity content addition.
    HighVelocity,
    /// High monotonic append pattern.
    MonotonicAppend,
    /// Low edit entropy.
    LowEntropy,
    /// Robotic keystroke cadence.
    RoboticCadence,
    /// Undetected paste operation.
    UndetectedPaste,
    /// Content-keystroke mismatch.
    ContentMismatch,
    /// Scattered deletion pattern.
    ScatteredDeletions,
}

impl fmt::Display for AnomalyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AnomalyType::Gap => write!(f, "gap"),
            AnomalyType::HighVelocity => write!(f, "high_velocity"),
            AnomalyType::MonotonicAppend => write!(f, "monotonic_append"),
            AnomalyType::LowEntropy => write!(f, "low_entropy"),
            AnomalyType::RoboticCadence => write!(f, "robotic_cadence"),
            AnomalyType::UndetectedPaste => write!(f, "undetected_paste"),
            AnomalyType::ContentMismatch => write!(f, "content_mismatch"),
            AnomalyType::ScatteredDeletions => write!(f, "scattered_deletions"),
        }
    }
}

/// Severity level for anomalies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Warning,
    Alert,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Info => write!(f, "info"),
            Severity::Warning => write!(f, "warning"),
            Severity::Alert => write!(f, "alert"),
        }
    }
}

/// Overall assessment verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Assessment {
    /// Consistent with human authorship.
    Consistent,
    /// Suspicious patterns detected.
    Suspicious,
    /// Insufficient data for assessment.
    #[default]
    Insufficient,
}

impl fmt::Display for Assessment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Assessment::Consistent => write!(f, "CONSISTENT WITH HUMAN AUTHORSHIP"),
            Assessment::Suspicious => write!(f, "SUSPICIOUS PATTERNS DETECTED"),
            Assessment::Insufficient => write!(f, "INSUFFICIENT DATA"),
        }
    }
}

// =============================================================================
// Edit Topology Analysis
// =============================================================================

/// Computes all primary metrics from events and regions.
pub fn compute_primary_metrics(
    events: &[EventData],
    regions: &HashMap<i64, Vec<RegionData>>,
) -> Result<PrimaryMetrics, ForensicsError> {
    if events.len() < MIN_EVENTS_FOR_ANALYSIS {
        return Err(ForensicsError::InsufficientData);
    }

    let all_regions = flatten_regions(regions);
    if all_regions.is_empty() {
        return Err(ForensicsError::InsufficientData);
    }

    Ok(PrimaryMetrics {
        monotonic_append_ratio: monotonic_append_ratio(&all_regions, DEFAULT_APPEND_THRESHOLD),
        edit_entropy: edit_entropy(&all_regions, DEFAULT_HISTOGRAM_BINS),
        median_interval: median_interval(events),
        positive_negative_ratio: positive_negative_ratio(&all_regions),
        deletion_clustering: deletion_clustering_coef(&all_regions),
    })
}

/// Calculates the fraction of edits at document end.
///
/// Formula: |{r : r.start_pct >= threshold}| / |R|
pub fn monotonic_append_ratio(regions: &[RegionData], threshold: f32) -> f64 {
    if regions.is_empty() {
        return 0.0;
    }

    let append_count = regions.iter().filter(|r| r.start_pct >= threshold).count();
    append_count as f64 / regions.len() as f64
}

/// Calculates Shannon entropy of edit position histogram.
///
/// Formula: H = -sum (c_j/n) * log2(c_j/n) for non-zero bins
pub fn edit_entropy(regions: &[RegionData], bins: usize) -> f64 {
    if regions.is_empty() || bins == 0 {
        return 0.0;
    }

    // Build histogram of edit positions
    let mut histogram = vec![0usize; bins];
    for r in regions {
        let mut pos = r.start_pct;
        if pos < 0.0 {
            pos = 0.0;
        }
        if pos >= 1.0 {
            pos = 0.9999;
        }
        let bin_idx = (pos * bins as f32) as usize;
        let bin_idx = bin_idx.min(bins - 1);
        histogram[bin_idx] += 1;
    }

    shannon_entropy(&histogram)
}

/// Calculates Shannon entropy from a histogram.
fn shannon_entropy(histogram: &[usize]) -> f64 {
    let n: usize = histogram.iter().sum();
    if n == 0 {
        return 0.0;
    }

    let n_float = n as f64;
    let mut entropy = 0.0;
    for &count in histogram {
        if count > 0 {
            let p = count as f64 / n_float;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Calculates the median inter-event interval in seconds.
pub fn median_interval(events: &[EventData]) -> f64 {
    if events.len() < 2 {
        return 0.0;
    }

    // Sort events by timestamp
    let mut sorted: Vec<_> = events.to_vec();
    sorted.sort_by_key(|e| e.timestamp_ns);

    // Calculate intervals
    let intervals: Vec<f64> = sorted
        .windows(2)
        .map(|w| (w[1].timestamp_ns - w[0].timestamp_ns) as f64 / 1e9)
        .collect();

    compute_median(&intervals)
}

/// Computes the median of a slice of values.
fn compute_median(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }

    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let n = sorted.len();
    if n.is_multiple_of(2) {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
    } else {
        sorted[n / 2]
    }
}

/// Calculates insertions / (insertions + deletions).
///
/// Formula: |{r : r.delta_sign > 0}| / |{r : r.delta_sign != 0}|
pub fn positive_negative_ratio(regions: &[RegionData]) -> f64 {
    let mut insertions = 0;
    let mut total = 0;

    for r in regions {
        if r.delta_sign > 0 {
            insertions += 1;
            total += 1;
        } else if r.delta_sign < 0 {
            total += 1;
        }
        // delta_sign == 0 are replacements without size change, excluded
    }

    if total == 0 {
        return 0.5; // Neutral when no insertions or deletions
    }

    insertions as f64 / total as f64
}

/// Calculates the nearest-neighbor ratio for deletions.
///
/// Clustered deletions (revision pass) produce < 1.
/// Scattered deletions (fake) produce ~ 1.
/// No deletions produces 0.
pub fn deletion_clustering_coef(regions: &[RegionData]) -> f64 {
    // Extract deletion positions
    let mut deletion_positions: Vec<f64> = regions
        .iter()
        .filter(|r| r.delta_sign < 0)
        .map(|r| r.start_pct as f64)
        .collect();

    let n = deletion_positions.len();
    if n < 2 {
        return 0.0;
    }

    // Sort positions
    deletion_positions.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    // Calculate nearest-neighbor distances
    let mut total_dist = 0.0;
    for i in 0..n {
        let mut min_dist = f64::MAX;

        // Check left neighbor
        if i > 0 {
            let dist = deletion_positions[i] - deletion_positions[i - 1];
            if dist < min_dist {
                min_dist = dist;
            }
        }

        // Check right neighbor
        if i < n - 1 {
            let dist = deletion_positions[i + 1] - deletion_positions[i];
            if dist < min_dist {
                min_dist = dist;
            }
        }

        total_dist += min_dist;
    }

    let mean_dist = total_dist / n as f64;

    // Expected uniform distance for n points in [0,1]
    let expected_uniform_dist = 1.0 / (n + 1) as f64;

    if expected_uniform_dist == 0.0 {
        return 0.0;
    }

    mean_dist / expected_uniform_dist
}

/// Flattens regions from a map into a single slice.
fn flatten_regions(regions: &HashMap<i64, Vec<RegionData>>) -> Vec<RegionData> {
    regions.values().flat_map(|rs| rs.iter().cloned()).collect()
}

// =============================================================================
// Keystroke Cadence Analysis
// =============================================================================

/// Analyzes keystroke cadence from jitter samples.
pub fn analyze_cadence(samples: &[SimpleJitterSample]) -> CadenceMetrics {
    let mut metrics = CadenceMetrics::default();

    if samples.len() < 2 {
        return metrics;
    }

    // Calculate inter-keystroke intervals
    let ikis: Vec<f64> = samples
        .windows(2)
        .map(|w| (w[1].timestamp_ns - w[0].timestamp_ns) as f64)
        .collect();

    if ikis.is_empty() {
        return metrics;
    }

    // Basic statistics
    let sum: f64 = ikis.iter().sum();
    metrics.mean_iki_ns = sum / ikis.len() as f64;

    let variance: f64 = ikis
        .iter()
        .map(|x| (x - metrics.mean_iki_ns).powi(2))
        .sum::<f64>()
        / ikis.len() as f64;
    metrics.std_dev_iki_ns = variance.sqrt();

    // Coefficient of variation
    if metrics.mean_iki_ns > 0.0 {
        metrics.coefficient_of_variation = metrics.std_dev_iki_ns / metrics.mean_iki_ns;
    }

    // Median
    metrics.median_iki_ns = compute_median(&ikis);

    // Percentiles using statrs
    let mut data = Data::new(ikis.clone());
    metrics.percentiles = [
        data.percentile(10),
        data.percentile(25),
        data.percentile(50),
        data.percentile(75),
        data.percentile(90),
    ];

    // Detect robotic patterns
    metrics.is_robotic = metrics.coefficient_of_variation < ROBOTIC_CV_THRESHOLD;

    // Burst and pause detection
    let (bursts, pauses) = detect_bursts_and_pauses(&ikis);
    metrics.burst_count = bursts.len();
    metrics.pause_count = pauses.len();

    if !bursts.is_empty() {
        metrics.avg_burst_length =
            bursts.iter().map(|b| b.length as f64).sum::<f64>() / bursts.len() as f64;
    }

    if !pauses.is_empty() {
        metrics.avg_pause_duration_ns = pauses.iter().sum::<f64>() / pauses.len() as f64;
    }

    metrics
}

/// Detected typing burst.
#[derive(Debug, Clone)]
pub struct TypingBurst {
    pub start_idx: usize,
    pub length: usize,
    pub avg_iki_ns: f64,
}

/// Detects typing bursts and pauses in IKI sequence.
///
/// A burst is a sequence of fast keystrokes (< 200ms between each).
/// A pause is an interval > 2 seconds.
fn detect_bursts_and_pauses(ikis: &[f64]) -> (Vec<TypingBurst>, Vec<f64>) {
    const BURST_THRESHOLD_NS: f64 = 200_000_000.0; // 200ms
    const PAUSE_THRESHOLD_NS: f64 = 2_000_000_000.0; // 2 seconds

    let mut bursts = Vec::new();
    let mut pauses = Vec::new();

    let mut burst_start: Option<usize> = None;
    let mut burst_sum = 0.0;

    for (i, &iki) in ikis.iter().enumerate() {
        if iki < BURST_THRESHOLD_NS {
            if burst_start.is_none() {
                burst_start = Some(i);
                burst_sum = 0.0;
            }
            burst_sum += iki;
        } else {
            // End current burst if any
            if let Some(start) = burst_start {
                let length = i - start;
                if length >= 3 {
                    // Minimum burst length
                    bursts.push(TypingBurst {
                        start_idx: start,
                        length,
                        avg_iki_ns: burst_sum / length as f64,
                    });
                }
                burst_start = None;
            }

            // Check for pause
            if iki > PAUSE_THRESHOLD_NS {
                pauses.push(iki);
            }
        }
    }

    // Close final burst if any
    if let Some(start) = burst_start {
        let length = ikis.len() - start;
        if length >= 3 {
            bursts.push(TypingBurst {
                start_idx: start,
                length,
                avg_iki_ns: burst_sum / length as f64,
            });
        }
    }

    (bursts, pauses)
}

/// Evaluates whether keystrokes suggest retyped/transcribed content.
///
/// Returns true if the cadence pattern is too rhythmic to be original composition.
pub fn is_retyped_content(samples: &[SimpleJitterSample]) -> bool {
    if samples.len() < 20 {
        return false;
    }

    let ikis: Vec<f64> = samples
        .windows(2)
        .map(|w| (w[1].timestamp_ns - w[0].timestamp_ns) as f64)
        .collect();

    let mean = ikis.iter().sum::<f64>() / ikis.len() as f64;
    let variance = ikis.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / ikis.len() as f64;
    let std_dev = variance.sqrt();

    if mean <= 0.0 {
        return false;
    }

    let cv = std_dev / mean;
    cv < ROBOTIC_CV_THRESHOLD
}

// =============================================================================
// Velocity Analysis
// =============================================================================

/// Analyzes edit velocity patterns.
pub fn analyze_velocity(events: &[EventData]) -> VelocityMetrics {
    let mut metrics = VelocityMetrics::default();

    if events.len() < 2 {
        return metrics;
    }

    let mut sorted = events.to_vec();
    sorted.sort_by_key(|e| e.timestamp_ns);

    let mut velocities = Vec::new();
    let mut high_velocity_bursts = 0;
    let mut autocomplete_chars: i64 = 0;

    for window in sorted.windows(2) {
        let delta_ns = window[1].timestamp_ns - window[0].timestamp_ns;
        let delta_sec = delta_ns as f64 / 1e9;

        if delta_sec > 0.0 && delta_sec < 60.0 {
            let bytes_delta = window[1].size_delta.abs() as f64;
            let bps = bytes_delta / delta_sec;
            velocities.push(bps);

            if bps > THRESHOLD_HIGH_VELOCITY_BPS {
                high_velocity_bursts += 1;

                // Estimate autocomplete chars: excess over human typing speed (~50 chars/sec)
                let human_max_bps = 50.0;
                if bps > human_max_bps {
                    let excess = (bps - human_max_bps) * delta_sec;
                    autocomplete_chars += excess as i64;
                }
            }
        }
    }

    if !velocities.is_empty() {
        metrics.mean_bps = velocities.iter().sum::<f64>() / velocities.len() as f64;
        metrics.max_bps = velocities.iter().cloned().fold(0.0, f64::max);
    }

    metrics.high_velocity_bursts = high_velocity_bursts;
    metrics.autocomplete_chars = autocomplete_chars;

    metrics
}

// =============================================================================
// Session Detection
// =============================================================================

/// Detects editing sessions based on gap threshold.
pub fn detect_sessions(events: &[EventData], gap_threshold_sec: f64) -> Vec<Vec<EventData>> {
    if events.is_empty() {
        return Vec::new();
    }

    let mut sorted = events.to_vec();
    sorted.sort_by_key(|e| e.timestamp_ns);

    let mut sessions = Vec::new();
    let mut current_session = vec![sorted[0].clone()];

    for window in sorted.windows(2) {
        let delta_ns = window[1].timestamp_ns - window[0].timestamp_ns;
        let delta_sec = delta_ns as f64 / 1e9;

        if delta_sec > gap_threshold_sec {
            sessions.push(std::mem::take(&mut current_session));
            current_session = vec![window[1].clone()];
        } else {
            current_session.push(window[1].clone());
        }
    }

    if !current_session.is_empty() {
        sessions.push(current_session);
    }

    sessions
}

/// Computes session statistics.
pub fn compute_session_stats(events: &[EventData]) -> SessionStats {
    let mut stats = SessionStats::default();

    if events.is_empty() {
        return stats;
    }

    let sessions = detect_sessions(events, DEFAULT_SESSION_GAP_SEC);
    stats.session_count = sessions.len();

    let mut total_duration = 0.0;
    for session in &sessions {
        if session.len() >= 2 {
            let first = session.iter().map(|e| e.timestamp_ns).min().unwrap_or(0);
            let last = session.iter().map(|e| e.timestamp_ns).max().unwrap_or(0);
            total_duration += (last - first) as f64 / 1e9;
        }
    }

    stats.total_editing_time_sec = total_duration;
    if stats.session_count > 0 {
        stats.avg_session_duration_sec = total_duration / stats.session_count as f64;
    }

    // Time span
    let first = events.iter().map(|e| e.timestamp_ns).min().unwrap_or(0);
    let last = events.iter().map(|e| e.timestamp_ns).max().unwrap_or(0);
    stats.time_span_sec = (last - first) as f64 / 1e9;

    stats
}

// =============================================================================
// Anomaly Detection
// =============================================================================

/// Detects anomalies in editing patterns.
pub fn detect_anomalies(
    events: &[EventData],
    regions: &HashMap<i64, Vec<RegionData>>,
    metrics: &PrimaryMetrics,
) -> Vec<Anomaly> {
    let mut anomalies = Vec::new();

    // Check for high monotonic append ratio
    if metrics.monotonic_append_ratio > THRESHOLD_MONOTONIC_APPEND {
        anomalies.push(Anomaly {
            timestamp: None,
            anomaly_type: AnomalyType::MonotonicAppend,
            description: "High monotonic append ratio suggests sequential content generation"
                .to_string(),
            severity: Severity::Warning,
            context: Some(format!(
                "Ratio: {:.2}%",
                metrics.monotonic_append_ratio * 100.0
            )),
        });
    }

    // Check for low edit entropy
    if metrics.edit_entropy < THRESHOLD_LOW_ENTROPY && metrics.edit_entropy > 0.0 {
        anomalies.push(Anomaly {
            timestamp: None,
            anomaly_type: AnomalyType::LowEntropy,
            description: "Low edit entropy indicates concentrated editing patterns".to_string(),
            severity: Severity::Warning,
            context: Some(format!("Entropy: {:.3}", metrics.edit_entropy)),
        });
    }

    // Check for scattered deletions
    if metrics.deletion_clustering > 0.9 && metrics.deletion_clustering < 1.1 {
        anomalies.push(Anomaly {
            timestamp: None,
            anomaly_type: AnomalyType::ScatteredDeletions,
            description: "Scattered deletion pattern suggests artificial editing".to_string(),
            severity: Severity::Warning,
            context: Some(format!(
                "Clustering coef: {:.3}",
                metrics.deletion_clustering
            )),
        });
    }

    // Detect temporal anomalies
    anomalies.extend(detect_temporal_anomalies(events, regions));

    anomalies
}

/// Detects gaps and high-velocity editing periods.
fn detect_temporal_anomalies(
    events: &[EventData],
    _regions: &HashMap<i64, Vec<RegionData>>,
) -> Vec<Anomaly> {
    let mut anomalies = Vec::new();

    if events.len() < 2 {
        return anomalies;
    }

    let mut sorted = events.to_vec();
    sorted.sort_by_key(|e| e.timestamp_ns);

    for window in sorted.windows(2) {
        let prev = &window[0];
        let curr = &window[1];

        let delta_ns = curr.timestamp_ns - prev.timestamp_ns;
        let delta_sec = delta_ns as f64 / 1e9;
        let delta_hours = delta_sec / 3600.0;

        // Check for long gaps
        if delta_hours > THRESHOLD_GAP_HOURS {
            anomalies.push(Anomaly {
                timestamp: Some(DateTime::from_timestamp_nanos(curr.timestamp_ns)),
                anomaly_type: AnomalyType::Gap,
                description: "Long editing gap detected".to_string(),
                severity: Severity::Info,
                context: Some(format!("Gap: {:.1} hours", delta_hours)),
            });
        }

        // Check for high-velocity editing
        if delta_sec > 0.0 && delta_sec < 60.0 {
            let bytes_delta = curr.size_delta.abs();
            let bytes_per_sec = bytes_delta as f64 / delta_sec;
            if bytes_per_sec > THRESHOLD_HIGH_VELOCITY_BPS {
                anomalies.push(Anomaly {
                    timestamp: Some(DateTime::from_timestamp_nanos(curr.timestamp_ns)),
                    anomaly_type: AnomalyType::HighVelocity,
                    description: "High-velocity content addition detected".to_string(),
                    severity: Severity::Warning,
                    context: Some(format!("Velocity: {:.1} bytes/sec", bytes_per_sec)),
                });
            }
        }
    }

    anomalies
}

// =============================================================================
// Assessment
// =============================================================================

/// Determines overall assessment verdict.
pub fn determine_assessment(
    metrics: &PrimaryMetrics,
    anomalies: &[Anomaly],
    event_count: usize,
) -> Assessment {
    if event_count < MIN_EVENTS_FOR_ASSESSMENT {
        return Assessment::Insufficient;
    }

    // Count alerts
    let alert_count = anomalies
        .iter()
        .filter(|a| a.severity == Severity::Alert)
        .count();
    let warning_count = anomalies
        .iter()
        .filter(|a| a.severity == Severity::Warning)
        .count();

    // Count suspicious indicators
    let mut suspicious_indicators = 0;

    // Very high monotonic append ratio
    if metrics.monotonic_append_ratio > 0.90 {
        suspicious_indicators += 1;
    }

    // Very low entropy
    if metrics.edit_entropy < 1.0 && metrics.edit_entropy > 0.0 {
        suspicious_indicators += 1;
    }

    // Extreme positive/negative ratio (almost all insertions)
    if metrics.positive_negative_ratio > 0.95 {
        suspicious_indicators += 1;
    }

    // No clustering in deletions
    if metrics.deletion_clustering > 0.9 && metrics.deletion_clustering < 1.1 {
        suspicious_indicators += 1;
    }

    // Determine verdict
    if alert_count >= ALERT_THRESHOLD || suspicious_indicators >= 3 {
        return Assessment::Suspicious;
    }

    if warning_count >= 3 || suspicious_indicators >= 2 {
        return Assessment::Suspicious;
    }

    Assessment::Consistent
}

/// Calculates an overall assessment score (0.0 - 1.0, higher = more human-like).
pub fn calculate_assessment_score(
    primary: &PrimaryMetrics,
    cadence: &CadenceMetrics,
    anomaly_count: usize,
    event_count: usize,
) -> f64 {
    if event_count < MIN_EVENTS_FOR_ANALYSIS {
        return 0.5; // Neutral for insufficient data
    }

    let mut score = 1.0;

    // Penalize high monotonic append ratio
    if primary.monotonic_append_ratio > 0.85 {
        score -= 0.2 * (primary.monotonic_append_ratio - 0.85) / 0.15;
    }

    // Penalize low entropy (max entropy for 20 bins is log2(20) ~ 4.32)
    let normalized_entropy = primary.edit_entropy / 4.32;
    if normalized_entropy < 0.35 {
        score -= 0.15;
    }

    // Penalize extreme positive/negative ratio
    if primary.positive_negative_ratio > 0.95 {
        score -= 0.1;
    }

    // Penalize scattered deletions
    if primary.deletion_clustering > 0.9 && primary.deletion_clustering < 1.1 {
        score -= 0.1;
    }

    // Penalize robotic cadence (Behavioral check)
    if cadence.is_robotic {
        score -= 0.35; // Increased penalty
    }

    // Penalize low coefficient of variation (too consistent)
    if cadence.coefficient_of_variation < 0.2 {
        score -= 0.15 * (0.2 - cadence.coefficient_of_variation) / 0.2;
    }

    // Penalize anomalies
    score -= 0.05 * anomaly_count as f64;

    score.clamp(0.0, 1.0)
}

/// Determines risk level from assessment score.
pub fn determine_risk_level(score: f64, event_count: usize) -> RiskLevel {
    if event_count < MIN_EVENTS_FOR_ANALYSIS {
        return RiskLevel::Insufficient;
    }

    if score >= 0.7 {
        RiskLevel::Low
    } else if score >= 0.4 {
        RiskLevel::Medium
    } else {
        RiskLevel::High
    }
}

// =============================================================================
// Profile Building
// =============================================================================

/// Builds a complete authorship profile from events and regions.
pub fn build_profile(
    events: &[EventData],
    regions_by_event: &HashMap<i64, Vec<RegionData>>,
) -> AuthorshipProfile {
    if events.len() < MIN_EVENTS_FOR_ANALYSIS {
        return AuthorshipProfile {
            event_count: events.len(),
            assessment: Assessment::Insufficient,
            ..Default::default()
        };
    }

    let mut sorted = events.to_vec();
    sorted.sort_by_key(|e| e.timestamp_ns);

    let file_path = sorted
        .first()
        .map(|e| e.file_path.clone())
        .unwrap_or_default();
    let first_ts =
        DateTime::from_timestamp_nanos(sorted.first().map(|e| e.timestamp_ns).unwrap_or(0));
    let last_ts =
        DateTime::from_timestamp_nanos(sorted.last().map(|e| e.timestamp_ns).unwrap_or(0));
    let time_span = last_ts.signed_duration_since(first_ts);

    let sessions = detect_sessions(&sorted, DEFAULT_SESSION_GAP_SEC);

    let metrics = match compute_primary_metrics(&sorted, regions_by_event) {
        Ok(m) => m,
        Err(_) => {
            return AuthorshipProfile {
                file_path,
                event_count: events.len(),
                time_span,
                session_count: sessions.len(),
                first_event: first_ts,
                last_event: last_ts,
                assessment: Assessment::Insufficient,
                ..Default::default()
            };
        }
    };

    let anomalies = detect_anomalies(&sorted, regions_by_event, &metrics);
    let assessment = determine_assessment(&metrics, &anomalies, events.len());

    AuthorshipProfile {
        file_path,
        event_count: events.len(),
        time_span,
        session_count: sessions.len(),
        first_event: first_ts,
        last_event: last_ts,
        metrics,
        anomalies,
        assessment,
    }
}

// =============================================================================
// Comprehensive Forensic Analysis
// =============================================================================

/// Performs comprehensive forensic analysis.
pub fn analyze_forensics(
    events: &[EventData],
    regions: &HashMap<i64, Vec<RegionData>>,
    jitter_samples: Option<&[SimpleJitterSample]>,
) -> ForensicMetrics {
    let mut metrics = ForensicMetrics::default();

    // Primary metrics
    if let Ok(primary) = compute_primary_metrics(events, regions) {
        metrics.primary = primary;
    }

    // Cadence and Behavioral metrics
    if let Some(samples) = jitter_samples {
        metrics.cadence = analyze_cadence(samples);

        // Compute behavioral fingerprint (the "How")
        let fingerprint = BehavioralFingerprint::from_samples(samples);
        metrics.behavioral = Some(fingerprint);

        // Run forgery detection
        let forgery = BehavioralFingerprint::detect_forgery(samples);
        metrics.forgery_analysis = Some(forgery.clone());

        // Compute Steganographic Confidence (the "What")
        // In a full implementation, this would verify the HMAC-jitter values.
        // For now, we correlate stability with steganographic presence.
        metrics.steg_confidence = if metrics.cadence.coefficient_of_variation > 0.3 {
            0.95 // High entropy suggests authentic human jitter
        } else {
            0.20 // Too stable suggests either replaying or missing steganography
        };

        // Fusion: If steg is "perfect" but behavioral is "suspicious", penalize score heavily.
        if forgery.is_suspicious && metrics.steg_confidence > 0.8 {
            // "Perfect Replay" detection
            metrics.anomaly_count += 1;
        }
    }

    // Velocity metrics
    metrics.velocity = analyze_velocity(events);

    // Session stats
    metrics.session_stats = compute_session_stats(events);

    // Anomaly count
    let anomalies = detect_anomalies(events, regions, &metrics.primary);
    metrics.anomaly_count += anomalies.len();

    // Assessment score
    metrics.assessment_score = calculate_assessment_score(
        &metrics.primary,
        &metrics.cadence,
        metrics.anomaly_count,
        events.len(),
    );

    // Risk level
    metrics.risk_level = determine_risk_level(metrics.assessment_score, events.len());

    metrics
}

// =============================================================================
// Content-Keystroke Correlation
// =============================================================================

/// Input for content-keystroke correlation analysis.
#[derive(Debug, Clone, Default)]
pub struct CorrelationInput {
    /// Final document size in bytes.
    pub document_length: i64,
    /// Total keystroke count.
    pub total_keystrokes: i64,
    /// Characters from detected pastes.
    pub detected_paste_chars: i64,
    /// Number of paste operations.
    pub detected_paste_count: i64,
    /// Characters from velocity-detected autocomplete.
    pub autocomplete_chars: i64,
    /// Number of suspicious velocity bursts.
    pub suspicious_bursts: usize,
    /// Actual edit ratio if known.
    pub actual_edit_ratio: Option<f64>,
}

/// Result of content-keystroke correlation analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationResult {
    pub document_length: i64,
    pub total_keystrokes: i64,
    pub detected_paste_chars: i64,
    pub detected_paste_count: i64,
    pub effective_keystrokes: i64,
    pub expected_content: i64,
    pub discrepancy: i64,
    pub discrepancy_ratio: f64,
    pub autocomplete_chars: i64,
    pub suspicious_bursts: usize,
    pub status: CorrelationStatus,
    pub explanation: String,
    pub flags: Vec<CorrelationFlag>,
}

/// Correlation status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CorrelationStatus {
    Consistent,
    Suspicious,
    Inconsistent,
    Insufficient,
}

impl fmt::Display for CorrelationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CorrelationStatus::Consistent => write!(f, "consistent"),
            CorrelationStatus::Suspicious => write!(f, "suspicious"),
            CorrelationStatus::Inconsistent => write!(f, "inconsistent"),
            CorrelationStatus::Insufficient => write!(f, "insufficient"),
        }
    }
}

/// Correlation flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CorrelationFlag {
    ExcessContent,
    UndetectedPaste,
    Autocomplete,
    NoKeystrokes,
    HighEditRatio,
    ExternalGenerated,
}

impl fmt::Display for CorrelationFlag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CorrelationFlag::ExcessContent => write!(f, "excess_content"),
            CorrelationFlag::UndetectedPaste => write!(f, "undetected_paste"),
            CorrelationFlag::Autocomplete => write!(f, "autocomplete"),
            CorrelationFlag::NoKeystrokes => write!(f, "no_keystrokes"),
            CorrelationFlag::HighEditRatio => write!(f, "high_edit_ratio"),
            CorrelationFlag::ExternalGenerated => write!(f, "external_generated"),
        }
    }
}

/// Content-keystroke correlator.
#[derive(Debug, Clone)]
pub struct ContentKeystrokeCorrelator {
    suspicious_ratio_threshold: f64,
    inconsistent_ratio_threshold: f64,
    estimated_edit_ratio: f64,
    min_keystrokes: i64,
    min_document_length: i64,
}

impl Default for ContentKeystrokeCorrelator {
    fn default() -> Self {
        Self {
            suspicious_ratio_threshold: SUSPICIOUS_RATIO_THRESHOLD,
            inconsistent_ratio_threshold: INCONSISTENT_RATIO_THRESHOLD,
            estimated_edit_ratio: DEFAULT_EDIT_RATIO,
            min_keystrokes: 10,
            min_document_length: 50,
        }
    }
}

impl ContentKeystrokeCorrelator {
    /// Creates a new correlator with default config.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a correlator with custom thresholds.
    pub fn with_thresholds(
        suspicious_threshold: f64,
        inconsistent_threshold: f64,
        edit_ratio: f64,
    ) -> Self {
        Self {
            suspicious_ratio_threshold: suspicious_threshold,
            inconsistent_ratio_threshold: inconsistent_threshold,
            estimated_edit_ratio: edit_ratio,
            ..Default::default()
        }
    }

    /// Performs correlation analysis.
    pub fn analyze(&self, input: &CorrelationInput) -> CorrelationResult {
        let mut result = CorrelationResult {
            document_length: input.document_length,
            total_keystrokes: input.total_keystrokes,
            detected_paste_chars: input.detected_paste_chars,
            detected_paste_count: input.detected_paste_count,
            effective_keystrokes: 0,
            expected_content: 0,
            discrepancy: 0,
            discrepancy_ratio: 0.0,
            autocomplete_chars: input.autocomplete_chars,
            suspicious_bursts: input.suspicious_bursts,
            status: CorrelationStatus::Insufficient,
            explanation: String::new(),
            flags: Vec::new(),
        };

        // Insufficient data check
        if input.total_keystrokes < self.min_keystrokes
            && input.document_length < self.min_document_length
        {
            result.explanation =
                "Insufficient data for meaningful correlation analysis".to_string();
            return result;
        }

        // Calculate effective keystrokes
        let edit_ratio = input.actual_edit_ratio.unwrap_or(self.estimated_edit_ratio);
        result.effective_keystrokes = (input.total_keystrokes as f64 * (1.0 - edit_ratio)) as i64;

        // Expected content
        result.expected_content =
            result.effective_keystrokes + input.detected_paste_chars + input.autocomplete_chars;

        // Handle edge case: no expected content
        if result.expected_content <= 0 {
            if input.document_length > 0 {
                result.status = CorrelationStatus::Inconsistent;
                result.explanation =
                    "Document has content but no keystroke/paste activity detected".to_string();
                result.flags.push(CorrelationFlag::NoKeystrokes);
                result.flags.push(CorrelationFlag::ExternalGenerated);
            } else {
                result.status = CorrelationStatus::Consistent;
                result.explanation = "Empty document with no activity".to_string();
            }
            return result;
        }

        // Calculate discrepancy
        result.discrepancy = input.document_length - result.expected_content;
        result.discrepancy_ratio = result.discrepancy as f64 / result.expected_content as f64;

        // Assess discrepancy
        self.assess_discrepancy(&mut result, input);

        result
    }

    fn assess_discrepancy(&self, result: &mut CorrelationResult, input: &CorrelationInput) {
        let abs_ratio = result.discrepancy_ratio.abs();

        // Check for suspicious velocity patterns
        if input.suspicious_bursts > 0 {
            result.flags.push(CorrelationFlag::Autocomplete);
        }

        // Positive discrepancy: more content than explained
        if result.discrepancy > 0 {
            if abs_ratio >= self.inconsistent_ratio_threshold {
                result.status = CorrelationStatus::Inconsistent;
                result.flags.push(CorrelationFlag::ExcessContent);

                let unexplained = result.discrepancy;
                if unexplained > 100 && input.detected_paste_count == 0 {
                    result.flags.push(CorrelationFlag::UndetectedPaste);
                    result.explanation = format!(
                        "Content exceeds expected by {} bytes ({:.0}%); likely undetected paste or external generation",
                        result.discrepancy, abs_ratio * 100.0
                    );
                } else if input.suspicious_bursts > 3 {
                    result.flags.push(CorrelationFlag::ExternalGenerated);
                    result.explanation = format!(
                        "Content exceeds expected by {} bytes ({:.0}%) with {} suspicious velocity bursts",
                        result.discrepancy, abs_ratio * 100.0, input.suspicious_bursts
                    );
                } else {
                    result.explanation = format!(
                        "Content exceeds expected by {} bytes ({:.0}%)",
                        result.discrepancy,
                        abs_ratio * 100.0
                    );
                }
            } else if abs_ratio >= self.suspicious_ratio_threshold {
                result.status = CorrelationStatus::Suspicious;
                result.explanation = format!(
                    "Minor discrepancy: content exceeds expected by {} bytes ({:.0}%)",
                    result.discrepancy,
                    abs_ratio * 100.0
                );
            } else {
                result.status = CorrelationStatus::Consistent;
                result.explanation =
                    "Content length is consistent with keystroke activity".to_string();
            }
            return;
        }

        // Negative discrepancy: less content than expected (heavy editing)
        if result.discrepancy < 0 {
            if abs_ratio >= self.suspicious_ratio_threshold {
                result.status = CorrelationStatus::Suspicious;
                result.flags.push(CorrelationFlag::HighEditRatio);
                result.explanation = format!(
                    "Document is {} bytes shorter than expected; indicates heavy editing ({:.0}% edit ratio)",
                    -result.discrepancy, abs_ratio * 100.0
                );
            } else {
                result.status = CorrelationStatus::Consistent;
                result.explanation =
                    "Content length is consistent with keystroke activity (normal editing)"
                        .to_string();
            }
            return;
        }

        // Perfect match
        result.status = CorrelationStatus::Consistent;
        result.explanation =
            "Content length exactly matches expected keystroke activity".to_string();
    }
}

/// Quick correlation check.
///
/// Returns true if content is suspicious (likely not human-typed).
pub fn quick_correlate(document_length: i64, keystrokes: i64, paste_chars: i64) -> bool {
    if keystrokes == 0 && document_length > 50 {
        return true;
    }

    let effective_keystrokes = (keystrokes as f64 * 0.85) as i64;
    let expected = effective_keystrokes + paste_chars;

    if expected <= 0 {
        return document_length > 50;
    }

    let discrepancy_ratio = (document_length - expected) as f64 / expected as f64;
    discrepancy_ratio > 0.5
}

// =============================================================================
// Profile Correlation
// =============================================================================

/// Compares two authorship profiles for consistency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileComparison {
    /// Overall similarity score (0.0 - 1.0).
    pub similarity_score: f64,
    /// Whether profiles are consistent with same author.
    pub is_consistent: bool,
    /// Detailed dimension comparisons.
    pub dimension_scores: DimensionScores,
    /// Explanation of comparison result.
    pub explanation: String,
}

/// Scores for individual comparison dimensions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DimensionScores {
    pub monotonic_append_similarity: f64,
    pub entropy_similarity: f64,
    pub interval_similarity: f64,
    pub pos_neg_ratio_similarity: f64,
    pub deletion_clustering_similarity: f64,
    pub cadence_cv_similarity: f64,
}

/// Compares two profiles for authorship consistency.
#[allow(clippy::field_reassign_with_default)]
pub fn compare_profiles(
    profile_a: &AuthorshipProfile,
    profile_b: &AuthorshipProfile,
) -> ProfileComparison {
    let mut scores = DimensionScores::default();

    // Compare metrics with Gaussian similarity
    scores.monotonic_append_similarity = gaussian_similarity(
        profile_a.metrics.monotonic_append_ratio,
        profile_b.metrics.monotonic_append_ratio,
        0.15, // Standard deviation threshold
    );

    scores.entropy_similarity = gaussian_similarity(
        profile_a.metrics.edit_entropy,
        profile_b.metrics.edit_entropy,
        0.5,
    );

    scores.interval_similarity = gaussian_similarity(
        profile_a.metrics.median_interval.ln().max(0.0),
        profile_b.metrics.median_interval.ln().max(0.0),
        0.5,
    );

    scores.pos_neg_ratio_similarity = gaussian_similarity(
        profile_a.metrics.positive_negative_ratio,
        profile_b.metrics.positive_negative_ratio,
        0.1,
    );

    scores.deletion_clustering_similarity = gaussian_similarity(
        profile_a.metrics.deletion_clustering,
        profile_b.metrics.deletion_clustering,
        0.2,
    );

    // Overall similarity (weighted average)
    let similarity_score = 0.25 * scores.monotonic_append_similarity
        + 0.20 * scores.entropy_similarity
        + 0.15 * scores.interval_similarity
        + 0.20 * scores.pos_neg_ratio_similarity
        + 0.20 * scores.deletion_clustering_similarity;

    let is_consistent = similarity_score >= 0.6;

    let explanation = if is_consistent {
        format!(
            "Profiles are consistent with same author (similarity: {:.1}%)",
            similarity_score * 100.0
        )
    } else {
        format!(
            "Profiles show significant differences (similarity: {:.1}%)",
            similarity_score * 100.0
        )
    };

    ProfileComparison {
        similarity_score,
        is_consistent,
        dimension_scores: scores,
        explanation,
    }
}

/// Computes Gaussian similarity between two values.
fn gaussian_similarity(a: f64, b: f64, sigma: f64) -> f64 {
    let diff = a - b;
    (-diff * diff / (2.0 * sigma * sigma)).exp()
}

/// Compares cadence metrics for consistency.
pub fn compare_cadence(cadence_a: &CadenceMetrics, cadence_b: &CadenceMetrics) -> f64 {
    if cadence_a.mean_iki_ns == 0.0 || cadence_b.mean_iki_ns == 0.0 {
        return 0.0;
    }

    let cv_sim = gaussian_similarity(
        cadence_a.coefficient_of_variation,
        cadence_b.coefficient_of_variation,
        0.1,
    );

    let mean_ratio = cadence_a.mean_iki_ns.min(cadence_b.mean_iki_ns)
        / cadence_a.mean_iki_ns.max(cadence_b.mean_iki_ns);

    0.5 * cv_sim + 0.5 * mean_ratio
}

// =============================================================================
// Report Generation
// =============================================================================

/// Generates a human-readable forensic report.
pub fn generate_report(profile: &AuthorshipProfile) -> String {
    let mut report = String::new();

    // Header
    report.push_str(&"=".repeat(72));
    report.push('\n');
    report.push_str("                    FORENSIC AUTHORSHIP ANALYSIS\n");
    report.push_str(&"=".repeat(72));
    report.push_str("\n\n");

    // File info
    if !profile.file_path.is_empty() {
        report.push_str(&format!("File:           {}\n", profile.file_path));
    }
    report.push_str(&format!("Events:         {}\n", profile.event_count));
    report.push_str(&format!("Sessions:       {}\n", profile.session_count));
    report.push_str(&format!(
        "Time Span:      {}\n",
        format_duration(profile.time_span)
    ));
    if profile.first_event.timestamp() != 0 {
        report.push_str(&format!(
            "First Event:    {}\n",
            profile.first_event.format("%Y-%m-%dT%H:%M:%S%z")
        ));
        report.push_str(&format!(
            "Last Event:     {}\n",
            profile.last_event.format("%Y-%m-%dT%H:%M:%S%z")
        ));
    }
    report.push('\n');

    // Primary Metrics
    report.push_str(&"-".repeat(72));
    report.push_str("\nPRIMARY METRICS\n");
    report.push_str(&"-".repeat(72));
    report.push_str("\n\n");

    let m = &profile.metrics;

    // Monotonic Append Ratio
    report.push_str(&format!(
        "Monotonic Append Ratio:   {:.3}  {}\n",
        m.monotonic_append_ratio,
        format_metric_bar(m.monotonic_append_ratio, 0.0, 1.0, 20)
    ));
    report.push_str(&format!(
        "  -> {}\n\n",
        interpret_monotonic_append(m.monotonic_append_ratio)
    ));

    // Edit Entropy
    let max_entropy = 4.32; // log2(20) for 20 bins
    report.push_str(&format!(
        "Edit Entropy:             {:.3}  {}\n",
        m.edit_entropy,
        format_metric_bar(m.edit_entropy, 0.0, max_entropy, 20)
    ));
    report.push_str(&format!(
        "  -> {}\n\n",
        interpret_edit_entropy(m.edit_entropy)
    ));

    // Median Interval
    report.push_str(&format!(
        "Median Interval:          {:.2} sec\n",
        m.median_interval
    ));
    report.push_str(&format!(
        "  -> {}\n\n",
        interpret_median_interval(m.median_interval)
    ));

    // Positive/Negative Ratio
    report.push_str(&format!(
        "Positive/Negative Ratio:  {:.3}  {}\n",
        m.positive_negative_ratio,
        format_metric_bar(m.positive_negative_ratio, 0.0, 1.0, 20)
    ));
    report.push_str(&format!(
        "  -> {}\n\n",
        interpret_pos_neg_ratio(m.positive_negative_ratio)
    ));

    // Deletion Clustering
    report.push_str(&format!(
        "Deletion Clustering:      {:.3}\n",
        m.deletion_clustering
    ));
    report.push_str(&format!(
        "  -> {}\n\n",
        interpret_deletion_clustering(m.deletion_clustering)
    ));

    // Anomalies
    if !profile.anomalies.is_empty() {
        report.push_str(&"-".repeat(72));
        report.push_str("\nANOMALIES DETECTED\n");
        report.push_str(&"-".repeat(72));
        report.push_str("\n\n");

        for (i, a) in profile.anomalies.iter().enumerate() {
            let severity_marker = match a.severity {
                Severity::Alert => "!!!",
                Severity::Warning => " ! ",
                Severity::Info => " i ",
            };
            report.push_str(&format!(
                "{}. [{}] {}: {}\n",
                i + 1,
                severity_marker,
                a.anomaly_type,
                a.description
            ));
            if let Some(ts) = a.timestamp {
                report.push_str(&format!("   At: {}\n", ts.format("%Y-%m-%dT%H:%M:%S%z")));
            }
            if let Some(ctx) = &a.context {
                report.push_str(&format!("   Context: {}\n", ctx));
            }
        }
        report.push('\n');
    }

    // Assessment
    report.push_str(&"=".repeat(72));
    report.push_str(&format!("\nASSESSMENT: {}\n", profile.assessment));
    report.push_str(&"=".repeat(72));
    report.push('\n');

    report
}

/// Formats a duration in human-readable form.
fn format_duration(d: ChronoDuration) -> String {
    if d < ChronoDuration::zero() {
        return "0 seconds".to_string();
    }

    let total_secs = d.num_seconds();
    let days = total_secs / 86400;
    let hours = (total_secs % 86400) / 3600;
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;

    if days > 0 {
        if days == 1 {
            format!("{} day, {} hours", days, hours)
        } else {
            format!("{} days, {} hours", days, hours)
        }
    } else if hours > 0 {
        if hours == 1 {
            format!("{} hour, {} minutes", hours, minutes)
        } else {
            format!("{} hours, {} minutes", hours, minutes)
        }
    } else if minutes > 0 {
        if minutes == 1 {
            format!("{} minute, {} seconds", minutes, seconds)
        } else {
            format!("{} minutes, {} seconds", minutes, seconds)
        }
    } else if seconds == 1 {
        format!("{} second", seconds)
    } else {
        format!("{} seconds", seconds)
    }
}

/// Formats a metric bar for visualization.
fn format_metric_bar(value: f64, min: f64, max: f64, width: usize) -> String {
    if width == 0 || max <= min {
        return "-".repeat(width);
    }

    let normalized = ((value - min) / (max - min)).clamp(0.0, 1.0);
    let filled = (normalized * width as f64) as usize;
    let filled = filled.min(width);

    format!("[{}{}]", "#".repeat(filled), "-".repeat(width - filled))
}

fn interpret_monotonic_append(ratio: f64) -> &'static str {
    if ratio > 0.90 {
        "Very high: Nearly all edits at end of document (AI-like pattern)"
    } else if ratio > 0.70 {
        "High: Most edits at end of document"
    } else if ratio > 0.40 {
        "Moderate: Mixed editing patterns (typical human behavior)"
    } else {
        "Low: Distributed editing throughout document"
    }
}

fn interpret_edit_entropy(entropy: f64) -> &'static str {
    if entropy < 1.0 {
        "Very low: Highly concentrated editing (suspicious)"
    } else if entropy < 2.0 {
        "Low: Somewhat focused editing patterns"
    } else if entropy < 3.0 {
        "Moderate: Typical editing distribution"
    } else {
        "High: Well-distributed editing (normal revision behavior)"
    }
}

fn interpret_median_interval(interval: f64) -> &'static str {
    if interval < 1.0 {
        "Very fast: Sub-second editing pace (automated?)"
    } else if interval < 5.0 {
        "Fast: Rapid editing pace"
    } else if interval < 30.0 {
        "Moderate: Typical typing/thinking pace"
    } else if interval < 300.0 {
        "Slow: Thoughtful/deliberate editing"
    } else {
        "Very slow: Extended pauses between edits"
    }
}

fn interpret_pos_neg_ratio(ratio: f64) -> &'static str {
    if ratio > 0.95 {
        "Almost all insertions: No revision behavior (suspicious)"
    } else if ratio > 0.80 {
        "Mostly insertions: Limited revision"
    } else if ratio > 0.60 {
        "Balanced toward insertions: Typical drafting pattern"
    } else if ratio > 0.40 {
        "Balanced: Active revision behavior"
    } else {
        "Mostly deletions: Heavy revision/editing mode"
    }
}

fn interpret_deletion_clustering(coef: f64) -> &'static str {
    if coef == 0.0 {
        "No deletions or insufficient data"
    } else if coef < 0.5 {
        "Highly clustered: Systematic revision passes (human-like)"
    } else if coef < 0.8 {
        "Moderately clustered: Natural editing pattern"
    } else if coef < 1.2 {
        "Scattered: Random deletion distribution (suspicious)"
    } else {
        "Very scattered: Possibly artificial deletion pattern"
    }
}

// =============================================================================
// Forensic Engine (Original API Compatibility)
// =============================================================================

/// Result of a forensic physical analysis.
#[derive(Debug, Clone)]
pub struct ForensicReport {
    /// Confidence score (0.0 to 1.0).
    pub confidence_score: f64,
    /// Whether this is an anomaly.
    pub is_anomaly: bool,
    /// Whether retyped content was detected via robotic IKI cadence.
    pub is_retyped_content: bool,
    /// Detailed signal analyses.
    pub details: Vec<SignalAnalysis>,
}

/// Individual signal analysis result.
#[derive(Debug, Clone)]
pub struct SignalAnalysis {
    pub name: String,
    pub z_score: f64,
    pub probability: f64,
}

/// Forensic engine for physical context analysis.
pub struct ForensicEngine;

impl ForensicEngine {
    /// Evaluates authorship metrics including cognitive cadence.
    ///
    /// Human original composition has "Cognitive Bursts":
    /// Fast typing for familiar words, then long pauses for thought.
    /// Retyping AI content has high stability (consistent rhythm).
    pub fn evaluate_cadence(samples: &[SimpleJitterSample]) -> bool {
        is_retyped_content(samples)
    }

    /// Evaluates a PhysicalContext against known baselines.
    pub fn evaluate(
        ctx: &PhysicalContext,
        baselines: &[(String, f64, f64)], // (name, mean, std_dev)
    ) -> ForensicReport {
        let mut analyses = Vec::new();
        let mut total_prob = 0.0;
        let mut count = 0;

        for (name, mean, std_dev) in baselines {
            let val = match name.as_str() {
                "clock_skew" => ctx.clock_skew as f64,
                "thermal_proxy" => ctx.thermal_proxy as f64,
                "io_latency" => ctx.io_latency_ns as f64,
                _ => continue,
            };

            // Calculate Z-score
            let z_score = if *std_dev > 0.0 {
                (val - *mean).abs() / *std_dev
            } else {
                0.0
            };

            // Calculate probability using Gaussian CDF
            let prob = if *std_dev > 0.0 {
                if let Ok(n) = Normal::new(*mean, *std_dev) {
                    2.0 * (1.0 - n.cdf(mean + (val - mean).abs()))
                } else {
                    1.0
                }
            } else {
                1.0
            };

            analyses.push(SignalAnalysis {
                name: name.clone(),
                z_score,
                probability: prob,
            });

            total_prob += prob;
            count += 1;
        }

        let confidence = if count > 0 {
            total_prob / count as f64
        } else {
            1.0
        };

        ForensicReport {
            confidence_score: confidence,
            is_anomaly: confidence < 0.01,
            is_retyped_content: false,
            details: analyses,
        }
    }
}

// =============================================================================
// Error Types
// =============================================================================

/// Forensics analysis error.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ForensicsError {
    #[error("Insufficient data for analysis")]
    InsufficientData,
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Computation error: {0}")]
    ComputationError(String),
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_events(count: usize) -> Vec<EventData> {
        (0..count)
            .map(|i| EventData {
                id: i as i64,
                timestamp_ns: i as i64 * 1_000_000_000, // 1 second apart
                file_size: 100 + i as i64 * 10,
                size_delta: 10,
                file_path: "/test/file.txt".to_string(),
            })
            .collect()
    }

    fn create_test_regions() -> HashMap<i64, Vec<RegionData>> {
        let mut regions = HashMap::new();
        for i in 0..10 {
            regions.insert(
                i,
                vec![RegionData {
                    start_pct: i as f32 / 10.0,
                    end_pct: (i + 1) as f32 / 10.0,
                    delta_sign: if i % 3 == 0 { -1 } else { 1 },
                    byte_count: 10,
                }],
            );
        }
        regions
    }

    #[test]
    fn test_monotonic_append_ratio() {
        let regions = vec![
            RegionData {
                start_pct: 0.96,
                end_pct: 0.98,
                delta_sign: 1,
                byte_count: 10,
            },
            RegionData {
                start_pct: 0.50,
                end_pct: 0.55,
                delta_sign: 1,
                byte_count: 10,
            },
            RegionData {
                start_pct: 0.97,
                end_pct: 0.99,
                delta_sign: 1,
                byte_count: 10,
            },
        ];

        let ratio = monotonic_append_ratio(&regions, 0.95);
        assert!((ratio - 0.666).abs() < 0.01);
    }

    #[test]
    fn test_edit_entropy() {
        // All edits in one bin should have entropy 0
        let regions_concentrated = vec![
            RegionData {
                start_pct: 0.5,
                end_pct: 0.51,
                delta_sign: 1,
                byte_count: 10,
            },
            RegionData {
                start_pct: 0.51,
                end_pct: 0.52,
                delta_sign: 1,
                byte_count: 10,
            },
        ];
        let entropy_low = edit_entropy(&regions_concentrated, 20);
        assert!(entropy_low < 0.1);

        // Spread across bins should have higher entropy
        let regions_spread: Vec<_> = (0..20)
            .map(|i| RegionData {
                start_pct: i as f32 / 20.0,
                end_pct: (i + 1) as f32 / 20.0,
                delta_sign: 1,
                byte_count: 10,
            })
            .collect();
        let entropy_high = edit_entropy(&regions_spread, 20);
        assert!(entropy_high > 4.0); // Max is log2(20) ~ 4.32
    }

    #[test]
    fn test_positive_negative_ratio() {
        let regions = vec![
            RegionData {
                start_pct: 0.1,
                end_pct: 0.2,
                delta_sign: 1,
                byte_count: 10,
            },
            RegionData {
                start_pct: 0.2,
                end_pct: 0.3,
                delta_sign: 1,
                byte_count: 10,
            },
            RegionData {
                start_pct: 0.3,
                end_pct: 0.4,
                delta_sign: -1,
                byte_count: 5,
            },
            RegionData {
                start_pct: 0.4,
                end_pct: 0.5,
                delta_sign: 0,
                byte_count: 10,
            }, // Replacement, excluded
        ];

        let ratio = positive_negative_ratio(&regions);
        assert!((ratio - 0.666).abs() < 0.01);
    }

    #[test]
    fn test_deletion_clustering() {
        // Clustered deletions
        let regions_clustered = vec![
            RegionData {
                start_pct: 0.50,
                end_pct: 0.51,
                delta_sign: -1,
                byte_count: 5,
            },
            RegionData {
                start_pct: 0.51,
                end_pct: 0.52,
                delta_sign: -1,
                byte_count: 5,
            },
            RegionData {
                start_pct: 0.52,
                end_pct: 0.53,
                delta_sign: -1,
                byte_count: 5,
            },
        ];
        let coef_clustered = deletion_clustering_coef(&regions_clustered);
        assert!(coef_clustered < 0.5);

        // Scattered deletions
        let regions_scattered = vec![
            RegionData {
                start_pct: 0.1,
                end_pct: 0.11,
                delta_sign: -1,
                byte_count: 5,
            },
            RegionData {
                start_pct: 0.5,
                end_pct: 0.51,
                delta_sign: -1,
                byte_count: 5,
            },
            RegionData {
                start_pct: 0.9,
                end_pct: 0.91,
                delta_sign: -1,
                byte_count: 5,
            },
        ];
        let coef_scattered = deletion_clustering_coef(&regions_scattered);
        assert!(coef_scattered > coef_clustered);
    }

    #[test]
    fn test_cadence_analysis() {
        // Create samples with robotic timing
        let robotic_samples: Vec<_> = (0..50)
            .map(|i| SimpleJitterSample {
                timestamp_ns: i as i64 * 100_000_000, // Exactly 100ms apart
                duration_since_last_ns: 100_000_000,
                zone: 0,
            })
            .collect();

        let cadence = analyze_cadence(&robotic_samples);
        assert!(cadence.is_robotic);
        assert!(cadence.coefficient_of_variation < ROBOTIC_CV_THRESHOLD);

        // Create samples with human-like variation
        let human_samples: Vec<_> = (0..50)
            .map(|i| {
                let variation = ((i * 17) % 100) as i64 * 5_000_000; // Pseudo-random variation
                SimpleJitterSample {
                    timestamp_ns: i as i64 * 150_000_000 + variation,
                    duration_since_last_ns: 150_000_000 + variation as u64,
                    zone: 0,
                }
            })
            .collect();

        let cadence_human = analyze_cadence(&human_samples);
        assert!(!cadence_human.is_robotic);
    }

    #[test]
    fn test_compute_primary_metrics() {
        let events = create_test_events(10);
        let regions = create_test_regions();

        let metrics = compute_primary_metrics(&events, &regions).unwrap();

        assert!(metrics.monotonic_append_ratio >= 0.0 && metrics.monotonic_append_ratio <= 1.0);
        assert!(metrics.edit_entropy >= 0.0);
        assert!(metrics.median_interval >= 0.0);
        assert!(metrics.positive_negative_ratio >= 0.0 && metrics.positive_negative_ratio <= 1.0);
    }

    #[test]
    fn test_insufficient_data() {
        let events = create_test_events(2);
        let regions = HashMap::new();

        let result = compute_primary_metrics(&events, &regions);
        assert!(matches!(result, Err(ForensicsError::InsufficientData)));
    }

    #[test]
    fn test_session_detection() {
        let mut events = create_test_events(10);
        // Add a gap
        events[5].timestamp_ns = events[4].timestamp_ns + 3_600_000_000_000; // 1 hour gap

        let sessions = detect_sessions(&events, 1800.0); // 30 min threshold
        assert_eq!(sessions.len(), 2);
    }

    #[test]
    fn test_correlation() {
        let correlator = ContentKeystrokeCorrelator::new();

        // Consistent case
        let input_consistent = CorrelationInput {
            document_length: 1000,
            total_keystrokes: 1200, // With 15% edit ratio, effective = 1020
            detected_paste_chars: 0,
            detected_paste_count: 0,
            autocomplete_chars: 0,
            suspicious_bursts: 0,
            actual_edit_ratio: None,
        };

        let result = correlator.analyze(&input_consistent);
        assert_eq!(result.status, CorrelationStatus::Consistent);

        // Suspicious case
        let input_suspicious = CorrelationInput {
            document_length: 5000,
            total_keystrokes: 1000,
            detected_paste_chars: 0,
            detected_paste_count: 0,
            autocomplete_chars: 0,
            suspicious_bursts: 5,
            actual_edit_ratio: None,
        };

        let result = correlator.analyze(&input_suspicious);
        assert!(matches!(
            result.status,
            CorrelationStatus::Suspicious | CorrelationStatus::Inconsistent
        ));
    }

    #[test]
    fn test_profile_comparison() {
        let profile_a = AuthorshipProfile {
            metrics: PrimaryMetrics {
                monotonic_append_ratio: 0.5,
                edit_entropy: 2.5,
                median_interval: 3.0,
                positive_negative_ratio: 0.7,
                deletion_clustering: 0.4,
            },
            ..Default::default()
        };

        let profile_b = AuthorshipProfile {
            metrics: PrimaryMetrics {
                monotonic_append_ratio: 0.55,
                edit_entropy: 2.6,
                median_interval: 3.2,
                positive_negative_ratio: 0.72,
                deletion_clustering: 0.45,
            },
            ..Default::default()
        };

        let comparison = compare_profiles(&profile_a, &profile_b);
        assert!(comparison.is_consistent);
        assert!(comparison.similarity_score > 0.6);
    }

    #[test]
    fn test_assessment_score() {
        let good_primary = PrimaryMetrics {
            monotonic_append_ratio: 0.4,
            edit_entropy: 3.0,
            median_interval: 5.0,
            positive_negative_ratio: 0.7,
            deletion_clustering: 0.5,
        };

        let good_cadence = CadenceMetrics {
            coefficient_of_variation: 0.4,
            is_robotic: false,
            ..Default::default()
        };

        let score = calculate_assessment_score(&good_primary, &good_cadence, 0, 100);
        assert!(score > 0.7);

        let bad_primary = PrimaryMetrics {
            monotonic_append_ratio: 0.95,
            edit_entropy: 0.5,
            median_interval: 5.0,
            positive_negative_ratio: 0.98,
            deletion_clustering: 1.0,
        };

        let bad_cadence = CadenceMetrics {
            coefficient_of_variation: 0.1,
            is_robotic: true,
            ..Default::default()
        };

        let bad_score = calculate_assessment_score(&bad_primary, &bad_cadence, 5, 100);
        assert!(bad_score < 0.5);
    }

    #[test]
    fn test_report_generation() {
        let events = create_test_events(20);
        let regions = create_test_regions();
        let profile = build_profile(&events, &regions);

        let report = generate_report(&profile);
        assert!(report.contains("FORENSIC AUTHORSHIP ANALYSIS"));
        assert!(report.contains("PRIMARY METRICS"));
        assert!(report.contains("Monotonic Append Ratio"));
        assert!(report.contains("ASSESSMENT"));
    }
}
