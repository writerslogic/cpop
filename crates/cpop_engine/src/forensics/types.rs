// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Core types, constants, and enums for forensic analysis.

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::analysis::{
    BehavioralFingerprint, ForgeryAnalysis, IkiCompressionAnalysis, LabyrinthAnalysis,
    LyapunovAnalysis, SnrAnalysis,
};
use crate::forensics::cross_modal::CrossModalResult;
use crate::forensics::forgery_cost::ForgeryCostEstimate;
use cpop_protocol::forensics::{ForensicAnalysis as ProtocolForensicAnalysis, ForensicVerdict};

/// Edits past this position (95%) count as "append".
pub const DEFAULT_APPEND_THRESHOLD: f32 = 0.95;

/// Bin count for edit entropy histogram.
pub const DEFAULT_HISTOGRAM_BINS: usize = 20;

/// Minimum events for stable analysis.
pub const MIN_EVENTS_FOR_ANALYSIS: usize = 5;

/// Minimum events for a verdict.
pub const MIN_EVENTS_FOR_ASSESSMENT: usize = 10;

/// Session gap threshold: 30 minutes.
pub const DEFAULT_SESSION_GAP_SEC: f64 = 1800.0;

/// Above this append ratio, AI generation is suspected.
pub const THRESHOLD_MONOTONIC_APPEND: f64 = 0.85;

/// Minimum timing entropy (bits/sample) per draft-condrey-rats-pop-appraisal.
pub const THRESHOLD_TIMING_ENTROPY: f64 = 3.0;
/// Minimum revision entropy (bits) per draft-condrey-rats-pop-appraisal.
pub const THRESHOLD_REVISION_ENTROPY: f64 = 3.0;
/// Minimum pause entropy (bits) per draft-condrey-rats-pop-appraisal.
pub const THRESHOLD_PAUSE_ENTROPY: f64 = 2.0;
/// Below this edit entropy, non-human editing is suspected.
/// Uses the minimum of the per-type thresholds as a general floor.
pub const THRESHOLD_LOW_ENTROPY: f64 = 2.0;

/// Bytes/sec above which velocity is flagged as anomalous.
pub const THRESHOLD_HIGH_VELOCITY_BPS: f64 = 100.0;

/// Gap longer than this (hours) triggers an anomaly.
pub const THRESHOLD_GAP_HOURS: f64 = 24.0;

/// Alert-level anomalies needed for `Suspicious` verdict.
pub const ALERT_THRESHOLD: usize = 2;

/// CV below this indicates robotic typing.
pub const ROBOTIC_CV_THRESHOLD: f64 = 0.15;

/// Estimated fraction of keystrokes that are deletions.
pub const DEFAULT_EDIT_RATIO: f64 = 0.15;

/// Discrepancy ratio above this is `Suspicious`.
pub const SUSPICIOUS_RATIO_THRESHOLD: f64 = 0.3;

/// Discrepancy ratio above this is `Inconsistent`.
pub const INCONSISTENT_RATIO_THRESHOLD: f64 = 0.5;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventData {
    pub id: i64,
    pub timestamp_ns: i64,
    pub file_size: i64,
    pub size_delta: i32,
    pub file_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionData {
    /// Position in document as fraction `[0.0, 1.0]`.
    pub start_pct: f32,
    /// Position in document as fraction `[0.0, 1.0]`.
    pub end_pct: f32,
    /// +1 insertion, -1 deletion, 0 replacement.
    pub delta_sign: i8,
    pub byte_count: i32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PrimaryMetrics {
    /// Fraction of edits at document end (>0.95 position).
    pub monotonic_append_ratio: f64,
    /// Shannon entropy of edit positions (20-bin histogram).
    pub edit_entropy: f64,
    /// Median inter-event interval (seconds).
    pub median_interval: f64,
    /// `insertions / (insertions + deletions)`.
    pub positive_negative_ratio: f64,
    /// Nearest-neighbor distance ratio for deletions (<1 = clustered).
    pub deletion_clustering: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CadenceMetrics {
    pub mean_iki_ns: f64,
    pub std_dev_iki_ns: f64,
    /// `std_dev / mean`
    pub coefficient_of_variation: f64,
    pub median_iki_ns: f64,
    pub burst_count: usize,
    /// Pauses > 2s.
    pub pause_count: usize,
    pub avg_burst_length: f64,
    pub avg_pause_duration_ns: f64,
    /// CV below `ROBOTIC_CV_THRESHOLD`.
    pub is_robotic: bool,
    /// IKI percentiles: p10, p25, p50, p75, p90.
    pub percentiles: [f64; 5],
    /// Ratio of cross-hand IKI std_dev to same-hand IKI std_dev.
    /// Human typing shows >1.3; transcriptive <1.1.
    pub cross_hand_timing_ratio: f64,
    /// CV of the first 5 keystrokes after each pause (>1s).
    /// Cognitive >0.25; transcriptive <0.15.
    pub post_pause_cv: f64,
    /// Lag-1 autocorrelation of IKI sequence.
    /// Cognitive: -0.1 to 0.2; transcriptive: >0.3.
    pub iki_autocorrelation: f64,
    /// Fraction of keystrokes that are backspace/delete (zone 0xFF).
    /// Cognitive >0.05; transcriptive <0.02.
    pub correction_ratio: f64,
    /// Distribution of pause durations: [sentence_1_3s, paragraph_3_10s, deep_thought_10s_plus].
    pub pause_depth_distribution: [f64; 3],
}

/// Focus pattern metrics for cognitive/transcriptive analysis.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FocusMetrics {
    /// Total number of focus switches during editing.
    pub switch_count: usize,
    /// Fraction of editing time spent out-of-focus.
    pub out_of_focus_ratio: f64,
    /// Number of switches to known AI/browser apps.
    pub ai_app_switch_count: usize,
    /// Average duration of focus-away periods in seconds.
    pub avg_away_duration_sec: f64,
    /// Whether the pattern suggests reading from external source.
    pub reading_pattern_detected: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ForensicMetrics {
    pub primary: PrimaryMetrics,
    pub cadence: CadenceMetrics,
    pub behavioral: Option<BehavioralFingerprint>,
    pub forgery_analysis: Option<ForgeryAnalysis>,
    pub velocity: VelocityMetrics,
    pub session_stats: SessionStats,
    /// `[0.0, 1.0]` -- higher = more human-like.
    pub assessment_score: f64,
    /// Lower = more expected/human-like.
    pub perplexity_score: f64,
    /// Confidence that timing steganography is present.
    pub steg_confidence: f64,
    pub anomaly_count: usize,
    pub risk_level: RiskLevel,
    /// Biological cadence steadiness score (0.0-1.0, higher = steadier).
    pub biological_cadence_score: f64,
    /// Cross-modal consistency analysis (keystroke/content/jitter coherence).
    pub cross_modal: Option<CrossModalResult>,
    /// Forgery cost estimation for user-adversary threat model.
    pub forgery_cost: Option<ForgeryCostEstimate>,
    /// Number of checkpoints in the evidence chain (distinct from session_count).
    pub checkpoint_count: usize,
    /// Hurst exponent from cadence timing analysis, if computed.
    pub hurst_exponent: Option<f64>,
    pub snr: Option<SnrAnalysis>,
    pub lyapunov: Option<LyapunovAnalysis>,
    pub iki_compression: Option<IkiCompressionAnalysis>,
    pub labyrinth: Option<LabyrinthAnalysis>,
    /// Focus-switching pattern analysis.
    pub focus: FocusMetrics,
}

impl ForensicMetrics {
    /// Map to protocol-standard `ForensicVerdict`.
    pub fn map_to_protocol_verdict(&self) -> ForensicVerdict {
        if let Some(forgery) = &self.forgery_analysis {
            if forgery.is_suspicious {
                // V4, not V5: a single heuristic flag is insufficient to confirm forgery.
                // V5ConfirmedForgery requires broken chain integrity (handled in verify()).
                return ForensicVerdict::V4LikelySynthetic;
            }
        }

        // Cross-modal inconsistency is strong evidence of forgery
        if let Some(cm) = &self.cross_modal {
            if cm.verdict == crate::forensics::cross_modal::CrossModalVerdict::Inconsistent {
                return ForensicVerdict::V4LikelySynthetic;
            }
        }

        match self.risk_level {
            RiskLevel::Low => {
                if self.assessment_score > 0.9 {
                    ForensicVerdict::V1VerifiedHuman
                } else {
                    ForensicVerdict::V2LikelyHuman
                }
            }
            RiskLevel::Medium => ForensicVerdict::V3Suspicious,
            RiskLevel::High => {
                if self.cadence.is_robotic {
                    ForensicVerdict::V4LikelySynthetic
                } else {
                    ForensicVerdict::V3Suspicious
                }
            }
            RiskLevel::Insufficient => ForensicVerdict::V3Suspicious,
        }
    }

    /// Convert to `ProtocolForensicAnalysis` for wire serialization.
    pub fn to_protocol_analysis(&self) -> ProtocolForensicAnalysis {
        ProtocolForensicAnalysis {
            verdict: self.map_to_protocol_verdict(),
            coefficient_of_variation: self.cadence.coefficient_of_variation,
            linearity_score: Some(self.primary.monotonic_append_ratio),
            hurst_exponent: self.hurst_exponent,
            checkpoint_count: self.checkpoint_count,
            chain_duration_secs: self.session_stats.total_editing_time_sec as u64,
            explanation: format!("Internal Assessment Score: {:.2}", self.assessment_score),
        }
    }
}

/// Edit velocity (bytes/sec) metrics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VelocityMetrics {
    pub mean_bps: f64,
    pub max_bps: f64,
    pub high_velocity_bursts: usize,
    /// Estimated characters from autocomplete (excess over human max).
    pub autocomplete_chars: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionStats {
    pub session_count: usize,
    pub avg_session_duration_sec: f64,
    pub total_editing_time_sec: f64,
    /// Wall-clock span from first to last event (seconds).
    pub time_span_sec: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum RiskLevel {
    #[default]
    Low,
    Medium,
    High,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anomaly {
    pub timestamp: Option<DateTime<Utc>>,
    pub anomaly_type: AnomalyType,
    pub description: String,
    pub severity: Severity,
    pub context: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnomalyType {
    Gap,
    HighVelocity,
    MonotonicAppend,
    LowEntropy,
    RoboticCadence,
    UndetectedPaste,
    ContentMismatch,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointFlags {
    pub ordinal: u64,
    pub event_count: usize,
    pub timing_cv: f64,
    pub max_velocity_bps: f64,
    pub all_append: bool,
    pub flagged: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerCheckpointResult {
    pub checkpoint_flags: Vec<CheckpointFlags>,
    pub pct_flagged: f64,
    pub suspicious: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Assessment {
    Consistent,
    Suspicious,
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
