// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Main orchestration functions for forensic analysis.

use chrono::DateTime;
use std::collections::HashMap;

use crate::analysis::BehavioralFingerprint;
use crate::jitter::SimpleJitterSample;

use super::assessment::{
    apply_focus_penalties, compute_assessment_score, detect_anomalies, determine_assessment,
    determine_risk_level,
};
use super::cadence::analyze_cadence;
use super::topology::compute_primary_metrics;
use super::types::{
    Assessment, AuthorshipProfile, EventData, ForensicMetrics, RegionData, DEFAULT_SESSION_GAP_SEC,
    MIN_EVENTS_FOR_ANALYSIS,
};
use super::velocity::{compute_session_stats, count_sessions_sorted};

use super::types::{CheckpointFlags, FocusMetrics, PerCheckpointResult};
use crate::analysis::labyrinth::{analyze_labyrinth, LabyrinthParams};
use crate::analysis::{analyze_iki_compression, analyze_lyapunov, analyze_snr};
use crate::evidence::CheckpointProof;
use crate::sentinel::types::FocusSwitchRecord;

const PERPLEXITY_ANOMALY_THRESHOLD: f64 = 15.0;
const MIN_IKI_FOR_HURST: usize = 50;
const STEG_LOW_CONF: f64 = 0.3;
const STEG_HIGH_CONF: f64 = 0.95;
const STEG_PENALTY: f64 = 0.20;
const STEG_ALERT_THRESHOLD: f64 = 0.8;
const MIN_IKI_FOR_LABYRINTH: usize = 50;
pub(crate) const PER_CHECKPOINT_SUSPICIOUS_THRESHOLD: f64 = 0.3;
const PER_CHECKPOINT_ROBOTIC_CV: f64 = 0.10;

/// Minimum plausible timestamp (2000-01-01 in nanoseconds).
const MIN_PLAUSIBLE_TS_NS: i64 = 946_684_800_000_000_000;
/// Maximum plausible timestamp (2100-01-01 in nanoseconds).
const MAX_PLAUSIBLE_TS_NS: i64 = 4_102_444_800_000_000_000;

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

    // Clone + sort is required because the function takes &[EventData] (shared
    // reference) and callers rely on the original order being preserved.
    let mut sorted = events.to_vec();
    sorted.sort_unstable_by_key(|e| e.timestamp_ns);

    // Clamp implausible timestamps to prevent corrupt time_span calculations
    for event in &mut sorted {
        event.timestamp_ns = event
            .timestamp_ns
            .clamp(MIN_PLAUSIBLE_TS_NS, MAX_PLAUSIBLE_TS_NS);
    }

    let file_path = sorted
        .first()
        .map(|e| e.file_path.clone())
        .unwrap_or_default();
    let first_ts =
        DateTime::from_timestamp_nanos(sorted.first().map(|e| e.timestamp_ns).unwrap_or(0));
    let last_ts =
        DateTime::from_timestamp_nanos(sorted.last().map(|e| e.timestamp_ns).unwrap_or(0));
    let time_span = last_ts.signed_duration_since(first_ts);

    let session_count = count_sessions_sorted(&sorted, DEFAULT_SESSION_GAP_SEC);

    let metrics = match compute_primary_metrics(&sorted, regions_by_event) {
        Ok(m) => m,
        Err(_) => {
            return AuthorshipProfile {
                file_path,
                event_count: events.len(),
                time_span,
                session_count,
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
        session_count,
        first_event: first_ts,
        last_event: last_ts,
        metrics,
        anomalies,
        assessment,
    }
}

#[derive(Default)]
pub struct AnalysisContext {
    pub document_length: i64,
    pub total_keystrokes: i64,
    pub checkpoint_count: u64,
}

pub fn analyze_forensics(
    events: &[EventData],
    regions: &HashMap<i64, Vec<RegionData>>,
    jitter_samples: Option<&[SimpleJitterSample]>,
    perplexity_model: Option<&crate::analysis::perplexity::PerplexityModel>,
    document_text: Option<&str>,
) -> ForensicMetrics {
    analyze_forensics_ext(
        events,
        regions,
        jitter_samples,
        perplexity_model,
        document_text,
        &AnalysisContext::default(),
    )
}

pub fn analyze_forensics_ext(
    events: &[EventData],
    regions: &HashMap<i64, Vec<RegionData>>,
    jitter_samples: Option<&[SimpleJitterSample]>,
    perplexity_model: Option<&crate::analysis::perplexity::PerplexityModel>,
    document_text: Option<&str>,
    context: &AnalysisContext,
) -> ForensicMetrics {
    analyze_forensics_ext_with_focus(
        events,
        regions,
        jitter_samples,
        perplexity_model,
        document_text,
        context,
        None,
    )
}

pub fn analyze_forensics_ext_with_focus(
    events: &[EventData],
    regions: &HashMap<i64, Vec<RegionData>>,
    jitter_samples: Option<&[SimpleJitterSample]>,
    perplexity_model: Option<&crate::analysis::perplexity::PerplexityModel>,
    document_text: Option<&str>,
    context: &AnalysisContext,
    focus_metrics: Option<FocusMetrics>,
) -> ForensicMetrics {
    let mut metrics = ForensicMetrics::default();

    if let (Some(model), Some(text)) = (perplexity_model, document_text) {
        let score = model.compute_perplexity(text);
        metrics.perplexity_score = if score.is_finite() {
            score
        } else {
            log::warn!("perplexity_score is non-finite ({score}); substituting 1.0");
            1.0
        };
        if metrics.perplexity_score > PERPLEXITY_ANOMALY_THRESHOLD {
            metrics.anomaly_count += 1;
        }
    } else {
        metrics.perplexity_score = 1.0;
    }

    if let Ok(primary) = compute_primary_metrics(events, regions) {
        metrics.primary = primary;
    }

    if let Some(samples) = jitter_samples {
        metrics.cadence = analyze_cadence(samples);

        let iki_intervals: Vec<f64> = samples
            .windows(2)
            .filter_map(|w| {
                w[1].timestamp_ns
                    .checked_sub(w[0].timestamp_ns)
                    .map(|d| d as f64)
            })
            .filter(|&d| d > 0.0)
            .collect();
        if iki_intervals.len() >= MIN_IKI_FOR_HURST {
            if let Ok(hurst) = crate::analysis::hurst::compute_hurst_rs(&iki_intervals) {
                metrics.hurst_exponent = Some(hurst.exponent);
            }
        }

        metrics.biological_cadence_score =
            crate::physics::biological::BiologicalCadence::analyze(samples);

        let fingerprint = BehavioralFingerprint::from_samples(samples);
        metrics.behavioral = Some(fingerprint);

        let forgery = BehavioralFingerprint::detect_forgery(samples);
        metrics.forgery_analysis = Some(forgery.clone());

        // CV-based heuristic: higher timing variability correlates with genuine human input.
        // Degenerate inputs (< 2 samples) yield a default CV of 0.0 — return 0.0 confidence
        // since no meaningful inference is possible.
        let cv = metrics.cadence.coefficient_of_variation;
        metrics.steg_confidence = if samples.len() < 2 || !cv.is_finite() {
            0.0
        } else if cv > STEG_LOW_CONF {
            STEG_HIGH_CONF
        } else {
            STEG_PENALTY
        };

        // Steg looks valid but behavioral is suspicious — likely a perfect replay attack
        if forgery.is_suspicious && metrics.steg_confidence > STEG_ALERT_THRESHOLD {
            metrics.anomaly_count += 1;
        }

        // SNR analysis
        if let Some(snr) = analyze_snr(&iki_intervals) {
            if snr.flagged {
                metrics.anomaly_count += 1;
            }
            metrics.snr = Some(snr);
        }

        // Lyapunov exponent analysis
        if let Some(lyap) = analyze_lyapunov(&iki_intervals) {
            if lyap.flagged {
                metrics.anomaly_count += 1;
            }
            metrics.lyapunov = Some(lyap);
        }

        // IKI compression ratio analysis
        if let Some(comp) = analyze_iki_compression(&iki_intervals) {
            if comp.flagged {
                metrics.anomaly_count += 1;
            }
            metrics.iki_compression = Some(comp);
        }

        // Labyrinth (Takens' embedding) analysis
        if iki_intervals.len() >= MIN_IKI_FOR_LABYRINTH {
            let params = LabyrinthParams::default();
            if let Ok(lab) = analyze_labyrinth(&iki_intervals, &[], &params) {
                if !lab.is_biologically_plausible() {
                    metrics.anomaly_count += 1;
                }
                metrics.labyrinth = Some(lab);
            }
        }
    }

    metrics.velocity = super::velocity::analyze_velocity(events);
    metrics.session_stats = compute_session_stats(events);
    metrics.checkpoint_count = context.checkpoint_count as usize;

    let anomalies = detect_anomalies(events, regions, &metrics.primary);
    metrics.anomaly_count += anomalies.len();

    // Skip cross-modal when context is default/unpopulated to avoid false positives
    let skip_cross_modal = context.checkpoint_count == 0 && context.document_length == 0;

    if !skip_cross_modal {
        let cm_input = super::cross_modal::CrossModalInput {
            events,
            jitter_samples,
            document_length: context.document_length,
            total_keystrokes: context.total_keystrokes,
            checkpoint_count: context.checkpoint_count,
            session_duration_sec: metrics.session_stats.total_editing_time_sec,
        };
        let cm_result = super::cross_modal::analyze_cross_modal(&cm_input);

        let cm_penalty = match cm_result.verdict {
            super::cross_modal::CrossModalVerdict::Inconsistent => 2,
            super::cross_modal::CrossModalVerdict::Marginal => 1,
            _ => 0,
        };
        metrics.anomaly_count += cm_penalty;
        metrics.cross_modal = Some(cm_result);
    }

    metrics.assessment_score = compute_assessment_score(
        &metrics.primary,
        &metrics.cadence,
        metrics.anomaly_count,
        events.len(),
        metrics.biological_cadence_score,
    );
    if let Some(focus) = focus_metrics {
        metrics.focus = focus;
        apply_focus_penalties(&mut metrics.assessment_score, &metrics.focus);
    }

    metrics.risk_level = determine_risk_level(metrics.assessment_score, events.len());

    metrics.writing_mode = Some(super::writing_mode::classify_writing_mode(
        &metrics.primary,
        &metrics.cadence,
        events,
        events.len(),
    ));

    metrics
}

/// Analyze events partitioned by checkpoint boundaries.
pub fn per_checkpoint_flags(
    events: &[EventData],
    checkpoints: &[CheckpointProof],
) -> PerCheckpointResult {
    if checkpoints.is_empty() {
        return PerCheckpointResult {
            checkpoint_flags: Vec::new(),
            pct_flagged: 0.0,
            suspicious: false,
        };
    }

    let mut sorted_events = events.to_vec();
    sorted_events.sort_by_key(|e| e.timestamp_ns);

    let mut flags = Vec::with_capacity(checkpoints.len());

    for (idx, cp) in checkpoints.iter().enumerate() {
        let cp_ts = cp.timestamp.timestamp_nanos_opt().unwrap_or(i64::MAX);
        let prev_ts = if idx > 0 {
            checkpoints[idx - 1]
                .timestamp
                .timestamp_nanos_opt()
                .unwrap_or(0)
        } else {
            0
        };

        let start_idx = sorted_events.partition_point(|e| e.timestamp_ns <= prev_ts);
        let end_idx = sorted_events.partition_point(|e| e.timestamp_ns <= cp_ts);
        let interval_events: Vec<&EventData> = sorted_events[start_idx..end_idx].iter().collect();

        let event_count = interval_events.len();

        let timing_cv = if event_count >= 2 {
            let intervals: Vec<f64> = interval_events
                .windows(2)
                .map(|w| w[1].timestamp_ns.saturating_sub(w[0].timestamp_ns) as f64)
                .collect();
            let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
            if mean > f64::EPSILON {
                let variance = intervals.iter().map(|&x| (x - mean).powi(2)).sum::<f64>()
                    / intervals.len() as f64;
                if mean.is_finite() && variance.is_finite() {
                    crate::utils::finite_or(variance.sqrt() / mean, 0.0)
                } else {
                    0.0
                }
            } else {
                0.0
            }
        } else {
            0.0
        };

        let max_velocity_bps = if event_count >= 2 {
            interval_events
                .windows(2)
                .map(|w| {
                    let dt = w[1].timestamp_ns.saturating_sub(w[0].timestamp_ns) as f64 / 1e9;
                    if dt > 0.0 {
                        w[1].size_delta.unsigned_abs() as f64 / dt
                    } else {
                        0.0
                    }
                })
                .fold(0.0f64, f64::max)
        } else {
            0.0
        };

        let all_append = if event_count > 0 {
            interval_events.iter().all(|e| e.size_delta >= 0)
        } else {
            false
        };

        let flagged = (timing_cv < PER_CHECKPOINT_ROBOTIC_CV && event_count >= 3)
            || (all_append && event_count >= 5);

        flags.push(CheckpointFlags {
            ordinal: cp.ordinal,
            event_count,
            timing_cv,
            max_velocity_bps,
            all_append,
            flagged,
        });
    }

    let flagged_count = flags.iter().filter(|f| f.flagged).count();
    let pct_flagged = if flags.is_empty() {
        0.0
    } else {
        flagged_count as f64 / flags.len() as f64
    };
    let suspicious = pct_flagged > PER_CHECKPOINT_SUSPICIOUS_THRESHOLD;

    PerCheckpointResult {
        checkpoint_flags: flags,
        pct_flagged,
        suspicious,
    }
}

/// Bundle IDs of known AI assistant apps.
const AI_APP_BUNDLE_IDS: &[&str] = &["chatgpt", "claude", "openai", "copilot", "bard", "gemini"];

/// Browser bundle IDs that may indicate quick AI/reference lookups.
const BROWSER_BUNDLE_IDS: &[&str] = &[
    "com.apple.Safari",
    "com.google.Chrome",
    "org.mozilla.firefox",
    "com.microsoft.edgemac",
    "com.brave.Browser",
];

/// Short away duration threshold (seconds) for browser-as-AI-reference heuristic.
const BROWSER_SHORT_AWAY_SEC: f64 = 30.0;

/// Short switch threshold (seconds) for reading-pattern detection.
const READING_PATTERN_SWITCH_SEC: f64 = 10.0;

/// Minimum repeated short switches to the same app to flag a reading pattern.
const READING_PATTERN_MIN_REPEATS: usize = 3;

/// Analyze focus-switching patterns for cognitive vs. transcriptive signals.
pub fn analyze_focus_patterns(
    switches: &[FocusSwitchRecord],
    total_session_ms: i64,
) -> FocusMetrics {
    if switches.is_empty() || total_session_ms <= 0 {
        return FocusMetrics::default();
    }

    let switch_count = switches.len();
    let mut total_away_sec = 0.0;
    let mut completed_count = 0usize;
    let mut ai_app_switch_count = 0usize;

    for sw in switches {
        let away_sec = sw
            .regained_at
            .and_then(|r| r.duration_since(sw.lost_at).ok())
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);

        if sw.regained_at.is_some() {
            total_away_sec += away_sec;
            completed_count += 1;
        }

        let bid_lower = sw.target_bundle_id.to_lowercase();
        let app_lower = sw.target_app.to_lowercase();

        let is_ai_app = AI_APP_BUNDLE_IDS
            .iter()
            .any(|pat| bid_lower.contains(pat) || app_lower.contains(pat));

        let is_browser_short = BROWSER_BUNDLE_IDS
            .iter()
            .any(|b| bid_lower == b.to_lowercase())
            && away_sec > 0.0
            && away_sec < BROWSER_SHORT_AWAY_SEC;

        if is_ai_app || is_browser_short {
            ai_app_switch_count += 1;
        }
    }

    let total_session_sec = total_session_ms as f64 / 1000.0;
    let out_of_focus_ratio = if total_session_sec > f64::EPSILON {
        (total_away_sec / total_session_sec).min(1.0)
    } else {
        0.0
    };
    let avg_away_duration_sec = if completed_count > 0 {
        total_away_sec / completed_count as f64
    } else {
        0.0
    };

    // Detect reading pattern: repeated short switches to the same app.
    let reading_pattern_detected = detect_reading_pattern(switches);

    FocusMetrics {
        switch_count,
        out_of_focus_ratio,
        ai_app_switch_count,
        avg_away_duration_sec,
        reading_pattern_detected,
    }
}

/// Detect a copy-reference workflow: frequent short switches (<10s) to the same app.
fn detect_reading_pattern(switches: &[FocusSwitchRecord]) -> bool {
    // Group completed short switches by target bundle ID.
    let mut short_counts: HashMap<&str, usize> = HashMap::new();
    let mut short_durations: Vec<f64> = Vec::new();
    for sw in switches {
        let away_sec = sw
            .regained_at
            .and_then(|r| r.duration_since(sw.lost_at).ok())
            .map(|d| d.as_secs_f64())
            .unwrap_or(f64::MAX);

        if away_sec < READING_PATTERN_SWITCH_SEC {
            *short_counts
                .entry(sw.target_bundle_id.as_str())
                .or_insert(0) += 1;
            short_durations.push(away_sec);
        }
    }

    let frequent = short_counts
        .values()
        .any(|&count| count >= READING_PATTERN_MIN_REPEATS);

    // Also detect regular-interval switching: if the CV of short switch
    // durations is very low, the pattern is mechanically regular (stronger
    // transcription signal than just frequency).
    let regular_interval = if short_durations.len() >= READING_PATTERN_MIN_REPEATS {
        let mean = short_durations.iter().sum::<f64>() / short_durations.len() as f64;
        if mean > 0.0 {
            let var = short_durations
                .iter()
                .map(|d| (d - mean).powi(2))
                .sum::<f64>()
                / short_durations.len() as f64;
            let cv = var.sqrt() / mean;
            cv < 0.3 // Very regular intervals
        } else {
            false
        }
    } else {
        false
    };

    frequent || regular_interval
}
