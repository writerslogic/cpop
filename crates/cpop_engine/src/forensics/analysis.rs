// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Main orchestration functions for forensic analysis.

use chrono::DateTime;
use std::collections::HashMap;

use crate::analysis::BehavioralFingerprint;
use crate::jitter::SimpleJitterSample;

use super::assessment::{
    compute_assessment_score, detect_anomalies, determine_assessment, determine_risk_level,
};
use super::cadence::analyze_cadence;
use super::topology::compute_primary_metrics;
use super::types::{
    Assessment, AuthorshipProfile, EventData, ForensicMetrics, RegionData, DEFAULT_SESSION_GAP_SEC,
    MIN_EVENTS_FOR_ANALYSIS,
};
use super::velocity::{compute_session_stats, count_sessions_sorted};

use super::types::{CheckpointFlags, PerCheckpointResult};
use crate::analysis::labyrinth::{analyze_labyrinth, LabyrinthParams};
use crate::analysis::{analyze_iki_compression, analyze_lyapunov, analyze_snr};
use crate::evidence::CheckpointProof;

const PERPLEXITY_ANOMALY_THRESHOLD: f64 = 15.0;
const MIN_IKI_FOR_HURST: usize = 50;
const STEG_LOW_CONF: f64 = 0.3;
const STEG_HIGH_CONF: f64 = 0.95;
const STEG_PENALTY: f64 = 0.20;
const STEG_ALERT_THRESHOLD: f64 = 0.8;
const MIN_IKI_FOR_LABYRINTH: usize = 50;
const PER_CHECKPOINT_SUSPICIOUS_THRESHOLD: f64 = 0.3;
const PER_CHECKPOINT_ROBOTIC_CV: f64 = 0.10;

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
    let mut metrics = ForensicMetrics::default();

    if let (Some(model), Some(text)) = (perplexity_model, document_text) {
        metrics.perplexity_score = model.compute_perplexity(text);
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
            .map(|w| (w[1].timestamp_ns - w[0].timestamp_ns) as f64)
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
            if let Ok(lab) = analyze_labyrinth(&iki_intervals, &params) {
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

    metrics.risk_level = determine_risk_level(metrics.assessment_score, events.len());

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

        let interval_events: Vec<&EventData> = sorted_events
            .iter()
            .filter(|e| e.timestamp_ns > prev_ts && e.timestamp_ns <= cp_ts)
            .collect();

        let event_count = interval_events.len();

        let timing_cv = if event_count >= 2 {
            let intervals: Vec<f64> = interval_events
                .windows(2)
                .map(|w| (w[1].timestamp_ns - w[0].timestamp_ns) as f64)
                .collect();
            let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
            if mean > 0.0 {
                let variance = intervals.iter().map(|&x| (x - mean).powi(2)).sum::<f64>()
                    / intervals.len() as f64;
                variance.sqrt() / mean
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
                    let dt = (w[1].timestamp_ns - w[0].timestamp_ns) as f64 / 1e9;
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
