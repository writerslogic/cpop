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

const PERPLEXITY_ANOMALY_THRESHOLD: f64 = 15.0;
const MIN_IKI_FOR_HURST: usize = 50;
const STEG_LOW_CONF: f64 = 0.3;
const STEG_HIGH_CONF: f64 = 0.95;
const STEG_PENALTY: f64 = 0.20;
const STEG_ALERT_THRESHOLD: f64 = 0.8;

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
