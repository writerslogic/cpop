// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Main orchestration functions for forensic analysis.

use chrono::DateTime;
use std::collections::HashMap;

use crate::analysis::BehavioralFingerprint;
use crate::jitter::SimpleJitterSample;

use super::assessment::{
    calculate_assessment_score, detect_anomalies, determine_assessment, determine_risk_level,
};
use super::cadence::analyze_cadence;
use super::topology::compute_primary_metrics;
use super::types::{
    Assessment, AuthorshipProfile, EventData, ForensicMetrics, RegionData, DEFAULT_SESSION_GAP_SEC,
    MIN_EVENTS_FOR_ANALYSIS,
};
use super::velocity::{compute_session_stats, count_sessions_sorted};

/// Build a complete authorship profile from events and edit regions.
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

/// Run comprehensive forensic analysis across all dimensions.
pub fn analyze_forensics(
    events: &[EventData],
    regions: &HashMap<i64, Vec<RegionData>>,
    jitter_samples: Option<&[SimpleJitterSample]>,
    perplexity_model: Option<&crate::analysis::perplexity::PerplexityModel>,
    document_text: Option<&str>,
) -> ForensicMetrics {
    let mut metrics = ForensicMetrics::default();

    if let (Some(model), Some(text)) = (perplexity_model, document_text) {
        metrics.perplexity_score = model.calculate_perplexity(text);
        if metrics.perplexity_score > 15.0 {
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

        // Biological cadence steadiness
        metrics.biological_cadence_score =
            crate::physics::biological::BiologicalCadence::analyze(samples);

        let fingerprint = BehavioralFingerprint::from_samples(samples);
        metrics.behavioral = Some(fingerprint);

        let forgery = BehavioralFingerprint::detect_forgery(samples);
        metrics.forgery_analysis = Some(forgery.clone());

        // TODO: verify HMAC-jitter values; for now, approximate via CV
        metrics.steg_confidence = if metrics.cadence.coefficient_of_variation > 0.3 {
            0.95
        } else {
            0.20
        };

        // "Perfect Replay" detection: steg looks valid but behavioral is suspicious
        if forgery.is_suspicious && metrics.steg_confidence > 0.8 {
            metrics.anomaly_count += 1;
        }
    }

    metrics.velocity = super::velocity::analyze_velocity(events);
    metrics.session_stats = compute_session_stats(events);

    let anomalies = detect_anomalies(events, regions, &metrics.primary);
    metrics.anomaly_count += anomalies.len();

    metrics.assessment_score = calculate_assessment_score(
        &metrics.primary,
        &metrics.cadence,
        metrics.anomaly_count,
        events.len(),
        metrics.biological_cadence_score,
    );

    metrics.risk_level = determine_risk_level(metrics.assessment_score, events.len());

    metrics
}
