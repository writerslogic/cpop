// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Anomaly detection and assessment.

use chrono::DateTime;
use std::collections::HashMap;

use super::types::{
    Anomaly, AnomalyType, Assessment, CadenceMetrics, EventData, PrimaryMetrics, RegionData,
    RiskLevel, Severity, ALERT_THRESHOLD, MIN_EVENTS_FOR_ANALYSIS, MIN_EVENTS_FOR_ASSESSMENT,
    THRESHOLD_GAP_HOURS, THRESHOLD_HIGH_VELOCITY_BPS, THRESHOLD_LOW_ENTROPY,
    THRESHOLD_MONOTONIC_APPEND,
};

/// Max Shannon entropy for 20-bin edit-position histogram: log2(20).
const ENTROPY_NORMALIZATION: f64 = 4.321928;
/// Below this normalized entropy, editing pattern is suspiciously ordered.
const LOW_ENTROPY_SCORE_THRESHOLD: f64 = 0.35;
/// Monotonic append ratio above which penalty starts.
const MONOTONIC_PENALTY_START: f64 = 0.85;
/// Coefficient of variation below which typing cadence is suspiciously uniform.
const CV_ROBOTIC_THRESHOLD: f64 = 0.2;
/// Per-anomaly penalty in authenticity score.
const ANOMALY_PENALTY: f64 = 0.05;

/// Detect anomalies in editing patterns (topology + temporal).
pub fn detect_anomalies(
    events: &[EventData],
    regions: &HashMap<i64, Vec<RegionData>>,
    metrics: &PrimaryMetrics,
) -> Vec<Anomaly> {
    let mut anomalies = Vec::new();

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

    if metrics.edit_entropy < THRESHOLD_LOW_ENTROPY && metrics.edit_entropy > 0.0 {
        anomalies.push(Anomaly {
            timestamp: None,
            anomaly_type: AnomalyType::LowEntropy,
            description: "Low edit entropy indicates concentrated editing patterns".to_string(),
            severity: Severity::Warning,
            context: Some(format!("Entropy: {:.3}", metrics.edit_entropy)),
        });
    }

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

    anomalies.extend(detect_temporal_anomalies(events, regions));

    anomalies
}

/// Detect temporal gaps and high-velocity editing periods.
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

        if delta_hours > THRESHOLD_GAP_HOURS {
            anomalies.push(Anomaly {
                timestamp: Some(DateTime::from_timestamp_nanos(curr.timestamp_ns)),
                anomaly_type: AnomalyType::Gap,
                description: "Long editing gap detected".to_string(),
                severity: Severity::Info,
                context: Some(format!("Gap: {:.1} hours", delta_hours)),
            });
        }

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

/// Determine overall assessment verdict from metrics and anomalies.
pub fn determine_assessment(
    metrics: &PrimaryMetrics,
    anomalies: &[Anomaly],
    event_count: usize,
) -> Assessment {
    if event_count < MIN_EVENTS_FOR_ASSESSMENT {
        return Assessment::Insufficient;
    }

    let (alert_count, warning_count) =
        anomalies
            .iter()
            .fold((0, 0), |(a, w), anom| match anom.severity {
                Severity::Alert => (a + 1, w),
                Severity::Warning => (a, w + 1),
                _ => (a, w),
            });

    let mut suspicious_indicators = 0;

    if metrics.monotonic_append_ratio > 0.90 {
        suspicious_indicators += 1;
    }

    if metrics.edit_entropy < THRESHOLD_LOW_ENTROPY && metrics.edit_entropy > 0.0 {
        suspicious_indicators += 1;
    }

    if metrics.positive_negative_ratio > 0.95 {
        suspicious_indicators += 1;
    }

    if metrics.deletion_clustering > 0.9 && metrics.deletion_clustering < 1.1 {
        suspicious_indicators += 1;
    }

    if alert_count >= ALERT_THRESHOLD || suspicious_indicators >= 3 {
        return Assessment::Suspicious;
    }

    if warning_count >= 3 || suspicious_indicators >= 2 {
        return Assessment::Suspicious;
    }

    Assessment::Consistent
}

/// Overall assessment score in `[0.0, 1.0]` (higher = more human-like).
pub fn calculate_assessment_score(
    primary: &PrimaryMetrics,
    cadence: &CadenceMetrics,
    anomaly_count: usize,
    event_count: usize,
    biological_cadence_score: f64,
) -> f64 {
    if event_count < MIN_EVENTS_FOR_ANALYSIS {
        return 0.5;
    }

    let mut score = 1.0;

    if primary.monotonic_append_ratio > MONOTONIC_PENALTY_START {
        score -= 0.2 * (primary.monotonic_append_ratio - MONOTONIC_PENALTY_START)
            / (1.0 - MONOTONIC_PENALTY_START);
    }

    let normalized_entropy = primary.edit_entropy / ENTROPY_NORMALIZATION;
    if normalized_entropy < LOW_ENTROPY_SCORE_THRESHOLD {
        score -= 0.15;
    }

    if primary.positive_negative_ratio > 0.95 {
        score -= 0.1;
    }

    if primary.deletion_clustering > 0.9 && primary.deletion_clustering < 1.1 {
        score -= 0.1;
    }

    if cadence.is_robotic {
        score -= 0.35;
    }

    if cadence.coefficient_of_variation < CV_ROBOTIC_THRESHOLD {
        score -=
            0.15 * (CV_ROBOTIC_THRESHOLD - cadence.coefficient_of_variation) / CV_ROBOTIC_THRESHOLD;
    }

    score -= ANOMALY_PENALTY * anomaly_count as f64;

    // Reward steady biological cadence (supports human authorship)
    if biological_cadence_score > 0.5 {
        score += 0.05 * (biological_cadence_score - 0.5) / 0.5;
    }

    score.clamp(0.0, 1.0)
}

/// Quick cadence-only score for real-time use before full topology is available.
pub fn calculate_cadence_score(cadence: &CadenceMetrics) -> f64 {
    let mut score = 1.0;

    if cadence.is_robotic {
        score -= 0.5;
    }

    if cadence.coefficient_of_variation < 0.2 {
        let penalty = (0.2 - cadence.coefficient_of_variation) / 0.2;
        score -= 0.2 * penalty;
    }

    if cadence.percentiles[4] == 0.0 {
        return 0.5;
    }

    score.clamp(0.0, 1.0)
}

/// Map assessment score to risk level.
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
