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

/// Deletion clustering lower bound for scattered-deletion anomaly.
const DELETION_CLUSTERING_LOW: f64 = 0.9;
/// Deletion clustering upper bound for scattered-deletion anomaly.
const DELETION_CLUSTERING_HIGH: f64 = 1.1;
/// Monotonic append ratio for "suspicious" verdict (stricter than penalty start).
const MONOTONIC_SUSPICIOUS: f64 = 0.90;
/// Positive-to-negative edit ratio above which pattern is suspicious.
const POS_NEG_SUSPICIOUS: f64 = 0.95;
/// Default score when insufficient data is available.
const INSUFFICIENT_DATA_SCORE: f64 = 0.5;
/// Penalty multiplier for high monotonic append ratio.
const MONOTONIC_PENALTY_WEIGHT: f64 = 0.2;
/// Penalty for low normalized edit entropy.
const LOW_ENTROPY_PENALTY: f64 = 0.15;
/// Penalty for high positive/negative edit ratio.
const POS_NEG_PENALTY: f64 = 0.1;
/// Penalty when cadence is flagged robotic.
const ROBOTIC_CADENCE_PENALTY: f64 = 0.35;
/// Penalty multiplier for low coefficient of variation.
const COV_PENALTY_WEIGHT: f64 = 0.15;
/// Biological cadence score above which a reward is applied.
const BIOLOGICAL_CADENCE_THRESHOLD: f64 = 0.5;
/// Maximum reward for biological cadence evidence.
const BIOLOGICAL_CADENCE_REWARD: f64 = 0.05;
/// Cadence-only penalty for robotic flag.
const CADENCE_ROBOTIC_PENALTY: f64 = 0.5;
/// Cadence-only penalty multiplier for low CoV.
const CADENCE_COV_PENALTY: f64 = 0.2;
/// Assessment score at or above which risk is Low.
const RISK_LOW_THRESHOLD: f64 = 0.7;
/// Assessment score at or above which risk is Medium (below Low).
const RISK_MEDIUM_THRESHOLD: f64 = 0.4;
/// Warning count triggering suspicious verdict.
const SUSPICIOUS_WARNING_COUNT: usize = 3;
/// Indicator count triggering suspicious verdict.
const SUSPICIOUS_INDICATOR_COUNT: usize = 2;
/// Indicator count triggering immediate suspicious verdict.
const SUSPICIOUS_INDICATOR_CRITICAL: usize = 3;
/// Maximum inter-event delta (seconds) for velocity anomaly detection.
const VELOCITY_WINDOW_SEC: f64 = 60.0;

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

    if metrics.deletion_clustering > DELETION_CLUSTERING_LOW
        && metrics.deletion_clustering < DELETION_CLUSTERING_HIGH
    {
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

        if delta_sec > 0.0 && delta_sec < VELOCITY_WINDOW_SEC {
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

    if metrics.monotonic_append_ratio > MONOTONIC_SUSPICIOUS {
        suspicious_indicators += 1;
    }

    if metrics.edit_entropy < THRESHOLD_LOW_ENTROPY && metrics.edit_entropy > 0.0 {
        suspicious_indicators += 1;
    }

    if metrics.positive_negative_ratio > POS_NEG_SUSPICIOUS {
        suspicious_indicators += 1;
    }

    if metrics.deletion_clustering > DELETION_CLUSTERING_LOW
        && metrics.deletion_clustering < DELETION_CLUSTERING_HIGH
    {
        suspicious_indicators += 1;
    }

    if alert_count >= ALERT_THRESHOLD || suspicious_indicators >= SUSPICIOUS_INDICATOR_CRITICAL {
        return Assessment::Suspicious;
    }

    if warning_count >= SUSPICIOUS_WARNING_COUNT
        || suspicious_indicators >= SUSPICIOUS_INDICATOR_COUNT
    {
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
        return INSUFFICIENT_DATA_SCORE;
    }

    let mut score = 1.0;

    if primary.monotonic_append_ratio > MONOTONIC_PENALTY_START {
        score -= MONOTONIC_PENALTY_WEIGHT
            * (primary.monotonic_append_ratio - MONOTONIC_PENALTY_START)
            / (1.0 - MONOTONIC_PENALTY_START);
    }

    let normalized_entropy = primary.edit_entropy / ENTROPY_NORMALIZATION;
    if normalized_entropy < LOW_ENTROPY_SCORE_THRESHOLD {
        score -= LOW_ENTROPY_PENALTY;
    }

    if primary.positive_negative_ratio > POS_NEG_SUSPICIOUS {
        score -= POS_NEG_PENALTY;
    }

    if primary.deletion_clustering > DELETION_CLUSTERING_LOW
        && primary.deletion_clustering < DELETION_CLUSTERING_HIGH
    {
        score -= POS_NEG_PENALTY;
    }

    if cadence.is_robotic {
        score -= ROBOTIC_CADENCE_PENALTY;
    }

    if cadence.coefficient_of_variation < CV_ROBOTIC_THRESHOLD {
        score -= COV_PENALTY_WEIGHT * (CV_ROBOTIC_THRESHOLD - cadence.coefficient_of_variation)
            / CV_ROBOTIC_THRESHOLD;
    }

    score -= ANOMALY_PENALTY * anomaly_count as f64;

    if biological_cadence_score > BIOLOGICAL_CADENCE_THRESHOLD {
        score += BIOLOGICAL_CADENCE_REWARD
            * (biological_cadence_score - BIOLOGICAL_CADENCE_THRESHOLD)
            / BIOLOGICAL_CADENCE_THRESHOLD;
    }

    score.clamp(0.0, 1.0)
}

/// Quick cadence-only score for real-time use before full topology is available.
pub fn calculate_cadence_score(cadence: &CadenceMetrics) -> f64 {
    let mut score = 1.0;

    if cadence.is_robotic {
        score -= CADENCE_ROBOTIC_PENALTY;
    }

    if cadence.coefficient_of_variation < CV_ROBOTIC_THRESHOLD {
        let penalty =
            (CV_ROBOTIC_THRESHOLD - cadence.coefficient_of_variation) / CV_ROBOTIC_THRESHOLD;
        score -= CADENCE_COV_PENALTY * penalty;
    }

    if cadence.percentiles[4] == 0.0 {
        return INSUFFICIENT_DATA_SCORE;
    }

    score.clamp(0.0, 1.0)
}

/// Map assessment score to risk level.
pub fn determine_risk_level(score: f64, event_count: usize) -> RiskLevel {
    if event_count < MIN_EVENTS_FOR_ANALYSIS {
        return RiskLevel::Insufficient;
    }

    if score >= RISK_LOW_THRESHOLD {
        RiskLevel::Low
    } else if score >= RISK_MEDIUM_THRESHOLD {
        RiskLevel::Medium
    } else {
        RiskLevel::High
    }
}
