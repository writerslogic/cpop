// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Velocity analysis and session detection.

use super::types::{
    EventData, SessionStats, VelocityMetrics, DEFAULT_SESSION_GAP_SEC, THRESHOLD_HIGH_VELOCITY_BPS,
};

/// Analyze edit velocity patterns (bytes/sec).
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

/// Count sessions in pre-sorted events without cloning.
pub fn count_sessions_sorted(sorted_events: &[EventData], gap_threshold_sec: f64) -> usize {
    if sorted_events.is_empty() {
        return 0;
    }
    let mut count = 1;
    for i in 1..sorted_events.len() {
        let delta_ns = sorted_events[i].timestamp_ns - sorted_events[i - 1].timestamp_ns;
        if delta_ns as f64 / 1e9 > gap_threshold_sec {
            count += 1;
        }
    }
    count
}

/// Split events into sessions using `gap_threshold_sec`.
pub fn detect_sessions(events: &[EventData], gap_threshold_sec: f64) -> Vec<Vec<EventData>> {
    if events.is_empty() {
        return Vec::new();
    }

    let mut sorted = events.to_vec();
    sorted.sort_by_key(|e| e.timestamp_ns);

    // Find split points, then split_off to move data without cloning again.
    let mut split_at: Vec<usize> = Vec::new();
    for i in 1..sorted.len() {
        let delta_ns = sorted[i].timestamp_ns - sorted[i - 1].timestamp_ns;
        if delta_ns as f64 / 1e9 > gap_threshold_sec {
            split_at.push(i);
        }
    }

    let mut sessions = Vec::with_capacity(split_at.len() + 1);
    let mut rest = sorted;
    for &idx in split_at.iter().rev() {
        sessions.push(rest.split_off(idx));
    }
    sessions.push(rest);
    sessions.reverse();
    sessions
}

/// Compute aggregate session statistics.
pub fn compute_session_stats(events: &[EventData]) -> SessionStats {
    let mut stats = SessionStats::default();

    if events.is_empty() {
        return stats;
    }

    let sessions = detect_sessions(events, DEFAULT_SESSION_GAP_SEC);
    stats.session_count = sessions.len();

    let mut total_duration = 0.0;
    for session in &sessions {
        // Sessions are already sorted by timestamp_ns.
        if session.len() >= 2 {
            let first = session.first().unwrap().timestamp_ns;
            let last = session.last().unwrap().timestamp_ns;
            total_duration += (last - first) as f64 / 1e9;
        }
    }

    stats.total_editing_time_sec = total_duration;
    if stats.session_count > 0 {
        stats.avg_session_duration_sec = total_duration / stats.session_count as f64;
    }

    let first = sessions
        .first()
        .and_then(|s| s.first())
        .map_or(0, |e| e.timestamp_ns);
    let last = sessions
        .last()
        .and_then(|s| s.last())
        .map_or(0, |e| e.timestamp_ns);
    stats.time_span_sec = (last - first) as f64 / 1e9;

    stats
}
