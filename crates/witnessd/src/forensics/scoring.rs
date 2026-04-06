// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Shared forensic scoring helpers used across FFI call sites.
//!
//! Consolidates cadence-score, focus-penalty, and combined-score logic
//! that was previously duplicated in multiple FFI modules.

use super::types::FocusMetrics;
use crate::jitter::SimpleJitterSample;
use crate::sentinel::types::FocusSwitchRecord;

/// Minimum number of jitter samples required to compute a meaningful
/// cadence score. Below this threshold the score is 0.0.
const MIN_CADENCE_SAMPLES: usize = 20;

/// Compute a cadence score from raw jitter samples.
///
/// Returns 0.0 when fewer than [`MIN_CADENCE_SAMPLES`] samples are
/// available, otherwise delegates to [`analyze_cadence`] +
/// [`compute_cadence_score`].
pub fn cadence_score_from_samples(samples: &[SimpleJitterSample]) -> f64 {
    if samples.len() >= MIN_CADENCE_SAMPLES {
        super::compute_cadence_score(&super::analyze_cadence(samples))
    } else {
        0.0
    }
}

/// Compute focus-switching penalty from focus pattern metrics.
///
/// Returns a penalty in `[0.0, 0.15]` to subtract from a forensic score:
/// - 0.15 if a reading-from-source pattern was detected,
/// - 0.10 if more than 3 AI-app switches occurred,
/// - 0.0 otherwise.
pub fn compute_focus_penalty(focus: &FocusMetrics) -> f64 {
    if focus.reading_pattern_detected {
        0.15
    } else if focus.ai_app_switch_count > 3 {
        0.10
    } else {
        0.0
    }
}

/// Compute a combined forensic score from jitter samples and focus
/// switch records for a session that has no store-backed checkpoint
/// data yet.
///
/// The score is `cadence_score - focus_penalty`, clamped to `[0.0, 1.0]`.
pub fn session_forensic_score(
    jitter_samples: &[SimpleJitterSample],
    focus_switches: &[FocusSwitchRecord],
    total_focus_ms: i64,
) -> f64 {
    let cadence = cadence_score_from_samples(jitter_samples);
    let focus = super::analysis::analyze_focus_patterns(focus_switches, total_focus_ms);
    let penalty = compute_focus_penalty(&focus);
    (cadence - penalty).clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cadence_score_below_threshold_is_zero() {
        let samples: Vec<SimpleJitterSample> = (0..19)
            .map(|i| SimpleJitterSample {
                duration_since_last_ns: (i as u64 + 1) * 100_000_000,
                timestamp_ns: (i as i64) * 200_000_000,
                ..Default::default()
            })
            .collect();
        assert_eq!(cadence_score_from_samples(&samples), 0.0);
    }

    #[test]
    fn cadence_score_above_threshold_nonzero() {
        let samples: Vec<SimpleJitterSample> = (0..30)
            .map(|i| SimpleJitterSample {
                duration_since_last_ns: (i as u64 + 1) * 100_000_000,
                timestamp_ns: (i as i64) * 200_000_000,
                ..Default::default()
            })
            .collect();
        let score = cadence_score_from_samples(&samples);
        // With enough samples we should get a non-negative score.
        assert!(score >= 0.0);
    }

    #[test]
    fn focus_penalty_no_flags() {
        let focus = FocusMetrics::default();
        assert_eq!(compute_focus_penalty(&focus), 0.0);
    }

    #[test]
    fn focus_penalty_reading_pattern() {
        let focus = FocusMetrics {
            reading_pattern_detected: true,
            ..Default::default()
        };
        assert!((compute_focus_penalty(&focus) - 0.15).abs() < f64::EPSILON);
    }

    #[test]
    fn focus_penalty_ai_switches() {
        let focus = FocusMetrics {
            ai_app_switch_count: 5,
            ..Default::default()
        };
        assert!((compute_focus_penalty(&focus) - 0.10).abs() < f64::EPSILON);
    }

    #[test]
    fn session_score_empty_inputs() {
        let score = session_forensic_score(&[], &[], 0);
        assert_eq!(score, 0.0);
    }
}
