// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Cross-modal consistency analysis for adversarial forgery detection.
//!
//! Verifies that independently-captured evidence channels (keystrokes, content
//! growth, timing jitter, edit topology) are mutually consistent. A user
//! adversary must fabricate ALL channels simultaneously and maintain coherence
//! across them, which raises the cost of forgery from O(1) per channel to
//! O(n^2) due to pairwise consistency constraints.

use serde::{Deserialize, Serialize};

use super::types::EventData;
use crate::jitter::SimpleJitterSample;

/// Minimum events for cross-modal analysis.
const MIN_EVENTS: usize = 10;
/// Minimum jitter samples for cross-modal analysis.
const MIN_JITTER_SAMPLES: usize = 20;

/// Human typing rarely exceeds 15 chars/second sustained over 10+ seconds.
const MAX_SUSTAINED_CHARS_PER_SEC: f64 = 15.0;
/// Minimum ratio of edit events to jitter samples (keystrokes should
/// produce content changes; a ratio below this suggests injected jitter).
const MIN_EDIT_TO_JITTER_RATIO: f64 = 0.02;
/// Maximum allowable gap between last jitter sample and last edit event (seconds).
const MAX_TEMPORAL_DRIFT_SEC: f64 = 120.0;

/// Cross-modal consistency input bundle.
pub struct CrossModalInput<'a> {
    pub events: &'a [EventData],
    pub jitter_samples: Option<&'a [SimpleJitterSample]>,
    pub document_length: i64,
    pub total_keystrokes: i64,
    pub checkpoint_count: u64,
    pub session_duration_sec: f64,
}

/// Cross-modal consistency result.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CrossModalResult {
    /// Overall consistency score [0.0, 1.0]; higher = more consistent.
    pub score: f64,
    pub checks: Vec<CrossModalCheck>,
    pub verdict: CrossModalVerdict,
}

/// Individual cross-modal consistency check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossModalCheck {
    pub name: String,
    pub passed: bool,
    pub score: f64,
    pub detail: String,
}

/// Cross-modal verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum CrossModalVerdict {
    /// All cross-modal checks pass.
    Consistent,
    /// Some checks raise warnings.
    Marginal,
    /// Multiple channels are inconsistent -- likely forgery.
    Inconsistent,
    /// Insufficient data to determine.
    #[default]
    Insufficient,
}

/// Run all cross-modal consistency checks.
pub fn analyze_cross_modal(input: &CrossModalInput<'_>) -> CrossModalResult {
    let mut checks = Vec::new();

    if input.events.len() < MIN_EVENTS {
        return CrossModalResult {
            score: 0.5,
            checks,
            verdict: CrossModalVerdict::Insufficient,
        };
    }

    checks.push(check_content_growth_rate(input));
    checks.push(check_edit_checkpoint_ratio(input));

    if let Some(samples) = input.jitter_samples {
        if samples.len() >= MIN_JITTER_SAMPLES {
            checks.push(check_jitter_edit_coherence(input.events, samples));
            checks.push(check_temporal_span_alignment(input.events, samples));
            checks.push(check_jitter_content_entanglement(
                samples,
                input.document_length,
                input.total_keystrokes,
            ));
        }
    }

    if checks.is_empty() {
        return CrossModalResult {
            score: 0.5,
            checks,
            verdict: CrossModalVerdict::Insufficient,
        };
    }

    let total: f64 = checks.iter().map(|c| c.score).sum();
    let score = total / checks.len() as f64;
    let failed = checks.iter().filter(|c| !c.passed).count();

    let verdict = if failed >= 3 {
        CrossModalVerdict::Inconsistent
    } else if failed >= 1 {
        CrossModalVerdict::Marginal
    } else {
        CrossModalVerdict::Consistent
    };

    CrossModalResult {
        score,
        checks,
        verdict,
    }
}

/// Check 1: Content growth rate vs session duration.
///
/// If document length / session time exceeds human typing speed, the content
/// was likely pasted or AI-generated and the session fabricated around it.
fn check_content_growth_rate(input: &CrossModalInput<'_>) -> CrossModalCheck {
    if input.document_length < 0 {
        return CrossModalCheck {
            name: "content_growth_rate".into(),
            passed: false,
            score: 0.0,
            detail: format!(
                "Negative document length ({}); invalid input",
                input.document_length
            ),
        };
    }

    if input.session_duration_sec < 10.0 {
        return CrossModalCheck {
            name: "content_growth_rate".into(),
            passed: true,
            score: 0.5,
            detail: "Session too short for growth rate analysis".into(),
        };
    }

    let chars_per_sec = input.document_length as f64 / input.session_duration_sec;
    let passed = chars_per_sec <= MAX_SUSTAINED_CHARS_PER_SEC;

    // Smooth scoring: 1.0 at 0 cps, drops linearly above threshold
    let score = if chars_per_sec <= MAX_SUSTAINED_CHARS_PER_SEC {
        1.0
    } else {
        (1.0 - (chars_per_sec - MAX_SUSTAINED_CHARS_PER_SEC) / MAX_SUSTAINED_CHARS_PER_SEC)
            .clamp(0.0, 1.0)
    };

    CrossModalCheck {
        name: "content_growth_rate".into(),
        passed,
        score,
        detail: format!(
            "Content growth: {:.1} chars/sec (threshold: {:.0})",
            chars_per_sec, MAX_SUSTAINED_CHARS_PER_SEC
        ),
    }
}

/// Check 2: Edit events should produce checkpoints at a reasonable rate.
///
/// If checkpoint_count is much lower than expected for the number of edits,
/// the checkpoints may have been fabricated after the fact.
fn check_edit_checkpoint_ratio(input: &CrossModalInput<'_>) -> CrossModalCheck {
    if input.checkpoint_count == 0 {
        return CrossModalCheck {
            name: "edit_checkpoint_ratio".into(),
            passed: false,
            score: 0.0,
            detail: "No checkpoints recorded".into(),
        };
    }

    let events_per_checkpoint = input.events.len() as f64 / input.checkpoint_count as f64;

    // Expect roughly 1-100 events per checkpoint; outside this range is suspicious
    let passed = (0.5..=200.0).contains(&events_per_checkpoint);
    let score = if passed { 1.0 } else { 0.3 };

    CrossModalCheck {
        name: "edit_checkpoint_ratio".into(),
        passed,
        score,
        detail: format!(
            "{:.1} events per checkpoint ({} events, {} checkpoints)",
            events_per_checkpoint,
            input.events.len(),
            input.checkpoint_count
        ),
    }
}

/// Check 3: Jitter samples and edit events should overlap temporally.
///
/// If jitter samples exist but don't align with edit event timestamps,
/// the jitter was likely injected from a separate source.
fn check_jitter_edit_coherence(
    events: &[EventData],
    samples: &[SimpleJitterSample],
) -> CrossModalCheck {
    let edit_count = events.len();
    let jitter_count = samples.len();

    let ratio = edit_count as f64 / jitter_count as f64;
    let passed = ratio >= MIN_EDIT_TO_JITTER_RATIO;

    let score = if ratio >= 0.1 {
        1.0
    } else if ratio >= MIN_EDIT_TO_JITTER_RATIO {
        0.6
    } else {
        (ratio / MIN_EDIT_TO_JITTER_RATIO).clamp(0.0, 0.4)
    };

    CrossModalCheck {
        name: "jitter_edit_coherence".into(),
        passed,
        score,
        detail: format!(
            "Edit/jitter ratio: {:.4} ({} edits, {} jitter samples)",
            ratio, edit_count, jitter_count
        ),
    }
}

/// Check 4: Temporal span of jitter samples should align with edit events.
///
/// The first and last jitter timestamps should bracket (or closely match)
/// the first and last edit event timestamps. Large drift suggests the
/// jitter was recorded in a different session.
fn check_temporal_span_alignment(
    events: &[EventData],
    samples: &[SimpleJitterSample],
) -> CrossModalCheck {
    let edit_first = events.iter().map(|e| e.timestamp_ns).min().unwrap_or(0);
    let edit_last = events.iter().map(|e| e.timestamp_ns).max().unwrap_or(0);

    let jitter_first = samples.iter().map(|s| s.timestamp_ns).min().unwrap_or(0);
    let jitter_last = samples.iter().map(|s| s.timestamp_ns).max().unwrap_or(0);

    // Allow 0 timestamps (legacy data that doesn't have them)
    if jitter_first == 0 || jitter_last == 0 || edit_first == 0 || edit_last == 0 {
        return CrossModalCheck {
            name: "temporal_span_alignment".into(),
            passed: true,
            score: 0.5,
            detail: "Timestamps unavailable for temporal alignment check".into(),
        };
    }

    // Compute drift at both ends (seconds), using i128 to avoid i64 overflow
    let start_drift = (edit_first as i128 - jitter_first as i128).unsigned_abs() as f64 / 1e9;
    let end_drift = (edit_last as i128 - jitter_last as i128).unsigned_abs() as f64 / 1e9;
    let max_drift = start_drift.max(end_drift);

    let passed = max_drift <= MAX_TEMPORAL_DRIFT_SEC;
    let score = if max_drift <= 10.0 {
        1.0
    } else if max_drift <= MAX_TEMPORAL_DRIFT_SEC {
        1.0 - (max_drift - 10.0) / (MAX_TEMPORAL_DRIFT_SEC - 10.0) * 0.4
    } else {
        (0.3 - (max_drift - MAX_TEMPORAL_DRIFT_SEC) / 600.0).clamp(0.0, 0.3)
    };

    CrossModalCheck {
        name: "temporal_span_alignment".into(),
        passed,
        score,
        detail: format!(
            "Temporal drift: start={:.1}s, end={:.1}s (max allowed: {:.0}s)",
            start_drift, end_drift, MAX_TEMPORAL_DRIFT_SEC
        ),
    }
}

/// Check 5: Jitter volume should correlate with content length.
///
/// Each keystroke produces one jitter sample, so the ratio of
/// jitter_count to document_length should be plausible for human typing
/// (accounting for deletions, corrections, navigation keys).
fn check_jitter_content_entanglement(
    samples: &[SimpleJitterSample],
    document_length: i64,
    total_keystrokes: i64,
) -> CrossModalCheck {
    if document_length <= 0 {
        return CrossModalCheck {
            name: "jitter_content_entanglement".into(),
            passed: true,
            score: 0.5,
            detail: "No document content for entanglement check".into(),
        };
    }

    let jitter_count = samples.len() as i64;
    let keystroke_source = if total_keystrokes > 0 {
        total_keystrokes
    } else {
        jitter_count
    };

    // Keystrokes should be >= document_length (because of edits, deletions, nav keys)
    // and jitter samples should track keystroke count.
    // Ratio of keystrokes to content: typically 1.1x to 3.0x for normal editing
    let ks_content_ratio = keystroke_source as f64 / document_length as f64;
    // Ratio of jitter to keystrokes: should be close to 1.0
    let jitter_ks_ratio = if keystroke_source > 0 {
        jitter_count as f64 / keystroke_source as f64
    } else {
        0.0
    };

    // Content with no keystrokes at all = highly suspicious
    let passed = ks_content_ratio >= 0.5 && jitter_ks_ratio >= 0.3;

    let score = if ks_content_ratio >= 1.0 && jitter_ks_ratio >= 0.8 {
        1.0
    } else if passed {
        0.6
    } else {
        0.2
    };

    CrossModalCheck {
        name: "jitter_content_entanglement".into(),
        passed,
        score,
        detail: format!(
            "Keystroke/content ratio: {:.2}, jitter/keystroke ratio: {:.2}",
            ks_content_ratio, jitter_ks_ratio
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_events(count: usize, start_ns: i64, interval_ns: i64) -> Vec<EventData> {
        (0..count)
            .map(|i| EventData {
                id: i as i64,
                timestamp_ns: start_ns + i as i64 * interval_ns,
                file_size: (i as i64 + 1) * 100,
                size_delta: 10,
                file_path: "test.txt".into(),
            })
            .collect()
    }

    fn make_jitter(count: usize, start_ns: i64, interval_ns: i64) -> Vec<SimpleJitterSample> {
        (0..count)
            .map(|i| SimpleJitterSample {
                timestamp_ns: start_ns + i as i64 * interval_ns,
                duration_since_last_ns: 150_000_000, // 150ms
                zone: 0,
            })
            .collect()
    }

    #[test]
    fn test_consistent_session() {
        let events = make_events(50, 1_000_000_000, 1_000_000_000);
        let jitter = make_jitter(200, 1_000_000_000, 250_000_000);

        let input = CrossModalInput {
            events: &events,
            jitter_samples: Some(&jitter),
            document_length: 500,
            total_keystrokes: 600,
            checkpoint_count: 10,
            session_duration_sec: 50.0,
        };

        let result = analyze_cross_modal(&input);
        assert!(result.score > 0.7);
        assert_eq!(result.verdict, CrossModalVerdict::Consistent);
    }

    #[test]
    fn test_content_too_fast() {
        let events = make_events(20, 1_000_000_000, 500_000_000);
        let input = CrossModalInput {
            events: &events,
            jitter_samples: None,
            document_length: 5000,
            total_keystrokes: 100,
            checkpoint_count: 5,
            session_duration_sec: 10.0,
        };

        let result = analyze_cross_modal(&input);
        let growth_check = result
            .checks
            .iter()
            .find(|c| c.name == "content_growth_rate")
            .unwrap();
        assert!(!growth_check.passed);
    }

    #[test]
    fn test_jitter_without_edits() {
        let events = make_events(10, 1_000_000_000, 1_000_000_000);
        let jitter = make_jitter(10000, 1_000_000_000, 100_000);

        let input = CrossModalInput {
            events: &events,
            jitter_samples: Some(&jitter),
            document_length: 100,
            total_keystrokes: 50,
            checkpoint_count: 5,
            session_duration_sec: 10.0,
        };

        let result = analyze_cross_modal(&input);
        // High jitter count with few edits is suspicious
        assert!(result.score < 0.9);
    }

    #[test]
    fn test_insufficient_data() {
        let events = make_events(3, 1_000_000_000, 1_000_000_000);
        let input = CrossModalInput {
            events: &events,
            jitter_samples: None,
            document_length: 100,
            total_keystrokes: 50,
            checkpoint_count: 1,
            session_duration_sec: 3.0,
        };

        let result = analyze_cross_modal(&input);
        assert_eq!(result.verdict, CrossModalVerdict::Insufficient);
    }
}
