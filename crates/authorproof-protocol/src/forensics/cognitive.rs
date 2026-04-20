// SPDX-License-Identifier: Apache-2.0

//! Cognitive vs transcriptive classification using content-aware signals.
//!
//! Two classifiers that require text content alongside timing data:
//! - **Lexical Retrieval Delay (LRD)**: Correlation between word frequency and
//!   pre-word pause duration. Cognitive writers pause longer before rare words;
//!   transcribers don't (they're reading, not retrieving).
//! - **Non-Append Ratio**: Proportion of edits that aren't simple appends.
//!   Cognitive writers jump around, insert, and delete; transcribers type linearly.

use serde::{Deserialize, Serialize};

/// A word boundary event with timing and frequency data.
#[derive(Debug, Clone)]
pub struct WordBoundaryEvent {
    /// Pause duration before the word started (ms).
    pub pre_word_pause_ms: u32,
    /// Frequency tier of the word (1 = top 100, 2 = 101-1000, 3 = 1001-5000, 4 = rare).
    pub frequency_tier: u8,
}

/// Edit operation type for non-append ratio computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditOp {
    /// Character appended at end of document.
    Append,
    /// Character inserted at non-end position.
    Insert,
    /// Character(s) deleted.
    Delete,
    /// Cursor repositioned without editing.
    CursorJump,
}

/// Combined cognitive classification result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CognitiveContentMetrics {
    /// Pearson correlation between log(word_rank) and pre-word pause.
    /// Cognitive: r > 0.25 (rare words → longer pauses).
    /// Transcriptive: r ≈ 0 (pause independent of word rarity).
    pub lrd_correlation: f64,
    /// Proportion of edit operations that are not simple appends.
    /// Cognitive: > 0.15 (inserts, deletes, jumps).
    /// Transcriptive: < 0.03 (almost pure append stream).
    pub non_append_ratio: f64,
    /// Deletion semantic score: average length of deleted spans.
    /// Cognitive: > 3.0 (whole words/phrases deleted — changed mind).
    /// Transcriptive: < 2.0 (single-char typo corrections).
    pub mean_deletion_length: f64,
    /// Combined cognitive probability [0, 1].
    pub cognitive_probability: f64,
    /// Number of word boundaries analyzed for LRD.
    pub word_boundary_count: usize,
    /// Total edit operations analyzed.
    pub total_edit_ops: usize,
}

/// Compute Lexical Retrieval Delay correlation.
///
/// Measures Pearson r between frequency_tier (proxy for log word rank) and
/// pre-word pause. Requires at least 20 word boundary events.
pub fn compute_lrd_correlation(events: &[WordBoundaryEvent]) -> Option<f64> {
    if events.len() < 20 {
        return None;
    }

    // Filter out extreme pauses (> 10s = not typing, likely distraction).
    let filtered: Vec<&WordBoundaryEvent> = events
        .iter()
        .filter(|e| e.pre_word_pause_ms > 0 && e.pre_word_pause_ms < 10_000)
        .collect();

    if filtered.len() < 15 {
        return None;
    }

    let n = filtered.len() as f64;
    let mut sum_x = 0.0f64;
    let mut sum_y = 0.0f64;
    let mut sum_xy = 0.0f64;
    let mut sum_x2 = 0.0f64;
    let mut sum_y2 = 0.0f64;

    for event in &filtered {
        let x = event.frequency_tier as f64; // 1-4 (proxy for log rank)
        let y = event.pre_word_pause_ms as f64;
        sum_x += x;
        sum_y += y;
        sum_xy += x * y;
        sum_x2 += x * x;
        sum_y2 += y * y;
    }

    let numerator = n * sum_xy - sum_x * sum_y;
    let denom_x = n * sum_x2 - sum_x * sum_x;
    let denom_y = n * sum_y2 - sum_y * sum_y;
    let denominator = (denom_x * denom_y).sqrt();

    if denominator < 1e-10 {
        return Some(0.0); // No variance in one or both variables.
    }

    Some(numerator / denominator)
}

/// Compute non-append ratio and mean deletion length from edit operations.
///
/// Returns (non_append_ratio, mean_deletion_length).
pub fn compute_edit_topology(ops: &[EditOp]) -> (f64, f64) {
    if ops.is_empty() {
        return (0.0, 0.0);
    }

    let total = ops.len() as f64;
    let non_append = ops.iter().filter(|&&op| op != EditOp::Append).count() as f64;

    // Compute mean deletion run length.
    let mut deletion_lengths: Vec<usize> = Vec::new();
    let mut current_run = 0usize;
    for &op in ops {
        if op == EditOp::Delete {
            current_run += 1;
        } else {
            if current_run > 0 {
                deletion_lengths.push(current_run);
            }
            current_run = 0;
        }
    }
    if current_run > 0 {
        deletion_lengths.push(current_run);
    }

    let mean_del_len = if deletion_lengths.is_empty() {
        0.0
    } else {
        deletion_lengths.iter().sum::<usize>() as f64 / deletion_lengths.len() as f64
    };

    (non_append / total, mean_del_len)
}

/// Compute combined cognitive content metrics from word boundaries and edit ops.
pub fn analyze_cognitive_content(
    word_events: &[WordBoundaryEvent],
    edit_ops: &[EditOp],
) -> CognitiveContentMetrics {
    let lrd = compute_lrd_correlation(word_events).unwrap_or(0.0);
    let (non_append, mean_del) = compute_edit_topology(edit_ops);

    // Map LRD correlation to probability: sigmoid centered at 0.15.
    let lrd_prob = 1.0 / (1.0 + (-10.0 * (lrd - 0.15)).exp());

    // Map non-append ratio to probability: sigmoid centered at 0.08.
    let nar_prob = 1.0 / (1.0 + (-30.0 * (non_append - 0.08)).exp());

    // Map mean deletion length: > 3 chars = thinking deletions.
    let del_prob = 1.0 / (1.0 + (-1.5 * (mean_del - 2.5)).exp());

    // Weight: LRD is strongest signal, non-append is structural, deletion confirms.
    let combined = if word_events.len() >= 20 && edit_ops.len() >= 50 {
        lrd_prob * 0.45 + nar_prob * 0.35 + del_prob * 0.20
    } else if word_events.len() >= 20 {
        lrd_prob * 0.7 + del_prob * 0.3
    } else if edit_ops.len() >= 50 {
        nar_prob * 0.6 + del_prob * 0.4
    } else {
        0.5 // Insufficient data, neutral.
    };

    CognitiveContentMetrics {
        lrd_correlation: lrd,
        non_append_ratio: non_append,
        mean_deletion_length: mean_del,
        cognitive_probability: combined,
        word_boundary_count: word_events.len(),
        total_edit_ops: edit_ops.len(),
    }
}

/// Classify a word into frequency tier based on rank.
/// Tier 1: top 100 (the, of, and, to, a, in, is, ...).
/// Tier 2: 101-1000 (common everyday words).
/// Tier 3: 1001-5000 (educated vocabulary).
/// Tier 4: 5001+ (rare/technical/literary).
pub fn word_frequency_tier(word: &str) -> u8 {
    let lower = word.to_ascii_lowercase();
    let w = lower.as_str();

    // Tier 1: Top 100 English words (covers ~50% of all text).
    if matches!(w,
        "the" | "of" | "and" | "to" | "a" | "in" | "is" | "it" | "that" | "was" |
        "for" | "on" | "are" | "with" | "as" | "i" | "his" | "they" | "be" | "at" |
        "one" | "have" | "this" | "from" | "or" | "had" | "by" | "not" | "but" | "what" |
        "all" | "were" | "when" | "we" | "there" | "can" | "an" | "your" | "which" | "their" |
        "said" | "if" | "do" | "will" | "each" | "about" | "how" | "up" | "out" | "them" |
        "then" | "she" | "many" | "some" | "so" | "these" | "would" | "other" | "into" | "has" |
        "her" | "two" | "like" | "him" | "see" | "time" | "could" | "no" | "make" | "than" |
        "first" | "been" | "its" | "who" | "now" | "people" | "my" | "made" | "over" | "did" |
        "down" | "only" | "way" | "find" | "use" | "may" | "long" | "very" | "after" | "words" |
        "just" | "where" | "most" | "know" | "get" | "through" | "back" | "much" | "go" | "good"
    ) {
        return 1;
    }

    // Tier 2: Next 900 (common words most adults use daily).
    // Approximate by word length + common suffixes heuristic.
    if w.len() <= 5 {
        return 2; // Short words tend to be common.
    }

    // Tier 3: Words 6-9 chars with common patterns.
    if w.len() <= 9 && (w.ends_with("ing") || w.ends_with("tion") || w.ends_with("ment")
        || w.ends_with("able") || w.ends_with("ness") || w.ends_with("ful"))
    {
        return 3;
    }

    // Tier 4: Long/unusual words.
    if w.len() >= 10 {
        return 4;
    }

    // Default tier 3 for medium-length words without common suffixes.
    3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lrd_cognitive_pattern() {
        // Cognitive: rare words (tier 4) get long pauses, common (tier 1) get short.
        let events: Vec<WordBoundaryEvent> = (0..60)
            .map(|i| {
                let tier = (i % 4) as u8 + 1;
                let pause = match tier {
                    1 => 150,  // Common: short pause
                    2 => 250,  // Medium: moderate
                    3 => 400,  // Uncommon: longer
                    _ => 700,  // Rare: long retrieval delay
                };
                WordBoundaryEvent {
                    pre_word_pause_ms: pause,
                    frequency_tier: tier,
                }
            })
            .collect();

        let r = compute_lrd_correlation(&events).unwrap();
        assert!(r > 0.8, "Expected high correlation for cognitive pattern, got {r}");
    }

    #[test]
    fn test_lrd_transcriptive_pattern() {
        // Transcriptive: uniform pauses regardless of word frequency.
        let events: Vec<WordBoundaryEvent> = (0..60)
            .map(|i| WordBoundaryEvent {
                pre_word_pause_ms: 180 + (i as u32 % 20), // ~uniform
                frequency_tier: (i % 4) as u8 + 1,
            })
            .collect();

        let r = compute_lrd_correlation(&events).unwrap();
        assert!(r.abs() < 0.2, "Expected low correlation for transcription, got {r}");
    }

    #[test]
    fn test_non_append_cognitive() {
        // Cognitive: lots of inserts, deletes, jumps.
        let ops = vec![
            EditOp::Append, EditOp::Append, EditOp::Append,
            EditOp::Delete, EditOp::Delete, EditOp::Delete, EditOp::Delete, // 4-char deletion
            EditOp::Insert, EditOp::Insert,
            EditOp::Append, EditOp::Append,
            EditOp::CursorJump,
            EditOp::Insert, EditOp::Insert, EditOp::Insert,
            EditOp::Append, EditOp::Append, EditOp::Append, EditOp::Append,
            EditOp::Delete, EditOp::Delete, EditOp::Delete, // 3-char deletion
        ];
        let (ratio, mean_del) = compute_edit_topology(&ops);
        assert!(ratio > 0.4, "ratio={ratio}");
        assert!(mean_del > 3.0, "mean_del={mean_del}");
    }

    #[test]
    fn test_non_append_transcriptive() {
        // Transcriptive: almost all appends, occasional single-char delete.
        let mut ops = vec![EditOp::Append; 100];
        ops[30] = EditOp::Delete;
        ops[60] = EditOp::Delete;
        let (ratio, mean_del) = compute_edit_topology(&ops);
        assert!(ratio < 0.03, "ratio={ratio}");
        assert!(mean_del <= 1.0, "mean_del={mean_del}");
    }

    #[test]
    fn test_word_frequency_tiers() {
        assert_eq!(word_frequency_tier("the"), 1);
        assert_eq!(word_frequency_tier("and"), 1);
        assert_eq!(word_frequency_tier("cat"), 2);
        assert_eq!(word_frequency_tier("running"), 3);
        assert_eq!(word_frequency_tier("conflagration"), 4);
        assert_eq!(word_frequency_tier("sesquipedalian"), 4);
    }

    #[test]
    fn test_combined_cognitive() {
        let word_events: Vec<WordBoundaryEvent> = (0..40)
            .map(|i| {
                let tier = (i % 4) as u8 + 1;
                WordBoundaryEvent {
                    pre_word_pause_ms: 100 + tier as u32 * 150,
                    frequency_tier: tier,
                }
            })
            .collect();

        let mut edit_ops = vec![EditOp::Append; 50];
        // Add cognitive edits: insertions and multi-char deletions.
        for i in (10..50).step_by(5) {
            edit_ops[i] = EditOp::Delete;
            if i + 1 < 50 { edit_ops[i + 1] = EditOp::Delete; }
            if i + 2 < 50 { edit_ops[i + 2] = EditOp::Delete; }
        }
        edit_ops.push(EditOp::Insert);
        edit_ops.push(EditOp::Insert);
        edit_ops.push(EditOp::CursorJump);

        let metrics = analyze_cognitive_content(&word_events, &edit_ops);
        assert!(
            metrics.cognitive_probability > 0.6,
            "prob={}", metrics.cognitive_probability
        );
    }

    #[test]
    fn test_combined_transcriptive() {
        let word_events: Vec<WordBoundaryEvent> = (0..40)
            .map(|i| WordBoundaryEvent {
                pre_word_pause_ms: 200,
                frequency_tier: (i % 4) as u8 + 1,
            })
            .collect();

        let edit_ops = vec![EditOp::Append; 100];

        let metrics = analyze_cognitive_content(&word_events, &edit_ops);
        assert!(
            metrics.cognitive_probability < 0.4,
            "prob={}", metrics.cognitive_probability
        );
    }
}
