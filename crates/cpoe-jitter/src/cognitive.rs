// SPDX-License-Identifier: Apache-2.0

//! Cognitive vs transcriptive writing differentiation via temporal microstructure.
//!
//! Two timing-only classifiers that work on raw inter-keystroke intervals (IKI):
//! - **Sentence Initiation Delay Ratio**: cognitive writers pause significantly
//!   longer before new sentences (thinking) vs transcribers (just reading next line).
//! - **Bigram Fluency Differential**: cognitive writers type common letter pairs
//!   much faster than rare ones (motor memory); transcribers are more uniform.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

/// Result of cognitive temporal analysis on a keystroke timing session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CognitiveTemporalMetrics {
    /// Ratio of mean sentence-initial pause to median within-sentence IKI.
    /// Cognitive: 8-30x, Transcriptive: 2-4x.
    pub sentence_initiation_ratio: f64,
    /// Variance of sentence initiation ratios across sentences.
    /// Cognitive: high (some sentences flow, others need thought).
    /// Transcriptive: low (uniform reading pace).
    pub sentence_initiation_variance: f64,
    /// Ratio of common bigram speed to rare bigram speed.
    /// Cognitive: >2.5 (automated motor sequences vs novel planning).
    /// Transcriptive: <1.5 (uniform visual-motor transfer).
    pub bigram_fluency_ratio: f64,
    /// Combined cognitive probability [0, 1].
    /// 0 = strongly transcriptive, 1 = strongly cognitive.
    pub cognitive_probability: f64,
    /// Number of sentences analyzed.
    pub sentence_count: usize,
    /// Number of bigram pairs analyzed.
    pub bigram_pairs_analyzed: usize,
}

/// A keystroke event with timing and character identity.
#[derive(Debug, Clone, Copy)]
pub struct TimedKeystroke {
    /// Inter-keystroke interval in microseconds (time since previous key).
    pub iki_us: u64,
    /// The character typed (ASCII byte; 0 for non-printable).
    pub char_byte: u8,
    /// Whether this keystroke follows a sentence-ending punctuation.
    pub after_sentence_end: bool,
}

/// Top 50 most common English bigrams by frequency.
/// Source: Peter Norvig corpus analysis / Mayzner & Tresselt.
const COMMON_BIGRAMS: &[[u8; 2]] = &[
    *b"th", *b"he", *b"in", *b"er", *b"an", *b"re", *b"on", *b"at",
    *b"en", *b"nd", *b"ti", *b"es", *b"or", *b"te", *b"of", *b"ed",
    *b"is", *b"it", *b"al", *b"ar", *b"st", *b"to", *b"nt", *b"ng",
    *b"se", *b"ha", *b"as", *b"ou", *b"io", *b"le", *b"ve", *b"co",
    *b"me", *b"de", *b"hi", *b"ri", *b"ro", *b"ic", *b"ne", *b"ea",
    *b"ra", *b"ce", *b"li", *b"ch", *b"ll", *b"be", *b"ma", *b"si",
    *b"om", *b"ur",
];

/// Analyze cognitive vs transcriptive writing from timed keystrokes.
///
/// Requires at least 20 keystrokes and 3 sentence boundaries for meaningful results.
pub fn analyze_cognitive_temporal(keystrokes: &[TimedKeystroke]) -> Option<CognitiveTemporalMetrics> {
    if keystrokes.len() < 20 {
        return None;
    }

    let sentence_metrics = compute_sentence_initiation(keystrokes)?;
    let bigram_metrics = compute_bigram_fluency(keystrokes);

    let sid_score = sentence_initiation_to_probability(
        sentence_metrics.0,
        sentence_metrics.1,
    );
    let bigram_score = bigram_fluency_to_probability(bigram_metrics.0);

    // Weight: sentence initiation is the stronger signal (harder to fake).
    // If bigram data is ambiguous (score near 0.5), rely more on sentence initiation.
    let cognitive_probability = if sentence_metrics.2 >= 3 && bigram_metrics.1 >= 30 {
        let bigram_confidence = (bigram_score - 0.5).abs() * 2.0; // 0 = ambiguous, 1 = clear
        let bigram_weight = 0.35 * bigram_confidence;
        let sid_weight = 1.0 - bigram_weight;
        sid_score * sid_weight + bigram_score * bigram_weight
    } else if sentence_metrics.2 >= 3 {
        sid_score
    } else if bigram_metrics.1 >= 30 {
        bigram_score
    } else {
        return None; // Insufficient data
    };

    Some(CognitiveTemporalMetrics {
        sentence_initiation_ratio: sentence_metrics.0,
        sentence_initiation_variance: sentence_metrics.1,
        bigram_fluency_ratio: bigram_metrics.0,
        cognitive_probability,
        sentence_count: sentence_metrics.2,
        bigram_pairs_analyzed: bigram_metrics.1,
    })
}

/// Returns (mean_ratio, variance_of_ratios, sentence_count).
fn compute_sentence_initiation(keystrokes: &[TimedKeystroke]) -> Option<(f64, f64, usize)> {
    // Collect within-sentence IKIs and sentence-initial IKIs.
    let mut within_sentence_ikis: Vec<u64> = Vec::new();
    let mut sentence_initial_ikis: Vec<u64> = Vec::new();

    for ks in keystrokes {
        if ks.iki_us == 0 {
            continue;
        }
        if ks.after_sentence_end {
            sentence_initial_ikis.push(ks.iki_us);
        } else {
            within_sentence_ikis.push(ks.iki_us);
        }
    }

    if sentence_initial_ikis.len() < 3 || within_sentence_ikis.len() < 10 {
        return None;
    }

    // Median within-sentence IKI (robust to outliers).
    within_sentence_ikis.sort_unstable();
    let median_within = within_sentence_ikis[within_sentence_ikis.len() / 2] as f64;
    if median_within < 1.0 {
        return None;
    }

    // Compute per-sentence initiation ratios.
    let ratios: Vec<f64> = sentence_initial_ikis
        .iter()
        .map(|&iki| iki as f64 / median_within)
        .collect();

    let mean_ratio = ratios.iter().sum::<f64>() / ratios.len() as f64;
    let variance = if ratios.len() > 1 {
        ratios.iter().map(|r| (r - mean_ratio).powi(2)).sum::<f64>() / (ratios.len() - 1) as f64
    } else {
        0.0
    };

    Some((mean_ratio, variance, sentence_initial_ikis.len()))
}

/// Returns (fluency_ratio, total_bigram_pairs).
fn compute_bigram_fluency(keystrokes: &[TimedKeystroke]) -> (f64, usize) {
    let mut common_speeds: Vec<u64> = Vec::new();
    let mut rare_speeds: Vec<u64> = Vec::new();

    for pair in keystrokes.windows(2) {
        let prev = pair[0].char_byte.to_ascii_lowercase();
        let curr = pair[1].char_byte.to_ascii_lowercase();

        // Only consider letter pairs with valid timing.
        if !prev.is_ascii_lowercase() || !curr.is_ascii_lowercase() {
            continue;
        }
        if pair[1].iki_us == 0 || pair[1].iki_us > 2_000_000 {
            continue; // Skip zero or >2s gaps (not typing speed)
        }

        let bigram = [prev, curr];
        if is_common_bigram(&bigram) {
            common_speeds.push(pair[1].iki_us);
        } else {
            rare_speeds.push(pair[1].iki_us);
        }
    }

    let total = common_speeds.len() + rare_speeds.len();
    if common_speeds.len() < 10 || rare_speeds.len() < 10 {
        return (1.0, total); // Insufficient data, neutral ratio
    }

    // Use median speed (inverse of IKI) for robustness.
    common_speeds.sort_unstable();
    rare_speeds.sort_unstable();

    let median_common = common_speeds[common_speeds.len() / 2] as f64;
    let median_rare = rare_speeds[rare_speeds.len() / 2] as f64;

    if median_common < 1.0 {
        return (1.0, total);
    }

    // Ratio of rare/common IKI (higher = common bigrams typed faster = cognitive).
    let ratio = median_rare / median_common;
    (ratio, total)
}

fn is_common_bigram(bigram: &[u8; 2]) -> bool {
    COMMON_BIGRAMS.iter().any(|b| b == bigram)
}

/// Map sentence initiation ratio to [0, 1] cognitive probability.
/// Cognitive: ratio 8-30 → high probability.
/// Transcriptive: ratio 2-4 → low probability.
fn sentence_initiation_to_probability(mean_ratio: f64, variance: f64) -> f64 {
    // Ratio contribution: sigmoid centered at 6.0 (transition zone).
    let ratio_score = 1.0 / (1.0 + (-0.5 * (mean_ratio - 6.0)).exp());

    // Variance contribution: high variance = cognitive (some sentences easy, some hard).
    // Normalize variance; cognitive typically > 20, transcriptive < 5.
    let variance_score = 1.0 / (1.0 + (-0.2 * (variance - 10.0)).exp());

    // Combine: ratio is primary, variance confirms.
    ratio_score * 0.7 + variance_score * 0.3
}

/// Map bigram fluency ratio to [0, 1] cognitive probability.
/// Cognitive: ratio > 2.5. Transcriptive: ratio < 1.5.
fn bigram_fluency_to_probability(ratio: f64) -> f64 {
    // Sigmoid centered at 2.0 (transition zone between 1.5 and 2.5).
    1.0 / (1.0 + (-2.0 * (ratio - 2.0)).exp())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cognitive_keystrokes() -> Vec<TimedKeystroke> {
        let mut ks = Vec::new();
        // Simulate cognitive writing: long pauses at sentence starts, variable within.
        // 5 sentences to ensure >= 3 sentence boundaries after first.
        let sentences: &[&[u8]] = &[
            b"The quick brown fox jumps over the lazy dog near the river bank.",
            b"A second thought emerges from the depths of creative thinking here.",
            b"Perhaps the reader will notice something unusual about this text.",
            b"Writing from memory produces irregular rhythms and varied pauses.",
            b"The final sentence wraps up the cognitive composition naturally.",
        ];
        let sentence_pauses = [0u64, 800_000, 1_500_000, 2_200_000, 600_000];
        for (si, sentence) in sentences.iter().enumerate() {
            for (ci, &ch) in sentence.iter().enumerate() {
                let after_sentence_end = si > 0 && ci == 0;
                let iki = if after_sentence_end {
                    sentence_pauses[si] // Variable thinking pauses (0.6-2.2s)
                } else if ch == b' ' {
                    180_000
                } else {
                    120_000 + ((ch as u64 * 7) % 80_000)
                };
                ks.push(TimedKeystroke {
                    iki_us: iki,
                    char_byte: ch,
                    after_sentence_end,
                });
            }
        }
        ks
    }

    fn make_transcriptive_keystrokes() -> Vec<TimedKeystroke> {
        let mut ks = Vec::new();
        // Simulate transcription: uniform pace, short sentence-start pauses.
        let sentences: &[&[u8]] = &[
            b"The quick brown fox jumps over the lazy dog near the river bank.",
            b"A second thought emerges from the depths of creative thinking here.",
            b"Perhaps the reader will notice something unusual about this text.",
            b"Writing from memory produces irregular rhythms and varied pauses.",
            b"The final sentence wraps up the cognitive composition naturally.",
        ];
        for (si, sentence) in sentences.iter().enumerate() {
            for (ci, &ch) in sentence.iter().enumerate() {
                let after_sentence_end = si > 0 && ci == 0;
                let iki = if after_sentence_end {
                    300_000 // just reading next line: 300ms
                } else {
                    110_000 // uniform typing
                };
                ks.push(TimedKeystroke {
                    iki_us: iki,
                    char_byte: ch,
                    after_sentence_end,
                });
            }
        }
        ks
    }

    #[test]
    fn test_cognitive_detected() {
        let ks = make_cognitive_keystrokes();
        let metrics = analyze_cognitive_temporal(&ks).unwrap();
        assert!(
            metrics.sentence_initiation_ratio > 5.0,
            "ratio={}", metrics.sentence_initiation_ratio
        );
        assert!(
            metrics.cognitive_probability > 0.6,
            "prob={}", metrics.cognitive_probability
        );
    }

    #[test]
    fn test_transcriptive_detected() {
        let ks = make_transcriptive_keystrokes();
        let metrics = analyze_cognitive_temporal(&ks).unwrap();
        assert!(
            metrics.sentence_initiation_ratio < 4.0,
            "ratio={}", metrics.sentence_initiation_ratio
        );
        assert!(
            metrics.cognitive_probability < 0.5,
            "prob={}", metrics.cognitive_probability
        );
    }

    #[test]
    fn test_insufficient_data_returns_none() {
        let ks = vec![
            TimedKeystroke { iki_us: 100_000, char_byte: b'a', after_sentence_end: false },
            TimedKeystroke { iki_us: 100_000, char_byte: b'b', after_sentence_end: false },
        ];
        assert!(analyze_cognitive_temporal(&ks).is_none());
    }

    #[test]
    fn test_bigram_common_lookup() {
        assert!(is_common_bigram(b"th"));
        assert!(is_common_bigram(b"he"));
        assert!(!is_common_bigram(b"qx"));
        assert!(!is_common_bigram(b"zv"));
    }
}
