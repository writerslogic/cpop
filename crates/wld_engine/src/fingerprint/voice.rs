// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Writing style fingerprint (word length, punctuation, MinHash n-grams,
//! correction patterns). No raw text is ever stored.
//!
//! Disabled by default; requires explicit consent.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};

const MAX_WORD_LENGTH: usize = 20;
const MINHASH_FUNCTIONS: usize = 100;
const NGRAM_SIZE: usize = 3;
const MIN_NGRAMS: usize = 50;

/// Statistical writing-style fingerprint (content-free).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoiceFingerprint {
    pub consent_given: bool,
    pub word_length_distribution: [f32; MAX_WORD_LENGTH],
    pub punctuation_signature: PunctuationSignature,
    pub ngram_signature: NgramSignature,
    pub correction_rate: f64,
    pub backspace_signature: BackspaceSignature,
    pub total_chars: u64,
    pub total_words: u64,
}

impl Default for VoiceFingerprint {
    fn default() -> Self {
        Self {
            consent_given: false,
            word_length_distribution: [0.0; MAX_WORD_LENGTH],
            punctuation_signature: PunctuationSignature::default(),
            ngram_signature: NgramSignature::default(),
            correction_rate: 0.0,
            backspace_signature: BackspaceSignature::default(),
            total_chars: 0,
            total_words: 0,
        }
    }
}

impl VoiceFingerprint {
    pub fn new(consent_given: bool) -> Self {
        Self {
            consent_given,
            ..Default::default()
        }
    }

    /// Weighted merge by `total_chars`.
    pub fn merge(&mut self, other: &VoiceFingerprint) {
        let total = self.total_chars + other.total_chars;
        if total == 0 {
            return;
        }

        let self_weight = self.total_chars as f64 / total as f64;
        let other_weight = other.total_chars as f64 / total as f64;

        for i in 0..MAX_WORD_LENGTH {
            self.word_length_distribution[i] = (self.word_length_distribution[i] as f64
                * self_weight
                + other.word_length_distribution[i] as f64 * other_weight)
                as f32;
        }

        self.punctuation_signature
            .merge(&other.punctuation_signature, self_weight, other_weight);
        self.ngram_signature.merge(&other.ngram_signature);
        self.backspace_signature
            .merge(&other.backspace_signature, self_weight, other_weight);

        self.correction_rate =
            self.correction_rate * self_weight + other.correction_rate * other_weight;
        self.total_chars = total;
        self.total_words += other.total_words;
    }

    pub fn avg_word_length(&self) -> f64 {
        let mut weighted_sum = 0.0;
        let mut total_weight = 0.0;
        for (i, &freq) in self.word_length_distribution.iter().enumerate() {
            let word_len = (i + 1) as f64;
            weighted_sum += word_len * freq as f64;
            total_weight += freq as f64;
        }
        if total_weight > 0.0 {
            weighted_sum / total_weight
        } else {
            0.0
        }
    }

    /// Weighted similarity (0.0-1.0) across all voice dimensions.
    pub fn similarity(&self, other: &VoiceFingerprint) -> f64 {
        let word_len_sim = histogram_similarity(
            &self.word_length_distribution,
            &other.word_length_distribution,
        );
        let punct_sim = self
            .punctuation_signature
            .similarity(&other.punctuation_signature);
        let ngram_sim = self.ngram_signature.similarity(&other.ngram_signature);
        let correction_sim = 1.0
            - (self.correction_rate - other.correction_rate)
                .abs()
                .min(1.0);

        (word_len_sim * 0.25 + punct_sim * 0.25 + ngram_sim * 0.35 + correction_sim * 0.15)
            .clamp(0.0, 1.0)
    }
}

/// Normalized punctuation character frequencies.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PunctuationSignature {
    pub frequencies: HashMap<char, f32>,
    /// Hashed context patterns (privacy-preserving).
    ///
    /// Structural placeholder: populating this requires surrounding-word context
    /// which is intentionally not captured in privacy-preserving mode. The field
    /// is retained for future opt-in content-aware analysis behind explicit consent.
    #[allow(dead_code)] // Requires content access not available in privacy-preserving mode
    pub context_patterns: Vec<u64>,
}

impl PunctuationSignature {
    pub fn record(&mut self, c: char) {
        if c.is_ascii_punctuation() {
            *self.frequencies.entry(c).or_insert(0.0) += 1.0;
        }
    }

    pub fn normalize(&mut self) {
        let total: f32 = self.frequencies.values().sum();
        if total > 0.0 {
            for v in self.frequencies.values_mut() {
                *v /= total;
            }
        }
    }

    /// Weighted merge.
    pub fn merge(&mut self, other: &PunctuationSignature, self_weight: f64, other_weight: f64) {
        for (k, v) in &other.frequencies {
            let entry = self.frequencies.entry(*k).or_insert(0.0);
            *entry = (*entry as f64 * self_weight + *v as f64 * other_weight) as f32;
        }
    }

    pub fn similarity(&self, other: &PunctuationSignature) -> f64 {
        if self.frequencies.is_empty() && other.frequencies.is_empty() {
            return 1.0;
        }

        let all_keys: HashSet<_> = self
            .frequencies
            .keys()
            .chain(other.frequencies.keys())
            .collect();

        let mut sim_sum = 0.0;
        for k in &all_keys {
            let a = *self.frequencies.get(*k).unwrap_or(&0.0) as f64;
            let b = *other.frequencies.get(*k).unwrap_or(&0.0) as f64;
            sim_sum += 1.0 - (a - b).abs();
        }

        sim_sum / all_keys.len() as f64
    }
}

/// Privacy-preserving n-gram signature via MinHash.
/// Allows Jaccard similarity estimation without revealing content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NgramSignature {
    pub minhash: Vec<u64>,
    pub ngram_count: u64,
}

impl Default for NgramSignature {
    fn default() -> Self {
        Self {
            minhash: vec![u64::MAX; MINHASH_FUNCTIONS],
            ngram_count: 0,
        }
    }
}

impl NgramSignature {
    /// Update MinHash slots with a new n-gram.
    pub fn add_ngram(&mut self, ngram: &str) {
        for i in 0..MINHASH_FUNCTIONS {
            let hash = hash_with_seed(ngram, i as u64);
            if hash < self.minhash[i] {
                self.minhash[i] = hash;
            }
        }
        self.ngram_count += 1;
    }

    /// MinHash merge: element-wise minimum.
    pub fn merge(&mut self, other: &NgramSignature) {
        for i in 0..MINHASH_FUNCTIONS {
            self.minhash[i] = self.minhash[i].min(other.minhash[i]);
        }
        self.ngram_count += other.ngram_count;
    }

    /// Estimated Jaccard similarity. Returns 0.5 if either side has < `MIN_NGRAMS`.
    pub fn similarity(&self, other: &NgramSignature) -> f64 {
        if self.ngram_count < MIN_NGRAMS as u64 || other.ngram_count < MIN_NGRAMS as u64 {
            return 0.5;
        }

        let matches = self
            .minhash
            .iter()
            .zip(other.minhash.iter())
            .filter(|(a, b)| a == b)
            .count();

        matches as f64 / MINHASH_FUNCTIONS as f64
    }
}

/// SHA-256 with seed, truncated to `u64` for MinHash.
fn hash_with_seed(s: &str, seed: u64) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    hasher.update(seed.to_le_bytes());
    let result = hasher.finalize();
    u64::from_le_bytes(result[0..8].try_into().expect("8-byte slice"))
}

/// Correction/backspace behavioral signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackspaceSignature {
    /// Average characters typed between consecutive backspaces.
    pub mean_chars_before_backspace: f64,
    /// Average length of consecutive-backspace runs.
    pub mean_consecutive_backspaces: f64,
    /// Backspaces per 100 characters typed.
    pub backspace_frequency: f64,
    /// Fraction of backspaces occurring within 2 characters of prior backspace.
    pub quick_correction_rate: f64,
}

impl Default for BackspaceSignature {
    fn default() -> Self {
        Self {
            mean_chars_before_backspace: 0.0,
            mean_consecutive_backspaces: 0.0,
            backspace_frequency: 0.0,
            quick_correction_rate: 0.0,
        }
    }
}

impl BackspaceSignature {
    /// Weighted merge.
    pub fn merge(&mut self, other: &BackspaceSignature, self_weight: f64, other_weight: f64) {
        self.mean_chars_before_backspace = self.mean_chars_before_backspace * self_weight
            + other.mean_chars_before_backspace * other_weight;
        self.mean_consecutive_backspaces = self.mean_consecutive_backspaces * self_weight
            + other.mean_consecutive_backspaces * other_weight;
        self.backspace_frequency =
            self.backspace_frequency * self_weight + other.backspace_frequency * other_weight;
        self.quick_correction_rate =
            self.quick_correction_rate * self_weight + other.quick_correction_rate * other_weight;
    }

    pub fn similarity(&self, other: &BackspaceSignature) -> f64 {
        let sims = [
            relative_sim(
                self.mean_chars_before_backspace,
                other.mean_chars_before_backspace,
            ),
            relative_sim(
                self.mean_consecutive_backspaces,
                other.mean_consecutive_backspaces,
            ),
            relative_sim(self.backspace_frequency, other.backspace_frequency),
            relative_sim(self.quick_correction_rate, other.quick_correction_rate),
        ];
        sims.iter().sum::<f64>() / 4.0
    }
}

use crate::analysis::stats::relative_similarity as relative_sim;

/// Streaming collector that builds a `VoiceFingerprint` from keystroke events.
pub struct VoiceCollector {
    current_word: String,
    ngram_buffer: VecDeque<char>,
    chars_since_backspace: usize,
    consecutive_backspaces: usize,
    total_backspaces: usize,
    quick_corrections: usize,
    total_chars: usize,
    word_lengths: [usize; MAX_WORD_LENGTH],
    fingerprint: VoiceFingerprint,
    /// Running sum of chars-before-backspace gaps (for computing mean).
    chars_before_backspace_sum: usize,
    /// Number of backspace events that ended a non-zero character gap.
    chars_before_backspace_count: usize,
    /// Running sum of consecutive-backspace run lengths.
    consecutive_run_sum: usize,
    /// Number of completed consecutive-backspace runs.
    consecutive_run_count: usize,
    /// Whether the previous keystroke was a backspace (for run tracking).
    prev_was_backspace: bool,
}

impl VoiceCollector {
    pub fn new() -> Self {
        Self {
            current_word: String::new(),
            ngram_buffer: VecDeque::with_capacity(NGRAM_SIZE),
            chars_since_backspace: 0,
            consecutive_backspaces: 0,
            total_backspaces: 0,
            quick_corrections: 0,
            total_chars: 0,
            word_lengths: [0; MAX_WORD_LENGTH],
            fingerprint: VoiceFingerprint::new(false),
            chars_before_backspace_sum: 0,
            chars_before_backspace_count: 0,
            consecutive_run_sum: 0,
            consecutive_run_count: 0,
            prev_was_backspace: false,
        }
    }

    /// Process a keystroke, updating word/ngram/punctuation/backspace stats.
    pub fn record_keystroke(&mut self, keycode: u16, char_value: Option<char>) {
        if is_backspace_keycode(keycode) {
            self.handle_backspace();
            return;
        }

        // End of a consecutive-backspace run — record it.
        if self.prev_was_backspace && self.consecutive_backspaces > 0 {
            self.consecutive_run_sum += self.consecutive_backspaces;
            self.consecutive_run_count += 1;
        }
        self.consecutive_backspaces = 0;
        self.prev_was_backspace = false;

        if let Some(c) = char_value {
            self.total_chars += 1;
            self.chars_since_backspace += 1;

            if c.is_alphabetic() {
                self.current_word.extend(c.to_lowercase());
                self.add_to_ngram_buffer(c);
            } else if c.is_whitespace() || c.is_ascii_punctuation() {
                self.finish_word();
                if c.is_ascii_punctuation() {
                    self.fingerprint.punctuation_signature.record(c);
                }
            }
        }
    }

    fn handle_backspace(&mut self) {
        self.total_backspaces += 1;
        self.consecutive_backspaces += 1;
        self.prev_was_backspace = true;

        // Record the gap length before this backspace run started.
        if self.consecutive_backspaces == 1 && self.chars_since_backspace > 0 {
            self.chars_before_backspace_sum += self.chars_since_backspace;
            self.chars_before_backspace_count += 1;
        }

        if self.chars_since_backspace <= 2 {
            self.quick_corrections += 1;
        }
        self.chars_since_backspace = 0;

        self.current_word.pop();
        self.ngram_buffer.pop_back();
    }

    fn finish_word(&mut self) {
        if !self.current_word.is_empty() {
            let len = self.current_word.len().min(MAX_WORD_LENGTH);
            if len > 0 {
                self.word_lengths[len - 1] += 1;
            }
            self.fingerprint.total_words += 1;
        }
        self.current_word.clear();
    }

    fn add_to_ngram_buffer(&mut self, c: char) {
        self.ngram_buffer
            .push_back(c.to_lowercase().next().unwrap_or(c));
        if self.ngram_buffer.len() > NGRAM_SIZE {
            self.ngram_buffer.pop_front();
        }

        if self.ngram_buffer.len() == NGRAM_SIZE {
            let ngram: String = self.ngram_buffer.iter().collect();
            self.fingerprint.ngram_signature.add_ngram(&ngram);
        }
    }

    /// Snapshot the accumulated stats into a `VoiceFingerprint`.
    pub fn current_fingerprint(&self) -> VoiceFingerprint {
        let mut fp = self.fingerprint.clone();

        let total_words: usize = self.word_lengths.iter().sum();
        if total_words > 0 {
            for i in 0..MAX_WORD_LENGTH {
                fp.word_length_distribution[i] = self.word_lengths[i] as f32 / total_words as f32;
            }
        }

        if self.total_chars > 0 {
            fp.correction_rate = self.total_backspaces as f64 / self.total_chars as f64;
            fp.backspace_signature.backspace_frequency =
                (self.total_backspaces as f64 / self.total_chars as f64) * 100.0;
            if self.total_backspaces > 0 {
                fp.backspace_signature.quick_correction_rate =
                    self.quick_corrections as f64 / self.total_backspaces as f64;
            }
            if self.chars_before_backspace_count > 0 {
                fp.backspace_signature.mean_chars_before_backspace = self.chars_before_backspace_sum
                    as f64
                    / self.chars_before_backspace_count as f64;
            }
            // Include any in-progress backspace run in the mean.
            let run_count = self.consecutive_run_count
                + if self.consecutive_backspaces > 0 {
                    1
                } else {
                    0
                };
            let run_sum = self.consecutive_run_sum + self.consecutive_backspaces;
            if run_count > 0 {
                fp.backspace_signature.mean_consecutive_backspaces =
                    run_sum as f64 / run_count as f64;
            }
        }

        fp.total_chars = self.total_chars as u64;
        fp.punctuation_signature.normalize();

        fp
    }

    pub fn sample_count(&self) -> usize {
        self.total_chars
    }

    pub fn reset(&mut self) {
        self.current_word.clear();
        self.ngram_buffer.clear();
        self.chars_since_backspace = 0;
        self.consecutive_backspaces = 0;
        self.total_backspaces = 0;
        self.quick_corrections = 0;
        self.total_chars = 0;
        self.word_lengths = [0; MAX_WORD_LENGTH];
        self.fingerprint = VoiceFingerprint::new(false);
        self.chars_before_backspace_sum = 0;
        self.chars_before_backspace_count = 0;
        self.consecutive_run_sum = 0;
        self.consecutive_run_count = 0;
        self.prev_was_backspace = false;
    }
}

impl Default for VoiceCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Cross-platform backspace detection (macOS/Linux/Windows/ASCII DEL).
fn is_backspace_keycode(keycode: u16) -> bool {
    keycode == 0x33 || keycode == 14 || keycode == 0x08 || keycode == 0x7F
}

/// Bhattacharyya coefficient between two f32 histograms.
pub fn histogram_similarity(a: &[f32], b: &[f32]) -> f64 {
    a.iter()
        .zip(b.iter())
        .map(|(&x, &y)| ((x as f64) * (y as f64)).sqrt())
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_voice_fingerprint_default() {
        let fp = VoiceFingerprint::default();
        assert!(!fp.consent_given);
        assert_eq!(fp.total_chars, 0);
    }

    #[test]
    fn test_minhash_similarity() {
        let mut sig1 = NgramSignature::default();
        let mut sig2 = NgramSignature::default();

        for word in ["the", "quick", "brown", "fox", "jumps"] {
            for ngram in word.chars().collect::<Vec<_>>().windows(3) {
                let s: String = ngram.iter().collect();
                sig1.add_ngram(&s);
                sig2.add_ngram(&s);
            }
        }

        for i in 0..50 {
            sig1.add_ngram(&format!("xxx{}", i));
            sig2.add_ngram(&format!("xxx{}", i));
        }

        let sim = sig1.similarity(&sig2);
        assert!(sim > 0.9, "Same content should have high similarity");
    }

    #[test]
    fn test_voice_collector() {
        let mut collector = VoiceCollector::new();

        for c in "hello".chars() {
            collector.record_keystroke(0, Some(c));
        }
        collector.record_keystroke(0, Some(' '));
        for c in "world".chars() {
            collector.record_keystroke(0, Some(c));
        }
        collector.record_keystroke(0, Some('.'));

        let fp = collector.current_fingerprint();
        assert_eq!(fp.total_words, 2);
        assert!(fp.total_chars > 0);
    }

    #[test]
    fn test_punctuation_signature() {
        let mut sig = PunctuationSignature::default();
        sig.record('.');
        sig.record('.');
        sig.record(',');
        sig.normalize();

        assert!(sig.frequencies.get(&'.').unwrap() > sig.frequencies.get(&',').unwrap());
    }
}
