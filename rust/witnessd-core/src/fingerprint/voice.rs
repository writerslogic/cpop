//! Voice Fingerprint - Writing style analysis
//!
//! This module captures writing style characteristics WITHOUT storing raw text:
//! - Word length distribution
//! - Punctuation patterns
//! - N-gram signatures (hashed, not plaintext)
//! - Correction/backspace patterns
//!
//! This is DISABLED by default and requires explicit consent.
//!
//! # Privacy
//!
//! - No raw text is ever stored
//! - N-grams are hashed using MinHash for anonymization
//! - All metrics are statistical aggregates
//! - Data can be completely deleted by revoking consent

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};

// =============================================================================
// Constants
// =============================================================================

/// Maximum word length tracked
const MAX_WORD_LENGTH: usize = 20;
/// Number of hash functions for MinHash
const MINHASH_FUNCTIONS: usize = 100;
/// N-gram size for signature
const NGRAM_SIZE: usize = 3;
/// Minimum n-grams before generating signature
const MIN_NGRAMS: usize = 50;

// =============================================================================
// VoiceFingerprint
// =============================================================================

/// Voice fingerprint capturing writing style without storing content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoiceFingerprint {
    /// Whether consent was given for this fingerprint
    pub consent_given: bool,
    /// Word length distribution (1-20 characters)
    pub word_length_distribution: [f32; MAX_WORD_LENGTH],
    /// Punctuation usage signature
    pub punctuation_signature: PunctuationSignature,
    /// N-gram signature using MinHash (no raw text)
    pub ngram_signature: NgramSignature,
    /// Correction/editing behavior
    pub correction_rate: f64,
    /// Backspace usage patterns
    pub backspace_signature: BackspaceSignature,
    /// Total characters processed
    pub total_chars: u64,
    /// Total words processed
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
    /// Create a new voice fingerprint with consent flag.
    pub fn new(consent_given: bool) -> Self {
        Self {
            consent_given,
            ..Default::default()
        }
    }

    /// Merge another fingerprint into this one.
    pub fn merge(&mut self, other: &VoiceFingerprint) {
        let total = self.total_chars + other.total_chars;
        if total == 0 {
            return;
        }

        let self_weight = self.total_chars as f64 / total as f64;
        let other_weight = other.total_chars as f64 / total as f64;

        // Word length distribution
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

    /// Calculate the average word length from the distribution.
    pub fn avg_word_length(&self) -> f64 {
        let mut weighted_sum = 0.0;
        let mut total_weight = 0.0;
        for (i, &freq) in self.word_length_distribution.iter().enumerate() {
            let word_len = (i + 1) as f64; // 1-indexed
            weighted_sum += word_len * freq as f64;
            total_weight += freq as f64;
        }
        if total_weight > 0.0 {
            weighted_sum / total_weight
        } else {
            0.0
        }
    }

    /// Calculate similarity with another fingerprint.
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

        // Weighted combination
        (word_len_sim * 0.25 + punct_sim * 0.25 + ngram_sim * 0.35 + correction_sim * 0.15)
            .clamp(0.0, 1.0)
    }
}

// =============================================================================
// Punctuation Signature
// =============================================================================

/// Punctuation usage patterns.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PunctuationSignature {
    /// Frequency of common punctuation marks (normalized)
    pub frequencies: HashMap<char, f32>,
    /// Punctuation after word patterns (e.g., comma after "and")
    pub context_patterns: Vec<u64>, // Hashed patterns
}

impl PunctuationSignature {
    /// Record a punctuation character.
    pub fn record(&mut self, c: char) {
        if c.is_ascii_punctuation() {
            *self.frequencies.entry(c).or_insert(0.0) += 1.0;
        }
    }

    /// Normalize frequencies.
    pub fn normalize(&mut self) {
        let total: f32 = self.frequencies.values().sum();
        if total > 0.0 {
            for v in self.frequencies.values_mut() {
                *v /= total;
            }
        }
    }

    /// Merge with another signature.
    pub fn merge(&mut self, other: &PunctuationSignature, self_weight: f64, other_weight: f64) {
        for (k, v) in &other.frequencies {
            let entry = self.frequencies.entry(*k).or_insert(0.0);
            *entry = (*entry as f64 * self_weight + *v as f64 * other_weight) as f32;
        }
    }

    /// Calculate similarity.
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

// =============================================================================
// N-gram Signature
// =============================================================================

/// N-gram signature using MinHash for privacy-preserving style matching.
///
/// This captures writing style patterns without storing actual text.
/// The MinHash signature allows similarity comparison without revealing content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NgramSignature {
    /// MinHash signature (hashes of minimum hash values)
    pub minhash: Vec<u64>,
    /// Number of n-grams processed
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
    /// Add an n-gram to the signature.
    pub fn add_ngram(&mut self, ngram: &str) {
        // Hash the n-gram with different seeds to get MinHash values
        for i in 0..MINHASH_FUNCTIONS {
            let hash = hash_with_seed(ngram, i as u64);
            if hash < self.minhash[i] {
                self.minhash[i] = hash;
            }
        }
        self.ngram_count += 1;
    }

    /// Merge with another signature.
    pub fn merge(&mut self, other: &NgramSignature) {
        // MinHash merge: take minimum of each position
        for i in 0..MINHASH_FUNCTIONS {
            self.minhash[i] = self.minhash[i].min(other.minhash[i]);
        }
        self.ngram_count += other.ngram_count;
    }

    /// Calculate Jaccard similarity estimate using MinHash.
    pub fn similarity(&self, other: &NgramSignature) -> f64 {
        if self.ngram_count < MIN_NGRAMS as u64 || other.ngram_count < MIN_NGRAMS as u64 {
            // Not enough data for reliable comparison
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

/// Hash a string with a seed for MinHash.
fn hash_with_seed(s: &str, seed: u64) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    hasher.update(seed.to_le_bytes());
    let result = hasher.finalize();
    // Take first 8 bytes as u64
    u64::from_le_bytes(result[0..8].try_into().unwrap())
}

// =============================================================================
// Backspace Signature
// =============================================================================

/// Backspace/correction behavior patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackspaceSignature {
    /// Average characters before backspace
    pub mean_chars_before_backspace: f64,
    /// Average consecutive backspaces
    pub mean_consecutive_backspaces: f64,
    /// Backspace frequency (per 100 characters)
    pub backspace_frequency: f64,
    /// Quick correction rate (backspace within 2 chars of mistake)
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
    /// Merge with another signature.
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

    /// Calculate similarity.
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

fn relative_sim(a: f64, b: f64) -> f64 {
    if a == 0.0 && b == 0.0 {
        1.0
    } else {
        1.0 - (a - b).abs() / (a + b + 0.001)
    }
}

// =============================================================================
// Voice Collector
// =============================================================================

/// Collector for building voice fingerprints from keystroke events.
pub struct VoiceCollector {
    /// Current word buffer
    current_word: String,
    /// Recent n-grams (sliding window)
    ngram_buffer: VecDeque<char>,
    /// Characters since last backspace
    chars_since_backspace: usize,
    /// Consecutive backspace count
    consecutive_backspaces: usize,
    /// Total backspace count
    total_backspaces: usize,
    /// Quick corrections (backspace within 2 chars)
    quick_corrections: usize,
    /// Total character count
    total_chars: usize,
    /// Word length counts
    word_lengths: [usize; MAX_WORD_LENGTH],
    /// Current fingerprint
    fingerprint: VoiceFingerprint,
}

impl VoiceCollector {
    /// Create a new voice collector.
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
            fingerprint: VoiceFingerprint::new(true),
        }
    }

    /// Record a keystroke.
    pub fn record_keystroke(&mut self, keycode: u16, char_value: Option<char>) {
        // Check for backspace
        if is_backspace_keycode(keycode) {
            self.handle_backspace();
            return;
        }

        self.consecutive_backspaces = 0;

        if let Some(c) = char_value {
            self.total_chars += 1;
            self.chars_since_backspace += 1;

            if c.is_alphabetic() {
                self.current_word.push(c.to_lowercase().next().unwrap_or(c));
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

        if self.chars_since_backspace <= 2 {
            self.quick_corrections += 1;
        }
        self.chars_since_backspace = 0;

        // Remove from current word
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

    /// Get the current fingerprint.
    pub fn current_fingerprint(&self) -> VoiceFingerprint {
        let mut fp = self.fingerprint.clone();

        // Update word length distribution
        let total_words: usize = self.word_lengths.iter().sum();
        if total_words > 0 {
            for i in 0..MAX_WORD_LENGTH {
                fp.word_length_distribution[i] = self.word_lengths[i] as f32 / total_words as f32;
            }
        }

        // Update backspace signature
        if self.total_chars > 0 {
            fp.correction_rate = self.total_backspaces as f64 / self.total_chars as f64;
            fp.backspace_signature.backspace_frequency =
                (self.total_backspaces as f64 / self.total_chars as f64) * 100.0;
            if self.total_backspaces > 0 {
                fp.backspace_signature.quick_correction_rate =
                    self.quick_corrections as f64 / self.total_backspaces as f64;
            }
        }

        fp.total_chars = self.total_chars as u64;
        fp.punctuation_signature.normalize();

        fp
    }

    /// Get the number of samples (characters).
    pub fn sample_count(&self) -> usize {
        self.total_chars
    }

    /// Reset the collector.
    pub fn reset(&mut self) {
        self.current_word.clear();
        self.ngram_buffer.clear();
        self.chars_since_backspace = 0;
        self.consecutive_backspaces = 0;
        self.total_backspaces = 0;
        self.quick_corrections = 0;
        self.total_chars = 0;
        self.word_lengths = [0; MAX_WORD_LENGTH];
        self.fingerprint = VoiceFingerprint::new(true);
    }
}

impl Default for VoiceCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if a keycode is backspace.
fn is_backspace_keycode(keycode: u16) -> bool {
    // Common backspace keycodes across platforms
    keycode == 0x33     // macOS
        || keycode == 14    // Linux evdev
        || keycode == 0x08  // Windows VK_BACK
        || keycode == 0x7F // ASCII DEL
}

/// Calculate histogram similarity (Bhattacharyya coefficient).
pub fn histogram_similarity(a: &[f32], b: &[f32]) -> f64 {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| ((*x as f64) * (*y as f64)).sqrt())
        .sum()
}

// =============================================================================
// Tests
// =============================================================================

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

        // Same content should have high similarity
        for word in ["the", "quick", "brown", "fox", "jumps"] {
            for ngram in word.chars().collect::<Vec<_>>().windows(3) {
                let s: String = ngram.iter().collect();
                sig1.add_ngram(&s);
                sig2.add_ngram(&s);
            }
        }

        // Need minimum n-grams for comparison
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

        // Simulate typing "hello world"
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
