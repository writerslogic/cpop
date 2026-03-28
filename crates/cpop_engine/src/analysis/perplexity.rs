// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Character-level n-gram model for perplexity-based authorship anomaly detection.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PerplexityModel {
    /// N-gram order (context length in characters).
    pub n: usize,
    /// Per-context character frequency counts.
    pub counts: HashMap<String, HashMap<char, usize>>,
    /// Total observations per context string.
    pub totals: HashMap<String, usize>,
    /// Total characters ingested during training.
    pub sample_count: usize,
}

impl PerplexityModel {
    /// Create an empty model with the given n-gram order.
    pub fn new(n: usize) -> Self {
        Self {
            n,
            ..Default::default()
        }
    }

    /// Ingest text, updating n-gram frequency tables.
    pub fn train(&mut self, text: &str) {
        let chars: Vec<char> = text.chars().collect();
        if chars.len() <= self.n {
            return;
        }

        let mut buf = String::with_capacity(self.n * 4);
        for i in 0..(chars.len() - self.n) {
            buf.clear();
            buf.extend(&chars[i..(i + self.n)]);
            let next_char = chars[i + self.n];

            // Lookup by &str avoids allocation for existing contexts (the common case).
            if let Some(total) = self.totals.get_mut(buf.as_str()) {
                *total += 1;
                if let Some(char_map) = self.counts.get_mut(buf.as_str()) {
                    *char_map.entry(next_char).or_default() += 1;
                } else {
                    let mut char_map = HashMap::new();
                    char_map.insert(next_char, 1);
                    self.counts.insert(buf.clone(), char_map);
                }
            } else {
                let key = buf.clone();
                self.totals.insert(key.clone(), 1);
                let mut char_map = HashMap::new();
                char_map.insert(next_char, 1);
                self.counts.insert(key, char_map);
            }
        }
        self.sample_count += text.chars().count();
    }

    /// Perplexity of `text` under the trained model.
    /// Low = natural, high = anomalous. Returns 1.0 if undertrained (< 1000 chars).
    pub fn compute_perplexity(&self, text: &str) -> f64 {
        if self.sample_count < 1000 {
            return 1.0;
        }

        let chars: Vec<char> = text.chars().collect();
        if chars.len() <= self.n {
            return 1.0;
        }

        let mut log_prob_sum = 0.0;
        let mut count = 0;
        let mut buf = String::with_capacity(self.n * 4);

        for i in 0..(chars.len() - self.n) {
            buf.clear();
            buf.extend(&chars[i..(i + self.n)]);
            let next_char = chars[i + self.n];

            let prob = if let Some(context_counts) = self.counts.get(buf.as_str()) {
                let char_count = *context_counts.get(&next_char).unwrap_or(&0);
                let total = *self.totals.get(buf.as_str()).unwrap_or(&1);

                // Laplace smoothing
                (char_count as f64 + 0.1) / (total as f64 + 0.1 * 256.0)
            } else {
                // Backoff smoothing for unseen contexts
                0.1 / (self.sample_count as f64 + 256.0)
            };

            log_prob_sum += prob.ln();
            count += 1;
        }

        if count == 0 {
            return 1.0;
        }

        (-log_prob_sum / count as f64).exp()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_model_defaults() {
        let model = PerplexityModel::new(3);
        assert_eq!(model.n, 3);
        assert_eq!(model.sample_count, 0);
        assert!(model.counts.is_empty());
        assert!(model.totals.is_empty());
    }

    #[test]
    fn test_train_populates_ngrams() {
        let mut model = PerplexityModel::new(2);
        model.train("hello world");

        assert!(model.sample_count > 0);
        assert!(!model.counts.is_empty());
        assert!(model.counts.contains_key("he"));
        assert!(model.counts.contains_key("ll"));
    }

    #[test]
    fn test_train_short_text_noop() {
        let mut model = PerplexityModel::new(5);
        model.train("hi"); // len 2 <= n=5, counts not populated

        assert!(model.counts.is_empty());
    }

    #[test]
    fn test_perplexity_undertrained_returns_one() {
        let mut model = PerplexityModel::new(2);
        model.train("short");

        let ppl = model.compute_perplexity("test text");
        assert!((ppl - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_perplexity_familiar_text_lower_than_random() {
        let mut model = PerplexityModel::new(2);
        let training = "the quick brown fox jumps over the lazy dog ".repeat(50);
        model.train(&training);

        let ppl_same = model.compute_perplexity("the quick brown fox jumps over the lazy dog");
        let ppl_random = model.compute_perplexity("xzqw jklm npqr stvw yzab cdef ghij");

        assert!(
            ppl_same < ppl_random,
            "Perplexity of familiar text ({ppl_same}) should be lower than random ({ppl_random})"
        );
    }

    #[test]
    fn test_perplexity_short_input_returns_one() {
        let mut model = PerplexityModel::new(3);
        let training = "the quick brown fox jumps over the lazy dog ".repeat(50);
        model.train(&training);

        let ppl = model.compute_perplexity("ab");
        assert!((ppl - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_incremental_training() {
        let mut model = PerplexityModel::new(2);
        model.train("hello ");
        let count_after_first = model.sample_count;

        model.train("world ");
        assert!(model.sample_count > count_after_first);
        assert!(model.counts.contains_key("wo"));
    }

    #[test]
    fn test_perplexity_is_positive_and_finite() {
        let mut model = PerplexityModel::new(2);
        let training = "abcdefghijklmnopqrstuvwxyz ".repeat(50);
        model.train(&training);

        let ppl = model.compute_perplexity("abcdefghij");
        assert!(ppl > 0.0, "Perplexity must be positive, got {ppl}");
        assert!(ppl.is_finite(), "Perplexity must be finite, got {ppl}");
    }
}
