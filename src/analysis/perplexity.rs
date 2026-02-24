use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A lightweight character-level n-gram model for perplexity analysis.
/// Used to detect text that deviates from the user's natural statistical patterns.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PerplexityModel {
    pub n: usize,
    pub counts: HashMap<String, HashMap<char, usize>>,
    pub totals: HashMap<String, usize>,
    pub sample_count: usize,
}

impl PerplexityModel {
    pub fn new(n: usize) -> Self {
        Self {
            n,
            ..Default::default()
        }
    }

    /// Trains the model on a piece of text.
    pub fn train(&mut self, text: &str) {
        if text.len() < self.n {
            return;
        }

        let chars: Vec<char> = text.chars().collect();
        for i in 0..(chars.len() - self.n) {
            let context: String = chars[i..(i + self.n)].iter().collect();
            let next_char = chars[i + self.n];

            *self
                .counts
                .entry(context.clone())
                .or_default()
                .entry(next_char)
                .or_default() += 1;
            *self.totals.entry(context).or_default() += 1;
        }
        self.sample_count += text.len();
    }

    /// Calculates the perplexity of a piece of text.
    /// Lower score = more "natural" (according to trained data).
    /// Higher score = more "surprising" (potentially AI or different author).
    pub fn calculate_perplexity(&self, text: &str) -> f64 {
        if self.sample_count < 1000 || text.len() < self.n {
            return 1.0; // Neutral score if model is not sufficiently trained
        }

        let chars: Vec<char> = text.chars().collect();
        let mut log_prob_sum = 0.0;
        let mut count = 0;

        for i in 0..(chars.len() - self.n) {
            let context: String = chars[i..(i + self.n)].iter().collect();
            let next_char = chars[i + self.n];

            let prob = if let Some(context_counts) = self.counts.get(&context) {
                let char_count = *context_counts.get(&next_char).unwrap_or(&0);
                let total = *self.totals.get(&context).unwrap_or(&1);

                // Simple Laplace smoothing
                (char_count as f64 + 0.1) / (total as f64 + 0.1 * 256.0)
            } else {
                // Backoff or absolute smoothing
                0.1 / (self.sample_count as f64 + 256.0)
            };

            log_prob_sum += prob.ln();
            count += 1;
        }

        if count == 0 {
            return 1.0;
        }

        // Perplexity = exp(-1/N * sum(log P))
        (-log_prob_sum / count as f64).exp()
    }
}
