// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Character-level n-gram model for perplexity-based authorship anomaly detection.
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
                *self
                    .counts
                    .get_mut(buf.as_str())
                    .unwrap()
                    .entry(next_char)
                    .or_default() += 1;
            } else {
                let key = buf.clone();
                self.totals.insert(key.clone(), 1);
                let mut char_map = HashMap::new();
                char_map.insert(next_char, 1);
                self.counts.insert(key, char_map);
            }
        }
        self.sample_count += text.len();
    }

    /// Perplexity of `text` under the trained model.
    /// Low = natural, high = anomalous. Returns 1.0 if undertrained (< 1000 chars).
    pub fn calculate_perplexity(&self, text: &str) -> f64 {
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
