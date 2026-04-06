// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use authorproof_protocol::baseline::StreamingStats;

/// Welford's online algorithm extensions for `StreamingStats`.
pub trait StreamingStatsExt {
    /// Create a zeroed stats accumulator.
    fn new_empty() -> Self;
    /// Incorporate a new sample using Welford's algorithm.
    fn update(&mut self, value: f64);
    /// Return the sample standard deviation.
    fn std_dev(&self) -> f64;
    /// Return the sample variance (Bessel-corrected).
    fn variance(&self) -> f64;
}

impl StreamingStatsExt for StreamingStats {
    fn new_empty() -> Self {
        Self {
            count: 0,
            mean: 0.0,
            m2: 0.0,
            min: f64::MAX,
            max: f64::NEG_INFINITY,
        }
    }

    fn update(&mut self, value: f64) {
        self.count += 1;
        let delta = value - self.mean;
        let new_mean = self.mean + delta / self.count as f64;
        self.mean = new_mean;
        let delta2 = value - new_mean;
        self.m2 += delta * delta2;

        if value < self.min {
            self.min = value;
        }
        if value > self.max {
            self.max = value;
        }
    }

    fn variance(&self) -> f64 {
        if self.count < 2 {
            0.0
        } else {
            self.m2 / (self.count - 1) as f64
        }
    }

    fn std_dev(&self) -> f64 {
        self.variance().sqrt()
    }
}
