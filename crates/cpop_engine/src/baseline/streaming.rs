// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use cpop_protocol::baseline::StreamingStats;

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
            min: f32::MAX,
            max: f32::NEG_INFINITY,
        }
    }

    fn update(&mut self, value: f64) {
        self.count += 1;
        let mean = self.mean as f64;
        let delta = value - mean;
        let new_mean = mean + delta / self.count as f64;
        self.mean = new_mean as f32;
        let delta2 = value - new_mean;
        self.m2 = (self.m2 as f64 + delta * delta2) as f32;

        let v32 = value as f32;
        if v32 < self.min {
            self.min = v32;
        }
        if v32 > self.max {
            self.max = v32;
        }
    }

    fn variance(&self) -> f64 {
        if self.count < 2 {
            0.0
        } else {
            self.m2 as f64 / (self.count - 1) as f64
        }
    }

    fn std_dev(&self) -> f64 {
        self.variance().sqrt()
    }
}
