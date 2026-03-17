// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::platform::events::MouseEvent;
use serde::{Deserialize, Serialize};

/// Running statistics for mouse idle jitter (used in behavioral fingerprinting).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MouseIdleStats {
    pub total_events: u64,
    pub sum_dx: f64,
    pub sum_dy: f64,
    pub sum_dx_squared: f64,
    pub sum_dy_squared: f64,
    pub sum_magnitude: f64,
    pub sum_magnitude_squared: f64,
    pub max_magnitude: f64,
    pub min_magnitude: f64,
    pub quadrant_counts: [u64; 4],
}

impl MouseIdleStats {
    pub fn new() -> Self {
        Self {
            min_magnitude: f64::MAX,
            ..Default::default()
        }
    }

    pub fn record(&mut self, event: &MouseEvent) {
        self.total_events += 1;
        self.sum_dx += event.dx;
        self.sum_dy += event.dy;
        self.sum_dx_squared += event.dx * event.dx;
        self.sum_dy_squared += event.dy * event.dy;

        let magnitude = event.movement_magnitude();
        self.sum_magnitude += magnitude;
        self.sum_magnitude_squared += magnitude * magnitude;
        self.max_magnitude = self.max_magnitude.max(magnitude);
        self.min_magnitude = self.min_magnitude.min(magnitude);

        let quadrant = match (event.dx >= 0.0, event.dy >= 0.0) {
            (true, false) => 0,
            (false, false) => 1,
            (false, true) => 2,
            (true, true) => 3,
        };
        self.quadrant_counts[quadrant] += 1;
    }

    pub fn mean_dx(&self) -> f64 {
        if self.total_events == 0 {
            0.0
        } else {
            self.sum_dx / self.total_events as f64
        }
    }

    pub fn mean_dy(&self) -> f64 {
        if self.total_events == 0 {
            0.0
        } else {
            self.sum_dy / self.total_events as f64
        }
    }

    pub fn mean_magnitude(&self) -> f64 {
        if self.total_events == 0 {
            0.0
        } else {
            self.sum_magnitude / self.total_events as f64
        }
    }

    pub fn variance_magnitude(&self) -> f64 {
        if self.total_events < 2 {
            0.0
        } else {
            let mean = self.mean_magnitude();
            (self.sum_magnitude_squared / self.total_events as f64) - (mean * mean)
        }
    }

    pub fn std_magnitude(&self) -> f64 {
        self.variance_magnitude().sqrt()
    }

    pub fn quadrant_bias(&self) -> f64 {
        if self.total_events == 0 {
            return 0.0;
        }
        let expected = self.total_events as f64 / 4.0;
        let chi_squared: f64 = self
            .quadrant_counts
            .iter()
            .map(|&count| {
                let diff = count as f64 - expected;
                (diff * diff) / expected
            })
            .sum();
        (chi_squared / (3.0 * self.total_events as f64)).min(1.0)
    }

    pub fn merge(&mut self, other: &MouseIdleStats) {
        self.total_events += other.total_events;
        self.sum_dx += other.sum_dx;
        self.sum_dy += other.sum_dy;
        self.sum_dx_squared += other.sum_dx_squared;
        self.sum_dy_squared += other.sum_dy_squared;
        self.sum_magnitude += other.sum_magnitude;
        self.sum_magnitude_squared += other.sum_magnitude_squared;
        self.max_magnitude = self.max_magnitude.max(other.max_magnitude);
        self.min_magnitude = self.min_magnitude.min(other.min_magnitude);
        for i in 0..4 {
            self.quadrant_counts[i] += other.quadrant_counts[i];
        }
    }
}

/// Mouse steganography encoding mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum MouseStegoMode {
    #[default]
    TimingOnly,
    SubPixel,
    FirstMoveOnly,
}

/// Configuration for mouse steganography timing injection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MouseStegoParams {
    pub enabled: bool,
    pub mode: MouseStegoMode,
    pub min_delay_micros: u32,
    pub max_delay_micros: u32,
    pub inject_on_first_move: bool,
    pub inject_while_traveling: bool,
}

impl Default for MouseStegoParams {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: MouseStegoMode::TimingOnly,
            min_delay_micros: 500,
            max_delay_micros: 2000,
            inject_on_first_move: true,
            inject_while_traveling: false,
        }
    }
}
