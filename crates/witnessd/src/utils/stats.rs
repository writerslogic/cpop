// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Shared math and statistics utilities.

use crate::utils::finite_or;

/// Compute the arithmetic mean of a slice of `f64`.
pub fn mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let sum: f64 = values.iter().sum();
    sum / values.len() as f64
}

/// Compute population standard deviation and mean in a single pass.
/// Returns (mean, std_dev).
pub fn mean_and_std_dev(values: &[f64]) -> (f64, f64) {
    let n = values.len();
    if n == 0 {
        return (0.0, 0.0);
    }
    if n == 1 {
        return (values[0], 0.0);
    }

    // Welford's algorithm for numerical stability
    let mut m = 0.0;
    let mut s = 0.0;
    for (k, &x) in values.iter().enumerate() {
        let old_m = m;
        m += (x - old_m) / (k + 1) as f64;
        s += (x - old_m) * (x - m);
    }

    (m, (s / n as f64).sqrt())
}

/// Compute the population standard deviation of a slice of `f64`.
pub fn std_dev(values: &[f64]) -> f64 {
    mean_and_std_dev(values).1
}

/// Compute the coefficient of variation (std_dev / mean) of a slice of `f64`.
pub fn coefficient_of_variation(values: &[f64]) -> f64 {
    let (m, std) = mean_and_std_dev(values);
    if m.abs() <= f64::EPSILON {
        return 0.0;
    }
    finite_or(std / m, 0.0)
}

/// Compute the median of a slice of `f64`.
pub fn median(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut sorted = values.to_vec();
    // Use partial_cmp to handle NaNs by sorting them to the end.
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let len = sorted.len();
    if len % 2 == 1 {
        sorted[len / 2]
    } else {
        (sorted[len / 2 - 1] + sorted[len / 2]) / 2.0
    }
}
