// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

/// Single-pass mean and sample standard deviation.
pub fn mean_and_std_dev(data: &[f64]) -> (f64, f64) {
    let n = data.len() as f64;
    if n < 1.0 {
        return (0.0, 0.0);
    }
    let sum: f64 = data.iter().sum();
    let mean = sum / n;
    if n < 2.0 {
        return (mean, 0.0);
    }
    let sum_sq: f64 = data.iter().map(|&x| (x - mean).powi(2)).sum();
    let std_dev = (sum_sq / (n - 1.0)).sqrt();
    (mean, std_dev)
}

/// Mean of a slice, or 0.0 if empty.
pub fn mean_or_zero(data: &[f64]) -> f64 {
    if data.is_empty() {
        0.0
    } else {
        data.iter().sum::<f64>() / data.len() as f64
    }
}

/// Population skewness given pre-computed mean and std dev.
pub fn skewness(data: &[f64], mean: f64, std: f64) -> f64 {
    if std == 0.0 || data.is_empty() {
        return 0.0;
    }
    let n = data.len() as f64;
    let sum_cubed: f64 = data.iter().map(|&x| ((x - mean) / std).powi(3)).sum();
    sum_cubed / n
}

/// Excess kurtosis given pre-computed mean and std dev.
pub fn kurtosis(data: &[f64], mean: f64, std: f64) -> f64 {
    if std == 0.0 || data.is_empty() {
        return 0.0;
    }
    let n = data.len() as f64;
    let sum_fourth: f64 = data.iter().map(|&x| ((x - mean) / std).powi(4)).sum();
    sum_fourth / n - 3.0
}

/// Bhattacharyya coefficient between two f64 histograms.
///
/// If the slices differ in length, only the overlapping prefix is compared
/// and a warning is logged.
pub fn bhattacharyya_coefficient(a: &[f64], b: &[f64]) -> f64 {
    if a.len() != b.len() {
        log::warn!(
            "bhattacharyya_coefficient: length mismatch (a={}, b={}); truncating to min",
            a.len(),
            b.len()
        );
    }
    a.iter()
        .zip(b.iter())
        .map(|(&x, &y)| (x.max(0.0) * y.max(0.0)).sqrt())
        .sum()
}

/// Normalize a histogram in place so entries sum to 1.0.
///
/// If the histogram sums to zero (or negative), it is left unchanged.
pub fn normalize_histogram(hist: &mut [f64]) {
    let total: f64 = hist.iter().sum();
    if total > 0.0 {
        for h in hist {
            *h /= total;
        }
    }
}

/// Weighted merge of histogram `b` into `a`: `a[i] = a[i] * a_weight + b[i] * b_weight`.
///
/// If `b` is shorter than `a`, the trailing bins in `a` are scaled by `a_weight` only
/// (equivalent to padding `b` with zeros). A warning is logged on length mismatch.
pub fn merge_histogram(a: &mut [f64], b: &[f64], a_weight: f64, b_weight: f64) {
    if a.len() != b.len() {
        log::warn!(
            "merge_histogram: length mismatch (a={}, b={}); padding shorter with zeros",
            a.len(),
            b.len()
        );
    }
    let overlap = a.len().min(b.len());
    for i in 0..overlap {
        a[i] = a[i] * a_weight + b[i] * b_weight;
    }
    for i in overlap..a.len() {
        a[i] *= a_weight;
    }
}

/// Cosine similarity between two f64 slices.
///
/// Returns 0.0 if either vector has zero magnitude.
pub fn cosine_similarity(a: &[f64], b: &[f64]) -> f64 {
    let mut dot = 0.0;
    let mut norm_a = 0.0;
    let mut norm_b = 0.0;
    for (&fa, &fb) in a.iter().zip(b.iter()) {
        dot += fa * fb;
        norm_a += fa * fa;
        norm_b += fb * fb;
    }
    if norm_a <= 0.0 || norm_b <= 0.0 {
        return 0.0;
    }
    dot / (norm_a.sqrt() * norm_b.sqrt())
}

/// Relative similarity: 1.0 when both zero, else `1 - |a-b|/(a+b+ε)`.
pub fn relative_similarity(a: f64, b: f64) -> f64 {
    if a == 0.0 && b == 0.0 {
        1.0
    } else {
        1.0 - (a - b).abs() / (a + b + 0.001)
    }
}

/// Linear regression returning (slope, intercept, r_squared, std_error).
pub fn linear_regression(x: &[f64], y: &[f64]) -> Result<(f64, f64, f64, f64), String> {
    let n = x.len();
    if n < 2 || n != y.len() {
        return Err("Regression requires at least 2 matching data points".to_string());
    }

    let x_mean: f64 = x.iter().sum::<f64>() / n as f64;
    let y_mean: f64 = y.iter().sum::<f64>() / n as f64;

    let mut ss_xx = 0.0;
    let mut ss_xy = 0.0;
    let mut ss_yy = 0.0;

    for i in 0..n {
        let dx = x[i] - x_mean;
        let dy = y[i] - y_mean;
        ss_xx += dx * dx;
        ss_xy += dx * dy;
        ss_yy += dy * dy;
    }

    if ss_xx.abs() < f64::EPSILON {
        return Err("No variance in x data".to_string());
    }

    let slope = ss_xy / ss_xx;
    if !slope.is_finite() {
        return Err("Degenerate regression: slope is NaN/Inf".to_string());
    }
    let intercept = y_mean - slope * x_mean;

    let r_squared = if ss_yy > 0.0 {
        let r2 = (ss_xy * ss_xy) / (ss_xx * ss_yy);
        if r2.is_finite() {
            r2
        } else {
            0.0
        }
    } else {
        1.0
    };

    let mut ss_res = 0.0;
    for i in 0..n {
        let predicted = slope * x[i] + intercept;
        ss_res += (y[i] - predicted).powi(2);
    }
    let mse = ss_res / (n - 2).max(1) as f64;
    let std_error = (mse / ss_xx).sqrt();
    let std_error = if std_error.is_finite() {
        std_error
    } else {
        0.0
    };

    Ok((slope, intercept, r_squared, std_error))
}
