// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

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

    if ss_xx == 0.0 {
        return Err("No variance in x data".to_string());
    }

    let slope = ss_xy / ss_xx;
    let intercept = y_mean - slope * x_mean;

    let r_squared = if ss_yy > 0.0 {
        (ss_xy * ss_xy) / (ss_xx * ss_yy)
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

    Ok((slope, intercept, r_squared, std_error))
}
