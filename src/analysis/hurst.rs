//! Hurst exponent calculation for time series analysis.
//!
//! The Hurst exponent (H) characterizes the long-term memory of time series:
//! - H ≈ 0.5: Random walk (white noise) - no memory
//! - H > 0.5: Persistent/trending behavior
//! - H < 0.5: Anti-persistent/mean-reverting
//!
//! Human typing patterns typically exhibit H ≈ 0.7 (mild persistence),
//! reflecting cognitive rhythm and motor control patterns.
//!
//! RFC draft-condrey-rats-pop-01 specifies:
//! - Reject H ≈ 0.5 (pure random - likely synthetic)
//! - Reject H ≈ 1.0 (fully predictable - likely scripted)
//! - Accept H ∈ [0.55, 0.85] as biologically plausible

use serde::{Deserialize, Serialize};

/// Hurst exponent analysis result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HurstAnalysis {
    /// The calculated Hurst exponent.
    pub exponent: f64,

    /// Standard error of the estimate.
    pub std_error: f64,

    /// R-squared value indicating fit quality.
    pub r_squared: f64,

    /// Interpretation of the result.
    pub interpretation: HurstInterpretation,

    /// Whether this passes RFC validation.
    pub is_valid: bool,
}

/// Interpretation of Hurst exponent value.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum HurstInterpretation {
    /// H ≈ 0.5: White noise, random walk (suspicious for human input).
    WhiteNoise,
    /// H < 0.5: Anti-persistent, mean-reverting.
    AntiPersistent,
    /// H ∈ (0.5, 0.85]: Persistent, long memory (typical of human input).
    Persistent,
    /// H > 0.85: Highly predictable (suspicious for human input).
    HighlyPredictable,
}

impl HurstAnalysis {
    /// RFC-compliant validation range for human input.
    pub const MIN_VALID: f64 = 0.55;
    pub const MAX_VALID: f64 = 0.85;
    pub const WHITE_NOISE_TOLERANCE: f64 = 0.05;

    /// Check if the Hurst exponent is within biologically plausible range.
    pub fn is_biologically_plausible(&self) -> bool {
        self.exponent >= Self::MIN_VALID && self.exponent <= Self::MAX_VALID
    }

    /// Check if the series appears to be white noise.
    pub fn is_white_noise(&self) -> bool {
        (self.exponent - 0.5).abs() < Self::WHITE_NOISE_TOLERANCE
    }

    /// Check if the series is suspiciously predictable.
    pub fn is_suspiciously_predictable(&self) -> bool {
        self.exponent > 0.95
    }
}

/// Calculate Hurst exponent using R/S (Rescaled Range) analysis.
///
/// This is the classical method described by Mandelbrot and Wallis.
///
/// # Arguments
/// * `data` - Time series data (e.g., inter-keystroke intervals)
///
/// # Returns
/// * `HurstAnalysis` with exponent and diagnostics, or error message
pub fn calculate_hurst_rs(data: &[f64]) -> Result<HurstAnalysis, String> {
    let n = data.len();
    if n < 20 {
        return Err("Insufficient data points (minimum 20 required)".to_string());
    }

    // Use multiple window sizes for regression
    let mut log_n_vec = Vec::new();
    let mut log_rs_vec = Vec::new();

    // Window sizes: powers of 2 from 8 to n/4
    let min_window = 8;
    let max_window = n / 4;

    let mut window_size = min_window;
    while window_size <= max_window {
        let rs = calculate_rs_for_window(data, window_size);
        if rs > 0.0 {
            log_n_vec.push((window_size as f64).ln());
            log_rs_vec.push(rs.ln());
        }
        window_size *= 2;
    }

    if log_n_vec.len() < 3 {
        return Err("Insufficient window sizes for reliable estimation".to_string());
    }

    // Linear regression: log(R/S) = H * log(n) + c
    let (slope, _intercept, r_squared, std_error) = linear_regression(&log_n_vec, &log_rs_vec)?;

    let exponent = slope.clamp(0.0, 1.0);

    let interpretation = if (exponent - 0.5).abs() < 0.05 {
        HurstInterpretation::WhiteNoise
    } else if exponent < 0.5 {
        HurstInterpretation::AntiPersistent
    } else if exponent <= 0.85 {
        HurstInterpretation::Persistent
    } else {
        HurstInterpretation::HighlyPredictable
    };

    let is_valid = (HurstAnalysis::MIN_VALID..=HurstAnalysis::MAX_VALID).contains(&exponent);

    Ok(HurstAnalysis {
        exponent,
        std_error,
        r_squared,
        interpretation,
        is_valid,
    })
}

/// Calculate R/S statistic for a specific window size.
fn calculate_rs_for_window(data: &[f64], window_size: usize) -> f64 {
    let n = data.len();
    if window_size > n || window_size < 2 {
        return 0.0;
    }

    let num_windows = n / window_size;
    if num_windows == 0 {
        return 0.0;
    }

    let mut rs_sum = 0.0;
    let mut valid_windows = 0;

    for i in 0..num_windows {
        let start = i * window_size;
        let end = start + window_size;
        let window = &data[start..end];

        // Calculate mean
        let mean: f64 = window.iter().sum::<f64>() / window_size as f64;

        // Calculate cumulative deviations from mean
        let mut cumulative = Vec::with_capacity(window_size);
        let mut cumsum = 0.0;
        for &x in window {
            cumsum += x - mean;
            cumulative.push(cumsum);
        }

        // Range: max - min of cumulative deviations
        let max_cumsum = cumulative.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let min_cumsum = cumulative.iter().cloned().fold(f64::INFINITY, f64::min);
        let range = max_cumsum - min_cumsum;

        // Standard deviation
        let variance: f64 =
            window.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / (window_size - 1) as f64;
        let std_dev = variance.sqrt();

        if std_dev > 0.0 {
            rs_sum += range / std_dev;
            valid_windows += 1;
        }
    }

    if valid_windows > 0 {
        rs_sum / valid_windows as f64
    } else {
        0.0
    }
}

/// Calculate Hurst exponent using Detrended Fluctuation Analysis (DFA).
///
/// DFA is more robust to non-stationarities than R/S analysis.
///
/// # Arguments
/// * `data` - Time series data
///
/// # Returns
/// * `HurstAnalysis` with exponent and diagnostics
pub fn calculate_hurst_dfa(data: &[f64]) -> Result<HurstAnalysis, String> {
    let n = data.len();
    if n < 32 {
        return Err("Insufficient data points for DFA (minimum 32 required)".to_string());
    }

    // Calculate cumulative sum (profile)
    let mean: f64 = data.iter().sum::<f64>() / n as f64;
    let mut profile = Vec::with_capacity(n);
    let mut cumsum = 0.0;
    for &x in data {
        cumsum += x - mean;
        profile.push(cumsum);
    }

    // Calculate fluctuation function for different scales
    let mut log_scales = Vec::new();
    let mut log_fluct = Vec::new();

    // Scales from 8 to n/4
    let min_scale = 8;
    let max_scale = n / 4;

    let mut scale = min_scale;
    while scale <= max_scale {
        let f = calculate_dfa_fluctuation(&profile, scale);
        if f > 0.0 {
            log_scales.push((scale as f64).ln());
            log_fluct.push(f.ln());
        }
        scale = (scale as f64 * 1.5).ceil() as usize;
    }

    if log_scales.len() < 3 {
        return Err("Insufficient scales for reliable DFA estimation".to_string());
    }

    // Linear regression to get Hurst exponent
    let (slope, _intercept, r_squared, std_error) = linear_regression(&log_scales, &log_fluct)?;

    let exponent = slope.clamp(0.0, 2.0);

    let interpretation = if (exponent - 0.5).abs() < 0.05 {
        HurstInterpretation::WhiteNoise
    } else if exponent < 0.5 {
        HurstInterpretation::AntiPersistent
    } else if exponent <= 0.85 {
        HurstInterpretation::Persistent
    } else {
        HurstInterpretation::HighlyPredictable
    };

    let is_valid = (HurstAnalysis::MIN_VALID..=HurstAnalysis::MAX_VALID).contains(&exponent);

    Ok(HurstAnalysis {
        exponent,
        std_error,
        r_squared,
        interpretation,
        is_valid,
    })
}

/// Calculate DFA fluctuation for a given scale.
fn calculate_dfa_fluctuation(profile: &[f64], scale: usize) -> f64 {
    let n = profile.len();
    if scale > n || scale < 4 {
        return 0.0;
    }

    let num_segments = n / scale;
    if num_segments == 0 {
        return 0.0;
    }

    let mut total_variance = 0.0;

    for i in 0..num_segments {
        let start = i * scale;
        let end = start + scale;
        let segment = &profile[start..end];

        // Linear detrend using least squares
        let detrended_variance = detrend_variance(segment);
        total_variance += detrended_variance;
    }

    // Average variance, then sqrt for fluctuation
    (total_variance / num_segments as f64).sqrt()
}

/// Calculate variance after linear detrending.
fn detrend_variance(segment: &[f64]) -> f64 {
    let n = segment.len();
    if n < 2 {
        return 0.0;
    }

    // Fit linear trend: y = a*x + b
    let x: Vec<f64> = (0..n).map(|i| i as f64).collect();
    let y = segment;

    let x_mean: f64 = x.iter().sum::<f64>() / n as f64;
    let y_mean: f64 = y.iter().sum::<f64>() / n as f64;

    let mut num = 0.0;
    let mut denom = 0.0;
    for i in 0..n {
        num += (x[i] - x_mean) * (y[i] - y_mean);
        denom += (x[i] - x_mean).powi(2);
    }

    let a = if denom > 0.0 { num / denom } else { 0.0 };
    let b = y_mean - a * x_mean;

    // Calculate variance of residuals
    let mut variance = 0.0;
    for i in 0..n {
        let predicted = a * x[i] + b;
        variance += (y[i] - predicted).powi(2);
    }

    variance / n as f64
}

/// Simple linear regression returning (slope, intercept, r_squared, std_error).
fn linear_regression(x: &[f64], y: &[f64]) -> Result<(f64, f64, f64, f64), String> {
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

    // R-squared
    let r_squared = if ss_yy > 0.0 {
        (ss_xy * ss_xy) / (ss_xx * ss_yy)
    } else {
        1.0
    };

    // Standard error of slope
    let mut ss_res = 0.0;
    for i in 0..n {
        let predicted = slope * x[i] + intercept;
        ss_res += (y[i] - predicted).powi(2);
    }
    let mse = ss_res / (n - 2).max(1) as f64;
    let std_error = (mse / ss_xx).sqrt();

    Ok((slope, intercept, r_squared, std_error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hurst_white_noise() {
        // White noise should have H ≈ 0.5
        use rand::Rng;
        let mut rng = rand::rng();
        let data: Vec<f64> = (0..500).map(|_| rng.random::<f64>()).collect();

        let result = calculate_hurst_rs(&data).unwrap();
        // White noise typically gives H in range 0.4-0.6
        assert!(
            result.exponent > 0.2 && result.exponent < 0.8,
            "White noise Hurst should be near 0.5, got {}",
            result.exponent
        );
    }

    #[test]
    fn test_hurst_trending() {
        // Cumulative sum of white noise should have H ≈ 1.0
        use rand::Rng;
        let mut rng = rand::rng();
        let mut cumsum = 0.0;
        let data: Vec<f64> = (0..500)
            .map(|_| {
                cumsum += rng.random::<f64>() - 0.5;
                cumsum
            })
            .collect();

        let result = calculate_hurst_rs(&data).unwrap();
        // Trending data should have H > 0.7
        assert!(
            result.exponent > 0.7,
            "Trending data Hurst should be > 0.7, got {}",
            result.exponent
        );
    }

    #[test]
    fn test_hurst_insufficient_data() {
        let data: Vec<f64> = vec![1.0, 2.0, 3.0];
        let result = calculate_hurst_rs(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_hurst_validity_check() {
        let analysis = HurstAnalysis {
            exponent: 0.7,
            std_error: 0.05,
            r_squared: 0.95,
            interpretation: HurstInterpretation::Persistent,
            is_valid: true,
        };

        assert!(analysis.is_biologically_plausible());
        assert!(!analysis.is_white_noise());
        assert!(!analysis.is_suspiciously_predictable());
    }

    #[test]
    fn test_dfa_basic() {
        // Simple test with synthetic data
        let data: Vec<f64> = (0..100)
            .map(|i| (i as f64).sin() + 0.1 * i as f64)
            .collect();
        let result = calculate_hurst_dfa(&data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_linear_regression() {
        let x = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let y = vec![2.0, 4.0, 6.0, 8.0, 10.0];

        let (slope, intercept, r_squared, _) = linear_regression(&x, &y).unwrap();

        assert!((slope - 2.0).abs() < 0.001);
        assert!(intercept.abs() < 0.001);
        assert!((r_squared - 1.0).abs() < 0.001);
    }
}
