// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

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
    /// Upper bound of the RFC-valid Hurst exponent range.
    pub const MAX_VALID: f64 = 0.85;
    /// Tolerance around 0.5 for classifying as white noise.
    pub const WHITE_NOISE_TOLERANCE: f64 = 0.05;

    /// Return true if the exponent falls within biologically plausible bounds.
    pub fn is_biologically_plausible(&self) -> bool {
        self.exponent >= Self::MIN_VALID && self.exponent <= Self::MAX_VALID
    }

    /// Return true if the exponent is indistinguishable from white noise.
    pub fn is_white_noise(&self) -> bool {
        (self.exponent - 0.5).abs() < Self::WHITE_NOISE_TOLERANCE
    }

    /// Threshold above which the series is suspiciously deterministic.
    pub const SUSPICIOUSLY_PREDICTABLE: f64 = 0.95;

    /// Return true if the exponent suggests scripted or deterministic input.
    pub fn is_suspiciously_predictable(&self) -> bool {
        self.exponent > Self::SUSPICIOUSLY_PREDICTABLE
    }
}

const RS_MIN_DATA_POINTS: usize = 20;
const RS_MIN_WINDOW: usize = 8;
const DFA_MIN_DATA_POINTS: usize = 32;
const DFA_MIN_SCALE: usize = 8;

/// Calculate Hurst exponent using R/S (Rescaled Range) analysis
/// (Mandelbrot & Wallis method).
pub fn calculate_hurst_rs(data: &[f64]) -> Result<HurstAnalysis, String> {
    let n = data.len();
    if n < RS_MIN_DATA_POINTS {
        return Err("Insufficient data points (minimum 20 required)".to_string());
    }

    let mut log_n_vec = Vec::new();
    let mut log_rs_vec = Vec::new();

    let min_window = RS_MIN_WINDOW;
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

    let (slope, _intercept, r_squared, std_error) = linear_regression(&log_n_vec, &log_rs_vec)?;

    // NaN/Inf from degenerate inputs would bypass clamp and propagate silently
    if !slope.is_finite() || !r_squared.is_finite() || !std_error.is_finite() {
        return Err("Degenerate regression output (NaN/Inf)".to_string());
    }

    // R/S Hurst exponent is bounded [0, 1] by definition
    let exponent = slope.clamp(0.0, 1.0);

    let interpretation = if (exponent - 0.5).abs() < HurstAnalysis::WHITE_NOISE_TOLERANCE {
        HurstInterpretation::WhiteNoise
    } else if exponent < 0.5 {
        HurstInterpretation::AntiPersistent
    } else if exponent <= HurstAnalysis::MAX_VALID {
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

/// R/S statistic for a specific window size.
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

        let mean: f64 = window.iter().sum::<f64>() / window_size as f64;

        let mut cumulative = Vec::with_capacity(window_size);
        let mut cumsum = 0.0;
        for &x in window {
            cumsum += x - mean;
            cumulative.push(cumsum);
        }

        let max_cumsum = cumulative.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let min_cumsum = cumulative.iter().cloned().fold(f64::INFINITY, f64::min);
        let range = max_cumsum - min_cumsum;

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
/// More robust to non-stationarities than R/S.
pub fn calculate_hurst_dfa(data: &[f64]) -> Result<HurstAnalysis, String> {
    let n = data.len();
    if n < DFA_MIN_DATA_POINTS {
        return Err("Insufficient data points for DFA (minimum 32 required)".to_string());
    }

    let mean: f64 = data.iter().sum::<f64>() / n as f64;
    let mut profile = Vec::with_capacity(n);
    let mut cumsum = 0.0;
    for &x in data {
        cumsum += x - mean;
        profile.push(cumsum);
    }

    let mut log_scales = Vec::new();
    let mut log_fluct = Vec::new();

    let min_scale = DFA_MIN_SCALE;
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

    let (slope, _intercept, r_squared, std_error) = linear_regression(&log_scales, &log_fluct)?;

    if !slope.is_finite() || !r_squared.is_finite() || !std_error.is_finite() {
        return Err("Degenerate regression output (NaN/Inf)".to_string());
    }

    // DFA alpha can reach 2.0 (Brownian ~1.5, ballistic ~2.0)
    let exponent = slope.clamp(0.0, 2.0);

    let interpretation = if (exponent - 0.5).abs() < HurstAnalysis::WHITE_NOISE_TOLERANCE {
        HurstInterpretation::WhiteNoise
    } else if exponent < 0.5 {
        HurstInterpretation::AntiPersistent
    } else if exponent <= HurstAnalysis::MAX_VALID {
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

/// DFA fluctuation for a given scale.
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

        let detrended_variance = detrend_variance(segment);
        total_variance += detrended_variance;
    }

    (total_variance / num_segments as f64).sqrt()
}

/// Variance after linear detrending.
fn detrend_variance(segment: &[f64]) -> f64 {
    let n = segment.len();
    if n < 2 {
        return 0.0;
    }

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

    let mut variance = 0.0;
    for i in 0..n {
        let predicted = a * x[i] + b;
        variance += (y[i] - predicted).powi(2);
    }

    variance / n as f64
}

use super::stats::linear_regression;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hurst_white_noise() {
        use rand::Rng;
        let mut rng = rand::rng();
        let data: Vec<f64> = (0..500).map(|_| rng.random::<f64>()).collect();

        let result = calculate_hurst_rs(&data).unwrap();
        assert!(
            result.exponent > 0.2 && result.exponent < 0.8,
            "White noise Hurst should be near 0.5, got {}",
            result.exponent
        );
    }

    #[test]
    fn test_hurst_trending() {
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
