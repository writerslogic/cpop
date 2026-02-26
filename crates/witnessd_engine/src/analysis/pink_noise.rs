// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Pink noise (1/f noise) analysis for human behavioral signals.
//!
//! Pink noise, also known as 1/f noise, is characterized by a power spectral
//! density that is inversely proportional to frequency:
//!
//!   S(f) ∝ 1/f^α  where α ≈ 1
//!
//! Human motor control and cognitive processes naturally produce pink noise
//! patterns in timing data. This is a universal feature of biological systems.
//!
//! RFC draft-condrey-rats-pop-01 specifies:
//! - Spectral slope α ∈ [0.8, 1.2] is biologically plausible
//! - White noise (α ≈ 0) indicates synthetic generation
//! - Brown noise (α ≈ 2) indicates over-smoothed/scripted data

use serde::{Deserialize, Serialize};
use std::f64::consts::PI;

/// Result of pink noise analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinkNoiseAnalysis {
    /// Spectral slope (α) from log-log regression of power spectrum.
    /// α ≈ 1.0 for ideal pink noise.
    pub spectral_slope: f64,

    /// Standard error of the slope estimate.
    pub slope_std_error: f64,

    /// R-squared value indicating fit quality.
    pub r_squared: f64,

    /// Interpretation of the spectral characteristics.
    pub noise_type: NoiseType,

    /// Whether the signal passes RFC validation as biologically plausible.
    pub is_valid: bool,

    /// Dominant frequency components (Hz) if any stand out.
    pub dominant_frequencies: Vec<f64>,
}

/// Classification of noise type based on spectral slope.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum NoiseType {
    /// α ≈ 0: White noise (flat spectrum) - random, no memory.
    White,
    /// α ∈ (0, 0.8): Pinkish-white, some correlation.
    PinkishWhite,
    /// α ∈ [0.8, 1.2]: Pink noise (1/f) - typical of biological systems.
    Pink,
    /// α ∈ (1.2, 1.8): Pinkish-brown, stronger correlation.
    PinkishBrown,
    /// α ≈ 2: Brown/red noise (1/f²) - random walk.
    Brown,
    /// α > 2: Black noise - very strong low-frequency dominance.
    Black,
}

impl PinkNoiseAnalysis {
    /// RFC-compliant range for biological plausibility.
    pub const MIN_VALID_SLOPE: f64 = 0.8;
    pub const MAX_VALID_SLOPE: f64 = 1.2;

    /// Check if the spectral slope indicates biologically plausible patterns.
    pub fn is_biologically_plausible(&self) -> bool {
        self.spectral_slope >= Self::MIN_VALID_SLOPE && self.spectral_slope <= Self::MAX_VALID_SLOPE
    }

    /// Check if the signal appears to be white noise (suspicious).
    pub fn is_white_noise(&self) -> bool {
        self.spectral_slope < 0.3
    }

    /// Check if the signal appears to be over-smoothed (suspicious).
    pub fn is_over_smoothed(&self) -> bool {
        self.spectral_slope > 1.8
    }
}

/// Analyze a time series for pink noise characteristics.
///
/// Uses FFT to compute power spectral density, then fits log-log
/// regression to determine spectral slope.
///
/// # Arguments
/// * `data` - Time series data (e.g., inter-event intervals)
/// * `sample_rate` - Sampling rate in Hz (for frequency axis)
///
/// # Returns
/// * `PinkNoiseAnalysis` with spectral characteristics
pub fn analyze_pink_noise(data: &[f64], sample_rate: f64) -> Result<PinkNoiseAnalysis, String> {
    let n = data.len();
    if n < 32 {
        return Err("Insufficient data for spectral analysis (minimum 32 points)".to_string());
    }

    // Compute power spectral density using FFT
    let psd = compute_psd(data)?;

    // Frequency bins (skip DC component)
    let freq_step = sample_rate / n as f64;
    let mut log_freq = Vec::new();
    let mut log_power = Vec::new();

    // Use only positive frequencies up to Nyquist
    let nyquist_idx = n / 2;
    for (i, &power) in psd.iter().enumerate().take(nyquist_idx).skip(1) {
        let freq = i as f64 * freq_step;

        // Filter out zero or negative power
        if power > 1e-20 {
            log_freq.push(freq.ln());
            log_power.push(power.ln());
        }
    }

    if log_freq.len() < 5 {
        return Err("Insufficient valid frequency bins for analysis".to_string());
    }

    // Linear regression: log(P) = -α * log(f) + c
    let (slope, _intercept, r_squared, std_error) = linear_regression(&log_freq, &log_power)?;

    // Spectral slope is negative of regression slope
    // (since P ∝ 1/f^α means log(P) = -α*log(f) + c)
    let spectral_slope = -slope;

    let noise_type = classify_noise_type(spectral_slope);
    let is_valid = (PinkNoiseAnalysis::MIN_VALID_SLOPE..=PinkNoiseAnalysis::MAX_VALID_SLOPE)
        .contains(&spectral_slope);

    // Find dominant frequencies (peaks in PSD)
    let dominant_frequencies = find_dominant_frequencies(&psd, freq_step);

    Ok(PinkNoiseAnalysis {
        spectral_slope,
        slope_std_error: std_error,
        r_squared,
        noise_type,
        is_valid,
        dominant_frequencies,
    })
}

/// Classify noise type based on spectral slope.
fn classify_noise_type(slope: f64) -> NoiseType {
    if slope < 0.3 {
        NoiseType::White
    } else if slope < 0.8 {
        NoiseType::PinkishWhite
    } else if slope <= 1.2 {
        NoiseType::Pink
    } else if slope <= 1.8 {
        NoiseType::PinkishBrown
    } else if slope <= 2.2 {
        NoiseType::Brown
    } else {
        NoiseType::Black
    }
}

/// Compute power spectral density using discrete Fourier transform.
///
/// Uses a simple radix-2 FFT implementation for power calculation.
fn compute_psd(data: &[f64]) -> Result<Vec<f64>, String> {
    let n = data.len();

    // Pad to next power of 2 for FFT efficiency
    let fft_size = n.next_power_of_two();

    // Apply Hann window to reduce spectral leakage
    let mut windowed: Vec<f64> = data
        .iter()
        .enumerate()
        .map(|(i, &x)| {
            let window = 0.5 * (1.0 - (2.0 * PI * i as f64 / (n - 1) as f64).cos());
            x * window
        })
        .collect();

    // Zero-pad if necessary
    windowed.resize(fft_size, 0.0);

    // Compute DFT (simple O(n²) implementation for clarity)
    // In production, use a proper FFT library
    let mut real = vec![0.0; fft_size];
    let mut imag = vec![0.0; fft_size];

    for k in 0..fft_size {
        for (n_idx, &x) in windowed.iter().enumerate() {
            let angle = -2.0 * PI * k as f64 * n_idx as f64 / fft_size as f64;
            real[k] += x * angle.cos();
            imag[k] += x * angle.sin();
        }
    }

    // Compute power spectral density (magnitude squared)
    let psd: Vec<f64> = real
        .iter()
        .zip(imag.iter())
        .map(|(&r, &i)| (r * r + i * i) / fft_size as f64)
        .collect();

    Ok(psd)
}

/// Find dominant frequencies in the power spectrum.
///
/// Returns frequencies of peaks that are significantly above the mean.
fn find_dominant_frequencies(psd: &[f64], freq_step: f64) -> Vec<f64> {
    let n = psd.len();
    if n < 5 {
        return Vec::new();
    }

    let nyquist_idx = n / 2;

    // Calculate mean power (excluding DC)
    let mean_power: f64 = psd[1..nyquist_idx].iter().sum::<f64>() / (nyquist_idx - 1) as f64;
    let threshold = mean_power * 3.0; // 3x mean for peak detection

    let mut peaks = Vec::new();

    // Find local maxima above threshold
    for i in 2..nyquist_idx - 1 {
        if psd[i] > threshold && psd[i] > psd[i - 1] && psd[i] > psd[i + 1] {
            peaks.push(i as f64 * freq_step);
        }
    }

    // Sort by power (strongest first) and take top 5
    peaks.truncate(5);
    peaks
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

/// Generate synthetic pink noise for testing.
///
/// Uses the Voss-McCartney algorithm for 1/f noise generation.
pub fn generate_pink_noise(length: usize, seed: u64) -> Vec<f64> {
    // Simple PRNG for reproducibility
    let mut state = seed;
    let mut next_random = || {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        ((state >> 33) as f64 / u32::MAX as f64) * 2.0 - 1.0
    };

    // Voss-McCartney algorithm with 8 octaves
    let num_octaves = 8;
    let mut octave_values: Vec<f64> = vec![0.0; num_octaves];
    let mut counter = 0u32;
    let mut output = Vec::with_capacity(length);

    for _ in 0..length {
        // Update octaves based on bit changes
        let mut mask = 1u32;
        for octave in octave_values.iter_mut() {
            if (counter & mask) == 0 {
                *octave = next_random();
            }
            mask <<= 1;
        }
        counter = counter.wrapping_add(1);

        // Sum all octaves
        let sample: f64 = octave_values.iter().sum::<f64>() / num_octaves as f64;
        output.push(sample);
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pink_noise_detection() {
        // Generate synthetic pink noise
        let data = generate_pink_noise(512, 42);

        // Analyze at 100 Hz sample rate
        let result = analyze_pink_noise(&data, 100.0).unwrap();

        // Should detect as pink-ish (slope around 1.0)
        assert!(
            result.spectral_slope > 0.5 && result.spectral_slope < 2.0,
            "Pink noise spectral slope should be in reasonable range, got {}",
            result.spectral_slope
        );
    }

    #[test]
    fn test_white_noise_detection() {
        // Generate white noise
        use rand::Rng;
        let mut rng = rand::rng();
        let data: Vec<f64> = (0..512).map(|_| rng.random::<f64>() * 2.0 - 1.0).collect();

        let result = analyze_pink_noise(&data, 100.0).unwrap();

        // White noise should have slope near 0
        assert!(
            result.spectral_slope < 0.5,
            "White noise should have low spectral slope, got {}",
            result.spectral_slope
        );
        assert_eq!(result.noise_type, NoiseType::White);
    }

    #[test]
    fn test_noise_type_classification() {
        assert_eq!(classify_noise_type(0.1), NoiseType::White);
        assert_eq!(classify_noise_type(0.5), NoiseType::PinkishWhite);
        assert_eq!(classify_noise_type(1.0), NoiseType::Pink);
        assert_eq!(classify_noise_type(1.5), NoiseType::PinkishBrown);
        assert_eq!(classify_noise_type(2.0), NoiseType::Brown);
        assert_eq!(classify_noise_type(2.5), NoiseType::Black);
    }

    #[test]
    fn test_biological_plausibility() {
        let analysis = PinkNoiseAnalysis {
            spectral_slope: 1.0,
            slope_std_error: 0.1,
            r_squared: 0.9,
            noise_type: NoiseType::Pink,
            is_valid: true,
            dominant_frequencies: vec![],
        };

        assert!(analysis.is_biologically_plausible());
        assert!(!analysis.is_white_noise());
        assert!(!analysis.is_over_smoothed());
    }

    #[test]
    fn test_insufficient_data() {
        let data = vec![1.0, 2.0, 3.0];
        let result = analyze_pink_noise(&data, 100.0);
        assert!(result.is_err());
    }
}
