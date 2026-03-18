// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Signal-to-noise ratio analysis on inter-keystroke interval (IKI) data.
//!
//! Human typing produces a mix of low-frequency cadence patterns (signal)
//! and high-frequency jitter (noise). Synthetic input that is "too clean"
//! will have an abnormally high SNR across all windows.

use serde::{Deserialize, Serialize};

/// SNR above this threshold across all windows indicates synthetic input.
const SNR_SYNTHETIC_THRESHOLD_DB: f64 = 20.0;

/// Maximum SNR value in dB to avoid infinity in serialized output.
const MAX_SNR_DB: f64 = 100.0;

/// Sliding window size in samples.
const WINDOW_SIZE: usize = 32;

/// Minimum IKI samples required for SNR analysis.
const MIN_SAMPLES: usize = 64;

/// Result of signal-to-noise ratio analysis on IKI data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnrAnalysis {
    /// Overall SNR in decibels.
    pub snr_db: f64,
    /// Per-window SNR values.
    pub windowed_snr: Vec<f64>,
    /// Whether SNR is flagged as anomalous (too clean = synthetic).
    pub flagged: bool,
}

/// Compute SNR across sliding windows of IKI data.
///
/// Signal power = variance of window means (low-frequency cadence).
/// Noise power = mean of window variances (high-frequency jitter).
pub fn analyze_snr(iki_intervals_ns: &[f64]) -> Option<SnrAnalysis> {
    if iki_intervals_ns.len() < MIN_SAMPLES {
        return None;
    }
    if iki_intervals_ns.iter().any(|x| !x.is_finite()) {
        return None;
    }

    let windows: Vec<&[f64]> = iki_intervals_ns
        .windows(WINDOW_SIZE)
        .step_by(WINDOW_SIZE / 2)
        .collect();
    if windows.len() < 2 {
        return None;
    }

    let window_means: Vec<f64> = windows
        .iter()
        .map(|w| w.iter().sum::<f64>() / w.len() as f64)
        .collect();

    let window_variances: Vec<f64> = windows
        .iter()
        .zip(window_means.iter())
        .map(|(w, &mean)| w.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / w.len() as f64)
        .collect();

    // Signal power: variance of the window means (low-frequency component)
    let grand_mean = window_means.iter().sum::<f64>() / window_means.len() as f64;
    let signal_power = window_means
        .iter()
        .map(|&m| (m - grand_mean).powi(2))
        .sum::<f64>()
        / window_means.len() as f64;

    // Noise power: mean of the window variances (high-frequency component)
    let noise_power = window_variances.iter().sum::<f64>() / window_variances.len() as f64;

    let snr_db = if noise_power > 0.0 {
        (10.0 * (signal_power / noise_power).log10()).min(MAX_SNR_DB)
    } else {
        MAX_SNR_DB
    };

    // Per-window SNR
    let windowed_snr: Vec<f64> = window_variances
        .iter()
        .map(|&var| {
            if var > 0.0 {
                (10.0 * (signal_power / var).log10()).min(MAX_SNR_DB)
            } else {
                MAX_SNR_DB
            }
        })
        .collect();

    let all_high = windowed_snr.iter().all(|&s| s > SNR_SYNTHETIC_THRESHOLD_DB);
    let flagged = all_high && snr_db > SNR_SYNTHETIC_THRESHOLD_DB;

    Some(SnrAnalysis {
        snr_db,
        windowed_snr,
        flagged,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snr_human_like_data() {
        // Simulate human typing: mean ~150ms with significant jitter
        let mut data = Vec::new();
        for i in 0..200 {
            let base = 150_000_000.0; // 150ms in ns
            let jitter =
                ((i as f64 * 0.7).sin() * 50_000_000.0) + ((i as f64 * 2.3).cos() * 30_000_000.0);
            data.push(base + jitter);
        }
        let result = analyze_snr(&data).unwrap();
        // Human data should NOT be flagged
        assert!(
            !result.flagged,
            "Human-like data should not be flagged, SNR={:.1}",
            result.snr_db
        );
    }

    #[test]
    fn test_snr_too_few_samples() {
        let data: Vec<f64> = (0..30).map(|i| i as f64 * 1000.0).collect();
        assert!(analyze_snr(&data).is_none());
    }

    #[test]
    fn test_snr_robotic_constant() {
        // Perfectly constant intervals — noise ≈ 0, SNR → ∞ → flagged
        let data: Vec<f64> = vec![100_000_000.0; 200];
        let result = analyze_snr(&data).unwrap();
        assert!(result.flagged, "Constant intervals should be flagged");
    }
}
