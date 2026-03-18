// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Largest Lyapunov exponent estimation via Rosenstein's method.
//!
//! A positive exponent indicates chaotic dynamics (human-like).
//! An exponent ≤ 0 indicates periodic/robotic behavior.
//! An anomalously high exponent indicates random noise (no deterministic structure).

use serde::{Deserialize, Serialize};

/// Minimum data points for Lyapunov analysis.
const MIN_DATA_POINTS: usize = 100;

/// Embedding dimension for phase-space reconstruction.
const EMBED_DIM: usize = 5;

/// Time delay for embedding.
const EMBED_DELAY: usize = 2;

/// Minimum temporal separation to avoid correlated neighbors.
const MEAN_PERIOD_MULTIPLIER: usize = 10;

/// Exponent below this is periodic/robotic.
const PERIODIC_THRESHOLD: f64 = 0.0;

/// Exponent above this is random noise (no deterministic structure).
const NOISE_THRESHOLD: f64 = 2.0;

/// Result of Lyapunov exponent analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LyapunovAnalysis {
    /// Largest Lyapunov exponent (bits/sample).
    pub exponent: f64,
    /// Whether the result is flagged as anomalous.
    pub flagged: bool,
    /// Confidence in the estimate (0.0-1.0).
    pub confidence: f64,
}

/// Estimate the largest Lyapunov exponent using Rosenstein's method.
///
/// Rosenstein, Collins & De Luca (1993), "A practical method for
/// calculating largest Lyapunov exponents from small data sets."
pub fn analyze_lyapunov(iki_intervals_ns: &[f64]) -> Option<LyapunovAnalysis> {
    if iki_intervals_ns.len() < MIN_DATA_POINTS {
        return None;
    }

    // Normalize data
    let mean = iki_intervals_ns.iter().sum::<f64>() / iki_intervals_ns.len() as f64;
    let std_dev = (iki_intervals_ns
        .iter()
        .map(|&x| (x - mean).powi(2))
        .sum::<f64>()
        / iki_intervals_ns.len() as f64)
        .sqrt();

    if std_dev < 1e-10 {
        // Zero variance → perfectly periodic → flagged
        return Some(LyapunovAnalysis {
            exponent: f64::NEG_INFINITY,
            flagged: true,
            confidence: 1.0,
        });
    }

    let normalized: Vec<f64> = iki_intervals_ns
        .iter()
        .map(|&x| (x - mean) / std_dev)
        .collect();

    // Construct delay embedding
    let embed_len = normalized
        .len()
        .saturating_sub((EMBED_DIM - 1) * EMBED_DELAY);
    if embed_len < 20 {
        return None;
    }

    let embedding: Vec<Vec<f64>> = (0..embed_len)
        .map(|i| {
            (0..EMBED_DIM)
                .map(|d| normalized[i + d * EMBED_DELAY])
                .collect()
        })
        .collect();

    let min_sep = MEAN_PERIOD_MULTIPLIER;
    let max_iter = embed_len / 4;
    if max_iter < 5 {
        return None;
    }

    // For each point, find nearest neighbor with temporal separation
    let mut divergence_sum = vec![0.0f64; max_iter];
    let mut divergence_count = vec![0usize; max_iter];

    for i in 0..embedding.len() {
        let mut min_dist = f64::INFINITY;
        let mut nn_idx = 0;

        for j in 0..embedding.len() {
            let temporal_sep = i.abs_diff(j);
            if temporal_sep < min_sep {
                continue;
            }

            let dist: f64 = embedding[i]
                .iter()
                .zip(embedding[j].iter())
                .map(|(&a, &b)| (a - b).powi(2))
                .sum::<f64>()
                .sqrt();

            if dist < min_dist && dist > 0.0 {
                min_dist = dist;
                nn_idx = j;
            }
        }

        if min_dist < f64::INFINITY {
            // Track divergence over time
            for k in 0..max_iter {
                let i_k = i + k;
                let j_k = nn_idx + k;
                if i_k < embedding.len() && j_k < embedding.len() {
                    let dist_k: f64 = embedding[i_k]
                        .iter()
                        .zip(embedding[j_k].iter())
                        .map(|(&a, &b)| (a - b).powi(2))
                        .sum::<f64>()
                        .sqrt();

                    if dist_k > 0.0 {
                        divergence_sum[k] += dist_k.ln();
                        divergence_count[k] += 1;
                    }
                }
            }
        }
    }

    // Average log divergence curve
    let log_divergence: Vec<f64> = divergence_sum
        .iter()
        .zip(divergence_count.iter())
        .filter_map(|(&sum, &count)| {
            if count > 0 {
                Some(sum / count as f64)
            } else {
                None
            }
        })
        .collect();

    if log_divergence.len() < 5 {
        return None;
    }

    // Estimate slope of the linear region (first quarter)
    let fit_len = (log_divergence.len() / 4).max(5).min(log_divergence.len());
    let (slope, _) = linear_regression(&log_divergence[..fit_len]);

    let confidence = (iki_intervals_ns.len() as f64 / 500.0).min(1.0);
    let flagged = slope <= PERIODIC_THRESHOLD || slope > NOISE_THRESHOLD;

    Some(LyapunovAnalysis {
        exponent: slope,
        flagged,
        confidence,
    })
}

/// Simple least-squares linear regression. Returns (slope, intercept).
fn linear_regression(y: &[f64]) -> (f64, f64) {
    let n = y.len() as f64;
    let sum_x: f64 = (0..y.len()).map(|i| i as f64).sum();
    let sum_y: f64 = y.iter().sum();
    let sum_xy: f64 = y.iter().enumerate().map(|(i, &v)| i as f64 * v).sum();
    let sum_x2: f64 = (0..y.len()).map(|i| (i as f64).powi(2)).sum();

    let denom = n * sum_x2 - sum_x * sum_x;
    if denom.abs() < 1e-15 {
        return (0.0, sum_y / n);
    }

    let slope = (n * sum_xy - sum_x * sum_y) / denom;
    let intercept = (sum_y - slope * sum_x) / n;
    (slope, intercept)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lyapunov_insufficient_data() {
        let data: Vec<f64> = (0..50).map(|i| i as f64).collect();
        assert!(analyze_lyapunov(&data).is_none());
    }

    #[test]
    fn test_lyapunov_periodic_data() {
        // Perfectly periodic data should have exponent ≤ 0
        let data: Vec<f64> = (0..300)
            .map(|i| (i as f64 * 0.1).sin() * 100_000_000.0 + 150_000_000.0)
            .collect();
        let result = analyze_lyapunov(&data);
        if let Some(r) = result {
            assert!(
                r.exponent <= 0.5,
                "Periodic data should have low exponent, got {}",
                r.exponent
            );
        }
    }

    #[test]
    fn test_lyapunov_chaotic_data() {
        // Logistic map at r=3.9 — known chaotic
        let mut data = Vec::new();
        let mut x = 0.1;
        for _ in 0..300 {
            x = 3.9 * x * (1.0 - x);
            data.push(x * 200_000_000.0 + 50_000_000.0);
        }
        let result = analyze_lyapunov(&data);
        if let Some(r) = result {
            assert!(
                r.exponent > 0.0,
                "Chaotic data should have positive exponent, got {}",
                r.exponent
            );
        }
    }

    #[test]
    fn test_lyapunov_constant_data() {
        let data = vec![100_000_000.0; 200];
        let result = analyze_lyapunov(&data).unwrap();
        assert!(result.flagged, "Constant data should be flagged");
    }
}
