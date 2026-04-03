// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Labyrinth structure analysis via Takens' delay-coordinate embedding.
//! RFC draft-condrey-rats-pop-01 §5.4.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Result of labyrinth structure analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabyrinthAnalysis {
    /// Number of dimensions needed to unfold the attractor.
    pub embedding_dimension: usize,

    /// Optimal time delay (in samples).
    pub optimal_delay: usize,

    /// Fractal dimension of the attractor (Grassberger-Procaccia estimate).
    pub correlation_dimension: f64,

    /// Betti numbers (β₀, β₁, β₂): connected components, loops, and voids.
    pub betti_numbers: [usize; 3],

    /// Fraction of recurrent points in the recurrence plot.
    pub recurrence_rate: f64,

    /// Ratio of recurrent points forming diagonal lines (predictability).
    pub determinism: f64,

    /// Whether the analysis falls within biologically plausible ranges.
    pub is_valid: bool,

    /// 0.0-1.0, based on data quantity and embedding parameter quality.
    pub confidence: f64,
}

impl LabyrinthAnalysis {
    /// RFC-compliant range for human motor signals (draft-condrey-rats-pop-01 §5.4).
    pub const MIN_EMBEDDING_DIM: usize = 3;
    /// Maximum plausible embedding dimension for human motor signals.
    pub const MAX_EMBEDDING_DIM: usize = 8;

    /// Minimum plausible correlation dimension for human attractors.
    pub const MIN_CORRELATION_DIM: f64 = 1.5;
    /// Maximum plausible correlation dimension for human attractors.
    pub const MAX_CORRELATION_DIM: f64 = 5.0;

    /// Minimum determinism threshold for human-like recurrence.
    pub const MIN_DETERMINISM: f64 = 0.3;
    /// Maximum determinism threshold (above this suggests periodic/robotic input).
    pub const MAX_DETERMINISM: f64 = 0.95;

    /// Return `true` if all metrics fall within RFC-defined human ranges.
    pub fn is_biologically_plausible(&self) -> bool {
        self.embedding_dimension >= Self::MIN_EMBEDDING_DIM
            && self.embedding_dimension <= Self::MAX_EMBEDDING_DIM
            && self.correlation_dimension >= Self::MIN_CORRELATION_DIM
            && self.correlation_dimension <= Self::MAX_CORRELATION_DIM
            && self.determinism > Self::MIN_DETERMINISM
            && self.determinism < Self::MAX_DETERMINISM
    }
}

/// Configuration parameters for labyrinth analysis.
#[derive(Debug, Clone)]
pub struct LabyrinthParams {
    /// Maximum embedding dimension to test via FNN.
    pub max_embedding_dim: usize,
    /// Maximum time delay to test via mutual information.
    pub max_delay: usize,
    /// Fraction of standard deviation used as recurrence threshold.
    pub recurrence_threshold: f64,
    /// Minimum diagonal line length for determinism counting.
    pub min_line_length: usize,
}

impl Default for LabyrinthParams {
    fn default() -> Self {
        Self {
            max_embedding_dim: 10,
            max_delay: 20,
            recurrence_threshold: 0.1,
            min_line_length: 2,
        }
    }
}

const MIN_LABYRINTH_DATA_POINTS: usize = 50;
const MAX_EMBEDDING_DIM_LIMIT: usize = 20;
const MAX_DELAY_LIMIT: usize = 50;
/// Below this FNN ratio, the embedding dimension is considered sufficient.
const FNN_RATIO_THRESHOLD: f64 = 0.1;

/// Perform Takens' delay-coordinate embedding analysis on a time series.
pub fn analyze_labyrinth(
    data: &[f64],
    params: &LabyrinthParams,
) -> Result<LabyrinthAnalysis, String> {
    let n = data.len();
    if n < MIN_LABYRINTH_DATA_POINTS {
        return Err("Insufficient data for labyrinth analysis (minimum 50 points)".to_string());
    }

    if params.max_embedding_dim > MAX_EMBEDDING_DIM_LIMIT {
        return Err(format!(
            "max_embedding_dim {} exceeds limit of {}",
            params.max_embedding_dim, MAX_EMBEDDING_DIM_LIMIT
        ));
    }
    if params.max_delay > MAX_DELAY_LIMIT {
        return Err(format!(
            "max_delay {} exceeds limit of {}",
            params.max_delay, MAX_DELAY_LIMIT
        ));
    }

    let optimal_delay = find_optimal_delay(data, params.max_delay);
    let embedding_dimension =
        estimate_embedding_dimension(data, optimal_delay, params.max_embedding_dim);
    let embedding = construct_embedding(data, embedding_dimension, optimal_delay);

    if embedding.is_empty() {
        return Err("Could not construct valid embedding".to_string());
    }

    let (recurrence_rate, determinism) = compute_recurrence_quantification(
        &embedding,
        params.recurrence_threshold,
        params.min_line_length,
    );
    let correlation_dimension = estimate_correlation_dimension(&embedding);
    let betti_numbers = estimate_betti_numbers(&embedding, params.recurrence_threshold);

    let is_valid = (LabyrinthAnalysis::MIN_EMBEDDING_DIM..=LabyrinthAnalysis::MAX_EMBEDDING_DIM)
        .contains(&embedding_dimension)
        && (LabyrinthAnalysis::MIN_CORRELATION_DIM..=LabyrinthAnalysis::MAX_CORRELATION_DIM)
            .contains(&correlation_dimension);
    let confidence = compute_confidence(n, embedding_dimension, optimal_delay);

    Ok(LabyrinthAnalysis {
        embedding_dimension,
        optimal_delay,
        correlation_dimension,
        betti_numbers,
        recurrence_rate,
        determinism,
        is_valid,
        confidence,
    })
}

/// First minimum of mutual information selects the optimal delay.
fn find_optimal_delay(data: &[f64], max_delay: usize) -> usize {
    let n = data.len();
    if n < max_delay + 10 {
        return 1;
    }

    let min_val = data.iter().cloned().fold(f64::INFINITY, f64::min);
    let max_val = data.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let range = (max_val - min_val).max(1e-10);

    let normalized: Vec<f64> = data.iter().map(|&x| (x - min_val) / range).collect();

    let num_bins = 16;
    let mut prev_mi = f64::INFINITY;

    for delay in 1..=max_delay {
        let mi = compute_mutual_information(&normalized, delay, num_bins);

        if mi > prev_mi {
            return delay - 1;
        }
        prev_mi = mi;
    }

    max_delay / 2
}

fn compute_mutual_information(data: &[f64], delay: usize, num_bins: usize) -> f64 {
    let n = data.len() - delay;
    if n < num_bins * 2 {
        return f64::INFINITY;
    }

    let mut joint_hist = vec![vec![0usize; num_bins]; num_bins];
    let mut hist_x = vec![0usize; num_bins];
    let mut hist_y = vec![0usize; num_bins];

    for i in 0..n {
        let x_bin = ((data[i] * num_bins as f64) as usize).min(num_bins - 1);
        let y_bin = ((data[i + delay] * num_bins as f64) as usize).min(num_bins - 1);

        joint_hist[x_bin][y_bin] += 1;
        hist_x[x_bin] += 1;
        hist_y[y_bin] += 1;
    }

    let mut mi = 0.0;
    let n_f = n as f64;

    for i in 0..num_bins {
        for j in 0..num_bins {
            let p_xy = joint_hist[i][j] as f64 / n_f;
            let p_x = hist_x[i] as f64 / n_f;
            let p_y = hist_y[j] as f64 / n_f;

            if p_xy > 0.0 && p_x > 0.0 && p_y > 0.0 {
                mi += p_xy * (p_xy / (p_x * p_y)).ln();
            }
        }
    }

    mi
}

fn estimate_embedding_dimension(data: &[f64], delay: usize, max_dim: usize) -> usize {
    for dim in 1..=max_dim {
        let embedding = construct_embedding(data, dim, delay);
        if embedding.len() < 20 {
            return dim;
        }

        let fnn_ratio = compute_fnn_ratio(&embedding, data, dim, delay);

        if fnn_ratio < FNN_RATIO_THRESHOLD {
            return dim;
        }
    }

    max_dim
}

/// FNN distance threshold for detecting false nearest neighbors.
///
/// Per Kennel, Brown & Abarbanel (1992) "Determining embedding dimension for
/// phase-space reconstruction using a geometrical construction", Phys. Rev. A,
/// 45(6), 3403-3411. A threshold of 15.0 is standard for identifying neighbors
/// that are "false" due to projection from a higher-dimensional space.
const FNN_DISTANCE_THRESHOLD: f64 = 15.0;

fn compute_fnn_ratio(embedding: &[Vec<f64>], original: &[f64], dim: usize, delay: usize) -> f64 {
    let n = embedding.len();
    if n < 10 {
        return 1.0;
    }

    let threshold = FNN_DISTANCE_THRESHOLD;
    let mut fnn_count = 0;
    let mut total_count = 0;

    let sample_size = n.min(100);
    let step = (n / sample_size).max(1);
    let sampled: Vec<usize> = (0..n).step_by(step).collect();

    for &i in &sampled {
        let mut min_dist = f64::INFINITY;
        let mut nn_idx = 0;

        for &j in &sampled {
            if i != j {
                let dist = euclidean_distance(&embedding[i], &embedding[j]);
                if dist < min_dist && dist > 0.0 {
                    min_dist = dist;
                    nn_idx = j;
                }
            }
        }

        if min_dist > 0.0 && min_dist < f64::INFINITY {
            // Map embedding index back to original array offset: orig[i + dim * delay]
            let orig_idx_i = dim.saturating_mul(delay).checked_add(i);
            let orig_idx_j = dim.saturating_mul(delay).checked_add(nn_idx);

            if let (Some(idx_i), Some(idx_j)) = (orig_idx_i, orig_idx_j) {
                if idx_i + delay < original.len() && idx_j + delay < original.len() {
                    let extra_dist = (original[idx_i + delay] - original[idx_j + delay]).abs();
                    let ratio = extra_dist / min_dist;

                    total_count += 1;
                    if ratio > threshold {
                        fnn_count += 1;
                    }
                }
            }
        }
    }

    if total_count > 0 {
        fnn_count as f64 / total_count as f64
    } else {
        1.0
    }
}

fn construct_embedding(data: &[f64], dim: usize, delay: usize) -> Vec<Vec<f64>> {
    let n = data.len();
    let embed_length = n.saturating_sub((dim - 1) * delay);

    if embed_length < 10 {
        return Vec::new();
    }

    let mut embedding = Vec::with_capacity(embed_length);

    for i in 0..embed_length {
        let mut point = Vec::with_capacity(dim);
        for d in 0..dim {
            point.push(data[i + d * delay]);
        }
        embedding.push(point);
    }

    embedding
}

fn compute_recurrence_quantification(
    embedding: &[Vec<f64>],
    threshold: f64,
    min_line_length: usize,
) -> (f64, f64) {
    let n = embedding.len();
    if n < 10 {
        return (0.0, 0.0);
    }

    let all_coords: Vec<f64> = embedding.iter().flat_map(|p| p.iter().copied()).collect();
    if all_coords.is_empty() {
        return (0.0, 0.0);
    }
    let mean: f64 = all_coords.iter().sum::<f64>() / all_coords.len() as f64;
    let variance: f64 =
        all_coords.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / all_coords.len() as f64;
    let std_dev = variance.sqrt();

    if !std_dev.is_finite() || std_dev == 0.0 {
        return (0.0, 0.0);
    }

    let eps = threshold * std_dev;

    let sample_n = n.min(200);
    let step = (n / sample_n).max(1);
    let sampled_indices: Vec<usize> = (0..n).step_by(step).collect();

    let mut recurrent_count = 0;
    let mut diagonal_count = 0;

    for (si, &i) in sampled_indices.iter().enumerate() {
        for (sj, &j) in sampled_indices.iter().enumerate() {
            if i != j {
                let dist = euclidean_distance(&embedding[i], &embedding[j]);
                if dist < eps {
                    recurrent_count += 1;

                    // Count diagonal lines of at least min_line_length consecutive
                    // recurrent points. Only start a walk from the *beginning* of a
                    // diagonal (predecessor (si-1, sj-1) is not recurrent or out of
                    // bounds) to avoid counting each diagonal L times.
                    let is_diagonal_start = if si > 0 && sj > 0 {
                        let i_prev = sampled_indices[si - 1];
                        let j_prev = sampled_indices[sj - 1];
                        i_prev == j_prev
                            || euclidean_distance(&embedding[i_prev], &embedding[j_prev]) >= eps
                    } else {
                        true
                    };

                    if is_diagonal_start {
                        let mut line_len = 1;
                        let mut k = 1;
                        while si + k < sampled_indices.len() && sj + k < sampled_indices.len() {
                            let i_next = sampled_indices[si + k];
                            let j_next = sampled_indices[sj + k];
                            if i_next < n
                                && j_next < n
                                && euclidean_distance(&embedding[i_next], &embedding[j_next]) < eps
                            {
                                line_len += 1;
                                k += 1;
                            } else {
                                break;
                            }
                        }
                        if line_len >= min_line_length {
                            diagonal_count += 1;
                        }
                    }
                }
            }
        }
    }

    let total_pairs = sampled_indices.len() * (sampled_indices.len() - 1);
    let recurrence_rate = if total_pairs > 0 {
        recurrent_count as f64 / total_pairs as f64
    } else {
        0.0
    };

    let determinism = if recurrent_count > 0 {
        diagonal_count as f64 / recurrent_count as f64
    } else {
        0.0
    };

    (recurrence_rate, determinism)
}

fn estimate_correlation_dimension(embedding: &[Vec<f64>]) -> f64 {
    let n = embedding.len();
    if n < 20 {
        return 0.0;
    }

    let mut distances = Vec::new();
    let sample_size = n.min(100);
    let step = (n / sample_size).max(1);

    for i in (0..n).step_by(step) {
        for j in (i + 1..n).step_by(step) {
            let dist = euclidean_distance(&embedding[i], &embedding[j]);
            if dist > 0.0 {
                distances.push(dist);
            }
        }
    }

    if distances.len() < 10 {
        return 0.0;
    }

    distances.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let mut log_r = Vec::new();
    let mut log_c = Vec::new();

    let r_min = distances[distances.len() / 10];
    let r_max = distances[distances.len() * 9 / 10];

    if r_max == r_min {
        return 0.0;
    }

    let num_bins = 10;
    for i in 0..num_bins {
        let r = r_min * ((r_max / r_min).powf(i as f64 / (num_bins - 1) as f64));
        if !r.is_finite() || r <= 0.0 {
            continue;
        }

        let count = distances.iter().filter(|&&d| d < r).count();
        let c = count as f64 / distances.len() as f64;

        if c > 0.0 {
            log_r.push(r.ln());
            log_c.push(c.ln());
        }
    }

    if log_r.len() < 3 {
        return 0.0;
    }

    let n_pts = log_r.len();
    let mean_r: f64 = log_r.iter().sum::<f64>() / n_pts as f64;
    let mean_c: f64 = log_c.iter().sum::<f64>() / n_pts as f64;

    let mut num = 0.0;
    let mut denom = 0.0;

    for i in 0..n_pts {
        num += (log_r[i] - mean_r) * (log_c[i] - mean_c);
        denom += (log_r[i] - mean_r).powi(2);
    }

    if denom > 0.0 {
        let slope = num / denom;
        if slope.is_finite() {
            slope.max(0.0)
        } else {
            0.0
        }
    } else {
        0.0
    }
}

fn estimate_betti_numbers(embedding: &[Vec<f64>], threshold: f64) -> [usize; 3] {
    let n = embedding.len();
    if n < 10 {
        return [1, 0, 0];
    }

    let all_coords: Vec<f64> = embedding.iter().flat_map(|p| p.iter().copied()).collect();
    if all_coords.is_empty() {
        return [1, 0, 0];
    }
    let mean: f64 = all_coords.iter().sum::<f64>() / all_coords.len() as f64;
    let variance: f64 =
        all_coords.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / all_coords.len() as f64;
    let std_dev = variance.sqrt();
    if !std_dev.is_finite() || std_dev == 0.0 {
        return [1, 0, 0];
    }
    let eps = threshold * std_dev * 3.0;

    let sample_n = n.min(100);
    let step = (n / sample_n).max(1);
    let mut adjacency: HashSet<(usize, usize)> = HashSet::new();

    for (si, i) in (0..n).step_by(step).enumerate() {
        for (sj, j) in (0..n).step_by(step).enumerate() {
            if si < sj {
                let dist = euclidean_distance(&embedding[i], &embedding[j]);
                if dist < eps {
                    adjacency.insert((si, sj));
                }
            }
        }
    }

    // β₀: Connected components (simplified using union-find)
    let num_vertices = sample_n;
    let beta_0 = count_connected_components(num_vertices, &adjacency);

    // β₁: Approximate number of 1-cycles (loops)
    // Using Euler characteristic: χ = V - E + F, and β₁ ≈ E - V + β₀ for graphs
    let num_edges = adjacency.len();
    let beta_1 = num_edges
        .saturating_sub(num_vertices)
        .saturating_add(beta_0);

    // β₂: Typically 0 for 2D/3D attractors
    let beta_2 = 0;

    [beta_0, beta_1, beta_2]
}

fn count_connected_components(n: usize, edges: &HashSet<(usize, usize)>) -> usize {
    let mut parent: Vec<usize> = (0..n).collect();

    fn find(parent: &mut [usize], i: usize) -> usize {
        if parent[i] != i {
            parent[i] = find(parent, parent[i]);
        }
        parent[i]
    }

    fn union(parent: &mut [usize], i: usize, j: usize) {
        let pi = find(parent, i);
        let pj = find(parent, j);
        if pi != pj {
            parent[pi] = pj;
        }
    }

    for &(i, j) in edges {
        if i < n && j < n {
            union(&mut parent, i, j);
        }
    }

    let mut roots = HashSet::new();
    for i in 0..n {
        roots.insert(find(&mut parent, i));
    }

    roots.len()
}

fn euclidean_distance(a: &[f64], b: &[f64]) -> f64 {
    a.iter()
        .zip(b.iter())
        .map(|(&x, &y)| (x - y).powi(2))
        .sum::<f64>()
        .sqrt()
}

fn compute_confidence(n: usize, dim: usize, delay: usize) -> f64 {
    let data_factor = (n as f64 / 100.0).min(1.0);

    let embed_factor = if (3..=8).contains(&dim) && (1..=10).contains(&delay) {
        1.0
    } else {
        0.5
    };

    data_factor * embed_factor
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_labyrinth_basic() {
        let mut data = Vec::new();
        let mut x = 1.0;
        for i in 0..200 {
            x = 3.7 * x * (1.0 - x); // Logistic map
            data.push(x * 100.0 + (i as f64 * 0.01).sin() * 10.0);
        }

        let params = LabyrinthParams::default();
        let result = analyze_labyrinth(&data, &params).unwrap();

        assert!(result.embedding_dimension >= 1);
        assert!(result.optimal_delay >= 1);
        assert!(result.confidence > 0.0);
    }

    #[test]
    fn test_labyrinth_insufficient_data() {
        let data: Vec<f64> = (0..20).map(|i| i as f64).collect();
        let params = LabyrinthParams::default();
        let result = analyze_labyrinth(&data, &params);
        assert!(result.is_err());
    }

    #[test]
    fn test_embedding_construction() {
        let data: Vec<f64> = (0..50).map(|i| i as f64).collect();
        let embedding = construct_embedding(&data, 3, 2);

        assert!(!embedding.is_empty());
        assert_eq!(embedding[0].len(), 3); // Dimension is 3
        assert_eq!(embedding[0][0], 0.0);
        assert_eq!(embedding[0][1], 2.0); // delay = 2
        assert_eq!(embedding[0][2], 4.0); // 2 * delay
    }

    #[test]
    fn test_connected_components() {
        let mut edges = HashSet::new();
        edges.insert((0, 1));
        edges.insert((1, 2));
        // 3, 4 are isolated

        let components = count_connected_components(5, &edges);
        assert_eq!(components, 3); // {0,1,2}, {3}, {4}
    }

    #[test]
    fn test_euclidean_distance() {
        let a = vec![0.0, 0.0];
        let b = vec![3.0, 4.0];
        assert!((euclidean_distance(&a, &b) - 5.0).abs() < 0.001);
    }
}
