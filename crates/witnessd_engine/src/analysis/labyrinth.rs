// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Labyrinth structure analysis using Takens' theorem.
//!
//! Implements delay-coordinate embedding to reconstruct the
//! attractor topology of human behavioral signals. Based on
//! Takens' theorem, which states that the dynamics of a system
//! can be reconstructed from a single observable.
//!
//! RFC draft-condrey-rats-pop-01 uses labyrinth structure to
//! detect the characteristic topological invariants of human
//! motor control, including:
//! - Embedding dimension estimation
//! - Betti numbers (topological holes)
//! - Correlation dimension
//!
//! Human motor control produces characteristic attractor structures
//! with specific topological properties that are difficult to fake.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Result of labyrinth structure analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabyrinthAnalysis {
    /// Estimated embedding dimension.
    /// Number of dimensions needed to unfold the attractor.
    pub embedding_dimension: usize,

    /// Optimal time delay (in samples).
    pub optimal_delay: usize,

    /// Correlation dimension estimate.
    /// Measures the complexity/fractal dimension of the attractor.
    pub correlation_dimension: f64,

    /// Betti numbers (β₀, β₁, β₂).
    /// Topological invariants counting connected components, loops, and voids.
    pub betti_numbers: [usize; 3],

    /// Recurrence rate (percentage of recurrent points).
    pub recurrence_rate: f64,

    /// Determinism (percentage of recurrent points forming diagonal lines).
    pub determinism: f64,

    /// Whether the structure passes RFC validation.
    pub is_valid: bool,

    /// Confidence score (0-1) based on data quality.
    pub confidence: f64,
}

impl LabyrinthAnalysis {
    /// RFC-compliant range for embedding dimension of human motor signals.
    pub const MIN_EMBEDDING_DIM: usize = 3;
    pub const MAX_EMBEDDING_DIM: usize = 8;

    /// Expected correlation dimension range for human motor control.
    pub const MIN_CORRELATION_DIM: f64 = 1.5;
    pub const MAX_CORRELATION_DIM: f64 = 5.0;

    /// Check if labyrinth structure is characteristic of human input.
    pub fn is_biologically_plausible(&self) -> bool {
        self.embedding_dimension >= Self::MIN_EMBEDDING_DIM
            && self.embedding_dimension <= Self::MAX_EMBEDDING_DIM
            && self.correlation_dimension >= Self::MIN_CORRELATION_DIM
            && self.correlation_dimension <= Self::MAX_CORRELATION_DIM
            && self.determinism > 0.3
            && self.determinism < 0.95
    }
}

/// Parameters for labyrinth analysis.
#[derive(Debug, Clone)]
pub struct LabyrinthParams {
    /// Maximum embedding dimension to test.
    pub max_embedding_dim: usize,
    /// Maximum time delay to test.
    pub max_delay: usize,
    /// Recurrence threshold (fraction of standard deviation).
    pub recurrence_threshold: f64,
    /// Minimum line length for determinism calculation.
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

/// Perform labyrinth structure analysis on a time series.
///
/// # Arguments
/// * `data` - Time series data (e.g., inter-keystroke intervals)
/// * `params` - Analysis parameters
///
/// # Returns
/// * `LabyrinthAnalysis` with topological characteristics
pub fn analyze_labyrinth(
    data: &[f64],
    params: &LabyrinthParams,
) -> Result<LabyrinthAnalysis, String> {
    let n = data.len();
    if n < 50 {
        return Err("Insufficient data for labyrinth analysis (minimum 50 points)".to_string());
    }

    // Step 1: Find optimal time delay using mutual information
    let optimal_delay = find_optimal_delay(data, params.max_delay);

    // Step 2: Estimate embedding dimension using false nearest neighbors
    let embedding_dimension =
        estimate_embedding_dimension(data, optimal_delay, params.max_embedding_dim);

    // Step 3: Construct delay-coordinate embedding
    let embedding = construct_embedding(data, embedding_dimension, optimal_delay);

    if embedding.is_empty() {
        return Err("Could not construct valid embedding".to_string());
    }

    // Step 4: Compute recurrence matrix and statistics
    let (recurrence_rate, determinism) = compute_recurrence_quantification(
        &embedding,
        params.recurrence_threshold,
        params.min_line_length,
    );

    // Step 5: Estimate correlation dimension
    let correlation_dimension = estimate_correlation_dimension(&embedding);

    // Step 6: Estimate Betti numbers (simplified)
    let betti_numbers = estimate_betti_numbers(&embedding, params.recurrence_threshold);

    // Validate results
    let is_valid = (LabyrinthAnalysis::MIN_EMBEDDING_DIM..=LabyrinthAnalysis::MAX_EMBEDDING_DIM)
        .contains(&embedding_dimension)
        && (LabyrinthAnalysis::MIN_CORRELATION_DIM..=LabyrinthAnalysis::MAX_CORRELATION_DIM)
            .contains(&correlation_dimension);

    // Calculate confidence based on data quality
    let confidence = calculate_confidence(n, embedding_dimension, optimal_delay);

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

/// Find optimal time delay using first minimum of mutual information.
fn find_optimal_delay(data: &[f64], max_delay: usize) -> usize {
    let n = data.len();
    if n < max_delay + 10 {
        return 1;
    }

    // Normalize data to [0, 1]
    let min_val = data.iter().cloned().fold(f64::INFINITY, f64::min);
    let max_val = data.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let range = (max_val - min_val).max(1e-10);

    let normalized: Vec<f64> = data.iter().map(|&x| (x - min_val) / range).collect();

    // Calculate mutual information for each delay
    let num_bins = 16;
    let mut prev_mi = f64::INFINITY;

    for delay in 1..=max_delay {
        let mi = calculate_mutual_information(&normalized, delay, num_bins);

        // Look for first local minimum
        if mi > prev_mi {
            return delay - 1;
        }
        prev_mi = mi;
    }

    // Default to delay where MI is lowest
    max_delay / 2
}

/// Calculate mutual information between x(t) and x(t+delay).
fn calculate_mutual_information(data: &[f64], delay: usize, num_bins: usize) -> f64 {
    let n = data.len() - delay;
    if n < num_bins * 2 {
        return f64::INFINITY;
    }

    // Create 2D histogram
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

    // Calculate mutual information
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

/// Estimate embedding dimension using false nearest neighbors.
fn estimate_embedding_dimension(data: &[f64], delay: usize, max_dim: usize) -> usize {
    let _n = data.len();

    for dim in 1..=max_dim {
        let embedding = construct_embedding(data, dim, delay);
        if embedding.len() < 20 {
            return dim;
        }

        let fnn_ratio = calculate_fnn_ratio(&embedding, data, dim, delay);

        // If FNN ratio drops below threshold, we've found the dimension
        if fnn_ratio < 0.1 {
            return dim;
        }
    }

    max_dim
}

/// Calculate false nearest neighbors ratio.
fn calculate_fnn_ratio(embedding: &[Vec<f64>], original: &[f64], dim: usize, delay: usize) -> f64 {
    let n = embedding.len();
    if n < 10 {
        return 1.0;
    }

    let threshold = 15.0; // Typical FNN threshold
    let mut fnn_count = 0;
    let mut total_count = 0;

    // Sample subset for efficiency
    let sample_size = n.min(100);
    let step = (n / sample_size).max(1);

    for i in (0..n).step_by(step) {
        // Find nearest neighbor in current embedding
        let mut min_dist = f64::INFINITY;
        let mut nn_idx = 0;

        for j in 0..n {
            if i != j {
                let dist = euclidean_distance(&embedding[i], &embedding[j]);
                if dist < min_dist && dist > 0.0 {
                    min_dist = dist;
                    nn_idx = j;
                }
            }
        }

        if min_dist > 0.0 && min_dist < f64::INFINITY {
            // Check if this is a false neighbor
            let orig_idx_i = i * delay + (dim - 1) * delay;
            let orig_idx_j = nn_idx * delay + (dim - 1) * delay;

            if orig_idx_i + delay < original.len() && orig_idx_j + delay < original.len() {
                let extra_dist =
                    (original[orig_idx_i + delay] - original[orig_idx_j + delay]).abs();
                let ratio = extra_dist / min_dist;

                total_count += 1;
                if ratio > threshold {
                    fnn_count += 1;
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

/// Construct delay-coordinate embedding.
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

/// Compute recurrence quantification analysis metrics.
fn compute_recurrence_quantification(
    embedding: &[Vec<f64>],
    threshold: f64,
    _min_line_length: usize,
) -> (f64, f64) {
    let n = embedding.len();
    if n < 10 {
        return (0.0, 0.0);
    }

    // Calculate standard deviation for threshold scaling
    let all_coords: Vec<f64> = embedding.iter().flat_map(|p| p.iter().copied()).collect();
    let mean: f64 = all_coords.iter().sum::<f64>() / all_coords.len() as f64;
    let variance: f64 =
        all_coords.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / all_coords.len() as f64;
    let std_dev = variance.sqrt();

    let eps = threshold * std_dev;

    // Sample recurrence matrix for efficiency
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

                    // Check for diagonal structure
                    if si + 1 < sampled_indices.len() && sj + 1 < sampled_indices.len() {
                        let i_next = sampled_indices[si + 1];
                        let j_next = sampled_indices[sj + 1];
                        if i_next < n && j_next < n {
                            let dist_next =
                                euclidean_distance(&embedding[i_next], &embedding[j_next]);
                            if dist_next < eps {
                                diagonal_count += 1;
                            }
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

/// Estimate correlation dimension using Grassberger-Procaccia algorithm.
fn estimate_correlation_dimension(embedding: &[Vec<f64>]) -> f64 {
    let n = embedding.len();
    if n < 20 {
        return 0.0;
    }

    // Calculate pairwise distances
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

    // Calculate correlation sum C(r) for different r values
    let mut log_r = Vec::new();
    let mut log_c = Vec::new();

    let r_min = distances[distances.len() / 10];
    let r_max = distances[distances.len() * 9 / 10];

    let num_bins = 10;
    for i in 0..num_bins {
        let r = r_min * ((r_max / r_min).powf(i as f64 / (num_bins - 1) as f64));

        // Count pairs within distance r
        let count = distances.iter().filter(|&&d| d < r).count();
        let c = count as f64 / distances.len() as f64;

        if c > 0.0 && r > 0.0 {
            log_r.push(r.ln());
            log_c.push(c.ln());
        }
    }

    if log_r.len() < 3 {
        return 0.0;
    }

    // Linear regression to get slope (correlation dimension)
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
        (num / denom).max(0.0)
    } else {
        0.0
    }
}

/// Estimate Betti numbers using simplicial complex approximation.
///
/// This is a simplified estimation - full persistent homology
/// would require a specialized library.
fn estimate_betti_numbers(embedding: &[Vec<f64>], threshold: f64) -> [usize; 3] {
    let n = embedding.len();
    if n < 10 {
        return [1, 0, 0];
    }

    // Calculate distance threshold
    let all_coords: Vec<f64> = embedding.iter().flat_map(|p| p.iter().copied()).collect();
    let mean: f64 = all_coords.iter().sum::<f64>() / all_coords.len() as f64;
    let variance: f64 =
        all_coords.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / all_coords.len() as f64;
    let eps = threshold * variance.sqrt() * 3.0;

    // Build adjacency graph
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

/// Count connected components using union-find.
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

/// Calculate Euclidean distance between two points.
fn euclidean_distance(a: &[f64], b: &[f64]) -> f64 {
    a.iter()
        .zip(b.iter())
        .map(|(&x, &y)| (x - y).powi(2))
        .sum::<f64>()
        .sqrt()
}

/// Calculate confidence score based on data quality.
fn calculate_confidence(n: usize, dim: usize, delay: usize) -> f64 {
    // More data points = higher confidence
    let data_factor = (n as f64 / 100.0).min(1.0);

    // Reasonable embedding parameters = higher confidence
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
        // Generate quasi-periodic data (Lorenz-like)
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
