// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Profile comparison and similarity analysis.

use serde::{Deserialize, Serialize};

use super::types::AuthorshipProfile;

/// Weighted similarity comparison of two authorship profiles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileComparison {
    /// Overall similarity score (0.0 - 1.0).
    pub similarity_score: f64,
    /// Whether profiles are consistent with same author.
    pub is_consistent: bool,
    /// Detailed dimension comparisons.
    pub dimension_scores: DimensionScores,
    /// Explanation of comparison result.
    pub explanation: String,
}

/// Per-dimension similarity scores.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DimensionScores {
    pub monotonic_append_similarity: f64,
    pub entropy_similarity: f64,
    pub interval_similarity: f64,
    pub pos_neg_ratio_similarity: f64,
    pub deletion_clustering_similarity: f64,
    pub cadence_cv_similarity: f64,
}

/// Compare two profiles for authorship consistency (Gaussian kernel similarity).
#[allow(clippy::field_reassign_with_default)]
pub fn compare_profiles(
    profile_a: &AuthorshipProfile,
    profile_b: &AuthorshipProfile,
) -> ProfileComparison {
    let mut scores = DimensionScores::default();

    scores.monotonic_append_similarity = gaussian_similarity(
        profile_a.metrics.monotonic_append_ratio,
        profile_b.metrics.monotonic_append_ratio,
        0.15,
    );

    scores.entropy_similarity = gaussian_similarity(
        profile_a.metrics.edit_entropy,
        profile_b.metrics.edit_entropy,
        0.5,
    );

    scores.interval_similarity = gaussian_similarity(
        profile_a.metrics.median_interval.ln().max(0.0),
        profile_b.metrics.median_interval.ln().max(0.0),
        0.5,
    );

    scores.pos_neg_ratio_similarity = gaussian_similarity(
        profile_a.metrics.positive_negative_ratio,
        profile_b.metrics.positive_negative_ratio,
        0.1,
    );

    scores.deletion_clustering_similarity = gaussian_similarity(
        profile_a.metrics.deletion_clustering,
        profile_b.metrics.deletion_clustering,
        0.2,
    );

    let similarity_score = 0.25 * scores.monotonic_append_similarity
        + 0.20 * scores.entropy_similarity
        + 0.15 * scores.interval_similarity
        + 0.20 * scores.pos_neg_ratio_similarity
        + 0.20 * scores.deletion_clustering_similarity;

    let is_consistent = similarity_score >= 0.6;

    let explanation = if is_consistent {
        format!(
            "Profiles are consistent with same author (similarity: {:.1}%)",
            similarity_score * 100.0
        )
    } else {
        format!(
            "Profiles show significant differences (similarity: {:.1}%)",
            similarity_score * 100.0
        )
    };

    ProfileComparison {
        similarity_score,
        is_consistent,
        dimension_scores: scores,
        explanation,
    }
}

/// Gaussian kernel similarity: `exp(-(a-b)^2 / 2*sigma^2)`
fn gaussian_similarity(a: f64, b: f64, sigma: f64) -> f64 {
    let diff = a - b;
    (-diff * diff / (2.0 * sigma * sigma)).exp()
}
