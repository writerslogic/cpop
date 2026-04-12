// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Profile comparison and similarity analysis.

use serde::{Deserialize, Serialize};

use super::types::AuthorshipProfile;

/// Minimum similarity score to consider two profiles as same-author.
const CONSISTENCY_THRESHOLD: f64 = 0.6;

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
}

/// Compare two profiles for authorship consistency (Gaussian kernel similarity).
pub fn compare_profiles(
    profile_a: &AuthorshipProfile,
    profile_b: &AuthorshipProfile,
) -> ProfileComparison {
    let scores = DimensionScores {
        monotonic_append_similarity: gaussian_similarity(
            profile_a.metrics.monotonic_append_ratio.get(),
            profile_b.metrics.monotonic_append_ratio.get(),
            0.15,
        ),
        entropy_similarity: gaussian_similarity(
            profile_a.metrics.edit_entropy,
            profile_b.metrics.edit_entropy,
            0.5,
        ),
        // Compare in log-space; guard against ln(0) = -inf and ln(neg) = NaN.
        // When both intervals are zero (no data), similarity is undefined; use NaN
        // so it does not masquerade as a perfect match.
        interval_similarity: if profile_a.metrics.median_interval <= 0.0
            && profile_b.metrics.median_interval <= 0.0
        {
            f64::NAN
        } else {
            gaussian_similarity(
                safe_ln(profile_a.metrics.median_interval),
                safe_ln(profile_b.metrics.median_interval),
                0.5,
            )
        },
        pos_neg_ratio_similarity: gaussian_similarity(
            profile_a.metrics.positive_negative_ratio.get(),
            profile_b.metrics.positive_negative_ratio.get(),
            0.1,
        ),
        deletion_clustering_similarity: gaussian_similarity(
            profile_a.metrics.deletion_clustering,
            profile_b.metrics.deletion_clustering,
            0.2,
        ),
    };

    // NaN handling strategy: when a dimension produces NaN (e.g., both
    // profiles lack interval data, or safe_ln received non-positive input),
    // that dimension's contribution and weight are zeroed out. The remaining
    // dimensions' weights are implicitly rescaled by dividing by
    // total_weight, which excludes the NaN dimension's weight. This avoids
    // penalizing or rewarding comparisons that lack a particular signal.
    fn guarded(raw: f64, weight: f64) -> (f64, f64) {
        if raw.is_nan() {
            (0.0, 0.0)
        } else {
            (weight * raw, weight)
        }
    }
    let (mono_c, mono_w) = guarded(scores.monotonic_append_similarity, 0.25);
    let (ent_c, ent_w) = guarded(scores.entropy_similarity, 0.20);
    let (int_c, int_w) = guarded(scores.interval_similarity, 0.15);
    let (pnr_c, pnr_w) = guarded(scores.pos_neg_ratio_similarity, 0.20);
    let (del_c, del_w) = guarded(scores.deletion_clustering_similarity, 0.20);
    let total_weight = mono_w + ent_w + int_w + pnr_w + del_w;
    let similarity_score = if total_weight > 0.0 {
        (mono_c + ent_c + int_c + pnr_c + del_c) / total_weight
    } else {
        0.0
    };

    let is_consistent = similarity_score >= CONSISTENCY_THRESHOLD;

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

/// Gaussian kernel similarity: `exp(-(a-b)^2 / 2*sigma^2)`, clamped to [0.0, 1.0].
fn gaussian_similarity(a: f64, b: f64, sigma: f64) -> f64 {
    let diff = a - b;
    crate::utils::Probability::clamp((-diff * diff / (2.0 * sigma * sigma)).exp()).get()
}

/// Return `ln(v)` for positive inputs, or `NAN` for non-positive inputs.
///
/// Returning NAN (rather than 0.0) ensures that dimensions with invalid data
/// are excluded from similarity scoring instead of silently biasing results.
fn safe_ln(v: f64) -> f64 {
    if v > 0.0 {
        v.ln()
    } else {
        f64::NAN
    }
}
