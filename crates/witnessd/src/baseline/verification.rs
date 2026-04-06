// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::analysis::stats::bhattacharyya_coefficient;
use authorproof_protocol::baseline::{BaselineDigest, SessionBehavioralSummary};

/// Score a session against the baseline digest, returning 0.0..1.0 similarity.
///
/// When the baseline has fewer than 2 sessions (`count < 2`), all Gaussian
/// similarity terms return 0.8 (lenient). This means a single-session baseline
/// yields ~0.8 for the similarity components, which is intentional: with only
/// one prior session there is no statistical basis for comparison, so we allow
/// the session through with a moderately high score rather than rejecting it.
pub fn verify_against_baseline(digest: &BaselineDigest, session: &SessionBehavioralSummary) -> f64 {
    let digest_hist: Vec<f64> = digest.aggregate_iki_histogram.to_vec();
    let session_hist: Vec<f64> = session.iki_histogram.to_vec();
    let b_coeff = bhattacharyya_coefficient(&digest_hist, &session_hist);

    let cv_sim = gaussian_similarity(
        session.iki_cv,
        digest.cv_stats.mean,
        digest.cv_stats.m2,
        digest.session_count,
    );
    let hurst_sim = gaussian_similarity(
        session.hurst,
        digest.hurst_stats.mean,
        digest.hurst_stats.m2,
        digest.session_count,
    );
    let pause_sim = gaussian_similarity(
        session.pause_frequency,
        digest.pause_stats.mean,
        digest.pause_stats.m2,
        digest.session_count,
    );

    (0.4 * b_coeff + 0.2 * cv_sim + 0.2 * hurst_sim + 0.2 * pause_sim).clamp(0.0, 1.0)
}

fn gaussian_similarity(value: f64, mean: f64, m2: f64, count: u64) -> f64 {
    if !value.is_finite() || !mean.is_finite() || !m2.is_finite() {
        return 0.5;
    }
    if count < 2 {
        // Fresh baseline with insufficient data; return lenient but not perfect similarity.
        return 0.8;
    }
    let variance = m2 / (count - 1) as f64;
    if variance < 1e-9 {
        return if (value - mean).abs() < 1e-9 {
            1.0
        } else {
            0.0
        };
    }

    let diff = value - mean;
    (-(diff * diff) / (2.0 * variance)).exp()
}
