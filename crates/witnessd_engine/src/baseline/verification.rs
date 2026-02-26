// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use witnessd_protocol::baseline::{BaselineDigest, SessionBehavioralSummary};

pub fn verify_against_baseline(digest: &BaselineDigest, session: &SessionBehavioralSummary) -> f64 {
    // 1. Bhattacharyya coefficient on IKI histograms
    let b_coeff = calculate_bhattacharyya(&digest.aggregate_iki_histogram, &session.iki_histogram);

    // 2. Gaussian similarity on CV, Hurst, and pause frequency
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

    // Weighted composite similarity
    0.4 * b_coeff + 0.2 * cv_sim + 0.2 * hurst_sim + 0.2 * pause_sim
}

fn calculate_bhattacharyya(h1: &[f64; 9], h2: &[f64; 9]) -> f64 {
    let mut score = 0.0;
    for i in 0..9 {
        score += (h1[i] * h2[i]).sqrt();
    }
    score
}

fn gaussian_similarity(value: f64, mean: f64, m2: f64, count: u64) -> f64 {
    if count < 2 {
        return 1.0; // Perfect similarity if no baseline data exists yet
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
