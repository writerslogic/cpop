// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::baseline::streaming::StreamingStatsExt;
use witnessd_protocol::baseline::{
    BaselineDigest, ConfidenceTier, SessionBehavioralSummary, StreamingStats,
};

pub fn compute_initial_digest(identity_fingerprint: Vec<u8>) -> BaselineDigest {
    BaselineDigest {
        version: 1,
        session_count: 0,
        total_keystrokes: 0,
        iki_stats: StreamingStats::new_empty(),
        cv_stats: StreamingStats::new_empty(),
        hurst_stats: StreamingStats::new_empty(),
        aggregate_iki_histogram: [0.0; 9],
        pause_stats: StreamingStats::new_empty(),
        session_merkle_root: vec![0u8; 32],
        confidence_tier: ConfidenceTier::PopulationReference,
        computed_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        identity_fingerprint,
    }
}

pub fn update_digest(
    mut digest: BaselineDigest,
    summary: &SessionBehavioralSummary,
) -> BaselineDigest {
    digest.session_count += 1;
    digest.total_keystrokes += summary.keystroke_count;

    // Estimate mean IKI from histogram bin centers (weighted average)
    let bin_centers: [f64; 9] = [
        25.0, 75.0, 125.0, 175.0, 250.0, 400.0, 750.0, 1500.0, 2500.0,
    ];
    let mean_iki: f64 = summary
        .iki_histogram
        .iter()
        .zip(bin_centers.iter())
        .map(|(w, c)| w * c)
        .sum();
    digest.iki_stats.update(mean_iki);
    digest.cv_stats.update(summary.iki_cv);
    digest.hurst_stats.update(summary.hurst);
    digest.pause_stats.update(summary.pause_frequency);

    // Update aggregate histogram (running average)
    let n = digest.session_count as f64;
    for i in 0..9 {
        digest.aggregate_iki_histogram[i] =
            (digest.aggregate_iki_histogram[i] * (n - 1.0) + summary.iki_histogram[i]) / n;
    }

    digest.confidence_tier = ConfidenceTier::from_session_count(digest.session_count);

    digest.computed_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    digest
}
