// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::baseline::streaming::StreamingStatsExt;
use cpop_protocol::baseline::{
    BaselineDigest, ConfidenceTier, SessionBehavioralSummary, StreamingStats,
};

/// Create a zero-session baseline digest for a new identity.
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

/// Incorporate a session's behavioral summary into the running digest.
pub fn update_digest(
    mut digest: BaselineDigest,
    summary: &SessionBehavioralSummary,
) -> BaselineDigest {
    digest.session_count += 1;
    digest.total_keystrokes += summary.keystroke_count;

    let bin_centers: [f64; 9] = [
        25.0, 75.0, 125.0, 175.0, 250.0, 400.0, 750.0, 1500.0, 2500.0,
    ];
    let total_weight: f64 = summary.iki_histogram.iter().map(|&w| w as f64).sum();
    let mean_iki: f64 = if total_weight > 0.0 {
        summary
            .iki_histogram
            .iter()
            .zip(bin_centers.iter())
            .map(|(&w, &c)| w as f64 * c)
            .sum::<f64>()
            / total_weight
    } else {
        0.0
    };
    digest.iki_stats.update(mean_iki);
    digest.cv_stats.update(summary.iki_cv as f64);
    digest.hurst_stats.update(summary.hurst as f64);
    digest.pause_stats.update(summary.pause_frequency as f64);

    let n = digest.session_count as f64;
    for i in 0..9 {
        let prev = digest.aggregate_iki_histogram[i] as f64;
        let cur = summary.iki_histogram[i] as f64;
        digest.aggregate_iki_histogram[i] = ((prev * (n - 1.0) + cur) / n) as f32;
    }

    digest.confidence_tier = ConfidenceTier::from_session_count(digest.session_count);

    digest.computed_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    digest
}
