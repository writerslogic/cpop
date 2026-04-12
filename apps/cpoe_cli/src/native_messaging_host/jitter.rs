// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

pub(crate) const MAX_JITTER_BATCHES_PER_WINDOW: u64 = 50;
/// Refill rate: 10 batches/sec = 10 milli-tokens per millisecond.
pub(crate) const JITTER_REFILL_PER_MS: u64 = 10;
/// One batch costs 1000 milli-tokens; max bucket = 50 * 1000.
pub(crate) const JITTER_TOKEN_COST: u64 = 1_000;
pub(crate) const JITTER_TOKEN_MAX: u64 = MAX_JITTER_BATCHES_PER_WINDOW * JITTER_TOKEN_COST;
pub(crate) const MAX_BATCH_SIZE: usize = 200;

pub(crate) struct JitterStats {
    pub(crate) count: usize,
    pub(crate) mean: f64,
    pub(crate) std_dev: f64,
    pub(crate) min: u64,
    pub(crate) max: u64,
}

pub(crate) fn compute_jitter_stats(intervals: &[u64]) -> JitterStats {
    if intervals.is_empty() {
        return JitterStats {
            count: 0,
            mean: 0.0,
            std_dev: 0.0,
            min: 0,
            max: 0,
        };
    }
    let count = intervals.len();
    let sum: u64 = intervals
        .iter()
        .copied()
        .fold(0u64, |a, b| a.saturating_add(b));
    let mean = sum as f64 / count as f64;

    let variance = intervals
        .iter()
        .map(|&v| {
            let diff = v as f64 - mean;
            diff * diff
        })
        .sum::<f64>()
        / count as f64;

    JitterStats {
        count,
        mean,
        std_dev: variance.sqrt(),
        min: intervals.iter().copied().min().unwrap_or(0),
        max: intervals.iter().copied().max().unwrap_or(0),
    }
}
