// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Keystroke cadence analysis.

use statrs::statistics::{Data, OrderStatistics};

use crate::jitter::SimpleJitterSample;

use super::topology::compute_median;
use super::types::{CadenceMetrics, ROBOTIC_CV_THRESHOLD};

/// IKI threshold in nanoseconds for fast-burst detection (200 ms).
const BURST_THRESHOLD_NS: f64 = 200_000_000.0;

/// IKI threshold in nanoseconds for pause detection (2 seconds).
const PAUSE_THRESHOLD_NS: f64 = 2_000_000_000.0;

/// Minimum consecutive fast keystrokes to qualify as a burst.
const MIN_BURST_LENGTH: usize = 3;

/// Minimum samples needed before flagging content as retyped.
const MIN_RETYPED_SAMPLES: usize = 20;

/// Analyze keystroke cadence from jitter samples.
pub fn analyze_cadence(samples: &[SimpleJitterSample]) -> CadenceMetrics {
    let mut metrics = CadenceMetrics::default();

    if samples.len() < 2 {
        return metrics;
    }

    let ikis: Vec<f64> = samples
        .windows(2)
        .map(|w| (w[1].timestamp_ns - w[0].timestamp_ns) as f64)
        .collect();

    if ikis.is_empty() {
        return metrics;
    }

    let sum: f64 = ikis.iter().sum();
    metrics.mean_iki_ns = sum / ikis.len() as f64;

    let variance: f64 = ikis
        .iter()
        .map(|x| (x - metrics.mean_iki_ns).powi(2))
        .sum::<f64>()
        / ikis.len() as f64;
    metrics.std_dev_iki_ns = variance.sqrt();

    if metrics.mean_iki_ns > 0.0 {
        metrics.coefficient_of_variation = metrics.std_dev_iki_ns / metrics.mean_iki_ns;
    }

    metrics.median_iki_ns = compute_median(&ikis);

    metrics.is_robotic = metrics.coefficient_of_variation < ROBOTIC_CV_THRESHOLD;

    let (bursts, pauses) = detect_bursts_and_pauses(&ikis);
    metrics.burst_count = bursts.len();
    metrics.pause_count = pauses.len();

    if !bursts.is_empty() {
        metrics.avg_burst_length =
            bursts.iter().map(|b| b.length as f64).sum::<f64>() / bursts.len() as f64;
    }

    if !pauses.is_empty() {
        metrics.avg_pause_duration_ns = pauses.iter().sum::<f64>() / pauses.len() as f64;
    }

    let mut data = Data::new(ikis);
    metrics.percentiles = [
        data.percentile(10),
        data.percentile(25),
        data.percentile(50),
        data.percentile(75),
        data.percentile(90),
    ];

    metrics
}

/// Contiguous run of fast keystrokes.
#[derive(Debug, Clone)]
pub struct TypingBurst {
    pub start_idx: usize,
    pub length: usize,
    pub avg_iki_ns: f64,
}

/// Segment IKI sequence into bursts and pauses.
fn detect_bursts_and_pauses(ikis: &[f64]) -> (Vec<TypingBurst>, Vec<f64>) {
    let mut bursts = Vec::new();
    let mut pauses = Vec::new();

    let mut burst_start: Option<usize> = None;
    let mut burst_sum = 0.0;

    for (i, &iki) in ikis.iter().enumerate() {
        if iki < BURST_THRESHOLD_NS {
            if burst_start.is_none() {
                burst_start = Some(i);
                burst_sum = 0.0;
            }
            burst_sum += iki;
        } else {
            if let Some(start) = burst_start {
                let length = i - start;
                if length >= MIN_BURST_LENGTH {
                    bursts.push(TypingBurst {
                        start_idx: start,
                        length,
                        avg_iki_ns: burst_sum / length as f64,
                    });
                }
                burst_start = None;
            }

            if iki > PAUSE_THRESHOLD_NS {
                pauses.push(iki);
            }
        }
    }

    if let Some(start) = burst_start {
        let length = ikis.len() - start;
        if length >= MIN_BURST_LENGTH {
            bursts.push(TypingBurst {
                start_idx: start,
                length,
                avg_iki_ns: burst_sum / length as f64,
            });
        }
    }

    (bursts, pauses)
}

/// Return `true` if cadence is too rhythmic for original composition (likely retyped).
pub fn is_retyped_content(samples: &[SimpleJitterSample]) -> bool {
    samples.len() >= MIN_RETYPED_SAMPLES && analyze_cadence(samples).is_robotic
}
