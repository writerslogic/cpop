// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Keystroke cadence analysis.

use statrs::statistics::{Data, OrderStatistics};

use crate::jitter::SimpleJitterSample;

use super::topology::compute_median;
use super::types::{CadenceMetrics, ROBOTIC_CV_THRESHOLD};

/// IKI threshold in nanoseconds for fast-burst detection (200 ms).
const BURST_THRESHOLD_NS: f64 = 200_000_000.0;

/// IKI threshold in nanoseconds for pause detection (2 seconds).
const PAUSE_THRESHOLD_NS: f64 = 2_000_000_000.0;

/// IKI threshold in nanoseconds for cognitive pause detection (1 second).
const COGNITIVE_PAUSE_THRESHOLD_NS: f64 = 1_000_000_000.0;

/// Sentence-level pause upper bound (3 seconds).
const SENTENCE_PAUSE_UPPER_NS: f64 = 3_000_000_000.0;

/// Paragraph-level pause upper bound (10 seconds).
const PARAGRAPH_PAUSE_UPPER_NS: f64 = 10_000_000_000.0;

/// Number of post-pause keystrokes to analyze.
const POST_PAUSE_WINDOW: usize = 5;

/// Zone value for unmapped keys (backspace, delete, etc.).
const CORRECTION_ZONE: u8 = 0xFF;

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

    let mut data = Data::new(ikis.clone());
    metrics.percentiles = [
        data.percentile(10),
        data.percentile(25),
        data.percentile(50),
        data.percentile(75),
        data.percentile(90),
    ];

    metrics.cross_hand_timing_ratio = compute_cross_hand_timing_ratio(samples, &ikis);
    metrics.post_pause_cv = compute_post_pause_cv(&ikis);
    metrics.iki_autocorrelation = compute_iki_autocorrelation(&ikis);
    metrics.correction_ratio = compute_correction_ratio(samples);
    metrics.pause_depth_distribution = compute_pause_depth_distribution(&ikis);

    metrics
}

/// Compute ratio of cross-hand IKI std_dev to same-hand IKI std_dev.
///
/// Zones 0-3 are left hand, 4-7 are right hand. Cross-hand transitions
/// naturally have more timing variance than same-hand transitions in
/// cognitive writing. Transcriptive typing shows less differentiation.
fn compute_cross_hand_timing_ratio(samples: &[SimpleJitterSample], ikis: &[f64]) -> f64 {
    let mut cross_hand_ikis = Vec::new();
    let mut same_hand_ikis = Vec::new();

    for (i, iki) in ikis.iter().enumerate() {
        let from_zone = samples[i].zone;
        let to_zone = samples[i + 1].zone;
        // Skip unmapped zones.
        if from_zone == CORRECTION_ZONE || to_zone == CORRECTION_ZONE {
            continue;
        }
        let from_left = from_zone < 4;
        let to_left = to_zone < 4;
        if from_left == to_left {
            same_hand_ikis.push(*iki);
        } else {
            cross_hand_ikis.push(*iki);
        }
    }

    let cross_std = std_dev_of(&cross_hand_ikis);
    let same_std = std_dev_of(&same_hand_ikis);

    if same_std > 0.0 {
        cross_std / same_std
    } else {
        0.0
    }
}

/// Compute CV of the first N keystrokes after each cognitive pause (>1s).
///
/// In cognitive writing, the burst after a thinking pause has variable speed
/// as the writer translates thoughts to keystrokes. Transcriptive typing
/// resumes at a uniform pace.
fn compute_post_pause_cv(ikis: &[f64]) -> f64 {
    let mut post_pause_ikis = Vec::new();

    let mut i = 0;
    while i < ikis.len() {
        if ikis[i] > COGNITIVE_PAUSE_THRESHOLD_NS {
            let window_end = (i + 1 + POST_PAUSE_WINDOW).min(ikis.len());
            let window = &ikis[i + 1..window_end];
            if window.len() >= 2 {
                post_pause_ikis.extend_from_slice(window);
            }
        }
        i += 1;
    }

    if post_pause_ikis.len() < 2 {
        return 0.0;
    }

    let mean = post_pause_ikis.iter().sum::<f64>() / post_pause_ikis.len() as f64;
    if mean <= 0.0 {
        return 0.0;
    }
    let std = std_dev_of(&post_pause_ikis);
    std / mean
}

/// Compute lag-1 autocorrelation of the IKI sequence.
///
/// Cognitive writing produces near-zero autocorrelation (each interval is
/// roughly independent). Transcriptive typing produces positive autocorrelation
/// because the rhythm is consistently maintained.
fn compute_iki_autocorrelation(ikis: &[f64]) -> f64 {
    if ikis.len() < 3 {
        return 0.0;
    }

    let n = ikis.len();
    let mean = ikis.iter().sum::<f64>() / n as f64;
    let variance: f64 = ikis.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n as f64;

    if variance <= 0.0 {
        return 0.0;
    }

    let covariance: f64 = ikis
        .windows(2)
        .map(|w| (w[0] - mean) * (w[1] - mean))
        .sum::<f64>()
        / (n - 1) as f64;

    (covariance / variance).clamp(-1.0, 1.0)
}

/// Compute fraction of keystrokes tagged as corrections (backspace/delete).
///
/// The zone field is set to `CORRECTION_ZONE` (0xFF) for unmapped keys,
/// which includes backspace and delete. Cognitive writing has more corrections
/// (>0.05) while transcriptive typing has almost none (<0.02).
fn compute_correction_ratio(samples: &[SimpleJitterSample]) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let corrections = samples.iter().filter(|s| s.zone == CORRECTION_ZONE).count();
    corrections as f64 / samples.len() as f64
}

/// Classify pauses into duration tiers and return normalized distribution.
///
/// Tiers: sentence-level (1-3s), paragraph-level (3-10s), deep thought (>10s).
/// Cognitive writing shows a spread across all tiers; transcriptive typing
/// concentrates pauses in the sentence tier or has none at all.
fn compute_pause_depth_distribution(ikis: &[f64]) -> [f64; 3] {
    let mut counts = [0u64; 3];

    for &iki in ikis {
        if iki > COGNITIVE_PAUSE_THRESHOLD_NS && iki <= SENTENCE_PAUSE_UPPER_NS {
            counts[0] += 1;
        } else if iki > SENTENCE_PAUSE_UPPER_NS && iki <= PARAGRAPH_PAUSE_UPPER_NS {
            counts[1] += 1;
        } else if iki > PARAGRAPH_PAUSE_UPPER_NS {
            counts[2] += 1;
        }
    }

    let total: u64 = counts.iter().sum();
    if total == 0 {
        return [0.0; 3];
    }
    [
        counts[0] as f64 / total as f64,
        counts[1] as f64 / total as f64,
        counts[2] as f64 / total as f64,
    ]
}

/// Compute population standard deviation of a slice.
fn std_dev_of(values: &[f64]) -> f64 {
    if values.len() < 2 {
        return 0.0;
    }
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    let variance = values.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / values.len() as f64;
    variance.sqrt()
}

/// Contiguous run of fast keystrokes.
#[derive(Debug, Clone)]
pub struct TypingBurst {
    /// Index into the IKI array where this burst begins.
    pub start_idx: usize,
    /// Number of consecutive fast keystrokes in this burst.
    pub length: usize,
    /// Mean inter-key interval within this burst (nanoseconds).
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
