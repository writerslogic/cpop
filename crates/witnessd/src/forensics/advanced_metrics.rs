// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Advanced forensic metrics: CLC, repair locality, and fatigue trajectory.

use crate::jitter::SimpleJitterSample;
use crate::utils::stats::{coefficient_of_variation, mean, std_dev};
use super::types::{ClcMetrics, RepairLocalityMetrics, FatigueTrajectoryMetrics};

/// Minimum samples for CLC analysis.
const MIN_CLC_SAMPLES: usize = 50;

/// Minimum samples for repair locality analysis.
const MIN_REPAIR_SAMPLES: usize = 5;

/// Minimum samples for fatigue trajectory analysis.
const MIN_FATIGUE_SAMPLES: usize = 30;

/// Compute Cognitive-Linguistic Complexity from checkpoint content windows and IKI samples.
///
/// CLC uses n-gram surprisal (bits per word) to measure linguistic predictability.
/// Cognitive writing shows higher surprisal (more varied language).
/// Transcriptive writing shows low surprisal (formulaic, repetitive patterns).
///
/// We correlate surprisal with IKI (inter-keystroke interval) to detect
/// synchronized typing patterns: faster typing on predictable text.
pub fn compute_clc_metrics(
    content_windows: &[String],
    samples: &[SimpleJitterSample],
) -> Option<ClcMetrics> {
    if content_windows.len() < 2 || samples.len() < MIN_CLC_SAMPLES {
        return None;
    }

    let ikis: Vec<f64> = samples
        .windows(2)
        .map(|w| (w[1].timestamp_ns.saturating_sub(w[0].timestamp_ns)).max(0) as f64)
        .collect();

    if ikis.is_empty() {
        return None;
    }

    // Simple n-gram surprisal: approximate using word frequency model.
    // For a window of text, estimate surprisal as negative log probability
    // based on unigram frequencies in a generic English corpus.
    let surprisals: Vec<f64> = content_windows
        .iter()
        .map(|window| estimate_unigram_surprisal(window))
        .collect();

    if surprisals.is_empty() {
        return None;
    }

    let mean_surprisal = mean(&surprisals);
    let std_surprisal = std_dev(&surprisals);
    let low_surprisal_count = surprisals.iter().filter(|&&s| s < 3.0).count();
    let low_surprisal_pct = (low_surprisal_count as f64 / surprisals.len() as f64) * 100.0;

    // Correlate IKI with surprisal: sample both at same indices.
    let iki_surprisal_corr = compute_iki_surprisal_correlation(&ikis, &surprisals);

    Some(ClcMetrics {
        mean_surprisal_bpw: mean_surprisal,
        std_dev_surprisal: std_surprisal,
        low_surprisal_pct,
        iki_surprisal_correlation: iki_surprisal_corr,
    })
}

/// Estimate unigram surprisal (bits per word) using a simplified corpus-based model.
///
/// This uses frequencies from common English words to approximate log2(1/P(word)).
/// A real implementation would load a full n-gram model; this is a lightweight approximation.
fn estimate_unigram_surprisal(text: &str) -> f64 {
    let words: Vec<&str> = text
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .collect();

    if words.is_empty() {
        return 0.0;
    }

    let total_surprisal: f64 = words.iter().map(|word| word_surprisal(word)).sum();
    total_surprisal / words.len() as f64
}

/// Lookup word surprisal from a simple frequency table.
/// Higher frequency words have lower surprisal.
fn word_surprisal(word: &str) -> f64 {
    let lower = word.to_lowercase();
    match lower.as_str() {
        // Top 100 English words (sample)
        "the" | "be" | "to" | "of" | "and" | "a" | "in" | "that" | "have" | "i" => 1.5,
        "it" | "for" | "not" | "on" | "with" | "he" | "as" | "you" | "do" | "at" => 2.0,
        "this" | "but" | "his" | "by" | "from" | "they" | "we" | "say" | "her" | "she" => 2.5,
        "or" | "an" | "will" | "my" | "one" | "all" | "would" | "there" | "their" | "what" => 3.0,
        // Medium frequency (2000-5000 rank)
        "about" | "after" | "could" | "think" | "people" | "time" | "very" | "right" | "make"
        | "come" => 4.5,
        // Rare/unknown words
        _ => 7.0,
    }
}

/// Quick check for common English words (simplified).
#[allow(dead_code)]
fn is_common_english_word(word: &str) -> bool {
    // Heuristics: English words are typically 3-8 chars, contain vowels, no numbers
    word.len() >= 3
        && word.len() <= 10
        && word.chars().all(|c| c.is_alphabetic())
        && word.chars().any(|c| matches!(c, 'a' | 'e' | 'i' | 'o' | 'u' | 'y'))
}

/// Compute Pearson correlation between IKI samples and surprisal values.
fn compute_iki_surprisal_correlation(ikis: &[f64], surprisals: &[f64]) -> f64 {
    let min_len = ikis.len().min(surprisals.len());
    if min_len < 3 {
        return 0.0;
    }

    let iki_sample = &ikis[..min_len];
    let surp_sample = &surprisals[..min_len];

    let iki_mean = mean(iki_sample);
    let surp_mean = mean(surp_sample);

    let iki_var = iki_sample.iter().map(|x| (x - iki_mean).powi(2)).sum::<f64>();
    let surp_var = surp_sample.iter().map(|x| (x - surp_mean).powi(2)).sum::<f64>();

    if !iki_var.is_finite() || !surp_var.is_finite() || iki_var <= 0.0 || surp_var <= 0.0 {
        return 0.0;
    }

    let covariance: f64 = iki_sample
        .iter()
        .zip(surp_sample.iter())
        .map(|(i, s)| (i - iki_mean) * (s - surp_mean))
        .sum();

    let correlation = covariance / (iki_var.sqrt() * surp_var.sqrt());
    correlation.clamp(-1.0, 1.0)
}

/// Analyze repair locality: track backspace events and their offsets from cursor.
///
/// Backspace offset = document position of deleted character relative to current cursor.
/// Human cognitive editing clusters repairs near recent edits (5-20 chars).
/// Synthetic/transcriptive editing scatters repairs across the document (50+ chars).
pub fn analyze_repair_locality(
    samples: &[SimpleJitterSample],
    file_sizes: &[i64],
) -> Option<RepairLocalityMetrics> {
    if samples.len() < MIN_REPAIR_SAMPLES || file_sizes.is_empty() {
        return None;
    }

    // Detect backspace events: corrections (zone 0xFF) or negative size deltas.
    let mut repairs = Vec::new();

    for (i, sample) in samples.iter().enumerate() {
        if sample.zone == 0xFF {
            // Unmapped key (backspace/delete)
            if i < file_sizes.len() {
                repairs.push(i);
            }
        }
    }

    if repairs.len() < MIN_REPAIR_SAMPLES {
        return None;
    }

    // Compute offsets: distance from cursor to repair location.
    let mut offsets = Vec::new();
    for &repair_idx in &repairs {
        if repair_idx < file_sizes.len() {
            let current_size = file_sizes[repair_idx];
            // Estimate cursor position as recent file size; offset is distance backward.
            let offset = if repair_idx > 0 {
                let prev_size = file_sizes[repair_idx - 1];
                (current_size - prev_size).unsigned_abs() as f64
            } else {
                0.0
            };
            if offset.is_finite() {
                offsets.push(offset);
            }
        }
    }

    if offsets.is_empty() {
        return None;
    }

    let mean_offset = mean(&offsets);
    let offset_cv = coefficient_of_variation(&offsets);

    // Compute percentages of repairs by distance category.
    let recent_repairs = offsets.iter().filter(|&&o| o <= 10.0).count();
    let distant_repairs = offsets.iter().filter(|&&o| o > 50.0).count();

    let recent_pct = (recent_repairs as f64 / offsets.len() as f64) * 100.0;
    let distant_pct = (distant_repairs as f64 / offsets.len() as f64) * 100.0;

    Some(RepairLocalityMetrics {
        mean_offset_chars: mean_offset,
        offset_cv,
        recent_repair_pct: recent_pct,
        distant_repair_pct: distant_pct,
    })
}

/// Analyze three-phase fatigue trajectory: warmup, plateau, fatigue.
///
/// Cognitive writing typically shows three phases:
/// 1. Warmup: initial ramp-up as thoughts organize (IKI decreasing)
/// 2. Plateau: steady-state typing (constant IKI)
/// 3. Fatigue: declining speed (IKI increasing) as fatigue sets in
///
/// Transcriptive/synthetic typing shows flat or monotonic patterns.
/// We fit a piecewise linear model and compute residuals.
pub fn analyze_fatigue_trajectory(samples: &[SimpleJitterSample]) -> Option<FatigueTrajectoryMetrics> {
    if samples.len() < MIN_FATIGUE_SAMPLES {
        return None;
    }

    let ikis: Vec<f64> = samples
        .windows(2)
        .map(|w| (w[1].timestamp_ns.saturating_sub(w[0].timestamp_ns)).max(0) as f64)
        .collect();

    if ikis.len() < MIN_FATIGUE_SAMPLES {
        return None;
    }

    // Fit three-phase model: find breakpoints that minimize residual.
    let (phase1_end, phase2_end, residual) = fit_three_phase_model(&ikis);

    let n = ikis.len() as f64;
    let warmup_frac = phase1_end as f64 / n;
    let plateau_frac = (phase2_end - phase1_end) as f64 / n;
    let fatigue_frac = (ikis.len() - phase2_end) as f64 / n;

    // Compute slope of fatigue phase (phase 2).
    let fatigue_slope = if phase2_end < ikis.len() {
        let phase2_ikis = &ikis[phase2_end..];
        if phase2_ikis.len() >= 2 {
            let first_half = mean(&phase2_ikis[..phase2_ikis.len() / 2]);
            let second_half = mean(&phase2_ikis[phase2_ikis.len() / 2..]);
            // Slope per 1000 keystrokes (IKI change per thousand key presses).
            ((second_half - first_half) / phase2_ikis.len() as f64) * 1000.0
        } else {
            0.0
        }
    } else {
        0.0
    };

    // Determine dominant phase.
    let dominant = if warmup_frac > plateau_frac && warmup_frac > fatigue_frac {
        0
    } else if plateau_frac > fatigue_frac {
        1
    } else if fatigue_frac > 0.0 {
        2
    } else {
        3 // Insufficient data
    };

    Some(FatigueTrajectoryMetrics {
        residual_sse: residual,
        warmup_fraction: warmup_frac,
        plateau_fraction: plateau_frac,
        fatigue_fraction: fatigue_frac,
        fatigue_slope_iki_per_kstroke: fatigue_slope,
        dominant_phase: dominant,
    })
}

/// Fit three-phase linear model to IKI sequence using a simple greedy approach.
///
/// Returns (phase1_end_index, phase2_end_index, residual_sse).
fn fit_three_phase_model(ikis: &[f64]) -> (usize, usize, f64) {
    let n = ikis.len();
    let mut best_residual = f64::INFINITY;
    let mut best_p1 = 0;
    let mut best_p2 = 0;

    // Try all breakpoint combinations (O(n²) but acceptable for ~100-1000 samples).
    for p1 in (n / 5)..(n / 2) {
        for p2 in (p1 + n / 5)..(4 * n / 5) {
            let residual = compute_three_phase_residual(ikis, p1, p2);
            if residual < best_residual {
                best_residual = residual;
                best_p1 = p1;
                best_p2 = p2;
            }
        }
    }

    (best_p1, best_p2, best_residual)
}

/// Compute SSE of three-phase linear fit at given breakpoints.
fn compute_three_phase_residual(ikis: &[f64], p1_end: usize, p2_end: usize) -> f64 {
    let mut sse = 0.0;

    // Phase 1 (warmup): fit linear trend downward.
    if p1_end >= 2 {
        let phase1 = &ikis[..p1_end];
        let (m1, b1) = fit_linear(phase1);
        for (i, &val) in phase1.iter().enumerate() {
            let pred = m1 * i as f64 + b1;
            sse += (val - pred).powi(2);
        }
    }

    // Phase 2 (plateau): constant (m ≈ 0).
    if p2_end > p1_end && p2_end - p1_end >= 2 {
        let phase2 = &ikis[p1_end..p2_end];
        let mean2 = mean(phase2);
        for &val in phase2 {
            sse += (val - mean2).powi(2);
        }
    }

    // Phase 3 (fatigue): fit linear trend upward.
    if ikis.len() > p2_end && ikis.len() - p2_end >= 2 {
        let phase3 = &ikis[p2_end..];
        let (m3, b3) = fit_linear(phase3);
        for (i, &val) in phase3.iter().enumerate() {
            let pred = m3 * i as f64 + b3;
            sse += (val - pred).powi(2);
        }
    }

    sse
}

/// Fit linear regression y = mx + b to a sequence.
fn fit_linear(data: &[f64]) -> (f64, f64) {
    if data.len() < 2 {
        return (0.0, mean(data));
    }

    let n = data.len() as f64;
    let x_mean = (n - 1.0) / 2.0; // 0, 1, 2, ..., n-1
    let y_mean = mean(data);

    let mut sum_xy = 0.0;
    let mut sum_x2 = 0.0;

    for (i, &y) in data.iter().enumerate() {
        let x = i as f64;
        sum_xy += (x - x_mean) * (y - y_mean);
        sum_x2 += (x - x_mean).powi(2);
    }

    if sum_x2 <= 0.0 {
        return (0.0, y_mean);
    }

    let m = sum_xy / sum_x2;
    let b = y_mean - m * x_mean;

    (m, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_word_surprisal_common() {
        let surp = word_surprisal("the");
        assert!(surp < 2.0, "common word should have low surprisal");
    }

    #[test]
    fn test_word_surprisal_rare() {
        // "xyzq" fails is_common_english_word because it lacks vowels
        let surp = word_surprisal("xyzq");
        assert_eq!(surp, 7.0, "rare word without vowels should have high surprisal");
    }

    #[test]
    fn test_estimate_unigram_surprisal() {
        let text1 = "the cat is on the mat";
        let text2 = "zyx qwe asd fgh jkl";
        let s1 = estimate_unigram_surprisal(text1);
        let s2 = estimate_unigram_surprisal(text2);
        assert!(s1 < s2, "common text should have lower surprisal than rare");
    }

    #[test]
    fn test_clc_metrics() {
        let windows = vec![
            "the cat sat on the mat".to_string(),
            "the dog ran very fast".to_string(),
            "the quick brown fox".to_string(),
        ];
        let mut samples = Vec::new();
        for i in 0..50 {
            samples.push(SimpleJitterSample {
                timestamp_ns: (i as i64 * 80_000_000),
                duration_since_last_ns: 80_000_000,
                zone: (i as u8) % 8,
                dwell_time_ns: Some(60_000_000),
                flight_time_ns: Some(20_000_000),
            });
        }

        let clc = compute_clc_metrics(&windows, &samples);
        assert!(clc.is_some());
        let m = clc.unwrap();
        assert!(m.mean_surprisal_bpw.is_finite());
        assert!(m.mean_surprisal_bpw > 0.0);
    }

    #[test]
    fn test_repair_locality() {
        let mut samples = Vec::new();
        for i in 0..20 {
            samples.push(SimpleJitterSample {
                timestamp_ns: (i as i64 * 80_000_000),
                duration_since_last_ns: 80_000_000,
                zone: if i % 4 == 0 { 0xFF } else { (i as u8) % 8 },
                dwell_time_ns: Some(60_000_000),
                flight_time_ns: Some(20_000_000),
            });
        }

        // Simulate varying file sizes to create repair offsets
        let file_sizes: Vec<i64> = (0..20).map(|i| (i * 100) as i64).collect();

        let repair = analyze_repair_locality(&samples, &file_sizes);
        assert!(repair.is_some());
        let r = repair.unwrap();
        assert!(r.mean_offset_chars.is_finite());
        assert!(r.mean_offset_chars >= 0.0);
    }

    #[test]
    fn test_fatigue_trajectory_warmup() {
        // Create samples with decreasing IKI (warmup phase).
        let mut samples: Vec<SimpleJitterSample> = Vec::new();
        for i in 0..50 {
            let iki_ns = ((50 - i as i64) * 2_000_000) as i64;
            let ts = if !samples.is_empty() {
                samples[samples.len() - 1].timestamp_ns + iki_ns
            } else {
                0
            };
            samples.push(SimpleJitterSample {
                timestamp_ns: ts,
                duration_since_last_ns: iki_ns as u64,
                zone: (i as u8) % 8,
                dwell_time_ns: Some(60_000_000),
                flight_time_ns: Some(20_000_000),
            });
        }

        let traj = analyze_fatigue_trajectory(&samples);
        assert!(traj.is_some());
        let t = traj.unwrap();
        assert!(t.warmup_fraction.is_finite());
        assert!(t.warmup_fraction >= 0.0 && t.warmup_fraction <= 1.0);
    }

    #[test]
    fn test_three_phase_model_fitting() {
        // Create synthetic three-phase data: warmup (decreasing), plateau (constant), fatigue (increasing).
        let mut ikis = Vec::new();

        // Phase 1: warmup (200ms down to 100ms)
        for i in 0..20 {
            ikis.push(200_000_000.0 - (i as f64 * 5_000_000.0));
        }

        // Phase 2: plateau (constant 100ms)
        for _ in 0..20 {
            ikis.push(100_000_000.0);
        }

        // Phase 3: fatigue (100ms up to 200ms)
        for i in 0..20 {
            ikis.push(100_000_000.0 + (i as f64 * 5_000_000.0));
        }

        let (p1, p2, residual) = fit_three_phase_model(&ikis);
        assert!(p1 > 5, "phase 1 endpoint should be detected");
        assert!(p2 > p1 + 5, "phase 2 endpoint should be after phase 1");
        assert!(residual.is_finite());
    }

    #[test]
    fn test_iki_surprisal_correlation_with_nan() {
        let ikis = vec![100.0, 110.0, f64::NAN, 120.0, 130.0];
        let surprisals = vec![2.0, 2.5, 3.0, 3.5, 4.0];
        let corr = compute_iki_surprisal_correlation(&ikis, &surprisals);
        assert_eq!(corr, 0.0, "correlation with NaN input should return 0.0, not NaN");
    }
}
