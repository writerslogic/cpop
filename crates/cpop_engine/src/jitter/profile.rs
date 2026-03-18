// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Typing profile analysis and plausibility checking.

use std::time::Duration;

use super::engine::TypingProfile;
use super::session::INTERVAL_BUCKET_SIZE_MS;

const NUM_INTERVAL_BUCKETS: i64 = super::session::NUM_INTERVAL_BUCKETS;

/// Number of histogram buckets per typing category.
const HISTOGRAM_BUCKET_COUNT: usize = 10;

/// Minimum hand alternation ratio for plausible human typing.
const MIN_HAND_ALTERNATION: f32 = 0.15;

/// Tolerance band used in quick-verify alerts (symmetric around 0.5).
const ALTERNATION_TOLERANCE: f32 = 0.85;

/// Maximum same-hand ratio; above this is implausible.
const MAX_SAME_HAND_RATIO: f64 = 0.30;

/// Minimum transitions before plausibility checks apply.
const MIN_TRANSITIONS_PLAUSIBILITY: u64 = 10;

/// Minimum total transitions before bucket analysis applies.
const MIN_TOTAL_BUCKET_ANALYSIS: u64 = 100;

/// Maximum fraction in a single bucket before flagging as robotic.
const MAX_BUCKET_CONCENTRATION: f64 = 0.80;

/// Minimum total transitions for concentration check.
const MIN_TRANSITIONS_VERIFICATION: u64 = 50;

/// Alert threshold: hand alternation below this is suspiciously low.
const ALTERNATION_ALERT_LOW: f32 = 0.25;

/// Alert threshold: hand alternation above this is suspiciously high.
const ALTERNATION_ALERT_HIGH: f32 = 0.75;

/// Weight for same-finger histogram in profile comparison.
const COMPARE_WEIGHT_SAME_FINGER: f64 = 0.3;
/// Weight for same-hand histogram in profile comparison.
const COMPARE_WEIGHT_SAME_HAND: f64 = 0.3;
/// Weight for alternating histogram in profile comparison.
const COMPARE_WEIGHT_ALTERNATING: f64 = 0.3;
/// Weight for hand alternation scalar in profile comparison.
const COMPARE_WEIGHT_HAND_ALT: f64 = 0.1;

/// Map a keystroke interval duration to a histogram bucket index (0..9).
pub fn interval_to_bucket(duration: Duration) -> u8 {
    let ms = duration.as_millis().min(i64::MAX as u128) as i64;
    let mut bucket = ms / INTERVAL_BUCKET_SIZE_MS;
    if bucket >= NUM_INTERVAL_BUCKETS {
        bucket = NUM_INTERVAL_BUCKETS - 1;
    }
    if bucket < 0 {
        bucket = 0;
    }
    bucket as u8
}

/// Compute a weighted similarity score (0.0..1.0) between two typing profiles.
pub fn compare_profiles(a: TypingProfile, b: TypingProfile) -> f64 {
    if a.total_transitions == 0 || b.total_transitions == 0 {
        return 0.0;
    }

    let same_finger = histogram_cosine_similarity(&a.same_finger_hist, &b.same_finger_hist);
    let same_hand = histogram_cosine_similarity(&a.same_hand_hist, &b.same_hand_hist);
    let alternating = histogram_cosine_similarity(&a.alternating_hist, &b.alternating_hist);

    let hand_alt_diff = (a.hand_alternation - b.hand_alternation).abs() as f64;
    let hand_alt_sim = if hand_alt_diff.is_nan() {
        0.0
    } else {
        1.0 - hand_alt_diff
    };

    COMPARE_WEIGHT_SAME_FINGER * same_finger
        + COMPARE_WEIGHT_SAME_HAND * same_hand
        + COMPARE_WEIGHT_ALTERNATING * alternating
        + COMPARE_WEIGHT_HAND_ALT * hand_alt_sim
}

fn histogram_cosine_similarity(a: &[u32; 10], b: &[u32; 10]) -> f64 {
    let fa: Vec<f64> = a.iter().map(|&v| v as f64).collect();
    let fb: Vec<f64> = b.iter().map(|&v| v as f64).collect();
    crate::analysis::stats::cosine_similarity(&fa, &fb)
}

/// Return true if the typing profile falls within human-plausible bounds.
pub fn is_human_plausible(profile: TypingProfile) -> bool {
    if profile.total_transitions < MIN_TRANSITIONS_PLAUSIBILITY {
        return true;
    }

    if profile.hand_alternation < MIN_HAND_ALTERNATION
        || profile.hand_alternation > ALTERNATION_TOLERANCE
    {
        return false;
    }

    let mut same_finger_total = 0u64;
    let mut same_hand_total = 0u64;
    let mut alternating_total = 0u64;
    for i in 0..HISTOGRAM_BUCKET_COUNT {
        same_finger_total += profile.same_finger_hist[i] as u64;
        same_hand_total += profile.same_hand_hist[i] as u64;
        alternating_total += profile.alternating_hist[i] as u64;
    }

    let total = same_finger_total + same_hand_total + alternating_total;
    if total == 0 {
        return true;
    }

    let same_finger_ratio = same_finger_total as f64 / total as f64;
    if same_finger_ratio > MAX_SAME_HAND_RATIO {
        return false;
    }

    let mut non_zero = 0;
    for i in 0..HISTOGRAM_BUCKET_COUNT {
        if profile.same_finger_hist[i] > 0
            || profile.same_hand_hist[i] > 0
            || profile.alternating_hist[i] > 0
        {
            non_zero += 1;
        }
    }
    if non_zero < 3 && total > MIN_TOTAL_BUCKET_ANALYSIS {
        return false;
    }

    let max_bucket_pct = max_histogram_concentration(&profile);
    if max_bucket_pct > MAX_BUCKET_CONCENTRATION && total > MIN_TRANSITIONS_VERIFICATION {
        return false;
    }

    true
}

fn max_histogram_concentration(profile: &TypingProfile) -> f64 {
    let mut total = 0u64;
    let mut max_bucket = 0u64;
    for i in 0..HISTOGRAM_BUCKET_COUNT {
        let bucket_total = profile.same_finger_hist[i] as u64
            + profile.same_hand_hist[i] as u64
            + profile.alternating_hist[i] as u64;
        total += bucket_total;
        if bucket_total > max_bucket {
            max_bucket = bucket_total;
        }
    }
    if total == 0 {
        return 0.0;
    }
    max_bucket as f64 / total as f64
}

/// Compute Euclidean distance between two normalized typing profiles.
pub fn profile_distance(a: TypingProfile, b: TypingProfile) -> f64 {
    let a_norm = normalize_histograms(&a);
    let b_norm = normalize_histograms(&b);

    let mut sum = 0.0;
    for i in 0..HISTOGRAM_BUCKET_COUNT {
        let diff = a_norm.same_finger[i] - b_norm.same_finger[i];
        sum += diff * diff;
    }
    for i in 0..HISTOGRAM_BUCKET_COUNT {
        let diff = a_norm.same_hand[i] - b_norm.same_hand[i];
        sum += diff * diff;
    }
    for i in 0..HISTOGRAM_BUCKET_COUNT {
        let diff = a_norm.alternating[i] - b_norm.alternating[i];
        sum += diff * diff;
    }

    let diff = a.hand_alternation as f64 - b.hand_alternation as f64;
    if !diff.is_nan() {
        sum += diff * diff;
    }

    sum.sqrt()
}

struct NormalizedProfile {
    same_finger: [f64; HISTOGRAM_BUCKET_COUNT],
    same_hand: [f64; HISTOGRAM_BUCKET_COUNT],
    alternating: [f64; HISTOGRAM_BUCKET_COUNT],
}

fn normalize_histograms(profile: &TypingProfile) -> NormalizedProfile {
    let mut same_finger_total = 0u64;
    let mut same_hand_total = 0u64;
    let mut alternating_total = 0u64;
    for i in 0..HISTOGRAM_BUCKET_COUNT {
        same_finger_total += profile.same_finger_hist[i] as u64;
        same_hand_total += profile.same_hand_hist[i] as u64;
        alternating_total += profile.alternating_hist[i] as u64;
    }

    let mut out = NormalizedProfile {
        same_finger: [0.0; HISTOGRAM_BUCKET_COUNT],
        same_hand: [0.0; HISTOGRAM_BUCKET_COUNT],
        alternating: [0.0; HISTOGRAM_BUCKET_COUNT],
    };

    for i in 0..HISTOGRAM_BUCKET_COUNT {
        if same_finger_total > 0 {
            out.same_finger[i] = profile.same_finger_hist[i] as f64 / same_finger_total as f64;
        }
        if same_hand_total > 0 {
            out.same_hand[i] = profile.same_hand_hist[i] as f64 / same_hand_total as f64;
        }
        if alternating_total > 0 {
            out.alternating[i] = profile.alternating_hist[i] as f64 / alternating_total as f64;
        }
    }

    out
}

/// Run quick plausibility checks and return a list of warning strings.
pub fn quick_verify_profile(profile: TypingProfile) -> Vec<String> {
    let mut issues = Vec::new();
    if !is_human_plausible(profile) {
        issues.push("profile fails human plausibility check".to_string());
    }
    if profile.total_transitions > MIN_TRANSITIONS_VERIFICATION {
        if profile.hand_alternation < ALTERNATION_ALERT_LOW {
            issues.push("hand alternation too low (< 25%)".to_string());
        }
        if profile.hand_alternation > ALTERNATION_ALERT_HIGH {
            issues.push("hand alternation too high (> 75%)".to_string());
        }
    }

    let bucket0 = profile.same_finger_hist[0] as u64
        + profile.same_hand_hist[0] as u64
        + profile.alternating_hist[0] as u64;
    if profile.total_transitions > 0 && bucket0 == profile.total_transitions {
        issues.push("all transitions in fastest bucket (robotic timing)".to_string());
    }

    issues
}
