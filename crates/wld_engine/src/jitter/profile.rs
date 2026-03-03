// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Typing profile analysis and plausibility checking.

use std::time::Duration;

use super::engine::TypingProfile;
use super::session::INTERVAL_BUCKET_SIZE_MS;

const NUM_INTERVAL_BUCKETS: i64 = super::session::NUM_INTERVAL_BUCKETS;

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

    0.3 * same_finger + 0.3 * same_hand + 0.3 * alternating + 0.1 * hand_alt_sim
}

fn histogram_cosine_similarity(a: &[u32; 10], b: &[u32; 10]) -> f64 {
    let mut dot = 0.0;
    let mut norm_a = 0.0;
    let mut norm_b = 0.0;
    for i in 0..10 {
        let fa = a[i] as f64;
        let fb = b[i] as f64;
        dot += fa * fb;
        norm_a += fa * fa;
        norm_b += fb * fb;
    }
    if norm_a == 0.0 || norm_b == 0.0 {
        return 0.0;
    }
    dot / (sqrt(norm_a) * sqrt(norm_b))
}

fn sqrt(x: f64) -> f64 {
    if x <= 0.0 {
        return 0.0;
    }
    x.sqrt()
}

pub fn is_human_plausible(profile: TypingProfile) -> bool {
    if profile.total_transitions < 10 {
        return true;
    }

    if profile.hand_alternation < 0.15 || profile.hand_alternation > 0.85 {
        return false;
    }

    let mut same_finger_total = 0u64;
    let mut same_hand_total = 0u64;
    let mut alternating_total = 0u64;
    for i in 0..10 {
        same_finger_total += profile.same_finger_hist[i] as u64;
        same_hand_total += profile.same_hand_hist[i] as u64;
        alternating_total += profile.alternating_hist[i] as u64;
    }

    let total = same_finger_total + same_hand_total + alternating_total;
    if total == 0 {
        return true;
    }

    let same_finger_ratio = same_finger_total as f64 / total as f64;
    if same_finger_ratio > 0.30 {
        return false;
    }

    let mut non_zero = 0;
    for i in 0..10 {
        if profile.same_finger_hist[i] > 0
            || profile.same_hand_hist[i] > 0
            || profile.alternating_hist[i] > 0
        {
            non_zero += 1;
        }
    }
    if non_zero < 3 && total > 100 {
        return false;
    }

    let max_bucket_pct = max_histogram_concentration(&profile);
    if max_bucket_pct > 0.80 && total > 50 {
        return false;
    }

    true
}

fn max_histogram_concentration(profile: &TypingProfile) -> f64 {
    let mut total = 0u64;
    let mut max_bucket = 0u64;
    for i in 0..10 {
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

pub fn profile_distance(a: TypingProfile, b: TypingProfile) -> f64 {
    let a_norm = normalize_histograms(&a);
    let b_norm = normalize_histograms(&b);

    let mut sum = 0.0;
    for i in 0..10 {
        let diff = a_norm.same_finger[i] - b_norm.same_finger[i];
        sum += diff * diff;
    }
    for i in 0..10 {
        let diff = a_norm.same_hand[i] - b_norm.same_hand[i];
        sum += diff * diff;
    }
    for i in 0..10 {
        let diff = a_norm.alternating[i] - b_norm.alternating[i];
        sum += diff * diff;
    }

    let diff = a.hand_alternation as f64 - b.hand_alternation as f64;
    if !diff.is_nan() {
        sum += diff * diff;
    }

    sqrt(sum)
}

struct NormalizedProfile {
    same_finger: [f64; 10],
    same_hand: [f64; 10],
    alternating: [f64; 10],
}

fn normalize_histograms(profile: &TypingProfile) -> NormalizedProfile {
    let mut same_finger_total = 0u64;
    let mut same_hand_total = 0u64;
    let mut alternating_total = 0u64;
    for i in 0..10 {
        same_finger_total += profile.same_finger_hist[i] as u64;
        same_hand_total += profile.same_hand_hist[i] as u64;
        alternating_total += profile.alternating_hist[i] as u64;
    }

    let mut out = NormalizedProfile {
        same_finger: [0.0; 10],
        same_hand: [0.0; 10],
        alternating: [0.0; 10],
    };

    for i in 0..10 {
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

pub fn quick_verify_profile(profile: TypingProfile) -> Vec<String> {
    let mut issues = Vec::new();
    if !is_human_plausible(profile) {
        issues.push("profile fails human plausibility check".to_string());
    }
    if profile.total_transitions > 50 {
        if profile.hand_alternation < 0.25 {
            issues.push("hand alternation too low (< 25%)".to_string());
        }
        if profile.hand_alternation > 0.75 {
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
