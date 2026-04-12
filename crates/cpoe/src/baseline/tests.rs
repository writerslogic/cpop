// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::*;
use authorproof_protocol::baseline::{
    BaselineDigest, ConfidenceTier, SessionBehavioralSummary, StreamingStats,
};
use streaming::StreamingStatsExt;

fn make_summary(
    keystroke_count: u64,
    iki_cv: f64,
    hurst: f64,
    pause_freq: f64,
) -> SessionBehavioralSummary {
    SessionBehavioralSummary {
        iki_histogram: [0.1, 0.2, 0.15, 0.1, 0.1, 0.15, 0.1, 0.05, 0.05],
        iki_cv,
        hurst,
        pause_frequency: pause_freq,
        duration_secs: 600,
        keystroke_count,
    }
}

// ── compute_initial_digest ──────────────────────────────────────────

#[test]
fn initial_digest_has_zero_sessions() {
    let fp = vec![0xAA; 32];
    let d = compute_initial_digest(fp.clone());
    assert_eq!(d.version, 1);
    assert_eq!(d.session_count, 0);
    assert_eq!(d.total_keystrokes, 0);
    assert_eq!(d.identity_fingerprint, fp);
    assert_eq!(d.confidence_tier, ConfidenceTier::PopulationReference);
    assert_eq!(d.session_merkle_root, vec![0u8; 32]);
}

#[test]
fn initial_digest_histogram_is_zeroed() {
    let d = compute_initial_digest(vec![1, 2, 3]);
    for bin in &d.aggregate_iki_histogram {
        assert_eq!(*bin, 0.0);
    }
}

#[test]
fn initial_digest_stats_are_empty() {
    let d = compute_initial_digest(vec![]);
    assert_eq!(d.iki_stats.count, 0);
    assert_eq!(d.cv_stats.count, 0);
    assert_eq!(d.hurst_stats.count, 0);
    assert_eq!(d.pause_stats.count, 0);
}

#[test]
fn initial_digest_computed_at_is_recent() {
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let d = compute_initial_digest(vec![]);
    assert!(d.computed_at >= before);
    assert!(d.computed_at <= before + 2);
}

// ── update_digest ───────────────────────────────────────────────────

#[test]
fn single_update_increments_session_count() {
    let mut d = compute_initial_digest(vec![]);
    let s = make_summary(100, 0.5, 0.7, 3.0);
    update_digest_in_place(&mut d, &s);
    assert_eq!(d.session_count, 1);
    assert_eq!(d.total_keystrokes, 100);
}

#[test]
fn multiple_updates_accumulate_keystrokes() {
    let mut d = compute_initial_digest(vec![]);
    let s1 = make_summary(100, 0.5, 0.7, 3.0);
    let s2 = make_summary(200, 0.5, 0.7, 3.0);
    let s3 = make_summary(50, 0.5, 0.7, 3.0);
    update_digest_in_place(&mut d, &s1);
    update_digest_in_place(&mut d, &s2);
    update_digest_in_place(&mut d, &s3);
    assert_eq!(d.session_count, 3);
    assert_eq!(d.total_keystrokes, 350);
}

#[test]
fn update_advances_confidence_tier() {
    let mut d = compute_initial_digest(vec![]);
    let s = make_summary(100, 0.5, 0.7, 3.0);

    for _ in 0..5 {
        update_digest_in_place(&mut d, &s);
    }
    assert_eq!(d.confidence_tier, ConfidenceTier::Emerging);

    for _ in 0..5 {
        update_digest_in_place(&mut d, &s);
    }
    assert_eq!(d.confidence_tier, ConfidenceTier::Established);

    for _ in 0..10 {
        update_digest_in_place(&mut d, &s);
    }
    assert_eq!(d.confidence_tier, ConfidenceTier::Mature);
}

#[test]
fn update_sets_histogram_to_session_on_first_update() {
    let mut d = compute_initial_digest(vec![]);
    let s = make_summary(100, 0.5, 0.7, 3.0);
    update_digest_in_place(&mut d, &s);
    for i in 0..9 {
        assert!(
            (d.aggregate_iki_histogram[i] - s.iki_histogram[i]).abs() < 1e-10,
            "bin {} mismatch: {} vs {}",
            i,
            d.aggregate_iki_histogram[i],
            s.iki_histogram[i],
        );
    }
}

#[test]
fn update_averages_histogram_over_sessions() {
    let mut d = compute_initial_digest(vec![]);
    let s1 = SessionBehavioralSummary {
        iki_histogram: [1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        ..make_summary(100, 0.5, 0.7, 3.0)
    };
    let s2 = SessionBehavioralSummary {
        iki_histogram: [0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        ..make_summary(100, 0.5, 0.7, 3.0)
    };
    update_digest_in_place(&mut d, &s1);
    update_digest_in_place(&mut d, &s2);
    assert!((d.aggregate_iki_histogram[0] - 0.5).abs() < 1e-10);
    assert!((d.aggregate_iki_histogram[1] - 0.5).abs() < 1e-10);
}

#[test]
fn update_tracks_iki_stats() {
    let mut d = compute_initial_digest(vec![]);
    let s = make_summary(100, 0.5, 0.7, 3.0);
    update_digest_in_place(&mut d, &s);
    assert_eq!(d.iki_stats.count, 1);
    assert!(d.iki_stats.mean > 0.0, "IKI mean should be positive");
}

// ── StreamingStats (Welford's) ──────────────────────────────────────

#[test]
fn streaming_stats_empty() {
    let s = StreamingStats::new_empty();
    assert_eq!(s.count, 0);
    assert_eq!(s.mean, 0.0);
    assert_eq!(s.m2, 0.0);
    assert_eq!(s.variance(), 0.0);
    assert_eq!(s.std_dev(), 0.0);
}

#[test]
fn streaming_stats_single_value() {
    let mut s = StreamingStats::new_empty();
    s.update(42.0);
    assert_eq!(s.count, 1);
    assert!((s.mean - 42.0).abs() < 1e-10);
    assert_eq!(s.min, 42.0);
    assert_eq!(s.max, 42.0);
    // Variance undefined for n=1, returns 0
    assert_eq!(s.variance(), 0.0);
}

#[test]
fn streaming_stats_known_sequence() {
    // Values: 2, 4, 4, 4, 5, 5, 7, 9 → mean=5.0, var=4.571..., std≈2.138
    let mut s = StreamingStats::new_empty();
    for v in [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0] {
        s.update(v);
    }
    assert_eq!(s.count, 8);
    assert!((s.mean - 5.0).abs() < 1e-10);
    assert_eq!(s.min, 2.0);
    assert_eq!(s.max, 9.0);
    // Sample variance = 32/7 ≈ 4.5714
    assert!((s.variance() - 32.0 / 7.0).abs() < 1e-10);
    assert!((s.std_dev() - (32.0_f64 / 7.0).sqrt()).abs() < 1e-10);
}

#[test]
fn streaming_stats_min_max_tracked() {
    let mut s = StreamingStats::new_empty();
    s.update(5.0);
    s.update(1.0);
    s.update(9.0);
    s.update(3.0);
    assert_eq!(s.min, 1.0);
    assert_eq!(s.max, 9.0);
}

// ── verify_against_baseline ─────────────────────────────────────────

fn build_trained_digest(sessions: u64) -> BaselineDigest {
    let mut d = compute_initial_digest(vec![0xAA; 32]);
    let s = make_summary(500, 0.45, 0.72, 3.5);
    for _ in 0..sessions {
        update_digest_in_place(&mut d, &s);
    }
    d
}

#[test]
fn verify_identical_session_scores_high() {
    let d = build_trained_digest(10);
    let s = make_summary(500, 0.45, 0.72, 3.5);
    let score = verify_against_baseline(&d, &s);
    assert!(
        score > 0.95,
        "Identical session should score > 0.95, got {score}"
    );
}

#[test]
fn verify_different_session_scores_lower() {
    let d = build_trained_digest(10);
    // Wildly different behavioral metrics
    let s = SessionBehavioralSummary {
        iki_histogram: [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0],
        iki_cv: 1.5,
        hurst: 0.1,
        pause_frequency: 20.0,
        duration_secs: 600,
        keystroke_count: 500,
    };
    let score = verify_against_baseline(&d, &s);
    let identical_score = verify_against_baseline(&d, &make_summary(500, 0.45, 0.72, 3.5));
    assert!(
        score < identical_score,
        "Different session ({score}) should score lower than identical ({identical_score})"
    );
}

#[test]
fn verify_score_bounded_zero_to_one() {
    let d = build_trained_digest(10);
    let s = make_summary(500, 0.45, 0.72, 3.5);
    let score = verify_against_baseline(&d, &s);
    assert!((0.0..=1.0).contains(&score), "Score {score} out of [0,1]");
}

#[test]
fn verify_with_few_sessions_is_lenient() {
    // With count < 2, gaussian_similarity returns 1.0
    let mut d = compute_initial_digest(vec![]);
    let s = make_summary(100, 0.5, 0.7, 3.0);
    update_digest_in_place(&mut d, &s);

    // Even a very different session should score high when baseline is thin
    let different = SessionBehavioralSummary {
        iki_histogram: [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0],
        iki_cv: 2.0,
        hurst: 0.1,
        pause_frequency: 50.0,
        duration_secs: 600,
        keystroke_count: 100,
    };
    let score = verify_against_baseline(&d, &different);
    // Gaussian components all return 1.0 (count=1 < 2), only Bhattacharyya differs
    assert!(score > 0.5, "Thin baseline should be lenient, got {score}");
}

// ── Roundtrip: create → update → verify ─────────────────────────────

#[test]
fn full_roundtrip_enrollment_to_verification() {
    let fp = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let mut d = compute_initial_digest(fp.clone());
    assert_eq!(d.confidence_tier, ConfidenceTier::PopulationReference);

    let session = make_summary(1000, 0.45, 0.72, 3.5);

    // Enroll 10 sessions
    for _ in 0..10 {
        update_digest_in_place(&mut d, &session);
    }
    assert_eq!(d.session_count, 10);
    assert_eq!(d.total_keystrokes, 10_000);
    assert_eq!(d.confidence_tier, ConfidenceTier::Established);
    assert_eq!(d.identity_fingerprint, fp);

    // Verify same-author session
    let score = verify_against_baseline(&d, &session);
    assert!(score > 0.95, "Same-author roundtrip score: {score}");
}

#[test]
fn roundtrip_with_varying_sessions() {
    let mut d = compute_initial_digest(vec![]);

    // Train with slightly varying sessions
    let sessions = [
        make_summary(400, 0.40, 0.70, 3.0),
        make_summary(500, 0.45, 0.72, 3.5),
        make_summary(450, 0.43, 0.71, 3.2),
        make_summary(480, 0.44, 0.73, 3.4),
        make_summary(520, 0.46, 0.69, 3.6),
    ];
    for s in &sessions {
        update_digest_in_place(&mut d, s);
    }

    // Verify with a session close to the mean
    let probe = make_summary(470, 0.44, 0.71, 3.3);
    let score = verify_against_baseline(&d, &probe);
    assert!(
        score > 0.8,
        "Near-mean probe should score well, got {score}"
    );
}
