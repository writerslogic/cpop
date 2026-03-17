// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::*;
use crate::jitter::SimpleJitterSample;

// --- biological ---

#[test]
fn biological_cadence_empty_samples() {
    let score = BiologicalCadence::analyze(&[]);
    assert_eq!(score, 0.0, "Empty samples should yield 0.0");
}

#[test]
fn biological_cadence_single_sample() {
    let samples = vec![SimpleJitterSample {
        timestamp_ns: 1000,
        duration_since_last_ns: 100_000,
        zone: 1,
    }];
    let score = BiologicalCadence::analyze(&samples);
    assert_eq!(score, 0.0, "Single sample should yield 0.0 (need >= 2)");
}

#[test]
fn biological_cadence_steady_typing() {
    // Uniform intervals → low CV → score near 1.0
    let samples: Vec<SimpleJitterSample> = (0..20)
        .map(|i| SimpleJitterSample {
            timestamp_ns: i * 100_000,
            duration_since_last_ns: 100_000,
            zone: 1,
        })
        .collect();
    let score = BiologicalCadence::analyze(&samples);
    assert!(
        score > 0.95,
        "Steady cadence should score near 1.0, got {score}"
    );
}

#[test]
fn biological_cadence_erratic_typing() {
    // Wildly varying intervals → high CV → score near 0.0
    let intervals = [1_000u64, 5_000_000, 200, 9_999_999, 500, 8_000_000];
    let samples: Vec<SimpleJitterSample> = intervals
        .iter()
        .enumerate()
        .map(|(i, &dur)| SimpleJitterSample {
            timestamp_ns: i as i64 * 1_000_000,
            duration_since_last_ns: dur,
            zone: 2,
        })
        .collect();
    let score = BiologicalCadence::analyze(&samples);
    assert!(
        score < 0.5,
        "Erratic cadence should score well below 1.0, got {score}"
    );
}

#[test]
fn biological_cadence_zero_durations_ignored() {
    // All-zero durations should return 0.0 (no valid data)
    let samples = vec![
        SimpleJitterSample {
            timestamp_ns: 0,
            duration_since_last_ns: 0,
            zone: 0,
        },
        SimpleJitterSample {
            timestamp_ns: 100,
            duration_since_last_ns: 0,
            zone: 0,
        },
    ];
    let score = BiologicalCadence::analyze(&samples);
    assert_eq!(score, 0.0, "All-zero durations should yield 0.0");
}

// --- clock ---

#[test]
fn clock_skew_returns_nonzero() {
    let skew = ClockSkew::measure();
    // On real hardware (x86_64 or aarch64) this should be nonzero.
    // On unsupported arches the stub returns 0.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
    assert_ne!(skew, 0, "Clock skew should be nonzero on real hardware");

    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
    assert_eq!(skew, 0);
}

// --- entanglement ---

#[test]
fn entanglement_seed_deterministic() {
    let content_hash = [0xABu8; 32];
    let ctx = PhysicalContext::capture(&[]);
    let seed1 = Entanglement::create_seed(content_hash, &ctx);
    let seed2 = Entanglement::create_seed(content_hash, &ctx);
    assert_eq!(seed1, seed2, "Same inputs must produce the same seed");
}

#[test]
fn entanglement_seed_varies_with_content() {
    let ctx = PhysicalContext::capture(&[]);
    let seed_a = Entanglement::create_seed([0x01u8; 32], &ctx);
    let seed_b = Entanglement::create_seed([0x02u8; 32], &ctx);
    assert_ne!(
        seed_a, seed_b,
        "Different content hashes must produce different seeds"
    );
}

// --- environment ---

#[test]
fn ambient_entropy_hash_nonzero() {
    let entropy = AmbientSensing::capture();
    assert_ne!(
        entropy.hash, [0u8; 32],
        "Ambient entropy hash should not be all zeros"
    );
}

// --- synthesis ---

#[test]
fn physical_context_capture_populates_fields() {
    let samples: Vec<SimpleJitterSample> = (0..5)
        .map(|i| SimpleJitterSample {
            timestamp_ns: i * 50_000,
            duration_since_last_ns: 50_000,
            zone: 1,
        })
        .collect();
    let ctx = PhysicalContext::capture(&samples);

    assert_ne!(
        ctx.combined_hash, [0u8; 32],
        "Combined hash must not be all zeros"
    );
    assert_ne!(
        ctx.silicon_puf, [0u8; 32],
        "PUF fingerprint must not be all zeros"
    );
    assert_ne!(
        ctx.ambient_hash, [0u8; 32],
        "Ambient hash must not be all zeros"
    );
}

#[test]
fn physical_context_different_samples_yield_different_hash() {
    let samples_a: Vec<SimpleJitterSample> = (0..5)
        .map(|i| SimpleJitterSample {
            timestamp_ns: i * 50_000,
            duration_since_last_ns: 50_000,
            zone: 1,
        })
        .collect();
    let samples_b: Vec<SimpleJitterSample> = (0..5)
        .map(|i| SimpleJitterSample {
            timestamp_ns: i * 50_000,
            duration_since_last_ns: 999_999,
            zone: 3,
        })
        .collect();

    let ctx_a = PhysicalContext::capture(&samples_a);
    let ctx_b = PhysicalContext::capture(&samples_b);

    assert_ne!(
        ctx_a.combined_hash, ctx_b.combined_hash,
        "Different biological samples should produce different combined hashes"
    );
}
