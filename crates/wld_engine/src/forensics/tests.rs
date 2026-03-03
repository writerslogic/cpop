// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Tests for the forensics module.

use super::*;
use std::collections::HashMap;

fn create_test_events(count: usize) -> Vec<EventData> {
    (0..count)
        .map(|i| EventData {
            id: i as i64,
            timestamp_ns: i as i64 * 1_000_000_000,
            file_size: 100 + i as i64 * 10,
            size_delta: 10,
            file_path: "/test/file.txt".to_string(),
        })
        .collect()
}

fn create_test_regions() -> HashMap<i64, Vec<RegionData>> {
    let mut regions = HashMap::new();
    for i in 0..10 {
        regions.insert(
            i,
            vec![RegionData {
                start_pct: i as f32 / 10.0,
                end_pct: (i + 1) as f32 / 10.0,
                delta_sign: if i % 3 == 0 { -1 } else { 1 },
                byte_count: 10,
            }],
        );
    }
    regions
}

#[test]
fn test_monotonic_append_ratio() {
    let regions = vec![
        RegionData {
            start_pct: 0.96,
            end_pct: 0.98,
            delta_sign: 1,
            byte_count: 10,
        },
        RegionData {
            start_pct: 0.50,
            end_pct: 0.55,
            delta_sign: 1,
            byte_count: 10,
        },
        RegionData {
            start_pct: 0.97,
            end_pct: 0.99,
            delta_sign: 1,
            byte_count: 10,
        },
    ];

    let ratio = monotonic_append_ratio(&regions, 0.95);
    assert!((ratio - 0.666).abs() < 0.01);
}

#[test]
fn test_edit_entropy() {
    let regions_concentrated = vec![
        RegionData {
            start_pct: 0.5,
            end_pct: 0.51,
            delta_sign: 1,
            byte_count: 10,
        },
        RegionData {
            start_pct: 0.51,
            end_pct: 0.52,
            delta_sign: 1,
            byte_count: 10,
        },
    ];
    let entropy_low = edit_entropy(&regions_concentrated, 20);
    assert!(entropy_low < 0.1);

    let regions_spread: Vec<_> = (0..20)
        .map(|i| RegionData {
            start_pct: i as f32 / 20.0,
            end_pct: (i + 1) as f32 / 20.0,
            delta_sign: 1,
            byte_count: 10,
        })
        .collect();
    let entropy_high = edit_entropy(&regions_spread, 20);
    assert!(entropy_high > 4.0); // Max is log2(20) ~ 4.32
}

#[test]
fn test_positive_negative_ratio() {
    let regions = vec![
        RegionData {
            start_pct: 0.1,
            end_pct: 0.2,
            delta_sign: 1,
            byte_count: 10,
        },
        RegionData {
            start_pct: 0.2,
            end_pct: 0.3,
            delta_sign: 1,
            byte_count: 10,
        },
        RegionData {
            start_pct: 0.3,
            end_pct: 0.4,
            delta_sign: -1,
            byte_count: 5,
        },
        RegionData {
            start_pct: 0.4,
            end_pct: 0.5,
            delta_sign: 0,
            byte_count: 10,
        },
    ];

    let ratio = positive_negative_ratio(&regions);
    assert!((ratio - 0.666).abs() < 0.01);
}

#[test]
fn test_deletion_clustering() {
    let regions_clustered = vec![
        RegionData {
            start_pct: 0.50,
            end_pct: 0.51,
            delta_sign: -1,
            byte_count: 5,
        },
        RegionData {
            start_pct: 0.51,
            end_pct: 0.52,
            delta_sign: -1,
            byte_count: 5,
        },
        RegionData {
            start_pct: 0.52,
            end_pct: 0.53,
            delta_sign: -1,
            byte_count: 5,
        },
    ];
    let coef_clustered = deletion_clustering_coef(&regions_clustered);
    assert!(coef_clustered < 0.5);

    let regions_scattered = vec![
        RegionData {
            start_pct: 0.1,
            end_pct: 0.11,
            delta_sign: -1,
            byte_count: 5,
        },
        RegionData {
            start_pct: 0.5,
            end_pct: 0.51,
            delta_sign: -1,
            byte_count: 5,
        },
        RegionData {
            start_pct: 0.9,
            end_pct: 0.91,
            delta_sign: -1,
            byte_count: 5,
        },
    ];
    let coef_scattered = deletion_clustering_coef(&regions_scattered);
    assert!(coef_scattered > coef_clustered);
}

#[test]
fn test_cadence_analysis() {
    use crate::jitter::SimpleJitterSample;

    let robotic_samples: Vec<_> = (0..50)
        .map(|i| SimpleJitterSample {
            timestamp_ns: i as i64 * 100_000_000,
            duration_since_last_ns: 100_000_000,
            zone: 0,
        })
        .collect();

    let cadence = analyze_cadence(&robotic_samples);
    assert!(cadence.is_robotic);
    assert!(cadence.coefficient_of_variation < ROBOTIC_CV_THRESHOLD);

    let human_samples: Vec<_> = (0..50)
        .map(|i| {
            let variation = ((i * 17) % 100) as i64 * 5_000_000;
            SimpleJitterSample {
                timestamp_ns: i as i64 * 150_000_000 + variation,
                duration_since_last_ns: 150_000_000 + variation as u64,
                zone: 0,
            }
        })
        .collect();

    let cadence_human = analyze_cadence(&human_samples);
    assert!(!cadence_human.is_robotic);
}

#[test]
fn test_compute_primary_metrics() {
    let events = create_test_events(10);
    let regions = create_test_regions();

    let metrics = compute_primary_metrics(&events, &regions).unwrap();

    assert!(metrics.monotonic_append_ratio >= 0.0 && metrics.monotonic_append_ratio <= 1.0);
    assert!(metrics.edit_entropy >= 0.0);
    assert!(metrics.median_interval >= 0.0);
    assert!(metrics.positive_negative_ratio >= 0.0 && metrics.positive_negative_ratio <= 1.0);
}

#[test]
fn test_insufficient_data() {
    let events = create_test_events(2);
    let regions = HashMap::new();

    let result = compute_primary_metrics(&events, &regions);
    assert!(matches!(result, Err(ForensicsError::InsufficientData)));
}

#[test]
fn test_session_detection() {
    let mut events = create_test_events(10);
    events[5].timestamp_ns = events[4].timestamp_ns + 3_600_000_000_000; // 1 hour gap

    let sessions = detect_sessions(&events, 1800.0);
    assert_eq!(sessions.len(), 2);
}

#[test]
fn test_correlation() {
    let correlator = ContentKeystrokeCorrelator::new();

    let input_consistent = CorrelationInput {
        document_length: 1000,
        total_keystrokes: 1200,
        detected_paste_chars: 0,
        detected_paste_count: 0,
        autocomplete_chars: 0,
        suspicious_bursts: 0,
        actual_edit_ratio: None,
    };

    let result = correlator.analyze(&input_consistent);
    assert_eq!(result.status, CorrelationStatus::Consistent);

    let input_suspicious = CorrelationInput {
        document_length: 5000,
        total_keystrokes: 1000,
        detected_paste_chars: 0,
        detected_paste_count: 0,
        autocomplete_chars: 0,
        suspicious_bursts: 5,
        actual_edit_ratio: None,
    };

    let result = correlator.analyze(&input_suspicious);
    assert!(matches!(
        result.status,
        CorrelationStatus::Suspicious | CorrelationStatus::Inconsistent
    ));
}

#[test]
fn test_profile_comparison() {
    let profile_a = AuthorshipProfile {
        metrics: PrimaryMetrics {
            monotonic_append_ratio: 0.5,
            edit_entropy: 2.5,
            median_interval: 3.0,
            positive_negative_ratio: 0.7,
            deletion_clustering: 0.4,
        },
        ..Default::default()
    };

    let profile_b = AuthorshipProfile {
        metrics: PrimaryMetrics {
            monotonic_append_ratio: 0.55,
            edit_entropy: 2.6,
            median_interval: 3.2,
            positive_negative_ratio: 0.72,
            deletion_clustering: 0.45,
        },
        ..Default::default()
    };

    let comparison = compare_profiles(&profile_a, &profile_b);
    assert!(comparison.is_consistent);
    assert!(comparison.similarity_score > 0.6);
}

#[test]
fn test_assessment_score() {
    let good_primary = PrimaryMetrics {
        monotonic_append_ratio: 0.4,
        edit_entropy: 3.0,
        median_interval: 5.0,
        positive_negative_ratio: 0.7,
        deletion_clustering: 0.5,
    };

    let good_cadence = CadenceMetrics {
        coefficient_of_variation: 0.4,
        is_robotic: false,
        ..Default::default()
    };

    let score = calculate_assessment_score(&good_primary, &good_cadence, 0, 100, 0.0);
    assert!(score > 0.7);

    let bad_primary = PrimaryMetrics {
        monotonic_append_ratio: 0.95,
        edit_entropy: 0.5,
        median_interval: 5.0,
        positive_negative_ratio: 0.98,
        deletion_clustering: 1.0,
    };

    let bad_cadence = CadenceMetrics {
        coefficient_of_variation: 0.1,
        is_robotic: true,
        ..Default::default()
    };

    let bad_score = calculate_assessment_score(&bad_primary, &bad_cadence, 5, 100, 0.0);
    assert!(bad_score < 0.5);
}

#[test]
fn test_report_generation() {
    let events = create_test_events(20);
    let regions = create_test_regions();
    let profile = build_profile(&events, &regions);

    let report = generate_report(&profile);
    assert!(report.contains("FORENSIC AUTHORSHIP ANALYSIS"));
    assert!(report.contains("PRIMARY METRICS"));
    assert!(report.contains("Monotonic Append Ratio"));
    assert!(report.contains("ASSESSMENT"));
}
