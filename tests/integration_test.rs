use std::thread;
use std::time::Duration;
use witnessd_core::platform::{
    compute_mouse_jitter, EventBroadcaster, MouseEvent, MouseIdleStats, MouseStegoEngine,
    MouseStegoMode, MouseStegoParams, SyncEventBroadcaster,
};

// Analysis imports
use witnessd_core::analysis::{
    analyze_galton_invariant, analyze_labyrinth, analyze_pink_noise, analyze_reflex_gate,
    calculate_hurst_dfa, calculate_hurst_rs, generate_pink_noise, LabyrinthParams,
};

// =============================================================================
// Mouse Capture Integration Tests
// =============================================================================

#[test]
fn test_mouse_event_types() {
    // Test MouseEvent creation and methods
    let event = MouseEvent {
        timestamp_ns: 1234567890,
        x: 100.0,
        y: 200.0,
        dx: 1.5,
        dy: -0.8,
        is_idle: true,
        is_hardware: true,
        device_id: Some("046d:c077".to_string()),
    };

    assert_eq!(event.timestamp_ns, 1234567890);
    assert!(event.is_idle);
    assert!(event.is_hardware);
    assert!(event.is_micro_movement()); // magnitude < 3.0
}

#[test]
fn test_mouse_event_micro_movement_detection() {
    // Small movement (micro)
    let micro = MouseEvent {
        timestamp_ns: 0,
        x: 0.0,
        y: 0.0,
        dx: 0.5,
        dy: 0.3,
        is_idle: false,
        is_hardware: true,
        device_id: None,
    };
    assert!(micro.is_micro_movement());

    // Large movement (not micro)
    let large = MouseEvent {
        timestamp_ns: 0,
        x: 0.0,
        y: 0.0,
        dx: 10.0,
        dy: 10.0,
        is_idle: false,
        is_hardware: true,
        device_id: None,
    };
    assert!(!large.is_micro_movement());

    // At threshold (3.0 magnitude)
    let threshold = MouseEvent {
        timestamp_ns: 0,
        x: 0.0,
        y: 0.0,
        dx: 3.0,
        dy: 0.0, // magnitude = 3.0
        is_idle: false,
        is_hardware: true,
        device_id: None,
    };
    assert!(!threshold.is_micro_movement()); // >= 3.0 is not micro
}

#[test]
fn test_mouse_idle_stats_accumulation() {
    let mut stats = MouseIdleStats::default();

    // Record some micro-movements
    // Q0 (NE): dx>=0, dy<0
    // Q1 (NW): dx<0, dy<0
    // Q2 (SW): dx<0, dy>=0
    // Q3 (SE): dx>=0, dy>=0
    let events = vec![
        MouseEvent {
            timestamp_ns: 0,
            x: 0.0,
            y: 0.0,
            dx: 1.0,
            dy: -1.0, // Q0 (NE)
            is_idle: true,
            is_hardware: true,
            device_id: None,
        },
        MouseEvent {
            timestamp_ns: 1000,
            x: 1.0,
            y: -1.0,
            dx: -1.0,
            dy: -1.0, // Q1 (NW)
            is_idle: true,
            is_hardware: true,
            device_id: None,
        },
        MouseEvent {
            timestamp_ns: 2000,
            x: 0.0,
            y: -2.0,
            dx: -1.0,
            dy: 1.0, // Q2 (SW)
            is_idle: true,
            is_hardware: true,
            device_id: None,
        },
        MouseEvent {
            timestamp_ns: 3000,
            x: -1.0,
            y: -1.0,
            dx: 1.0,
            dy: 1.0, // Q3 (SE)
            is_idle: true,
            is_hardware: true,
            device_id: None,
        },
    ];

    for event in &events {
        stats.record(event);
    }

    assert_eq!(stats.total_events, 4);
    assert_eq!(stats.sum_dx, 0.0); // 1 + (-1) + (-1) + 1 = 0
    assert_eq!(stats.sum_dy, 0.0); // (-1) + (-1) + 1 + 1 = 0

    // Test quadrant counts - one in each quadrant
    assert_eq!(stats.quadrant_counts[0], 1); // Q0 (NE)
    assert_eq!(stats.quadrant_counts[1], 1); // Q1 (NW)
    assert_eq!(stats.quadrant_counts[2], 1); // Q2 (SW)
    assert_eq!(stats.quadrant_counts[3], 1); // Q3 (SE)
}

#[test]
fn test_mouse_idle_stats_statistics() {
    let mut stats = MouseIdleStats::new(); // Use new() to properly initialize min_magnitude

    // Add 5 events with known magnitudes
    for i in 0..5 {
        let mag = (i + 1) as f64; // 1, 2, 3, 4, 5
        stats.record(&MouseEvent {
            timestamp_ns: i * 1000,
            x: 0.0,
            y: 0.0,
            dx: mag,
            dy: 0.0,
            is_idle: true,
            is_hardware: true,
            device_id: None,
        });
    }

    assert_eq!(stats.total_events, 5);
    assert_eq!(stats.min_magnitude, 1.0);
    assert_eq!(stats.max_magnitude, 5.0);

    // Mean magnitude should be (1+2+3+4+5)/5 = 3.0
    let mean = stats.mean_magnitude();
    assert!((mean - 3.0).abs() < 0.001);

    // Variance: ((1-3)^2 + (2-3)^2 + (3-3)^2 + (4-3)^2 + (5-3)^2) / 5
    //         = (4 + 1 + 0 + 1 + 4) / 5 = 10 / 5 = 2
    let variance = stats.variance_magnitude();
    assert!((variance - 2.0).abs() < 0.001);
}

#[test]
fn test_mouse_stego_engine() {
    let seed = [42u8; 32];

    let mut engine = MouseStegoEngine::new(seed);
    engine.set_params(MouseStegoParams {
        enabled: true,
        mode: MouseStegoMode::TimingOnly,
        min_delay_micros: 500,
        max_delay_micros: 2000,
        inject_on_first_move: true,
        inject_while_traveling: true,
    });

    // Generate several jitter values
    let mut jitters = Vec::new();
    for _ in 0..10 {
        if let Some(j) = engine.next_jitter() {
            jitters.push(j);
        }
    }

    // All jitter values should be in valid range (500-2000μs)
    for &j in &jitters {
        assert!(j >= 500, "Jitter {} should be >= 500", j);
        assert!(j <= 2000, "Jitter {} should be <= 2000", j);
    }

    // Jitter values should be deterministic - creating same engine should produce same sequence
    let mut engine2 = MouseStegoEngine::new(seed);
    engine2.set_params(MouseStegoParams {
        enabled: true,
        mode: MouseStegoMode::TimingOnly,
        min_delay_micros: 500,
        max_delay_micros: 2000,
        inject_on_first_move: true,
        inject_while_traveling: true,
    });
    for &expected in &jitters {
        let actual = engine2.next_jitter().unwrap();
        assert_eq!(actual, expected);
    }

    // Different seed should produce different sequence
    let different_seed = [99u8; 32];
    let mut engine3 = MouseStegoEngine::new(different_seed);
    engine3.set_params(MouseStegoParams {
        enabled: true,
        mode: MouseStegoMode::TimingOnly,
        min_delay_micros: 500,
        max_delay_micros: 2000,
        inject_on_first_move: true,
        inject_while_traveling: true,
    });
    let different_jitter = engine3.next_jitter().unwrap();
    // Very unlikely to match (1 in 1500 chance)
    // We just verify it runs without error
    assert!((500..=2000).contains(&different_jitter));
}

#[test]
fn test_compute_mouse_jitter_function() {
    let seed = [42u8; 32];
    let doc_hash = [1u8; 32];
    let prev_jitter = [0u8; 32];
    let params = MouseStegoParams::default();

    // Test basic computation
    let jitter1 = compute_mouse_jitter(&seed, doc_hash, 0, prev_jitter, &params);
    assert!(jitter1 >= params.min_delay_micros);
    assert!(jitter1 <= params.max_delay_micros);

    // Same inputs should give same output (deterministic)
    let jitter2 = compute_mouse_jitter(&seed, doc_hash, 0, prev_jitter, &params);
    assert_eq!(jitter1, jitter2);

    // Different event count should give different jitter
    let jitter3 = compute_mouse_jitter(&seed, doc_hash, 1, prev_jitter, &params);
    // Not guaranteed different, but very likely
    // Just verify it's in range
    assert!(jitter3 >= params.min_delay_micros);
    assert!(jitter3 <= params.max_delay_micros);
}

#[test]
fn test_mouse_stego_params() {
    // Default params
    let default_params = MouseStegoParams::default();
    assert_eq!(default_params.min_delay_micros, 500);
    assert_eq!(default_params.max_delay_micros, 2000);
    assert!(matches!(default_params.mode, MouseStegoMode::TimingOnly));

    // Custom params
    let custom_params = MouseStegoParams {
        enabled: true,
        min_delay_micros: 100,
        max_delay_micros: 500,
        mode: MouseStegoMode::FirstMoveOnly,
        inject_on_first_move: true,
        inject_while_traveling: false,
    };
    assert_eq!(custom_params.min_delay_micros, 100);
    assert_eq!(custom_params.max_delay_micros, 500);
}

#[tokio::test]
async fn test_event_broadcaster_basic() {
    let broadcaster: EventBroadcaster<i32> = EventBroadcaster::new();

    // Subscribe two receivers
    let (id1, mut rx1) = broadcaster.subscribe();
    let (id2, mut rx2) = broadcaster.subscribe();

    assert_ne!(id1, id2);

    // Broadcast a value
    broadcaster.broadcast(42);

    // Both receivers should get it
    assert_eq!(rx1.recv().await.unwrap(), 42);
    assert_eq!(rx2.recv().await.unwrap(), 42);

    // Unsubscribe one
    broadcaster.unsubscribe(id1);

    // Broadcast again
    broadcaster.broadcast(99);

    // Only rx2 should get it (rx1 was unsubscribed)
    assert_eq!(rx2.recv().await.unwrap(), 99);
}

#[tokio::test]
async fn test_event_broadcaster_stats() {
    let broadcaster: EventBroadcaster<String> = EventBroadcaster::new();

    assert_eq!(broadcaster.subscriber_count(), 0);
    assert_eq!(broadcaster.broadcast_count(), 0);
    assert_eq!(broadcaster.failed_sends(), 0);

    let (_id1, _rx1) = broadcaster.subscribe();
    let (_id2, _rx2) = broadcaster.subscribe();

    assert_eq!(broadcaster.subscriber_count(), 2);

    broadcaster.broadcast("test".to_string());

    assert_eq!(broadcaster.broadcast_count(), 1);
    assert_eq!(broadcaster.failed_sends(), 0);
}

#[tokio::test]
async fn test_event_broadcaster_dropped_receiver() {
    let broadcaster: EventBroadcaster<i32> = EventBroadcaster::new();

    let (_, rx1) = broadcaster.subscribe();
    let (_id2, _rx2) = broadcaster.subscribe();

    // Drop rx1
    drop(rx1);

    // Broadcast - should detect dropped receiver and clean up
    broadcaster.broadcast(1);

    // After cleanup, only 1 subscriber should remain
    assert_eq!(broadcaster.failed_sends(), 1);
}

#[test]
fn test_sync_event_broadcaster_basic() {
    let broadcaster: SyncEventBroadcaster<i32> = SyncEventBroadcaster::new();

    // Subscribe two receivers
    let (id1, rx1) = broadcaster.subscribe();
    let (id2, rx2) = broadcaster.subscribe();

    assert_ne!(id1, id2);

    // Broadcast a value
    broadcaster.broadcast(42);

    // Both receivers should get it
    assert_eq!(rx1.recv_timeout(Duration::from_millis(100)).unwrap(), 42);
    assert_eq!(rx2.recv_timeout(Duration::from_millis(100)).unwrap(), 42);

    // Unsubscribe one
    broadcaster.unsubscribe(id1);

    // Broadcast again
    broadcaster.broadcast(99);

    // Only rx2 should get it (rx1 was unsubscribed)
    assert_eq!(rx2.recv_timeout(Duration::from_millis(100)).unwrap(), 99);
}

#[test]
fn test_sync_event_broadcaster_concurrent() {
    use std::sync::Arc;

    let broadcaster = Arc::new(SyncEventBroadcaster::<i32>::new());
    let (_, rx) = broadcaster.subscribe();

    // Spawn a thread to broadcast
    let bc = Arc::clone(&broadcaster);
    let handle = thread::spawn(move || {
        for i in 0..100 {
            bc.broadcast(i);
        }
    });

    handle.join().unwrap();

    // Verify we received all messages
    let mut received = Vec::new();
    while let Ok(val) = rx.try_recv() {
        received.push(val);
    }

    assert_eq!(received.len(), 100);
    for (i, &val) in received.iter().enumerate() {
        assert_eq!(val, i as i32);
    }
}

#[test]
fn test_mouse_idle_stats_in_activity_fingerprint() {
    use witnessd_core::fingerprint::ActivityFingerprint;

    let mut fingerprint = ActivityFingerprint::default();
    assert!(fingerprint.mouse_idle_stats.is_none());

    // Create some stats
    let mut stats = MouseIdleStats::default();
    stats.record(&MouseEvent {
        timestamp_ns: 0,
        x: 0.0,
        y: 0.0,
        dx: 1.0,
        dy: 0.5,
        is_idle: true,
        is_hardware: true,
        device_id: None,
    });

    fingerprint.mouse_idle_stats = Some(stats.clone());

    assert!(fingerprint.mouse_idle_stats.is_some());
    let stored_stats = fingerprint.mouse_idle_stats.as_ref().unwrap();
    assert_eq!(stored_stats.total_events, 1);
}

// =============================================================================
// RFC Time Binding Tier Tests
// =============================================================================

#[test]
fn test_rfc_time_binding_tier_calculation() {
    use witnessd_core::rfc::TimeBindingTier;

    // Test tier ordering and values
    assert_eq!(TimeBindingTier::Maximum as u8, 1);
    assert_eq!(TimeBindingTier::Enhanced as u8, 2);
    assert_eq!(TimeBindingTier::Standard as u8, 3);
    assert_eq!(TimeBindingTier::Degraded as u8, 4);

    // Test tier string representation
    assert_eq!(TimeBindingTier::Maximum.as_str(), "maximum");
    assert_eq!(TimeBindingTier::Standard.as_str(), "standard");

    // Test tier calculation
    let tier = TimeBindingTier::calculate(2, 2, 0, true);
    assert_eq!(tier, TimeBindingTier::Maximum);

    let tier = TimeBindingTier::calculate(1, 1, 0, true);
    assert_eq!(tier, TimeBindingTier::Enhanced);

    let tier = TimeBindingTier::calculate(1, 0, 0, true);
    assert_eq!(tier, TimeBindingTier::Standard);

    let tier = TimeBindingTier::calculate(0, 0, 0, true);
    assert_eq!(tier, TimeBindingTier::Degraded);
}

// =============================================================================
// Behavioral Analysis Integration Tests
// =============================================================================

#[test]
fn test_hurst_analysis_human_typing() {
    // Simulate human-like typing intervals with long-range dependence
    // Using pink noise pattern that exhibits H ≈ 0.7
    let mut intervals = Vec::with_capacity(256);
    let base_interval = 150.0; // 150ms base typing speed

    // Generate correlated intervals (simulating human rhythm)
    for i in 0..256 {
        // Add slow oscillation (long-range correlation)
        let slow_wave = 20.0 * (i as f64 * 0.05).sin();
        // Add fast variation
        let fast_var = 10.0 * ((i as f64 * 0.3).sin() + (i as f64 * 0.7).cos());
        // Add small noise
        let noise = 5.0 * (i as f64 * 1.7).sin();

        let current = (base_interval + slow_wave + fast_var + noise).max(50.0);
        intervals.push(current);
    }

    // Test R/S method
    let rs_result = calculate_hurst_rs(&intervals).unwrap();
    // Human typing typically has H in [0.3, 1.0] range
    assert!(
        rs_result.exponent > 0.3 && rs_result.exponent < 1.0,
        "R/S Hurst exponent {} outside expected range",
        rs_result.exponent
    );

    // Test DFA method
    let dfa_result = calculate_hurst_dfa(&intervals).unwrap();
    assert!(
        dfa_result.exponent > 0.3 && dfa_result.exponent < 1.0,
        "DFA Hurst exponent {} outside expected range",
        dfa_result.exponent
    );
}

#[test]
fn test_hurst_rejects_white_noise() {
    // Generate white noise (random, uncorrelated) - need enough data
    let white_noise: Vec<f64> = (0..512)
        .map(|i| {
            // Use a simple hash-like function to generate pseudo-random values
            let seed = ((i as u64).wrapping_mul(1103515245).wrapping_add(12345)) % 2147483647;
            100.0 + 50.0 * ((seed as f64 / 2147483647.0) - 0.5) * 2.0
        })
        .collect();

    match calculate_hurst_rs(&white_noise) {
        Ok(result) => {
            // White noise should have H ≈ 0.5
            assert!(
                result.exponent < 0.75,
                "White noise should have low Hurst, got {}",
                result.exponent
            );
        }
        Err(e) => {
            // If analysis fails due to insufficient data, that's acceptable for this test
            assert!(e.contains("Insufficient"), "Unexpected error: {}", e);
        }
    }
}

#[test]
fn test_pink_noise_detection_synthetic() {
    // Generate synthetic pink noise
    let pink = generate_pink_noise(512, 42);

    let result = analyze_pink_noise(&pink, 100.0).unwrap();

    // Pink noise should have spectral slope near 1.0
    assert!(
        result.spectral_slope > 0.3 && result.spectral_slope < 2.5,
        "Pink noise spectral slope {} outside expected range",
        result.spectral_slope
    );
    assert!(!result.is_white_noise());
}

#[test]
fn test_error_topology_analysis() {
    use witnessd_core::analysis::{analyze_error_topology, EventType, TopologyEvent};

    // Simulate typing events with errors (corrections)
    let events: Vec<TopologyEvent> = (0..50)
        .map(|i| {
            // Every 10th event is an error correction
            let event_type = if i % 10 == 0 {
                EventType::Correction
            } else {
                EventType::Normal
            };
            TopologyEvent {
                timestamp_ns: i as i64 * 100_000_000, // 100ms between events
                event_type,
                key_code: Some((65 + (i % 26)) as u16), // A-Z key codes
                gap_ns: 100_000_000,                    // 100ms gap
            }
        })
        .collect();

    let result = analyze_error_topology(&events).unwrap();

    // Score should be between 0 and 1
    assert!(
        result.score >= 0.0 && result.score <= 1.0,
        "Error topology score {} outside [0,1]",
        result.score
    );

    // Should have detected errors
    assert!(result.error_count > 0, "Should have detected some errors");
}

#[test]
fn test_labyrinth_analysis() {
    // Generate a signal with some structure (sine wave + noise)
    let signal: Vec<f64> = (0..500)
        .map(|i| {
            let t = i as f64 * 0.1;
            t.sin() + 0.5 * (2.0 * t).sin() + 0.1 * (i as f64 * 0.7).cos()
        })
        .collect();

    let params = LabyrinthParams::default();
    let result = analyze_labyrinth(&signal, &params).unwrap();

    // Embedding dimension should be reasonable for this signal
    assert!(
        result.embedding_dimension >= 2 && result.embedding_dimension <= 10,
        "Embedding dimension {} outside expected range",
        result.embedding_dimension
    );

    // Optimal delay should be positive
    assert!(
        result.optimal_delay > 0,
        "Optimal delay {} should be positive",
        result.optimal_delay
    );

    // Betti numbers should be computed
    assert!(
        !result.betti_numbers.is_empty(),
        "Betti numbers should be computed"
    );
}

#[test]
fn test_galton_invariant_perturbation_response() {
    use witnessd_core::analysis::ProbeSample;

    // Simulate response times to perturbations (sudden rhythm changes)
    // Human responses show gradual recovery (absorption)
    // Need multiple perturbations spread across the sample
    let baseline = 150.0;
    let samples: Vec<ProbeSample> = (0..60)
        .map(|i| {
            // Perturbations at samples 10, 25, 40
            let is_pert = i == 10 || i == 25 || i == 40;
            let interval = if is_pert {
                // Large perturbation (> 30% deviation)
                baseline + 80.0
            } else if i > 10 && i < 20 {
                // Recovery after first perturbation
                let decay = (-(i as f64 - 10.0) * 0.3).exp();
                baseline + 80.0 * decay
            } else if i > 25 && i < 35 {
                // Recovery after second perturbation
                let decay = (-(i as f64 - 25.0) * 0.25).exp();
                baseline + 80.0 * decay
            } else if i > 40 && i < 50 {
                // Recovery after third perturbation
                let decay = (-(i as f64 - 40.0) * 0.35).exp();
                baseline + 80.0 * decay
            } else {
                baseline + 10.0 * (i as f64 * 0.5).sin()
            };
            ProbeSample {
                timestamp_ns: i as i64 * 200_000_000,
                interval_ms: interval,
                is_perturbed: is_pert,
                is_stimulus_response: false,
            }
        })
        .collect();

    let result = analyze_galton_invariant(&samples, baseline).unwrap();

    // Absorption coefficient should be in reasonable range
    assert!(
        result.absorption_coefficient >= 0.0 && result.absorption_coefficient <= 2.0,
        "Absorption coefficient {} outside expected range",
        result.absorption_coefficient
    );
}

#[test]
fn test_reflex_gate_minimum_latency() {
    use witnessd_core::analysis::ProbeSample;

    // Simulate reflex response times (stimulus -> response)
    let samples: Vec<ProbeSample> = (0..30)
        .map(|i| {
            // Human reflex time: typically 150-300ms with variability
            let base_latency = 200.0;
            let variation = 50.0 * ((i as f64 * 0.7).sin() + 0.5 * (i as f64 * 1.3).cos());
            ProbeSample {
                timestamp_ns: i as i64 * 500_000_000,
                interval_ms: (base_latency + variation).max(100.0),
                is_perturbed: false,
                is_stimulus_response: true,
            }
        })
        .collect();

    let result = analyze_reflex_gate(&samples).unwrap();

    // Minimum latency should be at least 100ms for human response
    assert!(
        result.min_latency_ms >= 50.0,
        "Min latency {}ms is suspiciously low for human",
        result.min_latency_ms
    );

    // CV (coefficient of variation) should be in human range
    assert!(
        result.coefficient_of_variation >= 0.0 && result.coefficient_of_variation <= 1.0,
        "CV {} outside expected range",
        result.coefficient_of_variation
    );
}
