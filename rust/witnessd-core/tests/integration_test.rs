use std::fs;
use std::thread;
use std::time::Duration;
use tempfile::TempDir;
use witnessd_core::api;
use witnessd_core::platform::{
    compute_mouse_jitter, EventBroadcaster, MouseEvent, MouseIdleStats, MouseStegoEngine,
    MouseStegoMode, MouseStegoParams, SyncEventBroadcaster,
};

#[test]
#[ignore = "Requires system accessibility permissions"]
fn test_full_pipeline() {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().join("witnessd");
    let watch_dir = tmp.path().join("watch");
    fs::create_dir_all(&data_dir).unwrap();
    fs::create_dir_all(&watch_dir).unwrap();

    // 1. Initialize
    let fingerprint =
        api::init_witnessd(Some(data_dir.to_string_lossy().to_string()), None).unwrap();
    assert!(!fingerprint.is_empty());
    assert!(api::is_initialized());

    // 2. Configure
    let mut config = api::get_config().unwrap();
    config.watch_dirs = vec![watch_dir.clone()];
    api::set_config(config).unwrap();

    // 3. Start Engine
    let status = api::start_engine_default().unwrap();
    assert!(status.running);

    // 4. Create a file and wait for watcher
    let test_file = watch_dir.join("test.txt");
    fs::write(&test_file, "Hello Witnessd").unwrap();

    // Give watcher and engine time to process
    thread::sleep(Duration::from_millis(2000));

    // 5. Verify report
    let reports = api::report_files().unwrap();
    assert!(!reports.is_empty(), "No reports found after file creation");
    let report = reports
        .iter()
        .find(|r| r.file_path.contains("test.txt"))
        .expect("Test file not in reports");
    assert!(report.event_count >= 1);

    // 6. Stop engine
    api::stop_engine().unwrap();
}

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
