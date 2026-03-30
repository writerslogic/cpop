// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Comprehensive integration tests for the full CPOP feature pipeline.
//!
//! Run with: `cargo test -p cpop_engine --test integration_tests --features ffi`
//!
//! Tests requiring real system permissions (CGEventTap, Input Monitoring)
//! are gated behind `CPOP_INTEGRATION=1`.

use std::io::Write;
use std::sync::Mutex;

// Serialize all tests that share CPOP_DATA_DIR env var.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn setup() -> (tempfile::TempDir, std::sync::MutexGuard<'static, ()>) {
    let guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = tempfile::tempdir().expect("tempdir");
    std::env::set_var("CPOP_DATA_DIR", dir.path());
    std::env::set_var("CPOP_NO_KEYCHAIN", "1");
    (dir, guard)
}

fn create_doc(dir: &tempfile::TempDir, name: &str, content: &str) -> String {
    let path = dir.path().join(name);
    let mut f = std::fs::File::create(&path).expect("create doc");
    f.write_all(content.as_bytes()).expect("write");
    path.to_string_lossy().to_string()
}

fn modify_doc(path: &str, content: &str) {
    let mut f = std::fs::File::create(path).expect("modify");
    f.write_all(content.as_bytes()).expect("write");
}

// ============================================================
// 1. Keystroke E2E flow
// ============================================================

/// Verify that injected keystrokes reach the sentinel session and are reported
/// via ffi_sentinel_witnessing_status. Requires system permissions on macOS,
/// so gated behind CPOP_INTEGRATION=1.
#[test]
fn test_keystroke_injection_reaches_session() {
    if std::env::var("CPOP_INTEGRATION").is_err() {
        eprintln!("Skipping test_keystroke_injection_reaches_session (set CPOP_INTEGRATION=1)");
        return;
    }

    let (dir, _g) = setup();
    let init = cpop_engine::ffi::system::ffi_init();
    assert!(init.success, "init failed: {:?}", init.error_message);

    let start = cpop_engine::ffi::sentinel::ffi_sentinel_start();
    assert!(
        start.success,
        "sentinel start failed: {:?}",
        start.error_message
    );

    let doc = create_doc(&dir, "test.txt", "Hello, integration test.");
    let witness = cpop_engine::ffi::sentinel_witnessing::ffi_sentinel_start_witnessing(doc);
    assert!(
        witness.success,
        "start witnessing failed: {:?}",
        witness.error_message
    );

    // Inject 20 keystrokes with realistic timing (100-250ms intervals).
    let base_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as i64;

    let keycodes: [u16; 20] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
    ];
    let intervals_ms: [i64; 20] = [
        0, 120, 180, 150, 200, 130, 170, 210, 140, 190, 160, 220, 135, 185, 175, 205, 145, 195,
        155, 165,
    ];

    let mut cumulative_ns = 0i64;
    for i in 0..20 {
        cumulative_ns += intervals_ms[i] * 1_000_000;
        let ts = base_ns + cumulative_ns;
        let zone = (i % 5) as u8;
        let accepted = cpop_engine::ffi::sentinel_inject::ffi_sentinel_inject_keystroke(
            ts,
            keycodes[i],
            zone,
            1,  // source_state_id = HID_SYSTEM
            40, // keyboard_type = ANSI
            0,  // source_pid = kernel (hardware)
        );
        assert!(accepted, "keystroke {i} was rejected");
    }

    let status = cpop_engine::ffi::sentinel_witnessing::ffi_sentinel_witnessing_status();
    assert!(status.is_tracking, "should be tracking");
    assert!(
        status.keystroke_count >= 20,
        "expected >= 20 keystrokes, got {}",
        status.keystroke_count
    );

    // Cleanup
    let stop_w = cpop_engine::ffi::sentinel_witnessing::ffi_sentinel_stop_witnessing(
        status.document_path.unwrap_or_default(),
    );
    assert!(
        stop_w.success,
        "stop witnessing failed: {:?}",
        stop_w.error_message
    );

    let stop = cpop_engine::ffi::sentinel::ffi_sentinel_stop();
    assert!(
        stop.success,
        "sentinel stop failed: {:?}",
        stop.error_message
    );
}

// ============================================================
// 2. Auto-witnessing validation (PreWitnessBuffer)
// ============================================================

#[test]
fn test_pre_witness_buffer_human_plausible() {
    use cpop_engine::sentinel::types::{
        AutoWitnessDecision, PreWitnessBuffer, PreWitnessKeystroke,
    };

    let mut buf = PreWitnessBuffer::new("/tmp/test_human.txt".to_string());

    // Add 15 keystrokes with human-like timing (100-300ms intervals, varied keycodes).
    let base_ns: i64 = 1_000_000_000_000;
    let intervals_ms = [
        0, 150, 220, 180, 130, 250, 170, 200, 140, 190, 160, 230, 120, 210, 155,
    ];
    let mut ts = base_ns;
    for i in 0..15 {
        ts += intervals_ms[i] * 1_000_000;
        buf.keystrokes.push(PreWitnessKeystroke {
            timestamp_ns: ts,
            keycode: (i * 3 + 1) as u16, // varied keycodes
            zone: (i % 4) as u8,         // multiple zones
            source_pid: 1,               // non-zero to avoid robotic check
        });
    }

    let decision = buf.should_auto_witness(10, 0.12, 0.60, 2);
    assert_eq!(
        decision,
        AutoWitnessDecision::HumanPlausible,
        "expected HumanPlausible, got {:?}",
        decision
    );
}

#[test]
fn test_pre_witness_buffer_rejects_robotic() {
    use cpop_engine::sentinel::types::{
        AutoWitnessDecision, PreWitnessBuffer, PreWitnessKeystroke,
    };

    let mut buf = PreWitnessBuffer::new("/tmp/test_robotic.txt".to_string());

    // Add 15 keystrokes with identical 100ms intervals (CV near 0).
    let base_ns: i64 = 1_000_000_000_000;
    for i in 0..15 {
        let ts = base_ns + (i as i64) * 100_000_000; // exactly 100ms apart
        buf.keystrokes.push(PreWitnessKeystroke {
            timestamp_ns: ts,
            keycode: (i * 2) as u16,
            zone: (i % 4) as u8,
            source_pid: 1,
        });
    }

    let decision = buf.should_auto_witness(10, 0.12, 0.60, 2);
    assert_eq!(
        decision,
        AutoWitnessDecision::RejectedRobotic,
        "expected RejectedRobotic, got {:?}",
        decision
    );
}

#[test]
fn test_pre_witness_buffer_rejects_burst() {
    use cpop_engine::sentinel::types::{
        AutoWitnessDecision, PreWitnessBuffer, PreWitnessKeystroke,
    };

    let mut buf = PreWitnessBuffer::new("/tmp/test_burst.txt".to_string());

    // Add 15 keystrokes all within 100ms total (burst).
    let base_ns: i64 = 1_000_000_000_000;
    for i in 0..15 {
        let ts = base_ns + (i as i64) * 5_000_000; // 5ms apart, 70ms total span
        buf.keystrokes.push(PreWitnessKeystroke {
            timestamp_ns: ts,
            keycode: (i * 2 + 1) as u16,
            zone: (i % 3) as u8,
            source_pid: 1,
        });
    }

    let decision = buf.should_auto_witness(10, 0.12, 0.60, 2);
    assert_eq!(
        decision,
        AutoWitnessDecision::RejectedBurst,
        "expected RejectedBurst, got {:?}",
        decision
    );
}

#[test]
fn test_pre_witness_buffer_rejects_repetitive() {
    use cpop_engine::sentinel::types::{
        AutoWitnessDecision, PreWitnessBuffer, PreWitnessKeystroke,
    };

    let mut buf = PreWitnessBuffer::new("/tmp/test_repetitive.txt".to_string());

    // Add 15 keystrokes all with the same keycode, human-like timing.
    let base_ns: i64 = 1_000_000_000_000;
    let intervals_ms = [
        0, 150, 220, 180, 130, 250, 170, 200, 140, 190, 160, 230, 120, 210, 155,
    ];
    let mut ts = base_ns;
    for i in 0..15 {
        ts += intervals_ms[i] * 1_000_000;
        buf.keystrokes.push(PreWitnessKeystroke {
            timestamp_ns: ts,
            keycode: 42, // all same keycode
            zone: (i % 4) as u8,
            source_pid: 1,
        });
    }

    let decision = buf.should_auto_witness(10, 0.12, 0.60, 2);
    assert_eq!(
        decision,
        AutoWitnessDecision::RejectedRepetitive,
        "expected RejectedRepetitive, got {:?}",
        decision
    );
}

// ============================================================
// 3. Auto-checkpoint creates events
// ============================================================

#[test]
fn test_checkpoint_creates_store_event() {
    let (dir, _g) = setup();
    let init = cpop_engine::ffi::system::ffi_init();
    assert!(init.success, "init failed: {:?}", init.error_message);

    let doc = create_doc(
        &dir,
        "checkpoint_test.txt",
        "Initial content for checkpoint.",
    );
    let cp = cpop_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(
        doc.clone(),
        "first checkpoint".to_string(),
    );
    assert!(cp.success, "checkpoint failed: {:?}", cp.error_message);

    // Verify status shows the tracked file.
    let status = cpop_engine::ffi::system::ffi_get_status();
    assert_eq!(status.tracked_file_count, 1);
    assert_eq!(status.total_checkpoints, 1);

    // Verify ffi_list_tracked_files shows the file.
    let files = cpop_engine::ffi::system::ffi_list_tracked_files();
    assert!(!files.is_empty(), "tracked files should be non-empty");

    let canonical = std::path::Path::new(&doc)
        .canonicalize()
        .unwrap_or_else(|_| std::path::PathBuf::from(&doc));
    let canonical_str = canonical.to_string_lossy().to_string();
    let found = files.iter().any(|f| f.path == canonical_str);
    assert!(
        found,
        "expected to find {} in tracked files: {:?}",
        canonical_str,
        files.iter().map(|f| &f.path).collect::<Vec<_>>()
    );

    let tracked = files.iter().find(|f| f.path == canonical_str).unwrap();
    assert_eq!(tracked.checkpoint_count, 1);
}

// ============================================================
// 4. Cumulative stats persist across sessions
// ============================================================

/// This test verifies that cumulative keystroke counts persist via the
/// sentinel session lifecycle. Requires system permissions.
#[test]
fn test_cumulative_keystrokes_persist_across_sessions() {
    if std::env::var("CPOP_INTEGRATION").is_err() {
        eprintln!(
            "Skipping test_cumulative_keystrokes_persist_across_sessions (set CPOP_INTEGRATION=1)"
        );
        return;
    }

    let (dir, _g) = setup();
    let init = cpop_engine::ffi::system::ffi_init();
    assert!(init.success, "init failed: {:?}", init.error_message);

    let start = cpop_engine::ffi::sentinel::ffi_sentinel_start();
    assert!(
        start.success,
        "sentinel start failed: {:?}",
        start.error_message
    );

    let doc = create_doc(&dir, "persist_test.txt", "Content for persistence.");
    let doc_clone = doc.clone();

    // Session 1: inject 50 keystrokes.
    let w1 = cpop_engine::ffi::sentinel_witnessing::ffi_sentinel_start_witnessing(doc.clone());
    assert!(
        w1.success,
        "start witnessing 1 failed: {:?}",
        w1.error_message
    );

    let base_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as i64;

    for i in 0..50 {
        let ts = base_ns + (i as i64) * 150_000_000 + (i as i64 * 13 % 50) * 1_000_000;
        cpop_engine::ffi::sentinel_inject::ffi_sentinel_inject_keystroke(
            ts,
            (i % 40) as u16,
            (i % 5) as u8,
            1,
            40,
            0,
        );
    }

    let s1 = cpop_engine::ffi::sentinel_witnessing::ffi_sentinel_witnessing_status();
    assert!(
        s1.keystroke_count >= 50,
        "session 1: expected >= 50, got {}",
        s1.keystroke_count
    );

    cpop_engine::ffi::sentinel_witnessing::ffi_sentinel_stop_witnessing(doc_clone.clone());

    // Session 2: start witnessing the same file again.
    let w2 =
        cpop_engine::ffi::sentinel_witnessing::ffi_sentinel_start_witnessing(doc_clone.clone());
    assert!(
        w2.success,
        "start witnessing 2 failed: {:?}",
        w2.error_message
    );

    let s2 = cpop_engine::ffi::sentinel_witnessing::ffi_sentinel_witnessing_status();
    // Cumulative keystrokes from session 1 should carry over.
    assert!(
        s2.keystroke_count >= 50,
        "session 2: cumulative keystrokes should be >= 50, got {}",
        s2.keystroke_count
    );

    cpop_engine::ffi::sentinel_witnessing::ffi_sentinel_stop_witnessing(doc_clone);
    cpop_engine::ffi::sentinel::ffi_sentinel_stop();
}

// ============================================================
// 5. Export + verify round-trip
// ============================================================

#[test]
fn test_export_verify_roundtrip() {
    let (dir, _g) = setup();
    let init = cpop_engine::ffi::system::ffi_init();
    assert!(init.success, "init failed: {:?}", init.error_message);

    let doc = create_doc(&dir, "roundtrip.txt", "Version 1.");

    // Create 3 checkpoints with edits.
    for i in 1..=3 {
        modify_doc(&doc, &format!("Version {i} with more content added here."));
        let cp = cpop_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(
            doc.clone(),
            format!("v{i}"),
        );
        assert!(cp.success, "checkpoint {i} failed: {:?}", cp.error_message);
    }

    // Export evidence to a temp file.
    let output_path = dir.path().join("evidence.cpop");
    let output_str = output_path.to_string_lossy().to_string();
    let export = cpop_engine::ffi::evidence_export::ffi_export_evidence(
        doc,
        "core".to_string(),
        output_str.clone(),
    );
    assert!(export.success, "export failed: {:?}", export.error_message);
    assert!(output_path.exists(), "evidence file not created");

    let file_size = std::fs::metadata(&output_path).unwrap().len();
    assert!(file_size > 0, "evidence file is empty");

    // Verify the exported evidence.
    let verify = cpop_engine::ffi::verify_detail::ffi_verify_evidence_detailed(output_str);
    assert!(verify.success, "verify failed: {:?}", verify.error_message);
    assert!(
        verify.checkpoint_count >= 3,
        "expected >= 3 checkpoints, got {}",
        verify.checkpoint_count
    );
}

// ============================================================
// 6. WAR report generation
// ============================================================

#[test]
fn test_war_report_html_generation() {
    let (dir, _g) = setup();
    let init = cpop_engine::ffi::system::ffi_init();
    assert!(init.success, "init failed: {:?}", init.error_message);

    let doc = create_doc(&dir, "war_html.txt", "Document for WAR report.");

    // Create checkpoints to have report data.
    for i in 1..=3 {
        modify_doc(
            &doc,
            &format!("Revision {i} with substantial edits and more text."),
        );
        let cp = cpop_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(
            doc.clone(),
            format!("rev{i}"),
        );
        assert!(cp.success, "checkpoint {i} failed: {:?}", cp.error_message);
    }

    let result = cpop_engine::ffi::report::ffi_render_war_html(doc);
    assert!(
        result.success,
        "WAR HTML failed: {:?}",
        result.error_message
    );
    let html = result.html.expect("html should be Some");
    assert!(!html.is_empty(), "HTML should be non-empty");
    assert!(html.contains("<html"), "HTML should contain <html tag");
    assert!(html.contains("WAR"), "HTML should reference WAR");
}

#[test]
fn test_war_report_build() {
    let (dir, _g) = setup();
    let init = cpop_engine::ffi::system::ffi_init();
    assert!(init.success, "init failed: {:?}", init.error_message);

    let doc = create_doc(&dir, "war_build.txt", "Document for WAR build.");

    for i in 1..=2 {
        modify_doc(
            &doc,
            &format!("Content revision {i} with edits and changes."),
        );
        let cp = cpop_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(
            doc.clone(),
            format!("rev{i}"),
        );
        assert!(cp.success, "checkpoint {i} failed: {:?}", cp.error_message);
    }

    let result = cpop_engine::ffi::report::ffi_build_war_report(doc);
    assert!(
        result.success,
        "WAR build failed: {:?}",
        result.error_message
    );
    assert!(result.report.is_some(), "report should be Some");
}

// ============================================================
// 7. Store document stats
// ============================================================

#[test]
fn test_document_stats_save_load() {
    let (dir, _g) = setup();
    let init = cpop_engine::ffi::system::ffi_init();
    assert!(init.success, "init failed: {:?}", init.error_message);

    // Open the store directly.
    let db_path = dir.path().join("events.db");
    let hmac_key = vec![0u8; 32];
    let store = cpop_engine::store::SecureStore::open(&db_path, hmac_key).expect("open store");

    let stats = cpop_engine::store::DocumentStats {
        file_path: "/tmp/stats_test.txt".to_string(),
        total_keystrokes: 100,
        total_focus_ms: 60_000,
        session_count: 1,
        total_duration_secs: 300,
        first_tracked_at: 1700000000,
        last_tracked_at: 1700000300,
    };

    store.save_document_stats(&stats).expect("save stats");

    let loaded = store
        .load_document_stats("/tmp/stats_test.txt")
        .expect("load stats")
        .expect("stats should exist");

    assert_eq!(loaded.total_keystrokes, 100);
    assert_eq!(loaded.total_focus_ms, 60_000);
    assert_eq!(loaded.session_count, 1);
    assert_eq!(loaded.total_duration_secs, 300);
    assert_eq!(loaded.first_tracked_at, 1700000000);
    assert_eq!(loaded.last_tracked_at, 1700000300);

    // Update and verify persistence.
    let updated = cpop_engine::store::DocumentStats {
        total_keystrokes: 250,
        session_count: 2,
        last_tracked_at: 1700001000,
        ..loaded
    };
    store
        .save_document_stats(&updated)
        .expect("save updated stats");

    let reloaded = store
        .load_document_stats("/tmp/stats_test.txt")
        .expect("reload stats")
        .expect("stats should still exist");

    assert_eq!(reloaded.total_keystrokes, 250);
    assert_eq!(reloaded.session_count, 2);
    assert_eq!(reloaded.last_tracked_at, 1700001000);
    // Unchanged fields should persist.
    assert_eq!(reloaded.total_focus_ms, 60_000);
    assert_eq!(reloaded.first_tracked_at, 1700000000);
}

#[test]
fn test_document_stats_none_for_unknown_file() {
    let (dir, _g) = setup();
    let init = cpop_engine::ffi::system::ffi_init();
    assert!(init.success, "init failed: {:?}", init.error_message);

    let db_path = dir.path().join("events.db");
    let hmac_key = vec![0u8; 32];
    let store = cpop_engine::store::SecureStore::open(&db_path, hmac_key).expect("open store");

    let result = store
        .load_document_stats("/nonexistent/file.txt")
        .expect("load should not error");
    assert!(result.is_none(), "stats should be None for unknown file");
}

// ============================================================
// 8. API field naming (camelCase serialization)
// ============================================================

#[test]
fn test_api_types_serialize_camelcase() {
    let enroll = cpop_engine::writersproof::types::EnrollRequest {
        public_key: "abc123".to_string(),
        device_id: "dev01".to_string(),
        platform: "macos".to_string(),
        attestation_type: "secure_enclave".to_string(),
        attestation_certificate: None,
    };
    let json = serde_json::to_string(&enroll).expect("serialize EnrollRequest");
    assert!(
        json.contains("\"publicKey\""),
        "EnrollRequest should use camelCase: {json}"
    );
    assert!(
        json.contains("\"deviceId\""),
        "EnrollRequest should use camelCase: {json}"
    );
    assert!(
        json.contains("\"attestationType\""),
        "EnrollRequest should use camelCase: {json}"
    );
    assert!(
        !json.contains("\"public_key\""),
        "EnrollRequest should not use snake_case: {json}"
    );

    let anchor = cpop_engine::writersproof::types::AnchorRequest {
        evidence_hash: "hash".to_string(),
        author_did: "did:cpop:test".to_string(),
        signature: "sig".to_string(),
        metadata: None,
    };
    let json = serde_json::to_string(&anchor).expect("serialize AnchorRequest");
    assert!(
        json.contains("\"evidenceHash\""),
        "AnchorRequest should use camelCase: {json}"
    );
    assert!(
        json.contains("\"authorDid\""),
        "AnchorRequest should use camelCase: {json}"
    );
    assert!(
        !json.contains("\"evidence_hash\""),
        "AnchorRequest should not use snake_case: {json}"
    );

    let nonce = cpop_engine::writersproof::types::NonceResponse {
        nonce: "abc".to_string(),
        expires_at: "2026-01-01T00:00:00Z".to_string(),
        nonce_id: "n1".to_string(),
    };
    let json = serde_json::to_string(&nonce).expect("serialize NonceResponse");
    assert!(
        json.contains("\"expiresAt\""),
        "NonceResponse should use camelCase: {json}"
    );
    assert!(
        json.contains("\"nonceId\""),
        "NonceResponse should use camelCase: {json}"
    );
    assert!(
        !json.contains("\"expires_at\""),
        "NonceResponse should not use snake_case: {json}"
    );
}

// ============================================================
// 9. Jitter session records and verifies chain
// ============================================================

#[test]
fn test_jitter_session_records_and_verifies() {
    let dir = tempfile::tempdir().expect("tempdir");
    let doc_path = dir.path().join("jitter_doc.txt");
    std::fs::write(&doc_path, "Initial jitter test content.").expect("write doc");

    let params = cpop_engine::jitter::default_parameters();
    let mut session = cpop_engine::jitter::Session::new(&doc_path, params).expect("create session");

    // Record 20 keystrokes. With sample_interval=10, we should get 2 samples.
    for _ in 0..20 {
        session.record_keystroke().expect("record keystroke");
    }

    assert_eq!(session.keystroke_count(), 20);
    assert_eq!(
        session.sample_count(),
        2,
        "expected 2 samples at interval=10"
    );

    // Export and verify chain integrity.
    let evidence = session.export();
    assert_eq!(evidence.samples.len(), 2);
    assert_eq!(evidence.statistics.total_keystrokes, 20);
    assert!(
        evidence.statistics.chain_valid,
        "jitter chain should be valid"
    );
}

#[test]
fn test_jitter_session_chain_integrity() {
    let dir = tempfile::tempdir().expect("tempdir");
    let doc_path = dir.path().join("jitter_chain.txt");
    std::fs::write(&doc_path, "Chain integrity test.").expect("write doc");

    let params = cpop_engine::jitter::Parameters {
        sample_interval: 5, // sample every 5 keystrokes for more chain links
        ..cpop_engine::jitter::default_parameters()
    };
    let mut session = cpop_engine::jitter::Session::new(&doc_path, params).expect("create session");

    // Record 30 keystrokes -> 6 samples.
    for _ in 0..30 {
        session.record_keystroke().expect("record keystroke");
    }

    assert_eq!(session.sample_count(), 6);

    let evidence = session.export();
    assert!(
        evidence.statistics.chain_valid,
        "chain should be valid after 6 samples"
    );

    // Verify each sample links to its predecessor.
    for i in 1..evidence.samples.len() {
        assert_eq!(
            evidence.samples[i].previous_hash,
            evidence.samples[i - 1].hash,
            "sample {i} should link to sample {}",
            i - 1,
        );
    }

    // First sample should have zero previous_hash.
    assert_eq!(evidence.samples[0].previous_hash, [0u8; 32]);
}

// ============================================================
// 10. Multiple checkpoints with export at different tiers
// ============================================================

#[test]
fn test_export_at_multiple_tiers() {
    let (dir, _g) = setup();
    let init = cpop_engine::ffi::system::ffi_init();
    assert!(init.success, "init failed: {:?}", init.error_message);

    let doc = create_doc(&dir, "tiers.txt", "Tier test v1.");

    for i in 1..=3 {
        modify_doc(
            &doc,
            &format!("Tier test version {i} with additional content."),
        );
        let cp = cpop_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(
            doc.clone(),
            format!("v{i}"),
        );
        assert!(cp.success, "checkpoint {i} failed: {:?}", cp.error_message);
    }

    for tier in &["core", "enhanced", "maximum"] {
        let output = dir.path().join(format!("evidence_{tier}.cpop"));
        let result = cpop_engine::ffi::evidence_export::ffi_export_evidence(
            doc.clone(),
            tier.to_string(),
            output.to_string_lossy().to_string(),
        );
        assert!(
            result.success,
            "export at tier {tier} failed: {:?}",
            result.error_message
        );
        assert!(output.exists(), "evidence file for tier {tier} not created");
        let size = std::fs::metadata(&output).unwrap().len();
        assert!(size > 0, "evidence file for tier {tier} is empty");
    }
}

// ============================================================
// 11. Compact reference format
// ============================================================

#[test]
fn test_compact_ref_format() {
    let (dir, _g) = setup();
    let init = cpop_engine::ffi::system::ffi_init();
    assert!(init.success, "init failed: {:?}", init.error_message);

    let doc = create_doc(&dir, "compact_ref.txt", "Compact ref test.");

    let cp =
        cpop_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(doc.clone(), String::new());
    assert!(cp.success, "checkpoint failed: {:?}", cp.error_message);

    let compact = cpop_engine::ffi::evidence_export::ffi_get_compact_ref(doc);
    assert!(
        compact.starts_with("pop-ref:writerslogic:"),
        "compact ref should start with 'pop-ref:writerslogic:', got: {compact}"
    );
    // Format: pop-ref:writerslogic:<hash_prefix>:<count>
    let parts: Vec<&str> = compact.split(':').collect();
    assert_eq!(
        parts.len(),
        4,
        "compact ref should have 4 colon-separated parts: {compact}"
    );
    assert_eq!(parts[3], "1", "should show 1 event");
}

// ============================================================
// 12. Dashboard metrics
// ============================================================

#[test]
fn test_dashboard_metrics_after_checkpoints() {
    let (dir, _g) = setup();
    let init = cpop_engine::ffi::system::ffi_init();
    assert!(init.success, "init failed: {:?}", init.error_message);

    let doc = create_doc(&dir, "dashboard.txt", "Dashboard test v1.");
    for i in 1..=3 {
        modify_doc(&doc, &format!("Dashboard version {i} with edits."));
        cpop_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(doc.clone(), format!("v{i}"));
    }

    let metrics = cpop_engine::ffi::system::ffi_get_dashboard_metrics();
    assert!(
        metrics.success,
        "dashboard metrics failed: {:?}",
        metrics.error_message
    );
    assert_eq!(metrics.total_files, 1);
    assert_eq!(metrics.total_checkpoints, 3);
}
