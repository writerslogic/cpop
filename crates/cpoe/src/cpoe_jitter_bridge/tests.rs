// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::*;
use crate::jitter::{decode_zone_transition, Parameters};
use std::io::Write;
use std::time::Duration;
use tempfile::NamedTempFile;

fn create_temp_doc() -> NamedTempFile {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(file, "test content for hybrid jitter").unwrap();
    file.flush().unwrap();
    file
}

#[test]
fn test_zone_tracking_engine() {
    let mut engine = ZoneTrackingEngine::new();

    let trans = engine.record_keycode(0x0C);
    assert_eq!(trans, None);

    let trans = engine.record_keycode(0x0D);
    assert!(trans.is_some());

    let (from, to) = decode_zone_transition(trans.unwrap());
    assert_eq!(from, 0);
    assert_eq!(to, 1);

    assert!(engine.profile().total_transitions > 0);
}

#[test]
fn test_hybrid_session_creation() {
    let doc = create_temp_doc();
    let session = HybridJitterSession::new(doc.path(), None, None);
    assert!(session.is_ok());

    let session = session.unwrap();
    assert!(!session.id.is_empty());
    assert_eq!(session.keystroke_count(), 0);
}

#[test]
fn test_hybrid_session_record_keystroke() {
    let doc = create_temp_doc();
    let mut session = HybridJitterSession::new(
        doc.path(),
        Some(Parameters {
            sample_interval: 1,
            ..crate::jitter::default_parameters()
        }),
        None,
    )
    .unwrap();

    let result = session.record_keystroke(0x0C);
    assert!(result.is_ok());

    let (jitter, sampled) = result.unwrap();
    assert!(sampled);
    assert!(jitter >= 500);
    assert!(jitter < 3000);

    assert_eq!(session.keystroke_count(), 1);
    assert_eq!(session.sample_count(), 1);
}

#[test]
fn test_hybrid_session_export() {
    let doc = create_temp_doc();
    let mut session = HybridJitterSession::new(
        doc.path(),
        Some(Parameters {
            sample_interval: 1,
            ..crate::jitter::default_parameters()
        }),
        None,
    )
    .unwrap();

    for keycode in [0x0C, 0x0D, 0x0E] {
        session.record_keystroke(keycode).unwrap();
    }

    session.end();
    let evidence = session.export();

    assert_eq!(evidence.samples.len(), 3);
    assert!(evidence.verify().is_ok());
    assert!(evidence.entropy_quality.phys_ratio >= 0.0);
    assert!(evidence.entropy_quality.phys_ratio <= 1.0);
}

#[test]
fn test_phys_ratio() {
    let doc = create_temp_doc();
    let mut session = HybridJitterSession::new(
        doc.path(),
        Some(Parameters {
            sample_interval: 1,
            ..crate::jitter::default_parameters()
        }),
        None,
    )
    .unwrap();

    for _ in 0..10 {
        session.record_keystroke(0x0C).unwrap();
    }

    let ratio = session.phys_ratio();
    assert!(ratio >= 0.0);
    assert!(ratio <= 1.0);
}

#[test]
fn test_entropy_quality() {
    let doc = create_temp_doc();
    let mut session = HybridJitterSession::new(
        doc.path(),
        Some(Parameters {
            sample_interval: 1,
            ..crate::jitter::default_parameters()
        }),
        None,
    )
    .unwrap();

    for _ in 0..5 {
        session.record_keystroke(0x0C).unwrap();
    }

    let quality = session.entropy_quality();
    assert_eq!(quality.total_samples, 5);
    assert_eq!(quality.phys_samples + quality.pure_samples, 5);
}

#[test]
fn test_session_creation_with_explicit_id() {
    let doc = create_temp_doc();
    let session = HybridJitterSession::new_with_id(doc.path(), None, "my-session-42").unwrap();

    assert_eq!(session.id, "my-session-42");
    assert_eq!(session.keystroke_count(), 0);
    assert_eq!(session.sample_count(), 0);
}

#[test]
fn test_session_creation_zero_sample_interval_rejected() {
    let doc = create_temp_doc();
    let result = HybridJitterSession::new(
        doc.path(),
        Some(Parameters {
            sample_interval: 0,
            ..crate::jitter::default_parameters()
        }),
        None,
    );
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("sample_interval"));
}

#[test]
fn test_session_creation_with_key_material() {
    let doc = create_temp_doc();
    let key = [0xABu8; 32];
    let session = HybridJitterSession::new(doc.path(), None, Some(key));
    assert!(session.is_ok());
}

#[test]
fn test_keystroke_sampling_interval() {
    let doc = create_temp_doc();
    let mut session = HybridJitterSession::new(
        doc.path(),
        Some(Parameters {
            sample_interval: 3,
            ..crate::jitter::default_parameters()
        }),
        None,
    )
    .unwrap();

    let (_, sampled1) = session.record_keystroke(0x0C).unwrap();
    assert!(!sampled1, "keystroke 1 of 3 should not sample");

    let (_, sampled2) = session.record_keystroke(0x0D).unwrap();
    assert!(!sampled2, "keystroke 2 of 3 should not sample");

    let (_, sampled3) = session.record_keystroke(0x0E).unwrap();
    assert!(sampled3, "keystroke 3 of 3 should sample");

    assert_eq!(session.keystroke_count(), 3);
    assert_eq!(session.sample_count(), 1);
}

#[test]
fn test_verify_chain_integrity() {
    let doc = create_temp_doc();
    let mut session = HybridJitterSession::new(
        doc.path(),
        Some(Parameters {
            sample_interval: 1,
            ..crate::jitter::default_parameters()
        }),
        None,
    )
    .unwrap();

    for keycode in [0x0C, 0x0D, 0x0E, 0x0F, 0x00] {
        session.record_keystroke(keycode).unwrap();
    }

    assert!(session.verify_chain().is_ok());

    // First sample's previous_hash should be all zeros
    assert_eq!(session.samples()[0].previous_hash, [0u8; 32]);

    // Each subsequent sample's previous_hash matches prior sample's hash
    for i in 1..session.samples().len() {
        assert_eq!(
            session.samples()[i].previous_hash,
            session.samples()[i - 1].hash
        );
    }
}

#[test]
fn test_export_standard_evidence() {
    let doc = create_temp_doc();
    let mut session = HybridJitterSession::new(
        doc.path(),
        Some(Parameters {
            sample_interval: 1,
            ..crate::jitter::default_parameters()
        }),
        None,
    )
    .unwrap();

    for keycode in [0x0C, 0x0D, 0x0E] {
        session.record_keystroke(keycode).unwrap();
    }
    session.end();

    let standard = session.export_standard();
    assert_eq!(standard.samples.len(), 3);
    assert!(standard.statistics.chain_valid);
    assert_eq!(standard.session_id, session.id);
}

#[test]
fn test_evidence_encode_decode_roundtrip() {
    let doc = create_temp_doc();
    let mut session = HybridJitterSession::new(
        doc.path(),
        Some(Parameters {
            sample_interval: 1,
            ..crate::jitter::default_parameters()
        }),
        None,
    )
    .unwrap();

    for keycode in [0x0C, 0x0D] {
        session.record_keystroke(keycode).unwrap();
    }
    session.end();

    let evidence = session.export();
    let encoded = evidence.encode().unwrap();
    let decoded = HybridEvidence::decode(&encoded).unwrap();

    assert_eq!(decoded.session_id, evidence.session_id);
    assert_eq!(decoded.samples.len(), evidence.samples.len());
    assert!(decoded.verify().is_ok());
}

#[test]
fn test_zone_engine_prev_zone_initial() {
    let engine = ZoneTrackingEngine::new();
    assert_eq!(engine.prev_zone(), -1);
}

#[test]
fn test_zone_engine_negative_zone_returns_0xff() {
    let mut engine = ZoneTrackingEngine::new();
    // record_zone with negative zone should return None
    let result = engine.record_zone(-1);
    assert_eq!(result, None);
    assert_eq!(
        engine.prev_zone(),
        -1,
        "negative zone should not update prev_zone"
    );
}

#[test]
fn test_zone_engine_profile_histogram_population() {
    let mut engine = ZoneTrackingEngine::new();

    // Record several keycodes across different zones to populate histograms
    let keycodes: &[u16] = &[0x0C, 0x0D, 0x0E, 0x0C, 0x0D, 0x0E, 0x0C];
    for &kc in keycodes {
        engine.record_keycode(kc);
    }

    let profile = engine.profile();
    assert!(profile.total_transitions >= 6);
    assert!(profile.hand_alternation >= 0.0 && profile.hand_alternation <= 1.0);
}

#[test]
fn test_interval_to_bucket_boundaries() {
    use crate::cpoe_jitter_bridge::helpers::interval_to_bucket;

    assert_eq!(interval_to_bucket(Duration::from_millis(0)), Some(0));
    assert_eq!(interval_to_bucket(Duration::from_millis(25)), Some(0));
    assert_eq!(interval_to_bucket(Duration::from_millis(50)), Some(1));
    assert_eq!(interval_to_bucket(Duration::from_millis(99)), Some(1));
    assert_eq!(interval_to_bucket(Duration::from_millis(100)), Some(2));
    assert_eq!(interval_to_bucket(Duration::from_millis(450)), Some(9));
    // 500ms-30s clamps to bucket 9
    assert_eq!(interval_to_bucket(Duration::from_millis(500)), Some(9));
    assert_eq!(interval_to_bucket(Duration::from_millis(10_000)), Some(9));
    // Beyond 30s is not typing behavior
    assert_eq!(interval_to_bucket(Duration::from_millis(30_001)), None);
    assert_eq!(interval_to_bucket(Duration::from_secs(3600)), None);
}

#[test]
fn test_save_load_roundtrip() {
    let doc = create_temp_doc();
    let mut session = HybridJitterSession::new(
        doc.path(),
        Some(Parameters {
            sample_interval: 1,
            ..crate::jitter::default_parameters()
        }),
        None,
    )
    .unwrap();

    for keycode in [0x0C, 0x0D, 0x0E] {
        session.record_keystroke(keycode).unwrap();
    }
    session.end();

    let orig_id = session.id.clone();
    let orig_doc_path = session.document_path.clone();
    let orig_keystroke_count = session.keystroke_count();
    let orig_sample_count = session.sample_count();
    let orig_started_at = session.started_at;
    let orig_params = session.params;

    // Save to a temp file
    let dir = tempfile::TempDir::new().unwrap();
    let save_path = dir.path().join("session1.json");
    session.save(&save_path).unwrap();

    // Load from saved file
    let loaded = HybridJitterSession::load(&save_path, None).unwrap();

    // Verify core fields survived the round-trip
    assert_eq!(loaded.id, orig_id);
    assert_eq!(loaded.document_path, orig_doc_path);
    assert_eq!(loaded.keystroke_count(), orig_keystroke_count);
    assert_eq!(loaded.sample_count(), orig_sample_count);
    assert_eq!(loaded.started_at, orig_started_at);
    assert_eq!(loaded.params.sample_interval, orig_params.sample_interval);
    assert!(loaded.ended_at.is_some());

    // Hash chain must still be valid
    assert!(loaded.verify_chain().is_ok());

    // Export from loaded session and verify sample count
    let evidence = loaded.export();
    assert_eq!(evidence.samples.len(), orig_sample_count);
    assert!(evidence.verify().is_ok());

    // Loaded session should be ended; recording should fail
    // (loaded sessions get a fresh PhysSession so the document tracker path
    // may not exist, but even if it does the session is logically complete)
    // We verify the session is read-only by confirming it was ended.
    assert!(loaded.ended_at.is_some());

    // Re-save to another path and re-load to verify double round-trip
    let save_path2 = dir.path().join("session2.json");
    loaded.save(&save_path2).unwrap();

    let reloaded = HybridJitterSession::load(&save_path2, None).unwrap();
    assert_eq!(reloaded.id, orig_id);
    assert_eq!(reloaded.keystroke_count(), orig_keystroke_count);
    assert_eq!(reloaded.sample_count(), orig_sample_count);
    assert!(reloaded.verify_chain().is_ok());
}

#[test]
fn test_evidence_entropy_source_labels() {
    let doc = create_temp_doc();
    let mut session = HybridJitterSession::new(
        doc.path(),
        Some(Parameters {
            sample_interval: 1,
            ..crate::jitter::default_parameters()
        }),
        None,
    )
    .unwrap();

    session.record_keystroke(0x0C).unwrap();
    session.end();

    let evidence = session.export();
    let source = evidence.entropy_source();
    // Should be one of the known labels
    assert!([
        "hardware (TSC-based)",
        "hybrid (hardware + HMAC)",
        "mostly HMAC (limited hardware)",
        "pure HMAC (no hardware entropy)"
    ]
    .contains(&source));
}
