// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::*;
use crate::jitter::{decode_zone_transition, Parameters};
use std::io::Write;
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
    assert_eq!(trans, 0xFF);

    let trans = engine.record_keycode(0x0D);
    assert_ne!(trans, 0xFF);

    let (from, to) = decode_zone_transition(trans);
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
