// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::*;
use crate::vdf::{self, Parameters};
use cpop_protocol::rfc;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tempfile::TempDir;

fn temp_document() -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("create temp dir");
    let canonical_dir = dir.path().canonicalize().expect("canonicalize temp dir");
    let path = canonical_dir.join("test_document.txt");
    fs::write(&path, b"initial content").expect("write initial content");
    (dir, path)
}

/// Create chain with Optional signature policy for legacy tests
fn test_chain(path: &Path) -> Chain {
    Chain::new(path, test_vdf_params())
        .expect("create chain")
        .with_signature_policy(SignaturePolicy::Optional)
}

fn test_chain_entangled(path: &Path) -> Chain {
    Chain::new_with_mode(path, test_vdf_params(), EntanglementMode::Entangled)
        .expect("create chain")
        .with_signature_policy(SignaturePolicy::Optional)
}

fn test_vdf_params() -> Parameters {
    Parameters {
        iterations_per_second: 1000,
        min_iterations: 10,
        max_iterations: 100_000,
    }
}

#[test]
fn test_chain_creation() {
    let (_dir, path) = temp_document();
    let chain = test_chain(&path);
    assert!(!chain.document_id.is_empty());
    assert!(chain.checkpoints.is_empty());
    assert_eq!(chain.document_path, path.to_string_lossy());
}

#[test]
fn test_chain_creation_invalid_path() {
    let err = Chain::new("/nonexistent/path/to/file.txt", test_vdf_params()).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("No such file") || msg.contains("cannot find the path"),
        "Unexpected error: {}",
        msg
    );
}

#[test]
fn test_single_commit() {
    let (_dir, path) = temp_document();
    let mut chain = test_chain(&path);
    let checkpoint = chain
        .commit(Some("first commit".to_string()))
        .expect("commit");

    assert_eq!(checkpoint.ordinal, 0);
    // Genesis prev-hash is now H(CBOR(document-ref)), not all-zeros
    assert_ne!(checkpoint.previous_hash, [0u8; 32]);
    assert_eq!(checkpoint.message, Some("first commit".to_string()));
    assert!(checkpoint.vdf.is_none());
    assert_ne!(checkpoint.content_hash, [0u8; 32]);
    assert_ne!(checkpoint.hash, [0u8; 32]);
}

#[test]
fn test_multiple_commits_with_vdf() {
    let (dir, path) = temp_document();
    let mut chain = test_chain(&path);

    let cp0 = chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 0");
    assert_eq!(cp0.ordinal, 0);
    assert!(cp0.vdf.is_none());

    fs::write(&path, b"updated content").expect("update content");

    let cp1 = chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 1");
    assert_eq!(cp1.ordinal, 1);
    assert!(cp1.vdf.is_some());
    assert_eq!(cp1.previous_hash, cp0.hash);

    fs::write(&path, b"final content").expect("update content again");

    let cp2 = chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 2");
    assert_eq!(cp2.ordinal, 2);
    assert!(cp2.vdf.is_some());
    assert_eq!(cp2.previous_hash, cp1.hash);

    chain.verify().expect("verify chain");

    drop(dir);
}

#[test]
fn test_chain_verification_valid() {
    let (dir, path) = temp_document();
    let mut chain = test_chain(&path);
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 0");

    fs::write(&path, b"updated").expect("update");
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 1");

    chain.verify().expect("verification should pass");
    drop(dir);
}

#[test]
fn test_chain_verification_hash_mismatch() {
    let (dir, path) = temp_document();
    let mut chain = test_chain(&path);
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit");

    chain.checkpoints[0].hash = [0xFFu8; 32];

    let err = chain.verify().unwrap_err();
    assert!(err.to_string().contains("hash mismatch"));
    drop(dir);
}

#[test]
fn test_chain_verification_broken_chain_link() {
    let (dir, path) = temp_document();
    let mut chain = test_chain(&path);
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 0");

    fs::write(&path, b"updated").expect("update");
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 1");

    chain.checkpoints[1].previous_hash = [0xFFu8; 32];
    chain.checkpoints[1].hash = chain.checkpoints[1].compute_hash();

    let err = chain.verify().unwrap_err();
    assert!(
        err.to_string().contains("broken chain link"),
        "Expected 'broken chain link', got: {}",
        err
    );
    drop(dir);
}

#[test]
fn test_chain_verification_nonzero_first_previous_hash() {
    let (dir, path) = temp_document();
    let mut chain = test_chain(&path);
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit");

    chain.checkpoints[0].previous_hash = [0x01u8; 32];
    chain.checkpoints[0].hash = chain.checkpoints[0].compute_hash();

    let err = chain.verify().unwrap_err();
    assert!(err.to_string().contains("invalid genesis prev-hash"));
    drop(dir);
}

#[test]
fn test_save_and_load_chain() {
    let (dir, path) = temp_document();
    let mut chain = test_chain(&path);
    chain
        .commit_with_vdf_duration(Some("test".to_string()), Duration::from_millis(10))
        .expect("commit");

    let chain_path = dir.path().join("chain.json");
    chain.save(&chain_path).expect("save chain");

    let loaded = Chain::load(&chain_path).expect("load chain");
    assert_eq!(loaded.document_id, chain.document_id);
    assert_eq!(loaded.document_path, chain.document_path);
    assert_eq!(loaded.checkpoints.len(), chain.checkpoints.len());
    assert_eq!(loaded.checkpoints[0].hash, chain.checkpoints[0].hash);
    loaded.verify().expect("loaded chain should verify");

    drop(dir);
}

#[test]
fn test_chain_summary() {
    let (dir, path) = temp_document();
    let mut chain = test_chain(&path);
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 0");

    fs::write(&path, b"updated").expect("update");
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 1");

    let summary = chain.summary();
    assert_eq!(summary.checkpoint_count, 2);
    assert!(summary.first_commit.is_some());
    assert!(summary.last_commit.is_some());
    assert!(summary.final_content_hash.is_some());
    assert!(summary.chain_valid.is_none());

    drop(dir);
}

#[test]
fn test_chain_latest_and_at() {
    let (dir, path) = temp_document();
    let mut chain = test_chain(&path);
    assert!(chain.latest().is_none());

    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 0");
    assert!(chain.latest().is_some());
    assert_eq!(chain.latest().unwrap().ordinal, 0);

    fs::write(&path, b"updated").expect("update");
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 1");
    assert_eq!(chain.latest().unwrap().ordinal, 1);

    assert_eq!(chain.at(0).unwrap().ordinal, 0);
    assert_eq!(chain.at(1).unwrap().ordinal, 1);
    assert!(chain.at(2).is_err());

    drop(dir);
}

#[test]
fn test_total_elapsed_time() {
    let (dir, path) = temp_document();
    let mut chain = test_chain(&path);

    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 0");
    assert_eq!(chain.total_elapsed_time(), Duration::from_secs(0));

    fs::write(&path, b"updated").expect("update");
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(50))
        .expect("commit 1");

    let elapsed = chain.total_elapsed_time();
    assert!(elapsed > Duration::from_secs(0));

    drop(dir);
}

#[test]
fn test_get_or_create_chain() {
    let dir = TempDir::new().expect("create temp dir");
    let doc_path = dir.path().join("document.txt");
    let writersproof_dir = dir.path().join(".writersproof");

    fs::write(&doc_path, b"content").expect("write doc");

    let chain1 = Chain::get_or_create_chain(&doc_path, &writersproof_dir, test_vdf_params())
        .expect("get_or_create");
    assert!(chain1.checkpoints.is_empty());

    drop(dir);
}

#[test]
fn test_find_chain_not_found() {
    let dir = TempDir::new().expect("create temp dir");
    let doc_path = dir.path().join("document.txt");
    let writersproof_dir = dir.path().join(".writersproof");

    fs::write(&doc_path, b"content").expect("write doc");
    fs::create_dir_all(writersproof_dir.join("chains")).expect("create chains dir");

    let err = Chain::find_chain(&doc_path, &writersproof_dir).unwrap_err();
    assert!(err.to_string().contains("no chain found"));

    drop(dir);
}

#[test]
fn test_commit_detects_content_changes() {
    let (dir, path) = temp_document();
    let mut chain = test_chain(&path);

    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 0");
    let hash0 = chain.checkpoints[0].content_hash;

    fs::write(&path, b"different content").expect("update");
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 1");
    let hash1 = chain.checkpoints[1].content_hash;

    assert_ne!(hash0, hash1);

    drop(dir);
}

#[test]
fn test_vdf_verification_in_chain() {
    let (dir, path) = temp_document();
    let mut chain = test_chain(&path);

    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 0");
    fs::write(&path, b"updated").expect("update");
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 1");

    if let Some(ref mut vdf) = chain.checkpoints[1].vdf {
        vdf.output = [0xFFu8; 32];
    }
    chain.checkpoints[1].hash = chain.checkpoints[1].compute_hash();

    let err = chain.verify().unwrap_err();
    assert!(
        err.to_string().contains("VDF verification failed"),
        "Expected 'VDF verification failed', got: {}",
        err
    );

    drop(dir);
}

#[test]
fn test_vdf_input_mismatch_detection() {
    let (dir, path) = temp_document();
    let mut chain = test_chain(&path);

    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 0");
    fs::write(&path, b"updated").expect("update");
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 1");

    if let Some(ref mut vdf) = chain.checkpoints[1].vdf {
        vdf.input = [0xAAu8; 32];
    }
    chain.checkpoints[1].hash = chain.checkpoints[1].compute_hash();

    let err = chain.verify().unwrap_err();
    assert!(
        err.to_string().contains("VDF input mismatch"),
        "Expected 'VDF input mismatch', got: {}",
        err
    );

    drop(dir);
}

#[test]
fn test_entangled_chain_creation() {
    let (dir, path) = temp_document();
    let chain = test_chain_entangled(&path);
    assert_eq!(chain.entanglement_mode, EntanglementMode::Entangled);
    assert!(chain.checkpoints.is_empty());
    drop(dir);
}

#[test]
fn test_entangled_commit_requires_entangled_mode() {
    let (dir, path) = temp_document();
    let mut chain = Chain::new(&path, test_vdf_params()).expect("create legacy chain");

    let err = chain
        .commit_entangled(
            None,
            [1u8; 32],
            "session-1".to_string(),
            100,
            Duration::from_millis(10),
            None,
        )
        .unwrap_err();
    assert!(err.to_string().contains("EntanglementMode::Entangled"));
    drop(dir);
}

#[test]
fn test_entangled_single_commit() {
    let (dir, path) = temp_document();
    let mut chain = test_chain_entangled(&path);

    let jitter_hash = [0xABu8; 32];
    let checkpoint = chain
        .commit_entangled(
            Some("first entangled commit".to_string()),
            jitter_hash,
            "session-1".to_string(),
            50,
            Duration::from_millis(10),
            None,
        )
        .expect("commit entangled");

    assert_eq!(checkpoint.ordinal, 0);
    assert!(checkpoint.vdf.is_some());
    assert!(checkpoint.jitter_binding.is_some());
    let binding = checkpoint.jitter_binding.as_ref().unwrap();
    assert_eq!(binding.jitter_hash, jitter_hash);
    assert_eq!(binding.session_id, "session-1");
    assert_eq!(binding.keystroke_count, 50);

    chain.verify().expect("verify entangled chain");
    drop(dir);
}

#[test]
fn test_entangled_multiple_commits() {
    let (dir, path) = temp_document();
    let mut chain = test_chain_entangled(&path);

    let cp0 = chain
        .commit_entangled(
            None,
            [1u8; 32],
            "session-1".to_string(),
            10,
            Duration::from_millis(10),
            None,
        )
        .expect("commit 0");

    fs::write(&path, b"updated content").expect("update");
    let cp1 = chain
        .commit_entangled(
            None,
            [2u8; 32],
            "session-1".to_string(),
            25,
            Duration::from_millis(10),
            None,
        )
        .expect("commit 1");

    fs::write(&path, b"final content").expect("final update");
    let cp2 = chain
        .commit_entangled(
            None,
            [3u8; 32],
            "session-1".to_string(),
            50,
            Duration::from_millis(10),
            None,
        )
        .expect("commit 2");

    assert_eq!(chain.checkpoints.len(), 3);
    assert_eq!(cp1.previous_hash, cp0.hash);
    assert_eq!(cp2.previous_hash, cp1.hash);

    let vdf0 = cp0.vdf.as_ref().unwrap();
    let vdf1 = cp1.vdf.as_ref().unwrap();
    let expected_input1 = vdf::chain_input_entangled(vdf0.output, [2u8; 32], cp1.content_hash, 1);
    assert_eq!(vdf1.input, expected_input1);

    chain.verify().expect("verify entangled chain");
    drop(dir);
}

#[test]
fn test_entangled_verify_detects_vdf_tampering() {
    let (dir, path) = temp_document();
    let mut chain = test_chain_entangled(&path);

    chain
        .commit_entangled(
            None,
            [1u8; 32],
            "session-1".to_string(),
            10,
            Duration::from_millis(10),
            None,
        )
        .expect("commit 0");

    fs::write(&path, b"updated").expect("update");
    chain
        .commit_entangled(
            None,
            [2u8; 32],
            "session-1".to_string(),
            20,
            Duration::from_millis(10),
            None,
        )
        .expect("commit 1");

    if let Some(ref mut vdf) = chain.checkpoints[0].vdf {
        vdf.output = [0xFFu8; 32];
    }
    chain.checkpoints[0].hash = chain.checkpoints[0].compute_hash();

    let err = chain.verify().unwrap_err();
    assert!(
        err.to_string().contains("VDF verification failed"),
        "Expected VDF verification failure, got: {}",
        err
    );
    drop(dir);
}

#[test]
fn test_entangled_verify_detects_jitter_tampering() {
    let (dir, path) = temp_document();
    let mut chain = test_chain_entangled(&path);

    chain
        .commit_entangled(
            None,
            [1u8; 32],
            "session-1".to_string(),
            10,
            Duration::from_millis(10),
            None,
        )
        .expect("commit 0");

    chain.checkpoints[0]
        .jitter_binding
        .as_mut()
        .unwrap()
        .jitter_hash = [0xFFu8; 32];
    chain.checkpoints[0].hash = chain.checkpoints[0].compute_hash();

    let err = chain.verify().unwrap_err();
    assert!(
        err.to_string().contains("VDF input mismatch"),
        "Expected VDF input mismatch, got: {}",
        err
    );
    drop(dir);
}

#[test]
fn test_entangled_verify_requires_jitter_binding() {
    let (dir, path) = temp_document();
    let mut chain = test_chain_entangled(&path);

    chain
        .commit_entangled(
            None,
            [1u8; 32],
            "session-1".to_string(),
            10,
            Duration::from_millis(10),
            None,
        )
        .expect("commit 0");

    chain.checkpoints[0].jitter_binding = None;
    chain.checkpoints[0].hash = chain.checkpoints[0].compute_hash();

    let err = chain.verify().unwrap_err();
    assert!(
        err.to_string().contains("missing jitter binding"),
        "Expected missing jitter binding error, got: {}",
        err
    );
    drop(dir);
}

#[test]
fn test_entangled_chain_save_load() {
    let dir = TempDir::new().expect("create temp dir");
    let canonical_dir = dir.path().canonicalize().expect("canonicalize");
    let path = canonical_dir.join("test_doc.txt");
    fs::write(&path, b"test content").expect("write");

    let mut chain = test_chain_entangled(&path);

    chain
        .commit_entangled(
            Some("entangled test".to_string()),
            [0xABu8; 32],
            "session-test".to_string(),
            42,
            Duration::from_millis(10),
            None,
        )
        .expect("commit");

    let chain_path = canonical_dir.join("chain.json");
    chain.save(&chain_path).expect("save");

    let loaded = Chain::load(&chain_path).expect("load");
    assert_eq!(loaded.entanglement_mode, EntanglementMode::Entangled);
    assert_eq!(loaded.checkpoints.len(), 1);

    let binding = loaded.checkpoints[0].jitter_binding.as_ref().unwrap();
    assert_eq!(binding.jitter_hash, [0xABu8; 32]);
    assert_eq!(binding.session_id, "session-test");
    assert_eq!(binding.keystroke_count, 42);

    loaded.verify().expect("verify loaded chain");
    drop(dir);
}

#[test]
fn test_legacy_mode_default() {
    let (dir, path) = temp_document();
    let chain = test_chain(&path);
    assert_eq!(chain.entanglement_mode, EntanglementMode::Legacy);
    drop(dir);
}

#[test]
fn test_commit_rfc_basic() {
    let (dir, path) = temp_document();
    let mut chain = test_chain(&path);

    let calibration = rfc::CalibrationAttestation::new(
        1_000_000, // 1M iterations per second
        "test-hardware".to_string(),
        vec![0u8; 64], // dummy signature
        1700000000,
    );

    let checkpoint = chain
        .commit_rfc(
            Some("RFC-compliant commit".to_string()),
            Duration::from_millis(10),
            None, // No jitter binding
            None, // No time evidence
            calibration,
            None,
        )
        .expect("commit_rfc");

    assert_eq!(checkpoint.ordinal, 0);
    assert!(checkpoint.vdf.is_none());
    assert!(checkpoint.rfc_vdf.is_none());
    assert!(checkpoint.rfc_jitter.is_none());
    assert!(checkpoint.time_evidence.is_none());

    chain.verify().expect("verify chain");
    drop(dir);
}

#[test]
fn test_commit_rfc_with_jitter_binding() {
    let (dir, path) = temp_document();
    let mut chain = test_chain(&path);

    let entropy_commitment = rfc::jitter_binding::EntropyCommitment {
        hash: [0xABu8; 32],
        timestamp_ms: 1700000000000,
        previous_hash: [0u8; 32],
    };

    let sources = vec![rfc::jitter_binding::SourceDescriptor {
        source_type: "keyboard".to_string(),
        weight: 1000,
        device_fingerprint: None,
        transport_calibration: None,
    }];

    let summary = rfc::jitter_binding::JitterSummary {
        sample_count: 100,
        mean_interval_us: 150000.0,
        std_dev: 50000.0,
        coefficient_of_variation: 0.33,
        percentiles: [50000.0, 80000.0, 140000.0, 200000.0, 300000.0],
        entropy_bits: 8.5,
        hurst_exponent: Some(0.72),
    };

    let binding_mac = rfc::jitter_binding::BindingMac {
        mac: [0xCDu8; 32],
        document_hash: [0u8; 32],
        keystroke_count: 100,
        timestamp_ms: 1700000000000,
    };

    let rfc_jitter = rfc::JitterBinding::new(entropy_commitment, sources, summary, binding_mac);

    let calibration = rfc::CalibrationAttestation::new(
        1_000_000,
        "test-hardware".to_string(),
        vec![0u8; 64],
        1700000000,
    );

    chain
        .commit_rfc(
            None,
            Duration::from_millis(10),
            None,
            None,
            calibration.clone(),
            None,
        )
        .expect("commit 0");

    fs::write(&path, b"updated content").expect("update");

    let checkpoint = chain
        .commit_rfc(
            Some("With jitter".to_string()),
            Duration::from_millis(10),
            Some(rfc_jitter),
            None,
            calibration,
            None,
        )
        .expect("commit 1");

    assert_eq!(checkpoint.ordinal, 1);
    assert!(checkpoint.vdf.is_some());
    assert!(checkpoint.rfc_vdf.is_some());
    assert!(checkpoint.rfc_jitter.is_some());
    assert!(checkpoint.jitter_binding.is_some());

    let rfc_vdf = checkpoint.rfc_vdf.as_ref().unwrap();
    assert!(rfc_vdf.iterations > 0);
    assert_eq!(rfc_vdf.calibration.hardware_class, "test-hardware");

    let jitter = checkpoint.rfc_jitter.as_ref().unwrap();
    assert_eq!(jitter.entropy_commitment.hash, [0xABu8; 32]);
    assert_eq!(jitter.summary.hurst_exponent, Some(0.72));

    chain.verify().expect("verify chain");
    drop(dir);
}

#[test]
fn test_commit_rfc_v3_domain_separator() {
    let (dir, path) = temp_document();
    let mut chain = test_chain(&path);

    let calibration =
        rfc::CalibrationAttestation::new(1_000_000, "test".to_string(), vec![], 1700000000);

    let cp0 = chain
        .commit_rfc(
            None,
            Duration::from_millis(10),
            None,
            None,
            calibration.clone(),
            None,
        )
        .expect("commit 0");

    let expected_hash = cp0.compute_hash();
    assert_eq!(cp0.hash, expected_hash);

    fs::write(&path, b"updated").expect("update");

    let entropy_commitment = rfc::jitter_binding::EntropyCommitment {
        hash: [1u8; 32],
        timestamp_ms: 1700000000000,
        previous_hash: [0u8; 32],
    };
    let summary = rfc::jitter_binding::JitterSummary {
        sample_count: 10,
        mean_interval_us: 100000.0,
        std_dev: 10000.0,
        coefficient_of_variation: 0.1,
        percentiles: [0.0; 5],
        entropy_bits: 5.0,
        hurst_exponent: None,
    };
    let binding_mac = rfc::jitter_binding::BindingMac {
        mac: [0u8; 32],
        document_hash: [0u8; 32],
        keystroke_count: 10,
        timestamp_ms: 1700000000000,
    };
    let rfc_jitter = rfc::JitterBinding::new(entropy_commitment, vec![], summary, binding_mac);

    let cp1 = chain
        .commit_rfc(
            None,
            Duration::from_millis(10),
            Some(rfc_jitter),
            None,
            calibration,
            None,
        )
        .expect("commit 1");

    assert!(cp1.rfc_jitter.is_some());
    let computed = cp1.compute_hash();
    assert_eq!(cp1.hash, computed);

    chain.verify().expect("verify chain");
    drop(dir);
}

#[test]
fn test_checkpoint_to_rfc_vdf_conversion() {
    let (dir, path) = temp_document();
    let mut chain = test_chain(&path);

    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 0");
    fs::write(&path, b"updated").expect("update");
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(50))
        .expect("commit 1");

    let checkpoint = &chain.checkpoints[1];
    assert!(checkpoint.vdf.is_some());

    let calibration = rfc::CalibrationAttestation::new(
        test_vdf_params().iterations_per_second as u64,
        "test".to_string(),
        vec![],
        1700000000,
    );
    let rfc_vdf = checkpoint.to_rfc_vdf(calibration).unwrap();
    let internal_vdf = checkpoint.vdf.as_ref().unwrap();
    assert_eq!(rfc_vdf.challenge, internal_vdf.input);
    assert_eq!(&rfc_vdf.output[..32], &internal_vdf.output[..]);
    assert_eq!(rfc_vdf.iterations, internal_vdf.iterations);
    assert_eq!(
        rfc_vdf.duration_ms,
        internal_vdf.duration.as_millis() as u64
    );

    drop(dir);
}

#[test]
fn test_ordinal_gap_detected() {
    let (dir, path) = temp_document();
    let mut chain = test_chain(&path);

    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 0");
    fs::write(&path, b"updated").expect("update");
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 1");

    chain.checkpoints[1].ordinal = 5;
    chain.checkpoints[1].hash = chain.checkpoints[1].compute_hash();

    let report = chain.verify_detailed();
    assert!(!report.valid);
    assert!(!report.ordinal_gaps.is_empty());
    assert_eq!(report.ordinal_gaps[0], (1, 5));
    assert!(report.error.as_ref().unwrap().contains("ordinal gap"));
    drop(dir);
}

#[test]
fn test_unsigned_checkpoint_rejected_required_policy() {
    let (_dir, path) = temp_document();
    let mut chain = Chain::new(&path, test_vdf_params()).expect("create chain");
    assert_eq!(chain.signature_policy, SignaturePolicy::Required);

    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 0");

    let err = chain.verify().unwrap_err();
    assert!(err.to_string().contains("unsigned"));
}

#[test]
fn test_unsigned_checkpoint_accepted_optional_policy() {
    let (_dir, path) = temp_document();
    let mut chain = test_chain(&path); // Optional policy

    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 0");

    let report = chain.verify_detailed();
    assert!(report.valid);
    assert!(!report.unsigned_checkpoints.is_empty());
    assert_eq!(report.unsigned_checkpoints[0], 0);
    assert!(!report.warnings.is_empty());
}

#[test]
fn test_signature_policy_serialization() {
    let (dir, path) = temp_document();
    let mut chain = test_chain(&path);
    chain.signature_policy = SignaturePolicy::Required;

    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 0");

    let chain_path = dir.path().join("policy_chain.json");
    chain.save(&chain_path).expect("save");

    let loaded = Chain::load(&chain_path).expect("load");
    assert_eq!(loaded.signature_policy, SignaturePolicy::Required);
    drop(dir);
}

#[test]
fn test_legacy_chain_deserializes_optional_policy() {
    // Legacy chains without signature_policy field should deserialize as Optional
    let json = r#"{
        "document_id": "test",
        "document_path": "/tmp/test.txt",
        "created_at": "2024-01-01T00:00:00Z",
        "checkpoints": [],
        "vdf_params": {"iterations_per_second": 1000, "min_iterations": 10, "max_iterations": 100000},
        "entanglement_mode": "Legacy"
    }"#;

    let chain: Chain = serde_json::from_str(json).expect("deserialize");
    assert_eq!(chain.signature_policy, SignaturePolicy::Optional);
}

#[test]
fn test_verify_detailed_report() {
    let (dir, path) = temp_document();
    let mut chain = test_chain(&path);

    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 0");
    fs::write(&path, b"updated").expect("update");
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 1");

    let report = chain.verify_detailed();
    assert!(report.valid);
    assert_eq!(report.unsigned_checkpoints.len(), 2);
    assert!(report.signature_failures.is_empty());
    assert!(report.ordinal_gaps.is_empty());
    assert!(report.metadata_valid);
    drop(dir);
}

#[test]
fn test_metadata_count_mismatch_detected() {
    let (dir, path) = temp_document();
    let mut chain = test_chain(&path);

    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 0");

    chain.metadata = Some(ChainMetadata {
        checkpoint_count: 5,
        mmr_root: [0u8; 32],
        mmr_leaf_count: 5,
        metadata_signature: None,
        metadata_version: 1,
    });

    let report = chain.verify_detailed();
    assert!(!report.valid);
    assert!(!report.metadata_valid);
    assert!(report
        .error
        .as_ref()
        .unwrap()
        .contains("metadata checkpoint count mismatch"));
    drop(dir);
}

#[test]
fn test_entangled_commit_with_physics_context() {
    let (dir, path) = temp_document();
    let mut chain = Chain::new_with_mode(&path, test_vdf_params(), EntanglementMode::Entangled)
        .expect("create chain")
        .with_signature_policy(SignaturePolicy::Optional);

    let physics = crate::PhysicalContext {
        clock_skew: 42,
        thermal_proxy: 1000,
        silicon_puf: [0xBBu8; 32],
        io_latency_ns: 500,
        ambient_hash: [0u8; 32],
        is_virtualized: false,
        combined_hash: [0xCCu8; 32],
    };

    let cp0 = chain
        .commit_entangled(
            Some("physics-bound commit".to_string()),
            [1u8; 32],
            "session-phys".to_string(),
            10,
            Duration::from_millis(10),
            Some(&physics),
        )
        .expect("commit 0");

    assert!(cp0.vdf.is_some());
    let binding = cp0.jitter_binding.as_ref().unwrap();
    assert!(binding.physics_seed.is_some());

    let expected_seed =
        crate::physics::entanglement::Entanglement::create_seed(cp0.content_hash, &physics);
    assert_eq!(binding.physics_seed.unwrap(), expected_seed);

    let plain_input = vdf::chain_input_entangled([0u8; 32], [1u8; 32], cp0.content_hash, 0);
    let vdf_proof = cp0.vdf.as_ref().unwrap();
    assert_ne!(
        vdf_proof.input, plain_input,
        "VDF input should differ from non-physics input"
    );

    chain.verify().expect("verify physics-bound chain");

    fs::write(&path, b"updated content").expect("update");
    let cp1 = chain
        .commit_entangled(
            None,
            [2u8; 32],
            "session-phys".to_string(),
            20,
            Duration::from_millis(10),
            Some(&physics),
        )
        .expect("commit 1");

    assert!(cp1.jitter_binding.as_ref().unwrap().physics_seed.is_some());
    chain
        .verify()
        .expect("verify multi-checkpoint physics chain");

    drop(dir);
}

#[test]
fn test_entangled_commit_mixed_physics_and_none() {
    let (dir, path) = temp_document();
    let mut chain = Chain::new_with_mode(&path, test_vdf_params(), EntanglementMode::Entangled)
        .expect("create chain")
        .with_signature_policy(SignaturePolicy::Optional);

    let physics = crate::PhysicalContext {
        clock_skew: 100,
        thermal_proxy: 2000,
        silicon_puf: [0xAAu8; 32],
        io_latency_ns: 300,
        ambient_hash: [0u8; 32],
        is_virtualized: false,
        combined_hash: [0xDDu8; 32],
    };

    chain
        .commit_entangled(
            None,
            [1u8; 32],
            "session-mix".to_string(),
            10,
            Duration::from_millis(10),
            Some(&physics),
        )
        .expect("commit 0");

    fs::write(&path, b"updated").expect("update");
    chain
        .commit_entangled(
            None,
            [2u8; 32],
            "session-mix".to_string(),
            20,
            Duration::from_millis(10),
            None,
        )
        .expect("commit 1");

    fs::write(&path, b"final").expect("final update");
    chain
        .commit_entangled(
            None,
            [3u8; 32],
            "session-mix".to_string(),
            30,
            Duration::from_millis(10),
            Some(&physics),
        )
        .expect("commit 2");

    assert!(chain.checkpoints[0]
        .jitter_binding
        .as_ref()
        .unwrap()
        .physics_seed
        .is_some());
    assert!(chain.checkpoints[1]
        .jitter_binding
        .as_ref()
        .unwrap()
        .physics_seed
        .is_none());
    assert!(chain.checkpoints[2]
        .jitter_binding
        .as_ref()
        .unwrap()
        .physics_seed
        .is_some());

    chain.verify().expect("verify mixed physics chain");
    drop(dir);
}
