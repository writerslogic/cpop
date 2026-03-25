// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::ffi::helpers::{detect_attestation_tier, open_store};
use crate::ffi::types::FfiResult;
use cpop_protocol::rfc::wire_types::{
    CheckpointWire, DocumentRef, EditDelta, EvidencePacketWire, HashValue, ProcessProof,
    ProofAlgorithm, ProofParams,
};

/// Export stored events for a file as a CBOR evidence packet at the given tier.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_export_evidence(path: String, tier: String, output: String) -> FfiResult {
    let file_path = match crate::sentinel::helpers::validate_path(&path) {
        Ok(p) => p,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Invalid source path: {}", e)),
            };
        }
    };
    let output_path = match crate::sentinel::helpers::validate_path(&output) {
        Ok(p) => p,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Invalid output path: {}", e)),
            };
        }
    };

    if !file_path.exists() {
        return FfiResult {
            success: false,
            message: None,
            error_message: Some(format!("File not found: {}", file_path.display())),
        };
    }

    let store = match open_store() {
        Ok(s) => s,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(e),
            };
        }
    };

    let file_path_str = file_path.to_string_lossy();
    let events = match store.get_events_for_file(&file_path_str) {
        Ok(e) => e,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Failed to load events: {}", e)),
            };
        }
    };

    if events.is_empty() {
        return FfiResult {
            success: false,
            message: None,
            error_message: Some("No events found for this file".to_string()),
        };
    }

    let latest = &events[events.len() - 1];
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis().min(u64::MAX as u128) as u64)
        .unwrap_or(0);

    let content_tier = match tier.to_lowercase().as_str() {
        "basic" | "core" => Some(cpop_protocol::rfc::wire_types::ContentTier::Core),
        "standard" | "enhanced" => Some(cpop_protocol::rfc::wire_types::ContentTier::Enhanced),
        "maximum" => Some(cpop_protocol::rfc::wire_types::ContentTier::Maximum),
        _ => Some(cpop_protocol::rfc::wire_types::ContentTier::Core),
    };

    let checkpoints: Vec<CheckpointWire> = match events
        .iter()
        .enumerate()
        .map(|(i, ev)| {
            let timestamp_ms = if ev.timestamp_ns < 0 {
                log::warn!(
                    "Negative timestamp_ns {} at index {i}, clamping to 0",
                    ev.timestamp_ns
                );
                0u64
            } else {
                (ev.timestamp_ns / 1_000_000) as u64
            };
            let vdf_input_bytes = ev
                .vdf_input
                .map(|b| b.to_vec())
                .unwrap_or_else(|| vec![0u8; 32]);
            let vdf_output_bytes = ev.vdf_output.map(|b| b.to_vec());
            let merkle_root = vdf_output_bytes.clone().unwrap_or_else(|| vec![0u8; 32]);

            Ok(CheckpointWire {
                sequence: i as u64,
                checkpoint_id: ev.device_id,
                timestamp: timestamp_ms,
                content_hash: HashValue::try_sha256(ev.content_hash.to_vec())?,
                char_count: ev.file_size as u64,
                delta: EditDelta {
                    chars_added: ev.size_delta.max(0) as u64,
                    // Widen to i64 before negating to avoid overflow on i32::MIN
                    chars_deleted: (-(ev.size_delta as i64)).max(0) as u64,
                    op_count: 1,
                    positions: None,
                    edit_graph_hash: None,
                    cursor_trajectory_histogram: None,
                    revision_depth_histogram: None,
                    pause_duration_histogram: None,
                },
                prev_hash: HashValue::try_sha256(ev.previous_hash.to_vec())?,
                checkpoint_hash: HashValue::try_sha256(ev.event_hash.to_vec())?,
                process_proof: ProcessProof {
                    algorithm: ProofAlgorithm::SwfSha256,
                    params: ProofParams {
                        time_cost: 0,
                        memory_cost: 0,
                        parallelism: 1,
                        steps: ev.vdf_iterations,
                        waypoint_interval: None,
                        waypoint_memory: None,
                    },
                    input: vdf_input_bytes,
                    merkle_root,
                    sampled_proofs: vec![],
                    claimed_duration: 0,
                },
                jitter_binding: None,
                physical_state: None,
                entangled_mac: None,
                receipts: None,
                active_probes: None,
                hat_proof: None,
                beacon_anchor: None,
                verifier_nonce: None,
            })
        })
        .collect::<Result<Vec<_>, String>>()
    {
        Ok(c) => c,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Invalid hash in event data: {e}")),
            };
        }
    };

    let doc_content_hash = match HashValue::try_sha256(latest.content_hash.to_vec()) {
        Ok(h) => h,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Invalid document content hash: {e}")),
            };
        }
    };

    let wire_packet = EvidencePacketWire {
        version: 1,
        profile_uri: "urn:ietf:params:rats:eat:profile:pop:1.0".to_string(),
        packet_id: latest.device_id,
        created: now_ms,
        document: DocumentRef {
            content_hash: doc_content_hash,
            filename: file_path
                .file_name()
                .and_then(|n| n.to_str())
                .map(|s| s.to_string()),
            byte_length: latest.file_size as u64,
            char_count: latest.file_size as u64,
            salt_mode: None,
            salt_commitment: None,
        },
        checkpoints,
        attestation_tier: Some(detect_attestation_tier()),
        limitations: None,
        profile: None,
        presence_challenges: None,
        channel_binding: None,
        content_tier,
        previous_packet_ref: None,
        packet_sequence: None,
        physical_liveness: None,
        baseline_verification: None,
    };

    match wire_packet.encode_cbor() {
        Ok(encoded) => {
            let tmp_path = output_path.with_extension("tmp");
            let write_result = (|| -> std::io::Result<()> {
                let mut f = std::fs::File::create(&tmp_path)?;
                std::io::Write::write_all(&mut f, &encoded)?;
                f.sync_all()?;
                std::fs::rename(&tmp_path, &output_path)?;
                Ok(())
            })();
            match write_result {
                Ok(()) => FfiResult {
                    success: true,
                    message: Some(format!("Exported CBOR to {}", output_path.display())),
                    error_message: None,
                },
                Err(e) => {
                    let _ = std::fs::remove_file(&tmp_path);
                    FfiResult {
                        success: false,
                        message: None,
                        error_message: Some(format!("Failed to write output: {}", e)),
                    }
                }
            }
        }
        Err(e) => FfiResult {
            success: false,
            message: None,
            error_message: Some(format!("Failed to encode CBOR packet: {}", e)),
        },
    }
}

/// Return a compact reference string for the latest event on a tracked file.
/// Link a derivative export (PDF, EPUB, DOCX, etc.) to a tracked source document.
///
/// Creates a "derivative" context event in the source's evidence chain that
/// binds the export hash, path, and optional message. The binding is VDF-timed
/// to prove temporal ordering.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_link_derivative(source_path: String, export_path: String, message: String) -> FfiResult {
    let source = match crate::sentinel::helpers::validate_path(&source_path) {
        Ok(p) => p,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Invalid source path: {e}")),
            };
        }
    };
    let export = match crate::sentinel::helpers::validate_path(&export_path) {
        Ok(p) => p,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Invalid export path: {e}")),
            };
        }
    };

    if !source.exists() {
        return FfiResult {
            success: false,
            message: None,
            error_message: Some(format!("Source file not found: {}", source.display())),
        };
    }
    if !export.exists() {
        return FfiResult {
            success: false,
            message: None,
            error_message: Some(format!("Export file not found: {}", export.display())),
        };
    }

    let mut store = match open_store() {
        Ok(s) => s,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(e),
            };
        }
    };

    let source_str = source.to_string_lossy().to_string();
    let events = match store.get_events_for_file(&source_str) {
        Ok(e) => e,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Failed to load events: {e}")),
            };
        }
    };

    if events.is_empty() {
        return FfiResult {
            success: false,
            message: None,
            error_message: Some("No evidence chain for source. Track the file first.".to_string()),
        };
    }

    for (label, p) in [("Export", &export), ("Source", &source)] {
        match std::fs::metadata(p) {
            Ok(m) if m.len() > crate::MAX_FILE_SIZE => {
                return FfiResult {
                    success: false,
                    message: None,
                    error_message: Some(format!(
                        "{} file too large ({:.0} MB, max {} MB)",
                        label,
                        m.len() as f64 / 1_000_000.0,
                        crate::MAX_FILE_SIZE / 1_000_000
                    )),
                };
            }
            Err(e) => {
                return FfiResult {
                    success: false,
                    message: None,
                    error_message: Some(format!("{} file metadata error: {e}", label)),
                };
            }
            _ => {}
        }
    }

    // Hash both files
    let export_hash = match crate::crypto::hash_file(&export) {
        Ok(h) => h,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Failed to hash export: {e}")),
            };
        }
    };
    let content_hash = match crate::crypto::hash_file(&source) {
        Ok(h) => h,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Failed to hash source: {e}")),
            };
        }
    };

    let file_size = std::fs::metadata(&source)
        .map(|m| m.len() as i64)
        .unwrap_or(0);

    let note = if message.is_empty() {
        format!(
            "Derived from {}",
            source.file_name().unwrap_or_default().to_string_lossy()
        )
    } else {
        message
    };
    let context_note = format!(
        "export_hash={};export_path={};{}",
        hex::encode(export_hash),
        export.to_string_lossy(),
        note
    );

    let last = &events[events.len() - 1];
    let size_delta = (file_size - last.file_size).clamp(i32::MIN as i64, i32::MAX as i64) as i32;
    let vdf_input = last.event_hash;

    // Load VDF params
    let data_dir =
        crate::ffi::helpers::get_data_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
    let config = crate::config::CpopConfig::load_or_default(&data_dir).unwrap_or_default();
    let vdf_params = crate::vdf::params::Parameters {
        iterations_per_second: config.vdf.iterations_per_second.max(1),
        min_iterations: config.vdf.min_iterations,
        max_iterations: config.vdf.max_iterations,
    };

    let vdf_proof =
        match crate::vdf::compute(vdf_input, std::time::Duration::from_secs(1), vdf_params) {
            Ok(p) => p,
            Err(e) => {
                return FfiResult {
                    success: false,
                    message: None,
                    error_message: Some(format!("VDF computation failed: {e}")),
                };
            }
        };

    let mut event = crate::store::SecureEvent {
        id: None,
        device_id: [0u8; 16],
        machine_id: String::new(),
        timestamp_ns: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos().min(i64::MAX as u128) as i64)
            .unwrap_or(0),
        file_path: source_str.clone(),
        content_hash,
        file_size,
        size_delta,
        previous_hash: [0u8; 32],
        event_hash: [0u8; 32],
        context_type: Some("derivative".to_string()),
        context_note: Some(context_note),
        vdf_input: Some(vdf_input),
        vdf_output: Some(vdf_proof.output),
        vdf_iterations: vdf_proof.iterations,
        forensic_score: 1.0,
        is_paste: false,
        hardware_counter: None,
        input_method: None,
    };

    match store.add_secure_event(&mut event) {
        Ok(_) => FfiResult {
            success: true,
            message: Some(format!(
                "Linked {} to evidence chain (hash: {}...)",
                export.file_name().unwrap_or_default().to_string_lossy(),
                hex::encode(&export_hash[..8])
            )),
            error_message: None,
        },
        Err(e) => FfiResult {
            success: false,
            message: None,
            error_message: Some(format!("Failed to save link event: {e}")),
        },
    }
}

/// Return a compact reference string for the latest event on a tracked file.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_compact_ref(path: String) -> String {
    let path = match crate::sentinel::helpers::validate_path(&path) {
        Ok(p) => p.to_string_lossy().to_string(),
        Err(_) => return String::new(),
    };

    let store = match open_store() {
        Ok(s) => s,
        Err(_) => return String::new(),
    };

    let events = match store.get_events_for_file(&path) {
        Ok(e) => e,
        Err(_) => return String::new(),
    };

    if events.is_empty() {
        return String::new();
    }

    let last_event = &events[events.len() - 1];
    let hash_hex = hex::encode(last_event.event_hash);

    format!(
        "pop-ref:writerslogic:{}:{}",
        &hash_hex[..hash_hex.len().min(12)],
        events.len()
    )
}

/// Create a manual checkpoint for a file, hashing its current content.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_create_checkpoint(path: String, message: String) -> FfiResult {
    let file_path = match crate::sentinel::helpers::validate_path(&path) {
        Ok(p) => p,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(e),
            };
        }
    };

    let mut store = match open_store() {
        Ok(s) => s,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(e),
            };
        }
    };

    let content_hash = match crate::crypto::hash_file(&file_path) {
        Ok(h) => h,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Failed to hash file: {}", e)),
            };
        }
    };

    let file_size = std::fs::metadata(&file_path)
        .map(|m| m.len() as i64)
        .unwrap_or(0);

    let context_note = if message.is_empty() {
        None
    } else {
        Some(message)
    };

    let mut event = crate::store::SecureEvent {
        id: None,
        device_id: [0u8; 16],
        machine_id: String::new(),
        timestamp_ns: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos().min(i64::MAX as u128) as i64)
            .unwrap_or(0),
        // Use canonicalized path so export/log lookups match
        file_path: file_path.to_string_lossy().to_string(),
        content_hash,
        file_size,
        size_delta: 0,
        previous_hash: [0u8; 32],
        event_hash: [0u8; 32],
        context_type: None,
        context_note,
        vdf_input: None,
        vdf_output: None,
        vdf_iterations: 0,
        forensic_score: 0.0,
        is_paste: false,
        hardware_counter: None,
        input_method: None,
    };

    match store.add_secure_event(&mut event) {
        Ok(_) => FfiResult {
            success: true,
            message: Some(format!(
                "Checkpoint created: {}",
                hex::encode(&content_hash[..8])
            )),
            error_message: None,
        },
        Err(e) => FfiResult {
            success: false,
            message: None,
            error_message: Some(format!("Failed to create checkpoint: {}", e)),
        },
    }
}

/// Export a C2PA sidecar manifest (.c2pa) for an evidence packet.
///
/// The manifest contains a signed claim binding the PoP evidence to the
/// original document, with standard `c2pa.actions` and custom `org.pop.evidence`
/// assertions in JUMBF format per ISO 19566-5.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_export_c2pa_manifest(
    evidence_path: String,
    document_path: String,
    output_path: String,
) -> FfiResult {
    let evidence_file = match crate::sentinel::helpers::validate_path(&evidence_path) {
        Ok(p) => p,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Invalid evidence path: {e}")),
            };
        }
    };
    let doc_file = match crate::sentinel::helpers::validate_path(&document_path) {
        Ok(p) => p,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Invalid document path: {e}")),
            };
        }
    };
    let out_file = match crate::sentinel::helpers::validate_path(&output_path) {
        Ok(p) => p,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Invalid output path: {e}")),
            };
        }
    };

    if !evidence_file.exists() {
        return FfiResult {
            success: false,
            message: None,
            error_message: Some(format!(
                "Evidence file not found: {}",
                evidence_file.display()
            )),
        };
    }
    const MAX_EVIDENCE_FILE_SIZE: u64 = 100_000_000;
    match std::fs::metadata(&evidence_file) {
        Ok(m) if m.len() > MAX_EVIDENCE_FILE_SIZE => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!(
                    "Evidence file too large: {} bytes (max {})",
                    m.len(),
                    MAX_EVIDENCE_FILE_SIZE
                )),
            };
        }
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Cannot stat evidence file: {e}")),
            };
        }
        _ => {}
    }
    if !doc_file.exists() {
        return FfiResult {
            success: false,
            message: None,
            error_message: Some(format!("Document not found: {}", doc_file.display())),
        };
    }

    let evidence_bytes = match std::fs::read(&evidence_file) {
        Ok(b) => b,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Failed to read evidence: {e}")),
            };
        }
    };

    let evidence_packet = match decode_evidence_for_c2pa(&evidence_bytes) {
        Ok(p) => p,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Failed to decode evidence: {e}")),
            };
        }
    };

    let doc_hash = match crate::crypto::hash_file(&doc_file) {
        Ok(h) => h,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Failed to hash document: {e}")),
            };
        }
    };

    let doc_filename = doc_file
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_string());
    let doc_title = doc_filename.clone();

    let mut builder =
        cpop_protocol::c2pa::C2paManifestBuilder::new(evidence_packet, evidence_bytes, doc_hash);
    if let Some(ref name) = doc_filename {
        builder = builder.document_filename(name);
    }
    if let Some(ref title) = doc_title {
        builder = builder.title(title);
    }

    let provider = crate::tpm::detect_provider();
    let signer = crate::tpm::TpmSigner::new(provider);

    let jumbf = match builder.build_jumbf(&signer) {
        Ok(j) => j,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Failed to build C2PA manifest: {e}")),
            };
        }
    };

    // Atomic write: tempfile + fsync + rename
    let parent = out_file
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    match tempfile::NamedTempFile::new_in(parent) {
        Ok(mut tmp) => {
            use std::io::Write;
            if let Err(e) = tmp.write_all(&jumbf).and_then(|_| tmp.as_file().sync_all()) {
                return FfiResult {
                    success: false,
                    message: None,
                    error_message: Some(format!("Failed to write C2PA manifest: {e}")),
                };
            }
            match tmp.persist(&out_file) {
                Ok(_) => FfiResult {
                    success: true,
                    message: Some(format!(
                        "C2PA manifest exported to {} ({} bytes)",
                        out_file.display(),
                        jumbf.len()
                    )),
                    error_message: None,
                },
                Err(e) => FfiResult {
                    success: false,
                    message: None,
                    error_message: Some(format!("Failed to persist C2PA manifest: {e}")),
                },
            }
        }
        Err(e) => FfiResult {
            success: false,
            message: None,
            error_message: Some(format!("Failed to create temp file for C2PA manifest: {e}")),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::system::ffi_init;
    use tempfile::TempDir;

    fn setup_temp_data_dir() -> TempDir {
        let dir = TempDir::new().expect("create temp dir");
        std::env::set_var("CPOP_DATA_DIR", dir.path());
        dir
    }

    #[test]
    fn checkpoint_success_returns_hash() {
        let _lock = crate::ffi::helpers::lock_ffi_env();
        let dir = setup_temp_data_dir();

        let init = ffi_init();
        assert!(init.success, "init failed: {:?}", init.error_message);

        let file_path = dir.path().join("doc.txt");
        std::fs::write(&file_path, "Hello, CPOP!").expect("write test file");

        let result = ffi_create_checkpoint(file_path.to_string_lossy().to_string(), String::new());
        assert!(
            result.success,
            "checkpoint failed: {:?}",
            result.error_message
        );
        // Message should contain the hex-encoded content hash prefix.
        let msg = result.message.unwrap();
        assert!(
            msg.starts_with("Checkpoint created:"),
            "unexpected message: {msg}"
        );
    }

    #[test]
    fn checkpoint_missing_file_returns_error() {
        let _lock = crate::ffi::helpers::lock_ffi_env();
        let dir = setup_temp_data_dir();

        let init = ffi_init();
        assert!(init.success);

        let bogus = dir.path().join("nonexistent.txt");
        let result = ffi_create_checkpoint(bogus.to_string_lossy().to_string(), String::new());
        assert!(!result.success);
        assert!(result.error_message.is_some());
    }

    #[test]
    fn checkpoint_with_tool_declaration_message() {
        let _lock = crate::ffi::helpers::lock_ffi_env();
        let dir = setup_temp_data_dir();

        let init = ffi_init();
        assert!(init.success, "init failed: {:?}", init.error_message);

        let file_path = dir.path().join("assisted.txt");
        std::fs::write(&file_path, "Content created with AI tools").expect("write file");

        let result = ffi_create_checkpoint(
            file_path.to_string_lossy().to_string(),
            "[tool:ai:ChatGPT]".to_string(),
        );
        assert!(
            result.success,
            "checkpoint with tool declaration failed: {:?}",
            result.error_message
        );
    }

    #[test]
    fn compact_ref_empty_before_checkpoint() {
        let _lock = crate::ffi::helpers::lock_ffi_env();
        let dir = setup_temp_data_dir();

        let init = ffi_init();
        assert!(init.success);

        let file_path = dir.path().join("no_checkpoints.txt");
        std::fs::write(&file_path, "nothing yet").expect("write file");

        let compact = ffi_get_compact_ref(file_path.to_string_lossy().to_string());
        assert!(
            compact.is_empty(),
            "expected empty compact ref, got: {compact}"
        );
    }

    #[test]
    fn compact_ref_nonempty_after_checkpoint() {
        let _lock = crate::ffi::helpers::lock_ffi_env();
        let _data_dir = setup_temp_data_dir();

        let init = ffi_init();
        assert!(init.success);

        // Use a separate temp file outside the data dir to avoid path canonicalization issues
        let file_dir = TempDir::new().expect("create file dir");
        let file_path = file_dir.path().join("tracked.txt");
        std::fs::write(&file_path, "tracked content").expect("write file");

        let canonical = file_path.canonicalize().expect("canonicalize");
        let path_str = canonical.to_string_lossy().to_string();

        let cp = ffi_create_checkpoint(path_str.clone(), "initial".to_string());
        assert!(cp.success, "checkpoint failed: {:?}", cp.error_message);

        let compact = ffi_get_compact_ref(path_str);
        assert!(
            compact.starts_with("pop-ref:writerslogic:"),
            "expected compact ref prefix, got: {compact}"
        );
    }
}

/// Decode evidence bytes into the protocol-level EvidencePacket for C2PA.
///
/// Returns an error if any hash field fails to decode — never silently
/// substitutes zero-filled hashes, which would produce a corrupt manifest.
fn decode_evidence_for_c2pa(
    data: &[u8],
) -> std::result::Result<cpop_protocol::rfc::EvidencePacket, String> {
    let packet = crate::evidence::Packet::decode(data)
        .map_err(|e| format!("Evidence decode failed: {e}"))?;

    let mut checkpoints = Vec::with_capacity(packet.checkpoints.len());
    for (i, cp) in packet.checkpoints.iter().enumerate() {
        let ctx = |field: &str, e: &hex::FromHexError| {
            format!("checkpoint[{i}].{field}: invalid hex: {e}")
        };

        let hash_bytes = hex::decode(&cp.hash).map_err(|e| ctx("hash", &e))?;
        let checkpoint_id: Vec<u8> = hash_bytes.iter().copied().take(16).collect();

        checkpoints.push(cpop_protocol::rfc::Checkpoint {
            sequence: cp.ordinal,
            checkpoint_id,
            timestamp: cp.timestamp.timestamp_millis() as u64,
            content_hash: cpop_protocol::rfc::HashValue {
                algorithm: cpop_protocol::rfc::HashAlgorithm::Sha256,
                digest: hex::decode(&cp.content_hash).map_err(|e| ctx("content_hash", &e))?,
            },
            char_count: cp.content_size,
            prev_hash: cpop_protocol::rfc::HashValue {
                algorithm: cpop_protocol::rfc::HashAlgorithm::Sha256,
                digest: hex::decode(&cp.previous_hash).map_err(|e| ctx("previous_hash", &e))?,
            },
            checkpoint_hash: cpop_protocol::rfc::HashValue {
                algorithm: cpop_protocol::rfc::HashAlgorithm::Sha256,
                digest: hash_bytes,
            },
            jitter_hash: None,
        });
    }

    let doc = &packet.document;
    let doc_hash = hex::decode(&doc.final_hash)
        .map_err(|e| format!("document.final_hash: invalid hex: {e}"))?;

    let packet_id = {
        use sha2::{Digest, Sha256};
        let full_hash = Sha256::digest(data);
        full_hash[..16].to_vec()
    };

    Ok(cpop_protocol::rfc::EvidencePacket {
        version: 1,
        profile_uri: "urn:ietf:params:rats:eat:profile:pop:1.0".to_string(),
        packet_id,
        created: chrono::Utc::now().timestamp_millis() as u64,
        document: cpop_protocol::rfc::DocumentRef {
            content_hash: cpop_protocol::rfc::HashValue {
                algorithm: cpop_protocol::rfc::HashAlgorithm::Sha256,
                digest: doc_hash,
            },
            filename: Some(doc.title.clone()),
            byte_length: doc.final_size,
            char_count: doc.final_size,
        },
        checkpoints,
        attestation_tier: None,
        baseline_verification: None,
    })
}
