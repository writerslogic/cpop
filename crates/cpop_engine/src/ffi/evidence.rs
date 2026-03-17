// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::ffi::helpers::{detect_attestation_tier, detect_attestation_tier_info, open_store};
use crate::ffi::types::{FfiResult, FfiVerifyResult};
use crate::rfc::wire_types::{
    CheckpointWire, DocumentRef, EditDelta, EvidencePacketWire, HashValue, ProcessProof,
    ProofAlgorithm, ProofParams,
};

/// Verify an evidence packet at the given path and return integrity results.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_verify_evidence(path: String) -> FfiVerifyResult {
    let (_, tier_num, tier_label) = detect_attestation_tier_info();

    let path = match crate::sentinel::helpers::validate_path(&path) {
        Ok(p) => p,
        Err(e) => {
            return FfiVerifyResult {
                success: false,
                checkpoint_count: 0,
                signature_valid: false,
                chain_integrity: false,
                swf_iterations_per_second: 0,
                attestation_tier: tier_num,
                attestation_tier_label: tier_label,
                error_message: Some(e),
            };
        }
    };

    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) => {
            return FfiVerifyResult {
                success: false,
                checkpoint_count: 0,
                signature_valid: false,
                chain_integrity: false,
                swf_iterations_per_second: 0,
                attestation_tier: tier_num,
                attestation_tier_label: tier_label,
                error_message: Some(format!("Failed to read file: {}", e)),
            };
        }
    };

    let packet = match crate::evidence::Packet::decode(&data) {
        Ok(p) => p,
        Err(e) => {
            return FfiVerifyResult {
                success: false,
                checkpoint_count: 0,
                signature_valid: false,
                chain_integrity: false,
                swf_iterations_per_second: 0,
                attestation_tier: tier_num,
                attestation_tier_label: tier_label,
                error_message: Some(format!("Failed to decode evidence: {}", e)),
            };
        }
    };

    let checkpoint_count = packet.checkpoints.len() as u32;
    let vdf_ips = packet.vdf_params.iterations_per_second;

    match packet.verify(packet.vdf_params) {
        Ok(()) => FfiVerifyResult {
            success: true,
            checkpoint_count,
            signature_valid: true,
            chain_integrity: true,
            swf_iterations_per_second: vdf_ips,
            attestation_tier: tier_num,
            attestation_tier_label: tier_label,
            error_message: None,
        },
        Err(e) => FfiVerifyResult {
            success: false,
            checkpoint_count,
            signature_valid: false,
            chain_integrity: false,
            swf_iterations_per_second: vdf_ips,
            attestation_tier: tier_num,
            attestation_tier_label: tier_label,
            error_message: Some(format!("Verification failed: {}", e)),
        },
    }
}

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

    let events = match store.get_events_for_file(&path) {
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
        "basic" | "core" => Some(crate::rfc::wire_types::ContentTier::Core),
        "standard" | "enhanced" => Some(crate::rfc::wire_types::ContentTier::Enhanced),
        "maximum" => Some(crate::rfc::wire_types::ContentTier::Maximum),
        _ => Some(crate::rfc::wire_types::ContentTier::Core),
    };

    let checkpoints: Vec<CheckpointWire> = match events
        .iter()
        .enumerate()
        .map(|(i, ev)| {
            let timestamp_ms = (ev.timestamp_ns.max(0) / 1_000_000) as u64;
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
        profile_uri: "urn:ietf:params:pop:profile:1.0".to_string(),
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
        Ok(encoded) => match std::fs::write(&output_path, &encoded) {
            Ok(()) => FfiResult {
                success: true,
                message: Some(format!("Exported CBOR to {}", output_path.display())),
                error_message: None,
            },
            Err(e) => FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Failed to write output: {}", e)),
            },
        },
        Err(e) => FfiResult {
            success: false,
            message: None,
            error_message: Some(format!("Failed to encode CBOR packet: {}", e)),
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
        "writerslogic:{}:{}",
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
        file_path: path.clone(),
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

    match std::fs::write(&out_file, &jumbf) {
        Ok(()) => FfiResult {
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
            error_message: Some(format!("Failed to write C2PA manifest: {e}")),
        },
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
        profile_uri: "urn:ietf:params:pop:profile:1.0".to_string(),
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
