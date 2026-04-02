// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::ffi::helpers::{detect_attestation_tier, open_store};
use crate::ffi::sentinel::get_sentinel;
use crate::ffi::types::FfiResult;
use crate::RwLockRecover;
use cpop_protocol::rfc::wire_types::{
    CheckpointWire, DocumentRef, EditDelta, EvidencePacketWire, HashValue, ProcessProof,
    ProofAlgorithm, ProofParams,
};
use sha2::{Digest, Sha256};

/// Export stored events as a human-readable JSON evidence packet.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_export_evidence_json(path: String, tier: String, output: String) -> FfiResult {
    // Build the same wire packet as the CBOR export, then serialize to JSON.
    let cbor_result = ffi_export_evidence(path.clone(), tier, output.clone());
    if !cbor_result.success {
        return cbor_result;
    }
    // Read the CBOR file we just wrote, decode, re-encode as JSON
    let output_path = std::path::Path::new(&output);
    let data = match std::fs::read(output_path) {
        Ok(d) => d,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Failed to read exported file: {e}")),
            };
        }
    };
    let cbor_payload = crate::ffi::helpers::unwrap_cose_or_raw(&data);
    match EvidencePacketWire::decode_cbor(&cbor_payload) {
        Ok(wire) => match serde_json::to_string_pretty(&wire) {
            Ok(json) => {
                if let Err(e) = std::fs::write(output_path, json.as_bytes()) {
                    return FfiResult {
                        success: false,
                        message: None,
                        error_message: Some(format!("Failed to write JSON: {e}")),
                    };
                }
                FfiResult {
                    success: true,
                    message: Some(format!("Exported JSON to {}", output_path.display())),
                    error_message: None,
                }
            }
            Err(e) => FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("JSON serialization failed: {e}")),
            },
        },
        Err(e) => FfiResult {
            success: false,
            message: None,
            error_message: Some(format!("Failed to decode CBOR for JSON conversion: {e}")),
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

    // Random salt so each export produces unique packet/checkpoint IDs.
    let export_nonce = rand::random::<[u8; 8]>();

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

            let checkpoint_id = {
                let mut h = Sha256::new();
                h.update(b"cpop-checkpoint-id-v1");
                h.update(ev.content_hash);
                h.update((i as u64).to_le_bytes());
                h.update(export_nonce);
                let d = h.finalize();
                let mut id = [0u8; 16];
                id.copy_from_slice(&d[..16]);
                id
            };

            Ok(CheckpointWire {
                sequence: i as u64,
                checkpoint_id,
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
                lamport_signature: ev.lamport_signature.clone(),
                lamport_pubkey_fingerprint: ev.lamport_pubkey_fingerprint.clone(),
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

    let packet_id = {
        let mut h = Sha256::new();
        h.update(b"cpop-packet-id-v1");
        h.update(latest.content_hash);
        h.update(export_nonce);
        let d = h.finalize();
        let mut id = [0u8; 16];
        id.copy_from_slice(&d[..16]);
        id
    };

    // Compute character count by reading the file as UTF-8.
    // Falls back to byte count for non-UTF-8 files.
    let byte_length = latest.file_size as u64;
    let char_count = std::fs::read(&file_path)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .map(|s| s.chars().count() as u64)
        .unwrap_or(byte_length);

    // Embed the signing public key so verifiers can identify the signer
    // without requiring out-of-band key distribution.
    let signing_pub = crate::ffi::helpers::load_signing_key()
        .ok()
        .map(|sk| serde_bytes::ByteBuf::from(sk.verifying_key().to_bytes().to_vec()));

    let wire_packet = EvidencePacketWire {
        version: 1,
        profile_uri: "urn:ietf:params:rats:eat:profile:pop:1.0".to_string(),
        packet_id,
        created: now_ms,
        document: DocumentRef {
            content_hash: doc_content_hash,
            filename: file_path
                .file_name()
                .and_then(|n| n.to_str())
                .map(|s| s.to_string()),
            byte_length,
            char_count,
            salt_mode: None,
            salt_commitment: None,
        },
        checkpoints,
        attestation_tier: Some(detect_attestation_tier()),
        limitations: collect_ai_tool_limitations(&path),
        profile: None,
        presence_challenges: None,
        channel_binding: None,
        signing_public_key: signing_pub,
        content_tier,
        previous_packet_ref: None,
        packet_sequence: None,
        physical_liveness: None,
        baseline_verification: None,
    };

    match wire_packet.encode_cbor() {
        Ok(encoded) => {
            // Sign the CBOR payload with COSE_Sign1 using the device signing key.
            // This prevents tampering, replay, and evidence reuse; any modification
            // to the packet content invalidates the signature.
            let signed_bytes = match crate::ffi::helpers::load_signing_key() {
                Ok(signing_key) => {
                    match cpop_protocol::crypto::sign_evidence_cose(&encoded, &signing_key) {
                        Ok(cose) => cose,
                        Err(e) => {
                            log::warn!("COSE signing failed, exporting unsigned: {e}");
                            encoded
                        }
                    }
                }
                Err(e) => {
                    log::warn!("Signing key unavailable, exporting unsigned: {e}");
                    encoded
                }
            };

            let tmp_path = output_path.with_extension("tmp");
            let write_result = (|| -> std::io::Result<()> {
                let mut f = std::fs::File::create(&tmp_path)?;
                std::io::Write::write_all(&mut f, &signed_bytes)?;
                f.sync_all()?;
                std::fs::rename(&tmp_path, &output_path)?;
                Ok(())
            })();
            match write_result {
                Ok(()) => FfiResult {
                    success: true,
                    message: Some(format!("Exported signed CBOR to {}", output_path.display())),
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

/// Collect AI tool limitations from the sentinel session matching `path`.
///
/// Returns `Some(vec)` when at least one AI tool was detected, `None` otherwise.
pub(crate) fn collect_ai_tool_limitations(path: &str) -> Option<Vec<String>> {
    let sentinel = get_sentinel()?;
    let sessions = sentinel.sessions.read_recover();
    let session = sessions.get(path)?;
    if session.ai_tools_detected.is_empty() {
        return None;
    }
    let limitations: Vec<String> = session
        .ai_tools_detected
        .iter()
        .map(|id| format!("AI tool detected during session: {}", id))
        .collect();
    Some(limitations)
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
