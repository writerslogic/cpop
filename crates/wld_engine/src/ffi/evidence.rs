// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::ffi::helpers::{detect_attestation_tier, detect_attestation_tier_info, open_store};
use crate::ffi::types::{FfiResult, FfiVerifyResult};
use crate::rfc::wire_types::{
    CheckpointWire, DocumentRef, EditDelta, EvidencePacketWire, HashValue, ProcessProof,
    ProofAlgorithm, ProofParams,
};

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

    let checkpoints: Vec<CheckpointWire> = events
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

            CheckpointWire {
                sequence: i as u64,
                checkpoint_id: ev.device_id,
                timestamp: timestamp_ms,
                content_hash: HashValue::sha256(ev.content_hash.to_vec()),
                char_count: ev.file_size as u64,
                delta: EditDelta {
                    chars_added: ev.size_delta.max(0) as u64,
                    // Widen to i64 before negating to avoid overflow on i32::MIN
                    chars_deleted: (-(ev.size_delta as i64)).max(0) as u64,
                    op_count: 1,
                    positions: None,
                },
                prev_hash: HashValue::sha256(ev.previous_hash.to_vec()),
                checkpoint_hash: HashValue::sha256(ev.event_hash.to_vec()),
                process_proof: ProcessProof {
                    algorithm: ProofAlgorithm::SwfSha256,
                    params: ProofParams {
                        time_cost: 0,
                        memory_cost: 0,
                        parallelism: 1,
                        iterations: ev.vdf_iterations,
                    },
                    input: vdf_input_bytes,
                    merkle_root,
                    sampled_proofs: vec![],
                    claimed_duration: 0,
                },
                jitter_binding: None,
                physical_state: None,
                entangled_mac: None,
                self_receipts: None,
                active_probes: None,
            }
        })
        .collect();

    let wire_packet = EvidencePacketWire {
        version: 1,
        profile_uri: "urn:ietf:params:rats:eat:profile:pop:1.0".to_string(),
        packet_id: latest.device_id,
        created: now_ms,
        document: DocumentRef {
            content_hash: HashValue::sha256(latest.content_hash.to_vec()),
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
    };

    match store.insert_secure_event(&mut event) {
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
