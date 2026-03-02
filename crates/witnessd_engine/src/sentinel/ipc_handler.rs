// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::core::Sentinel;
use crate::ipc::{IpcErrorCode, IpcMessage, IpcMessageHandler};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// IPC message handler that routes messages to a Sentinel instance.
pub struct SentinelIpcHandler {
    sentinel: Arc<Sentinel>,
    start_time: SystemTime,
    version: String,
}

impl SentinelIpcHandler {
    /// Create a new IPC handler for a Sentinel instance.
    pub fn new(sentinel: Arc<Sentinel>) -> Self {
        Self {
            sentinel,
            start_time: SystemTime::now(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

impl IpcMessageHandler for SentinelIpcHandler {
    fn handle(&self, msg: IpcMessage) -> IpcMessage {
        match msg {
            IpcMessage::Handshake { version } => {
                // Check version compatibility (for now, just acknowledge)
                IpcMessage::HandshakeAck {
                    version,
                    server_version: self.version.clone(),
                }
            }

            IpcMessage::Heartbeat => {
                let timestamp_ns = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_nanos() as u64)
                    .unwrap_or(0);
                IpcMessage::HeartbeatAck { timestamp_ns }
            }

            IpcMessage::StartWitnessing { file_path } => {
                let file_path = match super::helpers::validate_path(&file_path) {
                    Ok(p) => p,
                    Err(e) => {
                        return IpcMessage::Error {
                            code: IpcErrorCode::PermissionDenied,
                            message: format!("Invalid path: {}", e),
                        };
                    }
                };
                match self.sentinel.start_witnessing(&file_path) {
                    Ok(()) => IpcMessage::Ok {
                        message: Some(format!("Now tracking: {}", file_path.display())),
                    },
                    Err((code, message)) => IpcMessage::Error { code, message },
                }
            }

            IpcMessage::StopWitnessing { file_path } => {
                match file_path {
                    Some(path) => {
                        let path = match super::helpers::validate_path(&path) {
                            Ok(p) => p,
                            Err(e) => {
                                return IpcMessage::Error {
                                    code: IpcErrorCode::PermissionDenied,
                                    message: format!("Invalid path: {}", e),
                                };
                            }
                        };
                        match self.sentinel.stop_witnessing(&path) {
                            Ok(()) => IpcMessage::Ok {
                                message: Some(format!("Stopped tracking: {}", path.display())),
                            },
                            Err((code, message)) => IpcMessage::Error { code, message },
                        }
                    }
                    None => {
                        // Stop all witnessing - for now just return an error
                        // as we don't want to accidentally stop all tracking
                        IpcMessage::Error {
                            code: IpcErrorCode::InvalidMessage,
                            message: "Must specify a file path to stop witnessing".to_string(),
                        }
                    }
                }
            }

            IpcMessage::GetStatus => {
                let tracked_files = self.sentinel.tracked_files();
                let uptime_secs = self.start_time.elapsed().map(|d| d.as_secs()).unwrap_or(0);

                IpcMessage::StatusResponse {
                    running: self.sentinel.is_running(),
                    tracked_files,
                    uptime_secs,
                }
            }

            // Nonce protocol: Get attestation nonce for current session
            IpcMessage::GetAttestationNonce => {
                let nonce = self.sentinel.get_or_generate_nonce();
                IpcMessage::AttestationNonceResponse { nonce }
            }

            // Nonce protocol: Export evidence with verifier-provided nonce binding
            IpcMessage::ExportWithNonce {
                file_path,
                title: _,
                verifier_nonce,
            } => {
                let file_path = match super::helpers::validate_path(&file_path) {
                    Ok(p) => p,
                    Err(e) => {
                        return IpcMessage::NonceExportResponse {
                            success: false,
                            output_path: None,
                            packet_hash: None,
                            verifier_nonce: None,
                            attestation_nonce: None,
                            attestation_report: None,
                            error: Some(format!("Invalid path: {}", e)),
                        };
                    }
                };
                let db_path = self.sentinel.config.witnessd_dir.join("events.db");
                let key_bytes = self
                    .sentinel
                    .signing_key
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .to_bytes();
                let hmac_key = if key_bytes == [0u8; 32] {
                    log::warn!("Using zero signing key for HMAC derivation - identity may not be initialized");
                    crate::crypto::derive_hmac_key(&[0u8; 32])
                } else {
                    crate::crypto::derive_hmac_key(&key_bytes)
                };

                match crate::store::SecureStore::open(&db_path, hmac_key) {
                    Ok(db) => {
                        match db.get_events_for_file(&file_path.to_string_lossy()) {
                            Ok(events) => {
                                let evidence_hash =
                                    crate::evidence::compute_events_binding_hash(&events);
                                let attestation_nonce = self.sentinel.get_or_generate_nonce();

                                let provider = crate::tpm::detect_provider();
                                match crate::tpm::generate_attestation_report(
                                    &*provider,
                                    &verifier_nonce,
                                    &attestation_nonce,
                                    evidence_hash,
                                ) {
                                    Ok(report) => {
                                        let report_json =
                                            serde_json::to_string(&report).unwrap_or_default();
                                        IpcMessage::NonceExportResponse {
                                            success: true,
                                            output_path: None, // Direct JSON for now
                                            packet_hash: Some(hex::encode(evidence_hash)),
                                            verifier_nonce: Some(hex::encode(verifier_nonce)),
                                            attestation_nonce: Some(hex::encode(attestation_nonce)),
                                            attestation_report: Some(report_json),
                                            error: None,
                                        }
                                    }
                                    Err(e) => IpcMessage::NonceExportResponse {
                                        success: false,
                                        output_path: None,
                                        packet_hash: None,
                                        verifier_nonce: None,
                                        attestation_nonce: None,
                                        attestation_report: None,
                                        error: Some(format!("Hardware quote failed: {}", e)),
                                    },
                                }
                            }
                            Err(e) => IpcMessage::NonceExportResponse {
                                success: false,
                                output_path: None,
                                packet_hash: None,
                                verifier_nonce: None,
                                attestation_nonce: None,
                                attestation_report: None,
                                error: Some(format!("Failed to load events: {}", e)),
                            },
                        }
                    }
                    Err(e) => IpcMessage::NonceExportResponse {
                        success: false,
                        output_path: None,
                        packet_hash: None,
                        verifier_nonce: None,
                        attestation_nonce: None,
                        attestation_report: None,
                        error: Some(format!("Database error: {}", e)),
                    },
                }
            }

            // Nonce protocol: Verify evidence with expected nonce validation
            IpcMessage::VerifyWithNonce {
                evidence_path,
                expected_nonce,
            } => {
                let path = match super::helpers::validate_path(&evidence_path) {
                    Ok(p) => p,
                    Err(e) => {
                        return IpcMessage::NonceVerifyResponse {
                            valid: false,
                            nonce_valid: false,
                            checkpoint_count: 0,
                            total_elapsed_time_secs: 0.0,
                            verifier_nonce: None,
                            attestation_nonce: None,
                            errors: vec![e],
                        };
                    }
                };

                match std::fs::read(&path) {
                    Ok(data) => {
                        match crate::evidence::Packet::decode(&data) {
                            Ok(packet) => {
                                let vdf_params = packet.vdf_params;
                                let chain_ok = packet.verify(vdf_params).is_ok();
                                let sig_ok =
                                    packet.verify_signature(expected_nonce.as_ref()).is_ok();
                                let cp_count = packet.checkpoints.len() as u64;
                                let total_elapsed = packet.total_elapsed_time();
                                let total_elapsed_secs = total_elapsed.as_secs_f64();

                                // Extract nonce info from the packet
                                let pkt_verifier_nonce =
                                    packet.get_verifier_nonce().map(hex::encode);
                                let pkt_attestation_nonce = packet
                                    .hardware
                                    .as_ref()
                                    .and_then(|hw| hw.attestation_nonce)
                                    .map(hex::encode);

                                let nonce_valid =
                                    match (&expected_nonce, packet.get_verifier_nonce()) {
                                        (Some(expected), Some(actual)) => *actual == *expected,
                                        (None, None) => true,
                                        _ => false,
                                    };

                                let mut errors = Vec::new();
                                if !chain_ok {
                                    errors.push("Chain integrity verification failed".to_string());
                                }
                                if !sig_ok {
                                    errors.push("Signature verification failed (nonce mismatch or invalid signature)".to_string());
                                }
                                if !nonce_valid {
                                    errors.push(
                                        "Verifier nonce does not match expected nonce".to_string(),
                                    );
                                }

                                IpcMessage::NonceVerifyResponse {
                                    valid: chain_ok && sig_ok && nonce_valid,
                                    nonce_valid,
                                    checkpoint_count: cp_count,
                                    total_elapsed_time_secs: total_elapsed_secs,
                                    verifier_nonce: pkt_verifier_nonce,
                                    attestation_nonce: pkt_attestation_nonce,
                                    errors,
                                }
                            }
                            Err(e) => IpcMessage::NonceVerifyResponse {
                                valid: false,
                                nonce_valid: false,
                                checkpoint_count: 0,
                                total_elapsed_time_secs: 0.0,
                                verifier_nonce: None,
                                attestation_nonce: None,
                                errors: vec![format!("Failed to decode evidence: {}", e)],
                            },
                        }
                    }
                    Err(e) => IpcMessage::NonceVerifyResponse {
                        valid: false,
                        nonce_valid: false,
                        checkpoint_count: 0,
                        total_elapsed_time_secs: 0.0,
                        verifier_nonce: None,
                        attestation_nonce: None,
                        errors: vec![format!("Failed to read evidence file: {}", e)],
                    },
                }
            }

            // Response messages should not be received by the server
            IpcMessage::Ok { .. }
            | IpcMessage::Error { .. }
            | IpcMessage::HandshakeAck { .. }
            | IpcMessage::HeartbeatAck { .. }
            | IpcMessage::StatusResponse { .. }
            | IpcMessage::AttestationNonceResponse { .. }
            | IpcMessage::NonceExportResponse { .. }
            | IpcMessage::NonceVerifyResponse { .. } => IpcMessage::Error {
                code: IpcErrorCode::InvalidMessage,
                message: "Unexpected response message received as request".to_string(),
            },

            // Push events are sent from server to client, not the other way
            IpcMessage::Pulse(_)
            | IpcMessage::CheckpointCreated { .. }
            | IpcMessage::SystemAlert { .. } => IpcMessage::Error {
                code: IpcErrorCode::InvalidMessage,
                message: "Push events cannot be sent to the server".to_string(),
            },

            // P2 crypto operation: Create a manual checkpoint for a file
            IpcMessage::CreateFileCheckpoint { path, message } => {
                let witnessd_dir = &self.sentinel.config.witnessd_dir;
                let vdf_params = crate::vdf::default_parameters();

                // Derive chain path from file path
                let chain_path = match std::fs::canonicalize(&path) {
                    Ok(abs_path) => {
                        let path_hash = Sha256::digest(abs_path.to_string_lossy().as_bytes());
                        let doc_id = hex::encode(&path_hash[0..8]);
                        witnessd_dir.join("chains").join(format!("{doc_id}.json"))
                    }
                    Err(e) => {
                        return IpcMessage::CheckpointResponse {
                            success: false,
                            hash: None,
                            error: Some(format!("Failed to resolve path: {}", e)),
                        };
                    }
                };

                // Load existing chain or create new
                let mut chain = if chain_path.exists() {
                    match crate::checkpoint::Chain::load(&chain_path) {
                        Ok(c) => c,
                        Err(e) => {
                            return IpcMessage::CheckpointResponse {
                                success: false,
                                hash: None,
                                error: Some(format!("Failed to load chain: {}", e)),
                            };
                        }
                    }
                } else {
                    match crate::checkpoint::Chain::new(&path, vdf_params) {
                        Ok(c) => c,
                        Err(e) => {
                            return IpcMessage::CheckpointResponse {
                                success: false,
                                hash: None,
                                error: Some(format!("Failed to create chain: {}", e)),
                            };
                        }
                    }
                };

                match chain.commit(Some(message)) {
                    Ok(checkpoint) => {
                        if let Err(e) = chain.save(&chain_path) {
                            return IpcMessage::CheckpointResponse {
                                success: false,
                                hash: None,
                                error: Some(format!("Failed to save chain: {}", e)),
                            };
                        }
                        IpcMessage::CheckpointResponse {
                            success: true,
                            hash: Some(hex::encode(checkpoint.hash)),
                            error: None,
                        }
                    }
                    Err(e) => IpcMessage::CheckpointResponse {
                        success: false,
                        hash: None,
                        error: Some(format!("Commit failed: {}", e)),
                    },
                }
            }

            // P2 crypto operation: Verify an evidence file
            IpcMessage::VerifyFile { path } => {
                let validated_path = match super::helpers::validate_path(&path) {
                    Ok(p) => p,
                    Err(e) => {
                        return IpcMessage::VerifyFileResponse {
                            success: false,
                            checkpoint_count: 0,
                            signature_valid: false,
                            chain_integrity: false,
                            vdf_iterations_per_second: 0,
                            error: Some(e),
                        };
                    }
                };

                match std::fs::read(&validated_path) {
                    Ok(data) => match crate::evidence::Packet::decode(&data) {
                        Ok(packet) => {
                            let vdf_params = packet.vdf_params;
                            let chain_ok = packet.verify(vdf_params).is_ok();
                            let sig_ok = packet.verify_signature(None).is_ok();
                            let cp_count = packet.checkpoints.len() as u32;

                            IpcMessage::VerifyFileResponse {
                                success: chain_ok,
                                checkpoint_count: cp_count,
                                signature_valid: sig_ok,
                                chain_integrity: chain_ok,
                                vdf_iterations_per_second: vdf_params.iterations_per_second,
                                error: None,
                            }
                        }
                        Err(e) => IpcMessage::VerifyFileResponse {
                            success: false,
                            checkpoint_count: 0,
                            signature_valid: false,
                            chain_integrity: false,
                            vdf_iterations_per_second: 0,
                            error: Some(format!("Failed to decode evidence: {}", e)),
                        },
                    },
                    Err(e) => IpcMessage::VerifyFileResponse {
                        success: false,
                        checkpoint_count: 0,
                        signature_valid: false,
                        chain_integrity: false,
                        vdf_iterations_per_second: 0,
                        error: Some(format!("Failed to read file: {}", e)),
                    },
                }
            }

            // P2 crypto operation: Export evidence for a file
            IpcMessage::ExportFile {
                path,
                tier: _,
                output,
            } => {
                let witnessd_dir = &self.sentinel.config.witnessd_dir;

                // Validate paths
                let _src_path = match super::helpers::validate_path(&path) {
                    Ok(p) => p,
                    Err(e) => {
                        return IpcMessage::ExportFileResponse {
                            success: false,
                            error: Some(format!("Invalid source path: {}", e)),
                        };
                    }
                };
                let validated_output = match super::helpers::validate_path(&output) {
                    Ok(p) => p,
                    Err(e) => {
                        return IpcMessage::ExportFileResponse {
                            success: false,
                            error: Some(format!("Invalid output path: {}", e)),
                        };
                    }
                };

                // Find and load chain
                let chain = match crate::checkpoint::Chain::find_chain(&path, witnessd_dir) {
                    Ok(chain_path) => match crate::checkpoint::Chain::load(&chain_path) {
                        Ok(c) => c,
                        Err(e) => {
                            return IpcMessage::ExportFileResponse {
                                success: false,
                                error: Some(format!("Failed to load chain: {}", e)),
                            };
                        }
                    },
                    Err(e) => {
                        return IpcMessage::ExportFileResponse {
                            success: false,
                            error: Some(format!("No chain found: {}", e)),
                        };
                    }
                };

                if chain.checkpoints.is_empty() {
                    return IpcMessage::ExportFileResponse {
                        success: false,
                        error: Some("Chain has no checkpoints".to_string()),
                    };
                }

                // Build evidence packet
                let title = path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| "Untitled".to_string());
                let mut builder = crate::evidence::Builder::new(&title, &chain);

                // Create and sign a basic declaration
                let latest = chain.latest().unwrap(); // Safe: checked non-empty above
                let chain_hash_bytes = {
                    let mut arr = [0u8; 32];
                    if let Ok(bytes) = hex::decode(hex::encode(latest.hash)) {
                        if bytes.len() == 32 {
                            arr.copy_from_slice(&bytes);
                        }
                    }
                    arr
                };
                let signing_key = self
                    .sentinel
                    .signing_key
                    .read()
                    .unwrap_or_else(|e| e.into_inner());
                let decl = crate::declaration::no_ai_declaration(
                    latest.content_hash,
                    chain_hash_bytes,
                    &title,
                    "Exported via IPC",
                )
                .sign(&*signing_key);
                match decl {
                    Ok(d) => {
                        builder = builder.with_declaration(&d);
                    }
                    Err(e) => {
                        return IpcMessage::ExportFileResponse {
                            success: false,
                            error: Some(format!("Declaration signing failed: {}", e)),
                        };
                    }
                }

                // Add baseline verification data
                let summary = self
                    .sentinel
                    .activity_accumulator
                    .read()
                    .unwrap()
                    .to_session_summary();
                let mut bv = witnessd_protocol::baseline::BaselineVerification {
                    digest: None,
                    session_summary: summary,
                    digest_signature: None,
                };

                let (identity_fingerprint, hmac_key) = {
                    let signing_key = self.sentinel.signing_key.read().unwrap();
                    let mut hasher = sha2::Sha256::new();
                    hasher.update(signing_key.verifying_key().to_bytes());
                    let fingerprint = hasher.finalize().to_vec();
                    let hmac = crate::crypto::derive_hmac_key(&signing_key.to_bytes());
                    (fingerprint, hmac)
                };

                let db_path = self.sentinel.config.witnessd_dir.join("events.db");
                if let Ok(store) = crate::store::SecureStore::open(&db_path, hmac_key) {
                    if let Ok(Some((cbor, sig))) = store.get_baseline_digest(&identity_fingerprint)
                    {
                        if let Ok(digest) = serde_json::from_slice::<
                            witnessd_protocol::baseline::BaselineDigest,
                        >(&cbor)
                        {
                            bv.digest = Some(digest);
                            bv.digest_signature = Some(sig);
                        }
                    }
                }
                builder = builder.with_baseline_verification(bv);

                match builder.build() {
                    Ok(packet) => {
                        // Determine format from output extension
                        let format = if output.extension().map(|e| e == "json").unwrap_or(false) {
                            crate::codec::Format::Json
                        } else {
                            crate::codec::Format::Cbor
                        };
                        match packet.encode_with_format(format) {
                            Ok(encoded) => match std::fs::write(&validated_output, &encoded) {
                                Ok(()) => IpcMessage::ExportFileResponse {
                                    success: true,
                                    error: None,
                                },
                                Err(e) => IpcMessage::ExportFileResponse {
                                    success: false,
                                    error: Some(format!("Failed to write output: {}", e)),
                                },
                            },
                            Err(e) => IpcMessage::ExportFileResponse {
                                success: false,
                                error: Some(format!("Failed to encode packet: {}", e)),
                            },
                        }
                    }
                    Err(e) => IpcMessage::ExportFileResponse {
                        success: false,
                        error: Some(format!("Failed to build packet: {}", e)),
                    },
                }
            }

            // P2 crypto operation: Get forensic analysis for a file
            IpcMessage::GetFileForensics { path } => {
                let path = match super::helpers::validate_path(&path) {
                    Ok(p) => p,
                    Err(e) => {
                        return IpcMessage::ForensicsResponse {
                            assessment_score: 0.0,
                            risk_level: "INSUFFICIENT DATA".to_string(),
                            anomaly_count: 0,
                            monotonic_append_ratio: 0.0,
                            edit_entropy: 0.0,
                            median_interval: 0.0,
                            error: Some(format!("Invalid path: {}", e)),
                        };
                    }
                };
                let db_path = self.sentinel.config.witnessd_dir.join("events.db");
                let key_bytes = self
                    .sentinel
                    .signing_key
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .to_bytes();
                let hmac_key = if key_bytes == [0u8; 32] {
                    log::warn!("Using zero signing key for HMAC derivation - identity may not be initialized");
                    crate::crypto::derive_hmac_key(&[0u8; 32])
                } else {
                    crate::crypto::derive_hmac_key(&key_bytes)
                };

                match crate::store::SecureStore::open(&db_path, hmac_key) {
                    Ok(db) => match db.get_events_for_file(&path.to_string_lossy()) {
                        Ok(events) => {
                            if events.is_empty() {
                                return IpcMessage::ForensicsResponse {
                                    assessment_score: 0.0,
                                    risk_level: "INSUFFICIENT DATA".to_string(),
                                    anomaly_count: 0,
                                    monotonic_append_ratio: 0.0,
                                    edit_entropy: 0.0,
                                    median_interval: 0.0,
                                    error: Some("No events found for file".to_string()),
                                };
                            }

                            let event_data: Vec<crate::forensics::EventData> = events
                                .iter()
                                .enumerate()
                                .map(|(i, e)| crate::forensics::EventData {
                                    id: e.id.unwrap_or(i as i64),
                                    timestamp_ns: e.timestamp_ns,
                                    file_size: e.file_size,
                                    size_delta: e.size_delta,
                                    file_path: e.file_path.clone(),
                                })
                                .collect();

                            let regions = std::collections::HashMap::new();
                            let metrics = crate::forensics::analyze_forensics(
                                &event_data,
                                &regions,
                                None,
                                None,
                                None,
                            );

                            IpcMessage::ForensicsResponse {
                                assessment_score: metrics.assessment_score,
                                risk_level: metrics.risk_level.to_string(),
                                anomaly_count: metrics.anomaly_count as u32,
                                monotonic_append_ratio: metrics.primary.monotonic_append_ratio,
                                edit_entropy: metrics.primary.edit_entropy,
                                median_interval: metrics.primary.median_interval,
                                error: None,
                            }
                        }
                        Err(e) => IpcMessage::ForensicsResponse {
                            assessment_score: 0.0,
                            risk_level: "INSUFFICIENT DATA".to_string(),
                            anomaly_count: 0,
                            monotonic_append_ratio: 0.0,
                            edit_entropy: 0.0,
                            median_interval: 0.0,
                            error: Some(format!("Failed to load events: {}", e)),
                        },
                    },
                    Err(e) => IpcMessage::ForensicsResponse {
                        assessment_score: 0.0,
                        risk_level: "INSUFFICIENT DATA".to_string(),
                        anomaly_count: 0,
                        monotonic_append_ratio: 0.0,
                        edit_entropy: 0.0,
                        median_interval: 0.0,
                        error: Some(format!("Database error: {}", e)),
                    },
                }
            }

            // P2 crypto operation: Compute Process Score for a file
            IpcMessage::ComputeProcessScore { path } => {
                let path = match super::helpers::validate_path(&path) {
                    Ok(p) => p,
                    Err(e) => {
                        return IpcMessage::ProcessScoreResponse {
                            residency: 0.0,
                            sequence: 0.0,
                            behavioral: 0.0,
                            composite: 0.0,
                            meets_threshold: false,
                            error: Some(format!("Invalid path: {}", e)),
                        };
                    }
                };
                let db_path = self.sentinel.config.witnessd_dir.join("events.db");
                let key_bytes = self
                    .sentinel
                    .signing_key
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .to_bytes();
                let hmac_key = if key_bytes == [0u8; 32] {
                    log::warn!("Using zero signing key for HMAC derivation - identity may not be initialized");
                    crate::crypto::derive_hmac_key(&[0u8; 32])
                } else {
                    crate::crypto::derive_hmac_key(&key_bytes)
                };

                match crate::store::SecureStore::open(&db_path, hmac_key) {
                    Ok(db) => {
                        match db.get_events_for_file(&path.to_string_lossy()) {
                            Ok(events) => {
                                if events.is_empty() {
                                    return IpcMessage::ProcessScoreResponse {
                                        residency: 0.0,
                                        sequence: 0.0,
                                        behavioral: 0.0,
                                        composite: 0.0,
                                        meets_threshold: false,
                                        error: Some("No events found for file".to_string()),
                                    };
                                }

                                let event_data: Vec<crate::forensics::EventData> = events
                                    .iter()
                                    .enumerate()
                                    .map(|(i, e)| crate::forensics::EventData {
                                        id: e.id.unwrap_or(i as i64),
                                        timestamp_ns: e.timestamp_ns,
                                        file_size: e.file_size,
                                        size_delta: e.size_delta,
                                        file_path: e.file_path.clone(),
                                    })
                                    .collect();

                                let regions = std::collections::HashMap::new();
                                let metrics = crate::forensics::analyze_forensics(
                                    &event_data,
                                    &regions,
                                    None,
                                    None,
                                    None,
                                );

                                // PS = 0.3*R + 0.3*S + 0.4*B
                                let residency = if events.len() >= 5 {
                                    1.0
                                } else {
                                    events.len() as f64 / 5.0
                                };
                                let sequence = (metrics.primary.edit_entropy.min(3.0) / 3.0 * 0.5)
                                    + (metrics.primary.monotonic_append_ratio * 0.5);
                                let behavioral = metrics.assessment_score;
                                let composite = 0.3 * residency + 0.3 * sequence + 0.4 * behavioral;

                                IpcMessage::ProcessScoreResponse {
                                    residency,
                                    sequence,
                                    behavioral,
                                    composite,
                                    meets_threshold: composite >= 0.9,
                                    error: None,
                                }
                            }
                            Err(e) => IpcMessage::ProcessScoreResponse {
                                residency: 0.0,
                                sequence: 0.0,
                                behavioral: 0.0,
                                composite: 0.0,
                                meets_threshold: false,
                                error: Some(format!("Failed to load events: {}", e)),
                            },
                        }
                    }
                    Err(e) => IpcMessage::ProcessScoreResponse {
                        residency: 0.0,
                        sequence: 0.0,
                        behavioral: 0.0,
                        composite: 0.0,
                        meets_threshold: false,
                        error: Some(format!("Database error: {}", e)),
                    },
                }
            }

            IpcMessage::VerifyFileResponse { .. }
            | IpcMessage::ExportFileResponse { .. }
            | IpcMessage::ForensicsResponse { .. }
            | IpcMessage::ProcessScoreResponse { .. }
            | IpcMessage::CheckpointResponse { .. } => IpcMessage::Error {
                code: IpcErrorCode::InvalidMessage,
                message: "Unexpected response message received as request".to_string(),
            },
        }
    }
}
