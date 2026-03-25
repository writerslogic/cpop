// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::core::Sentinel;
use crate::ipc::{IpcErrorCode, IpcMessage, IpcMessageHandler};
use crate::RwLockRecover;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

/// IPC message handler that dispatches requests to the sentinel.
pub struct SentinelIpcHandler {
    sentinel: Arc<Sentinel>,
    start_time: SystemTime,
    version: String,
}

impl SentinelIpcHandler {
    /// Create a handler backed by the given sentinel instance.
    pub fn new(sentinel: Arc<Sentinel>) -> Self {
        Self {
            sentinel,
            start_time: SystemTime::now(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    fn open_db(&self) -> Result<crate::store::SecureStore, String> {
        let db_path = self.sentinel.config.writersproof_dir.join("events.db");
        let guard = self.sentinel.signing_key.read_recover();
        let signing_key = guard.as_ref().ok_or("Signing key not initialized")?;
        let key_bytes = Zeroizing::new(signing_key.to_bytes());
        let mut hmac_key = crate::crypto::derive_hmac_key(key_bytes.as_ref());
        drop(guard);
        crate::store::SecureStore::open(&db_path, std::mem::take(&mut *hmac_key))
            .map_err(|e| format!("Database error: {e}"))
    }

    fn load_events(
        &self,
        path: &std::path::Path,
    ) -> Result<Vec<crate::store::SecureEvent>, String> {
        let db = self.open_db()?;
        db.get_events_for_file(&path.to_string_lossy())
            .map_err(|e| format!("Failed to load events: {e}"))
    }

    fn to_forensic_data(events: &[crate::store::SecureEvent]) -> Vec<crate::forensics::EventData> {
        events
            .iter()
            .enumerate()
            .map(|(i, e)| crate::forensics::EventData {
                id: e.id.unwrap_or(i as i64),
                timestamp_ns: e.timestamp_ns,
                file_size: e.file_size,
                size_delta: e.size_delta,
                file_path: e.file_path.clone(),
            })
            .collect()
    }

    fn analyze_file(
        &self,
        path: &PathBuf,
    ) -> Result<
        (
            Vec<crate::store::SecureEvent>,
            crate::forensics::ForensicMetrics,
        ),
        String,
    > {
        let path = super::helpers::validate_path(path)?;
        let events = self.load_events(&path)?;
        if events.is_empty() {
            return Err("No events found for file".to_string());
        }
        let event_data = Self::to_forensic_data(&events);
        let regions = std::collections::HashMap::new();

        let accumulator = self.sentinel.activity_accumulator.read_recover();
        let jitter_samples = if accumulator.sample_count() > 0 {
            Some(accumulator.samples())
        } else {
            None
        };

        let metrics = crate::forensics::analyze_forensics(
            &event_data,
            &regions,
            jitter_samples.as_deref(),
            None,
            None,
        );
        Ok((events, metrics))
    }

    fn handle_export_with_nonce(
        &self,
        file_path: PathBuf,
        verifier_nonce: [u8; 32],
    ) -> Result<IpcMessage, String> {
        let file_path = super::helpers::validate_path(&file_path)?;
        let db = self.open_db()?;
        let events = db
            .get_events_for_file(&file_path.to_string_lossy())
            .map_err(|e| format!("Failed to load events: {e}"))?;

        let evidence_hash = crate::evidence::compute_events_binding_hash(&events);
        let attestation_nonce = self.sentinel.get_or_generate_nonce();

        let provider = crate::tpm::detect_provider();
        let report = crate::tpm::generate_attestation_report(
            &*provider,
            &verifier_nonce,
            &attestation_nonce,
            evidence_hash,
        )
        .map_err(|e| format!("Hardware quote failed: {e}"))?;

        Ok(IpcMessage::NonceExportResponse {
            success: true,
            output_path: None,
            packet_hash: Some(hex::encode(evidence_hash)),
            verifier_nonce: Some(hex::encode(verifier_nonce)),
            attestation_nonce: Some(hex::encode(attestation_nonce)),
            attestation_report: Some(
                serde_json::to_string(&report)
                    .map_err(|e| format!("Failed to serialize attestation report: {e}"))?,
            ),
            error: None,
        })
    }

    fn handle_verify_with_nonce(
        &self,
        evidence_path: PathBuf,
        expected_nonce: Option<[u8; 32]>,
    ) -> Result<IpcMessage, String> {
        let path = super::helpers::validate_path(&evidence_path)?;
        let data =
            std::fs::read(&path).map_err(|e| format!("Failed to read evidence file: {e}"))?;
        let packet = crate::evidence::Packet::decode(&data)
            .map_err(|e| format!("Failed to decode evidence: {e}"))?;

        let vdf_params = packet.vdf_params;
        let chain_ok = packet.verify(vdf_params).is_ok();
        let sig_ok = packet.verify_signature(expected_nonce.as_ref()).is_ok();
        let nonce_valid = match (&expected_nonce, packet.get_verifier_nonce()) {
            (Some(expected), Some(actual)) => *actual == *expected,
            (None, None) => true,
            _ => false,
        };

        let mut errors = Vec::new();
        if !chain_ok {
            errors.push("Chain integrity verification failed".to_string());
        }
        if !sig_ok {
            errors.push(
                "Signature verification failed (nonce mismatch or invalid signature)".to_string(),
            );
        }
        if !nonce_valid {
            errors.push("Verifier nonce does not match expected nonce".to_string());
        }

        Ok(IpcMessage::NonceVerifyResponse {
            valid: chain_ok && sig_ok && nonce_valid,
            nonce_valid,
            checkpoint_count: packet.checkpoints.len() as u64,
            total_elapsed_time_secs: packet.total_elapsed_time().as_secs_f64(),
            verifier_nonce: packet.get_verifier_nonce().map(hex::encode),
            attestation_nonce: packet
                .hardware
                .as_ref()
                .and_then(|hw| hw.attestation_nonce)
                .map(hex::encode),
            errors,
        })
    }

    fn handle_create_checkpoint(
        &self,
        path: PathBuf,
        message: String,
    ) -> Result<IpcMessage, String> {
        let path = super::helpers::validate_path(&path)?;
        let writersproof_dir = &self.sentinel.config.writersproof_dir;
        let vdf_params = crate::vdf::default_parameters();

        let path_hash = Sha256::digest(path.to_string_lossy().as_bytes());
        let doc_id = hex::encode(&path_hash[0..8]);
        let chain_path = writersproof_dir
            .join("chains")
            .join(format!("{doc_id}.json"));

        let mut chain = if chain_path.exists() {
            crate::checkpoint::Chain::load(&chain_path)
                .map_err(|e| format!("Failed to load chain: {e}"))?
        } else {
            crate::checkpoint::Chain::new(&path, vdf_params)
                .map_err(|e| format!("Failed to create chain: {e}"))?
        };

        let checkpoint =
            if chain.entanglement_mode == crate::checkpoint::EntanglementMode::Entangled {
                let accumulator = self.sentinel.activity_accumulator.read_recover();
                let samples = accumulator.samples();
                let keystroke_count = samples.len() as u64;

                let mut jitter_hasher = Sha256::new();
                jitter_hasher.update(b"witnessd-checkpoint-jitter-v1");
                jitter_hasher.update(keystroke_count.to_be_bytes());
                for s in &samples {
                    jitter_hasher.update(s.duration_since_last_ns.to_be_bytes());
                }
                let jitter_hash: [u8; 32] = jitter_hasher.finalize().into();

                let session_id = self
                    .sentinel
                    .sessions
                    .read_recover()
                    .get(&path.to_string_lossy().to_string())
                    .map(|s| s.session_id.clone())
                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

                let physics = crate::physics::PhysicalContext::capture(&samples);

                chain
                    .commit_entangled(
                        Some(message),
                        jitter_hash,
                        session_id,
                        keystroke_count,
                        std::time::Duration::from_secs(1),
                        Some(&physics),
                    )
                    .map_err(|e| format!("Entangled commit failed: {e}"))?
            } else {
                chain
                    .commit(Some(message))
                    .map_err(|e| format!("Commit failed: {e}"))?
            };
        chain
            .save(&chain_path)
            .map_err(|e| format!("Failed to save chain: {e}"))?;

        Ok(IpcMessage::CheckpointResponse {
            success: true,
            hash: Some(hex::encode(checkpoint.hash)),
            error: None,
        })
    }

    fn handle_verify_file(&self, path: PathBuf) -> Result<IpcMessage, String> {
        let validated_path = super::helpers::validate_path(&path)?;
        let data =
            std::fs::read(&validated_path).map_err(|e| format!("Failed to read file: {e}"))?;
        let packet = crate::evidence::Packet::decode(&data)
            .map_err(|e| format!("Failed to decode evidence: {e}"))?;

        let vdf_params = packet.vdf_params;
        let chain_ok = packet.verify(vdf_params).is_ok();
        let sig_ok = packet.verify_signature(None).is_ok();

        Ok(IpcMessage::VerifyFileResponse {
            success: chain_ok && sig_ok,
            checkpoint_count: packet.checkpoints.len() as u32,
            signature_valid: sig_ok,
            chain_integrity: chain_ok,
            vdf_iterations_per_second: vdf_params.iterations_per_second,
            error: None,
        })
    }

    fn handle_export_file(&self, path: PathBuf, output: PathBuf) -> Result<IpcMessage, String> {
        let writersproof_dir = &self.sentinel.config.writersproof_dir;

        let _ = super::helpers::validate_path(&path)
            .map_err(|e| format!("Invalid source path: {e}"))?;
        let validated_output = super::helpers::validate_path(&output)
            .map_err(|e| format!("Invalid output path: {e}"))?;

        let chain_path = crate::checkpoint::Chain::find_chain(&path, writersproof_dir)
            .map_err(|e| format!("No chain found: {e}"))?;
        let chain = crate::checkpoint::Chain::load(&chain_path)
            .map_err(|e| format!("Failed to load chain: {e}"))?;

        if chain.checkpoints.is_empty() {
            return Err("Chain has no checkpoints".to_string());
        }

        let title = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "Untitled".to_string());
        let mut builder = crate::evidence::Builder::new(&title, &chain);

        let latest = chain
            .latest()
            .ok_or("Chain reported non-empty but latest() returned None")?;

        let signing_key_guard = self.sentinel.signing_key.read_recover();
        let signing_key = signing_key_guard
            .as_ref()
            .ok_or("Signing key not initialized")?;
        let decl = crate::declaration::no_ai_declaration(
            latest.content_hash,
            latest.hash,
            &title,
            "Exported via IPC",
        )
        .sign(signing_key)
        .map_err(|e| format!("Declaration signing failed: {e}"))?;
        drop(signing_key_guard);
        builder = builder.with_declaration(&decl);

        let summary = self
            .sentinel
            .activity_accumulator
            .read_recover()
            .to_session_summary();
        let mut bv = cpop_protocol::baseline::BaselineVerification {
            digest: None,
            session_summary: summary,
            digest_signature: None,
        };

        let (identity_fingerprint, mut hmac_key) = {
            let guard = self.sentinel.signing_key.read_recover();
            let key = guard.as_ref().ok_or("Signing key not initialized")?;
            let mut hasher = Sha256::new();
            hasher.update(key.verifying_key().to_bytes());
            let fingerprint = hasher.finalize().to_vec();
            let key_bytes = Zeroizing::new(key.to_bytes());
            let hmac = crate::crypto::derive_hmac_key(key_bytes.as_ref());
            (fingerprint, hmac)
        };

        let db_path = self.sentinel.config.writersproof_dir.join("events.db");
        if let Ok(store) = crate::store::SecureStore::open(&db_path, std::mem::take(&mut *hmac_key))
        {
            if let Ok(Some((cbor, sig))) = store.get_baseline_digest(&identity_fingerprint) {
                if let Ok(digest) =
                    serde_json::from_slice::<cpop_protocol::baseline::BaselineDigest>(&cbor)
                {
                    bv.digest = Some(digest);
                    bv.digest_signature = Some(sig);
                }
            }
        }
        builder = builder.with_baseline_verification(bv);

        let jitter_samples = self.sentinel.activity_accumulator.read_recover().samples();
        let physics = crate::physics::PhysicalContext::capture(&jitter_samples);
        builder = builder.with_physical_context(&physics);

        let packet = builder
            .build()
            .map_err(|e| format!("Failed to build packet: {e}"))?;

        let format = if output.extension().map(|e| e == "json").unwrap_or(false) {
            cpop_protocol::codec::Format::Json
        } else {
            cpop_protocol::codec::Format::Cbor
        };
        let encoded = packet
            .encode_with_format(format)
            .map_err(|e| format!("Failed to encode packet: {e}"))?;

        {
            use std::io::Write;
            let tmp_path = validated_output.with_extension("tmp");
            let mut f = std::fs::File::create(&tmp_path)
                .map_err(|e| format!("Failed to create temp file: {e}"))?;
            f.write_all(&encoded)
                .map_err(|e| format!("Failed to write temp file: {e}"))?;
            f.sync_all()
                .map_err(|e| format!("Failed to sync temp file: {e}"))?;
            drop(f);
            std::fs::rename(&tmp_path, &validated_output)
                .map_err(|e| format!("Failed to rename output: {e}"))?;
        }

        Ok(IpcMessage::ExportFileResponse {
            success: true,
            error: None,
        })
    }

    fn handle_get_forensics(&self, path: PathBuf) -> Result<IpcMessage, String> {
        let (_events, metrics) = self.analyze_file(&path)?;

        Ok(IpcMessage::ForensicsResponse {
            assessment_score: metrics.assessment_score,
            risk_level: metrics.risk_level.to_string(),
            anomaly_count: metrics.anomaly_count as u32,
            monotonic_append_ratio: metrics.primary.monotonic_append_ratio,
            edit_entropy: metrics.primary.edit_entropy,
            median_interval: metrics.primary.median_interval,
            biological_cadence_score: metrics.biological_cadence_score,
            error: None,
        })
    }

    fn handle_process_score(&self, path: PathBuf) -> Result<IpcMessage, String> {
        let (events, metrics) = self.analyze_file(&path)?;

        let residency = if events.len() >= 5 {
            1.0
        } else {
            events.len() as f64 / 5.0
        };
        let sequence = (metrics.primary.edit_entropy.min(3.0) / 3.0 * 0.5)
            + (metrics.primary.monotonic_append_ratio * 0.5);
        let behavioral = metrics.assessment_score;
        let composite = 0.3 * residency + 0.3 * sequence + 0.4 * behavioral;

        Ok(IpcMessage::ProcessScoreResponse {
            residency,
            sequence,
            behavioral,
            composite,
            meets_threshold: composite >= 0.9,
            error: None,
        })
    }
}

impl IpcMessageHandler for SentinelIpcHandler {
    fn handle(&self, msg: IpcMessage) -> IpcMessage {
        match msg {
            IpcMessage::Handshake { version } => IpcMessage::HandshakeAck {
                version,
                server_version: self.version.clone(),
            },

            IpcMessage::Heartbeat => IpcMessage::HeartbeatAck {
                timestamp_ns: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_nanos() as u64)
                    .unwrap_or(0),
            },

            IpcMessage::StartWitnessing { file_path } => {
                let file_path = match super::helpers::validate_path(&file_path) {
                    Ok(p) => p,
                    Err(e) => {
                        return IpcMessage::Error {
                            code: IpcErrorCode::PermissionDenied,
                            message: format!("Invalid path: {e}"),
                        }
                    }
                };
                match self.sentinel.start_witnessing(&file_path) {
                    Ok(()) => IpcMessage::Ok {
                        message: Some(format!("Now tracking: {}", file_path.display())),
                    },
                    Err((code, message)) => IpcMessage::Error { code, message },
                }
            }

            IpcMessage::StopWitnessing { file_path } => match file_path {
                Some(path) => {
                    let path = match super::helpers::validate_path(&path) {
                        Ok(p) => p,
                        Err(e) => {
                            return IpcMessage::Error {
                                code: IpcErrorCode::PermissionDenied,
                                message: format!("Invalid path: {e}"),
                            }
                        }
                    };
                    match self.sentinel.stop_witnessing(&path) {
                        Ok(()) => IpcMessage::Ok {
                            message: Some(format!("Stopped tracking: {}", path.display())),
                        },
                        Err((code, message)) => IpcMessage::Error { code, message },
                    }
                }
                None => IpcMessage::Error {
                    code: IpcErrorCode::InvalidMessage,
                    message: "Must specify a file path to stop witnessing".into(),
                },
            },

            IpcMessage::GetStatus => {
                let tracked_files = self.sentinel.tracked_files();
                let uptime_secs = self.start_time.elapsed().map(|d| d.as_secs()).unwrap_or(0);
                IpcMessage::StatusResponse {
                    running: self.sentinel.is_running(),
                    tracked_files,
                    uptime_secs,
                }
            }

            IpcMessage::GetAttestationNonce => IpcMessage::AttestationNonceResponse {
                nonce: self.sentinel.get_or_generate_nonce(),
            },

            IpcMessage::ExportWithNonce {
                file_path,
                verifier_nonce,
                ..
            } => self
                .handle_export_with_nonce(file_path, verifier_nonce)
                .unwrap_or_else(|e| IpcMessage::NonceExportResponse {
                    success: false,
                    output_path: None,
                    packet_hash: None,
                    verifier_nonce: None,
                    attestation_nonce: None,
                    attestation_report: None,
                    error: Some(e),
                }),

            IpcMessage::VerifyWithNonce {
                evidence_path,
                expected_nonce,
            } => self
                .handle_verify_with_nonce(evidence_path, expected_nonce)
                .unwrap_or_else(|e| IpcMessage::NonceVerifyResponse {
                    valid: false,
                    nonce_valid: false,
                    checkpoint_count: 0,
                    total_elapsed_time_secs: 0.0,
                    verifier_nonce: None,
                    attestation_nonce: None,
                    errors: vec![e],
                }),

            IpcMessage::CreateFileCheckpoint { path, message } => self
                .handle_create_checkpoint(path, message)
                .unwrap_or_else(|e| IpcMessage::CheckpointResponse {
                    success: false,
                    hash: None,
                    error: Some(e),
                }),

            IpcMessage::VerifyFile { path } => {
                self.handle_verify_file(path)
                    .unwrap_or_else(|e| IpcMessage::VerifyFileResponse {
                        success: false,
                        checkpoint_count: 0,
                        signature_valid: false,
                        chain_integrity: false,
                        vdf_iterations_per_second: 0,
                        error: Some(e),
                    })
            }

            IpcMessage::ExportFile { path, output, .. } => self
                .handle_export_file(path, output)
                .unwrap_or_else(|e| IpcMessage::ExportFileResponse {
                    success: false,
                    error: Some(e),
                }),

            IpcMessage::GetFileForensics { path } => self
                .handle_get_forensics(path)
                .unwrap_or_else(|e| IpcMessage::ForensicsResponse {
                    assessment_score: 0.0,
                    risk_level: "INSUFFICIENT DATA".to_string(),
                    anomaly_count: 0,
                    monotonic_append_ratio: 0.0,
                    edit_entropy: 0.0,
                    median_interval: 0.0,
                    biological_cadence_score: 0.0,
                    error: Some(e),
                }),

            IpcMessage::ComputeProcessScore { path } => self
                .handle_process_score(path)
                .unwrap_or_else(|e| IpcMessage::ProcessScoreResponse {
                    residency: 0.0,
                    sequence: 0.0,
                    behavioral: 0.0,
                    composite: 0.0,
                    meets_threshold: false,
                    error: Some(e),
                }),

            IpcMessage::Ok { .. }
            | IpcMessage::Error { .. }
            | IpcMessage::HandshakeAck { .. }
            | IpcMessage::HeartbeatAck { .. }
            | IpcMessage::StatusResponse { .. }
            | IpcMessage::AttestationNonceResponse { .. }
            | IpcMessage::NonceExportResponse { .. }
            | IpcMessage::NonceVerifyResponse { .. }
            | IpcMessage::VerifyFileResponse { .. }
            | IpcMessage::ExportFileResponse { .. }
            | IpcMessage::ForensicsResponse { .. }
            | IpcMessage::ProcessScoreResponse { .. }
            | IpcMessage::CheckpointResponse { .. } => IpcMessage::Error {
                code: IpcErrorCode::InvalidMessage,
                message: "Unexpected response message received as request".into(),
            },

            IpcMessage::Pulse(_)
            | IpcMessage::CheckpointCreated { .. }
            | IpcMessage::SystemAlert { .. } => IpcMessage::Error {
                code: IpcErrorCode::InvalidMessage,
                message: "Push events cannot be sent to the server".into(),
            },
        }
    }
}
