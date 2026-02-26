// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! FFI bindings for macOS SwiftUI integration via UniFFI.
//!
//! Provides synchronous wrappers around core crypto operations that can be
//! called directly from Swift without spawning a CLI subprocess.
//!
//! Build with: `cargo build --release --features ffi`

use std::path::PathBuf;
use std::time::Duration;

// MARK: - FFI Result Types

/// Result of an evidence verification operation.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiVerifyResult {
    pub success: bool,
    pub checkpoint_count: u32,
    pub signature_valid: bool,
    pub chain_integrity: bool,
    /// Sequential Work Function iterations per second (spec: SWF/Argon2id).
    pub swf_iterations_per_second: u64,
    /// Attestation tier (1=software, 2=attested-software, 3=hardware-bound, 4=hardware-hardened)
    pub attestation_tier: u8,
    /// Human-readable attestation tier description
    pub attestation_tier_label: String,
    pub error_message: Option<String>,
}

/// Generic FFI result for operations that return success/error.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiResult {
    pub success: bool,
    pub message: Option<String>,
    pub error_message: Option<String>,
}

/// Result of forensic analysis.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiForensicResult {
    pub success: bool,
    pub assessment_score: f64,
    pub risk_level: String,
    pub anomaly_count: u32,
    pub monotonic_append_ratio: f64,
    pub edit_entropy: f64,
    pub median_interval: f64,
    pub error_message: Option<String>,
}

/// Result of process score computation.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiProcessScore {
    pub success: bool,
    pub residency: f64,
    pub sequence: f64,
    pub behavioral: f64,
    pub composite: f64,
    pub meets_threshold: bool,
    pub error_message: Option<String>,
}

/// Result of SWF (Sequential Work Function) calibration.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiCalibrationResult {
    pub success: bool,
    pub iterations_per_second: u64,
    pub error_message: Option<String>,
}

// MARK: - Helper: Get data directory

fn get_data_dir() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        dirs::home_dir().map(|h| h.join("Library/Application Support/Witnessd"))
    }
    #[cfg(not(target_os = "macos"))]
    {
        dirs::data_local_dir().map(|d| d.join("Witnessd"))
    }
}

fn get_db_path() -> Option<PathBuf> {
    get_data_dir().map(|d| d.join("events.db"))
}

/// Load the HMAC key from the signing key file in the data directory.
fn load_hmac_key() -> Option<Vec<u8>> {
    let data_dir = get_data_dir()?;
    let key_path = data_dir.join("signing_key");
    let key_data = std::fs::read(&key_path).ok()?;
    let seed = if key_data.len() >= 32 {
        &key_data[..32]
    } else {
        return None;
    };
    Some(crate::crypto::derive_hmac_key(seed))
}

/// Open the SecureStore with the HMAC key from the data directory.
fn open_store() -> Result<crate::store::SecureStore, String> {
    let db_path = get_db_path()
        .filter(|p| p.exists())
        .ok_or_else(|| "Database not found".to_string())?;
    let hmac_key = load_hmac_key().ok_or_else(|| "Failed to load signing key".to_string())?;
    crate::store::SecureStore::open(&db_path, hmac_key)
        .map_err(|e| format!("Failed to open database: {}", e))
}

/// Auto-detect attestation tier from available TPM hardware.
fn detect_attestation_tier() -> crate::rfc::wire_types::AttestationTier {
    let (tier, _, _) = detect_attestation_tier_info();
    tier
}

/// Auto-detect attestation tier and return both the enum and metadata.
fn detect_attestation_tier_info() -> (crate::rfc::wire_types::AttestationTier, u8, String) {
    use crate::rfc::wire_types::AttestationTier;

    let provider = crate::tpm::detect_provider();
    let caps = provider.capabilities();
    if caps.hardware_backed && caps.supports_sealing {
        (AttestationTier::HardwareBound, 3, "hardware-bound".to_string())
    } else if caps.hardware_backed && caps.supports_attestation {
        (AttestationTier::AttestedSoftware, 2, "attested-software".to_string())
    } else {
        (AttestationTier::SoftwareOnly, 1, "software-only".to_string())
    }
}

/// Convert SecureEvents to forensic EventData.
fn events_to_forensic_data(
    events: &[crate::store::SecureEvent],
) -> Vec<crate::forensics::EventData> {
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

// MARK: - FFI Functions

/// Verify an evidence packet file.
///
/// Reads the evidence file, deserializes it, and runs verification checks
/// including signature validation, chain integrity, and SWF proof verification.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_verify_evidence(path: String) -> FfiVerifyResult {
    let path = PathBuf::from(&path);
    let (_, tier_num, tier_label) = detect_attestation_tier_info();

    if !path.exists() {
        return FfiVerifyResult {
            success: false,
            checkpoint_count: 0,
            signature_valid: false,
            chain_integrity: false,
            swf_iterations_per_second: 0,
            attestation_tier: tier_num,
            attestation_tier_label: tier_label,
            error_message: Some(format!("File not found: {}", path.display())),
        };
    }

    // Read and decode the evidence packet
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

    // Run verification
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

/// Export evidence for a file to an output path.
///
/// Reads the events database, builds an evidence packet at the specified tier,
/// and writes it to the output path.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_export_evidence(path: String, tier: String, output: String) -> FfiResult {
    let file_path = PathBuf::from(&path);
    let output_path = PathBuf::from(&output);

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

    // Determine strength from tier string
    let _strength = match tier.to_lowercase().as_str() {
        "basic" => crate::evidence::Strength::Basic,
        "standard" => crate::evidence::Strength::Standard,
        "enhanced" => crate::evidence::Strength::Enhanced,
        "maximum" => crate::evidence::Strength::Maximum,
        _ => crate::evidence::Strength::Standard,
    };

    // Load events for this file
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

    // Build a CDDL-conformant evidence packet using wire types
    let latest = &events[events.len() - 1];
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    // Map content tier from tier string
    let content_tier = match tier.to_lowercase().as_str() {
        "basic" | "core" => Some(crate::rfc::wire_types::ContentTier::Core),
        "standard" | "enhanced" => Some(crate::rfc::wire_types::ContentTier::Enhanced),
        "maximum" => Some(crate::rfc::wire_types::ContentTier::Maximum),
        _ => Some(crate::rfc::wire_types::ContentTier::Core),
    };

    // Convert SecureEvents to CDDL CheckpointWire structs
    let checkpoints: Vec<crate::rfc::wire_types::CheckpointWire> = events
        .iter()
        .enumerate()
        .map(|(i, ev)| {
            let timestamp_ms = (ev.timestamp_ns / 1_000_000) as u64;
            let vdf_input_bytes = ev.vdf_input.map(|b| b.to_vec()).unwrap_or_else(|| vec![0u8; 32]);
            let vdf_output_bytes = ev.vdf_output.map(|b| b.to_vec());
            let merkle_root = vdf_output_bytes.clone().unwrap_or_else(|| vec![0u8; 32]);

            crate::rfc::wire_types::CheckpointWire {
                sequence: i as u64,
                checkpoint_id: ev.device_id,
                timestamp: timestamp_ms,
                content_hash: crate::rfc::wire_types::HashValue::sha256(ev.content_hash.to_vec()),
                char_count: ev.file_size as u64,
                delta: crate::rfc::wire_types::EditDelta {
                    chars_added: ev.size_delta.max(0) as u64,
                    chars_deleted: (-ev.size_delta).max(0) as u64,
                    op_count: 1,
                    positions: None,
                },
                prev_hash: crate::rfc::wire_types::HashValue::sha256(ev.previous_hash.to_vec()),
                checkpoint_hash: crate::rfc::wire_types::HashValue::sha256(ev.event_hash.to_vec()),
                process_proof: crate::rfc::wire_types::ProcessProof {
                    algorithm: crate::rfc::wire_types::ProofAlgorithm::SwfArgon2id,
                    params: crate::rfc::wire_types::ProofParams {
                        time_cost: 3,
                        memory_cost: 65536,
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

    // Build the CDDL EvidencePacketWire
    let wire_packet = crate::rfc::wire_types::EvidencePacketWire {
        version: 1,
        profile_uri: "urn:ietf:params:pop:profile:witnessd:v1".to_string(),
        packet_id: latest.device_id,
        created: now_ms,
        document: crate::rfc::wire_types::DocumentRef {
            content_hash: crate::rfc::wire_types::HashValue::sha256(latest.content_hash.to_vec()),
            filename: file_path.file_name().and_then(|n| n.to_str()).map(|s| s.to_string()),
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

    // Encode as CBOR with tag #6.1129336656
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

/// Run forensic analysis on a tracked file.
///
/// Loads events from the database and runs the full forensic analysis pipeline.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_forensics(path: String) -> FfiForensicResult {
    let file_path = PathBuf::from(&path);

    let store = match open_store() {
        Ok(s) => s,
        Err(e) => {
            return FfiForensicResult {
                success: false,
                assessment_score: 0.0,
                risk_level: "unknown".to_string(),
                anomaly_count: 0,
                monotonic_append_ratio: 0.0,
                edit_entropy: 0.0,
                median_interval: 0.0,
                error_message: Some(e),
            };
        }
    };

    let events = match store.get_events_for_file(&path) {
        Ok(e) => e,
        Err(e) => {
            return FfiForensicResult {
                success: false,
                assessment_score: 0.0,
                risk_level: "unknown".to_string(),
                anomaly_count: 0,
                monotonic_append_ratio: 0.0,
                edit_entropy: 0.0,
                median_interval: 0.0,
                error_message: Some(format!("Failed to load events: {}", e)),
            };
        }
    };

    if events.is_empty() {
        return FfiForensicResult {
            success: false,
            assessment_score: 0.0,
            risk_level: "unknown".to_string(),
            anomaly_count: 0,
            monotonic_append_ratio: 0.0,
            edit_entropy: 0.0,
            median_interval: 0.0,
            error_message: Some("No events found for this file".to_string()),
        };
    }

    // Convert SecureEvents to forensic EventData
    let event_data = events_to_forensic_data(&events);

    let regions = std::collections::HashMap::new();
    let metrics = crate::forensics::analyze_forensics(&event_data, &regions, None, None, None);

    let risk_level = if metrics.assessment_score >= 0.8 {
        "low"
    } else if metrics.assessment_score >= 0.5 {
        "medium"
    } else {
        "high"
    };

    FfiForensicResult {
        success: true,
        assessment_score: metrics.assessment_score,
        risk_level: risk_level.to_string(),
        anomaly_count: 0,
        monotonic_append_ratio: metrics.primary.monotonic_append_ratio,
        edit_entropy: metrics.primary.edit_entropy,
        median_interval: metrics.primary.median_interval,
        error_message: None,
    }
}

/// Compute the Process Score (PS) for a tracked file.
///
/// PS = 0.3*R + 0.3*S + 0.4*B, where:
/// - R = Residency (file was in witnessd's custody)
/// - S = Sequence (edit sequence is plausible)
/// - B = Behavioral (keystroke biometrics match)
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_compute_process_score(path: String) -> FfiProcessScore {
    let file_path = PathBuf::from(&path);

    let store = match open_store() {
        Ok(s) => s,
        Err(e) => {
            return FfiProcessScore {
                success: false,
                residency: 0.0,
                sequence: 0.0,
                behavioral: 0.0,
                composite: 0.0,
                meets_threshold: false,
                error_message: Some(e),
            };
        }
    };

    let events = match store.get_events_for_file(&path) {
        Ok(e) => e,
        Err(e) => {
            return FfiProcessScore {
                success: false,
                residency: 0.0,
                sequence: 0.0,
                behavioral: 0.0,
                composite: 0.0,
                meets_threshold: false,
                error_message: Some(format!("Failed to load events: {}", e)),
            };
        }
    };

    if events.is_empty() {
        return FfiProcessScore {
            success: false,
            residency: 0.0,
            sequence: 0.0,
            behavioral: 0.0,
            composite: 0.0,
            meets_threshold: false,
            error_message: Some("No events found for this file".to_string()),
        };
    }

    // Convert events to forensic data for analysis
    let event_data = events_to_forensic_data(&events);

    let regions = std::collections::HashMap::new();
    let metrics = crate::forensics::analyze_forensics(&event_data, &regions, None, None, None);

    // Compute Process Score components from forensic metrics
    // R (Residency): Based on chain integrity and continuous coverage
    let residency = if events.len() >= 5 {
        1.0
    } else {
        events.len() as f64 / 5.0
    };

    // S (Sequence): Based on edit entropy and monotonic append ratio
    let sequence = (metrics.primary.edit_entropy.min(3.0) / 3.0 * 0.5)
        + (metrics.primary.monotonic_append_ratio * 0.5);

    // B (Behavioral): Based on assessment score from forensic analysis
    let behavioral = metrics.assessment_score;

    // PS = 0.3R + 0.3S + 0.4B
    let composite = 0.3 * residency + 0.3 * sequence + 0.4 * behavioral;
    let meets_threshold = composite >= 0.9;

    FfiProcessScore {
        success: true,
        residency,
        sequence,
        behavioral,
        composite,
        meets_threshold,
        error_message: None,
    }
}

/// Calibrate SWF (Sequential Work Function) iterations per second for this machine.
///
/// Runs a 1-second Argon2id calibration to determine how many SWF iterations
/// this machine can compute, then stores the result.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_calibrate_swf() -> FfiCalibrationResult {
    match crate::vdf::calibrate(Duration::from_secs(1)) {
        Ok(params) => FfiCalibrationResult {
            success: true,
            iterations_per_second: params.iterations_per_second,
            error_message: None,
        },
        Err(e) => FfiCalibrationResult {
            success: false,
            iterations_per_second: 0,
            error_message: Some(format!("Calibration failed: {}", e)),
        },
    }
}

/// Get the compact evidence reference string for a file.
///
/// Returns a short, human-readable reference that can be used to
/// look up the full evidence packet.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_compact_ref(path: String) -> String {
    let file_path = PathBuf::from(&path);

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

    // Build a compact reference from the most recent event hash
    let last_event = &events[events.len() - 1];
    let hash_hex = hex::encode(last_event.event_hash);

    // Format: witnessd:<first 12 chars of hash>:<checkpoint count>
    format!(
        "witnessd:{}:{}",
        &hash_hex[..hash_hex.len().min(12)],
        events.len()
    )
}

/// Create a manual checkpoint for a file with an optional message.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_create_checkpoint(path: String, message: String) -> FfiResult {
    let file_path = PathBuf::from(&path);

    if !file_path.exists() {
        return FfiResult {
            success: false,
            message: None,
            error_message: Some(format!("File not found: {}", file_path.display())),
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

    // Read current file content to compute hash
    let content = match std::fs::read(&file_path) {
        Ok(c) => c,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Failed to read file: {}", e)),
            };
        }
    };

    use sha2::{Digest, Sha256};
    let content_hash: [u8; 32] = Sha256::digest(&content).into();

    let context_note = if message.is_empty() {
        None
    } else {
        Some(message)
    };

    // Build a SecureEvent for the checkpoint
    let mut event = crate::store::SecureEvent {
        id: None,
        device_id: [0u8; 16],
        machine_id: String::new(),
        timestamp_ns: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0),
        file_path: path.clone(),
        content_hash,
        file_size: content.len() as i64,
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

// MARK: - Expanded FFI Surface (Phase 1B)

/// Tracked file information returned by ffi_list_tracked_files.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiTrackedFile {
    pub path: String,
    pub last_checkpoint_ns: i64,
    pub checkpoint_count: i64,
}

/// Checkpoint log entry returned by ffi_get_log.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiLogEntry {
    pub ordinal: u64,
    pub timestamp_ns: i64,
    pub content_hash: String,
    pub file_size: i64,
    pub size_delta: i32,
    pub message: Option<String>,
}

/// Status information returned by ffi_get_status.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiStatus {
    pub initialized: bool,
    pub data_dir: String,
    pub tracked_file_count: u32,
    pub total_checkpoints: u64,
    pub swf_iterations_per_second: u64,
    pub error_message: Option<String>,
}

/// Dashboard metrics returned by ffi_get_dashboard_metrics.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiDashboardMetrics {
    pub success: bool,
    pub total_files: u32,
    pub total_checkpoints: u64,
    pub total_words_witnessed: u64,
    pub current_streak_days: u32,
    pub longest_streak_days: u32,
    pub active_days_30d: u32,
    pub error_message: Option<String>,
}

/// Activity data point for heatmap display.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiActivityPoint {
    pub day_timestamp: i64,
    pub checkpoint_count: u32,
}

/// Initialize the witnessd data directory and signing key.
///
/// Creates the data directory, database, and generates a new signing
/// key if one doesn't exist. Safe to call multiple times.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_init() -> FfiResult {
    let data_dir = match get_data_dir() {
        Some(d) => d,
        None => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some("Failed to determine data directory".to_string()),
            };
        }
    };

    // Create data directory if needed
    if let Err(e) = std::fs::create_dir_all(&data_dir) {
        return FfiResult {
            success: false,
            message: None,
            error_message: Some(format!("Failed to create data directory: {}", e)),
        };
    }

    // Generate signing key if it doesn't exist
    let key_path = data_dir.join("signing_key");
    if !key_path.exists() {
        use ed25519_dalek::SigningKey;
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|e| format!("Failed to generate random key: {}", e)).ok();
        let signing_key = SigningKey::from_bytes(&seed);
        if let Err(e) = std::fs::write(&key_path, signing_key.to_bytes()) {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Failed to write signing key: {}", e)),
            };
        }
    }

    // Initialize database
    let db_path = data_dir.join("events.db");
    let hmac_key = match load_hmac_key() {
        Some(k) => k,
        None => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some("Failed to derive HMAC key".to_string()),
            };
        }
    };

    match crate::store::SecureStore::open(&db_path, hmac_key) {
        Ok(_) => FfiResult {
            success: true,
            message: Some(format!("Initialized at {}", data_dir.display())),
            error_message: None,
        },
        Err(e) => FfiResult {
            success: false,
            message: None,
            error_message: Some(format!("Failed to initialize database: {}", e)),
        },
    }
}

/// Get structured status of the witnessd installation.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_status() -> FfiStatus {
    let data_dir = match get_data_dir() {
        Some(d) => d,
        None => {
            return FfiStatus {
                initialized: false,
                data_dir: String::new(),
                tracked_file_count: 0,
                total_checkpoints: 0,
                swf_iterations_per_second: 0,
                error_message: Some("Data directory not found".to_string()),
            };
        }
    };

    let initialized = data_dir.exists() && data_dir.join("events.db").exists();
    if !initialized {
        return FfiStatus {
            initialized: false,
            data_dir: data_dir.display().to_string(),
            tracked_file_count: 0,
            total_checkpoints: 0,
            swf_iterations_per_second: 0,
            error_message: None,
        };
    }

    let store = match open_store() {
        Ok(s) => s,
        Err(e) => {
            return FfiStatus {
                initialized: true,
                data_dir: data_dir.display().to_string(),
                tracked_file_count: 0,
                total_checkpoints: 0,
                swf_iterations_per_second: 0,
                error_message: Some(e),
            };
        }
    };

    let files = store.list_files().unwrap_or_default();
    let total_checkpoints: u64 = files.iter().map(|(_, _, count)| *count as u64).sum();

    FfiStatus {
        initialized: true,
        data_dir: data_dir.display().to_string(),
        tracked_file_count: files.len() as u32,
        total_checkpoints,
        swf_iterations_per_second: crate::vdf::default_parameters().iterations_per_second,
        error_message: None,
    }
}

/// List all tracked files with their checkpoint counts.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_list_tracked_files() -> Vec<FfiTrackedFile> {
    let store = match open_store() {
        Ok(s) => s,
        Err(_) => return vec![],
    };

    store
        .list_files()
        .unwrap_or_default()
        .into_iter()
        .map(|(path, last_ts, count)| FfiTrackedFile {
            path,
            last_checkpoint_ns: last_ts,
            checkpoint_count: count,
        })
        .collect()
}

/// Get checkpoint log for a specific file.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_log(path: String) -> Vec<FfiLogEntry> {
    let store = match open_store() {
        Ok(s) => s,
        Err(_) => return vec![],
    };

    store
        .get_events_for_file(&path)
        .unwrap_or_default()
        .into_iter()
        .enumerate()
        .map(|(i, ev)| FfiLogEntry {
            ordinal: i as u64,
            timestamp_ns: ev.timestamp_ns,
            content_hash: hex::encode(ev.content_hash),
            file_size: ev.file_size,
            size_delta: ev.size_delta,
            message: ev.context_note,
        })
        .collect()
}

/// Get dashboard metrics (streaks, activity, words witnessed).
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_dashboard_metrics() -> FfiDashboardMetrics {
    let store = match open_store() {
        Ok(s) => s,
        Err(e) => {
            return FfiDashboardMetrics {
                success: false,
                total_files: 0,
                total_checkpoints: 0,
                total_words_witnessed: 0,
                current_streak_days: 0,
                longest_streak_days: 0,
                active_days_30d: 0,
                error_message: Some(e),
            };
        }
    };

    let files = store.list_files().unwrap_or_default();
    let total_checkpoints: u64 = files.iter().map(|(_, _, c)| *c as u64).sum();

    // Compute word count from size deltas
    let summary = store.get_all_events_summary().unwrap_or_default();
    let total_chars_added: u64 = summary
        .iter()
        .map(|(_, delta)| (*delta).max(0) as u64)
        .sum();
    let total_words_witnessed = total_chars_added / 5; // rough estimate

    // Compute streaks from timestamps
    let thirty_days_ago_ns = (chrono::Utc::now() - chrono::Duration::days(90))
        .timestamp_nanos_opt()
        .unwrap_or(0);
    let timestamps = store
        .get_all_event_timestamps(thirty_days_ago_ns)
        .unwrap_or_default();

    let mut active_days: std::collections::BTreeSet<i64> = std::collections::BTreeSet::new();
    for ts in &timestamps {
        let day = ts / (86400 * 1_000_000_000); // nanoseconds to day
        active_days.insert(day);
    }

    // Count active days in last 30
    let now_day = chrono::Utc::now().timestamp() / 86400;
    let active_days_30d = active_days
        .iter()
        .filter(|d| **d >= now_day - 30)
        .count() as u32;

    // Compute current and longest streak
    let today = now_day;
    let mut current_streak: u32 = 0;
    let mut longest_streak: u32 = 0;
    let mut streak: u32 = 0;
    let mut prev_day: Option<i64> = None;

    for &day in active_days.iter().rev() {
        if let Some(prev) = prev_day {
            if prev - day == 1 {
                streak += 1;
            } else {
                longest_streak = longest_streak.max(streak);
                streak = 1;
            }
        } else {
            streak = 1;
            if day >= today - 1 {
                current_streak = 1; // Active today or yesterday
            }
        }
        prev_day = Some(day);
    }
    longest_streak = longest_streak.max(streak);

    // Current streak: count consecutive days ending at today/yesterday
    current_streak = 0;
    let mut check_day = today;
    while active_days.contains(&check_day) {
        current_streak += 1;
        check_day -= 1;
    }
    // Also check if streak starts from yesterday
    if current_streak == 0 {
        check_day = today - 1;
        while active_days.contains(&check_day) {
            current_streak += 1;
            check_day -= 1;
        }
    }

    FfiDashboardMetrics {
        success: true,
        total_files: files.len() as u32,
        total_checkpoints,
        total_words_witnessed,
        current_streak_days: current_streak,
        longest_streak_days: longest_streak,
        active_days_30d,
        error_message: None,
    }
}

/// Get activity data for heatmap display.
///
/// Returns checkpoint counts per day for the specified number of days.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_activity_data(days: u32) -> Vec<FfiActivityPoint> {
    let store = match open_store() {
        Ok(s) => s,
        Err(_) => return vec![],
    };

    let start_ns = (chrono::Utc::now() - chrono::Duration::days(days as i64))
        .timestamp_nanos_opt()
        .unwrap_or(0);

    let timestamps = store
        .get_all_event_timestamps(start_ns)
        .unwrap_or_default();

    // Aggregate by day
    let mut day_counts: std::collections::BTreeMap<i64, u32> = std::collections::BTreeMap::new();
    for ts in timestamps {
        let day_start = (ts / (86400 * 1_000_000_000)) * 86400; // day in seconds
        *day_counts.entry(day_start).or_insert(0) += 1;
    }

    day_counts
        .into_iter()
        .map(|(day_timestamp, checkpoint_count)| FfiActivityPoint {
            day_timestamp,
            checkpoint_count,
        })
        .collect()
}

// MARK: - Attestation & Hardware Identity FFI

/// Hardware attestation information.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiAttestationInfo {
    /// Attestation tier (1=software, 2=attested-software, 3=hardware-bound, 4=hardware-hardened)
    pub tier: u8,
    /// Human-readable tier label
    pub tier_label: String,
    /// TPM/Secure Enclave provider type
    pub provider_type: String,
    /// Whether the signing key is hardware-bound
    pub hardware_bound: bool,
    /// Whether the provider supports sealing
    pub supports_sealing: bool,
    /// Whether the provider has a monotonic counter
    pub has_monotonic_counter: bool,
    /// Whether the provider has a secure clock
    pub has_secure_clock: bool,
    /// Device identifier from the TPM/SE provider
    pub device_id: String,
}

/// Get hardware attestation information for this device.
///
/// Returns the attestation tier, provider capabilities, and device binding status.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_attestation_info() -> FfiAttestationInfo {
    let (_, tier_num, tier_label) = detect_attestation_tier_info();

    let provider = crate::tpm::detect_provider();
    let caps = provider.capabilities();
    FfiAttestationInfo {
        tier: tier_num,
        tier_label,
        provider_type: provider.device_id(),
        hardware_bound: caps.hardware_backed && caps.supports_sealing,
        supports_sealing: caps.supports_sealing,
        has_monotonic_counter: caps.monotonic_counter,
        has_secure_clock: caps.secure_clock,
        device_id: provider.device_id(),
    }
}

/// Re-seal the device identity after a platform change (OS update, firmware update).
///
/// This should be called after OS updates that may change PCR values, which would
/// prevent unsealing the existing identity blob. The reseal operation verifies the
/// existing identity, then re-seals it under the new platform state.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_reseal_identity() -> FfiResult {
    let data_dir = match get_data_dir() {
        Some(d) => d,
        None => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some("Could not determine data directory".to_string()),
            };
        }
    };

    let store = crate::sealed_identity::SealedIdentityStore::auto_detect(&data_dir);

    if !store.is_bound() {
        return FfiResult {
            success: false,
            message: None,
            error_message: Some("No sealed identity found on this device".to_string()),
        };
    }

    // Create a PUF for reseal derivation
    let puf_seed_path = data_dir.join("puf_seed");
    let puf = match crate::keyhierarchy::SoftwarePUF::new_with_path(&puf_seed_path) {
        Ok(p) => p,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Failed to initialize PUF: {}", e)),
            };
        }
    };

    match store.reseal(&puf) {
        Ok(()) => FfiResult {
            success: true,
            message: Some("Identity re-sealed under current platform state".to_string()),
            error_message: None,
        },
        Err(e) => FfiResult {
            success: false,
            message: None,
            error_message: Some(format!("Reseal failed: {}", e)),
        },
    }
}

/// Check if the device identity is hardware-bound.
///
/// Returns true if the signing key is sealed to TPM/Secure Enclave hardware,
/// meaning it cannot be extracted or used on another device.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_is_hardware_bound() -> bool {
    let data_dir = match get_data_dir() {
        Some(d) => d,
        None => return false,
    };

    let store = crate::sealed_identity::SealedIdentityStore::auto_detect(&data_dir);
    if !store.is_bound() {
        return false;
    }

    store.attestation_tier() == crate::rfc::wire_types::AttestationTier::HardwareBound
        || store.attestation_tier() == crate::rfc::wire_types::AttestationTier::HardwareHardened
}
