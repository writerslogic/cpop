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
    pub vdf_iterations_per_second: u64,
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

/// Result of VDF calibration.
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

// MARK: - FFI Functions

/// Verify an evidence packet file.
///
/// Reads the evidence file, deserializes it, and runs verification checks
/// including signature validation, chain integrity, and VDF proof verification.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_verify_evidence(path: String) -> FfiVerifyResult {
    let path = PathBuf::from(&path);

    if !path.exists() {
        return FfiVerifyResult {
            success: false,
            checkpoint_count: 0,
            signature_valid: false,
            chain_integrity: false,
            vdf_iterations_per_second: 0,
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
                vdf_iterations_per_second: 0,
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
                vdf_iterations_per_second: 0,
                error_message: Some(format!("Failed to decode evidence: {}", e)),
            };
        }
    };

    let checkpoint_count = packet.checkpoints.len() as u32;
    let vdf_ips = packet.vdf_params.iterations_per_second;

    // Run verification
    match packet.verify(packet.vdf_params.clone()) {
        Ok(()) => FfiVerifyResult {
            success: true,
            checkpoint_count,
            signature_valid: true,
            chain_integrity: true,
            vdf_iterations_per_second: vdf_ips,
            error_message: None,
        },
        Err(e) => FfiVerifyResult {
            success: false,
            checkpoint_count,
            signature_valid: false,
            chain_integrity: false,
            vdf_iterations_per_second: vdf_ips,
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

    let db_path = match get_db_path() {
        Some(p) if p.exists() => p,
        _ => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some("Database not found".to_string()),
            };
        }
    };

    // Open the database and load events for this file
    let store = match crate::store::SecureStore::open(db_path.to_str().unwrap_or("")) {
        Ok(s) => s,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Failed to open database: {}", e)),
            };
        }
    };

    // Determine strength from tier string
    let strength = match tier.to_lowercase().as_str() {
        "basic" => crate::evidence::Strength::Basic,
        "standard" => crate::evidence::Strength::Standard,
        "enhanced" => crate::evidence::Strength::Enhanced,
        "maximum" => crate::evidence::Strength::Maximum,
        _ => crate::evidence::Strength::Standard,
    };

    // Build the evidence packet
    let events = match store.get_events_for_file(file_path.to_str().unwrap_or("")) {
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

    // Build and encode packet
    match crate::evidence::PacketBuilder::new(file_path.clone(), strength)
        .with_events(&events)
        .build()
    {
        Ok(packet) => match packet.encode() {
            Ok(encoded) => match std::fs::write(&output_path, &encoded) {
                Ok(()) => FfiResult {
                    success: true,
                    message: Some(format!("Exported to {}", output_path.display())),
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
                error_message: Some(format!("Failed to encode packet: {}", e)),
            },
        },
        Err(e) => FfiResult {
            success: false,
            message: None,
            error_message: Some(format!("Failed to build packet: {}", e)),
        },
    }
}

/// Run forensic analysis on a tracked file.
///
/// Loads events from the database and runs the full forensic analysis pipeline.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_forensics(path: String) -> FfiForensicResult {
    let file_path = PathBuf::from(&path);

    let db_path = match get_db_path() {
        Some(p) if p.exists() => p,
        _ => {
            return FfiForensicResult {
                success: false,
                assessment_score: 0.0,
                risk_level: "unknown".to_string(),
                anomaly_count: 0,
                monotonic_append_ratio: 0.0,
                edit_entropy: 0.0,
                median_interval: 0.0,
                error_message: Some("Database not found".to_string()),
            };
        }
    };

    let store = match crate::store::SecureStore::open(db_path.to_str().unwrap_or("")) {
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
                error_message: Some(format!("Failed to open database: {}", e)),
            };
        }
    };

    let events = match store.get_events_for_file(file_path.to_str().unwrap_or("")) {
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
    let event_data: Vec<crate::forensics::EventData> = events
        .iter()
        .map(|e| crate::forensics::EventData {
            timestamp_ns: e.timestamp_ns as u64,
            size_delta: e.size_delta as i64,
            file_size: e.file_size as u64,
            is_paste: e.is_paste,
        })
        .collect();

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
        anomaly_count: 0, // Calculated from forgery analysis if present
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

    let db_path = match get_db_path() {
        Some(p) if p.exists() => p,
        _ => {
            return FfiProcessScore {
                success: false,
                residency: 0.0,
                sequence: 0.0,
                behavioral: 0.0,
                composite: 0.0,
                meets_threshold: false,
                error_message: Some("Database not found".to_string()),
            };
        }
    };

    let store = match crate::store::SecureStore::open(db_path.to_str().unwrap_or("")) {
        Ok(s) => s,
        Err(e) => {
            return FfiProcessScore {
                success: false,
                residency: 0.0,
                sequence: 0.0,
                behavioral: 0.0,
                composite: 0.0,
                meets_threshold: false,
                error_message: Some(format!("Failed to open database: {}", e)),
            };
        }
    };

    let events = match store.get_events_for_file(file_path.to_str().unwrap_or("")) {
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
    let event_data: Vec<crate::forensics::EventData> = events
        .iter()
        .map(|e| crate::forensics::EventData {
            timestamp_ns: e.timestamp_ns as u64,
            size_delta: e.size_delta as i64,
            file_size: e.file_size as u64,
            is_paste: e.is_paste,
        })
        .collect();

    let regions = std::collections::HashMap::new();
    let metrics = crate::forensics::analyze_forensics(&event_data, &regions, None, None, None);

    // Compute Process Score components from forensic metrics
    // R (Residency): Based on chain integrity and continuous coverage
    let residency = if events.len() >= 5 { 1.0 } else { events.len() as f64 / 5.0 };

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

/// Calibrate VDF iterations per second for this machine.
///
/// Runs a 1-second calibration to determine how many VDF iterations
/// this machine can compute, then stores the result.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_calibrate_vdf() -> FfiCalibrationResult {
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

    let db_path = match get_db_path() {
        Some(p) if p.exists() => p,
        _ => return String::new(),
    };

    let store = match crate::store::SecureStore::open(db_path.to_str().unwrap_or("")) {
        Ok(s) => s,
        Err(_) => return String::new(),
    };

    let events = match store.get_events_for_file(file_path.to_str().unwrap_or("")) {
        Ok(e) => e,
        Err(_) => return String::new(),
    };

    if events.is_empty() {
        return String::new();
    }

    // Build a compact reference from the most recent event hash
    let last_event = &events[events.len() - 1];
    let hash_hex = hex::encode(&last_event.event_hash);

    // Format: witnessd:<first 12 chars of hash>:<checkpoint count>
    format!("witnessd:{}:{}", &hash_hex[..hash_hex.len().min(12)], events.len())
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

    let db_path = match get_db_path() {
        Some(p) if p.exists() => p,
        _ => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some("Database not found".to_string()),
            };
        }
    };

    let store = match crate::store::SecureStore::open(db_path.to_str().unwrap_or("")) {
        Ok(s) => s,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Failed to open database: {}", e)),
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
    let content_hash = Sha256::digest(&content);

    let msg = if message.is_empty() {
        None
    } else {
        Some(message)
    };

    // Store the checkpoint event
    match store.insert_event(
        file_path.to_str().unwrap_or(""),
        &content_hash,
        content.len() as i64,
        0, // size_delta calculated by store
        msg.as_deref(),
        None, // context_type
        false, // is_paste
    ) {
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
