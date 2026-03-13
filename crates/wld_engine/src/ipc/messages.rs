// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::jitter::SimpleJitterSample;
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};

/// 1 MB cap on IPC frames
pub(crate) const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// Reject paths with `..` components, relative paths, or paths that resolve
/// into system directories. Called on every PathBuf deserialized from an IPC
/// message before any handler touches the filesystem.
fn validate_ipc_path(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(format!(
            "Relative path rejected (must be absolute): '{}'",
            path.display()
        ));
    }

    for component in path.components() {
        if matches!(component, Component::ParentDir) {
            return Err(format!("Path traversal rejected: '{}'", path.display()));
        }
    }

    // First line of defense at IPC boundary; sentinel::validate_path() does a
    // second check post-canonicalization.
    #[cfg(unix)]
    {
        let s = path.to_string_lossy();
        const BLOCKED: &[&str] = &[
            "/etc/",
            "/var/root/",
            "/System/",
            "/Library/",
            "/proc/",
            "/dev/",
            "/sys/",
            "/root/",
            "/private/etc/",
            "/private/var/root/",
            "/boot/",
            "/sbin/",
            "/bin/",
        ];
        for prefix in BLOCKED {
            if s.starts_with(prefix) {
                return Err("Access to system directory denied".to_string());
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        let s = path.to_string_lossy();
        let lower = s.to_lowercase();
        const BLOCKED_WIN: &[&str] = &[
            r"c:\windows\",
            r"c:\program files\",
            r"c:\program files (x86)\",
            r"c:\programdata\",
        ];
        for prefix in BLOCKED_WIN {
            if lower.starts_with(prefix) {
                return Err("Access to system directory denied".to_string());
            }
        }
    }

    Ok(())
}

/// IPC message protocol between the engine (Brain) and GUI (Face).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcMessage {
    Handshake {
        version: String,
    },
    StartWitnessing {
        file_path: PathBuf,
    },
    StopWitnessing {
        file_path: Option<PathBuf>,
    },
    GetStatus,

    GetAttestationNonce,
    ExportWithNonce {
        file_path: PathBuf,
        title: String,
        verifier_nonce: [u8; 32],
    },
    VerifyWithNonce {
        evidence_path: PathBuf,
        expected_nonce: Option<[u8; 32]>,
    },

    Pulse(SimpleJitterSample),
    CheckpointCreated {
        id: i64,
        hash: [u8; 32],
    },
    SystemAlert {
        level: String,
        message: String,
    },

    Heartbeat,

    Ok {
        message: Option<String>,
    },
    Error {
        code: IpcErrorCode,
        message: String,
    },
    HandshakeAck {
        version: String,
        server_version: String,
    },
    HeartbeatAck {
        timestamp_ns: u64,
    },
    StatusResponse {
        running: bool,
        tracked_files: Vec<String>,
        uptime_secs: u64,
    },
    AttestationNonceResponse {
        nonce: [u8; 32],
    },
    NonceExportResponse {
        success: bool,
        output_path: Option<String>,
        packet_hash: Option<String>,
        verifier_nonce: Option<String>,
        attestation_nonce: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        attestation_report: Option<String>,
        error: Option<String>,
    },
    NonceVerifyResponse {
        valid: bool,
        nonce_valid: bool,
        checkpoint_count: u64,
        total_elapsed_time_secs: f64,
        verifier_nonce: Option<String>,
        attestation_nonce: Option<String>,
        errors: Vec<String>,
    },

    VerifyFile {
        path: PathBuf,
    },
    VerifyFileResponse {
        success: bool,
        checkpoint_count: u32,
        signature_valid: bool,
        chain_integrity: bool,
        vdf_iterations_per_second: u64,
        error: Option<String>,
    },

    ExportFile {
        path: PathBuf,
        tier: String,
        output: PathBuf,
    },
    ExportFileResponse {
        success: bool,
        error: Option<String>,
    },

    GetFileForensics {
        path: PathBuf,
    },
    ForensicsResponse {
        assessment_score: f64,
        risk_level: String,
        anomaly_count: u32,
        monotonic_append_ratio: f64,
        edit_entropy: f64,
        median_interval: f64,
        /// Biological cadence steadiness (0.0-1.0, higher = steadier typing rhythm)
        biological_cadence_score: f64,
        error: Option<String>,
    },

    ComputeProcessScore {
        path: PathBuf,
    },
    ProcessScoreResponse {
        residency: f64,
        sequence: f64,
        behavioral: f64,
        composite: f64,
        meets_threshold: bool,
        error: Option<String>,
    },

    CreateFileCheckpoint {
        path: PathBuf,
        message: String,
    },
    CheckpointResponse {
        success: bool,
        hash: Option<String>,
        error: Option<String>,
    },
}

impl IpcMessage {
    /// Validate all PathBuf fields in this message against traversal attacks.
    /// Must be called immediately after deserialization, before dispatching to any handler.
    pub(crate) fn validate_paths(&self) -> Result<(), String> {
        match self {
            IpcMessage::StartWitnessing { file_path } => {
                validate_ipc_path(file_path)?;
            }
            IpcMessage::StopWitnessing { file_path: Some(p) } => {
                validate_ipc_path(p)?;
            }
            IpcMessage::ExportWithNonce { file_path, .. } => {
                validate_ipc_path(file_path)?;
            }
            IpcMessage::VerifyWithNonce { evidence_path, .. } => {
                validate_ipc_path(evidence_path)?;
            }
            IpcMessage::VerifyFile { path } => {
                validate_ipc_path(path)?;
            }
            IpcMessage::ExportFile { path, output, .. } => {
                validate_ipc_path(path)?;
                validate_ipc_path(output)?;
            }
            IpcMessage::GetFileForensics { path } => {
                validate_ipc_path(path)?;
            }
            IpcMessage::ComputeProcessScore { path } => {
                validate_ipc_path(path)?;
            }
            IpcMessage::CreateFileCheckpoint { path, .. } => {
                validate_ipc_path(path)?;
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum IpcErrorCode {
    Unknown = 0,
    InvalidMessage = 1,
    FileNotFound = 2,
    AlreadyTracking = 3,
    NotTracking = 4,
    PermissionDenied = 5,
    VersionMismatch = 6,
    InternalError = 7,
    NonceInvalid = 8,
    NotInitialized = 9,
}

pub trait IpcMessageHandler: Send + Sync + 'static {
    fn handle(&self, msg: IpcMessage) -> IpcMessage;
}
