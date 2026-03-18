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
    if is_blocked_system_path(path)? {
        return Err("Access to system directory denied".to_string());
    }

    Ok(())
}

/// Blocked system directory prefixes for Unix platforms.
#[cfg(unix)]
pub(crate) const BLOCKED_UNIX_PREFIXES: &[&str] = &[
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

/// Blocked system directory prefixes for Windows platforms.
#[cfg(target_os = "windows")]
pub(crate) const BLOCKED_WINDOWS_PREFIXES: &[&str] = &[
    r"c:\windows\",
    r"c:\program files\",
    r"c:\program files (x86)\",
    r"c:\programdata\",
];

/// Check whether a path falls under a blocked system directory.
///
/// Shared by both IPC-layer validation (`validate_ipc_path`) and
/// sentinel-layer validation (`validate_canonical_path`).
pub(crate) fn is_blocked_system_path(path: &Path) -> Result<bool, String> {
    #[cfg(unix)]
    {
        let s = path.to_string_lossy();
        for prefix in BLOCKED_UNIX_PREFIXES {
            if s.starts_with(prefix) {
                return Ok(true);
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        let s = path.to_string_lossy();
        let lower = s.to_lowercase();
        // Strip UNC extended-length prefix so \\?\C:\Windows\... is caught.
        let normalized = lower
            .strip_prefix(r"\\?\")
            .or_else(|| lower.strip_prefix(r"\??\"))
            .unwrap_or(&lower);
        for prefix in BLOCKED_WINDOWS_PREFIXES {
            if normalized.starts_with(prefix) {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

/// IPC message protocol between the engine (Brain) and GUI (Face).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcMessage {
    /// Client initiates connection with its version string.
    Handshake { version: String },
    /// Begin witnessing a file at the given path.
    StartWitnessing { file_path: PathBuf },
    /// Stop witnessing a specific file, or all files if None.
    StopWitnessing { file_path: Option<PathBuf> },
    /// Request current daemon status.
    GetStatus,

    /// Request the session attestation nonce bound to TPM/TEE state.
    GetAttestationNonce,
    /// Export evidence with a verifier-provided nonce for replay prevention.
    ExportWithNonce {
        file_path: PathBuf,
        title: String,
        verifier_nonce: [u8; 32],
    },
    /// Verify evidence with optional nonce validation.
    VerifyWithNonce {
        evidence_path: PathBuf,
        expected_nonce: Option<[u8; 32]>,
    },

    /// Keystroke timing jitter sample from the GUI.
    Pulse(SimpleJitterSample),
    /// Notification that a checkpoint was persisted.
    CheckpointCreated { id: i64, hash: [u8; 32] },
    /// System-level alert forwarded to the GUI.
    SystemAlert { level: String, message: String },

    /// Keep-alive ping from client.
    Heartbeat,

    /// Generic success response with optional detail message.
    Ok { message: Option<String> },
    /// Generic error response with structured error code.
    Error { code: IpcErrorCode, message: String },
    /// Server acknowledges handshake with its version.
    HandshakeAck {
        version: String,
        server_version: String,
    },
    /// Server acknowledges heartbeat with current timestamp.
    HeartbeatAck { timestamp_ns: u64 },
    /// Daemon status: running state, tracked files, and uptime.
    StatusResponse {
        running: bool,
        tracked_files: Vec<String>,
        uptime_secs: u64,
    },
    /// Return the 32-byte attestation nonce for this session.
    AttestationNonceResponse { nonce: [u8; 32] },
    /// Result of a nonce-bound evidence export.
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
    /// Result of a nonce-bound evidence verification.
    NonceVerifyResponse {
        valid: bool,
        nonce_valid: bool,
        checkpoint_count: u64,
        total_elapsed_time_secs: f64,
        verifier_nonce: Option<String>,
        attestation_nonce: Option<String>,
        errors: Vec<String>,
    },

    /// Verify an evidence packet at the given path.
    VerifyFile { path: PathBuf },
    /// Result of evidence file verification.
    VerifyFileResponse {
        success: bool,
        checkpoint_count: u32,
        signature_valid: bool,
        chain_integrity: bool,
        vdf_iterations_per_second: u64,
        error: Option<String>,
    },

    /// Export evidence for a file at the specified tier.
    ExportFile {
        path: PathBuf,
        tier: String,
        output: PathBuf,
    },
    /// Result of evidence file export.
    ExportFileResponse {
        success: bool,
        error: Option<String>,
    },

    /// Request forensic analysis of a tracked file.
    GetFileForensics { path: PathBuf },
    /// Forensic analysis results for a tracked file.
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

    /// Request composite process score for a tracked file.
    ComputeProcessScore { path: PathBuf },
    /// Composite process score breakdown.
    ProcessScoreResponse {
        residency: f64,
        sequence: f64,
        behavioral: f64,
        composite: f64,
        meets_threshold: bool,
        error: Option<String>,
    },

    /// Create a manual checkpoint for a tracked file.
    CreateFileCheckpoint { path: PathBuf, message: String },
    /// Result of checkpoint creation.
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

/// Structured error codes for IPC error responses.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum IpcErrorCode {
    /// Unclassified error.
    Unknown = 0,
    /// Malformed or unrecognized message.
    InvalidMessage = 1,
    /// Referenced file does not exist.
    FileNotFound = 2,
    /// File is already being witnessed.
    AlreadyTracking = 3,
    /// File is not currently being witnessed.
    NotTracking = 4,
    /// Caller lacks permission for the requested operation.
    PermissionDenied = 5,
    /// Client/server protocol version incompatibility.
    VersionMismatch = 6,
    /// Unexpected internal failure.
    InternalError = 7,
    /// Supplied nonce is invalid or does not match.
    NonceInvalid = 8,
    /// Engine identity or subsystem not yet initialized.
    NotInitialized = 9,
}

/// Dispatch trait for handling incoming IPC messages and producing responses.
pub trait IpcMessageHandler: Send + Sync + 'static {
    /// Process an incoming message and return the response to send back.
    fn handle(&self, msg: IpcMessage) -> IpcMessage;
}
