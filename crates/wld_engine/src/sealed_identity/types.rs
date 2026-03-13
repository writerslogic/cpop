// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::keyhierarchy::KeyHierarchyError;
use crate::tpm::TPMError;

/// Errors from sealed identity operations (seal, unseal, anti-rollback).
#[derive(Debug, thiserror::Error)]
pub enum SealedIdentityError {
    /// No TPM or Secure Enclave provider detected.
    #[error("sealed identity: no TPM provider available")]
    NoProvider,
    /// Sealing the identity seed to hardware failed.
    #[error("sealed identity: sealing failed: {0}")]
    SealFailed(String),
    /// Unsealing the identity seed from hardware failed.
    #[error("sealed identity: unsealing failed: {0}")]
    UnsealFailed(String),
    /// Monotonic counter regression detected (replay/rollback attack).
    #[error("sealed identity: rollback detected (counter {current} < last known {last_known})")]
    RollbackDetected { current: u64, last_known: u64 },
    /// Platform reboot detected during an active session.
    #[error("sealed identity: reboot detected during session")]
    RebootDetected,
    /// Sealed blob failed integrity check or has invalid structure.
    #[error("sealed identity: blob corrupted")]
    BlobCorrupted,
    /// Propagated key hierarchy derivation error.
    #[error("sealed identity: key hierarchy error: {0}")]
    KeyHierarchy(#[from] KeyHierarchyError),
    /// Propagated TPM/Secure Enclave error.
    #[error("sealed identity: TPM error: {0}")]
    Tpm(#[from] TPMError),
    /// Propagated filesystem I/O error.
    #[error("sealed identity: IO error: {0}")]
    Io(#[from] std::io::Error),
    /// JSON serialization or deserialization error.
    #[error("sealed identity: serialization error: {0}")]
    Serialization(String),
}

/// Persistent sealed identity blob stored on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SealedBlob {
    pub version: u32,
    pub provider_type: String,
    pub device_id: String,
    pub sealed_seed: Vec<u8>,
    pub public_key: Vec<u8>,
    pub fingerprint: String,
    pub sealed_at: DateTime<Utc>,
    pub counter_at_seal: Option<u64>,
    pub last_known_counter: Option<u64>,
    pub boot_count_at_seal: Option<u32>,
    pub restart_count_at_seal: Option<u32>,
}

/// Current version of the sealed blob on-disk format.
pub const SEALED_BLOB_VERSION: u32 = 1;
/// Filename for the sealed identity blob within the data directory.
pub const SEALED_BLOB_FILENAME: &str = "identity.sealed";
