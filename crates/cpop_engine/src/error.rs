// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Unified error type wrapping all subsystem errors for consistent handling
//! and pattern matching across the crate.

use thiserror::Error;

/// Top-level error type for cpop_engine.
#[derive(Debug, Error)]
pub enum Error {
    /// Anchor/timestamping subsystem error
    #[error("anchor: {0}")]
    Anchor(#[from] crate::anchors::AnchorError),

    /// Codec serialization/deserialization error
    #[error("codec: {0}")]
    Codec(#[from] crate::codec::CodecError),

    /// Compact reference error
    #[error("compact ref: {0}")]
    CompactRef(#[from] crate::compact_ref::CompactRefError),

    /// Forensics analysis error
    #[error("forensics: {0}")]
    Forensics(#[from] crate::forensics::ForensicsError),

    /// IPC communication error
    #[cfg(unix)]
    #[error("ipc: {0}")]
    Ipc(#[from] crate::ipc::unix_socket::IpcError),

    /// Key hierarchy error
    #[error("key hierarchy: {0}")]
    KeyHierarchy(#[from] crate::keyhierarchy::KeyHierarchyError),

    /// Merkle Mountain Range error
    #[error("mmr: {0}")]
    Mmr(#[from] crate::mmr::errors::MmrError),

    /// Sentinel (daemon) error
    #[error("sentinel: {0}")]
    Sentinel(#[from] crate::sentinel::SentinelError),

    /// TPM error
    #[error("tpm: {0}")]
    Tpm(#[from] crate::tpm::TpmError),

    /// VDF aggregation error
    #[error("vdf: {0}")]
    VdfAggregate(#[from] crate::vdf::AggregateError),

    /// Write-ahead log error
    #[error("wal: {0}")]
    Wal(#[from] crate::wal::WalError),

    /// I/O error
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// Cryptographic operation failed
    #[error("crypto: {0}")]
    Crypto(String),

    /// Signature verification failed
    #[error("signature: {0}")]
    Signature(String),

    /// Hash verification failed
    #[error("hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },

    /// Data validation failed
    #[error("validation: {0}")]
    Validation(String),

    /// Configuration error
    #[error("config: {0}")]
    Config(String),

    /// Resource not found
    #[error("not found: {0}")]
    NotFound(String),

    /// Invalid state for operation
    #[error("invalid state: {0}")]
    InvalidState(String),

    /// Operation timed out
    #[error("timeout: {0}")]
    Timeout(String),

    /// Checkpoint chain error
    #[error("checkpoint: {0}")]
    Checkpoint(String),

    /// Evidence generation/verification error
    #[error("evidence: {0}")]
    Evidence(String),

    /// VDF computation/verification error
    #[error("vdf: {0}")]
    Vdf(String),

    /// Identity/key management error
    #[error("identity: {0}")]
    Identity(String),

    /// Platform-specific error
    #[error("platform: {0}")]
    Platform(String),

    /// Physics/entropy error
    #[error("physics: {0}")]
    Physics(String),

    /// RFC structure error
    #[error("rfc: {0}")]
    Rfc(String),

    /// Internal error (should not occur in normal operation)
    #[error("internal: {0}")]
    Internal(String),

    /// Legacy error for migration from Result<T, String>
    #[error("{0}")]
    Legacy(String),
}

/// Crate-wide `Result` alias.
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Create a checkpoint chain error.
    pub fn checkpoint(msg: impl Into<String>) -> Self {
        Error::Checkpoint(msg.into())
    }

    /// Create an evidence generation/verification error.
    pub fn evidence(msg: impl Into<String>) -> Self {
        Error::Evidence(msg.into())
    }

    /// Create a VDF computation/verification error.
    pub fn vdf(msg: impl Into<String>) -> Self {
        Error::Vdf(msg.into())
    }

    /// Create a data validation error.
    pub fn validation(msg: impl Into<String>) -> Self {
        Error::Validation(msg.into())
    }

    /// Create a cryptographic operation error.
    pub fn crypto(msg: impl Into<String>) -> Self {
        Error::Crypto(msg.into())
    }

    /// Create a configuration error.
    pub fn config(msg: impl Into<String>) -> Self {
        Error::Config(msg.into())
    }

    /// Create a resource-not-found error.
    pub fn not_found(msg: impl Into<String>) -> Self {
        Error::NotFound(msg.into())
    }

    /// Create an invalid-state error.
    pub fn invalid_state(msg: impl Into<String>) -> Self {
        Error::InvalidState(msg.into())
    }

    /// Create a platform-specific error.
    pub fn platform(msg: impl Into<String>) -> Self {
        Error::Platform(msg.into())
    }

    /// Create an identity/key management error.
    pub fn identity(msg: impl Into<String>) -> Self {
        Error::Identity(msg.into())
    }

    /// Create a physics/entropy error.
    pub fn physics(msg: impl Into<String>) -> Self {
        Error::Physics(msg.into())
    }

    /// Create an RFC structure error.
    pub fn rfc(msg: impl Into<String>) -> Self {
        Error::Rfc(msg.into())
    }

    /// Create a signature verification error.
    pub fn signature(msg: impl Into<String>) -> Self {
        Error::Signature(msg.into())
    }

    /// Create an internal error (should not occur in normal operation).
    pub fn internal(msg: impl Into<String>) -> Self {
        Error::Internal(msg.into())
    }

    /// Returns `true` for errors that may succeed on retry (I/O, timeout, anchor).
    pub fn is_transient(&self) -> bool {
        matches!(self, Error::Io(_) | Error::Timeout(_) | Error::Anchor(_))
    }

    /// Returns `true` for validation/input errors (bad data, hash mismatch, bad sig).
    pub fn is_validation(&self) -> bool {
        matches!(
            self,
            Error::Validation(_) | Error::HashMismatch { .. } | Error::Signature(_)
        )
    }
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error::Legacy(s)
    }
}

impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Error::Legacy(s.to_string())
    }
}

impl From<Error> for String {
    fn from(e: Error) -> Self {
        e.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = Error::checkpoint("chain broken at index 5");
        assert_eq!(err.to_string(), "checkpoint: chain broken at index 5");
    }

    #[test]
    fn test_error_from_string() {
        let err: Error = "legacy error message".into();
        assert!(matches!(err, Error::Legacy(_)));
        assert_eq!(err.to_string(), "legacy error message");
    }

    #[test]
    fn test_error_to_string() {
        let err = Error::validation("invalid input");
        let s: String = err.into();
        assert_eq!(s, "validation: invalid input");
    }

    #[test]
    fn test_is_transient() {
        let timeout = Error::Timeout("operation timed out".into());
        assert!(timeout.is_transient());

        let validation = Error::Validation("bad input".into());
        assert!(!validation.is_transient());
    }

    #[test]
    fn test_is_validation() {
        let validation = Error::Validation("bad input".into());
        assert!(validation.is_validation());

        let hash_mismatch = Error::HashMismatch {
            expected: "abc".into(),
            actual: "def".into(),
        };
        assert!(hash_mismatch.is_validation());

        let io = Error::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "file"));
        assert!(!io.is_validation());
    }

    #[test]
    fn test_constructors() {
        assert!(matches!(Error::checkpoint("test"), Error::Checkpoint(_)));
        assert!(matches!(Error::evidence("test"), Error::Evidence(_)));
        assert!(matches!(Error::vdf("test"), Error::Vdf(_)));
        assert!(matches!(Error::validation("test"), Error::Validation(_)));
        assert!(matches!(Error::crypto("test"), Error::Crypto(_)));
        assert!(matches!(Error::config("test"), Error::Config(_)));
        assert!(matches!(Error::not_found("test"), Error::NotFound(_)));
        assert!(matches!(
            Error::invalid_state("test"),
            Error::InvalidState(_)
        ));
        assert!(matches!(Error::platform("test"), Error::Platform(_)));
        assert!(matches!(Error::identity("test"), Error::Identity(_)));
        assert!(matches!(Error::physics("test"), Error::Physics(_)));
        assert!(matches!(Error::rfc("test"), Error::Rfc(_)));
        assert!(matches!(Error::signature("test"), Error::Signature(_)));
        assert!(matches!(Error::internal("test"), Error::Internal(_)));
    }
}
