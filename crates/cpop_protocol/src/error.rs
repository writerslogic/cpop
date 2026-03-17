// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use thiserror::Error;

/// Alias for `std::result::Result` with the protocol `Error` type.
pub type Result<T> = std::result::Result<T, Error>;

/// Protocol-level error covering I/O, serialization, crypto, and validation failures.
#[derive(Debug, Error)]
pub enum Error {
    /// Wrap a `std::io::Error`.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// CBOR/JSON serialization or deserialization failure.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Signing, verification, or HMAC computation failure.
    #[error("cryptographic error: {0}")]
    Crypto(String),

    /// Wire-format or state-machine protocol violation.
    #[error("protocol violation: {0}")]
    Protocol(String),

    /// Structural or semantic validation failure.
    #[error("validation failed: {0}")]
    Validation(String),

    /// Catch-all for unclassified errors.
    #[error("unknown error: {0}")]
    Unknown(String),
}
