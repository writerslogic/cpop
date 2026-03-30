// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

/// Alias for `std::result::Result` with the protocol `Error` type.
pub type Result<T> = std::result::Result<T, Error>;

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

    #[error("validation failed: {0}")]
    Validation(String),

    #[error("unknown error: {0}")]
    Unknown(String),
}
