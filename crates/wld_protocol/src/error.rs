// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Cryptographic error: {0}")]
    Crypto(String),

    #[error("Protocol violation: {0}")]
    Protocol(String),

    #[error("Validation failed: {0}")]
    Validation(String),

    #[error("Unknown error: {0}")]
    Unknown(String),
}
