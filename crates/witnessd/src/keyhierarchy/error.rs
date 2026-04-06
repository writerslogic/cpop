// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

#[derive(Debug, thiserror::Error)]
pub enum KeyHierarchyError {
    #[error("ratchet state has been wiped")]
    RatchetWiped,
    #[error("invalid session certificate")]
    InvalidCert,
    #[error("checkpoint ordinal mismatch")]
    OrdinalMismatch,
    #[error("signature verification failed")]
    SignatureFailed,
    #[error("checkpoint hash mismatch")]
    HashMismatch,
    #[error("legacy signing key not found")]
    LegacyKeyNotFound,
    #[error("migration failed")]
    MigrationFailed,
    #[error("invalid migration record")]
    InvalidMigration,
    #[error("session cannot be recovered")]
    SessionNotRecoverable,
    #[error("session recovery failed")]
    SessionRecoveryFailed,
    #[error("no recovery data available")]
    NoRecoveryData,
    #[error("failed to initialize software PUF")]
    SoftwarePUFInit,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("crypto error: {0}")]
    Crypto(String),
}
