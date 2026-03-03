// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#[derive(Debug, thiserror::Error)]
pub enum KeyHierarchyError {
    #[error("keyhierarchy: ratchet state has been wiped")]
    RatchetWiped,
    #[error("keyhierarchy: invalid session certificate")]
    InvalidCert,
    #[error("keyhierarchy: checkpoint ordinal mismatch")]
    OrdinalMismatch,
    #[error("keyhierarchy: signature verification failed")]
    SignatureFailed,
    #[error("keyhierarchy: checkpoint hash mismatch")]
    HashMismatch,
    #[error("keyhierarchy: legacy signing key not found")]
    LegacyKeyNotFound,
    #[error("keyhierarchy: migration failed")]
    MigrationFailed,
    #[error("keyhierarchy: invalid migration record")]
    InvalidMigration,
    #[error("keyhierarchy: session cannot be recovered")]
    SessionNotRecoverable,
    #[error("keyhierarchy: session recovery failed")]
    SessionRecoveryFailed,
    #[error("keyhierarchy: no recovery data available")]
    NoRecoveryData,
    #[error("keyhierarchy: failed to initialize software PUF")]
    SoftwarePUFInit,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("crypto error: {0}")]
    Crypto(String),
}
