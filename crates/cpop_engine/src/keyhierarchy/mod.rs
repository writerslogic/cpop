// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

pub mod crypto;
pub mod error;
pub mod identity;
pub mod manager;
pub mod migration;
pub mod puf;
pub mod recovery;
pub mod session;
pub mod types;
pub mod verification;

#[cfg(test)]
mod tests;

pub use crypto::{compute_entangled_nonce, fingerprint_for_public_key, hkdf_expand};
pub use error::KeyHierarchyError;
pub use identity::derive_master_identity;
pub(crate) use identity::derive_master_private_key;
pub use manager::{ChainSigner, SessionManager};
pub use migration::{
    migrate_from_legacy_key, start_session_from_legacy_key, verify_legacy_migration,
};
pub use puf::{get_or_create_puf, SoftwarePUF};
pub use recovery::recover_session;
pub use session::{start_session, start_session_with_key};
pub use types::{
    CheckpointSignature, HardwareEvidence, KeyHierarchyEvidence, LegacyKeyMigration,
    MasterIdentity, PufProvider, Session, SessionBindingReport, SessionCertificate,
    SessionRecoveryState, VERSION,
};
pub use verification::{
    validate_cert_byte_lengths, verify_checkpoint_signatures, verify_key_hierarchy,
    verify_ratchet_key_consistency, verify_ratchet_signature, verify_session_binding,
    verify_session_certificate,
};
