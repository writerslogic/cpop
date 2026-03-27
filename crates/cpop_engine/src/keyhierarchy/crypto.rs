// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::DateTimeNanosExt;
use chrono::{DateTime, Utc};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use super::error::KeyHierarchyError;

pub(crate) const IDENTITY_DOMAIN: &str = "witnessd-identity-v1";
pub(crate) const SESSION_DOMAIN: &str = "witnessd-session-v1";
pub(crate) const RATCHET_INIT_DOMAIN: &str = "witnessd-ratchet-init-v1";
pub(crate) const RATCHET_ADVANCE_DOMAIN: &str = "witnessd-ratchet-advance-v1";
pub(crate) const SIGNING_KEY_DOMAIN: &str = "witnessd-signing-key-v1";

/// HKDF-SHA256 key derivation: `ikm` is the input keying material, `salt` is the
/// HKDF salt (passed as the info/domain label by callers), and `info` is the
/// context-specific binding (e.g. session input or empty). Matches RFC 5869.
pub fn hkdf_expand(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<[u8; 32], KeyHierarchyError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .map_err(|_| KeyHierarchyError::Crypto("HKDF expand failed".to_string()))?;
    Ok(okm)
}

pub(crate) fn build_cert_data(
    session_id: [u8; 32],
    session_pub_key: &[u8],
    created_at: DateTime<Utc>,
    document_hash: [u8; 32],
) -> Vec<u8> {
    let mut data = Vec::with_capacity(32 + 32 + 8 + 32);
    data.extend_from_slice(&session_id);
    data.extend_from_slice(session_pub_key);
    let nanos = created_at.timestamp_nanos_safe();
    if nanos < 0 {
        // Pre-epoch timestamps would wrap in u64 encoding; reject
        // to prevent certificate substitution attacks
        log::warn!("build_cert_data: rejecting pre-epoch timestamp");
    }
    data.extend_from_slice(&(nanos.max(0) as u64).to_be_bytes());
    data.extend_from_slice(&document_hash);
    data
}

pub fn fingerprint_for_public_key(public_key: &[u8]) -> String {
    let digest = Sha256::digest(public_key);
    hex::encode(&digest[0..8])
}

/// SHA-256(session_id || data_hash || mmr_root) nonce that binds a TPM quote
/// to the exact authorship chain state, preventing cross-session quote replay.
pub fn compute_entangled_nonce(
    session_id: &[u8; 32],
    data_hash: &[u8; 32],
    mmr_root: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"witnessd-entangled-nonce-v1");
    hasher.update(session_id);
    hasher.update(data_hash);
    hasher.update(mmr_root);
    hasher.finalize().into()
}
