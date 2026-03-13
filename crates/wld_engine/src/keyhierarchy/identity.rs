// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::crypto::{hkdf_expand, IDENTITY_DOMAIN};
use super::error::KeyHierarchyError;
use super::types::{MasterIdentity, PUFProvider, VERSION};

use chrono::Utc;

/// Derive the master signing key from the PUF challenge-response.
/// Shared by both `derive_master_identity` and `derive_master_private_key`.
fn derive_signing_key(puf: &dyn PUFProvider) -> Result<SigningKey, KeyHierarchyError> {
    let challenge = Sha256::digest(format!("{}-challenge", IDENTITY_DOMAIN).as_bytes());
    let puf_response = puf.get_response(&challenge)?;

    let seed = Zeroizing::new(hkdf_expand(
        &puf_response,
        IDENTITY_DOMAIN.as_bytes(),
        b"master-seed",
    )?);
    Ok(SigningKey::from_bytes(&seed))
}

/// Derive the master identity (public key + fingerprint) from the PUF provider.
pub fn derive_master_identity(puf: &dyn PUFProvider) -> Result<MasterIdentity, KeyHierarchyError> {
    let signing_key = derive_signing_key(puf)?;
    let public_key = signing_key.verifying_key().to_bytes().to_vec();

    let fingerprint = Sha256::digest(&public_key);
    let fingerprint_hex = hex::encode(&fingerprint[0..8]);

    Ok(MasterIdentity {
        public_key,
        fingerprint: fingerprint_hex,
        device_id: puf.device_id(),
        created_at: Utc::now(),
        version: VERSION,
    })
}

pub(crate) fn derive_master_private_key(
    puf: &dyn PUFProvider,
) -> Result<SigningKey, KeyHierarchyError> {
    derive_signing_key(puf)
}
