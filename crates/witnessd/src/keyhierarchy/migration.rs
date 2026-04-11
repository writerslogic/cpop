// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::DateTimeNanosExt;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::fs;
use std::path::Path;
use zeroize::Zeroizing;

use super::error::KeyHierarchyError;
use super::identity::derive_master_identity;
use super::session::start_session_inner;
use super::types::{LegacyKeyMigration, MasterIdentity, PufProvider, Session, VERSION};

pub fn migrate_from_legacy_key(
    puf: &dyn PufProvider,
    legacy_key_path: impl AsRef<Path>,
) -> Result<(LegacyKeyMigration, MasterIdentity), KeyHierarchyError> {
    let legacy_key = load_legacy_private_key(legacy_key_path)?;
    let legacy_pub = legacy_key.verifying_key().to_bytes().to_vec();

    let new_identity = derive_master_identity(puf)?;

    let migration_ts = Utc::now();
    let data = build_migration_data(&legacy_pub, &new_identity.public_key, migration_ts);
    let signature = legacy_key.sign(&data).to_bytes();

    Ok((
        LegacyKeyMigration {
            legacy_public_key: legacy_pub,
            new_master_public_key: new_identity.public_key.to_vec(),
            migration_timestamp: migration_ts,
            transition_signature: signature,
            version: VERSION,
        },
        new_identity,
    ))
}

pub fn verify_legacy_migration(migration: &LegacyKeyMigration) -> Result<(), KeyHierarchyError> {
    if migration.legacy_public_key.len() != 32 || migration.new_master_public_key.len() != 32 {
        return Err(KeyHierarchyError::InvalidMigration);
    }

    let data = build_migration_data(
        &migration.legacy_public_key,
        &migration.new_master_public_key,
        migration.migration_timestamp,
    );

    let pubkey = VerifyingKey::from_bytes(
        migration
            .legacy_public_key
            .as_slice()
            .try_into()
            .map_err(|_| KeyHierarchyError::InvalidMigration)?,
    )
    .map_err(|_| KeyHierarchyError::InvalidMigration)?;
    let signature = Signature::from_bytes(&migration.transition_signature);
    pubkey
        .verify(&data, &signature)
        .map_err(|_| KeyHierarchyError::InvalidMigration)
}

fn build_migration_data(
    legacy_pub: &[u8],
    new_master_pub: &[u8],
    timestamp: DateTime<Utc>,
) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(b"witnessd-key-migration-v1");
    data.extend_from_slice(legacy_pub);
    data.extend_from_slice(new_master_pub);
    data.extend_from_slice(&(timestamp.timestamp_nanos_safe().max(0) as u64).to_be_bytes());
    data
}

fn load_legacy_private_key(path: impl AsRef<Path>) -> Result<SigningKey, KeyHierarchyError> {
    let data: Zeroizing<Vec<u8>> = Zeroizing::new(fs::read(path)?);

    if data.len() == 32 {
        let mut seed: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(&data);
        Ok(SigningKey::from_bytes(&seed))
    } else if data.len() == 64 {
        let mut seed: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(&data[0..32]);
        let key = SigningKey::from_bytes(&seed);
        let expected_pub = key.verifying_key().to_bytes();
        if data[32..64] != expected_pub[..] {
            return Err(KeyHierarchyError::LegacyKeyNotFound);
        }
        Ok(key)
    } else {
        Err(KeyHierarchyError::LegacyKeyNotFound)
    }
}

pub fn start_session_from_legacy_key(
    legacy_key_path: impl AsRef<Path>,
    document_hash: [u8; 32],
) -> Result<Session, KeyHierarchyError> {
    let legacy_key = load_legacy_private_key(legacy_key_path)?;
    start_session_inner(&legacy_key, document_hash)
}
