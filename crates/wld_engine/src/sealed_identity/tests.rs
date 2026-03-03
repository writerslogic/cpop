// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::*;
use crate::keyhierarchy::{KeyHierarchyError, PUFProvider};
use crate::rfc::wire_types::AttestationTier;
use crate::tpm::{ProviderHandle, SoftwareProvider};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tempfile::TempDir;

struct TestPUF;
impl PUFProvider for TestPUF {
    fn get_response(&self, challenge: &[u8]) -> Result<Vec<u8>, KeyHierarchyError> {
        let mut hasher = Sha256::new();
        hasher.update(b"test-puf-seed");
        hasher.update(challenge);
        Ok(hasher.finalize().to_vec())
    }
    fn device_id(&self) -> String {
        "test-device".to_string()
    }
}

#[test]
fn test_sealed_identity_software_fallback() {
    let tmp = TempDir::new().unwrap();
    let provider: ProviderHandle = Arc::new(SoftwareProvider::new());
    let store = SealedIdentityStore::new(provider, tmp.path());
    let puf = TestPUF;

    let identity = store.initialize(&puf).unwrap();
    assert!(!identity.public_key.is_empty());
    assert!(!identity.fingerprint.is_empty());
    assert!(store.is_bound());

    let pub_id = store.public_identity().unwrap();
    assert_eq!(pub_id.public_key, identity.public_key);
    assert_eq!(pub_id.fingerprint, identity.fingerprint);
    assert_eq!(store.attestation_tier(), AttestationTier::SoftwareOnly);
}

#[test]
fn test_sealed_identity_counter_advance() {
    let tmp = TempDir::new().unwrap();
    let provider: ProviderHandle = Arc::new(SoftwareProvider::new());
    let store = SealedIdentityStore::new(provider, tmp.path());
    let puf = TestPUF;

    store.initialize(&puf).unwrap();
    store.advance_counter(5).unwrap();
    store.advance_counter(10).unwrap();

    let result = store.advance_counter(8);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        SealedIdentityError::RollbackDetected { .. }
    ));
}

#[test]
fn test_sealed_identity_reseal() {
    let tmp = TempDir::new().unwrap();
    let provider: ProviderHandle = Arc::new(SoftwareProvider::new());
    let store = SealedIdentityStore::new(provider, tmp.path());
    let puf = TestPUF;

    let identity = store.initialize(&puf).unwrap();

    store.reseal(&puf).unwrap();

    let pub_id = store.public_identity().unwrap();
    assert_eq!(pub_id.public_key, identity.public_key);
}

#[test]
fn test_sealed_identity_reinitialize() {
    let tmp = TempDir::new().unwrap();
    let provider: ProviderHandle = Arc::new(SoftwareProvider::new());
    let store = SealedIdentityStore::new(provider, tmp.path());
    let puf = TestPUF;
    let id1 = store.initialize(&puf).unwrap();
    let id2 = store.initialize(&puf).unwrap();
    assert_eq!(id1.public_key, id2.public_key);
}
