// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::*;
use crate::keyhierarchy::{KeyHierarchyError, PUFProvider};
use crate::rfc::wire_types::AttestationTier;
use crate::tpm::{ProviderHandle, SoftwareProvider};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tempfile::TempDir;
use zeroize::Zeroize;

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

#[test]
fn test_error_display_no_provider() {
    let err = SealedIdentityError::NoProvider;
    assert_eq!(
        err.to_string(),
        "sealed identity: no TPM provider available"
    );
}

#[test]
fn test_error_display_seal_failed() {
    let err = SealedIdentityError::SealFailed("timeout".to_string());
    assert!(err.to_string().contains("sealing failed"));
    assert!(err.to_string().contains("timeout"));
}

#[test]
fn test_error_display_unseal_failed() {
    let err = SealedIdentityError::UnsealFailed("bad auth".to_string());
    assert!(err.to_string().contains("unsealing failed"));
    assert!(err.to_string().contains("bad auth"));
}

#[test]
fn test_error_display_rollback_detected() {
    let err = SealedIdentityError::RollbackDetected {
        current: 5,
        last_known: 10,
    };
    let msg = err.to_string();
    assert!(msg.contains("rollback detected"));
    assert!(msg.contains("5"));
    assert!(msg.contains("10"));
}

#[test]
fn test_error_display_blob_corrupted() {
    let err = SealedIdentityError::BlobCorrupted;
    assert_eq!(err.to_string(), "sealed identity: blob corrupted");
}

#[test]
fn test_error_display_reboot_detected() {
    let err = SealedIdentityError::RebootDetected;
    assert!(err.to_string().contains("reboot detected"));
}

#[test]
fn test_error_display_serialization() {
    let err = SealedIdentityError::Serialization("invalid JSON".to_string());
    assert!(err.to_string().contains("serialization error"));
    assert!(err.to_string().contains("invalid JSON"));
}

#[test]
fn test_is_bound_no_blob() {
    let tmp = TempDir::new().unwrap();
    let provider: ProviderHandle = Arc::new(SoftwareProvider::new());
    let store = SealedIdentityStore::new(provider, tmp.path());
    assert!(!store.is_bound());
}

#[test]
fn test_public_identity_without_initialize_fails() {
    let tmp = TempDir::new().unwrap();
    let provider: ProviderHandle = Arc::new(SoftwareProvider::new());
    let store = SealedIdentityStore::new(provider, tmp.path());
    assert!(store.public_identity().is_err());
}

#[test]
fn test_attestation_tier_software_provider() {
    let tmp = TempDir::new().unwrap();
    let provider: ProviderHandle = Arc::new(SoftwareProvider::new());
    let store = SealedIdentityStore::new(provider, tmp.path());
    assert_eq!(store.attestation_tier(), AttestationTier::SoftwareOnly);
}

#[test]
fn test_advance_counter_requires_blob() {
    let tmp = TempDir::new().unwrap();
    let provider: ProviderHandle = Arc::new(SoftwareProvider::new());
    let store = SealedIdentityStore::new(provider, tmp.path());
    assert!(store.advance_counter(1).is_err());
}

#[test]
fn test_unseal_master_key_roundtrip() {
    let tmp = TempDir::new().unwrap();
    let provider: ProviderHandle = Arc::new(SoftwareProvider::new());
    let store = SealedIdentityStore::new(provider, tmp.path());
    let puf = TestPUF;

    store.initialize(&puf).unwrap();

    let key = store.unseal_master_key().unwrap();
    let key2 = store.unseal_master_key().unwrap();
    let mut bytes1 = key.to_bytes();
    let mut bytes2 = key2.to_bytes();
    assert_eq!(bytes1, bytes2);
    bytes1.zeroize();
    bytes2.zeroize();
}

#[test]
fn test_clock_info_from_software_provider() {
    let tmp = TempDir::new().unwrap();
    let provider: ProviderHandle = Arc::new(SoftwareProvider::new());
    let store = SealedIdentityStore::new(provider, tmp.path());
    // SoftwareProvider should return a clock info (may vary by impl)
    let result = store.clock_info();
    // Just verify it doesn't panic; software provider may or may not support this
    let _ = result;
}
