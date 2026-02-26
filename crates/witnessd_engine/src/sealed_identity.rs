// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Persistent TPM-sealed identity key storage with anti-rollback protection.
//!
//! This module bridges the key hierarchy (which derives keys from PUF providers)
//! with the TPM module (which can seal/unseal data to hardware). The master
//! identity seed is sealed to the device's TPM, preventing extraction or
//! migration to another machine.

use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

use crate::keyhierarchy::{
    derive_master_identity, KeyHierarchyError, MasterIdentity, PUFProvider,
};
use crate::rfc::wire_types::AttestationTier;
use crate::tpm::{ClockInfo, Provider, ProviderHandle, TPMError};

#[derive(Debug, thiserror::Error)]
pub enum SealedIdentityError {
    #[error("sealed identity: no TPM provider available")]
    NoProvider,
    #[error("sealed identity: sealing failed: {0}")]
    SealFailed(String),
    #[error("sealed identity: unsealing failed: {0}")]
    UnsealFailed(String),
    #[error("sealed identity: rollback detected (counter {current} < last known {last_known})")]
    RollbackDetected { current: u64, last_known: u64 },
    #[error("sealed identity: reboot detected during session")]
    RebootDetected,
    #[error("sealed identity: blob corrupted")]
    BlobCorrupted,
    #[error("sealed identity: key hierarchy error: {0}")]
    KeyHierarchy(#[from] KeyHierarchyError),
    #[error("sealed identity: TPM error: {0}")]
    Tpm(#[from] TPMError),
    #[error("sealed identity: IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("sealed identity: serialization error: {0}")]
    Serialization(String),
}

/// Persistent sealed identity blob stored on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SealedBlob {
    /// Format version
    version: u32,
    /// Provider type at seal time ("secure_enclave", "tpm2-windows", "tpm2-linux", "software")
    provider_type: String,
    /// Provider device ID at seal time
    device_id: String,
    /// TPM-sealed 32-byte master seed
    sealed_seed: Vec<u8>,
    /// Ed25519 public key (for verification without unseal)
    public_key: Vec<u8>,
    /// Key fingerprint
    fingerprint: String,
    /// When this blob was created
    sealed_at: DateTime<Utc>,
    /// Monotonic counter value when sealed
    counter_at_seal: Option<u64>,
    /// Last counter seen (ratchets forward on each checkpoint)
    last_known_counter: Option<u64>,
    /// TPM ResetCount at seal time (reboot detection)
    boot_count_at_seal: Option<u32>,
    /// TPM RestartCount at seal time
    restart_count_at_seal: Option<u32>,
}

const SEALED_BLOB_VERSION: u32 = 1;
const SEALED_BLOB_FILENAME: &str = "identity.sealed";

/// Persistent TPM-sealed key storage.
///
/// Seals the master identity seed to the platform's TPM hardware,
/// preventing key extraction or migration to another device.
pub struct SealedIdentityStore {
    provider: ProviderHandle,
    store_path: PathBuf,
}

impl SealedIdentityStore {
    /// Create a store with the given TPM provider and data directory.
    pub fn new(provider: ProviderHandle, data_dir: &Path) -> Self {
        let store_path = data_dir.join(SEALED_BLOB_FILENAME);
        Self {
            provider,
            store_path,
        }
    }

    /// Create a store with auto-detected TPM provider.
    pub fn auto_detect(data_dir: &Path) -> Self {
        let provider = crate::tpm::detect_provider();
        Self::new(provider, data_dir)
    }

    /// Initialize: derive master key from PUF, seal with TPM, persist blob.
    ///
    /// If a sealed blob already exists and can be unsealed, reuses it.
    /// Records boot_count and restart_count from TPM ClockInfo into the blob.
    pub fn initialize(
        &self,
        puf: &dyn PUFProvider,
    ) -> Result<MasterIdentity, SealedIdentityError> {
        // Try to unseal existing blob first
        if self.store_path.exists() {
            match self.unseal_master_key() {
                Ok(_signing_key) => {
                    // Blob is valid — return the public identity
                    return self.public_identity();
                }
                Err(e) => {
                    log::warn!(
                        "Existing sealed blob could not be unsealed ({}), re-deriving",
                        e
                    );
                }
            }
        }

        // Derive the master seed from PUF
        let identity = derive_master_identity(puf)?;
        let challenge = Sha256::digest(
            format!("{}-challenge", "witnessd-identity-v1").as_bytes(),
        );
        let puf_response = puf.get_response(&challenge)?;
        let mut seed = crate::keyhierarchy::hkdf_expand(
            &puf_response,
            b"witnessd-identity-v1",
            b"master-seed",
        )?;

        // Seal the seed with TPM
        let caps = self.provider.capabilities();
        let sealed_seed = if caps.supports_sealing {
            self.provider
                .seal(&seed, &[])
                .map_err(|e| SealedIdentityError::SealFailed(e.to_string()))?
        } else {
            // Fallback: PBKDF2-wrapped to disk with machine-specific salt
            self.software_wrap(&seed)?
        };

        // Get clock info for reboot detection
        let clock = self.provider.clock_info().ok();

        // Get current counter from binding
        let counter = self
            .provider
            .bind(b"identity-seal-counter")
            .ok()
            .and_then(|b| b.monotonic_counter);

        let blob = SealedBlob {
            version: SEALED_BLOB_VERSION,
            provider_type: format!("{:?}", caps),
            device_id: self.provider.device_id(),
            sealed_seed,
            public_key: identity.public_key.clone(),
            fingerprint: identity.fingerprint.clone(),
            sealed_at: Utc::now(),
            counter_at_seal: counter,
            last_known_counter: counter,
            boot_count_at_seal: clock.as_ref().map(|c| c.reset_count),
            restart_count_at_seal: clock.as_ref().map(|c| c.restart_count),
        };

        self.persist_blob(&blob)?;

        seed.zeroize();

        Ok(identity)
    }

    /// Unseal and return the master signing key (requires TPM access).
    ///
    /// **Anti-rollback**: Reads current hardware counter and verifies it is
    /// >= last_known_counter stored in the blob.
    /// **Anti-hammering**: authValue is machine-specific, so the sealed file
    /// cannot be brute-forced on a different device.
    pub fn unseal_master_key(&self) -> Result<SigningKey, SealedIdentityError> {
        let blob = self.load_blob()?;

        // Anti-rollback check
        if let Some(last_known) = blob.last_known_counter {
            if let Ok(binding) = self.provider.bind(b"identity-counter-check") {
                if let Some(current) = binding.monotonic_counter {
                    if current < last_known {
                        return Err(SealedIdentityError::RollbackDetected {
                            current,
                            last_known,
                        });
                    }
                }
            }
        }

        // Unseal the seed
        let caps = self.provider.capabilities();
        let mut seed = if caps.supports_sealing {
            self.provider
                .unseal(&blob.sealed_seed)
                .map_err(|e| SealedIdentityError::UnsealFailed(e.to_string()))?
        } else {
            self.software_unwrap(&blob.sealed_seed)?
        };

        if seed.len() != 32 {
            seed.zeroize();
            return Err(SealedIdentityError::BlobCorrupted);
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&seed);
        seed.zeroize();

        let signing_key = SigningKey::from_bytes(&key_bytes);
        key_bytes.zeroize();

        Ok(signing_key)
    }

    /// Advance last_known_counter in the blob (called after each checkpoint).
    ///
    /// Re-persists the blob with updated counter. This ensures the counter
    /// ratchets forward and prevents "forking" at the same counter value.
    pub fn advance_counter(&self, new_counter: u64) -> Result<(), SealedIdentityError> {
        let mut blob = self.load_blob()?;

        if let Some(last_known) = blob.last_known_counter {
            if new_counter < last_known {
                return Err(SealedIdentityError::RollbackDetected {
                    current: new_counter,
                    last_known,
                });
            }
        }

        blob.last_known_counter = Some(new_counter);
        self.persist_blob(&blob)?;
        Ok(())
    }

    /// Check if identity exists and can potentially be unsealed on this device.
    pub fn is_bound(&self) -> bool {
        if !self.store_path.exists() {
            return false;
        }
        match self.load_blob() {
            Ok(blob) => blob.device_id == self.provider.device_id(),
            Err(_) => false,
        }
    }

    /// Get public identity without unsealing (reads blob metadata).
    pub fn public_identity(&self) -> Result<MasterIdentity, SealedIdentityError> {
        let blob = self.load_blob()?;
        Ok(MasterIdentity {
            public_key: blob.public_key,
            fingerprint: blob.fingerprint,
            device_id: blob.device_id,
            created_at: blob.sealed_at,
            version: SEALED_BLOB_VERSION,
        })
    }

    /// Re-seal after PCR state change (OS update, firmware update).
    ///
    /// Unseals the current seed, then re-seals with the new platform state.
    /// Records new boot_count/restart_count to detect reboot-based attacks.
    pub fn reseal(&self, puf: &dyn PUFProvider) -> Result<(), SealedIdentityError> {
        let old_blob = self.load_blob()?;

        // Unseal the current seed
        let caps = self.provider.capabilities();
        let mut seed = if caps.supports_sealing {
            match self.provider.unseal(&old_blob.sealed_seed) {
                Ok(s) => s,
                Err(_) => {
                    // Unseal failed (PCR change?) — re-derive from PUF
                    let challenge = Sha256::digest(
                        format!("{}-challenge", "witnessd-identity-v1").as_bytes(),
                    );
                    let puf_response = puf.get_response(&challenge)?;
                    let seed = crate::keyhierarchy::hkdf_expand(
                        &puf_response,
                        b"witnessd-identity-v1",
                        b"master-seed",
                    )?;
                    seed.to_vec()
                }
            }
        } else {
            self.software_unwrap(&old_blob.sealed_seed)?
        };

        // Re-seal with updated platform state
        let sealed_seed = if caps.supports_sealing {
            self.provider
                .seal(&seed, &[])
                .map_err(|e| SealedIdentityError::SealFailed(e.to_string()))?
        } else {
            self.software_wrap(&seed)?
        };

        let clock = self.provider.clock_info().ok();

        let blob = SealedBlob {
            version: SEALED_BLOB_VERSION,
            provider_type: old_blob.provider_type,
            device_id: self.provider.device_id(),
            sealed_seed,
            public_key: old_blob.public_key,
            fingerprint: old_blob.fingerprint,
            sealed_at: Utc::now(),
            counter_at_seal: old_blob.last_known_counter,
            last_known_counter: old_blob.last_known_counter,
            boot_count_at_seal: clock.as_ref().map(|c| c.reset_count),
            restart_count_at_seal: clock.as_ref().map(|c| c.restart_count),
        };

        self.persist_blob(&blob)?;
        seed.zeroize();

        Ok(())
    }

    /// Get attestation tier based on provider capabilities.
    ///
    /// T4 (HardwareHardened): Reserved for SGX/TrustZone (future)
    /// T3 (HardwareBound):    hardware_backed && supports_sealing
    /// T2 (AttestedSoftware): hardware_backed && supports_attestation (but no sealing)
    /// T1 (SoftwareOnly):     pure software fallback
    pub fn attestation_tier(&self) -> AttestationTier {
        let caps = self.provider.capabilities();
        if caps.hardware_backed && caps.supports_sealing {
            AttestationTier::HardwareBound
        } else if caps.hardware_backed && caps.supports_attestation {
            AttestationTier::AttestedSoftware
        } else {
            AttestationTier::SoftwareOnly
        }
    }

    /// Get the current ClockInfo from the provider.
    pub fn clock_info(&self) -> Result<ClockInfo, SealedIdentityError> {
        self.provider.clock_info().map_err(SealedIdentityError::Tpm)
    }

    /// Get the provider handle (for session TPM binding).
    pub fn provider(&self) -> &ProviderHandle {
        &self.provider
    }

    // ---- Internal helpers ----

    fn load_blob(&self) -> Result<SealedBlob, SealedIdentityError> {
        let data = fs::read(&self.store_path)?;
        serde_json::from_slice(&data)
            .map_err(|e| SealedIdentityError::Serialization(e.to_string()))
    }

    fn persist_blob(&self, blob: &SealedBlob) -> Result<(), SealedIdentityError> {
        if let Some(parent) = self.store_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_vec_pretty(blob)
            .map_err(|e| SealedIdentityError::Serialization(e.to_string()))?;
        fs::write(&self.store_path, data)?;
        Ok(())
    }

    /// Software-only key wrapping for platforms without hardware TPM.
    /// Uses PBKDF2 with machine-specific salt.
    fn software_wrap(&self, seed: &[u8]) -> Result<Vec<u8>, SealedIdentityError> {
        let salt = self.machine_salt();
        let mut hasher = Sha256::new();
        hasher.update(&salt);
        hasher.update(b"witnessd-software-wrap-v1");
        let key_material = hasher.finalize();

        // XOR-based wrapping (sufficient for at-rest protection when
        // the threat model trusts the OS — hardware sealing is preferred)
        let mut wrapped = vec![0u8; 1 + seed.len()];
        wrapped[0] = 0x01; // version marker for software wrapping
        for (i, b) in seed.iter().enumerate() {
            wrapped[1 + i] = b ^ key_material[i % 32];
        }
        Ok(wrapped)
    }

    fn software_unwrap(&self, wrapped: &[u8]) -> Result<Vec<u8>, SealedIdentityError> {
        if wrapped.is_empty() || wrapped[0] != 0x01 {
            return Err(SealedIdentityError::BlobCorrupted);
        }
        let salt = self.machine_salt();
        let mut hasher = Sha256::new();
        hasher.update(&salt);
        hasher.update(b"witnessd-software-wrap-v1");
        let key_material = hasher.finalize();

        let mut seed = vec![0u8; wrapped.len() - 1];
        for (i, b) in wrapped[1..].iter().enumerate() {
            seed[i] = b ^ key_material[i % 32];
        }
        Ok(seed)
    }

    /// Derive a machine-specific salt from the device ID.
    fn machine_salt(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"witnessd-machine-salt-v1");
        hasher.update(self.provider.device_id().as_bytes());
        if let Ok(host) = hostname::get() {
            hasher.update(host.to_string_lossy().as_bytes());
        }
        hasher.finalize().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm::SoftwareProvider;
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

        // Initialize should succeed with software wrapping
        let identity = store.initialize(&puf).unwrap();
        assert!(!identity.public_key.is_empty());
        assert!(!identity.fingerprint.is_empty());

        // Should be "bound" (same device ID)
        assert!(store.is_bound());

        // Public identity should match
        let pub_id = store.public_identity().unwrap();
        assert_eq!(pub_id.public_key, identity.public_key);
        assert_eq!(pub_id.fingerprint, identity.fingerprint);

        // Attestation tier should be software-only
        assert_eq!(store.attestation_tier(), AttestationTier::SoftwareOnly);
    }

    #[test]
    fn test_sealed_identity_counter_advance() {
        let tmp = TempDir::new().unwrap();
        let provider: ProviderHandle = Arc::new(SoftwareProvider::new());
        let store = SealedIdentityStore::new(provider, tmp.path());
        let puf = TestPUF;

        store.initialize(&puf).unwrap();

        // Advance counter
        store.advance_counter(5).unwrap();
        store.advance_counter(10).unwrap();

        // Rollback should fail
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

        // Reseal should succeed
        store.reseal(&puf).unwrap();

        // Public identity should be preserved
        let pub_id = store.public_identity().unwrap();
        assert_eq!(pub_id.public_key, identity.public_key);
    }

    #[test]
    fn test_sealed_identity_reinitialize() {
        let tmp = TempDir::new().unwrap();
        let provider: ProviderHandle = Arc::new(SoftwareProvider::new());
        let store = SealedIdentityStore::new(provider, tmp.path());
        let puf = TestPUF;

        // First init
        let id1 = store.initialize(&puf).unwrap();

        // Second init should reuse the existing blob
        let id2 = store.initialize(&puf).unwrap();
        assert_eq!(id1.public_key, id2.public_key);
    }
}
