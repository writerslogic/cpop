// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce as AeadNonce,
};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

use crate::keyhierarchy::{
    crypto::IDENTITY_DOMAIN, derive_master_identity, MasterIdentity, PufProvider,
};
use crate::tpm::{ClockInfo, ProviderHandle};
use cpop_protocol::rfc::wire_types::AttestationTier;

use super::types::*;

/// Manage TPM-sealed identity keys with anti-rollback counter protection.
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

    /// Create a store by auto-detecting the best available TPM provider.
    pub fn auto_detect(data_dir: &Path) -> Self {
        let provider = crate::tpm::detect_provider();
        Self::new(provider, data_dir)
    }

    /// Reuses an existing sealed blob if it can be unsealed, otherwise re-derives.
    pub fn initialize(&self, puf: &dyn PufProvider) -> Result<MasterIdentity, SealedIdentityError> {
        if self.store_path.exists() {
            match self.unseal_master_key() {
                Ok(_signing_key) => {
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

        let identity = derive_master_identity(puf)?;
        let signing_key = crate::keyhierarchy::derive_master_private_key(puf)?;
        let seed = zeroize::Zeroizing::new(signing_key.to_bytes());

        let caps = self.provider.capabilities();
        let sealed_seed = if caps.supports_sealing {
            self.provider
                .seal(&*seed, &[])
                .map_err(|e| SealedIdentityError::SealFailed(e.to_string()))?
        } else {
            self.software_wrap(&*seed)?
        };

        let clock = self.provider.clock_info().ok();

        let counter = self
            .provider
            .bind(b"identity-seal-counter")
            .ok()
            .and_then(|b| b.monotonic_counter);

        let blob = SealedBlob {
            version: SEALED_BLOB_VERSION,
            provider_type: if caps.hardware_backed {
                if cfg!(target_os = "macos") {
                    "secure_enclave".to_string()
                } else {
                    "tpm2".to_string()
                }
            } else {
                "software".to_string()
            },
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

        Ok(identity)
    }

    /// **Anti-rollback**: Reads current hardware counter and verifies it is
    /// `>=` both `counter_at_seal` and `last_known_counter` stored in the blob,
    /// then ratchets `last_known_counter` forward to prevent replay.
    ///
    /// **Anti-hammering**: authValue is machine-specific, so the sealed file
    /// cannot be brute-forced on a different device.
    pub fn unseal_master_key(&self) -> Result<SigningKey, SealedIdentityError> {
        let mut blob = self.load_blob()?;

        // Anti-rollback: validate hardware counter against both seal-time and
        // last-known values, closing the gap where an older blob could be
        // replayed if only last_known_counter was checked.
        if blob.counter_at_seal.is_some() || blob.last_known_counter.is_some() {
            if let Ok(binding) = self.provider.bind(b"identity-counter-check") {
                if let Some(current) = binding.monotonic_counter {
                    if let Some(at_seal) = blob.counter_at_seal {
                        if current < at_seal {
                            return Err(SealedIdentityError::RollbackDetected {
                                current,
                                last_known: at_seal,
                            });
                        }
                    }
                    if let Some(last_known) = blob.last_known_counter {
                        if current < last_known {
                            return Err(SealedIdentityError::RollbackDetected {
                                current,
                                last_known,
                            });
                        }
                    }
                    blob.last_known_counter = Some(current);
                    self.persist_blob(&blob)?;
                }
            }
        } else if blob.last_known_counter.is_none() {
            if let Ok(binding) = self.provider.bind(b"identity-counter-check") {
                if let Some(current) = binding.monotonic_counter {
                    blob.last_known_counter = Some(current);
                    self.persist_blob(&blob)?;
                }
            }
        }

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

    /// Ratchet counter forward to prevent forking at the same counter value.
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

    /// Return `true` if the sealed blob exists and is bound to this device.
    pub fn is_bound(&self) -> bool {
        if !self.store_path.exists() {
            return false;
        }
        match self.load_blob() {
            Ok(blob) => blob.device_id == self.provider.device_id(),
            Err(_) => false,
        }
    }

    /// Load and return the public identity (key + fingerprint) from the sealed blob.
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

    /// Re-seal with fresh platform state to detect reboot-based attacks.
    pub fn reseal(&self, puf: &dyn PufProvider) -> Result<(), SealedIdentityError> {
        let old_blob = self.load_blob()?;

        let caps = self.provider.capabilities();
        let seed = Zeroizing::new(if caps.supports_sealing {
            match self.provider.unseal(&old_blob.sealed_seed) {
                Ok(s) => s,
                Err(_) => {
                    let challenge =
                        Sha256::digest(format!("{}-challenge", IDENTITY_DOMAIN).as_bytes());
                    let puf_response = puf.get_response(&challenge)?;
                    let mut derived = crate::keyhierarchy::hkdf_expand(
                        &puf_response,
                        IDENTITY_DOMAIN.as_bytes(),
                        b"master-seed",
                    )?;
                    let v = derived.to_vec();
                    derived.zeroize();
                    v
                }
            }
        } else {
            self.software_unwrap(&old_blob.sealed_seed)?
        });

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

        Ok(())
    }

    /// Determine the attestation tier based on provider hardware capabilities.
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

    /// Read the TPM clock info (boot count, restart count, uptime).
    pub fn clock_info(&self) -> Result<ClockInfo, SealedIdentityError> {
        self.provider.clock_info().map_err(SealedIdentityError::Tpm)
    }

    /// Return a reference to the underlying TPM provider handle.
    pub fn provider(&self) -> &ProviderHandle {
        &self.provider
    }

    fn load_blob(&self) -> Result<SealedBlob, SealedIdentityError> {
        let data = fs::read(&self.store_path)?;
        serde_json::from_slice(&data).map_err(|e| SealedIdentityError::Serialization(e.to_string()))
    }

    fn persist_blob(&self, blob: &SealedBlob) -> Result<(), SealedIdentityError> {
        if let Some(parent) = self.store_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_vec_pretty(blob)
            .map_err(|e| SealedIdentityError::Serialization(e.to_string()))?;
        let tmp_path = self.store_path.with_extension("tmp");
        fs::write(&tmp_path, data)?;
        fs::rename(&tmp_path, &self.store_path)?;
        if let Err(e) = crate::crypto::restrict_permissions(&self.store_path, 0o600) {
            log::warn!("Failed to set sealed identity permissions: {}", e);
        }
        Ok(())
    }

    fn software_wrap(&self, seed: &[u8]) -> Result<Vec<u8>, SealedIdentityError> {
        let machine_salt = self.machine_salt();

        let mut random_salt = [0u8; 32];
        getrandom::getrandom(&mut random_salt)
            .map_err(|e| SealedIdentityError::SealFailed(format!("rng: {e}")))?;

        let hk = Hkdf::<Sha256>::new(Some(&random_salt), &machine_salt);
        let mut key = [0u8; 32];
        hk.expand(b"witnessd-software-wrap-v2", &mut key)
            .map_err(|e| SealedIdentityError::SealFailed(format!("HKDF: {e}")))?;

        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|e| SealedIdentityError::SealFailed(format!("AEAD init: {e}")))?;

        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|e| SealedIdentityError::SealFailed(format!("rng: {e}")))?;
        let aead_nonce = AeadNonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(aead_nonce, seed)
            .map_err(|e| SealedIdentityError::SealFailed(format!("AEAD encrypt: {e}")))?;

        key.zeroize();

        // Format: version(1) || random_salt(32) || aead_nonce(12) || ciphertext+tag
        let mut wrapped = Vec::with_capacity(1 + 32 + 12 + ciphertext.len());
        wrapped.push(0x02); // version 2 = AEAD
        wrapped.extend_from_slice(&random_salt);
        wrapped.extend_from_slice(&nonce_bytes);
        wrapped.extend_from_slice(&ciphertext);
        Ok(wrapped)
    }

    fn software_unwrap(&self, wrapped: &[u8]) -> Result<Vec<u8>, SealedIdentityError> {
        if wrapped.is_empty() {
            return Err(SealedIdentityError::BlobCorrupted);
        }

        match wrapped[0] {
            0x01 => self.software_unwrap_v1(wrapped),
            0x02 => self.software_unwrap_v2(wrapped),
            _ => Err(SealedIdentityError::BlobCorrupted),
        }
    }

    /// Legacy v1: XOR cipher (backward compat only).
    fn software_unwrap_v1(&self, wrapped: &[u8]) -> Result<Vec<u8>, SealedIdentityError> {
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

    fn software_unwrap_v2(&self, wrapped: &[u8]) -> Result<Vec<u8>, SealedIdentityError> {
        // Format: version(1) || random_salt(32) || aead_nonce(12) || ciphertext+tag
        const HEADER_LEN: usize = 1 + 32 + 12; // 45
        if wrapped.len() < HEADER_LEN + 16 {
            return Err(SealedIdentityError::BlobCorrupted);
        }
        let random_salt = &wrapped[1..33];
        let nonce_bytes = &wrapped[33..45];
        let ciphertext = &wrapped[45..];

        let machine_salt = self.machine_salt();
        let hk = Hkdf::<Sha256>::new(Some(random_salt), &machine_salt);
        let mut key = [0u8; 32];
        hk.expand(b"witnessd-software-wrap-v2", &mut key)
            .map_err(|_| SealedIdentityError::BlobCorrupted)?;

        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| SealedIdentityError::BlobCorrupted)?;

        let aead_nonce = AeadNonce::from_slice(nonce_bytes);
        let plaintext = cipher
            .decrypt(aead_nonce, ciphertext)
            .map_err(|_| SealedIdentityError::BlobCorrupted)?;

        key.zeroize();
        Ok(plaintext)
    }

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
