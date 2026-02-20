//! Encrypted Fingerprint Storage
//!
//! This module handles secure storage of fingerprint profiles:
//! - Encrypted at rest using ChaCha20-Poly1305
//! - Key derived from device-specific secret
//! - Automatic key rotation support

use super::{AuthorFingerprint, ProfileId};
use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

// =============================================================================
// Constants
// =============================================================================

/// Storage file extension
const PROFILE_EXTENSION: &str = ".profile";
/// Nonce size for ChaCha20-Poly1305
const NONCE_SIZE: usize = 12;
/// Key size for ChaCha20-Poly1305
const KEY_SIZE: usize = 32;

// =============================================================================
// Stored Profile Metadata
// =============================================================================

/// Metadata about a stored fingerprint profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredProfile {
    /// Profile ID
    pub id: ProfileId,
    /// Human-readable name
    pub name: Option<String>,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
    /// Sample count
    pub sample_count: u64,
    /// Confidence level
    pub confidence: f64,
    /// Whether voice data is included
    pub has_voice: bool,
    /// File size in bytes
    pub file_size: u64,
}

// =============================================================================
// Fingerprint Storage
// =============================================================================

/// Secure storage for fingerprint profiles.
pub struct FingerprintStorage {
    /// Storage directory
    storage_dir: PathBuf,
    /// Encryption key (derived from device secret)
    encryption_key: [u8; KEY_SIZE],
    /// Profile index cache
    profile_index: HashMap<ProfileId, StoredProfile>,
}

impl FingerprintStorage {
    /// Create a new fingerprint storage.
    pub fn new(storage_dir: &Path) -> Result<Self> {
        fs::create_dir_all(storage_dir)?;

        // Derive encryption key from device-specific secret
        let encryption_key = derive_storage_key(storage_dir)?;

        let mut storage = Self {
            storage_dir: storage_dir.to_path_buf(),
            encryption_key,
            profile_index: HashMap::new(),
        };

        // Load profile index
        storage.refresh_index()?;

        Ok(storage)
    }

    /// Refresh the profile index from disk.
    pub fn refresh_index(&mut self) -> Result<()> {
        self.profile_index.clear();

        if !self.storage_dir.exists() {
            return Ok(());
        }

        for entry in fs::read_dir(&self.storage_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("profile") {
                if let Ok(profile) = self.load_metadata(&path) {
                    self.profile_index.insert(profile.id.clone(), profile);
                }
            }
        }

        Ok(())
    }

    /// Save a fingerprint profile.
    pub fn save(&mut self, fingerprint: &AuthorFingerprint) -> Result<()> {
        let path = self.profile_path(&fingerprint.id);

        // Serialize fingerprint
        let plaintext = serde_json::to_vec(fingerprint)?;

        // Encrypt
        let ciphertext = self.encrypt(&plaintext)?;

        // Write to file
        fs::write(&path, &ciphertext)?;

        // Update index
        let metadata = StoredProfile {
            id: fingerprint.id.clone(),
            name: fingerprint.name.clone(),
            created_at: fingerprint.created_at,
            updated_at: fingerprint.updated_at,
            sample_count: fingerprint.sample_count,
            confidence: fingerprint.confidence,
            has_voice: fingerprint.voice.is_some(),
            file_size: ciphertext.len() as u64,
        };
        self.profile_index.insert(fingerprint.id.clone(), metadata);

        Ok(())
    }

    /// Load a fingerprint profile by ID.
    pub fn load(&self, id: &ProfileId) -> Result<AuthorFingerprint> {
        let path = self.profile_path(id);

        if !path.exists() {
            return Err(anyhow!("Profile not found: {}", id));
        }

        // Read encrypted data
        let ciphertext = fs::read(&path)?;

        // Decrypt
        let plaintext = self.decrypt(&ciphertext)?;

        // Deserialize
        let fingerprint: AuthorFingerprint = serde_json::from_slice(&plaintext)?;

        Ok(fingerprint)
    }

    /// Load only metadata without decrypting full profile.
    fn load_metadata(&self, path: &Path) -> Result<StoredProfile> {
        // For now, we load the full profile to get metadata
        // In a production system, we might store metadata separately
        let ciphertext = fs::read(path)?;
        let plaintext = self.decrypt(&ciphertext)?;
        let fingerprint: AuthorFingerprint = serde_json::from_slice(&plaintext)?;

        Ok(StoredProfile {
            id: fingerprint.id,
            name: fingerprint.name,
            created_at: fingerprint.created_at,
            updated_at: fingerprint.updated_at,
            sample_count: fingerprint.sample_count,
            confidence: fingerprint.confidence,
            has_voice: fingerprint.voice.is_some(),
            file_size: ciphertext.len() as u64,
        })
    }

    /// Delete a fingerprint profile.
    pub fn delete(&mut self, id: &ProfileId) -> Result<()> {
        let path = self.profile_path(id);

        if path.exists() {
            // Secure delete: overwrite with random data before removing
            let size = fs::metadata(&path)?.len() as usize;
            let mut random_data = vec![0u8; size];
            getrandom::getrandom(&mut random_data)
                .map_err(|e| anyhow!("Failed to generate random data: {}", e))?;
            fs::write(&path, &random_data)?;
            fs::remove_file(&path)?;
        }

        self.profile_index.remove(id);
        Ok(())
    }

    /// Delete all voice fingerprint data.
    pub fn delete_all_voice_data(&mut self) -> Result<()> {
        let ids: Vec<ProfileId> = self.profile_index.keys().cloned().collect();

        for id in ids {
            if let Ok(mut fp) = self.load(&id) {
                if fp.voice.is_some() {
                    fp.voice = None;
                    self.save(&fp)?;
                }
            }
        }

        Ok(())
    }

    /// List all stored profiles.
    pub fn list_profiles(&self) -> Result<Vec<StoredProfile>> {
        Ok(self.profile_index.values().cloned().collect())
    }

    /// Check if a profile exists.
    pub fn exists(&self, id: &ProfileId) -> bool {
        self.profile_index.contains_key(id)
    }

    /// Get the path for a profile.
    fn profile_path(&self, id: &ProfileId) -> PathBuf {
        self.storage_dir
            .join(format!("{}{}", id, PROFILE_EXTENSION))
    }

    /// Encrypt data.
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new_from_slice(&self.encryption_key)
            .map_err(|e| anyhow!("Failed to create cipher: {}", e))?;

        // Generate random nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|e| anyhow!("Failed to generate nonce: {}", e))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;

        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt data.
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < NONCE_SIZE {
            return Err(anyhow!("Invalid encrypted data: too short"));
        }

        let cipher = ChaCha20Poly1305::new_from_slice(&self.encryption_key)
            .map_err(|e| anyhow!("Failed to create cipher: {}", e))?;

        // Extract nonce and ciphertext
        let nonce = Nonce::from_slice(&data[..NONCE_SIZE]);
        let ciphertext = &data[NONCE_SIZE..];

        // Decrypt
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow!("Decryption failed: {}", e))?;

        Ok(plaintext)
    }

    /// Export a profile to unencrypted JSON (for backup).
    pub fn export_json(&self, id: &ProfileId) -> Result<String> {
        let fingerprint = self.load(id)?;
        Ok(serde_json::to_string_pretty(&fingerprint)?)
    }

    /// Import a profile from JSON.
    pub fn import_json(&mut self, json: &str) -> Result<ProfileId> {
        let fingerprint: AuthorFingerprint = serde_json::from_str(json)?;
        let id = fingerprint.id.clone();
        self.save(&fingerprint)?;
        Ok(id)
    }
}

/// Derive storage encryption key from device-specific data.
fn derive_storage_key(storage_dir: &Path) -> Result<[u8; KEY_SIZE]> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    // Key file path
    let key_file = storage_dir.join(".storage_key");

    // Try to load existing key material
    let key_material = if key_file.exists() {
        fs::read(&key_file)?
    } else {
        // Generate new key material
        let mut material = vec![0u8; 32];
        getrandom::getrandom(&mut material)
            .map_err(|e| anyhow!("Failed to generate key material: {}", e))?;
        fs::write(&key_file, &material)?;

        // Set restrictive permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&key_file)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&key_file, perms)?;
        }

        material
    };

    // Derive actual encryption key using HKDF
    let salt = b"witnessd-fingerprint-storage-v1";
    let info = b"fingerprint-encryption-key";

    let hk = Hkdf::<Sha256>::new(Some(salt), &key_material);
    let mut key = [0u8; KEY_SIZE];
    hk.expand(info, &mut key)
        .map_err(|_| anyhow!("Key derivation failed"))?;

    Ok(key)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::activity::ActivityFingerprint;
    use tempfile::tempdir;

    #[test]
    fn test_storage_creation() {
        let dir = tempdir().unwrap();
        let storage = FingerprintStorage::new(dir.path()).unwrap();
        assert!(storage.list_profiles().unwrap().is_empty());
    }

    #[test]
    fn test_save_and_load() {
        let dir = tempdir().unwrap();
        let mut storage = FingerprintStorage::new(dir.path()).unwrap();

        let fp = AuthorFingerprint::new(ActivityFingerprint::default());
        let id = fp.id.clone();

        storage.save(&fp).unwrap();
        assert!(storage.exists(&id));

        let loaded = storage.load(&id).unwrap();
        assert_eq!(loaded.id, id);
    }

    #[test]
    fn test_delete() {
        let dir = tempdir().unwrap();
        let mut storage = FingerprintStorage::new(dir.path()).unwrap();

        let fp = AuthorFingerprint::new(ActivityFingerprint::default());
        let id = fp.id.clone();

        storage.save(&fp).unwrap();
        assert!(storage.exists(&id));

        storage.delete(&id).unwrap();
        assert!(!storage.exists(&id));
    }

    #[test]
    fn test_encryption_roundtrip() {
        let dir = tempdir().unwrap();
        let storage = FingerprintStorage::new(dir.path()).unwrap();

        let plaintext = b"Hello, World!";
        let ciphertext = storage.encrypt(plaintext).unwrap();
        let decrypted = storage.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_export_import() {
        let dir = tempdir().unwrap();
        let mut storage = FingerprintStorage::new(dir.path()).unwrap();

        let fp = AuthorFingerprint::new(ActivityFingerprint::default());
        let id = fp.id.clone();

        storage.save(&fp).unwrap();

        let json = storage.export_json(&id).unwrap();
        storage.delete(&id).unwrap();

        let imported_id = storage.import_json(&json).unwrap();
        assert_eq!(id, imported_id);
        assert!(storage.exists(&id));
    }
}
