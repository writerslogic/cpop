// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Encrypted fingerprint storage (ChaCha20-Poly1305, HKDF-derived key).

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
use std::time::SystemTime;
use zeroize::Zeroize;

use crate::identity::SecureStorage;

const PROFILE_EXTENSION: &str = ".profile";
const NONCE_SIZE: usize = 12;
const KEY_SIZE: usize = 32;

/// Index metadata for a stored profile (avoids full decryption).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredProfile {
    pub id: ProfileId,
    pub name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub sample_count: u64,
    pub confidence: f64,
    pub has_voice: bool,
    pub file_size: u64,
}

/// Encrypted on-disk profile store. Key material is zeroized on drop.
pub struct FingerprintStorage {
    storage_dir: PathBuf,
    encryption_key: [u8; KEY_SIZE],
    profile_index: HashMap<ProfileId, StoredProfile>,
    /// Tracks mtime per profile file path so refresh_index can skip unchanged files.
    file_mtimes: HashMap<PathBuf, SystemTime>,
}

impl FingerprintStorage {
    /// Initialize storage, deriving encryption key and building index.
    pub fn new(storage_dir: &Path) -> Result<Self> {
        fs::create_dir_all(storage_dir)?;

        let encryption_key = load_or_create_fingerprint_key(storage_dir)?;

        let mut storage = Self {
            storage_dir: storage_dir.to_path_buf(),
            encryption_key,
            profile_index: HashMap::new(),
            file_mtimes: HashMap::new(),
        };

        storage.refresh_index()?;

        Ok(storage)
    }

    /// Rebuild in-memory index by scanning `.profile` files on disk.
    ///
    /// Only decrypts files whose mtime has changed since the last refresh,
    /// avoiding repeated key-material exposure for unchanged profiles.
    pub fn refresh_index(&mut self) -> Result<()> {
        if !self.storage_dir.exists() {
            self.profile_index.clear();
            self.file_mtimes.clear();
            return Ok(());
        }

        let mut current_paths: HashMap<PathBuf, SystemTime> = HashMap::new();
        for entry in fs::read_dir(&self.storage_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("profile") {
                let mtime = entry
                    .metadata()
                    .and_then(|m| m.modified())
                    .unwrap_or(SystemTime::UNIX_EPOCH);
                current_paths.insert(path, mtime);
            }
        }

        let stale_ids: Vec<ProfileId> = self
            .profile_index
            .iter()
            .filter(|(_, profile)| {
                let path = self.profile_path_for_id(&profile.id);
                !current_paths.contains_key(&path)
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in &stale_ids {
            self.profile_index.remove(id);
        }
        self.file_mtimes
            .retain(|path, _| current_paths.contains_key(path));

        for (path, mtime) in &current_paths {
            let needs_decrypt = match self.file_mtimes.get(path) {
                Some(cached_mtime) => cached_mtime != mtime,
                None => true,
            };
            if needs_decrypt {
                if let Ok(profile) = self.load_metadata(path) {
                    self.profile_index.insert(profile.id.clone(), profile);
                    self.file_mtimes.insert(path.clone(), *mtime);
                }
            }
        }

        Ok(())
    }

    /// Build the canonical file path for a profile ID (used by cache bookkeeping).
    fn profile_path_for_id(&self, id: &ProfileId) -> PathBuf {
        self.profile_path(id)
    }

    /// Encrypt and persist a profile, updating the in-memory index.
    pub fn save(&mut self, fingerprint: &AuthorFingerprint) -> Result<()> {
        let path = self.profile_path(&fingerprint.id);
        let plaintext = serde_json::to_vec(fingerprint)?;
        let ciphertext = self.encrypt(&plaintext)?;
        fs::write(&path, &ciphertext)?;

        let mtime = fs::metadata(&path)
            .and_then(|m| m.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);
        self.file_mtimes.insert(path, mtime);

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

    /// Decrypt and deserialize a profile by ID.
    pub fn load(&self, id: &ProfileId) -> Result<AuthorFingerprint> {
        let path = self.profile_path(id);

        if !path.exists() {
            return Err(anyhow!("Profile not found: {}", id));
        }

        let ciphertext = fs::read(&path)?;
        let plaintext = self.decrypt(&ciphertext)?;
        let fingerprint: AuthorFingerprint = serde_json::from_slice(&plaintext)?;

        Ok(fingerprint)
    }

    /// Extract metadata from an encrypted profile file.
    fn load_metadata(&self, path: &Path) -> Result<StoredProfile> {
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

    /// Securely delete a profile (overwrite with random data, then unlink).
    pub fn delete(&mut self, id: &ProfileId) -> Result<()> {
        let path = self.profile_path(id);

        if path.exists() {
            let size = fs::metadata(&path)?.len() as usize;
            let mut random_data = vec![0u8; size];
            getrandom::getrandom(&mut random_data)
                .map_err(|e| anyhow!("Failed to generate random data: {}", e))?;
            fs::write(&path, &random_data)?;
            fs::remove_file(&path)?;
        }

        self.file_mtimes.remove(&path);
        self.profile_index.remove(id);
        Ok(())
    }

    /// Strip voice data from all profiles (used on consent revocation).
    pub fn delete_all_voice_data(&mut self) -> Result<()> {
        let ids: Vec<ProfileId> = self.profile_index.keys().cloned().collect();

        for id in ids {
            match self.load(&id) {
                Ok(mut fp) => {
                    if fp.voice.is_some() {
                        fp.voice = None;
                        self.save(&fp)?;
                    }
                }
                Err(e) => {
                    return Err(anyhow!(
                        "Cannot decrypt profile {} to verify voice data removal: {}",
                        id,
                        e
                    ));
                }
            }
        }

        Ok(())
    }

    pub fn list_profiles(&self) -> Result<Vec<StoredProfile>> {
        Ok(self.profile_index.values().cloned().collect())
    }

    pub fn exists(&self, id: &ProfileId) -> bool {
        self.profile_index.contains_key(id)
    }

    /// Sanitize `id` to prevent path traversal, then return file path.
    fn profile_path(&self, id: &ProfileId) -> PathBuf {
        let safe_id: String = id
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        self.storage_dir
            .join(format!("{}{}", safe_id, PROFILE_EXTENSION))
    }

    /// Encrypt with random nonce. Output: `nonce || ciphertext`.
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new_from_slice(&self.encryption_key)
            .map_err(|e| anyhow!("Failed to create cipher: {}", e))?;

        let mut nonce_bytes = [0u8; NONCE_SIZE];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|e| anyhow!("Failed to generate nonce: {}", e))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;

        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt `nonce || ciphertext` format.
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < NONCE_SIZE {
            return Err(anyhow!("Invalid encrypted data: too short"));
        }

        let cipher = ChaCha20Poly1305::new_from_slice(&self.encryption_key)
            .map_err(|e| anyhow!("Failed to create cipher: {}", e))?;

        let nonce = Nonce::from_slice(&data[..NONCE_SIZE]);
        let ciphertext = &data[NONCE_SIZE..];

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow!("Decryption failed: {}", e))?;

        Ok(plaintext)
    }

    /// Export profile as unencrypted JSON (for backup). Voice data is stripped.
    pub fn export_json(&self, id: &ProfileId) -> Result<String> {
        let mut fingerprint = self.load(id)?;
        fingerprint.voice = None;
        Ok(serde_json::to_string_pretty(&fingerprint)?)
    }

    /// Import profile from JSON, encrypting on save.
    pub fn import_json(&mut self, json: &str) -> Result<ProfileId> {
        let fingerprint: AuthorFingerprint = serde_json::from_str(json)?;
        let id = fingerprint.id.clone();
        self.save(&fingerprint)?;
        Ok(id)
    }
}

impl Drop for FingerprintStorage {
    fn drop(&mut self) {
        self.encryption_key.zeroize();
    }
}

/// Load fingerprint encryption key from OS keychain, migrating from legacy file if needed.
fn load_or_create_fingerprint_key(storage_dir: &Path) -> Result<[u8; KEY_SIZE]> {
    if let Ok(Some(mut key_vec)) = SecureStorage::load_fingerprint_key() {
        if key_vec.len() == KEY_SIZE {
            let mut key = [0u8; KEY_SIZE];
            key.copy_from_slice(&key_vec);
            key_vec.zeroize();
            return Ok(key);
        }
        key_vec.zeroize();
    }

    let key_file = storage_dir.join(".storage_key");
    if key_file.exists() {
        let key = hkdf_derive_from_file(&key_file)?;

        if let Err(e) = SecureStorage::save_fingerprint_key(&key) {
            log::warn!("Failed to migrate fingerprint key to secure storage: {}", e);
        } else {
            secure_delete_file(&key_file);
        }

        return Ok(key);
    }

    let mut key = [0u8; KEY_SIZE];
    getrandom::getrandom(&mut key)
        .map_err(|e| anyhow!("Failed to generate key material: {}", e))?;

    if let Err(e) = SecureStorage::save_fingerprint_key(&key) {
        log::warn!(
            "Secure storage unavailable ({}), using file-based fallback",
            e
        );
        // Write raw material and derive via HKDF, so re-reads through step 2
        // produce the same derived key.
        let mut material = [0u8; KEY_SIZE];
        getrandom::getrandom(&mut material)
            .map_err(|e| anyhow!("Failed to generate key material: {}", e))?;
        fs::write(&key_file, material)?;
        let _ = crate::crypto::restrict_permissions(&key_file, 0o600);
        material.zeroize();
        key.zeroize();
        return hkdf_derive_from_file(&key_file);
    }

    Ok(key)
}

/// HKDF-SHA256 derivation from a `.storage_key` file's raw material.
fn hkdf_derive_from_file(key_file: &Path) -> Result<[u8; KEY_SIZE]> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let mut key_material = fs::read(key_file)?;

    let salt = b"witnessd-fingerprint-storage-v1";
    let info = b"fingerprint-encryption-key";
    let hk = Hkdf::<Sha256>::new(Some(salt), &key_material);
    let mut key = [0u8; KEY_SIZE];
    hk.expand(info, &mut key)
        .map_err(|_| anyhow!("Key derivation failed"))?;

    key_material.zeroize();
    Ok(key)
}

/// Best-effort secure delete: overwrite with random data, then unlink.
fn secure_delete_file(path: &Path) {
    let size = match fs::metadata(path) {
        Ok(m) => m.len() as usize,
        Err(_) => {
            let _ = fs::remove_file(path);
            return;
        }
    };
    let mut random = vec![0u8; size];
    if getrandom::getrandom(&mut random).is_ok() {
        let _ = fs::write(path, &random);
    }
    let _ = fs::remove_file(path);
}

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

    /// Verify `hkdf_derive_from_file` produces the same key the old
    /// `derive_storage_key` inline HKDF would have, and that
    /// `secure_delete_file` cleans up the legacy file.
    #[test]
    fn test_legacy_key_derivation_compat() {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let dir = tempdir().unwrap();
        let key_file = dir.path().join(".storage_key");

        let mut material = vec![0u8; 32];
        getrandom::getrandom(&mut material).unwrap();
        fs::write(&key_file, &material).unwrap();

        let salt = b"witnessd-fingerprint-storage-v1";
        let info = b"fingerprint-encryption-key";
        let hk = Hkdf::<Sha256>::new(Some(salt), &material);
        let mut expected_key = [0u8; KEY_SIZE];
        hk.expand(info, &mut expected_key).unwrap();

        let actual_key = super::hkdf_derive_from_file(&key_file).unwrap();
        assert_eq!(expected_key, actual_key);

        let cipher = ChaCha20Poly1305::new_from_slice(&actual_key).unwrap();
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        getrandom::getrandom(&mut nonce_bytes).unwrap();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let plaintext = b"test payload";
        let ct = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();
        let pt = cipher.decrypt(nonce, ct.as_ref()).unwrap();
        assert_eq!(plaintext.to_vec(), pt);

        assert!(key_file.exists());
        super::secure_delete_file(&key_file);
        assert!(!key_file.exists());
    }
}
