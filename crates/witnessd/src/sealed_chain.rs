// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! AES-256-GCM encrypted chain file storage (anti-tamper).
//!
//! Chains are stored in a binary sealed format:
//!
//! ```text
//! [4B: magic "WCSF"]
//! [4B: version = 1]
//! [12B: AES-GCM nonce]
//! [32B: document_id hash (cleartext, for key derivation)]
//! [NB: AES-256-GCM(JSON chain)]
//! [16B: GCM auth tag (appended to ciphertext by aes-gcm)]
//! ```
//!
//! The encryption key is derived via HKDF from a master seed and
//! the document ID, preventing key reuse across chains.

use std::fs;
use std::path::Path;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::checkpoint::Chain;
use crate::crypto::ProtectedKey;
use crate::error::{Error, Result};

/// Magic bytes identifying a sealed chain file.
const SEALED_MAGIC: &[u8; 4] = b"WCSF";

/// Current sealed file format version.
const SEALED_VERSION: u32 = 1;

/// Fixed header size: magic(4) + version(4) + nonce(12) + document_id(32) = 52 bytes.
const HEADER_SIZE: usize = 4 + 4 + 12 + 32;

/// Encryption key for sealed chain files.
///
/// Derived from a master seed and the document's path hash
/// via HKDF-SHA256.
pub struct ChainEncryptionKey {
    key: ProtectedKey<32>,
}

impl ChainEncryptionKey {
    /// Derive a chain encryption key from a master seed and document ID.
    ///
    /// `master_seed` is the 32-byte identity seed (from sealed identity or PUF).
    /// `document_id` is the 32-byte hash of the canonical document path.
    pub fn derive(master_seed: &[u8], document_id: &[u8; 32]) -> Result<Self> {
        use zeroize::Zeroize;
        let hk = Hkdf::<Sha256>::new(Some(b"witnessd-chain-seal-v1"), master_seed);
        let mut key_bytes = [0u8; 32];
        hk.expand(document_id, &mut key_bytes)
            .map_err(|_| Error::crypto("HKDF expand failed for chain encryption key"))?;
        let p_key = ProtectedKey::new(key_bytes);
        key_bytes.zeroize();
        Ok(Self { key: p_key })
    }

    /// Create a key from raw bytes (for testing).
    #[cfg(test)]
    pub fn from_bytes(key_bytes: [u8; 32]) -> Self {
        Self {
            key: ProtectedKey::new(key_bytes),
        }
    }
}

/// Save a chain to a sealed (encrypted) file.
///
/// The chain is serialized to JSON, then encrypted with AES-256-GCM.
/// The `document_id` is stored in cleartext in the header so the correct
/// key can be derived during loading.
pub fn save_sealed(
    chain: &Chain,
    path: &Path,
    key: &ChainEncryptionKey,
    document_id: &[u8; 32],
) -> Result<()> {
    let plaintext = serde_json::to_vec(chain)
        .map_err(|e| Error::checkpoint(format!("failed to serialize chain: {e}")))?;

    let cipher = Aes256Gcm::new_from_slice(key.key.as_bytes())
        .map_err(|_| Error::crypto("AES-GCM key init failed"))?;

    let mut nonce_bytes = [0u8; 12];
    rand::Fill::fill(&mut nonce_bytes, &mut rand::rng());
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Build the header first so it can serve as AAD (associated data).
    // This authenticates magic, version, nonce, and document_id during
    // decryption, preventing header tampering.
    let mut header = Vec::with_capacity(HEADER_SIZE);
    header.extend_from_slice(SEALED_MAGIC);
    header.extend_from_slice(&SEALED_VERSION.to_le_bytes());
    header.extend_from_slice(&nonce_bytes);
    header.extend_from_slice(document_id);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: &plaintext,
                aad: &header,
            },
        )
        .map_err(|_| Error::crypto("AES-GCM encryption failed"))?;

    let mut output = Vec::with_capacity(HEADER_SIZE + ciphertext.len());
    output.extend_from_slice(&header);
    output.extend_from_slice(&ciphertext);

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp_path = path.with_extension("tmp");
    {
        use std::io::Write;
        let mut f = fs::File::create(&tmp_path)?;
        f.write_all(&output)?;
        f.sync_all()?;
    }
    fs::rename(&tmp_path, path)?;

    Ok(())
}

/// Load a chain from a sealed (encrypted) file.
///
/// Reads the document_id from the header, decrypts the chain JSON,
/// and deserializes it. Returns an error if the file is tampered,
/// the wrong key is used, or the format is invalid.
pub fn load_sealed(path: &Path, key: &ChainEncryptionKey) -> Result<Chain> {
    load_sealed_verified(path, key, None)
}

/// Load a sealed chain, verifying the embedded document_id matches `expected_id`.
///
/// Eliminates the TOCTOU gap between `read_sealed_document_id` and `load_sealed`
/// by performing header read and decryption in a single atomic file read.
pub fn load_sealed_verified(
    path: &Path,
    key: &ChainEncryptionKey,
    expected_id: Option<&[u8; 32]>,
) -> Result<Chain> {
    let data = fs::read(path)?;

    if data.len() < HEADER_SIZE + 16 {
        // Minimum: header + 16-byte GCM tag
        return Err(Error::checkpoint("sealed file too short"));
    }

    if &data[0..4] != SEALED_MAGIC {
        return Err(Error::checkpoint("invalid sealed file magic"));
    }

    let version = u32::from_le_bytes(
        data[4..8]
            .try_into()
            .map_err(|_| Error::checkpoint("sealed file header truncated"))?,
    );
    if version != SEALED_VERSION {
        return Err(Error::checkpoint(format!(
            "unsupported sealed file version: {version}"
        )));
    }

    let nonce_bytes = &data[8..20];
    let header_doc_id = &data[20..52];

    if let Some(expected) = expected_id {
        if header_doc_id != expected.as_slice() {
            return Err(Error::checkpoint(
                "sealed file document_id does not match expected value",
            ));
        }
    }

    let header = &data[..HEADER_SIZE];
    let ciphertext = &data[HEADER_SIZE..];

    let cipher = Aes256Gcm::new_from_slice(key.key.as_bytes())
        .map_err(|_| Error::crypto("AES-GCM key init failed"))?;

    let nonce = Nonce::from_slice(nonce_bytes);
    // Use the header as AAD so that any tampering of magic, version, nonce,
    // or document_id causes decryption to fail with an auth tag mismatch.
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: header,
            },
        )
        .map_err(|_| Error::crypto("AES-GCM decryption failed (tampered or wrong key)"))?;

    let mut chain: Chain = serde_json::from_slice(&plaintext)
        .map_err(|e| Error::checkpoint(format!("failed to deserialize sealed chain: {e}")))?;
    chain.set_storage_path(path.to_path_buf());

    Ok(chain)
}

/// Read the document_id from a sealed file header without decrypting.
///
/// Useful for deriving the correct key before loading.
pub fn read_sealed_document_id(path: &Path) -> Result<[u8; 32]> {
    let data = fs::read(path)?;
    if data.len() < HEADER_SIZE {
        return Err(Error::checkpoint("sealed file too short for header"));
    }
    if &data[0..4] != SEALED_MAGIC {
        return Err(Error::checkpoint("invalid sealed file magic"));
    }
    let mut doc_id = [0u8; 32];
    doc_id.copy_from_slice(&data[20..52]);
    Ok(doc_id)
}

/// Check if a file is a sealed chain file (by magic bytes).
pub fn is_sealed_file(path: &Path) -> bool {
    use std::io::Read;
    let mut magic = [0u8; 4];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut magic))
        .map(|()| &magic == SEALED_MAGIC)
        .unwrap_or(false)
}

/// Migrate a plaintext JSON chain file to sealed format.
///
/// 1. Loads the plaintext `.json` chain
/// 2. Saves it as a `.sealed` file
/// 3. Renames the original to `.json.bak`
///
/// Returns the path to the new sealed file.
pub fn migrate_to_sealed(
    json_path: &Path,
    key: &ChainEncryptionKey,
    document_id: &[u8; 32],
) -> Result<std::path::PathBuf> {
    let chain = Chain::load(json_path)?;

    let sealed_path = json_path.with_extension("sealed");
    save_sealed(&chain, &sealed_path, key, document_id)?;

    // Rename original to .bak — clean up sealed file on failure to avoid
    // leaving both plaintext and encrypted copies.
    let bak_path = json_path.with_extension("json.bak");
    if let Err(e) = fs::rename(json_path, &bak_path) {
        let _ = fs::remove_file(&sealed_path);
        return Err(e.into());
    }

    Ok(sealed_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::SignaturePolicy;
    use crate::vdf::Parameters;
    use std::time::Duration;
    use tempfile::TempDir;

    fn test_vdf_params() -> Parameters {
        Parameters {
            iterations_per_second: 1000,
            min_iterations: 10,
            max_iterations: 100_000,
        }
    }

    fn test_key() -> ChainEncryptionKey {
        ChainEncryptionKey::from_bytes([0xAA; 32])
    }

    fn test_document_id() -> [u8; 32] {
        [0xBB; 32]
    }

    #[test]
    fn test_sealed_roundtrip() {
        let dir = TempDir::new().unwrap();
        let canonical_dir = dir.path().canonicalize().unwrap();
        let doc_path = canonical_dir.join("test.txt");
        fs::write(&doc_path, b"hello world").unwrap();

        let mut chain = Chain::new(&doc_path, test_vdf_params())
            .unwrap()
            .with_signature_policy(SignaturePolicy::Optional);
        chain
            .commit_with_vdf_duration(None, Duration::from_millis(10))
            .unwrap();

        let key = test_key();
        let doc_id = test_document_id();
        let sealed_path = canonical_dir.join("chain.sealed");

        save_sealed(&chain, &sealed_path, &key, &doc_id).unwrap();
        assert!(sealed_path.exists());

        let loaded = load_sealed(&sealed_path, &key).unwrap();
        assert_eq!(loaded.checkpoints.len(), chain.checkpoints.len());
        assert_eq!(loaded.checkpoints[0].hash, chain.checkpoints[0].hash);
    }

    #[test]
    fn test_wrong_key_fails() {
        let dir = TempDir::new().unwrap();
        let canonical_dir = dir.path().canonicalize().unwrap();
        let doc_path = canonical_dir.join("test.txt");
        fs::write(&doc_path, b"data").unwrap();

        let mut chain = Chain::new(&doc_path, test_vdf_params())
            .unwrap()
            .with_signature_policy(SignaturePolicy::Optional);
        chain
            .commit_with_vdf_duration(None, Duration::from_millis(10))
            .unwrap();

        let key = test_key();
        let doc_id = test_document_id();
        let sealed_path = canonical_dir.join("chain.sealed");

        save_sealed(&chain, &sealed_path, &key, &doc_id).unwrap();

        let wrong_key = ChainEncryptionKey::from_bytes([0xCC; 32]);
        let result = load_sealed(&sealed_path, &wrong_key);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("tampered or wrong key"));
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let dir = TempDir::new().unwrap();
        let canonical_dir = dir.path().canonicalize().unwrap();
        let doc_path = canonical_dir.join("test.txt");
        fs::write(&doc_path, b"data").unwrap();

        let mut chain = Chain::new(&doc_path, test_vdf_params())
            .unwrap()
            .with_signature_policy(SignaturePolicy::Optional);
        chain
            .commit_with_vdf_duration(None, Duration::from_millis(10))
            .unwrap();

        let key = test_key();
        let doc_id = test_document_id();
        let sealed_path = canonical_dir.join("chain.sealed");

        save_sealed(&chain, &sealed_path, &key, &doc_id).unwrap();

        let mut data = fs::read(&sealed_path).unwrap();
        let tamper_idx = HEADER_SIZE + 5;
        data[tamper_idx] ^= 0xFF;
        fs::write(&sealed_path, &data).unwrap();

        let result = load_sealed(&sealed_path, &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_is_sealed_file() {
        let dir = TempDir::new().unwrap();
        let canonical_dir = dir.path().canonicalize().unwrap();

        let sealed_path = canonical_dir.join("test.sealed");
        let mut data = Vec::new();
        data.extend_from_slice(SEALED_MAGIC);
        data.extend_from_slice(&SEALED_VERSION.to_le_bytes());
        data.extend_from_slice(&[0u8; 12]); // nonce
        data.extend_from_slice(&[0u8; 32]); // doc_id
        data.extend_from_slice(&[0u8; 32]); // fake ciphertext
        fs::write(&sealed_path, &data).unwrap();
        assert!(is_sealed_file(&sealed_path));

        let json_path = canonical_dir.join("test.json");
        fs::write(&json_path, b"{}").unwrap();
        assert!(!is_sealed_file(&json_path));

        assert!(!is_sealed_file(&canonical_dir.join("nonexistent")));
    }

    #[test]
    fn test_read_sealed_document_id() {
        let dir = TempDir::new().unwrap();
        let canonical_dir = dir.path().canonicalize().unwrap();
        let doc_path = canonical_dir.join("test.txt");
        fs::write(&doc_path, b"data").unwrap();

        let mut chain = Chain::new(&doc_path, test_vdf_params())
            .unwrap()
            .with_signature_policy(SignaturePolicy::Optional);
        chain
            .commit_with_vdf_duration(None, Duration::from_millis(10))
            .unwrap();

        let key = test_key();
        let doc_id = test_document_id();
        let sealed_path = canonical_dir.join("chain.sealed");

        save_sealed(&chain, &sealed_path, &key, &doc_id).unwrap();

        let read_id = read_sealed_document_id(&sealed_path).unwrap();
        assert_eq!(read_id, doc_id);
    }

    #[test]
    fn test_migrate_to_sealed() {
        let dir = TempDir::new().unwrap();
        let canonical_dir = dir.path().canonicalize().unwrap();
        let doc_path = canonical_dir.join("test.txt");
        fs::write(&doc_path, b"hello").unwrap();

        let mut chain = Chain::new(&doc_path, test_vdf_params())
            .unwrap()
            .with_signature_policy(SignaturePolicy::Optional);
        chain
            .commit_with_vdf_duration(None, Duration::from_millis(10))
            .unwrap();

        let json_path = canonical_dir.join("chain.json");
        chain.save(&json_path).unwrap();
        assert!(json_path.exists());

        let key = test_key();
        let doc_id = test_document_id();

        let sealed_path = migrate_to_sealed(&json_path, &key, &doc_id).unwrap();
        assert!(sealed_path.exists());
        assert!(!json_path.exists()); // original renamed
        assert!(canonical_dir.join("chain.json.bak").exists());

        let loaded = load_sealed(&sealed_path, &key).unwrap();
        assert_eq!(loaded.checkpoints.len(), 1);
    }

    #[test]
    fn test_key_derivation() {
        let master_seed = [0x42u8; 32];
        let doc_id = [0x01u8; 32];

        let key1 = ChainEncryptionKey::derive(&master_seed, &doc_id).unwrap();
        let key2 = ChainEncryptionKey::derive(&master_seed, &doc_id).unwrap();

        assert_eq!(key1.key.as_bytes(), key2.key.as_bytes());

        let doc_id2 = [0x02u8; 32];
        let key3 = ChainEncryptionKey::derive(&master_seed, &doc_id2).unwrap();
        assert_ne!(key1.key.as_bytes(), key3.key.as_bytes());
    }

    #[test]
    fn test_short_file_fails() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("short.sealed");
        fs::write(&path, b"WCS").unwrap(); // Too short

        assert!(load_sealed(&path, &test_key()).is_err());
    }

    #[test]
    fn test_invalid_magic_fails() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("bad.sealed");
        let mut data = vec![0u8; 100];
        data[0..4].copy_from_slice(b"XXXX"); // Wrong magic
        fs::write(&path, &data).unwrap();

        assert!(load_sealed(&path, &test_key()).is_err());
    }

    #[test]
    fn test_load_sealed_verified_correct_id() {
        let dir = TempDir::new().unwrap();
        let canonical_dir = dir.path().canonicalize().unwrap();
        let doc_path = canonical_dir.join("test.txt");
        fs::write(&doc_path, b"data").unwrap();

        let mut chain = Chain::new(&doc_path, test_vdf_params())
            .unwrap()
            .with_signature_policy(SignaturePolicy::Optional);
        chain
            .commit_with_vdf_duration(None, Duration::from_millis(10))
            .unwrap();

        let key = test_key();
        let doc_id = test_document_id();
        let sealed_path = canonical_dir.join("chain.sealed");
        save_sealed(&chain, &sealed_path, &key, &doc_id).unwrap();

        let loaded = load_sealed_verified(&sealed_path, &key, Some(&doc_id)).unwrap();
        assert_eq!(loaded.checkpoints.len(), chain.checkpoints.len());
    }

    #[test]
    fn test_load_sealed_verified_wrong_id() {
        let dir = TempDir::new().unwrap();
        let canonical_dir = dir.path().canonicalize().unwrap();
        let doc_path = canonical_dir.join("test.txt");
        fs::write(&doc_path, b"data").unwrap();

        let mut chain = Chain::new(&doc_path, test_vdf_params())
            .unwrap()
            .with_signature_policy(SignaturePolicy::Optional);
        chain
            .commit_with_vdf_duration(None, Duration::from_millis(10))
            .unwrap();

        let key = test_key();
        let doc_id = test_document_id();
        let sealed_path = canonical_dir.join("chain.sealed");
        save_sealed(&chain, &sealed_path, &key, &doc_id).unwrap();

        let wrong_id = [0xCC; 32];
        let result = load_sealed_verified(&sealed_path, &key, Some(&wrong_id));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("does not match expected value"));
    }
}
