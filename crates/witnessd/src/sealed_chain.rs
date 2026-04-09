// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! AES-256-GCM encrypted chain file storage (anti-tamper).
//!
//! Refactored Version: Uses structured headers and atomic write primitives.
//! Optimizes for readability, safety, and performance.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::checkpoint::Chain;
use crate::crypto::ProtectedKey;
use crate::error::{Error, Result};

// ---------------------------------------------------------------------------
// Constants & Structured Header
// ---------------------------------------------------------------------------

const SEALED_MAGIC: &[u8; 4] = b"WCSF";
const SEALED_VERSION_V1: u32 = 1;
const SEALED_VERSION_V2: u32 = 2;
const HEADER_SIZE: usize = 52;

/// A formal structure for the file header to prevent manual slicing errors.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SealedHeader {
    version: u32,
    nonce: [u8; 12],
    document_id: [u8; 32],
}

impl SealedHeader {
    fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..4].copy_from_slice(SEALED_MAGIC);
        buf[4..8].copy_from_slice(&self.version.to_le_bytes());
        buf[8..20].copy_from_slice(&self.nonce);
        buf[20..52].copy_from_slice(&self.document_id);
        buf
    }

    fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < HEADER_SIZE {
            return Err(Error::checkpoint("sealed file header truncated"));
        }
        if &data[0..4] != SEALED_MAGIC {
            return Err(Error::checkpoint("invalid sealed file magic"));
        }
        let version = u32::from_le_bytes(data[4..8].try_into().unwrap());
        if version != SEALED_VERSION_V1 && version != SEALED_VERSION_V2 {
            return Err(Error::checkpoint(format!("unsupported version: {version}")));
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&data[8..20]);
        let mut document_id = [0u8; 32];
        document_id.copy_from_slice(&data[20..52]);

        Ok(Self { version, nonce, document_id })
    }
}

// ---------------------------------------------------------------------------
// Encryption Key Management
// ---------------------------------------------------------------------------

pub struct ChainEncryptionKey {
    key: ProtectedKey<32>,
}

impl ChainEncryptionKey {
    pub fn derive(master_seed: &[u8], document_id: &[u8; 32]) -> Result<Self> {
        if master_seed.len() < 32 {
            return Err(Error::crypto("master seed must be at least 32 bytes"));
        }
        let hk = Hkdf::<Sha256>::new(Some(b"witnessd-chain-seal-v1"), master_seed);
        let mut key_bytes = [0u8; 32];
        hk.expand(document_id, &mut key_bytes)
            .map_err(|_| Error::crypto("HKDF expand failed"))?;
        let p_key = ProtectedKey::new(key_bytes);
        key_bytes.zeroize();
        Ok(Self { key: p_key })
    }

    #[cfg(test)]
    pub fn from_bytes(key_bytes: [u8; 32]) -> Self {
        Self { key: ProtectedKey::new(key_bytes) }
    }
}

// ---------------------------------------------------------------------------
// Core Storage API
// ---------------------------------------------------------------------------

pub fn save_sealed(
    chain: &Chain,
    path: &Path,
    key: &ChainEncryptionKey,
    document_id: &[u8; 32],
) -> Result<()> {
    let plaintext = serde_json::to_vec(chain)
        .map_err(|e| Error::checkpoint(format!("serialization failed: {e}")))?;

    // Nonce V2: [8B Timestamp | 4B Random]
    let mut nonce_bytes = [0u8; 12];
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::crypto("system clock before UNIX epoch; cannot generate safe nonce"))?
        .as_nanos() as u64;
    nonce_bytes[..8].copy_from_slice(&ts.to_le_bytes());
    rand::Fill::fill(&mut nonce_bytes[8..], &mut rand::rng());

    let header = SealedHeader {
        version: SEALED_VERSION_V2,
        nonce: nonce_bytes,
        document_id: *document_id,
    };
    let header_bytes = header.to_bytes();

    let cipher = Aes256Gcm::new_from_slice(key.key.as_bytes())
        .map_err(|_| Error::crypto("cipher init failed"))?;

    let ciphertext = cipher.encrypt(
        Nonce::from_slice(&header.nonce),
        Payload { msg: &plaintext, aad: &header_bytes },
    ).map_err(|_| Error::crypto("encryption failed"))?;

    atomic_write(path, &header_bytes, &ciphertext)
}

pub fn load_sealed_verified(
    path: &Path,
    key: &ChainEncryptionKey,
    expected_id: Option<&[u8; 32]>,
) -> Result<Chain> {
    let data = fs::read(path)?;
    let header = SealedHeader::from_bytes(&data)?;

    if let Some(expected) = expected_id {
        if &header.document_id != expected {
            return Err(Error::checkpoint("document_id mismatch"));
        }
    }

    let cipher = Aes256Gcm::new_from_slice(key.key.as_bytes())
        .map_err(|_| Error::crypto("cipher init failed"))?;

    let plaintext = cipher.decrypt(
        Nonce::from_slice(&header.nonce),
        Payload { msg: &data[HEADER_SIZE..], aad: &data[..HEADER_SIZE] },
    ).map_err(|_| Error::crypto("decryption failed (tampered or wrong key)"))?;

    let mut chain: Chain = serde_json::from_slice(&plaintext)
        .map_err(|e| Error::checkpoint(format!("deserialization failed: {e}")))?;
    chain.set_storage_path(path.to_path_buf());
    Ok(chain)
}

pub fn load_sealed(path: &Path, key: &ChainEncryptionKey) -> Result<Chain> {
    load_sealed_verified(path, key, None)
}

pub fn read_sealed_document_id(path: &Path) -> Result<[u8; 32]> {
    let mut f = fs::File::open(path)?;
    let mut buf = [0u8; HEADER_SIZE];
    f.read_exact(&mut buf)?;
    let header = SealedHeader::from_bytes(&buf)?;
    Ok(header.document_id)
}

pub fn is_sealed_file(path: &Path) -> bool {
    fs::File::open(path)
        .and_then(|mut f| {
            let mut magic = [0u8; 4];
            f.read_exact(&mut magic).map(|_| &magic == SEALED_MAGIC)
        })
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Migration & Atomic Helpers
// ---------------------------------------------------------------------------

pub fn migrate_to_sealed(
    json_path: &Path,
    key: &ChainEncryptionKey,
    document_id: &[u8; 32],
) -> Result<PathBuf> {
    let chain = Chain::load(json_path)?;

    let sealed_path = json_path.with_extension("sealed");
    if sealed_path.exists() {
        let existing_id = read_sealed_document_id(&sealed_path)?;
        if existing_id != *document_id {
            return Err(Error::checkpoint("sealed file exists with different document_id"));
        }
    }
    save_sealed(&chain, &sealed_path, key, document_id)?;

    let bak_path = json_path.with_extension("json.bak");
    if let Err(e) = fs::rename(json_path, &bak_path) {
        let _ = fs::remove_file(&sealed_path);
        return Err(e.into());
    }

    Ok(sealed_path)
}

fn atomic_write(path: &Path, header: &[u8], body: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    tmp.write_all(header)?;
    tmp.write_all(body)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
fn save_sealed_v1(
    chain: &Chain,
    path: &Path,
    key: &ChainEncryptionKey,
    document_id: &[u8; 32],
) -> Result<()> {
    use aes_gcm::aead::Aead;
    let plaintext = serde_json::to_vec(chain)
        .map_err(|e| Error::checkpoint(format!("failed to serialize chain: {e}")))?;
    let cipher = Aes256Gcm::new_from_slice(key.key.as_bytes())
        .map_err(|_| Error::crypto("AES-GCM key init failed"))?;
    let mut nonce_bytes = [0u8; 12];
    rand::Fill::fill(&mut nonce_bytes, &mut rand::rng());
    let nonce = Nonce::from_slice(&nonce_bytes);
    let mut header = Vec::with_capacity(HEADER_SIZE);
    header.extend_from_slice(SEALED_MAGIC);
    header.extend_from_slice(&SEALED_VERSION_V1.to_le_bytes());
    header.extend_from_slice(&nonce_bytes);
    header.extend_from_slice(document_id);
    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: &plaintext, aad: &header })
        .map_err(|_| Error::crypto("AES-GCM encryption failed"))?;
    let mut output = Vec::with_capacity(HEADER_SIZE + ciphertext.len());
    output.extend_from_slice(&header);
    output.extend_from_slice(&ciphertext);
    let parent = path.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    tmp.write_all(&output)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
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
    fn test_header_roundtrip() {
        let header = SealedHeader {
            version: SEALED_VERSION_V2,
            nonce: [1u8; 12],
            document_id: [2u8; 32],
        };
        let bytes = header.to_bytes();
        let decoded = SealedHeader::from_bytes(&bytes).unwrap();
        assert_eq!(header, decoded);
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
        data.extend_from_slice(&SEALED_VERSION_V2.to_le_bytes());
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
            .contains("document_id mismatch"));
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
        fs::write(&path, b"WCS").unwrap();

        assert!(load_sealed(&path, &test_key()).is_err());
    }

    #[test]
    fn test_invalid_magic_fails() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("bad.sealed");
        let mut data = vec![0u8; 100];
        data[0..4].copy_from_slice(b"XXXX");
        fs::write(&path, &data).unwrap();

        assert!(load_sealed(&path, &test_key()).is_err());
    }

    #[test]
    fn test_v1_backward_compatibility() {
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
        let path = canonical_dir.join("chain_v1.sealed");

        save_sealed_v1(&chain, &path, &key, &doc_id).unwrap();

        let loaded = load_sealed(&path, &key).unwrap();
        assert_eq!(loaded.checkpoints.len(), chain.checkpoints.len());
        assert_eq!(loaded.checkpoints[0].hash, chain.checkpoints[0].hash);
    }
}