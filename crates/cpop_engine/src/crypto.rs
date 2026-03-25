// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

pub mod anti_analysis;
pub mod mem;
pub mod obfuscated;
pub mod obfuscation;
pub use anti_analysis::{harden_process, is_debugger_present};
pub use mem::{ProtectedBuf, ProtectedKey};
pub use obfuscated::Obfuscated;
pub use obfuscation::ObfuscatedString;

/// HMAC-SHA256 type alias used for event and integrity MACs.
pub type HmacSha256 = Hmac<Sha256>;

/// Compute SHA-256 hash of a file via streaming chunked reader.
pub fn hash_file(path: &Path) -> std::io::Result<[u8; 32]> {
    let (hash, _) = hash_file_with_size(path)?;
    Ok(hash)
}

/// Compute SHA-256 hash of a file, returning (hash, bytes_read).
/// Eliminates TOCTOU races vs separate `fs::metadata` call.
pub fn hash_file_with_size(path: &Path) -> std::io::Result<([u8; 32], u64)> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    let mut total_bytes: u64 = 0;

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
        total_bytes += bytes_read as u64;
    }

    Ok((hasher.finalize().into(), total_bytes))
}

/// Compute SHA-256 chain hash for a file event with domain separation.
pub fn compute_event_hash(
    device_id: &[u8; 16],
    timestamp_ns: i64,
    file_path: &str,
    content_hash: &[u8; 32],
    file_size: i64,
    size_delta: i32,
    previous_hash: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"witnessd-event-v2");
    hasher.update(device_id);
    hasher.update(timestamp_ns.to_be_bytes());
    // Length-prefix variable-length field to prevent concatenation ambiguity
    let path_bytes = file_path.as_bytes();
    hasher.update((path_bytes.len() as u32).to_be_bytes());
    hasher.update(path_bytes);
    hasher.update(content_hash);
    hasher.update(file_size.to_be_bytes());
    hasher.update(size_delta.to_be_bytes());
    hasher.update(previous_hash);

    hasher.finalize().into()
}

/// Compute HMAC-SHA256 integrity tag for a file event.
#[allow(clippy::too_many_arguments)]
pub fn compute_event_hmac(
    key: &[u8],
    device_id: &[u8; 16],
    timestamp_ns: i64,
    file_path: &str,
    content_hash: &[u8; 32],
    file_size: i64,
    size_delta: i32,
    previous_hash: &[u8; 32],
) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(b"witnessd-event-v2");
    mac.update(device_id);
    mac.update(&timestamp_ns.to_be_bytes());
    // Length-prefix variable-length field to prevent concatenation ambiguity
    let path_bytes = file_path.as_bytes();
    mac.update(&(path_bytes.len() as u32).to_be_bytes());
    mac.update(path_bytes);
    mac.update(content_hash);
    mac.update(&file_size.to_be_bytes());
    mac.update(&size_delta.to_be_bytes());
    mac.update(previous_hash);

    mac.finalize().into_bytes().into()
}

/// Compute HMAC-SHA256 integrity tag over chain hash and event count.
pub fn compute_integrity_hmac(key: &[u8], chain_hash: &[u8; 32], event_count: i64) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(b"witnessd-integrity-v1");
    mac.update(chain_hash);
    mac.update(&event_count.to_be_bytes());

    mac.finalize().into_bytes().into()
}

/// Derive an HMAC key from a private key seed via SHA-256 with domain separation.
///
/// NOTE: This intentionally uses SHA-256 rather than HKDF for backwards compatibility
/// with existing HMAC chains. Changing to HKDF would invalidate all previously stored
/// event integrity tags.
pub fn derive_hmac_key(priv_key_seed: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut hasher = Sha256::new();
    hasher.update(b"witnessd-hmac-key-v1");
    hasher.update(priv_key_seed);
    Zeroizing::new(hasher.finalize().to_vec())
}

/// Derive PRK per draft-condrey-rats-pop §5.3:
///   PRK = HKDF-Extract(salt="PoP-key-derivation-v1", IKM=merkle-root || input)
fn derive_pop_prk(merkle_root: &[u8], swf_input: &[u8]) -> Hkdf<Sha256> {
    let mut ikm = Vec::with_capacity(merkle_root.len() + swf_input.len());
    ikm.extend_from_slice(merkle_root);
    ikm.extend_from_slice(swf_input);
    Hkdf::<Sha256>::new(Some(b"PoP-key-derivation-v1"), &ikm)
}

/// Compute jitter tag per draft-condrey-rats-pop §5.3:
///   tag-key = HKDF-Expand(PRK, "PoP-jitter-tag-v1", 32)
///   jitter-tag = HMAC-SHA256(tag-key, CBOR-encode(intervals))
pub fn compute_jitter_seal(merkle_root: &[u8], swf_input: &[u8], intervals_cbor: &[u8]) -> Vec<u8> {
    let hk = derive_pop_prk(merkle_root, swf_input);
    let mut tag_key = [0u8; 32];
    hk.expand(b"PoP-jitter-tag-v1", &mut tag_key)
        .expect("32 bytes is valid HKDF-Expand length");

    let mut mac =
        HmacSha256::new_from_slice(&tag_key).expect("32-byte key is valid for HMAC-SHA256");
    tag_key.zeroize();
    mac.update(intervals_cbor);
    mac.finalize().into_bytes().to_vec()
}

/// Compute entangled-binding per draft-condrey-rats-pop §5.3:
///   binding-key = HKDF-Expand(PRK, "PoP-entangled-binding-v1", 32)
///   entangled-binding = HMAC-SHA256(binding-key, prev-hash || content-hash || ...)
pub fn compute_entangled_mac(
    merkle_root: &[u8],
    swf_input: &[u8],
    prev_hash: &[u8],
    content_hash: &[u8],
    jitter_binding_cbor: &[u8],
    physical_state_cbor: &[u8],
) -> Vec<u8> {
    let hk = derive_pop_prk(merkle_root, swf_input);
    let mut binding_key = [0u8; 32];
    hk.expand(b"PoP-entangled-binding-v1", &mut binding_key)
        .expect("32 bytes is valid HKDF-Expand length");

    let mut mac =
        HmacSha256::new_from_slice(&binding_key).expect("32-byte key is valid for HMAC-SHA256");
    binding_key.zeroize();
    mac.update(&(prev_hash.len() as u32).to_be_bytes());
    mac.update(prev_hash);
    mac.update(&(content_hash.len() as u32).to_be_bytes());
    mac.update(content_hash);
    mac.update(&(jitter_binding_cbor.len() as u32).to_be_bytes());
    mac.update(jitter_binding_cbor);
    mac.update(&(physical_state_cbor.len() as u32).to_be_bytes());
    mac.update(physical_state_cbor);
    mac.finalize().into_bytes().to_vec()
}

/// Owner-only permissions: Unix chmod `mode`, Windows icacls current-user-only.
pub fn restrict_permissions(path: &Path, mode: u32) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    }
    #[cfg(windows)]
    {
        let _ = mode;
        let user = std::env::var("USERNAME").unwrap_or_else(|_| "CURRENT_USER".into());
        let grant_arg = format!("{user}:(F)");
        match std::process::Command::new("icacls")
            .arg(path.as_os_str())
            .args(["/inheritance:r", "/grant:r"])
            .arg(&grant_arg)
            .output()
        {
            Ok(output) if output.status.success() => {}
            Ok(output) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!(
                        "icacls failed with exit code {:?}: {}",
                        output.status.code(),
                        String::from_utf8_lossy(&output.stderr)
                    ),
                ));
            }
            Err(e) => return Err(e),
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, mode);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jitter_seal_deterministic() {
        let root = [0xAA; 32];
        let input = [0x11; 32];
        let intervals = b"test-cbor-data";
        let seal1 = compute_jitter_seal(&root, &input, intervals);
        let seal2 = compute_jitter_seal(&root, &input, intervals);
        assert_eq!(seal1, seal2);
        assert_eq!(seal1.len(), 32);
    }

    #[test]
    fn jitter_seal_varies_with_root() {
        let input = [0x11; 32];
        let intervals = b"test-cbor-data";
        let seal_a = compute_jitter_seal(&[0xAA; 32], &input, intervals);
        let seal_b = compute_jitter_seal(&[0xBB; 32], &input, intervals);
        assert_ne!(seal_a, seal_b);
    }

    #[test]
    fn entangled_mac_deterministic() {
        let root = [0xCC; 32];
        let input = [0x11; 32];
        let prev = [0x01; 32];
        let content = [0x02; 32];
        let jb_cbor = b"jitter-binding";
        let ps_cbor = b"physical-state";
        let mac1 = compute_entangled_mac(&root, &input, &prev, &content, jb_cbor, ps_cbor);
        let mac2 = compute_entangled_mac(&root, &input, &prev, &content, jb_cbor, ps_cbor);
        assert_eq!(mac1, mac2);
        assert_eq!(mac1.len(), 32);
    }

    #[test]
    fn entangled_mac_varies_with_inputs() {
        let root = [0xCC; 32];
        let input = [0x11; 32];
        let prev = [0x01; 32];
        let content = [0x02; 32];
        let mac_a = compute_entangled_mac(&root, &input, &prev, &content, b"jb1", b"ps1");
        let mac_b = compute_entangled_mac(&root, &input, &prev, &content, b"jb2", b"ps1");
        assert_ne!(mac_a, mac_b);
    }

    #[test]
    fn event_hash_deterministic() {
        let device_id = [0x01; 16];
        let timestamp_ns = 1_700_000_000_000_000_000i64;
        let file_path = "/tmp/test.txt";
        let content_hash = [0xAB; 32];
        let file_size = 1024i64;
        let size_delta = 42i32;
        let previous_hash = [0x00; 32];

        let h1 = compute_event_hash(
            &device_id,
            timestamp_ns,
            file_path,
            &content_hash,
            file_size,
            size_delta,
            &previous_hash,
        );
        let h2 = compute_event_hash(
            &device_id,
            timestamp_ns,
            file_path,
            &content_hash,
            file_size,
            size_delta,
            &previous_hash,
        );
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 32);
    }

    #[test]
    fn event_hash_changes_with_any_input() {
        let device_id = [0x01; 16];
        let ts = 1_000i64;
        let path = "file.txt";
        let content = [0xAA; 32];
        let prev = [0x00; 32];

        let baseline = compute_event_hash(&device_id, ts, path, &content, 100, 10, &prev);

        // Different device_id
        let different_device = [0x02; 16];
        assert_ne!(
            baseline,
            compute_event_hash(&different_device, ts, path, &content, 100, 10, &prev)
        );

        // Different timestamp
        assert_ne!(
            baseline,
            compute_event_hash(&device_id, ts + 1, path, &content, 100, 10, &prev)
        );

        // Different file path
        assert_ne!(
            baseline,
            compute_event_hash(&device_id, ts, "other.txt", &content, 100, 10, &prev)
        );

        // Different previous hash
        let diff_prev = [0xFF; 32];
        assert_ne!(
            baseline,
            compute_event_hash(&device_id, ts, path, &content, 100, 10, &diff_prev)
        );
    }

    #[test]
    fn event_hmac_deterministic() {
        let key = b"test-hmac-key-32-bytes-long!!!!!";
        let device_id = [0x01; 16];
        let ts = 1_700_000_000i64;
        let path = "/doc.txt";
        let content = [0xCC; 32];
        let prev = [0x00; 32];

        let m1 = compute_event_hmac(key, &device_id, ts, path, &content, 512, 8, &prev);
        let m2 = compute_event_hmac(key, &device_id, ts, path, &content, 512, 8, &prev);
        assert_eq!(m1, m2);
        assert_eq!(m1.len(), 32);
    }

    #[test]
    fn event_hmac_differs_with_different_keys() {
        let device_id = [0x01; 16];
        let ts = 1_000i64;
        let path = "f.txt";
        let content = [0xAA; 32];
        let prev = [0x00; 32];

        let m1 = compute_event_hmac(b"key-alpha", &device_id, ts, path, &content, 1, 0, &prev);
        let m2 = compute_event_hmac(b"key-bravo", &device_id, ts, path, &content, 1, 0, &prev);
        assert_ne!(m1, m2);
    }

    #[test]
    fn event_hmac_differs_from_event_hash() {
        let key = b"some-key";
        let device_id = [0x01; 16];
        let ts = 1_000i64;
        let path = "f.txt";
        let content = [0xAA; 32];
        let prev = [0x00; 32];

        let hash = compute_event_hash(&device_id, ts, path, &content, 1, 0, &prev);
        let hmac = compute_event_hmac(key, &device_id, ts, path, &content, 1, 0, &prev);
        assert_ne!(hash.as_slice(), hmac.as_slice());
    }

    #[test]
    fn integrity_hmac_deterministic() {
        let key = b"integrity-key";
        let chain_hash = [0xDD; 32];
        let event_count = 42i64;

        let m1 = compute_integrity_hmac(key, &chain_hash, event_count);
        let m2 = compute_integrity_hmac(key, &chain_hash, event_count);
        assert_eq!(m1, m2);
        assert_eq!(m1.len(), 32);
    }

    #[test]
    fn integrity_hmac_differs_with_key() {
        let chain_hash = [0xDD; 32];
        let m1 = compute_integrity_hmac(b"key-1", &chain_hash, 10);
        let m2 = compute_integrity_hmac(b"key-2", &chain_hash, 10);
        assert_ne!(m1, m2);
    }

    #[test]
    fn integrity_hmac_differs_with_count() {
        let key = b"same-key";
        let chain_hash = [0xDD; 32];
        let m1 = compute_integrity_hmac(key, &chain_hash, 1);
        let m2 = compute_integrity_hmac(key, &chain_hash, 2);
        assert_ne!(m1, m2);
    }

    #[test]
    fn derive_hmac_key_deterministic() {
        let seed = b"my-private-key-seed";
        let k1 = derive_hmac_key(seed);
        let k2 = derive_hmac_key(seed);
        assert_eq!(k1, k2);
        assert_eq!(k1.len(), 32);
    }

    #[test]
    fn derive_hmac_key_different_seeds_give_different_keys() {
        let k1 = derive_hmac_key(b"seed-alpha");
        let k2 = derive_hmac_key(b"seed-bravo");
        assert_ne!(k1, k2);
    }

    #[test]
    fn hash_file_and_hash_file_with_size_agree() {
        let dir = std::env::temp_dir().join("cpop_crypto_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test_hash.txt");
        let content = b"hello world for hashing";
        std::fs::write(&path, content).unwrap();

        let hash_only = hash_file(&path).unwrap();
        let (hash_with_size, size) = hash_file_with_size(&path).unwrap();

        assert_eq!(hash_only, hash_with_size);
        assert_eq!(size, content.len() as u64);
        assert_eq!(hash_only.len(), 32);

        // Verify against known SHA-256 of the content
        let mut hasher = Sha256::new();
        hasher.update(content);
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(hash_only, expected);

        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn hash_file_nonexistent_returns_error() {
        let result = hash_file(Path::new("/tmp/cpop_crypto_nonexistent_file_xyz"));
        assert!(result.is_err());
    }
}
