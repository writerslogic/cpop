// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

pub mod anti_analysis;
pub mod mem;
pub mod obfuscated;
pub mod obfuscation;
pub use anti_analysis::{harden_process, is_debugger_present};
pub use mem::{ProtectedBuf, ProtectedKey};
pub use obfuscated::Obfuscated;
pub use obfuscation::ObfuscatedString;

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

pub fn compute_integrity_hmac(key: &[u8], chain_hash: &[u8; 32], event_count: i64) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(b"witnessd-integrity-v1");
    mac.update(chain_hash);
    mac.update(&event_count.to_be_bytes());

    mac.finalize().into_bytes().into()
}

pub fn derive_hmac_key(priv_key_seed: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"witnessd-hmac-key-v1");
    hasher.update(priv_key_seed);
    hasher.finalize().to_vec()
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
    mac.update(prev_hash);
    mac.update(content_hash);
    mac.update(jitter_binding_cbor);
    mac.update(physical_state_cbor);
    mac.finalize().into_bytes().to_vec()
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
}
