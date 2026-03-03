// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

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
