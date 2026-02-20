use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

pub mod obfuscated;
pub mod obfuscation;
pub use obfuscated::Obfuscated;
pub use obfuscation::ObfuscatedString;

pub type HmacSha256 = Hmac<Sha256>;

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
    hasher.update(b"witnessd-event-v1");
    hasher.update(device_id);
    hasher.update(timestamp_ns.to_be_bytes());
    hasher.update(file_path.as_bytes());
    hasher.update(content_hash);
    hasher.update(file_size.to_be_bytes());
    hasher.update(size_delta.to_be_bytes());
    hasher.update(previous_hash);

    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
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
    mac.update(b"witnessd-event-v1");
    mac.update(device_id);
    mac.update(&timestamp_ns.to_be_bytes());
    mac.update(file_path.as_bytes());
    mac.update(content_hash);
    mac.update(&file_size.to_be_bytes());
    mac.update(&size_delta.to_be_bytes());
    mac.update(previous_hash);

    let result = mac.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result.into_bytes());
    out
}

pub fn compute_integrity_hmac(key: &[u8], chain_hash: &[u8; 32], event_count: i64) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(b"witnessd-integrity-v1");
    mac.update(chain_hash);
    mac.update(&event_count.to_be_bytes());

    let result = mac.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result.into_bytes());
    out
}

pub fn derive_hmac_key(priv_key_seed: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"witnessd-hmac-key-v1");
    hasher.update(priv_key_seed);
    hasher.finalize().to_vec()
}
