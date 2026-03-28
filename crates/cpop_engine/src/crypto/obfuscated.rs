// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Memory-resident data obfuscation to defeat casual memory scraping.
//! NOT cryptographically secure—designed to raise the bar, not provide guarantees.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use zeroize::Zeroize;

/// Process-wide random secret, initialized once. Combined with the per-instance
/// nonce so that the mask is not recoverable from a memory snapshot of the
/// `Obfuscated` struct alone (EH-009).
static PROCESS_SECRET: OnceLock<u64> = OnceLock::new();

fn process_secret() -> u64 {
    *PROCESS_SECRET.get_or_init(|| {
        let mut buf = [0u8; 8];
        getrandom::getrandom(&mut buf).unwrap_or_else(|_| {
            // Fallback: use address-space entropy if getrandom fails
            buf = ((&buf as *const _ as u64) ^ 0xA5A5A5A5_5A5A5A5A).to_ne_bytes();
        });
        u64::from_ne_bytes(buf)
    })
}

// Accepted: concurrent threads may compute duplicate XOR keys; no security impact
/// Rolling nonce that changes every N accesses
static ROLLING_KEY: AtomicU64 = AtomicU64::new(0xDEADBEEF_CAFEBABE);

fn next_nonce() -> u64 {
    let current = ROLLING_KEY.load(Ordering::Relaxed);
    let next = current.rotate_left(7) ^ current.wrapping_mul(0x5851F42D4C957F2D);
    ROLLING_KEY.store(next, Ordering::Relaxed);
    next
}

/// Derive the effective mask key by mixing the per-instance nonce with the
/// process secret. The nonce is stored in the struct; the secret is not.
fn effective_key(nonce: u64) -> u64 {
    nonce ^ process_secret()
}

/// Obfuscated wrapper that keeps data XOR-masked in memory.
/// The effective mask is derived from combining a per-instance nonce with a
/// process-wide secret, so a memory dump of this struct alone cannot recover
/// the plaintext.
#[derive(Clone)]
pub struct Obfuscated<T> {
    masked_data: Vec<u8>,
    mask_nonce: u64,
    _phantom: std::marker::PhantomData<T>,
}

impl<T: Serialize + for<'de> Deserialize<'de>> Obfuscated<T> {
    /// Serialize and XOR-mask the value with a fresh rolling key.
    pub fn new(value: &T) -> Self {
        let mut serialized = match bincode::serde::encode_to_vec(value, bincode::config::standard())
        {
            Ok(v) => v,
            Err(e) => {
                log::error!("Obfuscated serialization failed: {e}");
                Vec::new()
            }
        };
        let mask_nonce = next_nonce();
        let masked_data = Self::xor_data(&serialized, effective_key(mask_nonce));
        serialized.zeroize();

        Self {
            masked_data,
            mask_nonce,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Unmask and deserialize the stored value.
    ///
    /// Returns `None` if deserialization fails (e.g. data was corrupted or the
    /// obfuscation key was lost). Callers should treat `None` as a tamper signal.
    pub fn reveal(&self) -> Option<T> {
        let mut unmasked = Self::xor_data(&self.masked_data, effective_key(self.mask_nonce));

        let result = bincode::serde::decode_from_slice(&unmasked, bincode::config::standard())
            .ok()
            .map(|(value, _): (T, usize)| value);

        unmasked.zeroize();

        result
    }

    fn xor_data(data: &[u8], key: u64) -> Vec<u8> {
        let mut out = data.to_vec();
        for (i, byte) in out.iter_mut().enumerate() {
            let key_byte = ((key >> ((i % 8) * 8)) & 0xFF) as u8;
            *byte ^= key_byte;
        }
        out
    }

    /// Re-mask with a new key (call periodically to frustrate memory snapshots).
    ///
    /// If deserialization fails the existing masked data is left unchanged.
    pub fn rotate(&mut self) {
        if let Some(value) = self.reveal() {
            *self = Self::new(&value);
        }
    }
}

impl<T> Drop for Obfuscated<T> {
    fn drop(&mut self) {
        self.masked_data.zeroize();
    }
}

impl<T> std::fmt::Debug for Obfuscated<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "***OBFUSCATED***")
    }
}

impl<T: Default + Serialize + for<'de> Deserialize<'de>> Default for Obfuscated<T> {
    fn default() -> Self {
        Self::new(&T::default())
    }
}
