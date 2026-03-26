// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Memory-resident data obfuscation to defeat casual memory scraping.
//! NOT cryptographically secure—designed to raise the bar, not provide guarantees.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use zeroize::Zeroize;

// Accepted: concurrent threads may compute duplicate XOR keys; no security impact
/// Rolling XOR key that changes every N accesses
static ROLLING_KEY: AtomicU64 = AtomicU64::new(0xDEADBEEF_CAFEBABE);

fn next_key() -> u64 {
    let current = ROLLING_KEY.load(Ordering::Relaxed);
    let next = current.rotate_left(7) ^ current.wrapping_mul(0x5851F42D4C957F2D);
    ROLLING_KEY.store(next, Ordering::Relaxed);
    next
}

/// Obfuscated wrapper that keeps data XOR-masked in memory
#[derive(Clone)]
pub struct Obfuscated<T> {
    masked_data: Vec<u8>,
    mask_key: u64,
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
        let mask_key = next_key();
        let masked_data = Self::xor_data(&serialized, mask_key);
        serialized.zeroize();

        Self {
            masked_data,
            mask_key,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Unmask and deserialize the stored value.
    ///
    /// Returns `None` if deserialization fails (e.g. data was corrupted or the
    /// obfuscation key was lost). Callers should treat `None` as a tamper signal.
    pub fn reveal(&self) -> Option<T> {
        let mut unmasked = Self::xor_data(&self.masked_data, self.mask_key);

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
