//! Memory-resident data obfuscation to defeat casual memory scraping.
//! NOT cryptographically secure—designed to raise the bar, not provide guarantees.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use zeroize::Zeroize;

/// Rolling XOR key that changes every N accesses
static ROLLING_KEY: AtomicU64 = AtomicU64::new(0xDEADBEEF_CAFEBABE);

fn next_key() -> u64 {
    // Simple LFSR-style rotation
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

// Any type that can be serialized/deserialized can be obfuscated
impl<T: Serialize + for<'de> Deserialize<'de>> Obfuscated<T> {
    pub fn new(value: &T) -> Self {
        let serialized = bincode::serde::encode_to_vec(value, bincode::config::standard())
            .expect("serialization failed");
        let mask_key = next_key();

        // XOR mask the data
        Self {
            masked_data: Self::xor_data(&serialized, mask_key),
            mask_key,
            _phantom: std::marker::PhantomData,
        }
    }

    pub fn reveal(&self) -> T {
        let mut unmasked = Self::xor_data(&self.masked_data, self.mask_key);

        let (value, _): (T, usize) =
            bincode::serde::decode_from_slice(&unmasked, bincode::config::standard())
                .expect("deserialization failed");

        // Zeroize temporary buffer
        unmasked.zeroize();

        value
    }

    fn xor_data(data: &[u8], key: u64) -> Vec<u8> {
        let mut out = data.to_vec();
        for (i, byte) in out.iter_mut().enumerate() {
            let key_byte = ((key >> ((i % 8) * 8)) & 0xFF) as u8;
            *byte ^= key_byte;
        }
        out
    }

    /// Re-mask with a new key (call periodically to frustrate memory snapshots)
    pub fn rotate(&mut self) {
        let value = self.reveal();
        *self = Self::new(&value);
    }
}

impl<T> Drop for Obfuscated<T> {
    fn drop(&mut self) {
        self.masked_data.zeroize();
    }
}

// Debug implementation that doesn't reveal
impl<T> std::fmt::Debug for Obfuscated<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "***OBFUSCATED***")
    }
}

// Default implementation
impl<T: Default + Serialize + for<'de> Deserialize<'de>> Default for Obfuscated<T> {
    fn default() -> Self {
        Self::new(&T::default())
    }
}
