// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::crypto::mem::ProtectedKey;
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

/// A wrapper for the sentinel's signing key that is tied to human behavioral entropy.
///
/// The key is "wrapped" in memory using a rolling window of behavioral entropy (jitter).
/// If typing stops for longer than the lock timeout, the rolling entropy is cleared,
/// effectively locking the key until new entropy is accumulated and the key is
/// re-authorized from its permanent storage (e.g., TPM or Keychain).
pub struct BehavioralKey {
    /// The master key bytes, used to derive the actual signing key.
    /// This is kept in mlocked memory.
    master_key: Option<ProtectedKey<32>>,
    /// Current signing key, available only when "hot".
    active_key: Option<SigningKey>,
    /// Rolling behavioral entropy pool.
    entropy_pool: Zeroizing<[u8; 32]>,
    /// Last time activity was recorded.
    last_activity: Instant,
    /// Duration after which the active key is zeroized.
    lock_timeout: Duration,
}

impl BehavioralKey {
    pub fn new(lock_timeout: Duration) -> Self {
        Self {
            master_key: None,
            active_key: None,
            entropy_pool: Zeroizing::new([0u8; 32]),
            last_activity: Instant::now(),
            lock_timeout,
        }
    }

    /// Set the master key and initialize the active key.
    pub fn set_key(&mut self, key: SigningKey) {
        let key_bytes = key.to_bytes();
        self.master_key = Some(ProtectedKey::new(key_bytes));
        self.active_key = Some(key);
        self.last_activity = Instant::now();
    }

    /// Record new behavioral entropy (e.g., nanosecond jitter).
    pub fn add_entropy(&mut self, data: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(&self.entropy_pool[..]);
        hasher.update(data);
        self.entropy_pool.copy_from_slice(&hasher.finalize());
        self.last_activity = Instant::now();

        // If we were locked but have master key, we can try to re-activate.
        // In a real implementation, this might require re-authorizing with the TPM.
        if self.active_key.is_none() {
            if let Some(ref mk) = self.master_key {
                let hk = Hkdf::<Sha256>::new(Some(&self.entropy_pool[..]), mk.as_bytes());
                let mut derived = Zeroizing::new([0u8; 32]);
                // HKDF-SHA256 expand only fails when output length > 255 * 32 bytes.
                // A 32-byte output is unconditionally valid, so this cannot fail.
                hk.expand(b"witnessd-behavioral-entropy-v1", &mut derived[..])
                    .expect("HKDF-SHA256 expand of 32 bytes is infallible");
                self.active_key = Some(SigningKey::from_bytes(&derived));
            }
        }
    }

    /// Access the signing key if it's currently hot.
    pub fn key(&self) -> Option<SigningKey> {
        if self.last_activity.elapsed() > self.lock_timeout {
            return None;
        }
        self.active_key.clone()
    }

    /// Access the signing key and update the lease if it's still valid.
    pub fn get_key(&mut self) -> Option<&SigningKey> {
        if self.last_activity.elapsed() > self.lock_timeout {
            if self.active_key.is_some() {
                log::info!("Behavioral key locked due to inactivity");
                self.active_key = None; // Zeroizes on drop
                self.entropy_pool.zeroize();
            }
            return None;
        }
        self.active_key.as_ref()
    }

    /// Check if the key is currently locked.
    pub fn is_locked(&self) -> bool {
        self.active_key.is_none() || self.last_activity.elapsed() > self.lock_timeout
    }

    /// Clear all key material and entropy.
    pub fn reset(&mut self) {
        self.active_key = None;
        self.master_key = None;
        self.entropy_pool.zeroize();
    }
}
