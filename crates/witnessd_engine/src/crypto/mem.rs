// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Memory-hardened storage for sensitive cryptographic material.
//!
//! Provides wrappers that ensure sensitive keys are zeroized on drop and,
//! where supported by the OS, locked in physical RAM to prevent swapping to disk.

use std::ops::Deref;
use zeroize::Zeroize;

#[cfg(unix)]
use libc::{mlock, munlock};

/// A wrapper for sensitive byte arrays that ensures zeroization on drop
/// and locks memory in RAM to prevent swapping to disk.
#[derive(Clone)]
pub struct ProtectedKey<const N: usize>([u8; N]);

impl<const N: usize> ProtectedKey<N> {
    /// Create a new protected key from raw bytes.
    pub fn new(mut bytes: [u8; N]) -> Self {
        let mut key = Self(bytes);
        key.lock_memory();
        bytes.zeroize();
        key
    }

    /// Access the underlying key bytes.
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }

    fn lock_memory(&mut self) {
        #[cfg(unix)]
        unsafe {
            // Attempt to lock the memory. If it fails (e.g. limit reached),
            // we proceed with just Zeroize protection.
            let _ = mlock(self.0.as_ptr() as *const libc::c_void, N);
        }
    }

    fn unlock_memory(&mut self) {
        #[cfg(unix)]
        unsafe {
            let _ = munlock(self.0.as_ptr() as *const libc::c_void, N);
        }
    }
}

impl<const N: usize> From<[u8; N]> for ProtectedKey<N> {
    fn from(bytes: [u8; N]) -> Self {
        Self::new(bytes)
    }
}

impl<const N: usize> Deref for ProtectedKey<N> {
    type Target = [u8; N];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> Drop for ProtectedKey<N> {
    fn drop(&mut self) {
        self.0.zeroize();
        self.unlock_memory();
    }
}

impl<const N: usize> std::fmt::Debug for ProtectedKey<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ProtectedKey<{} bytes>([REDACTED])", N)
    }
}

/// A wrapper for variable-length sensitive data.
#[derive(Clone)]
pub struct ProtectedBuf(Vec<u8>);

impl ProtectedBuf {
    /// Create a new protected buffer from a Vec.
    pub fn new(mut bytes: Vec<u8>) -> Self {
        let buf = Self(bytes.clone());
        bytes.zeroize();
        buf
    }

    /// Access the underlying buffer bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for ProtectedBuf {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl Deref for ProtectedBuf {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for ProtectedBuf {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for ProtectedBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ProtectedBuf<{} bytes>([REDACTED])", self.0.len())
    }
}
