// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Memory-hardened wrappers for key material: zeroize-on-drop with
//! optional `mlock` to prevent swap exposure.

use std::ops::Deref;
use zeroize::{Zeroize, Zeroizing};

#[cfg(unix)]
use libc::{mlock, munlock};

/// Fixed-size key buffer: zeroized on drop, `mlock`ed on Unix.
///
/// Clone is implemented manually to ensure the cloned copy is also mlocked.
/// The derived Clone would copy raw bytes without calling `lock_memory`.
pub struct ProtectedKey<const N: usize>([u8; N]);

impl<const N: usize> Clone for ProtectedKey<N> {
    fn clone(&self) -> Self {
        // Use new() to ensure the cloned copy is mlocked
        ProtectedKey::new(self.0)
    }
}

impl<const N: usize> ProtectedKey<N> {
    /// Wrap raw bytes, `mlock` the buffer, then zeroize the local parameter copy.
    ///
    /// **Warning**: This zeroizes the parameter copy but the caller's original
    /// variable may still hold key material on the stack. Prefer
    /// [`from_zeroizing`](Self::from_zeroizing) which guarantees the caller's
    /// copy is zeroized on drop.
    pub fn new(mut bytes: [u8; N]) -> Self {
        let mut key = Self(bytes);
        key.lock_memory();
        bytes.zeroize();
        key
    }

    /// Create a ProtectedKey from a `Zeroizing` wrapper, ensuring the caller's
    /// copy is automatically zeroized when the wrapper drops.
    pub fn from_zeroizing(bytes: Zeroizing<[u8; N]>) -> Self {
        let mut key = Self(*bytes);
        key.lock_memory();
        // `bytes` drops here; Zeroizing::drop zeroizes the caller's copy.
        key
    }

    /// Borrow the underlying key bytes.
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }

    fn lock_memory(&mut self) {
        #[cfg(unix)]
        unsafe {
            if mlock(self.0.as_ptr() as *const libc::c_void, N) != 0 {
                log::warn!("mlock failed: {}", std::io::Error::last_os_error());
            }
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

impl<const N: usize> From<Zeroizing<[u8; N]>> for ProtectedKey<N> {
    fn from(bytes: Zeroizing<[u8; N]>) -> Self {
        Self::from_zeroizing(bytes)
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

/// Variable-length sensitive buffer, zeroized on drop with `mlock` on Unix.
pub struct ProtectedBuf(Vec<u8>);

impl Clone for ProtectedBuf {
    fn clone(&self) -> Self {
        let mut buf = Self(self.0.clone());
        buf.lock_memory();
        buf
    }
}

impl ProtectedBuf {
    /// Move bytes into a protected buffer, mlock it, and zeroize the source.
    pub fn new(mut bytes: Vec<u8>) -> Self {
        let taken = std::mem::take(&mut bytes);
        bytes.zeroize();
        let mut buf = Self(taken);
        buf.lock_memory();
        buf
    }

    /// Borrow the underlying buffer bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    fn lock_memory(&mut self) {
        #[cfg(unix)]
        if !self.0.is_empty() {
            unsafe {
                if mlock(self.0.as_ptr() as *const libc::c_void, self.0.len()) != 0 {
                    log::warn!(
                        "mlock failed for ProtectedBuf: {}",
                        std::io::Error::last_os_error()
                    );
                }
            }
        }
    }

    fn unlock_memory(&mut self) {
        #[cfg(unix)]
        if !self.0.is_empty() {
            unsafe {
                let _ = munlock(self.0.as_ptr() as *const libc::c_void, self.0.len());
            }
        }
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
        self.unlock_memory();
    }
}

impl std::fmt::Debug for ProtectedBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ProtectedBuf<{} bytes>([REDACTED])", self.0.len())
    }
}
