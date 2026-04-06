// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use std::ops::Deref;
use zeroize::{Zeroize, Zeroizing};
use crate::utils::mlock::{mlock, munlock};

pub struct ProtectedKey<const N: usize>(Zeroizing<[u8; N]>);

impl<const N: usize> ProtectedKey<N> {
    pub fn new(mut bytes: [u8; N]) -> Self {
        let key = Self(Zeroizing::new(bytes));
        mlock(key.0.as_ptr(), N);
        bytes.zeroize();
        key
    }

    pub fn from_zeroizing(z: Zeroizing<[u8; N]>) -> Self {
        let key = Self(z);
        mlock(key.0.as_ptr(), N);
        key
    }

    pub fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> std::fmt::Debug for ProtectedKey<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[PROTECTED KEY]")
    }
}

impl<const N: usize> Drop for ProtectedKey<N> {
    fn drop(&mut self) {
        munlock(self.0.as_ptr(), N);
    }
}

impl<const N: usize> Deref for ProtectedKey<N> {
    type Target = [u8; N];
    fn deref(&self) -> &Self::Target { &self.0 }
}

pub struct ProtectedBuf(Zeroizing<Vec<u8>>);

impl ProtectedBuf {
    pub fn new(bytes: Vec<u8>) -> Self {
        let buf = Self(Zeroizing::new(bytes));
        mlock(buf.0.as_ptr(), buf.0.len());
        buf
    }
}

impl Deref for ProtectedBuf {
    type Target = [u8];
    fn deref(&self) -> &Self::Target { &self.0 }
}

impl ProtectedBuf {
    pub fn as_slice(&self) -> &[u8] { &self.0 }
}

impl Drop for ProtectedBuf {
    fn drop(&mut self) {
        munlock(self.0.as_ptr(), self.0.len());
    }
}
