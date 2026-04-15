// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Traits for safe lock recovery on poison.

/// Poison-recovering lock access for `RwLock`.
pub(crate) trait RwLockRecover<T> {
    fn read_recover(&self) -> std::sync::RwLockReadGuard<'_, T>;
    fn write_recover(&self) -> std::sync::RwLockWriteGuard<'_, T>;
}

impl<T> RwLockRecover<T> for std::sync::RwLock<T> {
    fn read_recover(&self) -> std::sync::RwLockReadGuard<'_, T> {
        self.read().unwrap_or_else(|p| {
            log::error!("RwLock poisoned; recovering with potentially inconsistent data");
            p.into_inner()
        })
    }
    fn write_recover(&self) -> std::sync::RwLockWriteGuard<'_, T> {
        self.write().unwrap_or_else(|p| {
            log::error!("RwLock poisoned; recovering with potentially inconsistent data");
            p.into_inner()
        })
    }
}

/// Poison-recovering lock access for `Mutex`.
pub(crate) trait MutexRecover<T> {
    fn lock_recover(&self) -> std::sync::MutexGuard<'_, T>;
}

impl<T> MutexRecover<T> for std::sync::Mutex<T> {
    fn lock_recover(&self) -> std::sync::MutexGuard<'_, T> {
        self.lock().unwrap_or_else(|p| {
            log::error!("Mutex poisoned; recovering with potentially inconsistent data");
            p.into_inner()
        })
    }
}
