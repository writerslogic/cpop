// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Shared memory locking utilities.

/// Lock the given memory range into physical memory to prevent it from being swapped.
pub fn mlock(ptr: *const u8, len: usize) {
    #[cfg(unix)]
    unsafe {
        let result = libc::mlock(ptr as *const _, len);
        if result != 0 {
            log::warn!("mlock failed: {}", std::io::Error::last_os_error());
        }
    }
    #[cfg(not(unix))]
    let _ = (ptr, len);
}

/// Unlock a previously locked memory range.
pub fn munlock(ptr: *const u8, len: usize) {
    #[cfg(unix)]
    unsafe {
        let _ = libc::munlock(ptr as *const _, len);
    }
    #[cfg(not(unix))]
    let _ = (ptr, len);
}
