// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Shared time and timestamp utilities.

use std::time::SystemTime;

/// Return the current system time in nanoseconds since the UNIX epoch.
///
/// If the timestamp exceeds `i64::MAX` (~2262+), it falls back to
/// millisecond-precision nanoseconds via saturating multiplication.
pub fn now_ns() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| {
            let nanos = d.as_nanos();
            if nanos > i64::MAX as u128 {
                (d.as_millis() as i64).saturating_mul(1_000_000)
            } else {
                nanos as i64
            }
        })
        .unwrap_or_else(|_| {
            log::warn!("SystemTime before UNIX_EPOCH in now_ns(); falling back to 0");
            0
        })
}
