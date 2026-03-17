// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::time::Duration;

const INTERVAL_BUCKET_SIZE_MS: i64 = 50;
const NUM_INTERVAL_BUCKETS: i64 = 10;

/// Map a duration to a 50ms-wide histogram bucket index (0-9).
pub fn interval_to_bucket(duration: Duration) -> u8 {
    let ms = duration.as_millis() as i64;
    let mut bucket = ms / INTERVAL_BUCKET_SIZE_MS;
    if bucket >= NUM_INTERVAL_BUCKETS {
        bucket = NUM_INTERVAL_BUCKETS - 1;
    }
    if bucket < 0 {
        bucket = 0;
    }
    bucket as u8
}
