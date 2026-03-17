// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Simple jitter session (legacy capture used by platform hooks).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::timestamp_nanos_u64;

/// Lightweight jitter sample used by legacy platform hooks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleJitterSample {
    /// Absolute timestamp in nanoseconds since epoch.
    pub timestamp_ns: i64,
    /// Nanoseconds elapsed since the previous sample.
    pub duration_since_last_ns: u64,
    /// QWERTY keyboard zone index for this keystroke.
    pub zone: u8,
}

/// Legacy jitter session that collects simple timestamped samples.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleJitterSession {
    /// UUID session identifier.
    pub id: String,
    /// When this session began.
    pub start_time: DateTime<Utc>,
    /// Collected jitter samples.
    pub samples: Vec<SimpleJitterSample>,
}

impl Default for SimpleJitterSession {
    fn default() -> Self {
        Self::new()
    }
}

impl SimpleJitterSession {
    pub fn new() -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            start_time: Utc::now(),
            samples: Vec::new(),
        }
    }

    /// Append a sample with the given nanosecond timestamp and keyboard zone.
    pub fn add_sample(&mut self, timestamp_ns: i64, zone: u8) {
        let start_nanos = timestamp_nanos_u64(self.start_time);
        let last_ts = self
            .samples
            .last()
            .map(|s| s.timestamp_ns)
            .unwrap_or(i64::try_from(start_nanos).unwrap_or(i64::MAX));
        let duration = timestamp_ns.saturating_sub(last_ts).max(0) as u64;

        self.samples.push(SimpleJitterSample {
            timestamp_ns,
            duration_since_last_ns: duration,
            zone,
        });
    }
}
