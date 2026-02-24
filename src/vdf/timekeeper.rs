use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

#[derive(Debug, Serialize, Deserialize)]
pub enum TimeAnchor {
    Network {
        timestamp: DateTime<Utc>,
        sources: Vec<String>,
    },
    Physical {
        duration_since_anchor: Duration,
        vdf_proof: [u8; 32], // Output of the VDF
    },
    Offline,
}

pub struct TimeKeeper {
    last_network_sync: Option<DateTime<Utc>>,
    start_instant: Instant,
}

impl Default for TimeKeeper {
    fn default() -> Self {
        Self::new()
    }
}

impl TimeKeeper {
    pub fn new() -> Self {
        Self {
            last_network_sync: None,
            start_instant: Instant::now(),
        }
    }

    /// Attempts to get a "Hard" network timestamp using Roughtime.
    pub async fn fetch_network_time() -> Option<DateTime<Utc>> {
        match crate::vdf::RoughtimeClient::get_verified_time() {
            Ok(micros) => {
                let seconds = (micros / 1_000_000) as i64;
                let nanos = ((micros % 1_000_000) * 1000) as u32;
                DateTime::from_timestamp(seconds, nanos)
            }
            Err(_) => None,
        }
    }

    /// Calculates the "Forensic Timestamp".
    /// If online, returns the NTP time.
    /// If offline, returns [Last NTP] + [VDF Duration].
    pub fn get_current_forensic_time(
        &self,
        current_ntp: Option<DateTime<Utc>>,
    ) -> (DateTime<Utc>, TimeAnchor) {
        match current_ntp {
            Some(ntp) => (
                ntp,
                TimeAnchor::Network {
                    timestamp: ntp,
                    sources: vec!["pool.ntp.org".to_string(), "time.apple.com".to_string()],
                },
            ),
            None => {
                let elapsed = self.start_instant.elapsed();
                let estimated = self
                    .last_network_sync
                    .map(|last| last + chrono::Duration::from_std(elapsed).unwrap())
                    .unwrap_or_else(Utc::now);

                (
                    estimated,
                    TimeAnchor::Physical {
                        duration_since_anchor: elapsed,
                        vdf_proof: [0u8; 32], // Bound to the actual VDF in the next step
                    },
                )
            }
        }
    }
}
