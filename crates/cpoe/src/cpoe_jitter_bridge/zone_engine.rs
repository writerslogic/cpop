// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::cpoe_jitter_bridge::helpers::interval_to_bucket;
use crate::jitter::{encode_zone_transition, keycode_to_zone, TypingProfile, ZoneTransition};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Track keyboard zone transitions and build a typing profile histogram.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneTrackingEngine {
    pub(crate) prev_zone: i32,
    pub(crate) profile: TypingProfile,
    pub(crate) prev_time: DateTime<Utc>,
}

impl Default for ZoneTrackingEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ZoneTrackingEngine {
    pub fn new() -> Self {
        Self {
            prev_zone: -1,
            profile: TypingProfile::default(),
            prev_time: Utc::now(),
        }
    }

    pub fn record_keycode(&mut self, keycode: u16) -> u8 {
        let zone = keycode_to_zone(keycode);
        self.record_zone(zone)
    }

    pub fn record_zone(&mut self, zone: i32) -> u8 {
        if zone < 0 {
            return 0xFF;
        }

        let now = Utc::now();
        let zone_transition = if self.prev_zone >= 0 {
            let encoded = encode_zone_transition(self.prev_zone, zone);
            let interval = now.signed_duration_since(self.prev_time);
            if interval.num_nanoseconds().unwrap_or(-1) < 0 {
                return 0xFF;
            }
            let bucket = interval_to_bucket(interval.to_std().unwrap_or(Duration::from_secs(0)));
            self.update_profile(self.prev_zone, zone, bucket);
            encoded
        } else {
            0xFF
        };

        self.prev_zone = zone;
        self.prev_time = now;
        zone_transition
    }

    pub fn profile(&self) -> &TypingProfile {
        &self.profile
    }

    pub fn prev_zone(&self) -> i32 {
        self.prev_zone
    }

    fn update_profile(&mut self, from_zone: i32, to_zone: i32, bucket: u8) {
        let idx = bucket as usize;
        if idx >= self.profile.same_finger_hist.len() {
            return;
        }
        let trans = ZoneTransition {
            from: from_zone,
            to: to_zone,
        };
        if trans.is_same_finger() {
            self.profile.same_finger_hist[idx] =
                self.profile.same_finger_hist[idx].saturating_add(1);
        } else if trans.is_same_hand() {
            self.profile.same_hand_hist[idx] = self.profile.same_hand_hist[idx].saturating_add(1);
        } else {
            self.profile.alternating_hist[idx] =
                self.profile.alternating_hist[idx].saturating_add(1);
        }

        self.profile.total_transitions += 1;
        if self.profile.total_transitions > 0 {
            let alternating_count: u64 = self
                .profile
                .alternating_hist
                .iter()
                .map(|&x| x as u64)
                .sum();
            self.profile.hand_alternation =
                alternating_count as f32 / self.profile.total_transitions as f32;
        }
    }
}
