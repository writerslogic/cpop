// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Zone-committed jitter engine for real-time keystroke monitoring.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use zeroize::Zeroize;

use super::content::compute_jitter_sample_hash;
use super::profile::interval_to_bucket;
use super::zones::keycode_to_zone;
use super::zones::{encode_zone_transition, ZoneTransition};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JitterSample {
    pub ordinal: u64,
    pub timestamp: DateTime<Utc>,
    pub doc_hash: [u8; 32],
    pub zone_transition: u8,
    pub interval_bucket: u8,
    pub jitter_micros: u32,
    pub clock_skew: u64,
    pub sample_hash: [u8; 32],
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct TypingProfile {
    pub same_finger_hist: [u32; 10],
    pub same_hand_hist: [u32; 10],
    pub alternating_hist: [u32; 10],
    pub hand_alternation: f32,
    pub total_transitions: u64,
    #[serde(skip)]
    pub(super) alternating_count: u64,
}

pub struct JitterEngine {
    secret: [u8; 32],
    ordinal: u64,
    prev_jitter: u32,
    prev_zone: i32,
    prev_time: DateTime<Utc>,
    profile: TypingProfile,
}

impl Drop for JitterEngine {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl JitterEngine {
    pub fn new(secret: [u8; 32]) -> Self {
        Self {
            secret,
            ordinal: 0,
            prev_jitter: 0,
            prev_zone: -1,
            prev_time: Utc::now(),
            profile: TypingProfile::default(),
        }
    }

    pub fn on_keystroke(
        &mut self,
        key_code: u16,
        doc_hash: [u8; 32],
    ) -> (u32, Option<JitterSample>) {
        let now = Utc::now();
        let zone = keycode_to_zone(key_code);
        if zone < 0 {
            return (0, None);
        }

        let mut zone_transition = 0xFF;
        let mut interval_bucket = 0u8;

        if self.prev_zone >= 0 {
            zone_transition = encode_zone_transition(self.prev_zone, zone);
            let interval = now.signed_duration_since(self.prev_time);
            interval_bucket =
                interval_to_bucket(interval.to_std().unwrap_or(Duration::from_secs(0)));
            self.update_profile(self.prev_zone, zone, interval_bucket);
        }

        let jitter = self.compute_jitter(doc_hash, zone_transition, interval_bucket, now);
        let clock_skew = crate::physics::clock::ClockSkew::measure();
        self.ordinal = self.ordinal.saturating_add(1);
        let mut sample = JitterSample {
            ordinal: self.ordinal,
            timestamp: now,
            doc_hash,
            zone_transition,
            interval_bucket,
            jitter_micros: jitter,
            clock_skew,
            sample_hash: [0u8; 32],
        };
        sample.sample_hash = compute_jitter_sample_hash(&sample);

        self.prev_zone = zone;
        self.prev_time = now;
        self.prev_jitter = jitter;

        (jitter, Some(sample))
    }

    pub fn profile(&self) -> TypingProfile {
        self.profile
    }

    fn compute_jitter(
        &self,
        doc_hash: [u8; 32],
        zone_transition: u8,
        interval_bucket: u8,
        timestamp: DateTime<Utc>,
    ) -> u32 {
        super::compute_zone_jitter(
            &self.secret,
            self.ordinal,
            &doc_hash,
            zone_transition,
            interval_bucket,
            timestamp,
            self.prev_jitter,
        )
    }

    fn update_profile(&mut self, from_zone: i32, to_zone: i32, bucket: u8) {
        let bucket = bucket.min(9) as usize;
        let trans = ZoneTransition {
            from: from_zone,
            to: to_zone,
        };
        if trans.is_same_finger() {
            self.profile.same_finger_hist[bucket] =
                self.profile.same_finger_hist[bucket].saturating_add(1);
        } else if trans.is_same_hand() {
            self.profile.same_hand_hist[bucket] =
                self.profile.same_hand_hist[bucket].saturating_add(1);
        } else {
            self.profile.alternating_hist[bucket] =
                self.profile.alternating_hist[bucket].saturating_add(1);
            self.profile.alternating_count = self.profile.alternating_count.saturating_add(1);
        }

        self.profile.total_transitions = self.profile.total_transitions.saturating_add(1);
        // Compute in f64 for precision, then narrow to f32
        let ratio = self.profile.alternating_count as f64 / self.profile.total_transitions as f64;
        self.profile.hand_alternation = ratio as f32;
    }
}
