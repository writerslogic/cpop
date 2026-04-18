// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Zone-committed jitter engine for real-time keystroke monitoring.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use zeroize::Zeroize;

use super::content::compute_jitter_sample_hash;
use super::profile::interval_to_bucket;
use super::zones::keycode_to_zone;
use super::zones::{encode_zone_transition, ZoneTransition};

/// Zone-committed jitter sample captured during real-time keystroke monitoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JitterSample {
    /// Monotonic sequence number within the session.
    pub ordinal: u64,
    /// Wall-clock time of the keystroke.
    pub timestamp: DateTime<Utc>,
    /// SHA-256 hash of the document at capture time.
    pub doc_hash: [u8; 32],
    /// Encoded zone transition (from << 3 | to), or 0xFF if none.
    pub zone_transition: u8,
    /// Keystroke interval bucket index (0..9).
    pub interval_bucket: u8,
    /// HMAC-derived jitter delay in microseconds.
    pub jitter_micros: u32,
    /// CPU counter measurement for clock skew evidence.
    pub clock_skew: u64,
    /// SHA-256 hash binding all sample fields.
    pub sample_hash: [u8; 32],
}

/// Accumulated typing behavior profile from zone transition statistics.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct TypingProfile {
    /// Histogram of same-finger transitions by interval bucket.
    pub same_finger_hist: [u32; 10],
    /// Histogram of same-hand (different finger) transitions by interval bucket.
    pub same_hand_hist: [u32; 10],
    /// Histogram of hand-alternating transitions by interval bucket.
    pub alternating_hist: [u32; 10],
    /// Ratio of alternating transitions to total transitions.
    pub hand_alternation: f32,
    /// Total number of zone transitions recorded.
    pub total_transitions: u64,
    #[serde(skip)]
    pub(crate) alternating_count: u64,
}

/// Real-time zone-committed jitter engine for keystroke monitoring sessions.
#[derive(Debug)]
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
    /// Create a new jitter engine seeded with the given 32-byte secret.
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

    /// Process a keystroke event, returning the jitter delay and an optional sample.
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

    /// Return the accumulated typing profile.
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
