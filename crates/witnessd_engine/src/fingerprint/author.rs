// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::fingerprint::activity::ActivityFingerprint;
use crate::fingerprint::voice::VoiceFingerprint;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Unique identifier for a fingerprint profile.
pub type ProfileId = String;

/// Combined author fingerprint with both activity and optional voice data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorFingerprint {
    pub id: ProfileId,
    pub name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub activity: ActivityFingerprint,
    pub voice: Option<VoiceFingerprint>,
    pub sample_count: u64,
    pub confidence: f64,
}

impl AuthorFingerprint {
    pub fn new(activity: ActivityFingerprint) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            activity,
            voice: None,
            sample_count: 0,
            confidence: 0.0,
        }
    }

    pub fn with_id(id: ProfileId, activity: ActivityFingerprint) -> Self {
        Self {
            id,
            name: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            activity,
            voice: None,
            sample_count: 0,
            confidence: 0.0,
        }
    }

    pub fn with_voice(mut self, voice: VoiceFingerprint) -> Self {
        self.voice = Some(voice);
        self
    }

    pub fn update_confidence(&mut self) {
        self.confidence = 1.0 - 1.0 / (1.0 + self.sample_count as f64 / 100.0);
    }

    pub fn merge(&mut self, other: &AuthorFingerprint) {
        self.activity.merge(&other.activity);
        if let Some(other_voice) = &other.voice {
            if let Some(ref mut voice) = self.voice {
                voice.merge(other_voice);
            } else {
                self.voice = Some(other_voice.clone());
            }
        }
        self.sample_count += other.sample_count;
        self.updated_at = Utc::now();
        self.update_confidence();
    }
}
