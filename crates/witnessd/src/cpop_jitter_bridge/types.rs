// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::cpop_jitter_bridge::zone_engine::ZoneTrackingEngine;
use crate::jitter::{Parameters, Statistics, TypingProfile};
use crate::DateTimeNanosExt;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Extended sample combining cpop_jitter evidence with zone tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridSample {
    pub timestamp: DateTime<Utc>,
    pub keystroke_count: u64,
    pub document_hash: [u8; 32],
    pub jitter_micros: u32,
    pub zone_transition: u8,
    pub hash: [u8; 32],
    pub previous_hash: [u8; 32],
    pub is_phys: bool,
    /// Session ID bound into the hash preimage to prevent cross-session transplant.
    #[serde(default)]
    pub session_id: Arc<str>,
}

impl HybridSample {
    /// Compute the SHA-256 hash of this sample's fields for chain integrity.
    /// Includes the session_id in the preimage to prevent cross-session transplant.
    pub fn compute_hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"witnessd-hybrid-sample-v2");
        hasher.update(self.session_id.as_bytes());
        hasher.update(self.timestamp.timestamp_nanos_safe().to_be_bytes());
        hasher.update(self.keystroke_count.to_be_bytes());
        hasher.update(self.document_hash);
        hasher.update(self.jitter_micros.to_be_bytes());
        hasher.update([self.zone_transition]);
        hasher.update([if self.is_phys { 1 } else { 0 }]);
        hasher.update(self.previous_hash);
        hasher.finalize().into()
    }
}

/// Quality metrics for entropy used in the session.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct EntropyQuality {
    pub phys_ratio: f64,
    pub total_samples: usize,
    pub phys_samples: usize,
    pub pure_samples: usize,
}

/// Serializable session data for persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct HybridSessionData {
    pub id: String,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub document_path: String,
    pub params: Parameters,
    pub samples: Vec<HybridSample>,
    pub keystroke_count: u64,
    pub last_jitter: u32,
    pub zone_engine: ZoneTrackingEngine,
    pub cpop_jitter_evidence: Option<String>,
}

/// Extended evidence format including jitter metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridEvidence {
    pub session_id: String,
    pub started_at: DateTime<Utc>,
    pub ended_at: DateTime<Utc>,
    pub document_path: String,
    pub params: Parameters,
    pub samples: Vec<HybridSample>,
    pub statistics: Statistics,
    pub entropy_quality: EntropyQuality,
    pub typing_profile: TypingProfile,
    pub cpop_jitter_evidence: Option<String>,
}
