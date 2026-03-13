// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Active or completed presence verification session with challenge history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Hex-encoded random session identifier.
    pub id: String,
    /// When the session began.
    pub start_time: DateTime<Utc>,
    /// When the session ended, if finalized.
    pub end_time: Option<DateTime<Utc>>,
    /// Whether the session is still accepting challenges.
    pub active: bool,
    /// Ordered list of challenges issued during this session.
    pub challenges: Vec<Challenge>,
    /// Checkpoint ordinals recorded during this session.
    pub checkpoint_ordinals: Vec<u64>,
    /// Total challenges issued.
    pub challenges_issued: i32,
    /// Challenges answered correctly.
    pub challenges_passed: i32,
    /// Challenges answered incorrectly.
    pub challenges_failed: i32,
    /// Challenges that expired without a response.
    pub challenges_missed: i32,
    /// Ratio of passed to issued challenges (0.0..1.0).
    pub verification_rate: f64,
}

impl Session {
    /// Serialize the session to pretty-printed JSON bytes.
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec_pretty(self).map_err(|e| e.to_string())
    }

    /// Deserialize a session from JSON bytes.
    pub fn decode(data: &[u8]) -> Result<Session, String> {
        serde_json::from_slice(data).map_err(|e| e.to_string())
    }
}

/// Single presence challenge with its expected answer hash and current status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    /// Hex-encoded random challenge identifier.
    pub id: String,
    /// Kind of challenge (phrase, math, word).
    pub challenge_type: ChallengeType,
    /// When the challenge was issued.
    pub issued_at: DateTime<Utc>,
    /// Deadline after which the challenge expires.
    pub expires_at: DateTime<Utc>,
    /// Duration of the response window.
    pub window: Duration,
    /// Human-readable prompt shown to the user.
    pub prompt: String,
    /// HMAC-SHA256 hash of the expected correct answer.
    pub expected_hash: String,
    /// When the user responded, if at all.
    pub responded_at: Option<DateTime<Utc>>,
    /// HMAC-SHA256 hash of the user's actual response.
    pub response_hash: Option<String>,
    /// Current resolution status.
    pub status: ChallengeStatus,
}

/// Kind of presence challenge presented to the user.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeType {
    /// Type a multi-word phrase exactly.
    TypePhrase,
    /// Solve a simple arithmetic problem.
    SimpleMath,
    /// Type a single word exactly.
    TypeWord,
}

/// Resolution status of a presence challenge.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    /// Awaiting user response.
    Pending,
    /// User responded correctly within the time window.
    Passed,
    /// User responded incorrectly.
    Failed,
    /// Response window elapsed without a valid response.
    Expired,
}

/// Configuration for presence verification timing and challenge types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Base interval between consecutive challenges.
    pub challenge_interval: Duration,
    /// Fractional variance applied to the interval (0.0..1.0).
    pub interval_variance: f64,
    /// How long the user has to respond to each challenge.
    pub response_window: Duration,
    /// Which challenge types are active.
    pub enabled_challenges: Vec<ChallengeType>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            challenge_interval: Duration::from_secs(10 * 60),
            interval_variance: 0.5,
            response_window: Duration::from_secs(60),
            enabled_challenges: vec![
                ChallengeType::TypePhrase,
                ChallengeType::SimpleMath,
                ChallengeType::TypeWord,
            ],
        }
    }
}

/// Aggregated presence verification evidence across multiple sessions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// All sessions included in this evidence bundle.
    pub sessions: Vec<Session>,
    /// Combined active duration across all sessions.
    pub total_duration: Duration,
    /// Total challenges issued across all sessions.
    pub total_challenges: i32,
    /// Total challenges passed across all sessions.
    pub total_passed: i32,
    /// Overall pass rate (0.0..1.0).
    pub overall_rate: f64,
}
