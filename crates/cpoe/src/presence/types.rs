// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Active or completed presence verification session with challenge history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Hex-encoded random identifier.
    pub id: String,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub active: bool,
    pub challenges: Vec<Challenge>,
    pub checkpoint_ordinals: Vec<u64>,
    pub challenges_issued: i32,
    pub challenges_passed: i32,
    pub challenges_failed: i32,
    pub challenges_missed: i32,
    /// Ratio of passed to issued (0.0..1.0).
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
    /// Hex-encoded random identifier.
    pub id: String,
    pub challenge_type: ChallengeType,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub window: Duration,
    pub prompt: String,
    /// HMAC-SHA256 hash of the expected correct answer.
    pub expected_hash: String,
    pub responded_at: Option<DateTime<Utc>>,
    /// HMAC-SHA256 hash of the user's actual response.
    pub response_hash: Option<String>,
    pub status: ChallengeStatus,
}

/// Kind of presence challenge presented to the user.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeType {
    TypePhrase,
    SimpleMath,
    TypeWord,
}

/// Resolution status of a presence challenge.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Pending,
    Passed,
    Failed,
    Expired,
}

/// Configuration for presence verification timing and challenge types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub challenge_interval: Duration,
    /// Fractional variance applied to the interval (0.0..1.0).
    pub interval_variance: f64,
    pub response_window: Duration,
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
    pub sessions: Vec<Session>,
    /// Combined active duration across all sessions.
    pub total_duration: Duration,
    pub total_challenges: i32,
    pub total_passed: i32,
    /// 0.0..1.0
    pub overall_rate: f64,
}
