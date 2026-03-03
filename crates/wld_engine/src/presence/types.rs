// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
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
    pub verification_rate: f64,
}

impl Session {
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec_pretty(self).map_err(|e| e.to_string())
    }

    pub fn decode(data: &[u8]) -> Result<Session, String> {
        serde_json::from_slice(data).map_err(|e| e.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    pub id: String,
    pub challenge_type: ChallengeType,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub window: Duration,
    pub prompt: String,
    pub expected_hash: String,
    pub responded_at: Option<DateTime<Utc>>,
    pub response_hash: Option<String>,
    pub status: ChallengeStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeType {
    TypePhrase,
    SimpleMath,
    TypeWord,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Pending,
    Passed,
    Failed,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub challenge_interval: Duration,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub sessions: Vec<Session>,
    pub total_duration: Duration,
    pub total_challenges: i32,
    pub total_passed: i32,
    pub overall_rate: f64,
}
