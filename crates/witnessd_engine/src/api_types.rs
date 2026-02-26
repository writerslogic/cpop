// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use serde::{Deserialize, Serialize};
use typeshare::typeshare;

#[typeshare]
#[derive(Debug, Serialize, Deserialize)]
pub struct StatusResponse {
    pub version: String,
    pub data_dir: String,
    pub sentinel_active: bool,
    pub tracked_files: Vec<TrackedFile>,
    pub total_checkpoints: u32,
    pub total_keystrokes: u32,
    pub identity_fingerprint: Option<String>,
    pub today_checkpoints: u32,
    pub current_streak: u32,
    pub longest_streak: u32,
    pub words_witnessed: u32,
    pub vdf_iterations_per_second: u32,
    pub tpm_available: bool,
    pub tpm_info: String,
}

#[typeshare]
#[derive(Debug, Serialize, Deserialize)]
pub struct TrackedFile {
    pub path: String,
    pub name: String,
    pub checkpoints: u32,
    pub last_checkpoint: String, // ISO 8601
}

#[typeshare]
#[derive(Debug, Serialize, Deserialize)]
pub struct MetricsResponse {
    pub current_streak: u32,
    pub longest_streak: u32,
    pub words_witnessed: u32,
    pub session_duration_minutes: u32,
    pub evidence_strength: u32,
    pub daily_goal_progress: u32,
    pub daily_goal_target: u32,
    pub today_checkpoints: u32,
    pub cadence_data: Vec<CadencePoint>,
}

#[typeshare]
#[derive(Debug, Serialize, Deserialize)]
pub struct CadencePoint {
    pub timestamp: String,
    pub intensity: f64,
}

#[typeshare]
#[derive(Debug, Serialize, Deserialize)]
pub struct ActivityResponse {
    pub weeks: Vec<WeekData>,
}

#[typeshare]
#[derive(Debug, Serialize, Deserialize)]
pub struct WeekData {
    pub days: Vec<DayData>,
}

#[typeshare]
#[derive(Debug, Serialize, Deserialize)]
pub struct DayData {
    pub date: String,
    pub checkpoints: u32,
    pub intensity: u32,
}

#[typeshare]
#[derive(Debug, Serialize, Deserialize)]
pub struct ForensicsResponse {
    pub assessment_score: f64,
    pub perplexity_score: f64,
    pub risk_level: String,
    pub anomaly_count: u32,
    pub primary: PrimaryMetrics,
}

#[typeshare]
#[derive(Debug, Serialize, Deserialize)]
pub struct PrimaryMetrics {
    pub monotonic_append_ratio: f64,
    pub edit_entropy: f64,
    pub median_interval: f64,
}
