// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const RESEARCH_UPLOAD_URL: &str =
    "https://aswcfxodrgcnjbwrcjrl.supabase.co/functions/v1/research-upload";

pub const MIN_SESSIONS_FOR_UPLOAD: usize = 5;

pub const DEFAULT_UPLOAD_INTERVAL_SECS: u64 = 4 * 60 * 60;

pub const WLD_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Anonymized jitter sample -- timing data only, no document/user info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymizedSample {
    pub relative_time_secs: f64,
    pub jitter_micros: u32,
    pub keystroke_ordinal: u64,
    pub document_changed: bool,
}

/// Anonymized session data for research contribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymizedSession {
    pub research_id: String,
    pub collected_at: DateTime<Utc>,
    pub hardware_class: HardwareClass,
    pub os_type: OsType,
    pub samples: Vec<AnonymizedSample>,
    pub statistics: AnonymizedStatistics,
}

/// Coarse-grained hardware class (bucketed for privacy).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareClass {
    pub arch: String,
    pub core_bucket: String,
    pub memory_bucket: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OsType {
    MacOS,
    Linux,
    Windows,
    Other,
}

/// Bucketed statistics for research (no raw identifiers).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymizedStatistics {
    pub total_samples: usize,
    pub duration_bucket: String,
    pub typing_rate_bucket: String,
    pub mean_jitter_micros: f64,
    pub jitter_std_dev: f64,
    pub min_jitter_micros: u32,
    pub max_jitter_micros: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phys_ratio: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entropy_source: Option<String>,
}

/// Serializable export envelope for research data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchDataExport {
    pub version: u32,
    pub exported_at: DateTime<Utc>,
    pub consent_confirmed: bool,
    pub sessions: Vec<AnonymizedSession>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadResult {
    pub sessions_uploaded: usize,
    pub samples_uploaded: usize,
    pub message: String,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct UploadResponse {
    pub(super) uploaded: usize,
    pub(super) samples: usize,
    pub(super) message: String,
}
