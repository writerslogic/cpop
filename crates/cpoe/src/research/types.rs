// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Endpoint URL for anonymized research data uploads.
pub const RESEARCH_UPLOAD_URL: &str =
    "https://aswcfxodrgcnjbwrcjrl.supabase.co/functions/v1/research-upload";

/// Minimum accumulated sessions before an upload is attempted.
pub const MIN_SESSIONS_FOR_UPLOAD: usize = 5;

/// Default interval between automatic upload attempts (4 hours).
pub const DEFAULT_UPLOAD_INTERVAL_SECS: u64 = 4 * 60 * 60;

/// Engine version string embedded at build time.
pub const CPOE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Anonymized jitter sample -- timing data only, no document/user info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymizedSample {
    /// Seconds elapsed since session start.
    pub relative_time_secs: f64,
    /// Inter-keystroke jitter in microseconds.
    pub jitter_micros: u32,
    /// Monotonic ordinal within the session.
    pub keystroke_ordinal: u64,
    pub document_changed: bool,
}

/// Anonymized session data for research contribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymizedSession {
    pub research_id: String,
    /// Rounded to hour for privacy.
    pub collected_at: DateTime<Utc>,
    pub hardware_class: HardwareClass,
    pub os_type: OsType,
    pub samples: Vec<AnonymizedSample>,
    pub statistics: AnonymizedStatistics,
}

/// Coarse-grained hardware class (bucketed for privacy).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareClass {
    /// e.g. "aarch64", "x86_64"
    pub arch: String,
    /// Bucketed range, e.g. "4-8"
    pub core_bucket: String,
    /// Bucketed range, e.g. "8-16GB"
    pub memory_bucket: String,
}

/// Operating system family for research bucketing.
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
    /// Bucketed, e.g. "30-60min"
    pub duration_bucket: String,
    /// Bucketed, e.g. "40-60wpm"
    pub typing_rate_bucket: String,
    /// Mean inter-keystroke jitter in microseconds.
    pub mean_jitter_micros: f64,
    /// Standard deviation in microseconds.
    pub jitter_std_dev: f64,
    /// In microseconds.
    pub min_jitter_micros: u32,
    /// In microseconds.
    pub max_jitter_micros: u32,
    /// Ratio of physical to virtual entropy sources.
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

/// Result of a research data upload attempt.
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
