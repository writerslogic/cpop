// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

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
pub const WLD_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Anonymized jitter sample -- timing data only, no document/user info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymizedSample {
    /// Seconds elapsed since the session start.
    pub relative_time_secs: f64,
    /// Inter-keystroke jitter in microseconds.
    pub jitter_micros: u32,
    /// Monotonic keystroke ordinal within the session.
    pub keystroke_ordinal: u64,
    /// Whether the document content changed at this sample.
    pub document_changed: bool,
}

/// Anonymized session data for research contribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymizedSession {
    /// Unique random identifier for this research session.
    pub research_id: String,
    /// Timestamp when the data was collected (rounded to hour).
    pub collected_at: DateTime<Utc>,
    /// Coarse hardware classification.
    pub hardware_class: HardwareClass,
    /// Operating system type.
    pub os_type: OsType,
    /// Anonymized jitter samples.
    pub samples: Vec<AnonymizedSample>,
    /// Aggregate statistics for this session.
    pub statistics: AnonymizedStatistics,
}

/// Coarse-grained hardware class (bucketed for privacy).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareClass {
    /// CPU architecture (e.g. "aarch64", "x86_64").
    pub arch: String,
    /// Bucketed core count range (e.g. "4-8").
    pub core_bucket: String,
    /// Bucketed memory range (e.g. "8-16GB").
    pub memory_bucket: String,
}

/// Operating system family for research bucketing.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OsType {
    /// Apple macOS.
    MacOS,
    /// Linux distributions.
    Linux,
    /// Microsoft Windows.
    Windows,
    /// Unrecognized or unsupported OS.
    Other,
}

/// Bucketed statistics for research (no raw identifiers).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymizedStatistics {
    /// Number of jitter samples in the session.
    pub total_samples: usize,
    /// Bucketed session duration (e.g. "30-60min").
    pub duration_bucket: String,
    /// Bucketed typing rate (e.g. "40-60wpm").
    pub typing_rate_bucket: String,
    /// Mean inter-keystroke jitter in microseconds.
    pub mean_jitter_micros: f64,
    /// Standard deviation of jitter in microseconds.
    pub jitter_std_dev: f64,
    /// Minimum observed jitter in microseconds.
    pub min_jitter_micros: u32,
    /// Maximum observed jitter in microseconds.
    pub max_jitter_micros: u32,
    /// Ratio of physical to virtual entropy sources, if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phys_ratio: Option<f64>,
    /// Description of the entropy source used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entropy_source: Option<String>,
}

/// Serializable export envelope for research data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchDataExport {
    /// Export format version.
    pub version: u32,
    /// When the export was created.
    pub exported_at: DateTime<Utc>,
    /// Whether the user confirmed research consent.
    pub consent_confirmed: bool,
    /// Anonymized sessions included in this export.
    pub sessions: Vec<AnonymizedSession>,
}

/// Result of a research data upload attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadResult {
    /// Number of sessions accepted by the server.
    pub sessions_uploaded: usize,
    /// Total samples accepted across all sessions.
    pub samples_uploaded: usize,
    /// Server response message.
    pub message: String,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct UploadResponse {
    pub(super) uploaded: usize,
    pub(super) samples: usize,
    pub(super) message: String,
}
