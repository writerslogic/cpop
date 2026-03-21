// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiWarReportResult {
    pub success: bool,
    pub report: Option<FfiWarReport>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiWarReport {
    pub report_id: String,
    pub algorithm_version: String,
    pub generated_at_epoch_ms: i64,
    pub schema_version: String,
    pub score: u32,
    pub verdict: String,
    pub verdict_description: String,
    pub likelihood_ratio: f64,
    pub enfsi_tier: String,
    pub document_hash: String,
    pub signing_key_fingerprint: String,
    pub document_chars: Option<u64>,
    pub evidence_bundle_version: String,
    pub session_count: u32,
    pub total_duration_min: f64,
    pub revision_events: u64,
    pub device_attestation: String,
    pub blockchain_anchor: Option<String>,
    pub checkpoints: Vec<FfiReportCheckpoint>,
    pub sessions: Vec<FfiReportSession>,
    pub process: FfiProcessEvidence,
    pub flags: Vec<FfiReportFlag>,
    pub forgery: FfiForgeryInfo,
    pub dimensions: Vec<FfiDimensionScore>,
    pub limitations: Vec<String>,
    pub guilloche_seed_hex: String,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiReportCheckpoint {
    pub ordinal: u64,
    pub timestamp_epoch_ms: i64,
    pub content_hash: String,
    pub content_size: u64,
    pub vdf_iterations: Option<u64>,
    pub elapsed_ms: Option<u64>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiReportSession {
    pub index: u32,
    pub start_epoch_ms: i64,
    pub duration_min: f64,
    pub event_count: u32,
    pub words_drafted: Option<u64>,
    pub device: Option<String>,
    pub summary: String,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiProcessEvidence {
    pub paste_operations: Option<u64>,
    pub swf_checkpoints: Option<u64>,
    pub swf_avg_compute_ms: Option<u64>,
    pub swf_chain_verified: bool,
    pub swf_backdating_hours: Option<f64>,
    pub revision_intensity: Option<f64>,
    pub pause_median_sec: Option<f64>,
    pub pause_p95_sec: Option<f64>,
    pub paste_ratio_pct: Option<f64>,
    pub iki_cv: Option<f64>,
    pub total_keystrokes: Option<u64>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiReportFlag {
    pub category: String,
    pub flag: String,
    pub detail: String,
    pub signal: String,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiForgeryInfo {
    pub tier: String,
    pub estimated_forge_time_sec: f64,
    pub weakest_link: Option<String>,
    pub components: Vec<FfiForgeryComponent>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiForgeryComponent {
    pub name: String,
    pub present: bool,
    pub cost_cpu_sec: f64,
    pub explanation: String,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiDimensionScore {
    pub name: String,
    pub score: u32,
    pub lr: f64,
    pub confidence: f64,
    pub key_discriminator: String,
    pub color: String,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiHtmlResult {
    pub success: bool,
    pub html: Option<String>,
    pub error_message: Option<String>,
}
