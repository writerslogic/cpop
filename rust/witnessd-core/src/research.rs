//! Anonymous research data collection for jitter proof-of-process analysis.
//!
//! This module enables opt-in collection of anonymized jitter timing data
//! to help build datasets for security analysis of the proof-of-process primitive.
//!
//! ## What is collected:
//! - Jitter timing samples (inter-keystroke intervals in microseconds)
//! - Hardware class (CPU architecture, core count range)
//! - OS type (macOS, Linux, Windows)
//! - Sample timestamps (rounded to hour for privacy)
//! - Session statistics (sample count, duration buckets)
//!
//! ## What is NOT collected:
//! - Document content or paths
//! - Actual keystrokes or text
//! - User identity or device identifiers
//! - Exact hardware model or serial numbers
//! - Network information

use chrono::{DateTime, Timelike, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::config::ResearchConfig;
use crate::jitter::{Evidence, Statistics};

/// Default upload endpoint for research data
pub const RESEARCH_UPLOAD_URL: &str =
    "https://aswcfxodrgcnjbwrcjrl.supabase.co/functions/v1/research-upload";

/// Minimum sessions before attempting upload
pub const MIN_SESSIONS_FOR_UPLOAD: usize = 5;

/// Default upload interval (4 hours)
pub const DEFAULT_UPLOAD_INTERVAL_SECS: u64 = 4 * 60 * 60;

/// Witnessd version for upload headers
pub const WITNESSD_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Anonymized jitter sample for research purposes.
/// Contains only timing data, no document or user information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymizedSample {
    /// Relative timestamp within session (seconds since session start)
    pub relative_time_secs: f64,
    /// Jitter value in microseconds
    pub jitter_micros: u32,
    /// Keystroke ordinal (relative position in session)
    pub keystroke_ordinal: u64,
    /// Whether document changed since last sample (without revealing content)
    pub document_changed: bool,
}

/// Anonymized session data for research contribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymizedSession {
    /// Random session identifier (not linked to actual session)
    pub research_id: String,
    /// Collection timestamp (rounded to hour)
    pub collected_at: DateTime<Utc>,
    /// Hardware class identifier
    pub hardware_class: HardwareClass,
    /// Operating system type
    pub os_type: OsType,
    /// Anonymized timing samples
    pub samples: Vec<AnonymizedSample>,
    /// Aggregate statistics
    pub statistics: AnonymizedStatistics,
}

/// Hardware class classification (coarse-grained for privacy)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareClass {
    /// CPU architecture: x86_64, aarch64, etc.
    pub arch: String,
    /// Core count bucket: "1-2", "3-4", "5-8", "9-16", "17+"
    pub core_bucket: String,
    /// Memory bucket: "<=4GB", "4-8GB", "8-16GB", "16-32GB", "32GB+"
    pub memory_bucket: String,
}

/// Operating system type
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OsType {
    MacOS,
    Linux,
    Windows,
    Other,
}

/// Anonymized statistics for research
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymizedStatistics {
    /// Total sample count
    pub total_samples: usize,
    /// Duration bucket: "0-5min", "5-15min", "15-30min", "30-60min", "60min+"
    pub duration_bucket: String,
    /// Typing rate bucket: "slow", "moderate", "fast", "very_fast"
    pub typing_rate_bucket: String,
    /// Mean jitter value
    pub mean_jitter_micros: f64,
    /// Standard deviation of jitter
    pub jitter_std_dev: f64,
    /// Minimum jitter value
    pub min_jitter_micros: u32,
    /// Maximum jitter value
    pub max_jitter_micros: u32,
}

/// Research data export format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchDataExport {
    /// Format version
    pub version: u32,
    /// Export timestamp
    pub exported_at: DateTime<Utc>,
    /// Data collection consent confirmation
    pub consent_confirmed: bool,
    /// Anonymized sessions
    pub sessions: Vec<AnonymizedSession>,
}

impl AnonymizedSession {
    /// Create an anonymized session from jitter evidence.
    /// Strips all identifying information while preserving timing patterns.
    pub fn from_evidence(evidence: &Evidence) -> Self {
        let research_id = generate_research_id();
        let collected_at = round_timestamp_to_hour(Utc::now());
        let hardware_class = detect_hardware_class();
        let os_type = detect_os_type();

        let start_time = evidence.started_at;
        let mut prev_doc_hash: Option<[u8; 32]> = None;

        let samples: Vec<AnonymizedSample> = evidence
            .samples
            .iter()
            .map(|s| {
                let relative_time = s
                    .timestamp
                    .signed_duration_since(start_time)
                    .to_std()
                    .map(|d| d.as_secs_f64())
                    .unwrap_or(0.0);

                let doc_changed = prev_doc_hash
                    .map(|prev| prev != s.document_hash)
                    .unwrap_or(true);
                prev_doc_hash = Some(s.document_hash);

                AnonymizedSample {
                    relative_time_secs: relative_time,
                    jitter_micros: s.jitter_micros,
                    keystroke_ordinal: s.keystroke_count,
                    document_changed: doc_changed,
                }
            })
            .collect();

        let statistics = compute_anonymized_statistics(&evidence.statistics, &samples);

        Self {
            research_id,
            collected_at,
            hardware_class,
            os_type,
            samples,
            statistics,
        }
    }
}

/// Generate a random research ID not linked to actual session
fn generate_research_id() -> String {
    let random_bytes: [u8; 16] = rand::random();
    hex::encode(random_bytes)
}

/// Round timestamp to nearest hour for privacy
fn round_timestamp_to_hour(ts: DateTime<Utc>) -> DateTime<Utc> {
    ts.with_minute(0)
        .and_then(|t| t.with_second(0))
        .and_then(|t| t.with_nanosecond(0))
        .unwrap_or(ts)
}

/// Detect hardware class (coarse-grained)
fn detect_hardware_class() -> HardwareClass {
    let arch = std::env::consts::ARCH.to_string();

    let core_count = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(1);

    let core_bucket = match core_count {
        1..=2 => "1-2",
        3..=4 => "3-4",
        5..=8 => "5-8",
        9..=16 => "9-16",
        _ => "17+",
    }
    .to_string();

    // Memory detection is platform-specific
    let memory_bucket = detect_memory_bucket();

    HardwareClass {
        arch,
        core_bucket,
        memory_bucket,
    }
}

#[cfg(target_os = "macos")]
fn detect_memory_bucket() -> String {
    use std::process::Command;

    let output = Command::new("sysctl")
        .args(["-n", "hw.memsize"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<u64>().ok());

    match output {
        Some(bytes) => {
            let gb = bytes / (1024 * 1024 * 1024);
            memory_gb_to_bucket(gb)
        }
        None => "unknown".to_string(),
    }
}

#[cfg(target_os = "linux")]
fn detect_memory_bucket() -> String {
    let meminfo = fs::read_to_string("/proc/meminfo").ok();

    let total_kb = meminfo.and_then(|content| {
        content
            .lines()
            .find(|l| l.starts_with("MemTotal:"))
            .and_then(|l| {
                l.split_whitespace()
                    .nth(1)
                    .and_then(|s| s.parse::<u64>().ok())
            })
    });

    match total_kb {
        Some(kb) => {
            let gb = kb / (1024 * 1024);
            memory_gb_to_bucket(gb)
        }
        None => "unknown".to_string(),
    }
}

#[cfg(target_os = "windows")]
fn detect_memory_bucket() -> String {
    // Windows memory detection via GlobalMemoryStatusEx
    // For now, return unknown to avoid unsafe code
    "unknown".to_string()
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn detect_memory_bucket() -> String {
    "unknown".to_string()
}

fn memory_gb_to_bucket(gb: u64) -> String {
    match gb {
        0..=4 => "<=4GB",
        5..=8 => "4-8GB",
        9..=16 => "8-16GB",
        17..=32 => "16-32GB",
        _ => "32GB+",
    }
    .to_string()
}

/// Detect operating system type
fn detect_os_type() -> OsType {
    match std::env::consts::OS {
        "macos" => OsType::MacOS,
        "linux" => OsType::Linux,
        "windows" => OsType::Windows,
        _ => OsType::Other,
    }
}

/// Compute anonymized statistics
fn compute_anonymized_statistics(
    stats: &Statistics,
    samples: &[AnonymizedSample],
) -> AnonymizedStatistics {
    let duration_secs = stats.duration.as_secs();
    let duration_bucket = match duration_secs {
        0..=300 => "0-5min",
        301..=900 => "5-15min",
        901..=1800 => "15-30min",
        1801..=3600 => "30-60min",
        _ => "60min+",
    }
    .to_string();

    let typing_rate_bucket = match stats.keystrokes_per_min as u32 {
        0..=30 => "slow",
        31..=60 => "moderate",
        61..=120 => "fast",
        _ => "very_fast",
    }
    .to_string();

    let jitter_values: Vec<f64> = samples.iter().map(|s| s.jitter_micros as f64).collect();

    let (mean, std_dev) = if jitter_values.is_empty() {
        (0.0, 0.0)
    } else {
        let mean = jitter_values.iter().sum::<f64>() / jitter_values.len() as f64;
        let variance =
            jitter_values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / jitter_values.len() as f64;
        (mean, variance.sqrt())
    };

    let min_jitter = samples
        .iter()
        .map(|s| s.jitter_micros)
        .min()
        .unwrap_or(0);
    let max_jitter = samples
        .iter()
        .map(|s| s.jitter_micros)
        .max()
        .unwrap_or(0);

    AnonymizedStatistics {
        total_samples: samples.len(),
        duration_bucket,
        typing_rate_bucket,
        mean_jitter_micros: mean,
        jitter_std_dev: std_dev,
        min_jitter_micros: min_jitter,
        max_jitter_micros: max_jitter,
    }
}

/// Research data collector
pub struct ResearchCollector {
    config: ResearchConfig,
    sessions: Vec<AnonymizedSession>,
}

impl ResearchCollector {
    pub fn new(config: ResearchConfig) -> Self {
        Self {
            config,
            sessions: Vec::new(),
        }
    }

    /// Check if research contribution is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.contribute_to_research
    }

    /// Add a session for research contribution (if enabled)
    pub fn add_session(&mut self, evidence: &Evidence) {
        if !self.is_enabled() {
            return;
        }

        // Only include sessions with sufficient samples
        if evidence.samples.len() < self.config.min_samples_per_session {
            return;
        }

        let anonymized = AnonymizedSession::from_evidence(evidence);
        self.sessions.push(anonymized);

        // Trim to max sessions
        while self.sessions.len() > self.config.max_sessions {
            self.sessions.remove(0);
        }
    }

    /// Get count of collected sessions
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Export collected research data
    pub fn export(&self) -> ResearchDataExport {
        ResearchDataExport {
            version: 1,
            exported_at: Utc::now(),
            consent_confirmed: self.config.contribute_to_research,
            sessions: self.sessions.clone(),
        }
    }

    /// Export to JSON string
    pub fn export_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(&self.export()).map_err(|e| e.to_string())
    }

    /// Save research data to disk
    pub fn save(&self) -> Result<(), String> {
        if self.sessions.is_empty() {
            return Ok(());
        }

        fs::create_dir_all(&self.config.research_data_dir).map_err(|e| e.to_string())?;

        let export = self.export();
        let filename = format!("research_{}.json", Utc::now().format("%Y%m%d_%H%M%S"));
        let path = self.config.research_data_dir.join(filename);

        let json = serde_json::to_string_pretty(&export).map_err(|e| e.to_string())?;
        fs::write(&path, json).map_err(|e| e.to_string())?;

        Ok(())
    }

    /// Load existing research data from disk
    pub fn load(&mut self) -> Result<(), String> {
        if !self.config.research_data_dir.exists() {
            return Ok(());
        }

        let entries = fs::read_dir(&self.config.research_data_dir).map_err(|e| e.to_string())?;

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "json").unwrap_or(false) {
                if let Ok(content) = fs::read_to_string(&path) {
                    if let Ok(export) = serde_json::from_str::<ResearchDataExport>(&content) {
                        for session in export.sessions {
                            self.sessions.push(session);
                        }
                    }
                }
            }
        }

        // Trim to max sessions
        while self.sessions.len() > self.config.max_sessions {
            self.sessions.remove(0);
        }

        Ok(())
    }

    /// Clear all collected research data
    pub fn clear(&mut self) -> Result<(), String> {
        self.sessions.clear();

        if self.config.research_data_dir.exists() {
            fs::remove_dir_all(&self.config.research_data_dir).map_err(|e| e.to_string())?;
        }

        Ok(())
    }

    /// Upload collected research data to the research server.
    /// Returns the number of sessions successfully uploaded.
    pub async fn upload(&mut self) -> Result<UploadResult, String> {
        if !self.is_enabled() {
            return Err("Research contribution not enabled".to_string());
        }

        if self.sessions.is_empty() {
            return Ok(UploadResult {
                sessions_uploaded: 0,
                samples_uploaded: 0,
                message: "No sessions to upload".to_string(),
            });
        }

        // Don't upload if we don't have enough sessions
        if self.sessions.len() < MIN_SESSIONS_FOR_UPLOAD {
            return Ok(UploadResult {
                sessions_uploaded: 0,
                samples_uploaded: 0,
                message: format!(
                    "Waiting for more sessions ({}/{})",
                    self.sessions.len(),
                    MIN_SESSIONS_FOR_UPLOAD
                ),
            });
        }

        let export = self.export();
        let client = reqwest::Client::new();

        let response = client
            .post(RESEARCH_UPLOAD_URL)
            .header("Content-Type", "application/json")
            .header("X-Witnessd-Version", WITNESSD_VERSION)
            .json(&export)
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .map_err(|e| format!("Upload failed: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!("Upload failed with status {}: {}", status, body));
        }

        let result: UploadResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))?;

        // Clear uploaded sessions on success
        if result.uploaded > 0 {
            self.sessions.clear();
            // Also clear local files
            if self.config.research_data_dir.exists() {
                let _ = fs::remove_dir_all(&self.config.research_data_dir);
            }
        }

        Ok(UploadResult {
            sessions_uploaded: result.uploaded,
            samples_uploaded: result.samples,
            message: result.message,
        })
    }

    /// Check if upload should be attempted (enough sessions collected)
    pub fn should_upload(&self) -> bool {
        self.is_enabled() && self.sessions.len() >= MIN_SESSIONS_FOR_UPLOAD
    }
}

/// Result of an upload attempt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadResult {
    pub sessions_uploaded: usize,
    pub samples_uploaded: usize,
    pub message: String,
}

/// Response from the upload endpoint
#[derive(Debug, Clone, Deserialize)]
struct UploadResponse {
    uploaded: usize,
    samples: usize,
    message: String,
}

/// Background uploader for periodic research data submission
pub struct ResearchUploader {
    collector: Arc<tokio::sync::Mutex<ResearchCollector>>,
    running: Arc<AtomicBool>,
    upload_interval: Duration,
}

impl ResearchUploader {
    /// Create a new research uploader
    pub fn new(collector: Arc<tokio::sync::Mutex<ResearchCollector>>) -> Self {
        Self {
            collector,
            running: Arc::new(AtomicBool::new(false)),
            upload_interval: Duration::from_secs(DEFAULT_UPLOAD_INTERVAL_SECS),
        }
    }

    /// Create with custom upload interval
    pub fn with_interval(
        collector: Arc<tokio::sync::Mutex<ResearchCollector>>,
        interval: Duration,
    ) -> Self {
        Self {
            collector,
            running: Arc::new(AtomicBool::new(false)),
            upload_interval: interval,
        }
    }

    /// Start the background upload task
    pub fn start(&self) -> tokio::task::JoinHandle<()> {
        let collector = Arc::clone(&self.collector);
        let running = Arc::clone(&self.running);
        let interval = self.upload_interval;

        running.store(true, Ordering::SeqCst);

        tokio::spawn(async move {
            while running.load(Ordering::SeqCst) {
                // Wait for the interval
                tokio::time::sleep(interval).await;

                if !running.load(Ordering::SeqCst) {
                    break;
                }

                // Attempt upload
                let mut guard = collector.lock().await;
                if guard.should_upload() {
                    match guard.upload().await {
                        Ok(result) => {
                            if result.sessions_uploaded > 0 {
                                eprintln!(
                                    "[research] Uploaded {} sessions ({} samples)",
                                    result.sessions_uploaded, result.samples_uploaded
                                );
                            }
                        }
                        Err(e) => {
                            eprintln!("[research] Upload failed: {}", e);
                            // Save locally as backup
                            let _ = guard.save();
                        }
                    }
                }
            }
        })
    }

    /// Stop the background upload task
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Check if the uploader is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Trigger an immediate upload attempt
    pub async fn upload_now(&self) -> Result<UploadResult, String> {
        let mut guard = self.collector.lock().await;
        guard.upload().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jitter::{default_parameters, Session};
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_hardware_class_detection() {
        let hw = detect_hardware_class();
        assert!(!hw.arch.is_empty());
        assert!(!hw.core_bucket.is_empty());
    }

    #[test]
    fn test_os_type_detection() {
        let os = detect_os_type();
        #[cfg(target_os = "macos")]
        assert_eq!(os, OsType::MacOS);
        #[cfg(target_os = "linux")]
        assert_eq!(os, OsType::Linux);
        #[cfg(target_os = "windows")]
        assert_eq!(os, OsType::Windows);
    }

    #[test]
    fn test_timestamp_rounding() {
        let ts = Utc::now();
        let rounded = round_timestamp_to_hour(ts);
        assert_eq!(rounded.minute(), 0);
        assert_eq!(rounded.second(), 0);
        assert_eq!(rounded.nanosecond(), 0);
    }

    #[test]
    fn test_anonymized_session_creation() {
        // Create a temp file for testing
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "test content").unwrap();
        temp_file.flush().unwrap();

        let params = default_parameters();
        let mut session = Session::new(temp_file.path(), params).unwrap();

        // Record some keystrokes
        for _ in 0..100 {
            let _ = session.record_keystroke();
        }

        let evidence = session.export();
        let anonymized = AnonymizedSession::from_evidence(&evidence);

        // Verify anonymization
        assert!(!anonymized.research_id.is_empty());
        assert_eq!(anonymized.collected_at.minute(), 0);
        assert!(!anonymized.hardware_class.arch.is_empty());
    }

    #[test]
    fn test_research_collector_disabled() {
        let config = ResearchConfig {
            contribute_to_research: false,
            ..Default::default()
        };

        let mut collector = ResearchCollector::new(config);
        assert!(!collector.is_enabled());

        // Create dummy evidence
        let evidence = Evidence {
            session_id: "test".to_string(),
            started_at: Utc::now(),
            ended_at: Utc::now(),
            document_path: "/test".to_string(),
            params: default_parameters(),
            samples: vec![],
            statistics: Statistics::default(),
        };

        collector.add_session(&evidence);
        assert_eq!(collector.session_count(), 0);
    }

    #[test]
    fn test_memory_bucket() {
        assert_eq!(memory_gb_to_bucket(2), "<=4GB");
        assert_eq!(memory_gb_to_bucket(6), "4-8GB");
        assert_eq!(memory_gb_to_bucket(12), "8-16GB");
        assert_eq!(memory_gb_to_bucket(24), "16-32GB");
        assert_eq!(memory_gb_to_bucket(64), "32GB+");
    }
}
