use crate::vdf::params::Parameters as VdfParameters;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessdConfig {
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,

    #[serde(default = "default_watch_dirs")]
    pub watch_dirs: Vec<PathBuf>,

    #[serde(default = "default_retention_days")]
    pub retention_days: u32,

    #[serde(default)]
    pub presence: PresenceConfig,

    #[serde(default)]
    pub vdf: VdfConfig,

    #[serde(default)]
    pub sentinel: SentinelConfig,

    #[serde(default)]
    pub research: ResearchConfig,

    #[serde(default)]
    pub fingerprint: FingerprintConfig,

    #[serde(default)]
    pub privacy: PrivacyConfig,
}

/// Configuration for author fingerprinting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintConfig {
    /// Enable activity fingerprinting (typing dynamics).
    /// Default: true (captures HOW you type, not WHAT you type)
    #[serde(default = "default_true")]
    pub activity_enabled: bool,

    /// Enable voice fingerprinting (writing style).
    /// Default: false (requires explicit consent)
    #[serde(default = "default_false")]
    pub voice_enabled: bool,

    /// Retention period for fingerprint profiles in days.
    #[serde(default = "default_fingerprint_retention")]
    pub retention_days: u32,

    /// Minimum samples before creating a fingerprint.
    #[serde(default = "default_min_fingerprint_samples")]
    pub min_samples: u32,

    /// Directory for fingerprint storage.
    #[serde(default = "default_fingerprint_dir")]
    pub storage_path: PathBuf,
}

impl Default for FingerprintConfig {
    fn default() -> Self {
        Self {
            activity_enabled: true,
            voice_enabled: false,
            retention_days: 365,
            min_samples: 100,
            storage_path: default_fingerprint_dir(),
        }
    }
}

fn default_fingerprint_retention() -> u32 {
    365
}

fn default_min_fingerprint_samples() -> u32 {
    100
}

fn default_fingerprint_dir() -> PathBuf {
    dirs::home_dir()
        .map(|h| h.join(".witnessd").join("fingerprints"))
        .unwrap_or_else(|| PathBuf::from(".witnessd/fingerprints"))
}

/// Privacy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyConfig {
    /// Detect and skip sensitive input fields (password, etc.).
    #[serde(default = "default_true")]
    pub detect_sensitive_fields: bool,

    /// Hash URLs before storing (privacy).
    #[serde(default = "default_true")]
    pub hash_urls: bool,

    /// Obfuscate window titles.
    #[serde(default = "default_true")]
    pub obfuscate_titles: bool,

    /// Excluded applications (never track).
    #[serde(default = "default_privacy_excluded")]
    pub excluded_apps: Vec<String>,
}

impl Default for PrivacyConfig {
    fn default() -> Self {
        Self {
            detect_sensitive_fields: true,
            hash_urls: true,
            obfuscate_titles: true,
            excluded_apps: default_privacy_excluded(),
        }
    }
}

fn default_privacy_excluded() -> Vec<String> {
    vec![
        "1Password".to_string(),
        "Keychain Access".to_string(),
        "System Preferences".to_string(),
        "Terminal".to_string(),
    ]
}

/// Configuration for anonymous research data contribution.
/// When enabled, anonymized jitter timing samples are collected to help
/// improve the security analysis of the proof-of-process primitive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchConfig {
    /// Opt-in toggle for contributing anonymous research data.
    /// Default: false (must be explicitly enabled by user)
    #[serde(default = "default_false")]
    pub contribute_to_research: bool,

    /// Directory for storing research data before export.
    #[serde(default = "default_research_dir")]
    pub research_data_dir: PathBuf,

    /// Maximum number of sessions to retain locally before export.
    #[serde(default = "default_max_research_sessions")]
    pub max_sessions: usize,

    /// Minimum samples per session before it's eligible for research.
    #[serde(default = "default_min_samples_for_research")]
    pub min_samples_per_session: usize,

    /// Upload interval in seconds (default: 4 hours).
    #[serde(default = "default_upload_interval")]
    pub upload_interval_secs: u64,

    /// Enable automatic periodic uploads.
    #[serde(default = "default_true")]
    pub auto_upload: bool,
}

impl Default for ResearchConfig {
    fn default() -> Self {
        Self {
            contribute_to_research: false,
            research_data_dir: default_research_dir(),
            max_sessions: default_max_research_sessions(),
            min_samples_per_session: default_min_samples_for_research(),
            upload_interval_secs: default_upload_interval(),
            auto_upload: true,
        }
    }
}

fn default_research_dir() -> PathBuf {
    dirs::home_dir()
        .map(|h| h.join(".witnessd").join("research"))
        .unwrap_or_else(|| PathBuf::from(".witnessd/research"))
}

fn default_max_research_sessions() -> usize {
    100
}

fn default_min_samples_for_research() -> usize {
    10
}

fn default_upload_interval() -> u64 {
    4 * 60 * 60 // 4 hours
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresenceConfig {
    #[serde(default = "default_interval")]
    pub challenge_interval_secs: u64,
    #[serde(default = "default_window")]
    pub response_window_secs: u64,
}

impl Default for PresenceConfig {
    fn default() -> Self {
        Self {
            challenge_interval_secs: default_interval(),
            response_window_secs: default_window(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VdfConfig {
    #[serde(default = "default_ips")]
    pub iterations_per_second: u64,
    #[serde(default = "default_min_iter")]
    pub min_iterations: u64,
    #[serde(default = "default_max_iter")]
    pub max_iterations: u64,
}

impl Default for VdfConfig {
    fn default() -> Self {
        Self {
            iterations_per_second: default_ips(),
            min_iterations: default_min_iter(),
            max_iterations: default_max_iter(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelConfig {
    #[serde(default = "default_false")]
    pub auto_start: bool,
    #[serde(default = "default_heartbeat")]
    pub heartbeat_interval_secs: u64,
    #[serde(default = "default_checkpoint")]
    pub checkpoint_interval_secs: u64,

    // Expanded fields
    #[serde(default = "default_witnessd_dir")]
    pub witnessd_dir: PathBuf,
    #[serde(default)]
    pub shadow_dir: PathBuf,
    #[serde(default)]
    pub wal_dir: PathBuf,
    #[serde(default)]
    pub watch_paths: Vec<PathBuf>,
    #[serde(default = "default_true")]
    pub recursive_watch: bool,
    #[serde(default = "default_debounce")]
    pub debounce_duration_ms: u64,
    #[serde(default = "default_idle")]
    pub idle_timeout_secs: u64,
    #[serde(default)]
    pub allowed_apps: Vec<String>,
    #[serde(default)]
    pub blocked_apps: Vec<String>,
    #[serde(default = "default_true")]
    pub track_unknown_apps: bool,
    #[serde(default = "default_true")]
    pub hash_on_focus: bool,
    #[serde(default = "default_true")]
    pub hash_on_save: bool,
    #[serde(default = "default_poll")]
    pub poll_interval_ms: u64,
}

impl Default for SentinelConfig {
    fn default() -> Self {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        let witnessd_dir = home.join(".witnessd");

        Self {
            auto_start: default_false(),
            heartbeat_interval_secs: default_heartbeat(),
            checkpoint_interval_secs: default_checkpoint(),
            witnessd_dir: witnessd_dir.clone(),
            shadow_dir: witnessd_dir.join("shadow"),
            wal_dir: witnessd_dir.join("sentinel").join("wal"),
            watch_paths: Vec::new(),
            recursive_watch: true,
            debounce_duration_ms: 500,
            idle_timeout_secs: 1800,
            allowed_apps: default_allowed_apps(),
            blocked_apps: default_blocked_apps(),
            track_unknown_apps: true,
            hash_on_focus: true,
            hash_on_save: true,
            poll_interval_ms: 100,
        }
    }
}

// Defaults
fn default_true() -> bool {
    true
}
fn default_debounce() -> u64 {
    500
}
fn default_idle() -> u64 {
    1800
}
fn default_poll() -> u64 {
    100
}
fn default_witnessd_dir() -> PathBuf {
    dirs::home_dir()
        .map(|h| h.join(".witnessd"))
        .unwrap_or_else(|| PathBuf::from(".witnessd"))
}

fn default_allowed_apps() -> Vec<String> {
    vec![
        "com.apple.TextEdit".to_string(),
        "com.microsoft.Word".to_string(),
        "code".to_string(),
        // ... (truncated for brevity, would match sentinel.rs list)
    ]
}

fn default_blocked_apps() -> Vec<String> {
    vec!["com.apple.finder".to_string(), "explorer".to_string()]
}

impl SentinelConfig {
    pub fn with_witnessd_dir(mut self, dir: impl AsRef<Path>) -> Self {
        let dir = dir.as_ref().to_path_buf();
        self.shadow_dir = dir.join("shadow");
        self.wal_dir = dir.join("sentinel").join("wal");
        self.witnessd_dir = dir;
        self
    }

    pub fn is_app_allowed(&self, bundle_id: &str, app_name: &str) -> bool {
        for blocked in &self.blocked_apps {
            if blocked == bundle_id || blocked == app_name {
                return false;
            }
        }
        if self.allowed_apps.is_empty() {
            return self.track_unknown_apps;
        }
        for allowed in &self.allowed_apps {
            if allowed == bundle_id || allowed == app_name {
                return true;
            }
        }
        self.track_unknown_apps
    }

    pub fn validate(&self) -> Result<()> {
        Ok(()) // Placeholder
    }

    pub fn ensure_directories(&self) -> Result<()> {
        fs::create_dir_all(&self.witnessd_dir)?;
        fs::create_dir_all(&self.shadow_dir)?;
        fs::create_dir_all(&self.wal_dir)?;
        Ok(())
    }
}

// Defaults
fn default_data_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        dirs::home_dir()
            .map(|h| h.join("Library/Application Support/Witnessd"))
            .unwrap_or_else(|| PathBuf::from(".witnessd"))
    }
    #[cfg(not(target_os = "macos"))]
    {
        dirs::home_dir()
            .map(|h| h.join(".witnessd"))
            .unwrap_or_else(|| PathBuf::from(".witnessd"))
    }
}

fn default_watch_dirs() -> Vec<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        dirs::home_dir()
            .map(|h| vec![h.join("Documents"), h.join("Desktop")])
            .unwrap_or_default()
    }
    #[cfg(not(target_os = "macos"))]
    {
        Vec::new()
    }
}

fn default_retention_days() -> u32 {
    30
}
fn default_interval() -> u64 {
    600
}
fn default_window() -> u64 {
    60
}
fn default_ips() -> u64 {
    1_000_000
}
fn default_min_iter() -> u64 {
    100_000
}
fn default_max_iter() -> u64 {
    3_600_000_000
}
fn default_false() -> bool {
    false
}
fn default_heartbeat() -> u64 {
    60
}
fn default_checkpoint() -> u64 {
    60
}

impl WitnessdConfig {
    pub fn load_or_default(data_dir: &Path) -> Result<Self> {
        let config_path = data_dir.join("witnessd.json");

        if config_path.exists() {
            let raw = fs::read_to_string(&config_path)?;
            let mut config: WitnessdConfig = serde_json::from_str(&raw)?;
            config.data_dir = data_dir.to_path_buf();
            return Ok(config);
        }

        // Migration logic
        let mut config = Self::default_with_dir(data_dir);
        let cli_path = data_dir.join("config.json");
        let gui_path = data_dir.join("engine_config.json");

        if cli_path.exists() {
            if let Ok(raw) = fs::read_to_string(&cli_path) {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) {
                    if let Some(vdf) = val.get("vdf") {
                        config.vdf.iterations_per_second = vdf
                            .get("iterations_per_second")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(config.vdf.iterations_per_second);
                    }
                }
            }
        }

        if gui_path.exists() {
            if let Ok(raw) = fs::read_to_string(&gui_path) {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) {
                    config.retention_days = val
                        .get("retention_days")
                        .and_then(|v| v.as_u64())
                        .map(|v| v as u32)
                        .unwrap_or(config.retention_days);
                    if let Some(dirs) = val.get("watch_dirs").and_then(|v| v.as_array()) {
                        config.watch_dirs = dirs
                            .iter()
                            .filter_map(|v| v.as_str().map(PathBuf::from))
                            .collect();
                    }
                }
            }
        }

        config.persist()?;
        Ok(config)
    }

    pub fn default_with_dir(data_dir: &Path) -> Self {
        Self {
            data_dir: data_dir.to_path_buf(),
            watch_dirs: default_watch_dirs(),
            retention_days: default_retention_days(),
            presence: PresenceConfig::default(),
            vdf: VdfConfig::default(),
            sentinel: SentinelConfig::default(),
            research: ResearchConfig {
                research_data_dir: data_dir.join("research"),
                ..Default::default()
            },
            fingerprint: FingerprintConfig {
                storage_path: data_dir.join("fingerprints"),
                ..Default::default()
            },
            privacy: PrivacyConfig::default(),
        }
    }

    pub fn persist(&self) -> Result<()> {
        fs::create_dir_all(&self.data_dir)?;
        let config_path = self.data_dir.join("witnessd.json");
        let raw = serde_json::to_string_pretty(self)?;
        fs::write(config_path, raw)?;
        Ok(())
    }
}

impl From<WitnessdConfig> for VdfParameters {
    fn from(cfg: WitnessdConfig) -> Self {
        Self {
            iterations_per_second: cfg.vdf.iterations_per_second,
            min_iterations: cfg.vdf.min_iterations,
            max_iterations: cfg.vdf.max_iterations,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_config_defaults() {
        let dir = tempdir().unwrap();
        let config = WitnessdConfig::default_with_dir(dir.path());

        assert_eq!(config.data_dir, dir.path());
        assert_eq!(config.retention_days, 30);
        assert!(config.vdf.iterations_per_second > 0);
        assert!(!config.sentinel.allowed_apps.is_empty());
    }

    #[test]
    fn test_config_persistence() {
        let dir = tempdir().unwrap();
        let config = WitnessdConfig::default_with_dir(dir.path());
        config.persist().expect("persist failed");

        let loaded = WitnessdConfig::load_or_default(dir.path()).expect("load failed");
        assert_eq!(loaded.data_dir, config.data_dir);
        assert_eq!(
            loaded.vdf.iterations_per_second,
            config.vdf.iterations_per_second
        );
    }

    #[test]
    fn test_sentinel_app_blocking() {
        let config = SentinelConfig::default();
        // Check defaults
        assert!(config.is_app_allowed("com.apple.TextEdit", "TextEdit"));
        assert!(!config.is_app_allowed("com.apple.finder", "Finder"));

        // Check unknown (assuming track_unknown_apps is true by default)
        assert!(config.is_app_allowed("com.unknown.App", "Unknown"));
    }
}
