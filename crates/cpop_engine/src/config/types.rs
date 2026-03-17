// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::defaults::*;
use crate::vdf::params::Parameters as VdfParameters;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Top-level engine configuration with subsystem settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpopConfig {
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

    #[serde(default)]
    pub writersproof: WritersProofConfig,
}

/// WritersProof external trust anchor integration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WritersProofConfig {
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[serde(default = "default_writersproof_url")]
    pub base_url: String,
    /// Auto-submit evidence on export
    #[serde(default = "default_false")]
    pub auto_attest: bool,
    /// Queue attestations when offline
    #[serde(default = "default_true")]
    pub offline_queue: bool,
}

impl Default for WritersProofConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            base_url: default_writersproof_url(),
            auto_attest: false,
            offline_queue: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintConfig {
    /// Typing dynamics (captures HOW you type, not WHAT)
    #[serde(default = "default_true")]
    pub activity_enabled: bool,

    /// Writing style analysis (requires explicit consent)
    #[serde(default = "default_false")]
    pub voice_enabled: bool,

    #[serde(default = "default_fingerprint_retention")]
    pub retention_days: u32,

    /// Minimum samples before creating a profile
    #[serde(default = "default_min_fingerprint_samples")]
    pub min_samples: u32,

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyConfig {
    /// Skip password fields and similar sensitive inputs
    #[serde(default = "default_true")]
    pub detect_sensitive_fields: bool,

    #[serde(default = "default_true")]
    pub hash_urls: bool,

    #[serde(default = "default_true")]
    pub obfuscate_titles: bool,

    /// Apps that are never tracked
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

/// Opt-in anonymous research data contribution (anonymized jitter timing).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchConfig {
    /// Must be explicitly enabled by user
    #[serde(default = "default_false")]
    pub contribute_to_research: bool,

    #[serde(default = "default_research_dir")]
    pub research_data_dir: PathBuf,

    #[serde(default = "default_max_research_sessions")]
    pub max_sessions: usize,

    #[serde(default = "default_min_samples_for_research")]
    pub min_samples_per_session: usize,

    /// Default: 4 hours
    #[serde(default = "default_upload_interval")]
    pub upload_interval_secs: u64,

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

    #[serde(default = "default_writerslogic_dir")]
    pub writerslogic_dir: PathBuf,
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
        let home = dirs::home_dir()
            .expect("cannot determine home directory; refusing to use insecure fallback path");
        let writerslogic_dir = home.join(".writerslogic");

        Self {
            auto_start: default_false(),
            heartbeat_interval_secs: default_heartbeat(),
            checkpoint_interval_secs: default_checkpoint(),
            writerslogic_dir: writerslogic_dir.clone(),
            shadow_dir: writerslogic_dir.join("shadow"),
            wal_dir: writerslogic_dir.join("sentinel").join("wal"),
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

impl SentinelConfig {
    /// Set the root directory, deriving shadow and WAL paths from it.
    pub fn with_writerslogic_dir(mut self, dir: impl AsRef<Path>) -> Self {
        let dir = dir.as_ref().to_path_buf();
        self.shadow_dir = dir.join("shadow");
        self.wal_dir = dir.join("sentinel").join("wal");
        self.writerslogic_dir = dir;
        self
    }

    /// Check whether an application is allowed for tracking by bundle ID or name.
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

    /// Validate sentinel config values (nonzero intervals, consistent bounds).
    pub fn validate(&self) -> Result<()> {
        use anyhow::bail;

        fn require_nonzero(val: u64, name: &str) -> Result<()> {
            if val == 0 {
                bail!("{name} must be > 0");
            }
            Ok(())
        }

        require_nonzero(self.checkpoint_interval_secs, "checkpoint_interval_secs")?;
        require_nonzero(self.heartbeat_interval_secs, "heartbeat_interval_secs")?;
        require_nonzero(self.poll_interval_ms, "poll_interval_ms")?;
        require_nonzero(self.debounce_duration_ms, "debounce_duration_ms")?;

        if self.idle_timeout_secs < self.checkpoint_interval_secs {
            bail!(
                "idle_timeout_secs ({}) must be >= checkpoint_interval_secs ({})",
                self.idle_timeout_secs,
                self.checkpoint_interval_secs
            );
        }
        Ok(())
    }

    /// Create writerslogic, shadow, and WAL directories if they don't exist.
    pub fn ensure_directories(&self) -> Result<()> {
        fs::create_dir_all(&self.writerslogic_dir)?;
        fs::create_dir_all(&self.shadow_dir)?;
        fs::create_dir_all(&self.wal_dir)?;
        Ok(())
    }
}

impl CpopConfig {
    /// Validate all config values after load/deserialization.
    pub fn validate(&self) -> Result<()> {
        use anyhow::bail;

        if self.retention_days == 0 {
            bail!("retention_days must be > 0");
        }
        if self.vdf.iterations_per_second == 0 {
            bail!("vdf.iterations_per_second must be > 0");
        }
        if self.vdf.min_iterations > self.vdf.max_iterations {
            bail!(
                "vdf.min_iterations ({}) must be <= max_iterations ({})",
                self.vdf.min_iterations,
                self.vdf.max_iterations
            );
        }
        if self.presence.challenge_interval_secs == 0 {
            bail!("presence.challenge_interval_secs must be > 0");
        }
        if self.presence.response_window_secs == 0 {
            bail!("presence.response_window_secs must be > 0");
        }
        self.sentinel.validate()?;
        Ok(())
    }
}

impl From<CpopConfig> for VdfParameters {
    fn from(cfg: CpopConfig) -> Self {
        Self {
            iterations_per_second: cfg.vdf.iterations_per_second,
            min_iterations: cfg.vdf.min_iterations,
            max_iterations: cfg.vdf.max_iterations,
        }
    }
}
