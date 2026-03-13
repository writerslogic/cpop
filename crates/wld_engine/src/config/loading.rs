// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::defaults::*;
use super::types::*;
use anyhow::Result;
use std::fs;
use std::path::Path;

impl WLDConfig {
    pub fn load_or_default(data_dir: &Path) -> Result<Self> {
        let config_path = data_dir.join("writerslogic.json");

        if config_path.exists() {
            let raw = fs::read_to_string(&config_path)?;
            let mut config: WLDConfig = serde_json::from_str(&raw)?;
            config.data_dir = data_dir.to_path_buf();
            config.validate()?;
            return Ok(config);
        }

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
                        .map(|v| v.min(u32::MAX as u64) as u32)
                        .unwrap_or(config.retention_days);
                    if let Some(dirs) = val.get("watch_dirs").and_then(|v| v.as_array()) {
                        config.watch_dirs = dirs
                            .iter()
                            .filter_map(|v| v.as_str().map(std::path::PathBuf::from))
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
            writersproof: WritersProofConfig::default(),
        }
    }

    pub fn persist(&self) -> Result<()> {
        fs::create_dir_all(&self.data_dir)?;
        let config_path = self.data_dir.join("writerslogic.json");
        let raw = serde_json::to_string_pretty(self)?;
        fs::write(&config_path, raw)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }
}
