// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::error::{Result, SentinelError};
use crate::crypto::ObfuscatedString;
use crate::RwLockRecover;
use std::collections::HashMap;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::{Duration, SystemTime};

/// Shadow buffer for tracking unsaved document content
#[derive(Debug, Clone)]
struct ShadowBuffer {
    id: String,
    app_name: String,
    window_title: ObfuscatedString,
    path: PathBuf,
    _created_at: SystemTime,
    updated_at: SystemTime,
    _size: i64,
}

/// Manages shadow buffers for unsaved documents
pub struct ShadowManager {
    base_dir: PathBuf,
    shadows: RwLock<HashMap<String, ShadowBuffer>>,
}

impl ShadowManager {
    pub fn new(base_dir: impl AsRef<Path>) -> Result<Self> {
        let base_dir = base_dir.as_ref().to_path_buf();
        fs::create_dir_all(&base_dir)?;

        Ok(Self {
            base_dir,
            shadows: RwLock::new(HashMap::new()),
        })
    }

    pub fn create(&self, app_name: &str, window_title: &str) -> Result<String> {
        use rand::Rng;
        let mut rng = rand::rng();
        let id_bytes: [u8; 16] = rng.random();
        let id = hex::encode(id_bytes);

        let path = self.base_dir.join(format!("{}.shadow", id));
        File::create(&path)?;

        let shadow = ShadowBuffer {
            id: id.clone(),
            app_name: app_name.to_string(),
            window_title: ObfuscatedString::new(window_title),
            path,
            _created_at: SystemTime::now(),
            updated_at: SystemTime::now(),
            _size: 0,
        };

        self.shadows.write_recover().insert(id.clone(), shadow);

        Ok(id)
    }

    /// Write shadow content to the shadow directory on disk.
    ///
    /// **Known limitation**: content is written unencrypted. The shadow directory
    /// inherits the application data directory's file-system permissions (mode 0700).
    /// Full encryption at rest is deferred; it would require key management for
    /// temporary files that may outlive the process.
    pub fn update(&self, id: &str, content: &[u8]) -> Result<()> {
        let mut shadows = self.shadows.write_recover();
        let shadow = shadows
            .get_mut(id)
            .ok_or_else(|| SentinelError::ShadowNotFound(id.to_string()))?;

        fs::write(&shadow.path, content)?;
        shadow.updated_at = SystemTime::now();
        shadow._size = i64::try_from(content.len()).unwrap_or(i64::MAX);

        Ok(())
    }

    pub fn get_path(&self, id: &str) -> Option<PathBuf> {
        self.shadows.read_recover().get(id).map(|s| s.path.clone())
    }

    pub fn delete(&self, id: &str) -> Result<()> {
        if let Some(shadow) = self.shadows.write_recover().remove(id) {
            if let Err(e) = fs::remove_file(&shadow.path) {
                log::debug!("shadow file remove: {e}");
            }
        }
        Ok(())
    }

    /// Migrate a shadow buffer to a real file path when the document is saved.
    pub fn migrate(&self, id: &str, _new_path: &str) -> Result<()> {
        if let Some(shadow) = self.shadows.write_recover().remove(id) {
            if let Err(e) = fs::remove_file(&shadow.path) {
                log::debug!("shadow file remove: {e}");
            }
        }
        Ok(())
    }

    pub fn cleanup_all(&self) {
        let mut shadows = self.shadows.write_recover();
        for shadow in shadows.values() {
            if let Err(e) = fs::remove_file(&shadow.path) {
                log::debug!("shadow cleanup: {e}");
            }
        }
        shadows.clear();
    }

    pub fn cleanup_old(&self, max_age: Duration) -> u32 {
        let cutoff = SystemTime::now() - max_age;
        let mut shadows = self.shadows.write_recover();
        let mut removed = 0u32;

        shadows.retain(|_, shadow| {
            if shadow.updated_at < cutoff {
                if let Err(e) = fs::remove_file(&shadow.path) {
                    log::debug!("shadow cleanup: {e}");
                }
                removed += 1;
                false
            } else {
                true
            }
        });

        removed
    }

    /// List active shadow buffers. Window titles are returned in their
    /// obfuscated form (`***OBFUSCATED***`) to avoid leaking plaintext
    /// through diagnostic or IPC surfaces. Callers that genuinely need
    /// the plaintext title should retrieve the shadow by ID and call
    /// `reveal()` explicitly.
    pub fn list(&self) -> Vec<(String, String, String)> {
        self.shadows
            .read_recover()
            .values()
            .map(|s| {
                (
                    s.id.clone(),
                    s.app_name.clone(),
                    format!("{:?}", s.window_title),
                )
            })
            .collect()
    }
}
