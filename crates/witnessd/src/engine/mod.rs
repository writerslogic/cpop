// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

mod session;
mod watcher;

#[cfg(test)]
mod tests;

use crate::config::CpopConfig;
use crate::jitter::SimpleJitterSession;
#[cfg(target_os = "macos")]
use crate::platform;
use crate::store::SecureStore;
use crate::MutexRecover;
use anyhow::{anyhow, Context, Result};
use notify::RecommendedWatcher;
use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use watcher::{load_or_create_device_identity, load_or_create_hmac_key, start_file_watcher};

/// Snapshot of the engine's runtime state.
#[derive(Clone, Debug, Serialize)]
pub struct EngineStatus {
    /// Whether the engine is actively monitoring.
    pub running: bool,
    /// Whether accessibility permissions are granted (macOS).
    pub accessibility_trusted: bool,
    /// Directories being watched for file changes.
    pub watch_dirs: Vec<PathBuf>,
    /// Total number of events written to the store.
    pub events_written: u64,
    /// Number of keystroke jitter samples collected this session.
    pub jitter_samples: u64,
    /// Timestamp (ns since epoch) of the most recent event.
    pub last_event_timestamp_ns: Option<i64>,
}

/// Summary of a monitored file's event history.
#[derive(Clone, Debug, Serialize)]
pub struct ReportFile {
    /// Canonical path of the monitored file.
    pub file_path: String,
    /// Timestamp (ns since epoch) of the last recorded event.
    pub last_event_timestamp_ns: i64,
    /// Total number of events recorded for this file.
    pub event_count: u64,
}

/// Core witnessing engine: monitors files and keystrokes, records evidence events.
pub struct Engine {
    inner: Arc<EngineInner>,
}

/// Maximum number of entries retained in the content hash map for rename detection.
const CONTENT_HASH_MAP_MAX_ENTRIES: usize = 1000;

/// Maximum age (in nanoseconds) of a content hash entry to be considered for rename detection.
const RENAME_WINDOW_NS: i64 = 60_000_000_000; // 60 seconds

// Lock ordering: status -> store -> jitter_session (always acquire in this order)
struct EngineInner {
    running: AtomicBool,
    status: Mutex<EngineStatus>,
    store: Mutex<SecureStore>,
    jitter_session: Arc<Mutex<SimpleJitterSession>>,
    #[cfg(target_os = "macos")]
    keystroke_monitor: Mutex<Option<platform::macos::KeystrokeMonitor>>,
    watcher: Mutex<Option<RecommendedWatcher>>,
    watcher_thread: Mutex<Option<std::thread::JoinHandle<()>>>,
    file_sizes: Mutex<HashMap<PathBuf, i64>>,
    /// Maps content hash → (last known path, timestamp_ns) for rename detection.
    content_hash_map: Mutex<HashMap<[u8; 32], (PathBuf, i64)>>,
    device_id: [u8; 16],
    machine_id: String,
    watch_dirs: Mutex<Vec<PathBuf>>,
    data_dir: PathBuf,
}

impl Engine {
    /// Initialize and start the engine with the given configuration.
    pub fn start(config: CpopConfig) -> Result<Self> {
        crate::crypto::harden_process();

        fs::create_dir_all(&config.data_dir)
            .with_context(|| format!("Failed to create data dir: {:?}", config.data_dir))?;

        #[cfg(target_os = "macos")]
        let accessibility_trusted = platform::macos::check_accessibility_permissions()
            || std::env::var("CPOP_SKIP_PERMISSIONS").is_ok();
        #[cfg(not(target_os = "macos"))]
        let accessibility_trusted = true;
        #[cfg(target_os = "macos")]
        let input_trusted = platform::macos::check_input_monitoring_permissions()
            || std::env::var("CPOP_SKIP_PERMISSIONS").is_ok();
        #[cfg(not(target_os = "macos"))]
        let input_trusted = true;

        if !accessibility_trusted || !input_trusted {
            return Err(anyhow!(
                "Accessibility and Input Monitoring permissions required for global key timing"
            ));
        }

        let (device_id, machine_id) = load_or_create_device_identity(&config.data_dir)?;
        let hmac_key = load_or_create_hmac_key(&config.data_dir)?;
        let store_path = config.data_dir.join("writerslogic.sqlite3");
        let store = SecureStore::open(store_path, hmac_key)?;

        let jitter_session = Arc::new(Mutex::new(SimpleJitterSession::new()));
        let status = EngineStatus {
            running: true,
            accessibility_trusted,
            watch_dirs: config.watch_dirs.clone(),
            events_written: 0,
            jitter_samples: 0,
            last_event_timestamp_ns: None,
        };

        let inner = Arc::new(EngineInner {
            running: AtomicBool::new(true),
            status: Mutex::new(status),
            store: Mutex::new(store),
            jitter_session: Arc::clone(&jitter_session),
            #[cfg(target_os = "macos")]
            keystroke_monitor: Mutex::new(None),
            watcher: Mutex::new(None),
            watcher_thread: Mutex::new(None),
            file_sizes: Mutex::new(HashMap::new()),
            content_hash_map: Mutex::new(HashMap::new()),
            device_id,
            machine_id,
            watch_dirs: Mutex::new(config.watch_dirs.clone()),
            data_dir: config.data_dir.clone(),
        });

        #[cfg(target_os = "macos")]
        if std::env::var("CPOP_SKIP_PERMISSIONS").is_err() {
            let monitor =
                platform::macos::KeystrokeMonitor::start(Arc::clone(&inner.jitter_session))?;
            *inner.keystroke_monitor.lock_recover() = Some(monitor);
        }

        start_file_watcher(&inner, config.watch_dirs)?;

        Ok(Self { inner })
    }
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine").finish_non_exhaustive()
    }
}
