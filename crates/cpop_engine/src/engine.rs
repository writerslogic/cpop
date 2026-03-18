// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::config::CpopConfig;
use crate::identity::SecureStorage;
use crate::jitter::SimpleJitterSession;
#[cfg(target_os = "macos")]
use crate::platform;
use crate::store::{SecureEvent, SecureStore};
use crate::MutexRecover;
use anyhow::{anyhow, Context, Result};
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use rand::RngCore;
use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::SystemTime;

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

struct EngineInner {
    running: AtomicBool,
    status: Mutex<EngineStatus>,
    store: Mutex<SecureStore>,
    jitter_session: Arc<Mutex<SimpleJitterSession>>,
    #[cfg(target_os = "macos")]
    keystroke_monitor: Mutex<Option<platform::macos::KeystrokeMonitor>>,
    watcher: Mutex<Option<RecommendedWatcher>>,
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

    /// Stop the engine (alias for `pause`).
    pub fn stop(&self) -> Result<()> {
        self.pause()
    }

    /// Pause monitoring: stop file watcher and keystroke capture.
    pub fn pause(&self) -> Result<()> {
        self.inner.running.store(false, Ordering::SeqCst);
        *self.inner.watcher.lock_recover() = None;
        #[cfg(target_os = "macos")]
        {
            *self.inner.keystroke_monitor.lock_recover() = None;
        }

        let mut status = self.inner.status.lock_recover();
        status.running = false;
        Ok(())
    }

    /// Resume monitoring after a pause, restarting watchers and capture.
    pub fn resume(&self) -> Result<()> {
        if self.inner.status.lock_recover().running {
            return Ok(());
        }

        self.inner.running.store(true, Ordering::SeqCst);

        #[cfg(target_os = "macos")]
        {
            let monitor =
                platform::macos::KeystrokeMonitor::start(Arc::clone(&self.inner.jitter_session))?;
            *self.inner.keystroke_monitor.lock_recover() = Some(monitor);
        }

        let dirs = self.inner.watch_dirs.lock_recover().clone();
        start_file_watcher(&self.inner, dirs)?;

        let mut status = self.inner.status.lock_recover();
        status.running = true;
        Ok(())
    }

    /// Return a snapshot of the engine's current status.
    pub fn status(&self) -> EngineStatus {
        let mut status = self.inner.status.lock_recover().clone();
        status.jitter_samples = self.inner.jitter_session.lock_recover().samples.len() as u64;
        status
    }

    /// List all monitored files with their event counts and timestamps.
    pub fn report_files(&self) -> Result<Vec<ReportFile>> {
        let rows = self.inner.store.lock_recover().list_files()?;
        Ok(rows
            .into_iter()
            .map(|(file_path, last_ts, count)| ReportFile {
                file_path,
                last_event_timestamp_ns: last_ts,
                event_count: count as u64,
            })
            .collect())
    }

    /// Return the engine's data directory path.
    pub fn data_dir(&self) -> PathBuf {
        self.inner.data_dir.clone()
    }

    /// Apply a new configuration, restarting watchers if currently running.
    pub fn update_config(&self, mut config: CpopConfig) -> Result<()> {
        config.data_dir = self.inner.data_dir.clone();
        config.persist()?;

        *self.inner.watch_dirs.lock_recover() = config.watch_dirs.clone();
        let mut status = self.inner.status.lock_recover();
        status.watch_dirs = config.watch_dirs.clone();
        drop(status);

        if self.inner.running.load(Ordering::SeqCst) {
            self.pause()?;
            self.resume()?;
        }
        Ok(())
    }
}

fn start_file_watcher(inner: &Arc<EngineInner>, watch_dirs: Vec<PathBuf>) -> Result<()> {
    let (tx, rx) = mpsc::channel();
    let mut watcher: RecommendedWatcher = RecommendedWatcher::new(tx, notify::Config::default())?;

    for dir in &watch_dirs {
        if dir.exists() {
            watcher.watch(dir, RecursiveMode::Recursive)?;
        }
    }

    let inner_clone = Arc::clone(inner);
    std::thread::spawn(move || {
        while inner_clone.running.load(Ordering::SeqCst) {
            let event = match rx.recv() {
                Ok(event) => event,
                Err(_) => break,
            };

            if let Ok(event) = event {
                if matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                    for path in event.paths {
                        if let Err(err) = process_file_event(&inner_clone, &path) {
                            let mut status = inner_clone.status.lock_recover();
                            status.last_event_timestamp_ns = Some(now_ns());
                            log::error!("file event error: {err}");
                        }
                    }
                }
            }
        }
    });

    *inner.watcher.lock_recover() = Some(watcher);
    Ok(())
}

/// If the file is inside a known project bundle (.scriv, .scrivx),
/// return the bundle path instead. Otherwise return the original path.
fn resolve_project_path(path: &Path) -> PathBuf {
    let mut current = path.parent();
    while let Some(parent) = current {
        if let Some(ext) = parent.extension() {
            if ext == "scriv" || ext == "scrivx" {
                return parent.to_path_buf();
            }
        }
        current = parent.parent();
    }
    path.to_path_buf()
}

fn process_file_event(inner: &Arc<EngineInner>, path: &Path) -> Result<()> {
    if !path.is_file() {
        return Ok(());
    }

    let metadata = fs::metadata(path)?;
    let file_size = metadata.len() as i64;

    // Hash the actual file that changed, not the bundle directory
    let content_hash = crate::crypto::hash_file(path)?;

    // Group events under the project bundle path when inside .scriv/.scrivx
    let resolved_path = resolve_project_path(path);

    // Rename detection: if this content hash was recently seen at a different path
    // that no longer exists, treat it as a file rename.
    {
        let now = now_ns();
        let mut hash_map = inner.content_hash_map.lock_recover();

        if let Some((old_path, ts)) = hash_map.get(&content_hash) {
            let is_different_path = *old_path != resolved_path;
            let is_recent = (now - ts) < RENAME_WINDOW_NS;
            let old_gone = !old_path.exists();

            if is_different_path && is_recent && old_gone {
                let old_str = old_path.to_string_lossy().to_string();
                let new_str = resolved_path.to_string_lossy().to_string();
                log::info!("File rename detected: {} \u{2192} {}", old_str, new_str);

                // Migrate stored events to the new path
                if let Ok(count) = inner
                    .store
                    .lock_recover()
                    .update_file_path(&old_str, &new_str)
                {
                    log::info!("Updated {count} events from old path to new path");
                }

                // Copy file_sizes entry from old path to new path
                let mut sizes = inner.file_sizes.lock_recover();
                if let Some(&old_size) = sizes.get(&old_path.to_path_buf()) {
                    sizes.insert(resolved_path.clone(), old_size);
                    sizes.remove(&old_path.to_path_buf());
                }
            }
        }

        // Record this hash → path mapping
        hash_map.insert(content_hash, (resolved_path.clone(), now));

        // Evict stale entries if the map is too large
        if hash_map.len() > CONTENT_HASH_MAP_MAX_ENTRIES {
            let cutoff = now - RENAME_WINDOW_NS;
            hash_map.retain(|_, (_, ts)| *ts >= cutoff);
        }
    }

    let size_delta = {
        let mut map = inner.file_sizes.lock_recover();
        let previous = map
            .insert(resolved_path.clone(), file_size)
            .unwrap_or(file_size);
        i32::try_from((file_size - previous).clamp(i32::MIN as i64, i32::MAX as i64)).unwrap_or(
            if file_size > previous {
                i32::MAX
            } else {
                i32::MIN
            },
        )
    };

    let (forensic_score, is_paste) = {
        let mut session = inner.jitter_session.lock_recover();
        if session.samples.is_empty() {
            // No keystrokes but file grew significantly → paste or dictation
            let is_paste = size_delta > 20;
            (1.0, is_paste)
        } else {
            let cadence = crate::forensics::analyze_cadence(&session.samples);
            let score = crate::forensics::compute_cadence_score(&cadence);

            let keystroke_count = session.samples.len() as i64;
            // Bytes-per-keystroke ratio: normal typing ≈ 1 byte/key, paste >> 3
            let avg_bytes_per_key = if keystroke_count > 0 {
                i64::from(size_delta).max(0) as f64 / keystroke_count as f64
            } else {
                0.0
            };
            let is_paste = (avg_bytes_per_key > 3.0 && size_delta > 20)
                || (i64::from(size_delta) > (keystroke_count * 5) && size_delta > 50);

            session.samples.clear();

            (score, is_paste)
        }
    };

    let mut event = SecureEvent {
        id: None,
        device_id: inner.device_id,
        machine_id: inner.machine_id.clone(),
        timestamp_ns: now_ns(),
        file_path: resolved_path.to_string_lossy().to_string(),
        content_hash,
        file_size,
        size_delta,
        previous_hash: [0u8; 32],
        event_hash: [0u8; 32],
        context_type: None,
        context_note: None,
        vdf_input: None,
        vdf_output: None,
        vdf_iterations: 0,
        forensic_score,
        is_paste,
        hardware_counter: None,
        input_method: None,
    };

    inner.store.lock_recover().add_secure_event(&mut event)?;

    let mut status = inner.status.lock_recover();
    status.events_written += 1;
    status.last_event_timestamp_ns = Some(event.timestamp_ns);
    Ok(())
}

fn load_or_create_device_identity(data_dir: &Path) -> Result<([u8; 16], String)> {
    let path = data_dir.join("device.json");

    if let Ok(Some(identity)) = SecureStorage::load_device_identity() {
        return Ok(identity);
    }

    if path.exists() {
        let content = fs::read_to_string(&path)?;
        let value: serde_json::Value = serde_json::from_str(&content)?;
        let device_hex = value["device_id"].as_str().unwrap_or_default();
        let machine_id = value["machine_id"].as_str().unwrap_or_default().to_string();
        let decoded = hex::decode(device_hex)?;
        let device_id: [u8; 16] = decoded
            .try_into()
            .map_err(|_| crate::error::Error::validation("device_id must be exactly 16 bytes"))?;

        if let Err(e) = SecureStorage::save_device_identity(&device_id, &machine_id) {
            log::warn!("Failed to migrate device identity to secure storage: {e}");
        } else {
            let _ = fs::remove_file(&path);
        }

        return Ok((device_id, machine_id));
    }

    let mut device_id = [0u8; 16];
    rand::rng().fill_bytes(&mut device_id);
    let machine_id = sysinfo::System::host_name().unwrap_or_else(|| "unknown".to_string());

    if let Err(e) = SecureStorage::save_device_identity(&device_id, &machine_id) {
        log::warn!("Secure storage unavailable ({e}), using file-based storage");
        let payload = serde_json::json!({
            "device_id": hex::encode(device_id),
            "machine_id": machine_id,
        });
        fs::write(&path, payload.to_string())?;
        if let Err(e) = crate::crypto::restrict_permissions(&path, 0o600) {
            log::warn!("Failed to set device identity permissions: {}", e);
        }
    }

    Ok((device_id, machine_id))
}

fn load_or_create_hmac_key(data_dir: &Path) -> Result<Vec<u8>> {
    let path = data_dir.join("hmac.key");

    if let Ok(Some(key)) = SecureStorage::load_hmac_key() {
        return Ok(key.to_vec());
    }

    if path.exists() {
        let key = fs::read(&path)?;
        if key.len() == 32 {
            if let Err(e) = SecureStorage::save_hmac_key(&key) {
                log::warn!("Failed to migrate HMAC key to secure storage: {e}");
            } else {
                let _ = fs::remove_file(&path);
            }
            return Ok(key);
        }
    }

    let mut key = vec![0u8; 32];
    rand::rng().fill_bytes(&mut key);

    if let Err(e) = SecureStorage::save_hmac_key(&key) {
        log::warn!("Secure storage unavailable ({e}), using file-based storage");
        fs::write(&path, &key)?;
        if let Err(e) = crate::crypto::restrict_permissions(&path, 0o600) {
            log::warn!("Failed to set HMAC key permissions: {}", e);
        }
    }

    Ok(key)
}

fn now_ns() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| {
            let nanos = d.as_nanos();
            if nanos > i64::MAX as u128 {
                (d.as_millis() as i64).saturating_mul(1_000_000)
            } else {
                nanos as i64
            }
        })
        .unwrap_or_else(|_| {
            log::warn!("SystemTime before UNIX_EPOCH in now_ns(); falling back to 0");
            0
        })
}
