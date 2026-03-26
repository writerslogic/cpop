// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

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
use std::time::{Duration, SystemTime};

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

    /// Stop the engine (alias for `pause`).
    pub fn stop(&self) -> Result<()> {
        self.pause()
    }

    /// Pause monitoring: stop file watcher and keystroke capture.
    pub fn pause(&self) -> Result<()> {
        self.inner.running.store(false, Ordering::SeqCst);
        // Drop the watcher first so the channel closes and the thread unblocks.
        *self.inner.watcher.lock_recover() = None;
        if let Some(handle) = self.inner.watcher_thread.lock_recover().take() {
            let _ = handle.join();
        }
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
                event_count: count.max(0) as u64,
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

impl Drop for Engine {
    fn drop(&mut self) {
        self.inner.running.store(false, Ordering::SeqCst);
        // Drop the watcher first so the channel closes and the thread unblocks.
        *self.inner.watcher.lock_recover() = None;
        if let Some(handle) = self.inner.watcher_thread.lock_recover().take() {
            let _ = handle.join();
        }
    }
}

fn start_file_watcher(inner: &Arc<EngineInner>, watch_dirs: Vec<PathBuf>) -> Result<()> {
    // Drop the old watcher first so the channel closes and the thread unblocks.
    *inner.watcher.lock_recover() = None;
    if let Some(handle) = inner.watcher_thread.lock_recover().take() {
        let _ = handle.join();
    }

    let (tx, rx) = mpsc::channel();
    let mut watcher: RecommendedWatcher = RecommendedWatcher::new(tx, notify::Config::default())?;

    for dir in &watch_dirs {
        if dir.exists() {
            watcher.watch(dir, RecursiveMode::Recursive)?;
        }
    }

    let inner_clone = Arc::clone(inner);
    let handle = std::thread::spawn(move || {
        while inner_clone.running.load(Ordering::SeqCst) {
            let event = match rx.recv_timeout(Duration::from_millis(500)) {
                Ok(event) => event,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            };

            if let Ok(event) = event {
                if matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                    for path in event.paths {
                        if let Err(err) = process_file_event(&inner_clone, &path) {
                            log::error!("file event error: {err}");
                        }
                    }
                }
            }
        }
    });

    *inner.watcher.lock_recover() = Some(watcher);
    *inner.watcher_thread.lock_recover() = Some(handle);
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

    // Capture the event timestamp before any I/O so it reflects when the OS event arrived.
    let event_timestamp_ns = now_ns();

    // Open once: get both hash and size from the same file handle to avoid TOCTOU.
    let (content_hash, file_size_u64) = crate::crypto::hash_file_with_size(path)?;
    let file_size = file_size_u64 as i64;

    // Group events under the project bundle path when inside .scriv/.scrivx
    let resolved_path = resolve_project_path(path);

    // Rename detection: if this content hash was recently seen at a different path
    // that no longer exists, treat it as a file rename.
    {
        let now = now_ns();

        // Extract candidate rename info under the lock, then drop lock before filesystem I/O.
        let rename_candidate = {
            let hash_map = inner.content_hash_map.lock_recover();
            if let Some((old_path, ts)) = hash_map.get(&content_hash) {
                let is_different_path = *old_path != resolved_path;
                let is_recent = (now - ts) < RENAME_WINDOW_NS;
                if is_different_path && is_recent {
                    Some(old_path.clone())
                } else {
                    None
                }
            } else {
                None
            }
        };

        if let Some(old_path) = rename_candidate {
            // Filesystem check outside the lock
            if !old_path.exists() {
                let old_str = old_path.to_string_lossy().to_string();
                let new_str = resolved_path.to_string_lossy().to_string();
                log::info!("File rename detected: {} \u{2192} {}", old_str, new_str);

                // Migrate stored events to the new path
                match inner
                    .store
                    .lock_recover()
                    .update_file_path(&old_str, &new_str)
                {
                    Ok(count) => log::info!("Updated {count} events from old path to new path"),
                    Err(e) => log::warn!("Could not migrate file path: {e}"),
                }

                // Copy file_sizes entry from old path to new path
                let mut sizes = inner.file_sizes.lock_recover();
                if let Some(&old_size) = sizes.get(&old_path) {
                    sizes.insert(resolved_path.clone(), old_size);
                    sizes.remove(&old_path);
                }
            }
        }

        // Re-acquire lock for hash map update
        let mut hash_map = inner.content_hash_map.lock_recover();

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
        // Use entry so a rename migration (which already inserted the new path with the old size)
        // is not overwritten here, preserving the correct previous size for delta computation.
        let previous = *map.entry(resolved_path.clone()).or_insert(file_size);
        map.insert(resolved_path.clone(), file_size);
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

            // Intentional: each file event gets its own forensic score from the
            // samples accumulated since the last event. Clearing ensures scores
            // reflect only the inter-event typing window.
            session.samples.clear();

            (score, is_paste)
        }
    };

    let mut event = SecureEvent {
        id: None,
        device_id: inner.device_id,
        machine_id: inner.machine_id.clone(),
        timestamp_ns: event_timestamp_ns,
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
        fs::write(
            &path,
            serde_json::to_string_pretty(&payload).unwrap_or_else(|_| payload.to_string()),
        )?;
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
        log::error!(
            "HMAC key file has wrong length ({} bytes, expected 32): {}",
            key.len(),
            path.display()
        );
        return Err(anyhow!(
            "HMAC key file has wrong length ({} bytes, expected 32)",
            key.len()
        ));
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tempfile::TempDir;

    #[test]
    fn test_now_ns_returns_positive() {
        let ts = now_ns();
        assert!(
            ts > 0,
            "now_ns() should return a positive nanosecond timestamp, got {ts}"
        );
    }

    #[test]
    fn test_now_ns_monotonic_across_calls() {
        let t1 = now_ns();
        let t2 = now_ns();
        assert!(t2 >= t1, "second call should be >= first: {t2} < {t1}");
    }

    #[test]
    fn test_resolve_project_path_regular() {
        let path = Path::new("/home/user/documents/essay.docx");
        let resolved = resolve_project_path(path);
        assert_eq!(resolved, path.to_path_buf());
    }

    #[test]
    fn test_resolve_project_path_scriv() {
        let path = Path::new("/home/user/Novel.scriv/Files/Draft/chapter1.rtf");
        let resolved = resolve_project_path(path);
        assert_eq!(resolved, Path::new("/home/user/Novel.scriv"));
    }

    #[test]
    fn test_resolve_project_path_scrivx() {
        let path = Path::new("/home/user/Novel.scrivx/content/file.txt");
        let resolved = resolve_project_path(path);
        assert_eq!(resolved, Path::new("/home/user/Novel.scrivx"));
    }

    #[test]
    fn test_resolve_project_path_nested_scriv() {
        let path = Path::new("/a/b/Project.scriv/c/d/e/deep.txt");
        let resolved = resolve_project_path(path);
        assert_eq!(resolved, Path::new("/a/b/Project.scriv"));
    }

    #[test]
    fn test_resolve_project_path_no_extension() {
        let path = Path::new("/a/b/c/file.txt");
        let resolved = resolve_project_path(path);
        assert_eq!(resolved, path.to_path_buf());
    }

    #[test]
    fn test_process_file_event_size_delta() {
        // Verify size delta computation logic by exercising the file_sizes map directly
        let mut file_sizes: HashMap<PathBuf, i64> = HashMap::new();
        let path = PathBuf::from("/test/file.txt");

        // First event: delta = 0 (previous defaults to current size)
        let file_size: i64 = 100;
        let previous = file_sizes
            .insert(path.clone(), file_size)
            .unwrap_or(file_size);
        let delta = (file_size - previous) as i32;
        assert_eq!(delta, 0, "first event should have zero delta");

        // Second event: file grew
        let file_size: i64 = 150;
        let previous = file_sizes
            .insert(path.clone(), file_size)
            .unwrap_or(file_size);
        let delta = (file_size - previous) as i32;
        assert_eq!(delta, 50, "delta should reflect growth");

        // Third event: file shrank
        let file_size: i64 = 120;
        let previous = file_sizes
            .insert(path.clone(), file_size)
            .unwrap_or(file_size);
        let delta = (file_size - previous) as i32;
        assert_eq!(delta, -30, "delta should reflect shrinkage");
    }

    #[test]
    fn test_content_hash_map_eviction() {
        let mut hash_map: HashMap<[u8; 32], (PathBuf, i64)> = HashMap::new();
        let now = now_ns();

        // Insert entries older than the rename window
        let stale_ts = now - RENAME_WINDOW_NS - 1;
        for i in 0..10u8 {
            let mut key = [0u8; 32];
            key[0] = i;
            hash_map.insert(key, (PathBuf::from(format!("/old/{i}")), stale_ts));
        }

        // Insert a fresh entry
        let mut fresh_key = [0u8; 32];
        fresh_key[0] = 255;
        hash_map.insert(fresh_key, (PathBuf::from("/fresh"), now));

        assert_eq!(hash_map.len(), 11);

        // Simulate eviction logic from process_file_event
        if hash_map.len() > CONTENT_HASH_MAP_MAX_ENTRIES {
            let cutoff = now - RENAME_WINDOW_NS;
            hash_map.retain(|_, (_, ts)| *ts >= cutoff);
        }
        // Map is under the limit, so no eviction yet
        assert_eq!(hash_map.len(), 11);

        // Now fill beyond the limit and trigger eviction
        for i in 0..CONTENT_HASH_MAP_MAX_ENTRIES {
            let mut key = [0u8; 32];
            key[0..4].copy_from_slice(&(i as u32).to_be_bytes());
            hash_map.insert(key, (PathBuf::from(format!("/stale/{i}")), stale_ts));
        }
        assert!(hash_map.len() > CONTENT_HASH_MAP_MAX_ENTRIES);

        let cutoff = now - RENAME_WINDOW_NS;
        hash_map.retain(|_, (_, ts)| *ts >= cutoff);
        // Only the fresh entry should survive
        assert_eq!(hash_map.len(), 1);
        assert!(hash_map.contains_key(&fresh_key));
    }

    #[test]
    fn test_load_or_create_device_identity() {
        let dir = TempDir::new().expect("create temp dir");
        let (device_id, machine_id) =
            load_or_create_device_identity(dir.path()).expect("create device identity");

        assert_ne!(
            device_id, [0u8; 16],
            "device_id should be random, not zeros"
        );
        assert!(!machine_id.is_empty(), "machine_id should not be empty");

        // Reload should return the same identity (via file fallback)
        let (device_id2, machine_id2) =
            load_or_create_device_identity(dir.path()).expect("reload device identity");
        assert_eq!(device_id, device_id2);
        assert_eq!(machine_id, machine_id2);
    }

    #[test]
    fn test_load_or_create_hmac_key() {
        let dir = TempDir::new().expect("create temp dir");
        let key = load_or_create_hmac_key(dir.path()).expect("create HMAC key");

        assert_eq!(key.len(), 32, "HMAC key should be 32 bytes");
        assert_ne!(key, vec![0u8; 32], "HMAC key should be random, not zeros");

        // Reload should return the same key (via file fallback)
        let key2 = load_or_create_hmac_key(dir.path()).expect("reload HMAC key");
        assert_eq!(key, key2);
    }

    #[test]
    fn test_engine_start_creates_store() {
        let dir = TempDir::new().expect("create temp dir");
        let watch_dir = dir.path().join("watched");
        fs::create_dir_all(&watch_dir).expect("create watch dir");

        let data_dir = dir.path().join("data");
        std::env::set_var("CPOP_SKIP_PERMISSIONS", "1");

        let config = CpopConfig {
            data_dir: data_dir.clone(),
            watch_dirs: vec![watch_dir],
            ..CpopConfig::default()
        };

        let engine = Engine::start(config).expect("start engine");

        assert!(data_dir.exists(), "data directory should be created");
        assert!(
            data_dir.join("writerslogic.sqlite3").exists(),
            "SQLite store should be created"
        );

        drop(engine);
    }

    #[test]
    fn test_engine_status_reflects_state() {
        let dir = TempDir::new().expect("create temp dir");
        let watch_dir = dir.path().join("watched");
        fs::create_dir_all(&watch_dir).expect("create watch dir");

        std::env::set_var("CPOP_SKIP_PERMISSIONS", "1");

        let config = CpopConfig {
            data_dir: dir.path().join("data"),
            watch_dirs: vec![watch_dir.clone()],
            ..CpopConfig::default()
        };

        let engine = Engine::start(config).expect("start engine");
        let status = engine.status();

        assert!(status.running);
        assert_eq!(status.events_written, 0);
        assert_eq!(status.jitter_samples, 0);
        assert!(status.last_event_timestamp_ns.is_none());
        assert_eq!(status.watch_dirs, vec![watch_dir]);

        drop(engine);
    }

    #[test]
    fn test_engine_pause_resume() {
        let dir = TempDir::new().expect("create temp dir");
        let watch_dir = dir.path().join("watched");
        fs::create_dir_all(&watch_dir).expect("create watch dir");

        std::env::set_var("CPOP_SKIP_PERMISSIONS", "1");

        let config = CpopConfig {
            data_dir: dir.path().join("data"),
            watch_dirs: vec![watch_dir],
            ..CpopConfig::default()
        };

        let engine = Engine::start(config).expect("start engine");
        assert!(engine.status().running);

        engine.pause().expect("pause engine");
        assert!(!engine.status().running);

        engine.resume().expect("resume engine");
        assert!(engine.status().running);

        drop(engine);
    }
}
