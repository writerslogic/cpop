use crate::config::WitnessdConfig;
use crate::identity::SecureStorage;
use crate::jitter::SimpleJitterSession;
#[cfg(target_os = "macos")]
use crate::platform;
use crate::store::{SecureEvent, SecureStore};
use anyhow::{anyhow, Context, Result};
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use rand::RngCore;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::SystemTime;

#[derive(Clone, Debug, Serialize)]
pub struct EngineStatus {
    pub running: bool,
    pub accessibility_trusted: bool,
    pub watch_dirs: Vec<PathBuf>,
    pub events_written: u64,
    pub jitter_samples: u64,
    pub last_event_timestamp_ns: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ReportFile {
    pub file_path: String,
    pub last_event_timestamp_ns: i64,
    pub event_count: u64,
}

pub struct Engine {
    inner: Arc<EngineInner>,
}

struct EngineInner {
    running: AtomicBool,
    status: Mutex<EngineStatus>,
    store: Mutex<SecureStore>,
    jitter_session: Arc<Mutex<SimpleJitterSession>>,
    #[cfg(target_os = "macos")]
    keystroke_monitor: Mutex<Option<platform::macos::KeystrokeMonitor>>,
    watcher: Mutex<Option<RecommendedWatcher>>,
    file_sizes: Mutex<HashMap<PathBuf, i64>>,
    device_id: [u8; 16],
    machine_id: String,
    watch_dirs: Mutex<Vec<PathBuf>>,
    data_dir: PathBuf,
}

impl Engine {
    pub fn start(config: WitnessdConfig) -> Result<Self> {
        fs::create_dir_all(&config.data_dir)
            .with_context(|| format!("Failed to create data dir: {:?}", config.data_dir))?;

        #[cfg(target_os = "macos")]
        let accessibility_trusted = platform::macos::check_accessibility_permissions()
            || std::env::var("WITNESSD_SKIP_PERMISSIONS").is_ok();
        #[cfg(not(target_os = "macos"))]
        let accessibility_trusted = true; // No equivalent permissions on Linux/Windows
        #[cfg(target_os = "macos")]
        let input_trusted = platform::macos::check_input_monitoring_permissions()
            || std::env::var("WITNESSD_SKIP_PERMISSIONS").is_ok();
        #[cfg(not(target_os = "macos"))]
        let input_trusted = true;

        if !accessibility_trusted || !input_trusted {
            return Err(anyhow!(
                "Accessibility and Input Monitoring permissions required for global key timing"
            ));
        }

        let (device_id, machine_id) = load_or_create_device_identity(&config.data_dir)?;
        let hmac_key = load_or_create_hmac_key(&config.data_dir)?;
        let store_path = config.data_dir.join("witnessd.sqlite3");
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
            device_id,
            machine_id,
            watch_dirs: Mutex::new(config.watch_dirs.clone()),
            data_dir: config.data_dir.clone(),
        });

        #[cfg(target_os = "macos")]
        if std::env::var("WITNESSD_SKIP_PERMISSIONS").is_err() {
            let monitor =
                platform::macos::KeystrokeMonitor::start(Arc::clone(&inner.jitter_session))?;
            *inner.keystroke_monitor.lock().unwrap() = Some(monitor);
        }

        start_file_watcher(&inner, config.watch_dirs)?;

        Ok(Self { inner })
    }

    pub fn stop(&self) -> Result<()> {
        self.pause()
    }

    pub fn pause(&self) -> Result<()> {
        self.inner.running.store(false, Ordering::SeqCst);
        *self.inner.watcher.lock().unwrap() = None;
        #[cfg(target_os = "macos")]
        {
            *self.inner.keystroke_monitor.lock().unwrap() = None;
        }

        let mut status = self.inner.status.lock().unwrap();
        status.running = false;
        Ok(())
    }

    pub fn resume(&self) -> Result<()> {
        if self.inner.status.lock().unwrap().running {
            return Ok(());
        }

        self.inner.running.store(true, Ordering::SeqCst);

        #[cfg(target_os = "macos")]
        {
            let monitor =
                platform::macos::KeystrokeMonitor::start(Arc::clone(&self.inner.jitter_session))?;
            *self.inner.keystroke_monitor.lock().unwrap() = Some(monitor);
        }

        let dirs = self.inner.watch_dirs.lock().unwrap().clone();
        start_file_watcher(&self.inner, dirs)?;

        let mut status = self.inner.status.lock().unwrap();
        status.running = true;
        Ok(())
    }

    pub fn status(&self) -> EngineStatus {
        let mut status = self.inner.status.lock().unwrap().clone();
        status.jitter_samples = self.inner.jitter_session.lock().unwrap().samples.len() as u64;
        status
    }

    pub fn report_files(&self) -> Result<Vec<ReportFile>> {
        let rows = self.inner.store.lock().unwrap().list_files()?;
        Ok(rows
            .into_iter()
            .map(|(file_path, last_ts, count)| ReportFile {
                file_path,
                last_event_timestamp_ns: last_ts,
                event_count: count as u64,
            })
            .collect())
    }

    pub fn data_dir(&self) -> PathBuf {
        self.inner.data_dir.clone()
    }

    pub fn update_config(&self, mut config: WitnessdConfig) -> Result<()> {
        config.data_dir = self.inner.data_dir.clone();
        config.persist()?;

        *self.inner.watch_dirs.lock().unwrap() = config.watch_dirs.clone();
        let mut status = self.inner.status.lock().unwrap();
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
                            let mut status = inner_clone.status.lock().unwrap();
                            status.last_event_timestamp_ns = Some(now_ns());
                            eprintln!("witnessd: file event error: {err}");
                        }
                    }
                }
            }
        }
    });

    *inner.watcher.lock().unwrap() = Some(watcher);
    Ok(())
}

fn process_file_event(inner: &Arc<EngineInner>, path: &Path) -> Result<()> {
    if !path.is_file() {
        return Ok(());
    }

    let metadata = fs::metadata(path)?;
    let file_size = metadata.len() as i64;

    let content = fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&content);
    let content_hash: [u8; 32] = hasher.finalize().into();

    let size_delta = {
        let mut map = inner.file_sizes.lock().unwrap();
        let previous = map
            .insert(path.to_path_buf(), file_size)
            .unwrap_or(file_size);
        (file_size - previous) as i32
    };

    let mut event = SecureEvent {
        id: None,
        device_id: inner.device_id,
        machine_id: inner.machine_id.clone(),
        timestamp_ns: now_ns(),
        file_path: path.to_string_lossy().to_string(),
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
        forensic_score: 1.0,
        is_paste: false,
    };

    inner
        .store
        .lock()
        .unwrap()
        .insert_secure_event(&mut event)?;

    let mut status = inner.status.lock().unwrap();
    status.events_written += 1;
    status.last_event_timestamp_ns = Some(event.timestamp_ns);
    Ok(())
}

fn load_or_create_device_identity(data_dir: &Path) -> Result<([u8; 16], String)> {
    let path = data_dir.join("device.json");
    if path.exists() {
        let content = fs::read_to_string(&path)?;
        let value: serde_json::Value = serde_json::from_str(&content)?;
        let device_hex = value["device_id"].as_str().unwrap_or_default();
        let machine_id = value["machine_id"].as_str().unwrap_or_default().to_string();
        let mut device_id = [0u8; 16];
        let decoded = hex::decode(device_hex)?;
        device_id.copy_from_slice(&decoded[..16]);
        return Ok((device_id, machine_id));
    }

    let mut device_id = [0u8; 16];
    rand::rng().fill_bytes(&mut device_id);
    let machine_id = sysinfo::System::host_name().unwrap_or_else(|| "unknown".to_string());

    let payload = serde_json::json!({
        "device_id": hex::encode(device_id),
        "machine_id": machine_id,
    });
    fs::write(&path, payload.to_string())?;

    Ok((
        device_id,
        payload["machine_id"]
            .as_str()
            .unwrap_or("unknown")
            .to_string(),
    ))
}

fn load_or_create_hmac_key(data_dir: &Path) -> Result<Vec<u8>> {
    let path = data_dir.join("hmac.key");

    // 1. Try loading from secure storage
    if let Ok(Some(key)) = SecureStorage::load_hmac_key() {
        return Ok(key);
    }

    // 2. Check for file (fallback or legacy)
    if path.exists() {
        let key = fs::read(&path)?;
        if key.len() == 32 {
            // Try to migrate to secure storage (ignore errors for headless/CI environments)
            if let Err(e) = SecureStorage::save_hmac_key(&key) {
                eprintln!(
                    "Warning: Failed to migrate HMAC key to secure storage: {}",
                    e
                );
            } else {
                // Delete file after successful migration
                let _ = fs::remove_file(&path);
            }
            return Ok(key);
        }
    }

    // 3. Generate new key
    let mut key = vec![0u8; 32];
    rand::rng().fill_bytes(&mut key);

    // Try to save to secure storage, fall back to file if unavailable
    if let Err(e) = SecureStorage::save_hmac_key(&key) {
        eprintln!(
            "Warning: Secure storage unavailable ({}), using file-based storage",
            e
        );
        fs::write(&path, &key)?;
    }

    Ok(key)
}

fn now_ns() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}
