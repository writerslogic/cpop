// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::error::{Result, SentinelError};
use super::focus::SentinelFocusTracker;
use super::helpers::*;
use super::shadow::ShadowManager;
use super::types::*;
use crate::config::SentinelConfig;
use crate::crypto::ObfuscatedString;
use crate::ipc::IpcErrorCode;
use crate::platform::{KeystrokeCapture, MouseCapture};
use crate::wal::{EntryType, Wal};
use crate::{MutexRecover, RwLockRecover};
use ed25519_dalek::{Signer, SigningKey};
use sha2::Digest;
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};
use tokio::sync::{broadcast, mpsc};
use tokio::time::interval;
use zeroize::Zeroize;

/// Core sentinel daemon for document focus tracking and session management.
pub struct Sentinel {
    pub(crate) config: Arc<SentinelConfig>,
    pub(crate) sessions: Arc<RwLock<HashMap<String, DocumentSession>>>,
    pub(crate) shadow: Arc<ShadowManager>,
    pub(crate) current_focus: Arc<RwLock<Option<String>>>,
    pub(crate) running: Arc<AtomicBool>,
    pub(crate) signing_key: Arc<RwLock<Option<SigningKey>>>,
    pub(crate) activity_accumulator:
        Arc<RwLock<crate::fingerprint::ActivityFingerprintAccumulator>>,
    session_events_tx: broadcast::Sender<SessionEvent>,
    pub(crate) shutdown_tx: Arc<Mutex<Option<mpsc::Sender<()>>>>,
    voice_collector: Arc<RwLock<Option<crate::fingerprint::VoiceCollector>>>,
    mouse_idle_stats: Arc<RwLock<crate::platform::MouseIdleStats>>,
    mouse_stego_engine: Arc<RwLock<crate::platform::MouseStegoEngine>>,
    session_nonce: Arc<RwLock<Option<[u8; 32]>>>,
    bridge_threads: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>>,
}

impl Sentinel {
    pub fn new(config: SentinelConfig) -> Result<Self> {
        config.validate().map_err(SentinelError::Anyhow)?;
        config.ensure_directories().map_err(SentinelError::Anyhow)?;

        let shadow = ShadowManager::new(&config.shadow_dir)?;
        let (session_events_tx, _) = broadcast::channel(100);

        let mut mouse_stego_seed = [0u8; 32];
        use rand::RngCore;
        rand::rng().fill_bytes(&mut mouse_stego_seed);

        Ok(Self {
            config: Arc::new(config),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            shadow: Arc::new(shadow),
            current_focus: Arc::new(RwLock::new(None)),
            running: Arc::new(AtomicBool::new(false)),
            signing_key: Arc::new(RwLock::new(None)),
            session_events_tx,
            shutdown_tx: Arc::new(Mutex::new(None)),
            activity_accumulator: Arc::new(RwLock::new(
                crate::fingerprint::ActivityFingerprintAccumulator::new(),
            )),
            voice_collector: Arc::new(RwLock::new(None)),
            mouse_idle_stats: Arc::new(RwLock::new(crate::platform::MouseIdleStats::new())),
            mouse_stego_engine: Arc::new(RwLock::new(crate::platform::MouseStegoEngine::new(
                mouse_stego_seed,
            ))),
            session_nonce: Arc::new(RwLock::new(None)),
            bridge_threads: Arc::new(Mutex::new(Vec::new())),
        })
    }

    pub fn get_or_generate_nonce(&self) -> [u8; 32] {
        let mut nonce_lock = self.session_nonce.write_recover();
        if let Some(nonce) = *nonce_lock {
            nonce
        } else {
            let mut nonce = [0u8; 32];
            use rand::RngCore;
            rand::rng().fill_bytes(&mut nonce);
            *nonce_lock = Some(nonce);
            nonce
        }
    }

    pub fn reset_nonce(&self) {
        let mut nonce_lock = self.session_nonce.write_recover();
        *nonce_lock = None;
    }

    pub fn enable_voice_fingerprinting(&self) {
        let mut collector = self.voice_collector.write_recover();
        if collector.is_none() {
            *collector = Some(crate::fingerprint::VoiceCollector::new());
        }
    }

    pub fn disable_voice_fingerprinting(&self) {
        let mut collector = self.voice_collector.write_recover();
        *collector = None;
    }

    pub fn current_activity_fingerprint(&self) -> crate::fingerprint::ActivityFingerprint {
        self.activity_accumulator
            .read_recover()
            .current_fingerprint()
    }

    pub fn current_voice_fingerprint(&self) -> Option<crate::fingerprint::VoiceFingerprint> {
        self.voice_collector
            .read_recover()
            .as_ref()
            .map(|c| c.current_fingerprint())
    }

    pub fn mouse_idle_stats(&self) -> crate::platform::MouseIdleStats {
        self.mouse_idle_stats.read_recover().clone()
    }

    pub fn reset_mouse_idle_stats(&self) {
        *self.mouse_idle_stats.write_recover() = crate::platform::MouseIdleStats::new();
    }

    pub fn mouse_stego_engine(&self) -> &Arc<RwLock<crate::platform::MouseStegoEngine>> {
        &self.mouse_stego_engine
    }

    fn update_mouse_stego_seed(&self) {
        let guard = self.signing_key.read_recover();
        if let Some(key) = guard.as_ref() {
            let mut seed = key.to_bytes();
            let mut engine = self.mouse_stego_engine.write_recover();
            engine.reset();
            *engine = crate::platform::MouseStegoEngine::new(seed);
            seed.zeroize();
        }
    }

    pub fn set_signing_key(&self, key: SigningKey) {
        *self.signing_key.write_recover() = Some(key);
        self.update_mouse_stego_seed();
    }

    pub fn set_hmac_key(&self, key: Vec<u8>) {
        if key.len() == 32 {
            let mut bytes: [u8; 32] = match key.try_into() {
                Ok(b) => b,
                Err(_) => {
                    log::error!("HMAC key must be exactly 32 bytes");
                    return;
                }
            };
            *self.signing_key.write_recover() = Some(SigningKey::from_bytes(&bytes));
            bytes.zeroize();
            self.update_mouse_stego_seed();
        } else {
            log::warn!("HMAC key length {} is not 32 bytes, ignoring", key.len());
        }
    }

    pub async fn start(&self) -> Result<()> {
        if self.running.swap(true, Ordering::SeqCst) {
            return Err(SentinelError::AlreadyRunning);
        }

        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        *self.shutdown_tx.lock_recover() = Some(shutdown_tx);

        #[cfg(target_os = "macos")]
        let focus_monitor: Box<dyn SentinelFocusTracker> =
            super::macos_focus::MacOSFocusMonitor::new_monitor(self.config.clone());

        #[cfg(target_os = "windows")]
        let focus_monitor: Box<dyn SentinelFocusTracker> =
            super::windows_focus::WindowsFocusMonitor::new_monitor(self.config.clone());

        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        let focus_monitor: Box<dyn SentinelFocusTracker> = Box::new(
            super::stub_focus::StubSentinelFocusTracker::new(self.config.clone()),
        );

        let (available, reason) = focus_monitor.available();
        if !available {
            self.running.store(false, Ordering::SeqCst);
            return Err(SentinelError::NotAvailable(reason));
        }

        focus_monitor.start()?;

        let sessions = Arc::clone(&self.sessions);
        let current_focus = Arc::clone(&self.current_focus);
        let config = self.config.clone();
        let shadow = Arc::clone(&self.shadow);
        let signing_key = Arc::clone(&self.signing_key);
        let session_events_tx = self.session_events_tx.clone();
        let running = Arc::clone(&self.running);
        let debounce_duration = Duration::from_millis(config.debounce_duration_ms);
        let idle_timeout = Duration::from_secs(config.idle_timeout_secs);
        let wal_dir = config.wal_dir.clone();

        let mut focus_rx = focus_monitor.focus_events()?;
        let mut change_rx = focus_monitor.change_events()?;

        let (keystroke_tx, mut keystroke_rx) =
            tokio::sync::mpsc::channel::<crate::platform::KeystrokeEvent>(1000);
        let keystroke_running = Arc::clone(&running);

        #[cfg(target_os = "macos")]
        let keystroke_capture_result = crate::platform::macos::MacOSKeystrokeCapture::new();
        #[cfg(target_os = "windows")]
        let keystroke_capture_result = crate::platform::windows::WindowsKeystrokeCapture::new();
        #[cfg(target_os = "linux")]
        let keystroke_capture_result = crate::platform::linux::LinuxKeystrokeCapture::new();
        #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
        let keystroke_capture_result: anyhow::Result<
            Box<dyn crate::platform::KeystrokeCapture>,
        > = Err(anyhow::anyhow!(
            "Keystroke capture not supported on this platform"
        ));

        if let Ok(mut keystroke_capture) = keystroke_capture_result {
            if let Ok(sync_rx) = keystroke_capture.start() {
                let sync_rx: std::sync::mpsc::Receiver<crate::platform::KeystrokeEvent> = sync_rx;
                let handle = std::thread::spawn(move || {
                    while keystroke_running.load(Ordering::SeqCst) {
                        match sync_rx.recv_timeout(std::time::Duration::from_millis(100)) {
                            Ok(event) => {
                                if keystroke_tx.blocking_send(event).is_err() {
                                    log::debug!("keystroke channel full, dropping event");
                                }
                            }
                            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                        }
                    }
                });
                self.bridge_threads.lock_recover().push(handle);
            }
        }

        let (mouse_tx, mut mouse_rx) =
            tokio::sync::mpsc::channel::<crate::platform::MouseEvent>(1000);
        let mouse_running = Arc::clone(&running);

        #[cfg(target_os = "macos")]
        let mouse_capture_result = crate::platform::macos::MacOSMouseCapture::new();
        #[cfg(target_os = "linux")]
        let mouse_capture_result = crate::platform::linux::LinuxMouseCapture::new();
        #[cfg(target_os = "windows")]
        let mouse_capture_result = crate::platform::windows::WindowsMouseCapture::new();

        if let Ok(mut mouse_capture) = mouse_capture_result {
            if let Ok(sync_rx) = mouse_capture.start() {
                let sync_rx: std::sync::mpsc::Receiver<crate::platform::MouseEvent> = sync_rx;
                let handle = std::thread::spawn(move || {
                    while mouse_running.load(Ordering::SeqCst) {
                        match sync_rx.recv_timeout(std::time::Duration::from_millis(100)) {
                            Ok(event) => {
                                if mouse_tx.blocking_send(event).is_err() {
                                    log::debug!("mouse channel full, dropping event");
                                }
                            }
                            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                        }
                    }
                });
                self.bridge_threads.lock_recover().push(handle);
            }
        }

        let activity_accumulator = Arc::clone(&self.activity_accumulator);
        let voice_collector = Arc::clone(&self.voice_collector);
        let mouse_idle_stats = Arc::clone(&self.mouse_idle_stats);
        let mouse_stego_engine = Arc::clone(&self.mouse_stego_engine);

        tokio::spawn(async move {
            let mut debounce_timer: Option<tokio::time::Instant> = None;
            let mut pending_focus: Option<FocusEvent> = None;
            let mut idle_check_interval = interval(Duration::from_secs(60));
            let mut last_keystroke_time = std::time::Instant::now();

            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        break;
                    }

                    Some(event) = keystroke_rx.recv() => {
                        let sample = crate::jitter::SimpleJitterSample {
                            timestamp_ns: event.timestamp_ns,
                            duration_since_last_ns: 0,
                            zone: event.zone,
                        };
                        // RwLock::write() per keystroke: at human typing speeds (5-10 Hz)
                        // contention is negligible. Revisit only if profiling shows otherwise.
                        activity_accumulator.write_recover().add_sample(&sample);

                        if let Some(ref mut collector) = *voice_collector.write_recover() {
                            collector.record_keystroke(event.keycode, event.char_value);
                        }

                        last_keystroke_time = std::time::Instant::now();
                    }

                    Some(event) = mouse_rx.recv() => {
                        let is_during_typing = last_keystroke_time.elapsed() < Duration::from_secs(2);
                        if is_during_typing && event.is_micro_movement() {
                            mouse_idle_stats.write_recover().record(&event);
                        }

                        mouse_stego_engine.write_recover().next_jitter();
                    }

                    Some(event) = focus_rx.recv() => {
                        pending_focus = Some(event);
                        debounce_timer = Some(tokio::time::Instant::now() + debounce_duration);
                    }

                    Some(event) = change_rx.recv() => {
                            handle_change_event_sync(
                                &event,
                                &sessions,
                                &signing_key,
                                &wal_dir,
                                &session_events_tx,
                            );

                    }

                    _ = idle_check_interval.tick() => {
                        check_idle_sessions_sync(&sessions, idle_timeout, &session_events_tx);
                    }

                    _ = async {
                        if let Some(deadline) = debounce_timer {
                            tokio::time::sleep_until(deadline).await;
                            true
                        } else {
                            std::future::pending::<bool>().await
                        }
                    } => {
                        if let Some(event) = pending_focus.take() {
                            handle_focus_event_sync(
                                event,
                                &sessions,
                                &config,
                                &shadow,
                                &signing_key,
                                &current_focus,
                                &wal_dir,
                                &session_events_tx,
                            );
                        }
                        debounce_timer = None;
                    }
                }

                if !running.load(Ordering::SeqCst) {
                    break;
                }
            }

            if let Err(e) = focus_monitor.stop() {
                log::debug!("focus monitor stop: {e}");
            }
            end_all_sessions_sync(&sessions, &shadow, &session_events_tx);
        });

        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        if !self.running.swap(false, Ordering::SeqCst) {
            return Ok(());
        }

        // take() under lock, then await outside to avoid holding lock across .await
        let tx = self.shutdown_tx.lock_recover().take();
        if let Some(tx) = tx {
            let _ = tx.send(()).await;
        }

        let handles: Vec<_> = self.bridge_threads.lock_recover().drain(..).collect();
        for handle in handles {
            let _ = handle.join();
        }

        self.shadow.cleanup_all();

        Ok(())
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    pub fn sessions(&self) -> Vec<DocumentSession> {
        self.sessions.read_recover().values().cloned().collect()
    }

    pub fn session(&self, path: &str) -> Result<DocumentSession> {
        self.sessions
            .read_recover()
            .get(path)
            .cloned()
            .ok_or_else(|| SentinelError::SessionNotFound(path.to_string()))
    }

    pub fn current_focus(&self) -> Option<String> {
        self.current_focus.read_recover().clone()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<SessionEvent> {
        self.session_events_tx.subscribe()
    }

    pub fn create_shadow(&self, app_name: &str, window_title: &str) -> Result<String> {
        self.shadow.create(app_name, window_title)
    }

    pub fn update_shadow_content(&self, shadow_id: &str, content: &[u8]) -> Result<()> {
        self.shadow.update(shadow_id, content)
    }

    pub fn available(&self) -> (bool, String) {
        #[cfg(target_os = "macos")]
        {
            if super::macos_focus::check_accessibility_permissions() {
                (true, "macOS Accessibility API available".to_string())
            } else {
                (false, "Accessibility permission required".to_string())
            }
        }

        #[cfg(target_os = "windows")]
        {
            (true, "Windows Focus API available".to_string())
        }

        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            (false, "Sentinel not available on this platform".to_string())
        }
    }

    pub fn start_witnessing(
        &self,
        file_path: &Path,
    ) -> std::result::Result<(), (IpcErrorCode, String)> {
        if !file_path.exists() {
            return Err((
                IpcErrorCode::FileNotFound,
                format!("File not found: {}", file_path.display()),
            ));
        }

        let path_str = file_path.to_string_lossy().to_string();

        // Single write lock for check+insert to avoid TOCTOU race
        let mut sessions = self.sessions.write_recover();
        if sessions.contains_key(&path_str) {
            return Err((
                IpcErrorCode::AlreadyTracking,
                format!("Already tracking: {}", file_path.display()),
            ));
        }
        let mut session = DocumentSession::new(
            path_str.clone(),
            "cli".to_string(),          // app_bundle_id for CLI-initiated tracking
            "writerslogic".to_string(), // app_name
            ObfuscatedString::new(&path_str),
        );

        if let Ok(hash) = compute_file_hash(&path_str) {
            session.initial_hash = Some(hash.clone());
            session.current_hash = Some(hash);
        }

        let wal_path = self
            .config
            .wal_dir
            .join(format!("{}.wal", session.session_id));
        let mut session_id_bytes = [0u8; 32];
        let hex_str = &session.session_id[..64.min(session.session_id.len())];
        if hex::decode_to_slice(hex_str, &mut session_id_bytes).is_ok() {
            if let Some(key) = self.signing_key.read_recover().clone() {
                if let Ok(wal) = Wal::open(&wal_path, session_id_bytes, key) {
                    let payload = create_session_start_payload(&session);
                    if let Err(e) = wal.append(EntryType::SessionStart, payload) {
                        log::warn!(
                            "WAL append failed for session {}: {}",
                            session.session_id,
                            e
                        );
                    }
                }
            } else {
                log::warn!(
                    "Signing key not initialized, skipping WAL for session {}",
                    session.session_id
                );
            }
        } else {
            log::warn!(
                "Invalid session ID hex '{}', skipping WAL",
                session.session_id
            );
        }

        if self
            .session_events_tx
            .send(SessionEvent {
                event_type: SessionEventType::Started,
                session_id: session.session_id.clone(),
                document_path: path_str.clone(),
                timestamp: SystemTime::now(),
            })
            .is_err()
        {
            log::debug!("no session event listeners for Started");
        }

        sessions.insert(path_str, session);
        Ok(())
    }

    pub fn stop_witnessing(
        &self,
        file_path: &Path,
    ) -> std::result::Result<(), (IpcErrorCode, String)> {
        let path_str = file_path.to_string_lossy().to_string();

        let session = self.sessions.write_recover().remove(&path_str);

        if let Some(session) = session {
            if self
                .session_events_tx
                .send(SessionEvent {
                    event_type: SessionEventType::Ended,
                    session_id: session.session_id,
                    document_path: path_str,
                    timestamp: SystemTime::now(),
                })
                .is_err()
            {
                log::debug!("no session event listeners for Ended");
            }

            if let Some(shadow_id) = session.shadow_id {
                if let Err(e) = self.shadow.delete(&shadow_id) {
                    log::warn!("shadow buffer delete failed for {shadow_id}: {e}");
                }
            }

            if let Err(e) = self.update_baseline() {
                log::error!("Failed to update baseline: {}", e);
            }

            Ok(())
        } else {
            Err((
                IpcErrorCode::NotTracking,
                format!("Not tracking: {}", file_path.display()),
            ))
        }
    }

    pub fn tracked_files(&self) -> Vec<String> {
        self.sessions.read_recover().keys().cloned().collect()
    }

    pub fn start_time(&self) -> Option<SystemTime> {
        None
    }

    pub fn update_baseline(&self) -> anyhow::Result<()> {
        let summary = self
            .activity_accumulator
            .read_recover()
            .to_session_summary();
        if summary.keystroke_count < 10 {
            return Ok(());
        }

        let guard = self.signing_key.read_recover();
        let signing_key = guard
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("signing key not initialized"))?;
        let public_key = signing_key.verifying_key().to_bytes();
        let mut hasher = sha2::Sha256::new();
        hasher.update(public_key);
        let identity_fingerprint = hasher.finalize().to_vec();

        let db_path = self.config.writerslogic_dir.join("events.db");
        let hmac_key = crate::crypto::derive_hmac_key(&signing_key.to_bytes());
        let store = crate::store::SecureStore::open(&db_path, hmac_key)?;

        let current_digest =
            if let Some((cbor, _)) = store.get_baseline_digest(&identity_fingerprint)? {
                serde_json::from_slice::<wld_protocol::baseline::BaselineDigest>(&cbor)?
            } else {
                crate::baseline::compute_initial_digest(identity_fingerprint.clone())
            };

        let updated_digest = crate::baseline::update_digest(current_digest, &summary);

        let digest_cbor = serde_json::to_vec(&updated_digest)?;
        let signature = signing_key.sign(&digest_cbor);

        store.save_baseline_digest(&identity_fingerprint, &digest_cbor, &signature.to_bytes())?;

        log::info!(
            "Authorship baseline updated. Tier: {:?}",
            updated_digest.confidence_tier
        );
        Ok(())
    }
}
