// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::error::{Result, SentinelError};
use super::focus::SentinelFocusTracker;
use super::helpers::*;
use super::shadow::ShadowManager;
use super::types::*;
use crate::config::SentinelConfig;
use crate::platform::{KeystrokeCapture, MouseCapture};
use crate::{MutexRecover, RwLockRecover};
use ed25519_dalek::SigningKey;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};
use tokio::sync::{broadcast, mpsc};
use tokio::time::interval;
use zeroize::Zeroize;

/// Hash a file, open the secure store, and write a checkpoint event.
///
/// Returns `true` if the checkpoint was committed, `false` on any failure.
/// Extracted from the event loop to eliminate duplicate checkpoint logic
/// between the idle-timeout and periodic-checkpoint timer arms.
fn commit_checkpoint_for_path(
    path: &str,
    note: &str,
    signing_key: &Arc<RwLock<Option<SigningKey>>>,
    writersproof_dir: &std::path::Path,
) -> bool {
    let file_path = std::path::Path::new(path);
    if !file_path.exists() {
        return false;
    }
    let content_hash = match crate::crypto::hash_file(file_path) {
        Ok(h) => h,
        Err(e) => {
            log::warn!("Auto-checkpoint hash failed for {path}: {e}");
            return false;
        }
    };
    let file_size = std::fs::metadata(file_path)
        .map(|m| i64::try_from(m.len()).unwrap_or(i64::MAX))
        .unwrap_or(0);

    let mut store = {
        let guard = signing_key.read_recover();
        let sk = match guard.as_ref() {
            Some(sk) => sk,
            None => return false,
        };
        let db_path = writersproof_dir.join("events.db");
        match crate::store::open_store_with_signing_key(sk, &db_path) {
            Ok(s) => s,
            Err(e) => {
                log::warn!("Auto-checkpoint store open failed for {path}: {e}");
                return false;
            }
        }
    };

    let mut event = crate::store::SecureEvent::new(
        path.to_string(),
        content_hash,
        file_size,
        Some(note.to_string()),
    );
    match store.add_secure_event(&mut event) {
        Ok(_) => {
            log::info!("Auto-checkpoint committed for {path} ({note})");
            true
        }
        Err(e) => {
            log::warn!("Auto-checkpoint store write failed for {path}: {e}");
            false
        }
    }
}

/// Sentinel source PID for events pre-verified by CGEventTap.
///
/// Negative value distinguishes pre-verified tap events from real PIDs (>0)
/// and synthetic/injected events (0). The validation layer does not penalize
/// negative PIDs.
const CGEVENTTAP_VERIFIED_PID: i64 = -1;

/// Core sentinel daemon for document focus tracking and session management.
///
/// # Lock ordering convention (AUD-041)
///
/// When acquiring multiple locks, always acquire in this order to prevent deadlocks:
///   1. `signing_key` (RwLock)
///   2. `sessions` (RwLock)
///   3. `current_focus` (RwLock)
///   4. All other Mutex-protected fields (no ordering between them)
///
/// Never acquire `sessions` before `signing_key`.
pub struct Sentinel {
    pub(crate) config: Arc<SentinelConfig>,
    pub(crate) sessions: Arc<RwLock<HashMap<String, DocumentSession>>>,
    pub(crate) shadow: Arc<ShadowManager>,
    pub(crate) current_focus: Arc<RwLock<Option<String>>>,
    pub(crate) running: Arc<AtomicBool>,
    pub(crate) signing_key: Arc<RwLock<Option<SigningKey>>>,
    pub(crate) activity_accumulator:
        Arc<RwLock<crate::fingerprint::ActivityFingerprintAccumulator>>,
    pub(crate) session_events_tx: broadcast::Sender<SessionEvent>,
    pub(crate) shutdown_tx: Arc<Mutex<Option<mpsc::Sender<()>>>>,
    pub(crate) voice_collector: Arc<RwLock<Option<crate::fingerprint::VoiceCollector>>>,
    mouse_idle_stats: Arc<RwLock<crate::platform::MouseIdleStats>>,
    mouse_stego_engine: Arc<RwLock<crate::platform::MouseStegoEngine>>,
    session_nonce: Arc<RwLock<Option<[u8; 32]>>>,
    bridge_threads: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>>,
    /// Handle for the main event loop task; aborted on Drop if stop() was never called.
    event_loop_handle: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    /// Active keystroke capture; stored so stop() can clean up CGEventTap threads.
    keystroke_capture: Arc<Mutex<Option<Box<dyn KeystrokeCapture>>>>,
    /// Active mouse capture; stored so stop() can clean up CGEventTap threads.
    mouse_capture: Arc<Mutex<Option<Box<dyn MouseCapture>>>>,
    /// Whether keystroke capture is active (false = degraded/focus-only mode).
    pub(crate) keystroke_capture_active: Arc<AtomicBool>,
    /// Last paste character count reported by the host app.
    last_paste_chars: Arc<std::sync::atomic::AtomicI64>,
    /// Timestamp when the sentinel was started via start().
    pub(crate) start_time: Arc<Mutex<Option<SystemTime>>>,
}

impl Sentinel {
    /// Create a new sentinel from the given configuration.
    pub fn new(config: SentinelConfig) -> Result<Self> {
        config.validate().map_err(SentinelError::Anyhow)?;
        config.ensure_directories().map_err(SentinelError::Anyhow)?;

        let shadow = ShadowManager::new(&config.shadow_dir)?;
        let (session_events_tx, _) = broadcast::channel(100);

        let mut mouse_stego_seed = [0u8; 32];
        use rand::RngCore;
        rand::rng().fill_bytes(&mut mouse_stego_seed);

        let sentinel = Self {
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
            event_loop_handle: Arc::new(Mutex::new(None)),
            keystroke_capture: Arc::new(Mutex::new(None)),
            mouse_capture: Arc::new(Mutex::new(None)),
            keystroke_capture_active: Arc::new(AtomicBool::new(false)),
            last_paste_chars: Arc::new(std::sync::atomic::AtomicI64::new(0)),
            start_time: Arc::new(Mutex::new(None)),
        };
        mouse_stego_seed.zeroize();
        Ok(sentinel)
    }

    /// Return the session nonce, generating one if not yet set.
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

    /// Clear the session nonce so a new one will be generated on next access.
    pub fn reset_nonce(&self) {
        let mut nonce_lock = self.session_nonce.write_recover();
        if let Some(ref mut nonce) = *nonce_lock {
            nonce.zeroize();
        }
        *nonce_lock = None;
    }

    /// Enable voice fingerprint collection for behavioral biometrics.
    pub fn enable_voice_fingerprinting(&self) {
        let mut collector = self.voice_collector.write_recover();
        if collector.is_none() {
            *collector = Some(crate::fingerprint::VoiceCollector::new());
        }
    }

    /// Disable voice fingerprint collection and discard the collector.
    pub fn disable_voice_fingerprinting(&self) {
        let mut collector = self.voice_collector.write_recover();
        *collector = None;
    }

    /// Return a snapshot of the current activity fingerprint.
    pub fn current_activity_fingerprint(&self) -> crate::fingerprint::ActivityFingerprint {
        self.activity_accumulator
            .read_recover()
            .current_fingerprint()
    }

    /// Return the current keystroke count from the activity accumulator.
    pub fn config(&self) -> &SentinelConfig {
        &self.config
    }

    pub fn keystroke_count(&self) -> u64 {
        self.activity_accumulator
            .read_recover()
            .to_session_summary()
            .keystroke_count
    }

    /// Inject a jitter sample into the activity accumulator (for testing).
    #[cfg(any(test, feature = "test-utils"))]
    pub fn inject_sample(&self, sample: &crate::jitter::SimpleJitterSample) {
        self.activity_accumulator.write_recover().add_sample(sample);
    }

    /// Return the current voice fingerprint, if collection is enabled.
    pub fn current_voice_fingerprint(&self) -> Option<crate::fingerprint::VoiceFingerprint> {
        self.voice_collector
            .read_recover()
            .as_ref()
            .map(|c| c.current_fingerprint())
    }

    /// Return a snapshot of mouse idle statistics during typing.
    pub fn mouse_idle_stats(&self) -> crate::platform::MouseIdleStats {
        self.mouse_idle_stats.read_recover().clone()
    }

    /// Reset mouse idle statistics to initial state.
    pub fn reset_mouse_idle_stats(&self) {
        *self.mouse_idle_stats.write_recover() = crate::platform::MouseIdleStats::new();
    }

    /// Return a shared reference to the mouse steganography engine.
    pub fn mouse_stego_engine(&self) -> &Arc<RwLock<crate::platform::MouseStegoEngine>> {
        &self.mouse_stego_engine
    }

    /// Update the mouse stego engine from the given key bytes (avoids re-acquiring signing_key lock).
    fn update_mouse_stego_seed_from(&self, key_bytes: &[u8; 32]) {
        let mut seed = *key_bytes;
        let mut engine = self.mouse_stego_engine.write_recover();
        engine.reset();
        *engine = crate::platform::MouseStegoEngine::new(seed);
        seed.zeroize();
    }

    /// Set the Ed25519 signing key and update the mouse stego seed.
    ///
    /// Rejects all-zero keys as invalid (likely uninitialized).
    pub fn set_signing_key(&self, key: SigningKey) {
        if key.to_bytes().iter().all(|&b| b == 0) {
            log::warn!("Rejected all-zero signing key — likely uninitialized");
            return;
        }
        let mut key_bytes = key.to_bytes();
        *self.signing_key.write_recover() = Some(key);
        // Update stego seed without re-acquiring the signing_key lock
        self.update_mouse_stego_seed_from(&key_bytes);
        key_bytes.zeroize();
    }

    /// Set the signing key from raw HMAC key bytes (must be exactly 32 bytes).
    pub fn set_hmac_key(&self, mut key: Vec<u8>) {
        if key.len() == 32 {
            let mut bytes: [u8; 32] = match key.as_slice().try_into() {
                Ok(b) => b,
                Err(_) => {
                    log::error!("HMAC key must be exactly 32 bytes");
                    return;
                }
            };
            key.zeroize(); // Zeroize the original Vec heap allocation
            let mut seed_copy = bytes;
            *self.signing_key.write_recover() = Some(SigningKey::from_bytes(&bytes));
            bytes.zeroize();
            self.update_mouse_stego_seed_from(&seed_copy);
            seed_copy.zeroize();
        } else {
            log::warn!("HMAC key length {} is not 32 bytes, ignoring", key.len());
            key.zeroize();
        }
    }

    /// Start the sentinel event loop (focus, keystroke, mouse monitoring).
    ///
    /// The `running` flag is set **after** all subsystems have initialized successfully
    /// so that `is_running()` only returns `true` when the sentinel is fully operational.
    // TODO(L-031): Refactor start() into smaller helpers (setup_focus, setup_keystroke,
    // setup_mouse, spawn_event_loop) to reduce complexity and improve testability.
    pub async fn start(&self) -> Result<()> {
        if self.running.load(Ordering::SeqCst) {
            return Err(SentinelError::AlreadyRunning);
        }

        *self.start_time.lock_recover() = Some(SystemTime::now());

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
            return Err(SentinelError::NotAvailable(reason));
        }

        focus_monitor.start()?;

        // Set running=true before spawning bridge threads so they see the flag immediately.
        self.running.store(true, Ordering::SeqCst);

        let sessions = Arc::clone(&self.sessions);
        let current_focus = Arc::clone(&self.current_focus);
        let config = self.config.clone();
        let shadow = Arc::clone(&self.shadow);
        let signing_key = Arc::clone(&self.signing_key);
        let session_events_tx = self.session_events_tx.clone();
        let running = Arc::clone(&self.running);
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

        let keystroke_active = Arc::clone(&self.keystroke_capture_active);
        let keystroke_capture_store = Arc::clone(&self.keystroke_capture);
        match keystroke_capture_result {
            Ok(mut keystroke_capture) => match keystroke_capture.start() {
                Ok(sync_rx) => {
                    keystroke_active.store(true, Ordering::SeqCst);
                    // Store capture so stop() can clean up the CGEventTap thread
                    *keystroke_capture_store.lock_recover() =
                        Some(Box::new(keystroke_capture) as Box<dyn KeystrokeCapture>);
                    let sync_rx: std::sync::mpsc::Receiver<crate::platform::KeystrokeEvent> =
                        sync_rx;
                    let handle = std::thread::spawn(move || {
                        #[cfg(debug_assertions)]
                        let mut bridge_count: u64 = 0;
                        let mut dropped_count: u64 = 0;
                        while keystroke_running.load(Ordering::SeqCst) {
                            match sync_rx.recv_timeout(std::time::Duration::from_millis(100)) {
                                Ok(event) => {
                                    #[cfg(debug_assertions)]
                                    {
                                        bridge_count += 1;
                                    }
                                    #[cfg(debug_assertions)]
                                    if bridge_count % 100 == 0 {
                                        if let Ok(dir) = std::env::var("CPOP_DATA_DIR") {
                                            let path = std::path::Path::new(&dir)
                                                .join("keystroke_debug.txt");
                                            if let Ok(mut f) = std::fs::OpenOptions::new()
                                                .create(true)
                                                .append(true)
                                                .open(&path)
                                            {
                                                use std::io::Write;
                                                let _ = writeln!(
                                                    f,
                                                    "[{}] bridge: forwarded #{bridge_count}",
                                                    chrono::Utc::now()
                                                );
                                            }
                                        }
                                    }
                                    if let Err(e) = keystroke_tx.try_send(event) {
                                        match e {
                                            tokio::sync::mpsc::error::TrySendError::Full(_) => {
                                                dropped_count += 1;
                                                if dropped_count == 1
                                                    || dropped_count.is_power_of_two()
                                                {
                                                    log::warn!(
                                                        "keystroke channel full, {} events dropped",
                                                        dropped_count
                                                    );
                                                }
                                            }
                                            tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                                                log::debug!("keystroke channel closed");
                                                break;
                                            }
                                        }
                                    }
                                }
                                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                            }
                        }
                    });
                    self.bridge_threads.lock_recover().push(handle);
                }
                Err(e) => {
                    log::warn!("Keystroke capture failed to start: {e}; running in degraded mode");
                }
            },
            Err(e) => {
                log::warn!(
                    "Keystroke capture unavailable: {e}; running in degraded mode (focus-only)"
                );
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
        #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
        let mouse_capture_result: anyhow::Result<Box<dyn crate::platform::MouseCapture>> = Err(
            anyhow::anyhow!("Mouse capture not supported on this platform"),
        );

        let mouse_capture_store = Arc::clone(&self.mouse_capture);
        match mouse_capture_result {
            Ok(mut mouse_capture) => match mouse_capture.start() {
                Ok(sync_rx) => {
                    // Store capture so stop() can clean up the CGEventTap thread
                    *mouse_capture_store.lock_recover() =
                        Some(Box::new(mouse_capture) as Box<dyn MouseCapture>);
                    let sync_rx: std::sync::mpsc::Receiver<crate::platform::MouseEvent> = sync_rx;
                    let handle = std::thread::spawn(move || {
                        while mouse_running.load(Ordering::SeqCst) {
                            match sync_rx.recv_timeout(std::time::Duration::from_millis(100)) {
                                Ok(event) => {
                                    if let Err(e) = mouse_tx.try_send(event) {
                                        match e {
                                            tokio::sync::mpsc::error::TrySendError::Full(_) => {
                                                log::debug!("mouse channel full, dropping event");
                                            }
                                            tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                                                log::debug!("mouse channel closed");
                                                break;
                                            }
                                        }
                                    }
                                }
                                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                            }
                        }
                    });
                    self.bridge_threads.lock_recover().push(handle);
                }
                Err(e) => {
                    log::warn!("Mouse capture failed to start: {e}; running in degraded mode");
                }
            },
            Err(e) => {
                log::warn!("Mouse capture unavailable: {e}; running in degraded mode (focus-only)");
            }
        }

        let activity_accumulator = Arc::clone(&self.activity_accumulator);
        let voice_collector = Arc::clone(&self.voice_collector);
        let mouse_idle_stats = Arc::clone(&self.mouse_idle_stats);
        let mouse_stego_engine = Arc::clone(&self.mouse_stego_engine);

        let checkpoint_interval_secs = config.checkpoint_interval_secs;
        let writersproof_dir = config.writersproof_dir.clone();
        let signing_key_for_cp = Arc::clone(&self.signing_key);

        // Re-focus preserved sessions from a prior run so that keystrokes
        // are attributed immediately, without waiting for the focus probe.
        // Also reset EventValidationState to avoid stale clock_discontinuity
        // and burst penalties from the pre-restart timestamps.
        {
            let focus = self.current_focus.read_recover().clone();
            if let Some(ref path) = focus {
                if let Some(session) = self.sessions.write_recover().get_mut(path.as_str()) {
                    session.focus_gained();
                    session.event_validation = Default::default();
                }
            }
        }

        let tap_check_capture = Arc::clone(&self.keystroke_capture);
        let tap_check_active = Arc::clone(&self.keystroke_capture_active);
        let bridge_health_threads = Arc::clone(&self.bridge_threads);

        let event_loop_handle_ref = Arc::clone(&self.event_loop_handle);
        let handle = tokio::spawn(async move {
            let mut idle_check_interval = interval(Duration::from_secs(60));
            let mut checkpoint_interval = interval(Duration::from_secs(checkpoint_interval_secs));
            let mut last_keystroke_time = std::time::Instant::now();
            let mut last_keystroke_ts_ns: i64 = 0;
            let mut last_mouse_ts_ns: i64 = 0;

            super::trace!("[EVENT_LOOP] started");

            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        break;
                    }

                    Some(event) = keystroke_rx.recv() => {
                        // Dedup guard: skip duplicate events with identical timestamps
                        if event.timestamp_ns == last_keystroke_ts_ns {
                            continue;
                        }

                        // Compute inter-keystroke duration
                        let duration_since_last_ns: u64 = if last_keystroke_ts_ns > 0 {
                            event.timestamp_ns.saturating_sub(last_keystroke_ts_ns).max(0) as u64
                        } else {
                            0
                        };
                        last_keystroke_ts_ns = event.timestamp_ns;
                        let sample = crate::jitter::SimpleJitterSample {
                            timestamp_ns: event.timestamp_ns,
                            duration_since_last_ns,
                            zone: event.zone,
                        };
                        activity_accumulator.write_recover().add_sample(&sample);

                        if let Some(ref mut collector) = *voice_collector.write_recover() {
                            collector.record_keystroke(event.keycode, event.char_value);
                        }

                        // Only count keystrokes when a tracked document is focused.
                        let focused_path = current_focus.read_recover().clone();
                        {
                            let session_keys: Vec<String> =
                                sessions.read_recover().keys().cloned().collect();
                            super::trace!(
                                "[KEYSTROKE] focus={:?} sessions={:?} kc={}",
                                focused_path, session_keys, event.keycode
                            );
                        }
                        if let Some(ref path) = focused_path {
                            let mut map = sessions.write_recover();
                            if let Some(session) = map.get_mut(path) {
                                session.keystroke_count += 1;
                                super::trace!(
                                    "[KEYSTROKE] COUNTED {:?} total={}",
                                    path, session.keystroke_count
                                );
                                if session.jitter_samples.len() < MAX_DOCUMENT_JITTER_SAMPLES {
                                    session.jitter_samples.push(sample.clone());
                                }

                                let validation = crate::forensics::validate_keystroke_event(
                                    event.timestamp_ns,
                                    event.keycode,
                                    sample.zone,
                                    CGEVENTTAP_VERIFIED_PID,
                                    None,
                                    session.has_focus,
                                    &mut session.event_validation,
                                );
                                if validation.confidence < 0.1 {
                                    session.keystroke_count -= 1;
                                    session.jitter_samples.pop();
                                    super::trace!(
                                        "[KEYSTROKE] REJECTED conf={:.2}", validation.confidence
                                    );
                                }
                            } else {
                                super::trace!(
                                    "[KEYSTROKE] NO SESSION for path={:?}", path
                                );
                            }
                        }

                        last_keystroke_time = std::time::Instant::now();
                    }

                    Some(event) = mouse_rx.recv() => {
                        let _mouse_duration_ns: u64 = if last_mouse_ts_ns > 0 {
                            event.timestamp_ns.saturating_sub(last_mouse_ts_ns).max(0) as u64
                        } else {
                            0
                        };
                        last_mouse_ts_ns = event.timestamp_ns;

                        let is_during_typing = last_keystroke_time.elapsed() < Duration::from_secs(2);
                        if is_during_typing && event.is_micro_movement() {
                            mouse_idle_stats.write_recover().record(&event);
                        }

                        mouse_stego_engine.write_recover().next_jitter();
                    }

                    Some(event) = focus_rx.recv() => {
                        // Process every focus event immediately. The 100ms polling
                        // interval provides natural throttling; no debounce needed.
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
                        // Auto-checkpoint idle sessions before ending them.
                        let idle_paths: Vec<String> = {
                            let map = sessions.read_recover();
                            map.iter()
                                .filter(|(_, s)| {
                                    !s.is_focused()
                                        && s.last_focused_at
                                            .elapsed()
                                            .map(|d| d > idle_timeout)
                                            .unwrap_or(false)
                                })
                                .map(|(p, _)| p.clone())
                                .collect()
                        };
                        for path in &idle_paths {
                            let needs_checkpoint = {
                                let map = sessions.read_recover();
                                map.get(path.as_str()).is_some_and(|s| {
                                    s.keystroke_count > s.last_checkpoint_keystrokes
                                        && !path.starts_with("shadow://")
                                })
                            };
                            if needs_checkpoint {
                                commit_checkpoint_for_path(
                                    path,
                                    "Auto-checkpoint on idle end",
                                    &signing_key_for_cp,
                                    &writersproof_dir,
                                );
                            }
                            end_session_sync(path, &sessions, &session_events_tx);
                        }

                        // Check CGEventTap health
                        {
                            let tap_dead = {
                                let guard = tap_check_capture.lock_recover();
                                guard.as_ref().is_some_and(|cap| !cap.is_tap_alive())
                            };
                            if tap_dead && tap_check_active.load(Ordering::SeqCst) {
                                log::error!(
                                    "CGEventTap died; marking keystroke capture inactive"
                                );
                                tap_check_active.store(false, Ordering::SeqCst);
                            }
                        }

                        // Check bridge thread health
                        {
                            let threads = bridge_health_threads.lock_recover();
                            for (i, handle) in threads.iter().enumerate() {
                                if handle.is_finished() {
                                    log::error!(
                                        "Bridge thread {i} exited unexpectedly"
                                    );
                                }
                            }
                        }
                    }

                    _ = checkpoint_interval.tick() => {
                        let candidates: Vec<String> = {
                            let map = sessions.read_recover();
                            map.iter()
                                .filter(|(p, s)| {
                                    s.keystroke_count > s.last_checkpoint_keystrokes
                                        && !p.starts_with("shadow://")
                                })
                                .map(|(p, _)| p.clone())
                                .collect()
                        };
                        for path in &candidates {
                            if commit_checkpoint_for_path(
                                path,
                                "Auto-checkpoint",
                                &signing_key_for_cp,
                                &writersproof_dir,
                            ) {
                                let mut map = sessions.write_recover();
                                if let Some(session) = map.get_mut(path.as_str()) {
                                    session.last_checkpoint_keystrokes =
                                        session.keystroke_count;
                                    // Persist cumulative keystroke count so the
                                    // history page shows accurate typing events
                                    // even after app restart.
                                    let guard = signing_key_for_cp.read_recover();
                                    if let Some(ref sk) = *guard {
                                        let db = writersproof_dir.join("events.db");
                                        if let Ok(store) =
                                            crate::store::open_store_with_signing_key(sk, &db)
                                        {
                                            let stats = crate::store::DocumentStats {
                                                file_path: path.clone(),
                                                total_keystrokes: i64::try_from(
                                                    session.total_keystrokes(),
                                                )
                                                .unwrap_or(i64::MAX),
                                                total_focus_ms: session
                                                    .total_focus_ms_cumulative(),
                                                session_count: i64::from(
                                                    session.session_number + 1,
                                                ),
                                                total_duration_secs: session
                                                    .start_time
                                                    .elapsed()
                                                    .map(|d| d.as_secs() as i64)
                                                    .unwrap_or(0),
                                                first_tracked_at: session
                                                    .first_tracked_at
                                                    .and_then(|t| {
                                                        t.duration_since(
                                                            std::time::UNIX_EPOCH,
                                                        )
                                                        .ok()
                                                    })
                                                    .map(|d| d.as_secs() as i64)
                                                    .unwrap_or(0),
                                                last_tracked_at: SystemTime::now()
                                                    .duration_since(std::time::UNIX_EPOCH)
                                                    .map(|d| d.as_secs() as i64)
                                                    .unwrap_or(0),
                                            };
                                            let _ = store.save_document_stats(&stats);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                if !running.load(Ordering::SeqCst) {
                    break;
                }
            }

            if let Err(e) = focus_monitor.stop() {
                log::debug!("focus monitor stop: {e}");
            }
            // Session unfocus is now handled by Sentinel::stop() directly
            // (not here) to avoid the abort race where this cleanup code
            // might never run if the event loop handle is aborted first.
        });

        // Store the event loop handle so it can be aborted on Drop
        *event_loop_handle_ref.lock_recover() = Some(handle);

        Ok(())
    }

    /// Stop the sentinel, joining bridge threads and cleaning up captures.
    pub async fn stop(&self) -> Result<()> {
        if !self.running.swap(false, Ordering::SeqCst) {
            return Ok(());
        }

        // take() under lock, then await outside to avoid holding lock across .await
        let tx = self.shutdown_tx.lock_recover().take();
        if let Some(tx) = tx {
            let _ = tx.send(()).await;
        }

        // Join bridge threads first (they check `running` flag)
        let handles: Vec<_> = self.bridge_threads.lock_recover().drain(..).collect();
        for handle in handles {
            let _ = handle.join();
        }

        // Stop CGEventTap threads (keystroke + mouse captures)
        if let Some(mut cap) = self.keystroke_capture.lock_recover().take() {
            let _ = cap.stop();
        }
        self.keystroke_capture_active.store(false, Ordering::SeqCst);
        if let Some(mut cap) = self.mouse_capture.lock_recover().take() {
            let _ = cap.stop();
        }

        // Unfocus all sessions here (not in the event loop cleanup) so that
        // has_focus is guaranteed to be false before start() re-focuses them.
        // The event loop abort below may fire before the loop's own cleanup
        // runs, so we must do this in stop() directly.
        {
            let paths: Vec<String> = self.sessions.read_recover().keys().cloned().collect();
            for path in paths {
                unfocus_document_sync(&path, &self.sessions, &self.session_events_tx);
            }
        }
        // current_focus is NOT cleared so run_event_loop() can re-focus
        // the same document on restart. The sessions above are unfocused
        // (has_focus = false) but still present in the map.

        // Abort the event loop task
        if let Some(handle) = self.event_loop_handle.lock_recover().take() {
            handle.abort();
        }

        self.shadow.cleanup_all();

        Ok(())
    }

    /// Return `true` if the sentinel event loop is active.
    /// Checks both the running flag AND whether the event loop task is alive.
    /// If the task panicked or exited, clears the running flag so callers
    /// know to restart.
    pub fn is_running(&self) -> bool {
        if !self.running.load(Ordering::SeqCst) {
            return false;
        }
        // Check if the event loop task is still alive
        let task_alive = {
            let guard = self.event_loop_handle.lock_recover();
            match guard.as_ref() {
                Some(handle) => !handle.is_finished(),
                None => false,
            }
        };
        if !task_alive {
            log::error!("Sentinel event loop task exited unexpectedly; clearing running flag");
            self.running.store(false, Ordering::SeqCst);
            return false;
        }
        true
    }

    /// Whether keystroke capture is active (false = degraded/focus-only mode).
    pub fn is_keystroke_capture_active(&self) -> bool {
        self.keystroke_capture_active.load(Ordering::SeqCst)
    }

    /// Restart keystroke capture after a tap failure (e.g. after macOS sleep/wake).
    /// This is a no-op convenience method; callers should use the FFI stop/start
    /// cycle instead, which fully restarts the event loop and bridge threads.
    /// Returns true if capture appears active after the check.
    pub fn restart_keystroke_capture(&self) -> bool {
        // A stop+start cycle is the only reliable way to restart capture
        // because the bridge thread holding the old receiver cannot be
        // reconnected to a new capture. The FFI layer handles this via
        // ffi_sentinel_stop() + ffi_sentinel_start().
        self.is_keystroke_capture_active()
    }

    /// Record a paste event from the host app.
    pub fn set_last_paste_chars(&self, chars: i64) {
        self.last_paste_chars.store(chars, Ordering::SeqCst);
    }

    /// Read and clear the last paste character count.
    pub fn take_last_paste_chars(&self) -> i64 {
        self.last_paste_chars.swap(0, Ordering::SeqCst)
    }

    /// Return a snapshot of all active document sessions.
    pub fn sessions(&self) -> Vec<DocumentSession> {
        self.sessions.read_recover().values().cloned().collect()
    }

    /// Look up a session by document path.
    pub fn session(&self, path: &str) -> Result<DocumentSession> {
        self.sessions
            .read_recover()
            .get(path)
            .cloned()
            .ok_or_else(|| SentinelError::SessionNotFound(path.to_string()))
    }

    /// Return per-document jitter samples for forensic analysis.
    pub fn document_jitter_samples(&self, path: &str) -> Vec<crate::jitter::SimpleJitterSample> {
        self.sessions
            .read_recover()
            .get(path)
            .map(|s| s.jitter_samples.clone())
            .unwrap_or_default()
    }

    /// Return the path of the currently focused document, if any.
    pub fn current_focus(&self) -> Option<String> {
        self.current_focus.read_recover().clone()
    }

    /// Subscribe to session lifecycle events (started, ended, idle).
    pub fn subscribe(&self) -> broadcast::Receiver<SessionEvent> {
        self.session_events_tx.subscribe()
    }

    /// Create a shadow buffer for apps that don't expose file paths directly.
    pub fn create_shadow(&self, app_name: &str, window_title: &str) -> Result<String> {
        self.shadow.create(app_name, window_title)
    }

    /// Write new content to an existing shadow buffer.
    pub fn update_shadow_content(&self, shadow_id: &str, content: &[u8]) -> Result<()> {
        self.shadow.update(shadow_id, content)
    }

    /// Check whether the sentinel can run on the current platform.
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

    // Session management methods (start_witnessing, stop_witnessing, tracked_files,
    // start_time, update_baseline) are in core_session.rs.
}

impl Drop for Sentinel {
    fn drop(&mut self) {
        // Signal all bridge threads and the event loop to exit.
        self.running.store(false, Ordering::SeqCst);

        // Stop CGEventTap threads so they don't leak.
        if let Some(mut cap) = self.keystroke_capture.lock_recover().take() {
            let _ = cap.stop();
        }
        self.keystroke_capture_active.store(false, Ordering::SeqCst);
        if let Some(mut cap) = self.mouse_capture.lock_recover().take() {
            let _ = cap.stop();
        }

        // Join bridge threads (they check the running flag on 100ms timeout).
        for handle in self.bridge_threads.lock_recover().drain(..) {
            let _ = handle.join();
        }

        // Abort the event loop task as a final safety net.
        if let Some(handle) = self.event_loop_handle.lock_recover().take() {
            handle.abort();
        }
    }
}
