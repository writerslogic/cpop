// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::error::{Result, SentinelError};
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

/// Sentinel source PID for events pre-verified by CGEventTap.
///
/// Negative value distinguishes pre-verified tap events from real PIDs (>0)
/// and synthetic/injected events (0). The validation layer does not penalize
/// negative PIDs.
const CGEVENTTAP_VERIFIED_PID: i64 = -1;

/// Async channel buffer size for keystroke and mouse bridge threads.
pub(super) const EVENT_CHANNEL_BUFFER: usize = 1000;

/// Duration after last keystroke within which mouse micro-movements are recorded.
const TYPING_PROXIMITY_SECS: u64 = 2;

/// Lock ordering levels for AUD-041 enforcement.
/// Lower values must be acquired before higher values.
#[cfg(debug_assertions)]
pub(super) mod lock_order {
    use std::cell::Cell;

    /// Ordering: signing_key(1) < sessions(2) < current_focus(3).
    pub const SIGNING_KEY: u8 = 1;
    pub const SESSIONS: u8 = 2;

    thread_local! {
        static MAX_HELD: Cell<u8> = const { Cell::new(0) };
    }

    /// Assert that acquiring a lock at `level` does not violate ordering.
    /// Panics in debug builds if a higher-ordered lock is already held.
    pub fn assert_order(level: u8) -> LockOrderGuard {
        MAX_HELD.with(|cell| {
            let held = cell.get();
            debug_assert!(
                held < level,
                "Lock ordering violation (AUD-041): attempted to acquire level {level} \
                 while level {held} is held. Order: signing_key(1) < sessions(2) < focus(3)."
            );
            cell.set(level);
        });
        LockOrderGuard { level }
    }

    /// RAII guard to ensure lock level is released on drop.
    pub struct LockOrderGuard {
        level: u8,
    }

    impl Drop for LockOrderGuard {
        fn drop(&mut self) {
            release(self.level);
        }
    }

    /// Release: reset the max held level to below this lock's level.
    pub fn release(level: u8) {
        MAX_HELD.with(|cell| {
            if cell.get() == level {
                cell.set(level - 1);
            }
        });
    }
}

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
/// In debug builds, `lock_order::assert_order` enforces this at runtime.
pub struct Sentinel {
    pub(crate) config: Arc<SentinelConfig>,
    /// Runtime toggle for document snapshots (can be changed without restart).
    pub(crate) snapshots_enabled: Arc<AtomicBool>,
    pub(crate) sessions: Arc<RwLock<HashMap<String, DocumentSession>>>,
    pub(crate) shadow: Arc<ShadowManager>,
    pub(crate) current_focus: Arc<RwLock<Option<String>>>,
    pub(crate) running: Arc<AtomicBool>,
    pub(crate) signing_key: Arc<RwLock<super::behavioral_key::BehavioralKey>>,
    pub(crate) activity_accumulator:
        Arc<RwLock<crate::fingerprint::ActivityFingerprintAccumulator>>,
    pub(crate) session_events_tx: broadcast::Sender<SessionEvent>,
    pub(crate) shutdown_tx: Arc<Mutex<Option<mpsc::Sender<()>>>>,
    pub(crate) voice_collector: Arc<RwLock<Option<crate::fingerprint::VoiceCollector>>>,
    mouse_idle_stats: Arc<RwLock<crate::platform::MouseIdleStats>>,
    mouse_stego_engine: Arc<RwLock<crate::platform::MouseStegoEngine>>,
    session_nonce: Arc<RwLock<Option<[u8; 32]>>>,
    pub(super) bridge_threads: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>>,
    /// Handle for the main event loop task; aborted on Drop if stop() was never called.
    event_loop_handle: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    /// Active keystroke capture; stored so stop() can clean up CGEventTap threads.
    pub(super) keystroke_capture: Arc<Mutex<Option<Box<dyn KeystrokeCapture>>>>,
    /// Active mouse capture; stored so stop() can clean up CGEventTap threads.
    pub(super) mouse_capture: Arc<Mutex<Option<Box<dyn MouseCapture>>>>,
    /// Whether keystroke capture is active (false = degraded/focus-only mode).
    pub(crate) keystroke_capture_active: Arc<AtomicBool>,
    /// Last paste character count reported by the host app.
    last_paste_chars: Arc<std::sync::atomic::AtomicI64>,
    /// Pre-fetched challenge nonce from the host app, consumed by the next checkpoint.
    /// Tuple: (nonce_value, nonce_id). `nonce_id` is `None` for FFI-sourced nonces
    /// (which arrive without a server-side UUID for confirmation).
    #[allow(clippy::type_complexity)]
    pub(crate) pending_challenge: Arc<RwLock<Option<(String, Option<String>)>>>,
    /// Timestamp when the sentinel was started via start().
    pub(crate) start_time: Arc<Mutex<Option<SystemTime>>>,
    /// False when any bridge thread has died; checked before processing events.
    bridge_healthy: Arc<AtomicBool>,
    /// Set to `true` when `stop()` begins; checked by checkpoint tasks to bail
    /// before opening SQLite, preventing a `findReusableFd` mutex deadlock.
    stopping: Arc<AtomicBool>,
    /// Hardware TPM/Secure Enclave provider for co-sign scheduling.
    pub(crate) tpm_provider: Option<Arc<dyn crate::tpm::Provider>>,
    /// Client for WritersProof service (freshness nonces, attestation).
    pub(crate) writersproof_client: Arc<crate::writersproof::WritersProofClient>,
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

        let snapshots_default = config.snapshots_enabled;

        let tpm_provider: Option<Arc<dyn crate::tpm::Provider>> = {
            #[cfg(target_os = "macos")]
            {
                crate::tpm::secure_enclave::try_init()
                    .map(|p| Arc::new(p) as Arc<dyn crate::tpm::Provider>)
            }
            #[cfg(not(target_os = "macos"))]
            {
                Some(Arc::new(crate::tpm::SoftwareProvider::new()) as Arc<dyn crate::tpm::Provider>)
            }
        };

        let writersproof_client = Arc::new(
            crate::writersproof::WritersProofClient::new("https://api.writersproof.com")
                .map_err(|e| SentinelError::Anyhow(anyhow::anyhow!(e)))?,
        );

        let sentinel = Self {
            config: Arc::new(config),
            snapshots_enabled: Arc::new(AtomicBool::new(snapshots_default)),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            shadow: Arc::new(shadow),
            current_focus: Arc::new(RwLock::new(None)),
            running: Arc::new(AtomicBool::new(false)),
            signing_key: Arc::new(RwLock::new(super::behavioral_key::BehavioralKey::new(
                std::time::Duration::from_secs(30),
            ))),
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
            pending_challenge: Arc::new(RwLock::new(None)),
            start_time: Arc::new(Mutex::new(None)),
            bridge_healthy: Arc::new(AtomicBool::new(true)),
            stopping: Arc::new(AtomicBool::new(false)),
            tpm_provider,
            writersproof_client,
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

    /// Toggle document snapshot saving at runtime.
    pub fn set_snapshots_enabled(&self, enabled: bool) {
        self.snapshots_enabled.store(enabled, Ordering::SeqCst);
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
        self.signing_key.write_recover().set_key(key);
        // Update stego seed without re-acquiring the signing_key lock
        self.update_mouse_stego_seed_from(&key_bytes);
        key_bytes.zeroize();
    }

    /// Set the signing key from raw HMAC key bytes (must be exactly 32 bytes).
    pub fn set_hmac_key(&self, mut key: Vec<u8>) {
        if key.len() == 32 {
            if key.iter().all(|&b| b == 0) {
                log::warn!("Rejected all-zero HMAC key — likely uninitialized");
                key.zeroize();
                return;
            }
            let mut bytes: [u8; 32] = match key.as_slice().try_into() {
                Ok(b) => b,
                Err(_) => {
                    log::error!("HMAC key must be exactly 32 bytes");
                    return;
                }
            };
            key.zeroize(); // Zeroize the original Vec heap allocation
            let mut seed_copy = bytes;
            let signing_key = SigningKey::from_bytes(&bytes);
            self.signing_key.write_recover().set_key(signing_key);
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
    pub async fn start(&self) -> Result<()> {
        if self.running.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
            return Err(SentinelError::AlreadyRunning);
        }

        *self.start_time.lock_recover() = Some(SystemTime::now());

        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        *self.shutdown_tx.lock_recover() = Some(shutdown_tx);

        let (focus_monitor, mut focus_rx, mut change_rx) = self.setup_focus()?;

        // Reset bridge health and stopping flag on (re-)start.
        // running is already true from the compare_exchange above.
        self.bridge_healthy.store(true, Ordering::SeqCst);
        self.stopping.store(false, Ordering::SeqCst);

        let sessions = Arc::clone(&self.sessions);
        let current_focus = Arc::clone(&self.current_focus);
        let config = self.config.clone();
        let shadow = Arc::clone(&self.shadow);
        let signing_key = Arc::clone(&self.signing_key);
        let session_events_tx = self.session_events_tx.clone();
        let running = Arc::clone(&self.running);
        let idle_timeout = Duration::from_secs(config.idle_timeout_secs);
        let wal_dir = config.wal_dir.clone();

        let mut keystroke_rx = self.setup_keystroke_bridge(&running);
        let mut mouse_rx = self.setup_mouse_bridge(&running);

        let activity_accumulator = Arc::clone(&self.activity_accumulator);
        let voice_collector = Arc::clone(&self.voice_collector);
        let mouse_idle_stats = Arc::clone(&self.mouse_idle_stats);
        let mouse_stego_engine = Arc::clone(&self.mouse_stego_engine);

        let checkpoint_interval_secs = config.checkpoint_interval_secs;
        let idle_check_interval_secs = config.idle_check_interval_secs;
        let writersproof_dir = config.writersproof_dir.clone();
        let signing_key_for_cp = Arc::clone(&self.signing_key);
        let stopping_flag = Arc::clone(&self.stopping);
        let pending_challenge = Arc::clone(&self.pending_challenge);

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

        let tpm_provider_for_loop = self.tpm_provider.clone();

        let tap_check_capture = Arc::clone(&self.keystroke_capture);
        let tap_check_active = Arc::clone(&self.keystroke_capture_active);
        let bridge_health_threads = Arc::clone(&self.bridge_threads);
        let bridge_healthy_flag = Arc::clone(&self.bridge_healthy);
        let snapshots_flag = Arc::clone(&self.snapshots_enabled);

        let writersproof_client_for_loop = Arc::clone(&self.writersproof_client);
        let mut session_events_rx = self.session_events_tx.subscribe();

        let event_loop_handle_ref = Arc::clone(&self.event_loop_handle);
        let handle = tokio::spawn(async move {
            let mut idle_check_interval = interval(Duration::from_secs(idle_check_interval_secs));
            let mut checkpoint_interval = interval(Duration::from_secs(checkpoint_interval_secs));
            let mut challenge_interval = interval(Duration::from_secs(30)); // 30s cycle for real-time hash attestation
            let mut last_keystroke_time = std::time::Instant::now();
            let mut last_keydown_ts_ns: i64 = 0;
            let mut last_mouse_ts_ns: i64 = 0;
            // Track pending keyDown timestamps per keycode for dwell time computation
            let mut pending_downs: HashMap<u16, i64> = HashMap::new();
            // Last keyUp timestamp for flight time computation
            let mut last_keyup_ts_ns: i64 = 0;

            super::trace!("[EVENT_LOOP] started");

            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        break;
                    }

                    Ok(event) = session_events_rx.recv() => {
                        let client = Arc::clone(&writersproof_client_for_loop);
                        match event.event_type {
                            SessionEventType::Started => {
                                if let Some(hash) = event.hash {
                                    let sid = event.session_id;
                                    tokio::spawn(async move {
                                        if let Err(e) = client.start_session(&sid, &hash).await {
                                            log::debug!("WritersProof start_session failed for {}: {}", sid, e);
                                        }
                                    });
                                }
                            }
                            SessionEventType::Ended => {
                                if let Some(hash) = event.hash {
                                    let sid = event.session_id;
                                    tokio::spawn(async move {
                                        if let Err(e) = client.end_session(&sid, &hash).await {
                                            log::debug!("WritersProof end_session failed for {}: {}", sid, e);
                                        }
                                    });
                                }
                            }
                            _ => {}
                        }
                    }

                    Some(event) = keystroke_rx.recv() => {
                        // Skip event processing when bridge is unhealthy to avoid
                        // silently operating in a degraded state.
                        if !bridge_healthy_flag.load(Ordering::SeqCst) {
                            log::warn!(
                                "Dropping keystroke event: bridge unhealthy"
                            );
                            continue;
                        }

                        // Handle keyUp: compute dwell time and update last_keyup_ts
                        if event.event_type == crate::platform::KeyEventType::Up {
                            if let Some(down_ts) = pending_downs.remove(&event.keycode) {
                                let _dwell = event.timestamp_ns.saturating_sub(down_ts).max(0) as u64;
                                // Dwell time is stored when the corresponding keyDown
                                // sample was created; keyUp events are not stored as
                                // separate jitter samples.
                            }
                            last_keyup_ts_ns = event.timestamp_ns;
                            continue;
                        }

                        // keyDown processing
                        if event.timestamp_ns == last_keydown_ts_ns {
                            continue; // dedup
                        }

                        // Track this keyDown for dwell time (computed when keyUp arrives).
                        // Evict stale entries (keys held > 10s are likely stuck).
                        pending_downs.retain(|_, ts| {
                            event.timestamp_ns.saturating_sub(*ts) < 10_000_000_000
                        });
                        // Cap at 256 entries (one per physical key is ~104; 256 is generous).
                        // A real keyboard cannot have more than ~256 simultaneous key-downs.
                        if pending_downs.len() < 256 {
                            pending_downs.insert(event.keycode, event.timestamp_ns);
                        }

                        // Inter-keyDown duration
                        let duration_since_last_ns: u64 = if last_keydown_ts_ns > 0 {
                            event.timestamp_ns.saturating_sub(last_keydown_ts_ns).max(0) as u64
                        } else {
                            0
                        };

                        // Flight time: gap between last keyUp and this keyDown
                        let flight_time_ns: Option<u64> = if last_keyup_ts_ns > 0 {
                            let ft = event.timestamp_ns.saturating_sub(last_keyup_ts_ns).max(0) as u64;
                            Some(ft)
                        } else {
                            None
                        };

                        last_keydown_ts_ns = event.timestamp_ns;
                        let sample = crate::jitter::SimpleJitterSample {
                            timestamp_ns: event.timestamp_ns,
                            duration_since_last_ns,
                            zone: event.zone,
                            dwell_time_ns: None, // filled when keyUp arrives (next iteration)
                            flight_time_ns,
                        };
                        activity_accumulator.write_recover().add_sample(&sample);

                        // EH-041: Add behavioral entropy to signing key to keep it hot
                        {
                            let jitter_bytes = event.timestamp_ns.to_le_bytes();
                            signing_key.write_recover().add_entropy(&jitter_bytes);
                        }

                        if let Some(ref mut collector) = *voice_collector.write_recover() {
                            collector.record_keystroke(event.keycode, event.char_value);
                        }

                        // Only count keystrokes when a tracked document is focused.
                        // Hold the focus read lock while acquiring the sessions write lock
                        // so focus cannot change between the two acquisitions (H-001).
                        // Lock ordering note: this acquires current_focus(3).read before
                        // sessions(2).write, which inverts the declared numeric order.
                        // This is safe because current_focus is only ever write-locked
                        // from the focus event branch (single-threaded event loop), and
                        // read-read does not conflict. No path holds sessions.write then
                        // acquires current_focus.write.
                        let focus_guard = current_focus.read_recover();
                        if let Some(ref path) = *focus_guard {
                            let mut map = sessions.write_recover();
                            super::trace!(
                                "[KEYSTROKE] focus={:?} sessions={:?} kc={}",
                                path,
                                map.keys().collect::<Vec<_>>(),
                                event.keycode
                            );
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
                                } else if let Some(ref tpm) = tpm_provider_for_loop {
                                    // Lazily initialize scheduler on first accepted keystroke.
                                    if session.hw_cosign_scheduler.is_none() {
                                        match crate::evidence::hw_cosign::HwCosignScheduler::with_defaults(
                                            tpm.as_ref(),
                                            &session.session_id,
                                        ) {
                                            Ok(sched) => {
                                                session.hw_cosign_scheduler = Some(sched);
                                            }
                                            Err(e) => {
                                                log::trace!(
                                                    "HW co-sign scheduler init failed: {e}"
                                                );
                                            }
                                        }
                                    }
                                    if let Some(ref mut sched) = session.hw_cosign_scheduler {
                                        let entropy = duration_since_last_ns.to_le_bytes();
                                        sched.record_entropy(&entropy);
                                    }
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

                        let is_during_typing = last_keystroke_time.elapsed() < Duration::from_secs(TYPING_PROXIMITY_SECS);
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
                            Some(&current_focus),
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
                                let cp_path = path.clone();
                                let cp_key = Arc::clone(&signing_key_for_cp);
                                let cp_dir = writersproof_dir.clone();
                                let cp_stop = Arc::clone(&stopping_flag);
                                let _ = tokio::task::spawn_blocking(move || {
                                    commit_checkpoint_for_path(
                                        &cp_path,
                                        "Auto-checkpoint on idle end",
                                        &cp_key,
                                        &cp_dir,
                                        &None,
                                        &cp_stop,
                                    )
                                })
                                .await;
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
                                        "Bridge thread {i} died; keystroke capture \
                                         is stopped. Restart sentinel to resume \
                                         keystroke capture."
                                    );
                                    bridge_healthy_flag
                                        .store(false, Ordering::SeqCst);
                                }
                            }
                        }
                    }

                    _ = challenge_interval.tick() => {
                        let focused_data = {
                            let focus_guard = current_focus.read_recover();
                            if let Some(ref path) = *focus_guard {
                                sessions.read_recover().get(path).map(|s| (s.session_id.clone(), s.current_hash.clone()))
                            } else {
                                None
                            }
                        };

                        if let Some((sid, hash_opt)) = focused_data {
                            let client = Arc::clone(&writersproof_client_for_loop);
                            let pending = Arc::clone(&pending_challenge);
                            tokio::spawn(async move {
                                if let Some(h) = hash_opt {
                                    // Send pulse: atomically log hash and fetch fresh nonce
                                    match client.pulse(&sid, &h).await {
                                        Ok(resp) => {
                                            *pending.write_recover() = Some((resp.nonce, Some(resp.nonce_id.clone())));
                                            log::debug!("Pulse sent for session {}: nonce_id={}", sid, resp.nonce_id);
                                        }
                                        Err(e) => {
                                            log::debug!("Pulse failed for session {}: {}", sid, e);
                                        }
                                    }
                                }
                            });
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

                        // Consume a pre-fetched challenge nonce if one was set
                        // by the host app via ffi_sentinel_set_challenge_nonce.
                        let pending_taken = pending_challenge.write_recover().take();
                        let challenge_nonce = pending_taken.as_ref().map(|(n, _)| n.clone());
                        let nonce_id = pending_taken.and_then(|(_, id)| id);

                        for path in &candidates {
                            let cp_path = path.clone();
                            let cp_key = Arc::clone(&signing_key_for_cp);
                            let cp_dir = writersproof_dir.clone();
                            let nonce_for_closure = challenge_nonce.clone();
                            let cp_stop = Arc::clone(&stopping_flag);
                            let committed = tokio::task::spawn_blocking(move || {
                                commit_checkpoint_for_path(
                                    &cp_path,
                                    "Auto-checkpoint",
                                    &cp_key,
                                    &cp_dir,
                                    &nonce_for_closure,
                                    &cp_stop,
                                )
                            })
                            .await
                            .unwrap_or_else(|e| {
                                log::error!("Checkpoint task panicked: {e}");
                                None
                            });
                            if let Some(event_hash) = committed {
                                // Close the nonce handshake loop: tell the server which
                                // checkpoint hash consumed its nonce, enabling temporal
                                // verification at writersproof.com.
                                if let Some(ref nid) = nonce_id {
                                    let confirm_client = Arc::clone(&writersproof_client_for_loop);
                                    let session_id = sessions
                                        .read_recover()
                                        .get(path.as_str())
                                        .map(|s| s.session_id.clone());
                                    if let Some(sid) = session_id {
                                        let nid = nid.clone();
                                        let cp_hash = hex::encode(event_hash);
                                        tokio::spawn(async move {
                                            if let Err(e) =
                                                confirm_client.confirm_nonce(&sid, &nid, &cp_hash).await
                                            {
                                                log::debug!("confirm_nonce failed for session {sid}: {e}");
                                            }
                                        });
                                    }
                                }
                            }
                            if committed.is_some() {
                                // AUD-041: signing_key must be acquired before sessions.
                                let sk_opt = {
                                    let guard = signing_key_for_cp.read_recover();
                                    guard.key()
                                };
                                let mut map = sessions.write_recover();
                                if let Some(session) = map.get_mut(path.as_str()) {
                                    session.last_checkpoint_keystrokes =
                                        session.keystroke_count;
                                    // Persist cumulative keystroke count so the
                                    // history page shows accurate typing events
                                    // even after app restart.
                                    if let Some(sk) = sk_opt {
                                        let db = writersproof_dir.join("events.db");
                                        if let Ok(store) =
                                            crate::store::open_store_with_signing_key(&sk, &db)
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
                                            if let Err(e) = store.save_document_stats(&stats) {
                                                log::warn!("Failed to save document stats for {path}: {e}");
                                            }
                                        }
                                    }

                                    // Save document snapshot if enabled
                                    if snapshots_flag.load(Ordering::SeqCst)
                                        && !path.starts_with("shadow://")
                                    {
                                        let src = std::path::Path::new(path);
                                        let path_hash = {
                                            use sha2::Digest;
                                            let h = sha2::Sha256::digest(path.as_bytes());
                                            hex::encode(&h[..8])
                                        };
                                        let ext = src
                                            .extension()
                                            .and_then(|e| e.to_str())
                                            .unwrap_or("txt");
                                        let snap_dir =
                                            writersproof_dir.join("snapshots").join(&path_hash);
                                        if let Err(e) = std::fs::create_dir_all(&snap_dir) {
                                            log::warn!(
                                                "Failed to create snapshot dir {}: {e}",
                                                snap_dir.display()
                                            );
                                        }
                                        let ordinal = session.last_checkpoint_keystrokes;
                                        let snap_name =
                                            format!("{:06}.{}", ordinal, ext);
                                        let snap_path = snap_dir.join(&snap_name);
                                        if let Err(e) = std::fs::copy(src, &snap_path) {
                                            log::debug!(
                                                "Snapshot save failed for {}: {e}",
                                                path
                                            );
                                        }
                                    }

                                    if let Some(ref tpm) = tpm_provider_for_loop {
                                        let content_hash: [u8; 32] = {
                                            use sha2::Digest;
                                            let src = std::path::Path::new(path);
                                            match std::fs::read(src) {
                                                Ok(data) => sha2::Sha256::digest(&data).into(),
                                                Err(e) => {
                                                    log::warn!(
                                                        "Skipping HW co-sign: file read failed \
                                                         for {}: {e}",
                                                        path
                                                    );
                                                    continue;
                                                }
                                            }
                                        };
                                        let store_and_path = signing_key_for_cp
                                            .read_recover()
                                            .key()
                                            .and_then(|sk| {
                                                let db = writersproof_dir.join("events.db");
                                                crate::store::open_store_with_signing_key(&sk, &db).ok()
                                            });

                                        // Decode server-issued nonce for causal binding into hw_cosign
                                        let nonce_bytes_opt = challenge_nonce.as_ref().and_then(|nonce_hex| {
                                            match hex::decode(nonce_hex) {
                                                Ok(bytes) if bytes.len() == 32 => {
                                                    let mut arr = [0u8; 32];
                                                    arr.copy_from_slice(&bytes);
                                                    Some(arr)
                                                }
                                                _ => {
                                                    log::debug!("Failed to decode challenge nonce for binding");
                                                    None
                                                }
                                            }
                                        });

                                        try_hw_cosign(
                                            session,
                                            tpm.as_ref(),
                                            &content_hash,
                                            nonce_bytes_opt.as_ref(),
                                            store_and_path.as_ref().map(|s| (s, path.as_str())),
                                        );
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

        // Set stopping flag FIRST so in-flight spawn_blocking checkpoint
        // tasks bail before opening SQLite (prevents findReusableFd deadlock).
        self.stopping.store(true, Ordering::SeqCst);

        // Send shutdown signal first so the event loop can run cleanup (focus_monitor.stop()).
        // take() under lock, then await outside to avoid holding lock across .await.
        let tx = self.shutdown_tx.lock_recover().take();
        if let Some(tx) = tx {
            let _ = tx.send(()).await;
        }

        // Give the event loop a short window to exit gracefully, then force-abort.
        let handle = self.event_loop_handle.lock_recover().take();
        if let Some(mut handle) = handle {
            match tokio::time::timeout(std::time::Duration::from_millis(500), &mut handle).await {
                Ok(_) => {} // exited gracefully
                Err(_) => handle.abort(),
            }
        }

        // Stop CGEventTap threads (keystroke + mouse captures) so
        // the std::sync::mpsc senders are dropped, causing bridge threads
        // to receive Disconnected and exit their recv_timeout loops.
        if let Some(mut cap) = self.keystroke_capture.lock_recover().take() {
            let _ = cap.stop();
        }
        self.keystroke_capture_active.store(false, Ordering::SeqCst);
        if let Some(mut cap) = self.mouse_capture.lock_recover().take() {
            let _ = cap.stop();
        }
        super::stop_hid_capture();

        // Now join bridge threads (senders dropped, so they will exit)
        let handles: Vec<_> = self.bridge_threads.lock_recover().drain(..).collect();
        for handle in handles {
            // Intentionally ignored: thread panic during shutdown is non-recoverable
            let _ = handle.join();
        }

        // Persist cumulative stats so keystroke counts survive across
        // stop/start cycles. Run in spawn_blocking with a timeout because
        // in-flight checkpoint tasks may still hold the SQLite fd mutex.
        {
            // AUD-041: signing_key before sessions.
            #[cfg(debug_assertions)]
            let _sk_guard = lock_order::assert_order(lock_order::SIGNING_KEY);
            let sk_clone = self.signing_key.read_recover().key();
            #[cfg(debug_assertions)]
            let _sess_guard = lock_order::assert_order(lock_order::SESSIONS);
            let stats_list: Vec<_> = self
                .sessions
                .read_recover()
                .iter()
                .filter(|(p, _)| !p.starts_with("shadow://"))
                .map(|(path, session)| {
                    let now_secs = SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0);
                    crate::store::DocumentStats {
                        file_path: path.clone(),
                        total_keystrokes: i64::try_from(session.total_keystrokes())
                            .unwrap_or(i64::MAX),
                        total_focus_ms: session.total_focus_ms_cumulative(),
                        session_count: i64::from(session.session_number + 1),
                        total_duration_secs: session
                            .start_time
                            .elapsed()
                            .map(|d| d.as_secs() as i64)
                            .unwrap_or(0),
                        first_tracked_at: session
                            .first_tracked_at
                            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                            .map(|d| d.as_secs() as i64)
                            .unwrap_or(now_secs),
                        last_tracked_at: now_secs,
                    }
                })
                .collect();

            if let Some(sk) = sk_clone {
                // Derive HMAC key now and drop the SigningKey immediately
                // so it is not held alive inside the spawn_blocking closure.
                let mut key_bytes = sk.to_bytes();
                let hmac_key = crate::crypto::derive_hmac_key(&key_bytes);
                key_bytes.zeroize();
                drop(sk);
                let db = self.config.writersproof_dir.join("events.db");
                let save_result = tokio::time::timeout(
                    Duration::from_secs(2),
                    tokio::task::spawn_blocking(move || {
                        if let Ok(store) = crate::store::SecureStore::open(&db, hmac_key) {
                            for stats in &stats_list {
                                if let Err(e) = store.save_document_stats(stats) {
                                    log::warn!("Failed to persist document stats: {e}");
                                }
                            }
                        }
                    }),
                )
                .await;
                if save_result.is_err() {
                    log::warn!(
                        "Stats persistence timed out during stop; \
                         stats will be recovered on next session start"
                    );
                }
            }

            // Unfocus all sessions so they are preserved for restart.
            let mut paths: Vec<String> = self.sessions.read_recover().keys().cloned().collect();
            paths.sort();
            for path in paths {
                unfocus_document_sync(&path, &self.sessions, &self.session_events_tx);
            }
        }
        // current_focus is NOT cleared so run_event_loop() can re-focus
        // the same document on restart. The sessions above are unfocused
        // (has_focus = false) but still present in the map.

        self.shadow.cleanup_all();

        // Zeroize key material. SigningKey has ZeroizeOnDrop; take() drops
        // it now rather than waiting for Arc refcount to reach zero.
        self.signing_key.write_recover().reset();
        // session_nonce is [u8; 32]; zeroize under a single lock hold.
        {
            let mut guard = self.session_nonce.write_recover();
            if let Some(nonce) = guard.as_mut() {
                nonce.zeroize();
            }
            *guard = None;
        }

        // Reset stopping flag so the sentinel can be restarted.
        self.stopping.store(false, Ordering::SeqCst);

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

    /// Whether all bridge threads are alive. Returns false after any bridge
    /// thread exits unexpectedly; the sentinel drops events in this state.
    pub fn is_bridge_healthy(&self) -> bool {
        self.bridge_healthy.load(Ordering::SeqCst)
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
        self.stopping.store(true, Ordering::SeqCst);

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

        // Stop HID capture so the global callback doesn't leak.
        super::stop_hid_capture();

        // Abort the event loop task as a final safety net.
        if let Some(handle) = self.event_loop_handle.lock_recover().take() {
            handle.abort();
        }

        // Zeroize key material (safety net if stop() was never called).
        self.signing_key.write_recover().reset();
        {
            let mut guard = self.session_nonce.write_recover();
            if let Some(nonce) = guard.as_mut() {
                nonce.zeroize();
            }
            *guard = None;
        }
    }
}
