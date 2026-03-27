// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Keystroke monitoring with CGEventTap: KeystrokeMonitor and MacOSKeystrokeCapture.

use super::ffi::*;
use super::synthetic::verify_event_source;
use super::{EventVerificationResult, HidDeviceInfo, KeystrokeEvent, SyntheticStats};
use crate::platform::KeystrokeCapture;
use anyhow::{anyhow, Result};
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};

use crate::jitter::SimpleJitterSession;
use crate::DateTimeNanosExt;

/// Global counter for debug file writes (only write every 100th keystroke).
static DEBUG_KEYSTROKE_COUNTER: AtomicU64 = AtomicU64::new(0);
/// Global counter for tap-disabled-by-timeout events (for diagnostics).
static TAP_DISABLED_COUNT: AtomicU64 = AtomicU64::new(0);

/// Write a debug line to `$CPOP_DATA_DIR/keystroke_debug.txt` (append mode).
/// Only writes every 100th call to avoid I/O overhead in the hot path.
fn debug_write_keystroke(tag: &str, count: u64) {
    let n = DEBUG_KEYSTROKE_COUNTER.fetch_add(1, Ordering::Relaxed);
    if n % 100 != 0 {
        return;
    }
    let dir = match std::env::var("CPOP_DATA_DIR") {
        Ok(d) => d,
        Err(_) => return,
    };
    let path = std::path::Path::new(&dir).join("keystroke_debug.txt");
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        use std::io::Write;
        let now = chrono::Utc::now();
        let _ = writeln!(f, "[{now}] {tag}: event #{n}, total_count={count}");
    }
}

/// Thread-safe handle to a CFRunLoop that can be stopped from another thread.
/// SAFETY: CFRunLoopStop is documented as thread-safe in Apple's documentation.
pub struct RunLoopHandle(pub(super) *mut std::ffi::c_void);
unsafe impl Send for RunLoopHandle {}
unsafe impl Sync for RunLoopHandle {}

/// Holds CF objects created by CGEventTap so they can be released on shutdown.
struct EventTapResources {
    run_loop: *mut std::ffi::c_void,
    tap: *mut std::ffi::c_void,
    source: *mut std::ffi::c_void,
}
unsafe impl Send for EventTapResources {}
unsafe impl Sync for EventTapResources {}

#[derive(Debug, Clone)]
pub struct KeystrokeInfo {
    pub timestamp_ns: i64,
    pub keycode: i64,
    pub zone: u8,
    pub verification: EventVerificationResult,
    pub device_hint: Option<HidDeviceInfo>,
}

pub type KeystrokeCallback = Arc<dyn Fn(KeystrokeInfo) + Send + Sync>;

pub struct KeystrokeMonitor {
    thread: Option<std::thread::JoinHandle<()>>,
    keystroke_count: Arc<AtomicU64>,
    verified_count: Arc<AtomicU64>,
    rejected_count: Arc<AtomicU64>,
    run_loop: Arc<Mutex<Option<RunLoopHandle>>>,
    tap_resources: Arc<Mutex<Option<EventTapResources>>>,
}

impl KeystrokeMonitor {
    pub fn start(session: Arc<Mutex<SimpleJitterSession>>) -> Result<Self> {
        Self::start_with_callback(session, None)
    }

    pub fn start_with_callback(
        session: Arc<Mutex<SimpleJitterSession>>,
        callback: Option<KeystrokeCallback>,
    ) -> Result<Self> {
        let session_clone = Arc::clone(&session);
        Self::start_event_tap(
            move |event: *mut std::ffi::c_void, verification: EventVerificationResult| {
                let now = chrono::Utc::now().timestamp_nanos_safe();
                let keycode =
                    unsafe { CGEventGetIntegerValueField(event, K_CG_KEYBOARD_EVENT_KEYCODE) };
                let zone_i = crate::jitter::keycode_to_zone(keycode as u16);
                let zone = if zone_i >= 0 { zone_i as u8 } else { 0xFF };

                if let Ok(mut s) = session_clone.lock() {
                    s.add_sample(now, zone);
                }

                if let Some(ref cb) = callback {
                    cb(KeystrokeInfo {
                        timestamp_ns: now,
                        keycode,
                        zone,
                        verification,
                        device_hint: None,
                    });
                }
            },
        )
    }

    pub fn keystroke_count(&self) -> u64 {
        self.keystroke_count.load(Ordering::SeqCst)
    }

    pub fn verified_count(&self) -> u64 {
        self.verified_count.load(Ordering::SeqCst)
    }

    pub fn rejected_count(&self) -> u64 {
        self.rejected_count.load(Ordering::SeqCst)
    }

    pub fn synthetic_injection_detected(&self) -> bool {
        self.rejected_count.load(Ordering::SeqCst) > 0
    }

    #[cfg(feature = "cpop_jitter")]
    pub fn start_with_hybrid(
        session: Arc<Mutex<crate::cpop_jitter_bridge::HybridJitterSession>>,
    ) -> Result<Self> {
        Self::start_with_hybrid_callback(session, None)
    }

    #[cfg(feature = "cpop_jitter")]
    pub fn start_with_hybrid_callback(
        session: Arc<Mutex<crate::cpop_jitter_bridge::HybridJitterSession>>,
        callback: Option<KeystrokeCallback>,
    ) -> Result<Self> {
        let session_clone = Arc::clone(&session);
        Self::start_event_tap(
            move |event: *mut std::ffi::c_void, verification: EventVerificationResult| {
                let keycode =
                    unsafe { CGEventGetIntegerValueField(event, K_CG_KEYBOARD_EVENT_KEYCODE) }
                        as u16;
                let zone = crate::jitter::keycode_to_zone(keycode);

                if let Ok(mut s) = session_clone.lock() {
                    let _ = s.record_keystroke(keycode);
                }

                if let Some(ref cb) = callback {
                    let now = chrono::Utc::now().timestamp_nanos_safe();
                    cb(KeystrokeInfo {
                        timestamp_ns: now,
                        keycode: keycode as i64,
                        zone: if zone >= 0 { zone as u8 } else { 0xFF },
                        verification,
                        device_hint: None,
                    });
                }
            },
        )
    }

    fn start_event_tap<F>(on_keystroke: F) -> Result<Self>
    where
        F: FnMut(*mut std::ffi::c_void, EventVerificationResult) + Send + 'static,
    {
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();

        let keystroke_count = Arc::new(AtomicU64::new(0));
        let verified_count = Arc::new(AtomicU64::new(0));
        let rejected_count = Arc::new(AtomicU64::new(0));

        let ks_count = Arc::clone(&keystroke_count);
        let ver_count = Arc::clone(&verified_count);
        let rej_count = Arc::clone(&rejected_count);

        let run_loop: Arc<Mutex<Option<RunLoopHandle>>> = Arc::new(Mutex::new(None));
        let run_loop_clone = Arc::clone(&run_loop);
        let tap_resources: Arc<Mutex<Option<EventTapResources>>> = Arc::new(Mutex::new(None));
        let tap_resources_clone = Arc::clone(&tap_resources);

        // Shared pointer so the callback can re-enable the tap after timeout.
        let tap_ptr = Arc::new(AtomicPtr::new(std::ptr::null_mut()));
        let tap_ptr_cb = Arc::clone(&tap_ptr);

        // H-070: No Mutex around on_keystroke; the callback is only ever invoked
        // from the single run-loop thread, so &mut access is safe without locking.
        let mut on_keystroke = on_keystroke;

        let thread = std::thread::spawn(move || {
            let mut tap_cb: TapCallback =
                Box::new(move |event: *mut std::ffi::c_void, event_type: u32| {
                    // macOS disables the tap when the callback is too slow.
                    // Re-enable it immediately.
                    if event_type == K_CG_EVENT_TAP_DISABLED_BY_TIMEOUT {
                        let ptr: *mut std::ffi::c_void = tap_ptr_cb.load(Ordering::SeqCst);
                        if !ptr.is_null() {
                            unsafe { CGEventTapEnable(ptr, true) };
                        }
                        let n = TAP_DISABLED_COUNT.fetch_add(1, Ordering::Relaxed);
                        log::warn!(
                            "CGEventTap disabled by timeout, re-enabled (count={})",
                            n + 1
                        );
                        return;
                    }

                    if event_type == K_CG_EVENT_KEY_DOWN {
                        let verification = unsafe { verify_event_source(event) };

                        match verification {
                            EventVerificationResult::Synthetic => {
                                rej_count.fetch_add(1, Ordering::SeqCst);
                                return;
                            }
                            EventVerificationResult::Hardware => {
                                ver_count.fetch_add(1, Ordering::SeqCst);
                            }
                            EventVerificationResult::Suspicious => {
                                // Suspicious events are forwarded but not counted as
                                // verified hardware; the caller sees the verification
                                // variant and can decide how to weight the event.
                            }
                        }

                        let count = ks_count.fetch_add(1, Ordering::SeqCst) + 1;
                        debug_write_keystroke("tap_cb", count);

                        on_keystroke(event, verification);
                    }
                });

            unsafe {
                let tap = CGEventTapCreate(
                    K_CG_HID_EVENT_TAP,
                    K_CG_HEAD_INSERT_EVENT_TAP,
                    K_CG_EVENT_TAP_OPTION_LISTEN_ONLY,
                    cg_event_mask_bit(K_CG_EVENT_KEY_DOWN),
                    event_tap_trampoline,
                    &mut tap_cb as *mut TapCallback as *mut std::ffi::c_void,
                );

                if tap.is_null() {
                    let _ = ready_tx.send(Err(anyhow!("Failed to create CGEventTap")));
                    return;
                }

                // Store tap pointer so the callback can re-enable after timeout.
                tap_ptr.store(tap, Ordering::SeqCst);

                let source = CFMachPortCreateRunLoopSource(std::ptr::null_mut(), tap, 0);
                if source.is_null() {
                    CFRelease(tap);
                    tap_ptr.store(std::ptr::null_mut(), Ordering::SeqCst);
                    let _ = ready_tx.send(Err(anyhow!("Failed to create runloop source")));
                    return;
                }

                let rl_ref = CFRunLoopGetCurrent();
                CFRetain(rl_ref);
                if let Ok(mut rl) = run_loop_clone.lock() {
                    *rl = Some(RunLoopHandle(rl_ref));
                }
                // H-071: Store tap and source for cleanup in stop()/Drop
                if let Ok(mut res) = tap_resources_clone.lock() {
                    *res = Some(EventTapResources {
                        run_loop: rl_ref,
                        tap,
                        source,
                    });
                }
                CFRunLoopAddSource(rl_ref, source, kCFRunLoopCommonModes);
                // Signal ready only after run_loop handle is stored (C-002 fix)
                let _ = ready_tx.send(Ok(()));
                CGEventTapEnable(tap, true);
                CFRunLoopRun();
            }
        });

        match ready_rx.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(Ok(())) => Ok(Self {
                thread: Some(thread),
                keystroke_count,
                verified_count,
                rejected_count,
                run_loop,
                tap_resources,
            }),
            Ok(Err(err)) => Err(err),
            Err(_) => Err(anyhow!("CGEventTap initialization timed out after 5s")),
        }
    }

    pub fn stop(&mut self) {
        // C-001: Stop the run loop first so the thread can exit, but take the
        // handle so a second call to stop() (e.g. from Drop) is a no-op.
        let rl_ptr = self
            .run_loop
            .lock()
            .ok()
            .and_then(|mut rl| rl.take().map(|h| h.0));
        if let Some(p) = rl_ptr {
            unsafe {
                CFRunLoopStop(p);
            }
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        // H-071: Release tap, source, and run loop after thread has exited.
        // tap_resources holds the canonical copies; run_loop was only taken
        // above to call CFRunLoopStop. Release everything exactly once here.
        if let Some(res) = self.tap_resources.lock().ok().and_then(|mut r| r.take()) {
            unsafe {
                CFRelease(res.source);
                CFRelease(res.tap);
                CFRelease(res.run_loop);
            }
        }
    }
}

impl Drop for KeystrokeMonitor {
    fn drop(&mut self) {
        self.stop();
    }
}

pub struct MacOSKeystrokeCapture {
    running: Arc<AtomicBool>,
    sender: Option<mpsc::Sender<KeystrokeEvent>>,
    thread: Option<std::thread::JoinHandle<()>>,
    strict_mode: bool,
    total_events: Arc<AtomicU64>,
    verified_hardware: Arc<AtomicU64>,
    rejected_synthetic: Arc<AtomicU64>,
    run_loop: Arc<Mutex<Option<RunLoopHandle>>>,
    tap_resources: Arc<Mutex<Option<EventTapResources>>>,
}

impl MacOSKeystrokeCapture {
    pub fn new() -> Result<Self> {
        Ok(Self {
            running: Arc::new(AtomicBool::new(false)),
            sender: None,
            thread: None,
            strict_mode: true,
            total_events: Arc::new(AtomicU64::new(0)),
            verified_hardware: Arc::new(AtomicU64::new(0)),
            rejected_synthetic: Arc::new(AtomicU64::new(0)),
            run_loop: Arc::new(Mutex::new(None)),
            tap_resources: Arc::new(Mutex::new(None)),
        })
    }
}

impl KeystrokeCapture for MacOSKeystrokeCapture {
    fn start(&mut self) -> Result<mpsc::Receiver<KeystrokeEvent>> {
        if self.running.load(Ordering::SeqCst) {
            return Err(anyhow!("Keystroke capture already running"));
        }

        let (tx, rx) = mpsc::channel();
        self.sender = Some(tx.clone());

        let running = Arc::clone(&self.running);
        let total_events = Arc::clone(&self.total_events);
        let verified_hardware = Arc::clone(&self.verified_hardware);
        let rejected_synthetic = Arc::clone(&self.rejected_synthetic);
        let strict = self.strict_mode;
        let run_loop = Arc::clone(&self.run_loop);
        let tap_resources = Arc::clone(&self.tap_resources);

        running.store(true, Ordering::SeqCst);

        // Shared pointer so the callback can re-enable the tap after timeout.
        let tap_ptr = Arc::new(AtomicPtr::new(std::ptr::null_mut()));
        let tap_ptr_cb = Arc::clone(&tap_ptr);

        let (ready_tx, ready_rx) = mpsc::channel();

        let thread = std::thread::spawn(move || {
            let mut tap_cb: TapCallback =
                Box::new(move |event: *mut std::ffi::c_void, event_type: u32| {
                    if !running.load(Ordering::SeqCst) {
                        return;
                    }

                    // macOS disables the tap when the callback is too slow.
                    // Re-enable it immediately.
                    if event_type == K_CG_EVENT_TAP_DISABLED_BY_TIMEOUT {
                        let ptr: *mut std::ffi::c_void = tap_ptr_cb.load(Ordering::SeqCst);
                        if !ptr.is_null() {
                            unsafe { CGEventTapEnable(ptr, true) };
                        }
                        let n = TAP_DISABLED_COUNT.fetch_add(1, Ordering::Relaxed);
                        log::warn!(
                            "CGEventTap disabled by timeout, re-enabled (count={})",
                            n + 1
                        );
                        return;
                    }

                    if event_type == K_CG_EVENT_KEY_DOWN {
                        let verification = unsafe { verify_event_source(event) };

                        let is_hardware = match verification {
                            EventVerificationResult::Hardware => true,
                            EventVerificationResult::Suspicious => !strict,
                            EventVerificationResult::Synthetic => false,
                        };

                        total_events.fetch_add(1, Ordering::Relaxed);
                        if is_hardware {
                            verified_hardware.fetch_add(1, Ordering::Relaxed);
                        } else {
                            rejected_synthetic.fetch_add(1, Ordering::Relaxed);
                        }

                        if is_hardware {
                            let now = chrono::Utc::now().timestamp_nanos_safe();
                            let keycode = unsafe {
                                CGEventGetIntegerValueField(event, K_CG_KEYBOARD_EVENT_KEYCODE)
                            } as u16;
                            let zone = crate::jitter::keycode_to_zone(keycode);

                            let keystroke = KeystrokeEvent {
                                timestamp_ns: now,
                                keycode,
                                zone: if zone >= 0 { zone as u8 } else { 0xFF },
                                char_value: None,
                                is_hardware: true,
                                device_id: None,
                                transport_type: None,
                            };

                            debug_write_keystroke(
                                "capture_tx",
                                total_events.load(Ordering::Relaxed),
                            );
                            let _ = tx.send(keystroke);
                        }
                    }
                });

            unsafe {
                let tap = CGEventTapCreate(
                    K_CG_HID_EVENT_TAP,
                    K_CG_HEAD_INSERT_EVENT_TAP,
                    K_CG_EVENT_TAP_OPTION_LISTEN_ONLY,
                    cg_event_mask_bit(K_CG_EVENT_KEY_DOWN),
                    event_tap_trampoline,
                    &mut tap_cb as *mut TapCallback as *mut std::ffi::c_void,
                );

                if tap.is_null() {
                    let _ = ready_tx.send(Err(anyhow!("Failed to create CGEventTap")));
                    return;
                }

                // Store tap pointer so the callback can re-enable after timeout.
                tap_ptr.store(tap, Ordering::SeqCst);

                let source = CFMachPortCreateRunLoopSource(std::ptr::null_mut(), tap, 0);
                if source.is_null() {
                    CFRelease(tap);
                    tap_ptr.store(std::ptr::null_mut(), Ordering::SeqCst);
                    let _ = ready_tx.send(Err(anyhow!("Failed to create runloop source")));
                    return;
                }

                let rl_ref = CFRunLoopGetCurrent();
                CFRetain(rl_ref);
                if let Ok(mut rl) = run_loop.lock() {
                    *rl = Some(RunLoopHandle(rl_ref));
                }
                // H-072: Store tap and source for cleanup in stop()/Drop
                if let Ok(mut res) = tap_resources.lock() {
                    *res = Some(EventTapResources {
                        run_loop: rl_ref,
                        tap,
                        source,
                    });
                }
                CFRunLoopAddSource(rl_ref, source, kCFRunLoopCommonModes);
                // Signal ready only after run_loop handle is stored (C-002 fix)
                let _ = ready_tx.send(Ok(()));
                CGEventTapEnable(tap, true);
                CFRunLoopRun();
            }
        });

        match ready_rx.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(Ok(())) => {
                self.thread = Some(thread);
                Ok(rx)
            }
            Ok(Err(err)) => {
                self.running.store(false, Ordering::SeqCst);
                self.sender = None;
                Err(err)
            }
            Err(_) => {
                self.running.store(false, Ordering::SeqCst);
                self.sender = None;
                Err(anyhow!("CGEventTap initialization timed out after 5s"))
            }
        }
    }

    fn stop(&mut self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);
        self.sender = None;
        // C-001: Stop the run loop first so the thread can exit, but take the
        // handle so a second call to stop() (e.g. from Drop) is a no-op.
        let rl_ptr = self
            .run_loop
            .lock()
            .ok()
            .and_then(|mut rl| rl.take().map(|h| h.0));
        if let Some(p) = rl_ptr {
            unsafe {
                CFRunLoopStop(p);
            }
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        // H-072: Release tap, source, and run loop after thread has exited.
        // tap_resources holds the canonical copies; run_loop was only taken
        // above to call CFRunLoopStop. Release everything exactly once here.
        if let Some(res) = self.tap_resources.lock().ok().and_then(|mut r| r.take()) {
            unsafe {
                CFRelease(res.source);
                CFRelease(res.tap);
                CFRelease(res.run_loop);
            }
        }
        Ok(())
    }

    fn synthetic_stats(&self) -> SyntheticStats {
        SyntheticStats {
            total_events: self.total_events.load(Ordering::Relaxed),
            verified_hardware: self.verified_hardware.load(Ordering::Relaxed),
            rejected_synthetic: self.rejected_synthetic.load(Ordering::Relaxed),
            ..SyntheticStats::default()
        }
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    fn set_strict_mode(&mut self, strict: bool) {
        self.strict_mode = strict;
    }

    fn get_strict_mode(&self) -> bool {
        self.strict_mode
    }
}

impl Drop for MacOSKeystrokeCapture {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
