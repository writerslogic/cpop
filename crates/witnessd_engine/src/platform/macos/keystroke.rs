// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Keystroke monitoring with CGEventTap: KeystrokeMonitor and MacOSKeystrokeCapture.

use super::ffi::*;
use super::synthetic::verify_event_source;
use super::{EventVerificationResult, HIDDeviceInfo, KeystrokeEvent, SyntheticStats};
use crate::platform::KeystrokeCapture;
use anyhow::{anyhow, Result};
use core_foundation::runloop::{kCFRunLoopCommonModes, CFRunLoop};
use core_graphics::event::{
    CGEvent, CGEventTap, CGEventTapLocation, CGEventTapOptions, CGEventTapPlacement, CGEventType,
};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};

use crate::jitter::SimpleJitterSession;
use crate::DateTimeNanosExt;

// =============================================================================
// RunLoopHandle
// =============================================================================

/// Thread-safe handle to a CFRunLoop that can be stopped from another thread.
/// SAFETY: CFRunLoopStop is documented as thread-safe in Apple's documentation.
pub struct RunLoopHandle(pub(super) *mut std::ffi::c_void);
unsafe impl Send for RunLoopHandle {}
unsafe impl Sync for RunLoopHandle {}

// =============================================================================
// KeystrokeMonitor
// =============================================================================

/// Extended keystroke information including device fingerprint.
#[derive(Debug, Clone)]
pub struct KeystrokeInfo {
    pub timestamp_ns: i64,
    pub keycode: i64,
    pub zone: u8,
    pub verification: EventVerificationResult,
    pub device_hint: Option<HIDDeviceInfo>,
}

/// Callback type for enhanced keystroke monitoring.
pub type KeystrokeCallback = Arc<dyn Fn(KeystrokeInfo) + Send + Sync>;

/// Enhanced keystroke monitor with synthetic event detection.
pub struct KeystrokeMonitor {
    thread: Option<std::thread::JoinHandle<()>>,
    keystroke_count: Arc<AtomicU64>,
    verified_count: Arc<AtomicU64>,
    rejected_count: Arc<AtomicU64>,
    run_loop: Arc<Mutex<Option<RunLoopHandle>>>,
}

impl KeystrokeMonitor {
    /// Start the keystroke monitor with a simple jitter session.
    pub fn start(session: Arc<Mutex<SimpleJitterSession>>) -> Result<Self> {
        Self::start_with_callback(session, None)
    }

    /// Start the keystroke monitor with optional callback for extended info.
    pub fn start_with_callback(
        session: Arc<Mutex<SimpleJitterSession>>,
        callback: Option<KeystrokeCallback>,
    ) -> Result<Self> {
        let session_clone = Arc::clone(&session);
        Self::start_event_tap(
            move |event: &CGEvent, verification: EventVerificationResult| {
                let now = chrono::Utc::now().timestamp_nanos_safe();
                let keycode = event.get_integer_value_field(K_CG_KEYBOARD_EVENT_KEYCODE);
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

    /// Get total keystroke count (verified events only).
    pub fn keystroke_count(&self) -> u64 {
        self.keystroke_count.load(Ordering::SeqCst)
    }

    /// Get count of verified hardware events.
    pub fn verified_count(&self) -> u64 {
        self.verified_count.load(Ordering::SeqCst)
    }

    /// Get count of rejected synthetic events.
    pub fn rejected_count(&self) -> u64 {
        self.rejected_count.load(Ordering::SeqCst)
    }

    /// Check if synthetic injection has been detected.
    pub fn synthetic_injection_detected(&self) -> bool {
        self.rejected_count.load(Ordering::SeqCst) > 0
    }

    /// Start the keystroke monitor with a hybrid jitter session (witnessd_jitter-backed).
    ///
    /// This variant uses witnessd_jitter's hardware entropy when available,
    /// with automatic fallback to HMAC-based jitter.
    #[cfg(feature = "witnessd_jitter")]
    pub fn start_with_hybrid(
        session: Arc<Mutex<crate::witnessd_jitter_bridge::HybridJitterSession>>,
    ) -> Result<Self> {
        Self::start_with_hybrid_callback(session, None)
    }

    /// Start the keystroke monitor with a hybrid jitter session and optional callback.
    #[cfg(feature = "witnessd_jitter")]
    pub fn start_with_hybrid_callback(
        session: Arc<Mutex<crate::witnessd_jitter_bridge::HybridJitterSession>>,
        callback: Option<KeystrokeCallback>,
    ) -> Result<Self> {
        let session_clone = Arc::clone(&session);
        Self::start_event_tap(
            move |event: &CGEvent, verification: EventVerificationResult| {
                let keycode = event.get_integer_value_field(K_CG_KEYBOARD_EVENT_KEYCODE) as u16;
                let zone = crate::jitter::keycode_to_zone(keycode);

                // Record keystroke in hybrid session
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

    /// Shared CGEventTap setup for all keystroke monitor variants.
    ///
    /// Handles event tap creation, source verification, run loop lifecycle,
    /// and counter management. The `on_keystroke` closure is called for each
    /// verified (non-synthetic) KeyDown event.
    fn start_event_tap<F>(on_keystroke: F) -> Result<Self>
    where
        F: FnMut(&CGEvent, EventVerificationResult) + Send + 'static,
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

        // Wrap in Mutex so the FnMut closure can be called from FnOnce context
        let on_keystroke = Mutex::new(on_keystroke);

        let thread = std::thread::spawn(move || {
            let events = vec![CGEventType::KeyDown];
            let tap = CGEventTap::new(
                CGEventTapLocation::HID,
                CGEventTapPlacement::HeadInsertEventTap,
                CGEventTapOptions::ListenOnly,
                events,
                move |_proxy, event_type, event| {
                    if matches!(event_type, CGEventType::KeyDown) {
                        let verification = verify_event_source(event);

                        match verification {
                            EventVerificationResult::Synthetic => {
                                rej_count.fetch_add(1, Ordering::SeqCst);
                                return Some(event.to_owned());
                            }
                            EventVerificationResult::Hardware
                            | EventVerificationResult::Suspicious => {
                                ver_count.fetch_add(1, Ordering::SeqCst);
                            }
                        }

                        ks_count.fetch_add(1, Ordering::SeqCst);

                        if let Ok(mut handler) = on_keystroke.lock() {
                            handler(event, verification);
                        }
                    }
                    Some(event.to_owned())
                },
            );

            let tap = match tap {
                Ok(tap) => tap,
                Err(_) => {
                    let _ = ready_tx.send(Err(anyhow!("Failed to create CGEventTap")));
                    return;
                }
            };

            let loop_source = match tap.mach_port.create_runloop_source(0) {
                Ok(source) => source,
                Err(_) => {
                    let _ = ready_tx.send(Err(anyhow!("Failed to create runloop source")));
                    return;
                }
            };

            let current_loop = CFRunLoop::get_current();
            unsafe {
                let rl_ref = CFRunLoopGetCurrent();
                CFRetain(rl_ref);
                if let Ok(mut rl) = run_loop_clone.lock() {
                    *rl = Some(RunLoopHandle(rl_ref));
                }
                current_loop.add_source(&loop_source, kCFRunLoopCommonModes);
            }
            // Signal ready only after run_loop handle is stored (C-002 fix)
            let _ = ready_tx.send(Ok(()));
            tap.enable();
            CFRunLoop::run_current();
        });

        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                thread: Some(thread),
                keystroke_count,
                verified_count,
                rejected_count,
                run_loop,
            }),
            Ok(Err(err)) => Err(err),
            Err(_) => Err(anyhow!("Failed to initialize CGEventTap thread")),
        }
    }

    /// Stop the keystroke monitor, terminating its run loop and joining the thread.
    pub fn stop(&mut self) {
        // Extract pointer and signal stop (C-001 fix: release only after thread exits)
        let ptr = self
            .run_loop
            .lock()
            .ok()
            .and_then(|mut rl| rl.take().map(|h| h.0));
        if let Some(p) = ptr {
            unsafe {
                CFRunLoopStop(p);
            }
        }
        // Join thread before releasing the run loop reference
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        if let Some(p) = ptr {
            unsafe {
                CFRelease(p);
            }
        }
    }
}

impl Drop for KeystrokeMonitor {
    fn drop(&mut self) {
        self.stop();
    }
}

// =============================================================================
// MacOSKeystrokeCapture
// =============================================================================

/// macOS keystroke capture implementation.
pub struct MacOSKeystrokeCapture {
    running: Arc<AtomicBool>,
    sender: Option<mpsc::Sender<KeystrokeEvent>>,
    thread: Option<std::thread::JoinHandle<()>>,
    strict_mode: bool,
    /// Total events seen (atomic — no lock contention in CGEventTap callback)
    total_events: Arc<AtomicU64>,
    /// Verified hardware events
    verified_hardware: Arc<AtomicU64>,
    /// Rejected synthetic events
    rejected_synthetic: Arc<AtomicU64>,
    run_loop: Arc<Mutex<Option<RunLoopHandle>>>,
}

impl MacOSKeystrokeCapture {
    /// Create a new macOS keystroke capture instance.
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

        running.store(true, Ordering::SeqCst);

        let (ready_tx, ready_rx) = mpsc::channel();

        let thread = std::thread::spawn(move || {
            let events = vec![CGEventType::KeyDown];
            let tap = CGEventTap::new(
                CGEventTapLocation::HID,
                CGEventTapPlacement::HeadInsertEventTap,
                CGEventTapOptions::ListenOnly,
                events,
                move |_proxy, event_type, event| {
                    if !running.load(Ordering::SeqCst) {
                        return Some(event.to_owned());
                    }

                    if matches!(event_type, CGEventType::KeyDown) {
                        let verification = verify_event_source(event);

                        let is_hardware = match verification {
                            EventVerificationResult::Hardware => true,
                            EventVerificationResult::Suspicious => !strict,
                            EventVerificationResult::Synthetic => false,
                        };

                        // Update stats via atomics (lock-free in CGEventTap callback)
                        total_events.fetch_add(1, Ordering::Relaxed);
                        if is_hardware {
                            verified_hardware.fetch_add(1, Ordering::Relaxed);
                        } else {
                            rejected_synthetic.fetch_add(1, Ordering::Relaxed);
                        }

                        if is_hardware {
                            let now = chrono::Utc::now().timestamp_nanos_safe();
                            let keycode =
                                event.get_integer_value_field(K_CG_KEYBOARD_EVENT_KEYCODE) as u16;
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

                            let _ = tx.send(keystroke);
                        }
                    }
                    Some(event.to_owned())
                },
            );

            let tap = match tap {
                Ok(tap) => tap,
                Err(_) => {
                    let _ = ready_tx.send(Err(anyhow!("Failed to create CGEventTap")));
                    return;
                }
            };

            let loop_source = match tap.mach_port.create_runloop_source(0) {
                Ok(source) => source,
                Err(_) => {
                    let _ = ready_tx.send(Err(anyhow!("Failed to create runloop source")));
                    return;
                }
            };

            let current_loop = CFRunLoop::get_current();
            unsafe {
                let rl_ref = CFRunLoopGetCurrent();
                CFRetain(rl_ref);
                if let Ok(mut rl) = run_loop.lock() {
                    *rl = Some(RunLoopHandle(rl_ref));
                }
                current_loop.add_source(&loop_source, kCFRunLoopCommonModes);
            }
            // Signal ready only after run_loop handle is stored (C-002 fix)
            let _ = ready_tx.send(Ok(()));
            tap.enable();
            CFRunLoop::run_current();
        });

        match ready_rx.recv() {
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
                Err(anyhow!("Failed to initialize CGEventTap thread"))
            }
        }
    }

    fn stop(&mut self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);
        self.sender = None;
        // C-001 fix: release only after thread exits to prevent use-after-free
        let ptr = self
            .run_loop
            .lock()
            .ok()
            .and_then(|mut rl| rl.take().map(|h| h.0));
        if let Some(p) = ptr {
            unsafe {
                CFRunLoopStop(p);
            }
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        if let Some(p) = ptr {
            unsafe {
                CFRelease(p);
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
