// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! macOS mouse capture using CGEventTap for idle jitter and steganography.

use super::ffi::*;
use super::keystroke::RunLoopHandle;
use crate::platform::{MouseCapture, MouseEvent, MouseIdleStats, MouseStegoParams};
use anyhow::{anyhow, Result};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex, RwLock};

use crate::DateTimeNanosExt;
use crate::RwLockRecover;

/// macOS mouse capture implementation using CGEventTap.
pub struct MacOSMouseCapture {
    running: Arc<AtomicBool>,
    sender: Option<mpsc::Sender<MouseEvent>>,
    thread: Option<std::thread::JoinHandle<()>>,
    idle_stats: Arc<RwLock<MouseIdleStats>>,
    stego_params: MouseStegoParams,
    idle_only_mode: bool,
    last_position: Arc<RwLock<(f64, f64)>>,
    keyboard_active: Arc<AtomicBool>,
    last_keystroke_time: Arc<RwLock<std::time::Instant>>,
    run_loop: Arc<Mutex<Option<RunLoopHandle>>>,
}

impl MacOSMouseCapture {
    pub fn new() -> Result<Self> {
        Ok(Self {
            running: Arc::new(AtomicBool::new(false)),
            sender: None,
            thread: None,
            idle_stats: Arc::new(RwLock::new(MouseIdleStats::new())),
            stego_params: MouseStegoParams::default(),
            idle_only_mode: true,
            last_position: Arc::new(RwLock::new((0.0, 0.0))),
            keyboard_active: Arc::new(AtomicBool::new(false)),
            last_keystroke_time: Arc::new(RwLock::new(std::time::Instant::now())),
            run_loop: Arc::new(Mutex::new(None)),
        })
    }

    /// Notify the mouse capture that a keystroke occurred.
    ///
    /// This is used to detect idle periods for mouse jitter capture.
    pub fn notify_keystroke(&self) {
        self.keyboard_active.store(true, Ordering::SeqCst);
        if let Ok(mut time) = self.last_keystroke_time.write() {
            *time = std::time::Instant::now();
        }
    }
}

impl MouseCapture for MacOSMouseCapture {
    fn start(&mut self) -> Result<mpsc::Receiver<MouseEvent>> {
        if self.running.load(Ordering::SeqCst) {
            return Err(anyhow!("Mouse capture already running"));
        }

        let (tx, rx) = mpsc::channel();
        self.sender = Some(tx.clone());

        let running = Arc::clone(&self.running);
        let idle_stats = Arc::clone(&self.idle_stats);
        let last_position = Arc::clone(&self.last_position);
        let keyboard_active = Arc::clone(&self.keyboard_active);
        let last_keystroke_time = Arc::clone(&self.last_keystroke_time);
        let idle_only_mode = self.idle_only_mode;
        let run_loop = Arc::clone(&self.run_loop);

        running.store(true, Ordering::SeqCst);

        let (ready_tx, ready_rx) = mpsc::channel::<Result<()>>();

        let thread = std::thread::spawn(move || {
            let mut tap_cb: TapCallback =
                Box::new(move |event: *mut std::ffi::c_void, event_type: u32| {
                    if !running.load(Ordering::SeqCst) {
                        return;
                    }

                    if event_type == K_CG_EVENT_MOUSE_MOVED {
                        let should_capture = if idle_only_mode {
                            if let Ok(time) = last_keystroke_time.read() {
                                time.elapsed() < std::time::Duration::from_secs(2)
                            } else {
                                false
                            }
                        } else {
                            true
                        };

                        if !should_capture {
                            return;
                        }

                        let now = chrono::Utc::now().timestamp_nanos_safe();

                        let location = unsafe { CGEventGetLocation(event) };
                        let x = location.x;
                        let y = location.y;

                        let (dx, dy) = {
                            let mut last_pos = last_position.write_recover();
                            let delta = (x - last_pos.0, y - last_pos.1);
                            *last_pos = (x, y);
                            delta
                        };

                        let is_idle = !keyboard_active.load(Ordering::SeqCst);
                        let mouse_event = if is_idle {
                            MouseEvent::idle_jitter(now, x, y, dx, dy)
                        } else {
                            MouseEvent::new(now, x, y, dx, dy)
                        };

                        if mouse_event.is_micro_movement() && is_idle {
                            idle_stats.write_recover().record(&mouse_event);
                        }

                        let _ = tx.send(mouse_event);

                        if !idle_only_mode {
                            keyboard_active.store(false, Ordering::SeqCst);
                        }
                    }
                });

            unsafe {
                let tap = CGEventTapCreate(
                    K_CG_HID_EVENT_TAP,
                    K_CG_HEAD_INSERT_EVENT_TAP,
                    K_CG_EVENT_TAP_OPTION_LISTEN_ONLY,
                    cg_event_mask_bit(K_CG_EVENT_MOUSE_MOVED),
                    event_tap_trampoline,
                    &mut tap_cb as *mut TapCallback as *mut std::ffi::c_void,
                );

                if tap.is_null() {
                    let _ = ready_tx.send(Err(anyhow!("Failed to create CGEventTap")));
                    return;
                }

                let source = CFMachPortCreateRunLoopSource(std::ptr::null_mut(), tap, 0);
                if source.is_null() {
                    CFRelease(tap);
                    let _ = ready_tx.send(Err(anyhow!("Failed to create runloop source")));
                    return;
                }

                let _ = ready_tx.send(Ok(()));
                let rl_ref = CFRunLoopGetCurrent();
                CFRetain(rl_ref);
                if let Ok(mut rl) = run_loop.lock() {
                    *rl = Some(RunLoopHandle(rl_ref));
                }
                CFRunLoopAddSource(rl_ref, source, kCFRunLoopCommonModes);
                CGEventTapEnable(tap, true);
                CFRunLoopRun();
            }
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
                Err(anyhow!("Failed to initialize mouse CGEventTap thread"))
            }
        }
    }

    fn stop(&mut self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);
        self.sender = None;
        if let Ok(mut rl) = self.run_loop.lock() {
            if let Some(handle) = rl.take() {
                unsafe {
                    CFRunLoopStop(handle.0);
                    CFRelease(handle.0);
                }
            }
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        Ok(())
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    fn idle_stats(&self) -> MouseIdleStats {
        self.idle_stats.read_recover().clone()
    }

    fn reset_idle_stats(&mut self) {
        if let Ok(mut stats) = self.idle_stats.write() {
            *stats = MouseIdleStats::new();
        }
    }

    fn set_stego_params(&mut self, params: MouseStegoParams) {
        self.stego_params = params;
    }

    fn get_stego_params(&self) -> MouseStegoParams {
        self.stego_params.clone()
    }

    fn set_idle_only_mode(&mut self, enabled: bool) {
        self.idle_only_mode = enabled;
    }

    fn is_idle_only_mode(&self) -> bool {
        self.idle_only_mode
    }
}
