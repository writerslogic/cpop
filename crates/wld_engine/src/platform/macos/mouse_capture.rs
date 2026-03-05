// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! macOS mouse capture using CGEventTap for idle jitter and steganography.

use super::ffi::*;
use super::keystroke::RunLoopHandle;
use crate::platform::{MouseCapture, MouseEvent, MouseIdleStats, MouseStegoParams};
use anyhow::{anyhow, Result};
use core_foundation::runloop::{kCFRunLoopCommonModes, CFRunLoop};
use core_graphics::event::{
    CGEventTap, CGEventTapLocation, CGEventTapOptions, CGEventTapPlacement, CGEventType,
};
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
            idle_only_mode: true, // Default to idle-only for fingerprinting
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
            // Capture mouse moved events
            let events = vec![CGEventType::MouseMoved];

            let tap = CGEventTap::new(
                CGEventTapLocation::HID,
                CGEventTapPlacement::HeadInsertEventTap,
                CGEventTapOptions::ListenOnly, // Listen only, don't modify
                events,
                move |_proxy, event_type, event| {
                    if !running.load(Ordering::SeqCst) {
                        return Some(event.to_owned());
                    }

                    if matches!(event_type, CGEventType::MouseMoved) {
                        // Check if we should capture (idle-only mode consideration)
                        let should_capture = if idle_only_mode {
                            // Only capture if keyboard was active recently (within 2 seconds)
                            if let Ok(time) = last_keystroke_time.read() {
                                time.elapsed() < std::time::Duration::from_secs(2)
                            } else {
                                false
                            }
                        } else {
                            true
                        };

                        if !should_capture {
                            return Some(event.to_owned());
                        }

                        let now = chrono::Utc::now().timestamp_nanos_safe();

                        // Get mouse position from event
                        // CGEvent location is in screen coordinates
                        let location = event.location();
                        let x = location.x;
                        let y = location.y;

                        // Calculate delta from last position
                        let (dx, dy) = {
                            let mut last_pos = last_position.write_recover();
                            let delta = (x - last_pos.0, y - last_pos.1);
                            *last_pos = (x, y);
                            delta
                        };

                        // Create mouse event
                        let is_idle = !keyboard_active.load(Ordering::SeqCst);
                        let mouse_event = if is_idle {
                            MouseEvent::idle_jitter(now, x, y, dx, dy)
                        } else {
                            MouseEvent::new(now, x, y, dx, dy)
                        };

                        // Record idle statistics for micro-movements
                        if mouse_event.is_micro_movement() && is_idle {
                            idle_stats.write_recover().record(&mouse_event);
                        }

                        // Send event
                        let _ = tx.send(mouse_event);

                        // Reset keyboard active flag after processing
                        // (will be set again by next keystroke)
                        if !idle_only_mode {
                            keyboard_active.store(false, Ordering::SeqCst);
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

            let _ = ready_tx.send(Ok(()));
            let current_loop = CFRunLoop::get_current();
            unsafe {
                // Store the run loop ref so stop() can terminate it
                let rl_ref = CFRunLoopGetCurrent();
                CFRetain(rl_ref);
                if let Ok(mut rl) = run_loop.lock() {
                    *rl = Some(RunLoopHandle(rl_ref));
                }
                current_loop.add_source(&loop_source, kCFRunLoopCommonModes);
            }
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
                Err(anyhow!("Failed to initialize mouse CGEventTap thread"))
            }
        }
    }

    fn stop(&mut self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);
        self.sender = None;
        // Stop the CFRunLoop so the thread can exit
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
