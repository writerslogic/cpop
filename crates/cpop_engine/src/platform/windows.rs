// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Windows platform implementation using WH_KEYBOARD_LL hook.
//!
//! This module provides keystroke capture via the low-level keyboard hook
//! and focus tracking via GetForegroundWindow.

use super::{
    FocusInfo, FocusMonitor, KeystrokeCapture, KeystrokeEvent, MouseCapture, MouseEvent,
    MouseIdleStats, MouseStegoParams, PermissionStatus, SyntheticStats,
};
use crate::DateTimeNanosExt;
use crate::{MutexRecover, RwLockRecover};
use anyhow::{anyhow, Result};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, Ordering};
use std::sync::{mpsc, Arc, Mutex, RwLock};
use windows::Win32::Foundation::{LPARAM, LRESULT, WPARAM};
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CallNextHookEx, GetForegroundWindow, GetMessageW, GetWindowTextW, GetWindowThreadProcessId,
    PostThreadMessageW, SetWindowsHookExW, UnhookWindowsHookEx, HHOOK, KBDLLHOOKSTRUCT,
    LLKHF_INJECTED, MSG, MSLLHOOKSTRUCT, WH_KEYBOARD_LL, WH_MOUSE_LL, WM_KEYDOWN, WM_MOUSEMOVE,
    WM_QUIT, WM_SYSKEYDOWN,
};

use crate::jitter::SimpleJitterSession;

/// A wrapper around HHOOK that implements Send + Sync.
///
/// # Safety
///
/// This is safe because:
/// - HHOOK handles are thread-safe for the operations we perform (unhook)
/// - The hook callback runs in the context of the thread that processes messages
/// - We properly synchronize access through the struct's atomics and only
///   unhook from the same thread context (via Drop)
#[derive(Debug)]
struct HookHandle(HHOOK);

// SAFETY: HHOOK is a handle that can be safely sent between threads.
// The actual hook callback runs in the message pump thread, and
// UnhookWindowsHookEx can be called from any thread.
unsafe impl Send for HookHandle {}
unsafe impl Sync for HookHandle {}

/// Get combined permission status.
/// On Windows, low-level keyboard hooks don't require special permissions.
pub fn get_permission_status() -> PermissionStatus {
    PermissionStatus {
        accessibility: true,
        input_monitoring: true,
        input_devices: true,
        all_granted: true,
    }
}

/// Request all required permissions.
/// On Windows, no special permissions are needed.
pub fn request_all_permissions() -> PermissionStatus {
    get_permission_status()
}

/// Check if all required permissions are granted.
pub fn has_required_permissions() -> bool {
    true
}

/// Get information about the currently focused application and document.
pub fn get_active_focus() -> Result<FocusInfo> {
    unsafe {
        let hwnd = GetForegroundWindow();
        if hwnd.0.is_null() {
            return Err(anyhow!("No active window"));
        }

        let mut pid = 0;
        GetWindowThreadProcessId(hwnd, Some(&mut pid));
        let app_path = get_process_path(pid)?;
        let app_name = std::path::Path::new(&app_path)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();

        let mut title_buffer = [0u16; 512];
        let title_len = GetWindowTextW(hwnd, &mut title_buffer);
        let window_title = if title_len > 0 {
            Some(String::from_utf16_lossy(
                &title_buffer[..title_len as usize],
            ))
        } else {
            None
        };

        Ok(FocusInfo {
            app_name,
            bundle_id: app_path.clone(),
            pid: pid as i32,
            doc_path: extract_doc_path_from_title(window_title.as_deref()),
            doc_title: window_title.clone(),
            window_title,
        })
    }
}

fn get_process_path(pid: u32) -> Result<String> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)?;
        let mut path = [0u16; 1024];
        let mut size = path.len() as u32;
        QueryFullProcessImageNameW(
            handle,
            Default::default(),
            windows::core::PWSTR(path.as_mut_ptr()),
            &mut size,
        )?;
        Ok(String::from_utf16_lossy(&path[..size as usize]))
    }
}

/// Try to extract document path from window title.
/// Many applications include the file path or name in the window title.
fn extract_doc_path_from_title(title: Option<&str>) -> Option<String> {
    let title = title?;

    for sep in [" - ", " \u{2014} ", " | "] {
        if let Some(parts) = title.split_once(sep) {
            for part in [parts.0, parts.1] {
                if looks_like_path(part) {
                    return Some(part.to_string());
                }
            }
        }
    }

    if looks_like_path(title) {
        return Some(title.to_string());
    }

    None
}

fn looks_like_path(s: &str) -> bool {
    (s.len() > 2 && s.chars().nth(1) == Some(':'))
        || s.starts_with("\\\\")
        || s.contains('\\')
        || s.contains('/')
}

/// Low-level keyboard hook monitor feeding a jitter session.
pub struct KeystrokeMonitor {
    session: Arc<Mutex<SimpleJitterSession>>,
    _hook: isize,
    pump_thread: Option<std::thread::JoinHandle<()>>,
    pump_thread_id: u32,
}

static GLOBAL_SESSION: Mutex<Option<Arc<Mutex<SimpleJitterSession>>>> = Mutex::new(None);
/// Guard ensuring only one KeystrokeMonitor instance exists at a time.
static MONITOR_ACTIVE: AtomicBool = AtomicBool::new(false);

impl KeystrokeMonitor {
    /// Install the keyboard hook and begin feeding keystrokes to the session.
    ///
    /// Returns an error if a monitor is already active (only one instance allowed).
    pub fn start(session: Arc<Mutex<SimpleJitterSession>>) -> Result<Self> {
        if MONITOR_ACTIVE.swap(true, Ordering::SeqCst) {
            return Err(anyhow!("KeystrokeMonitor already active"));
        }
        *GLOBAL_SESSION.lock_recover() = Some(Arc::clone(&session));
        unsafe {
            let hook = SetWindowsHookExW(WH_KEYBOARD_LL, Some(low_level_keyboard_proc), None, 0)?;
            let tid = Arc::new(AtomicU32::new(0));
            let tid_clone = Arc::clone(&tid);
            let handle = std::thread::spawn(move || {
                tid_clone.store(GetCurrentThreadId(), Ordering::Release);
                let mut msg = MSG::default();
                while GetMessageW(&mut msg, None, 0, 0).into() {}
            });
            // Spin briefly until the pump thread publishes its thread ID.
            while tid.load(Ordering::Acquire) == 0 {
                std::thread::yield_now();
            }
            Ok(Self {
                session,
                _hook: hook.0 as isize,
                pump_thread: Some(handle),
                pump_thread_id: tid.load(Ordering::Acquire),
            })
        }
    }
}

impl Drop for KeystrokeMonitor {
    fn drop(&mut self) {
        unsafe {
            let _ = UnhookWindowsHookEx(HHOOK(self._hook as *mut _));
            // Signal the message pump thread to exit and join it.
            let _ = PostThreadMessageW(self.pump_thread_id, WM_QUIT, WPARAM(0), LPARAM(0));
        }
        if let Some(handle) = self.pump_thread.take() {
            let _ = handle.join();
        }
        *GLOBAL_SESSION.lock_recover() = None;
        MONITOR_ACTIVE.store(false, Ordering::SeqCst);
    }
}

unsafe extern "system" fn low_level_keyboard_proc(
    code: i32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if code >= 0 && (wparam.0 as u32 == WM_KEYDOWN || wparam.0 as u32 == WM_SYSKEYDOWN) {
        let ptr = lparam.0 as *const KBDLLHOOKSTRUCT;
        if ptr.is_null() {
            return CallNextHookEx(None, code, wparam, lparam);
        }
        let kbd = *ptr;
        let now = chrono::Utc::now().timestamp_nanos_safe();
        let session = match GLOBAL_SESSION.lock() {
            Ok(g) => g.clone(),
            Err(poisoned) => {
                log::error!("GLOBAL_SESSION mutex poisoned: {}", poisoned);
                None
            }
        };
        if let Some(session_arc) = session {
            if let Ok(mut s) = session_arc.lock() {
                s.add_sample(now, (kbd.vkCode % 8) as u8);
            }
        }
    }
    CallNextHookEx(None, code, wparam, lparam)
}

/// Windows keystroke capture implementation.
pub struct WindowsKeystrokeCapture {
    running: Arc<AtomicBool>,
    sender: Option<mpsc::Sender<KeystrokeEvent>>,
    hook: Option<HookHandle>,
    strict_mode: bool,
    stats: Arc<RwLock<SyntheticStats>>,
    pump_thread: Option<std::thread::JoinHandle<()>>,
    pump_thread_id: Arc<std::sync::atomic::AtomicU32>,
}

static GLOBAL_SENDER: Mutex<Option<mpsc::Sender<KeystrokeEvent>>> = Mutex::new(None);
static GLOBAL_STATS: Mutex<Option<Arc<RwLock<SyntheticStats>>>> = Mutex::new(None);
static GLOBAL_STRICT_MODE: AtomicBool = AtomicBool::new(true);
/// Guard ensuring only one WindowsKeystrokeCapture instance is active at a time.
static CAPTURE_ACTIVE: AtomicBool = AtomicBool::new(false);

impl WindowsKeystrokeCapture {
    pub fn new() -> Result<Self> {
        Ok(Self {
            running: Arc::new(AtomicBool::new(false)),
            sender: None,
            hook: None,
            strict_mode: true,
            stats: Arc::new(RwLock::new(SyntheticStats::default())),
            pump_thread: None,
            pump_thread_id: Arc::new(std::sync::atomic::AtomicU32::new(0)),
        })
    }
}

impl KeystrokeCapture for WindowsKeystrokeCapture {
    fn start(&mut self) -> Result<mpsc::Receiver<KeystrokeEvent>> {
        if self.running.load(Ordering::SeqCst) {
            return Err(anyhow!("Keystroke capture already running"));
        }
        if CAPTURE_ACTIVE.swap(true, Ordering::SeqCst) {
            return Err(anyhow!(
                "Another WindowsKeystrokeCapture instance is already active"
            ));
        }

        let (tx, rx) = mpsc::channel();
        self.sender = Some(tx.clone());

        *GLOBAL_SENDER.lock_recover() = Some(tx);
        *GLOBAL_STATS.lock_recover() = Some(Arc::clone(&self.stats));
        GLOBAL_STRICT_MODE.store(self.strict_mode, Ordering::SeqCst);

        self.running.store(true, Ordering::SeqCst);

        unsafe {
            let hook = SetWindowsHookExW(WH_KEYBOARD_LL, Some(keystroke_capture_hook), None, 0)?;
            self.hook = Some(HookHandle(hook));
        }

        let running = Arc::clone(&self.running);
        let thread_id_store = Arc::clone(&self.pump_thread_id);
        let handle = std::thread::spawn(move || {
            // Record this thread's ID so stop() can post WM_QUIT to wake GetMessageW.
            let tid = unsafe { GetCurrentThreadId() };
            thread_id_store.store(tid, Ordering::SeqCst);

            let mut msg = MSG::default();
            while running.load(Ordering::SeqCst) {
                unsafe {
                    if GetMessageW(&mut msg, None, 0, 0).0 <= 0 {
                        break;
                    }
                }
            }
        });
        self.pump_thread = Some(handle);

        Ok(rx)
    }

    fn stop(&mut self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);

        if let Some(hook_handle) = self.hook.take() {
            unsafe {
                if let Err(e) = UnhookWindowsHookEx(hook_handle.0) {
                    log::warn!("UnhookWindowsHookEx failed for keyboard hook: {e}");
                }
            }
        }

        *GLOBAL_SENDER.lock_recover() = None;
        *GLOBAL_STATS.lock_recover() = None;

        // Post WM_QUIT to unblock GetMessageW in the pump thread, then join it.
        let tid = self.pump_thread_id.load(Ordering::SeqCst);
        if tid != 0 {
            unsafe {
                let _ = PostThreadMessageW(tid, WM_QUIT, WPARAM(0), LPARAM(0));
            }
        }
        if let Some(handle) = self.pump_thread.take() {
            let _ = handle.join();
        }

        self.sender = None;
        CAPTURE_ACTIVE.store(false, Ordering::SeqCst);
        Ok(())
    }

    fn synthetic_stats(&self) -> SyntheticStats {
        self.stats.read_recover().clone()
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    fn set_strict_mode(&mut self, strict: bool) {
        self.strict_mode = strict;
        GLOBAL_STRICT_MODE.store(strict, Ordering::SeqCst);
    }

    fn get_strict_mode(&self) -> bool {
        self.strict_mode
    }
}

impl Drop for WindowsKeystrokeCapture {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

unsafe extern "system" fn keystroke_capture_hook(
    code: i32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if code >= 0 && (wparam.0 as u32 == WM_KEYDOWN || wparam.0 as u32 == WM_SYSKEYDOWN) {
        let ptr = lparam.0 as *const KBDLLHOOKSTRUCT;
        if ptr.is_null() {
            return CallNextHookEx(None, code, wparam, lparam);
        }
        let kbd = *ptr;

        // LLKHF_INJECTED detects SendInput/keybd_event injections but not all
        // synthetic sources (e.g., DirectInput or driver-level injection may bypass it).
        let is_injected = (kbd.flags.0 & LLKHF_INJECTED.0) != 0;

        let stats_arc = GLOBAL_STATS.lock().ok().and_then(|g| g.clone());
        if let Some(stats) = stats_arc {
            if let Ok(mut s) = stats.write() {
                s.total_events += 1;
                if is_injected {
                    s.rejected_synthetic += 1;
                    s.rejection_reasons.injected_flag += 1;
                } else {
                    s.verified_hardware += 1;
                }
            }
        }

        if is_injected && GLOBAL_STRICT_MODE.load(Ordering::SeqCst) {
            return CallNextHookEx(None, code, wparam, lparam);
        }

        let sender = GLOBAL_SENDER.lock().ok().and_then(|g| g.clone());
        if let Some(sender) = sender {
            let now = chrono::Utc::now().timestamp_nanos_safe();
            let keycode = kbd.vkCode as u16;
            let zone = crate::jitter::keycode_to_zone(keycode);

            let event = KeystrokeEvent {
                timestamp_ns: now,
                keycode,
                zone: if zone >= 0 { zone as u8 } else { 0xFF },
                char_value: None,
                is_hardware: !is_injected,
                device_id: None,
                transport_type: None,
            };

            let _ = sender.send(event);
        }
    }

    CallNextHookEx(None, code, wparam, lparam)
}

/// Windows focus monitor implementation.
pub struct WindowsFocusMonitor {
    running: Arc<AtomicBool>,
    sender: Option<mpsc::Sender<FocusInfo>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl WindowsFocusMonitor {
    pub fn new() -> Result<Self> {
        Ok(Self {
            running: Arc::new(AtomicBool::new(false)),
            sender: None,
            thread: None,
        })
    }
}

impl FocusMonitor for WindowsFocusMonitor {
    fn get_active_focus(&self) -> Result<FocusInfo> {
        get_active_focus()
    }

    fn start_monitoring(&mut self) -> Result<mpsc::Receiver<FocusInfo>> {
        if self.running.load(Ordering::SeqCst) {
            return Err(anyhow!("Focus monitoring already running"));
        }

        let (tx, rx) = mpsc::channel();
        self.sender = Some(tx.clone());

        let running = Arc::clone(&self.running);
        running.store(true, Ordering::SeqCst);

        let thread = std::thread::spawn(move || {
            let mut last_focus: Option<FocusInfo> = None;

            while running.load(Ordering::SeqCst) {
                if let Ok(focus) = get_active_focus() {
                    let should_send = match &last_focus {
                        Some(last) => {
                            last.pid != focus.pid
                                || last.doc_path != focus.doc_path
                                || last.window_title != focus.window_title
                        }
                        None => true,
                    };

                    if should_send {
                        let _ = tx.send(focus.clone());
                        last_focus = Some(focus);
                    }
                }

                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        });

        self.thread = Some(thread);
        Ok(rx)
    }

    fn stop_monitoring(&mut self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);
        self.sender = None;
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
        Ok(())
    }

    fn is_monitoring(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}

static MOUSE_GLOBAL_SENDER: Mutex<Option<mpsc::Sender<MouseEvent>>> = Mutex::new(None);
static MOUSE_GLOBAL_IDLE_STATS: Mutex<Option<Arc<RwLock<MouseIdleStats>>>> = Mutex::new(None);
static MOUSE_LAST_POSITION: Mutex<(f64, f64)> = Mutex::new((0.0, 0.0));
/// Timestamp (ms since epoch) of the last keystroke, used to determine if
/// typing is active within a 500ms window.
static MOUSE_LAST_KEYSTROKE_TIME: AtomicI64 = AtomicI64::new(0);
static MOUSE_IDLE_ONLY_MODE: AtomicBool = AtomicBool::new(true);

/// Windows mouse capture implementation using WH_MOUSE_LL hook.
pub struct WindowsMouseCapture {
    running: Arc<AtomicBool>,
    sender: Option<mpsc::Sender<MouseEvent>>,
    hook: Option<HookHandle>,
    idle_stats: Arc<RwLock<MouseIdleStats>>,
    stego_params: MouseStegoParams,
    idle_only_mode: bool,
    keyboard_active: Arc<AtomicBool>,
    last_keystroke_time: Arc<RwLock<std::time::Instant>>,
    pump_thread: Option<std::thread::JoinHandle<()>>,
    pump_thread_id: Arc<std::sync::atomic::AtomicU32>,
}

impl WindowsMouseCapture {
    pub fn new() -> Result<Self> {
        Ok(Self {
            running: Arc::new(AtomicBool::new(false)),
            sender: None,
            hook: None,
            idle_stats: Arc::new(RwLock::new(MouseIdleStats::new())),
            stego_params: MouseStegoParams::default(),
            idle_only_mode: true,
            keyboard_active: Arc::new(AtomicBool::new(false)),
            last_keystroke_time: Arc::new(RwLock::new(std::time::Instant::now())),
            pump_thread: None,
            pump_thread_id: Arc::new(std::sync::atomic::AtomicU32::new(0)),
        })
    }

    /// Notify the mouse capture that a keystroke occurred.
    pub fn notify_keystroke(&self) {
        self.keyboard_active.store(true, Ordering::SeqCst);
        if let Ok(mut time) = self.last_keystroke_time.write() {
            *time = std::time::Instant::now();
        }
        let now_ms = chrono::Utc::now().timestamp_millis();
        MOUSE_LAST_KEYSTROKE_TIME.store(now_ms, Ordering::SeqCst);
    }
}

impl MouseCapture for WindowsMouseCapture {
    fn start(&mut self) -> Result<mpsc::Receiver<MouseEvent>> {
        if self.running.load(Ordering::SeqCst) {
            return Err(anyhow!("Mouse capture already running"));
        }

        let (tx, rx) = mpsc::channel();
        self.sender = Some(tx.clone());

        *MOUSE_GLOBAL_SENDER.lock_recover() = Some(tx);
        *MOUSE_GLOBAL_IDLE_STATS.lock_recover() = Some(Arc::clone(&self.idle_stats));
        MOUSE_IDLE_ONLY_MODE.store(self.idle_only_mode, Ordering::SeqCst);

        self.running.store(true, Ordering::SeqCst);

        unsafe {
            let hook = SetWindowsHookExW(WH_MOUSE_LL, Some(mouse_capture_hook), None, 0)?;
            self.hook = Some(HookHandle(hook));
        }

        let running = Arc::clone(&self.running);
        let thread_id_store = Arc::clone(&self.pump_thread_id);
        let handle = std::thread::spawn(move || {
            // Record this thread's ID so stop() can post WM_QUIT to wake GetMessageW.
            let tid = unsafe { GetCurrentThreadId() };
            thread_id_store.store(tid, Ordering::SeqCst);

            let mut msg = MSG::default();
            while running.load(Ordering::SeqCst) {
                unsafe {
                    if GetMessageW(&mut msg, None, 0, 0).0 <= 0 {
                        break;
                    }
                }
            }
        });
        self.pump_thread = Some(handle);

        Ok(rx)
    }

    fn stop(&mut self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);

        if let Some(hook_handle) = self.hook.take() {
            unsafe {
                if let Err(e) = UnhookWindowsHookEx(hook_handle.0) {
                    log::warn!("UnhookWindowsHookEx failed for mouse hook: {e}");
                }
            }
        }

        *MOUSE_GLOBAL_SENDER.lock_recover() = None;
        *MOUSE_GLOBAL_IDLE_STATS.lock_recover() = None;

        // Post WM_QUIT to unblock GetMessageW in the pump thread, then join it.
        let tid = self.pump_thread_id.load(Ordering::SeqCst);
        if tid != 0 {
            unsafe {
                let _ = PostThreadMessageW(tid, WM_QUIT, WPARAM(0), LPARAM(0));
            }
        }
        if let Some(handle) = self.pump_thread.take() {
            let _ = handle.join();
        }

        self.sender = None;
        Ok(())
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    fn idle_stats(&self) -> MouseIdleStats {
        self.idle_stats.read_recover().clone()
    }

    fn reset_idle_stats(&mut self) {
        *self.idle_stats.write_recover() = MouseIdleStats::new();
    }

    fn set_stego_params(&mut self, params: MouseStegoParams) {
        self.stego_params = params;
    }

    fn get_stego_params(&self) -> MouseStegoParams {
        self.stego_params.clone()
    }

    fn set_idle_only_mode(&mut self, enabled: bool) {
        self.idle_only_mode = enabled;
        MOUSE_IDLE_ONLY_MODE.store(enabled, Ordering::SeqCst);
    }

    fn is_idle_only_mode(&self) -> bool {
        self.idle_only_mode
    }
}

impl Drop for WindowsMouseCapture {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

unsafe extern "system" fn mouse_capture_hook(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if code >= 0 && wparam.0 as u32 == WM_MOUSEMOVE {
        let last_ks_ms = MOUSE_LAST_KEYSTROKE_TIME.load(Ordering::SeqCst);
        let now_ms = chrono::Utc::now().timestamp_millis();
        let kb_active = (now_ms - last_ks_ms) < 500;

        if MOUSE_IDLE_ONLY_MODE.load(Ordering::SeqCst) && !kb_active {
            return CallNextHookEx(None, code, wparam, lparam);
        }

        let ptr = lparam.0 as *const MSLLHOOKSTRUCT;
        if ptr.is_null() {
            return CallNextHookEx(None, code, wparam, lparam);
        }
        let mouse = *ptr;
        let now = chrono::Utc::now().timestamp_nanos_safe();

        let x = mouse.pt.x as f64;
        let y = mouse.pt.y as f64;

        let (dx, dy) = {
            let mut pos = MOUSE_LAST_POSITION.lock_recover();
            let dx = x - pos.0;
            let dy = y - pos.1;
            *pos = (x, y);
            (dx, dy)
        };

        let event = MouseEvent {
            timestamp_ns: now,
            x,
            y,
            dx,
            dy,
            is_idle: !kb_active,
            is_hardware: true,
            device_id: None,
        };

        if event.is_micro_movement() && !kb_active {
            let idle_stats = MOUSE_GLOBAL_IDLE_STATS.lock().ok().and_then(|g| g.clone());
            if let Some(stats) = idle_stats {
                if let Ok(mut s) = stats.write() {
                    s.record(&event);
                }
            }
        }

        let sender = MOUSE_GLOBAL_SENDER.lock().ok().and_then(|g| g.clone());
        if let Some(sender) = sender {
            let _ = sender.send(event);
        }
    }

    CallNextHookEx(None, code, wparam, lparam)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permission_check() {
        let status = get_permission_status();
        assert!(status.all_granted);
    }

    #[test]
    fn test_looks_like_path() {
        assert!(looks_like_path("C:\\Users\\test.txt"));
        assert!(looks_like_path("D:\\Documents\\file.doc"));
        assert!(looks_like_path("\\\\server\\share\\file.txt"));
        assert!(!looks_like_path("Hello World"));
    }
}
