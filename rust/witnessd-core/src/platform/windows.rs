//! Windows platform implementation using WH_KEYBOARD_LL hook.
//!
//! This module provides keystroke capture via the low-level keyboard hook
//! and focus tracking via GetForegroundWindow.

#![allow(dead_code)]

use super::types::{
    FocusInfo, KeystrokeEvent, MouseEvent, MouseIdleStats, MouseStegoParams, PermissionStatus,
    SyntheticStats,
};
use super::{FocusMonitor, KeystrokeCapture, MouseCapture};
use anyhow::{anyhow, Result};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex, RwLock};
use windows::Win32::Foundation::{LPARAM, LRESULT, WPARAM};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CallNextHookEx, GetForegroundWindow, GetMessageW, GetWindowTextW, GetWindowThreadProcessId,
    SetWindowsHookExW, UnhookWindowsHookEx, HHOOK, KBDLLHOOKSTRUCT, LLKHF_INJECTED, MSG,
    MSLLHOOKSTRUCT, WH_KEYBOARD_LL, WH_MOUSE_LL, WM_KEYDOWN, WM_MOUSEMOVE, WM_SYSKEYDOWN,
};

use crate::jitter::SimpleJitterSession;

// =============================================================================
// Thread-safe HHOOK wrapper
// =============================================================================

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

// =============================================================================
// Permission handling
// =============================================================================

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

// =============================================================================
// Focus tracking
// =============================================================================

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

        // Get window title
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

    // Common patterns:
    // "filename.ext - Application Name"
    // "Application Name - filename.ext"
    // "filename.ext"

    // Check for common separators
    for sep in [" - ", " \u{2014} ", " | "] {
        if let Some(parts) = title.split_once(sep) {
            // Check if either part looks like a file path
            for part in [parts.0, parts.1] {
                if looks_like_path(part) {
                    return Some(part.to_string());
                }
            }
        }
    }

    // Check if the whole title looks like a path
    if looks_like_path(title) {
        return Some(title.to_string());
    }

    None
}

fn looks_like_path(s: &str) -> bool {
    // Check for drive letter or UNC path
    (s.len() > 2 && s.chars().nth(1) == Some(':'))
        || s.starts_with("\\\\")
        || s.contains('\\')
        || (s.contains('.') && !s.contains(' '))
}

// =============================================================================
// Legacy keystroke monitor
// =============================================================================

pub struct KeystrokeMonitor {
    session: Arc<Mutex<SimpleJitterSession>>,
    _hook: isize,
}

static mut GLOBAL_SESSION: Option<Arc<Mutex<SimpleJitterSession>>> = None;

impl KeystrokeMonitor {
    pub fn start(session: Arc<Mutex<SimpleJitterSession>>) -> Result<Self> {
        unsafe {
            GLOBAL_SESSION = Some(Arc::clone(&session));
            let hook = SetWindowsHookExW(WH_KEYBOARD_LL, Some(low_level_keyboard_proc), None, 0)?;
            std::thread::spawn(|| {
                let mut msg = MSG::default();
                while GetMessageW(&mut msg, None, 0, 0).into() {}
            });
            Ok(Self {
                session,
                _hook: hook.0 as isize,
            })
        }
    }
}

unsafe extern "system" fn low_level_keyboard_proc(
    code: i32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if code >= 0 && (wparam.0 as u32 == WM_KEYDOWN || wparam.0 as u32 == WM_SYSKEYDOWN) {
        let kbd = *(lparam.0 as *const KBDLLHOOKSTRUCT);
        let now = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
        if let Some(ref session_arc) = GLOBAL_SESSION {
            if let Ok(mut s) = session_arc.lock() {
                s.add_sample(now, (kbd.vkCode % 8) as u8);
            }
        }
    }
    CallNextHookEx(None, code, wparam, lparam)
}

// =============================================================================
// Trait implementations
// =============================================================================

/// Windows keystroke capture implementation.
pub struct WindowsKeystrokeCapture {
    running: Arc<AtomicBool>,
    sender: Option<mpsc::Sender<KeystrokeEvent>>,
    hook: Option<HookHandle>,
    strict_mode: bool,
    stats: Arc<RwLock<SyntheticStats>>,
}

// Global sender for the hook callback
static mut GLOBAL_SENDER: Option<mpsc::Sender<KeystrokeEvent>> = None;
static mut GLOBAL_STATS: Option<Arc<RwLock<SyntheticStats>>> = None;
static mut GLOBAL_STRICT_MODE: bool = true;

impl WindowsKeystrokeCapture {
    /// Create a new Windows keystroke capture instance.
    pub fn new() -> Result<Self> {
        Ok(Self {
            running: Arc::new(AtomicBool::new(false)),
            sender: None,
            hook: None,
            strict_mode: true,
            stats: Arc::new(RwLock::new(SyntheticStats::default())),
        })
    }
}

impl KeystrokeCapture for WindowsKeystrokeCapture {
    fn start(&mut self) -> Result<mpsc::Receiver<KeystrokeEvent>> {
        if self.running.load(Ordering::SeqCst) {
            return Err(anyhow!("Keystroke capture already running"));
        }

        let (tx, rx) = mpsc::channel();
        self.sender = Some(tx.clone());

        // Set global state for the hook callback
        unsafe {
            GLOBAL_SENDER = Some(tx);
            GLOBAL_STATS = Some(Arc::clone(&self.stats));
            GLOBAL_STRICT_MODE = self.strict_mode;
        }

        self.running.store(true, Ordering::SeqCst);

        // Install the hook
        unsafe {
            let hook = SetWindowsHookExW(WH_KEYBOARD_LL, Some(keystroke_capture_hook), None, 0)?;
            self.hook = Some(HookHandle(hook));
        }

        // Start message pump in a separate thread
        let running = Arc::clone(&self.running);
        std::thread::spawn(move || {
            let mut msg = MSG::default();
            while running.load(Ordering::SeqCst) {
                unsafe {
                    if GetMessageW(&mut msg, None, 0, 0).into() {
                        // Process messages
                    } else {
                        break;
                    }
                }
            }
        });

        Ok(rx)
    }

    fn stop(&mut self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);

        if let Some(hook_handle) = self.hook.take() {
            unsafe {
                let _ = UnhookWindowsHookEx(hook_handle.0);
            }
        }

        unsafe {
            GLOBAL_SENDER = None;
            GLOBAL_STATS = None;
        }

        self.sender = None;
        Ok(())
    }

    fn synthetic_stats(&self) -> SyntheticStats {
        self.stats.read().unwrap().clone()
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    fn set_strict_mode(&mut self, strict: bool) {
        self.strict_mode = strict;
        unsafe {
            GLOBAL_STRICT_MODE = strict;
        }
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

/// Hook callback for keystroke capture.
unsafe extern "system" fn keystroke_capture_hook(
    code: i32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if code >= 0 && (wparam.0 as u32 == WM_KEYDOWN || wparam.0 as u32 == WM_SYSKEYDOWN) {
        let kbd = *(lparam.0 as *const KBDLLHOOKSTRUCT);

        // Check for injected events
        let is_injected = (kbd.flags.0 & LLKHF_INJECTED.0) != 0;

        // Update stats
        if let Some(ref stats) = GLOBAL_STATS {
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

        // In strict mode, reject injected events
        if is_injected && GLOBAL_STRICT_MODE {
            return CallNextHookEx(None, code, wparam, lparam);
        }

        // Send keystroke event
        if let Some(ref sender) = GLOBAL_SENDER {
            let now = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
            let keycode = kbd.vkCode as u16;
            let zone = crate::jitter::keycode_to_zone(keycode);

            let event = KeystrokeEvent {
                timestamp_ns: now,
                keycode,
                zone: if zone >= 0 { zone as u8 } else { 0xFF },
                char_value: None,
                is_hardware: !is_injected,
                device_id: None,
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
    /// Create a new Windows focus monitor instance.
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
        Ok(())
    }

    fn is_monitoring(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}

// =============================================================================
// Mouse Capture Implementation
// =============================================================================

// Global sender for the mouse hook callback
static mut MOUSE_GLOBAL_SENDER: Option<mpsc::Sender<MouseEvent>> = None;
static mut MOUSE_GLOBAL_IDLE_STATS: Option<Arc<RwLock<MouseIdleStats>>> = None;
static mut MOUSE_LAST_POSITION: (f64, f64) = (0.0, 0.0);
static mut MOUSE_KEYBOARD_ACTIVE: bool = false;
static mut MOUSE_IDLE_ONLY_MODE: bool = true;

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
}

impl WindowsMouseCapture {
    /// Create a new Windows mouse capture instance.
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
        })
    }

    /// Notify the mouse capture that a keystroke occurred.
    pub fn notify_keystroke(&self) {
        self.keyboard_active.store(true, Ordering::SeqCst);
        if let Ok(mut time) = self.last_keystroke_time.write() {
            *time = std::time::Instant::now();
        }
        unsafe {
            MOUSE_KEYBOARD_ACTIVE = true;
        }
    }
}

impl MouseCapture for WindowsMouseCapture {
    fn start(&mut self) -> Result<mpsc::Receiver<MouseEvent>> {
        if self.running.load(Ordering::SeqCst) {
            return Err(anyhow!("Mouse capture already running"));
        }

        let (tx, rx) = mpsc::channel();
        self.sender = Some(tx.clone());

        // Set global state for the hook callback
        unsafe {
            MOUSE_GLOBAL_SENDER = Some(tx);
            MOUSE_GLOBAL_IDLE_STATS = Some(Arc::clone(&self.idle_stats));
            MOUSE_IDLE_ONLY_MODE = self.idle_only_mode;
        }

        self.running.store(true, Ordering::SeqCst);

        // Install the hook
        unsafe {
            let hook = SetWindowsHookExW(WH_MOUSE_LL, Some(mouse_capture_hook), None, 0)?;
            self.hook = Some(HookHandle(hook));
        }

        // Start message pump in a separate thread
        let running = Arc::clone(&self.running);
        std::thread::spawn(move || {
            let mut msg = MSG::default();
            while running.load(Ordering::SeqCst) {
                unsafe {
                    if GetMessageW(&mut msg, None, 0, 0).into() {
                        // Process messages
                    } else {
                        break;
                    }
                }
            }
        });

        Ok(rx)
    }

    fn stop(&mut self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);

        if let Some(hook_handle) = self.hook.take() {
            unsafe {
                let _ = UnhookWindowsHookEx(hook_handle.0);
            }
        }

        unsafe {
            MOUSE_GLOBAL_SENDER = None;
            MOUSE_GLOBAL_IDLE_STATS = None;
        }

        self.sender = None;
        Ok(())
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    fn idle_stats(&self) -> MouseIdleStats {
        self.idle_stats.read().unwrap().clone()
    }

    fn reset_idle_stats(&mut self) {
        *self.idle_stats.write().unwrap() = MouseIdleStats::new();
    }

    fn set_stego_params(&mut self, params: MouseStegoParams) {
        self.stego_params = params;
    }

    fn get_stego_params(&self) -> MouseStegoParams {
        self.stego_params.clone()
    }

    fn set_idle_only_mode(&mut self, enabled: bool) {
        self.idle_only_mode = enabled;
        unsafe {
            MOUSE_IDLE_ONLY_MODE = enabled;
        }
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

/// Hook callback for mouse capture.
unsafe extern "system" fn mouse_capture_hook(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if code >= 0 && wparam.0 as u32 == WM_MOUSEMOVE {
        // Only capture if keyboard is active (idle mode) or idle_only_mode is disabled
        if MOUSE_IDLE_ONLY_MODE && !MOUSE_KEYBOARD_ACTIVE {
            return CallNextHookEx(None, code, wparam, lparam);
        }

        let mouse = *(lparam.0 as *const MSLLHOOKSTRUCT);
        let now = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);

        let x = mouse.pt.x as f64;
        let y = mouse.pt.y as f64;

        // Calculate delta
        let (last_x, last_y) = MOUSE_LAST_POSITION;
        let dx = x - last_x;
        let dy = y - last_y;
        MOUSE_LAST_POSITION = (x, y);

        let event = MouseEvent {
            timestamp_ns: now,
            x,
            y,
            dx,
            dy,
            is_idle: MOUSE_KEYBOARD_ACTIVE,
            is_hardware: true, // WH_MOUSE_LL can detect injected events via flags if needed
            device_id: None,
        };

        // Record idle stats for micro-movements
        if event.is_micro_movement() && MOUSE_KEYBOARD_ACTIVE {
            if let Some(ref stats) = MOUSE_GLOBAL_IDLE_STATS {
                if let Ok(mut s) = stats.write() {
                    s.record(&event);
                }
            }
        }

        // Send mouse event
        if let Some(ref sender) = MOUSE_GLOBAL_SENDER {
            let _ = sender.send(event);
        }

        // Reset keyboard active after processing (will be set again by next keystroke)
        MOUSE_KEYBOARD_ACTIVE = false;
    }

    CallNextHookEx(None, code, wparam, lparam)
}

// =============================================================================
// Tests
// =============================================================================

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
