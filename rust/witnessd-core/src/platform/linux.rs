//! Linux platform implementation using evdev.
//!
//! This module provides keystroke capture via evdev input devices
//! and focus tracking via X11/Wayland protocols.
//!
//! # Permissions
//!
//! Access to `/dev/input/event*` devices requires either:
//! - Root access
//! - Membership in the `input` group
//! - Appropriate udev rules

#![allow(dead_code)]

use super::types::{
    FocusInfo, HIDDeviceInfo, KeystrokeEvent, MouseEvent, MouseIdleStats, MouseStegoParams,
    PermissionStatus, SyntheticStats,
};
use super::{FocusMonitor, HIDEnumerator, KeystrokeCapture, MouseCapture};
use anyhow::{anyhow, Result};
use evdev::{Device, EventType, InputEventKind, Key, RelativeAxisType};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex, RwLock};

// =============================================================================
// Linux keycode to zone mapping
// =============================================================================

/// Map Linux evdev keycode to keyboard zone (0-7).
/// Zones are based on standard QWERTY keyboard layout and typical finger usage.
pub fn linux_keycode_to_zone(keycode: u16) -> u8 {
    match keycode {
        // Left pinky zone (0)
        1 | 15 | 16 | 30 | 44 | 58 | 42 | 29 => 0, // ESC, TAB, Q, A, Z, CAPS, LSHIFT, LCTRL

        // Left ring zone (1)
        2 | 17 | 31 | 45 => 1, // 1, W, S, X

        // Left middle zone (2)
        3 | 18 | 32 | 46 => 2, // 2, E, D, C

        // Left index zone (3)
        4 | 5 | 19 | 20 | 33 | 34 | 47 | 48 => 3, // 3, 4, R, T, F, G, V, B

        // Right index zone (4)
        6 | 7 | 21 | 22 | 35 | 36 | 49 | 50 => 4, // 5, 6, Y, U, H, J, N, M

        // Right middle zone (5)
        8 | 23 | 37 | 51 => 5, // 7, I, K, ,

        // Right ring zone (6)
        9 | 24 | 38 | 52 => 6, // 8, O, L, .

        // Right pinky zone (7)
        10 | 11 | 12 | 13 | 25 | 26 | 27 | 39 | 40 | 41 | 43 | 53 | 54 | 28 | 14 | 57 | 100
        | 97 | 56 => 7, // 9, 0, -, =, P, [, ], ;, ', `, \, /, RSHIFT, ENTER, BKSP, SPACE, RALT, RCTRL, LALT

        // Default to zone 0 for unknown keys
        _ => 0,
    }
}

// =============================================================================
// Permission handling
// =============================================================================

/// Check if we have access to input devices.
fn check_input_device_access() -> bool {
    // Try to enumerate devices to check access
    match fs::read_dir("/dev/input") {
        Ok(entries) => {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.to_string_lossy().contains("event") {
                    if let Ok(device) = Device::open(&path) {
                        // Check if it's a keyboard
                        if device
                            .supported_keys()
                            .is_some_and(|keys| keys.contains(Key::KEY_A))
                        {
                            return true;
                        }
                    }
                }
            }
            false
        }
        Err(_) => false,
    }
}

/// Get combined permission status.
pub fn get_permission_status() -> PermissionStatus {
    let input_devices = check_input_device_access();
    PermissionStatus {
        accessibility: true,    // Not applicable on Linux
        input_monitoring: true, // Not applicable on Linux
        input_devices,
        all_granted: input_devices,
    }
}

/// Request all required permissions.
/// On Linux, this just checks current status and provides guidance.
pub fn request_all_permissions() -> PermissionStatus {
    let status = get_permission_status();
    if !status.input_devices {
        eprintln!("Input device access not available.");
        eprintln!("To grant access, either:");
        eprintln!("  1. Run as root (not recommended for production)");
        eprintln!("  2. Add your user to the 'input' group:");
        eprintln!("     sudo usermod -aG input $USER");
        eprintln!("     Then log out and back in");
        eprintln!("  3. Set up a udev rule:");
        eprintln!("     echo 'KERNEL==\"event*\", SUBSYSTEM==\"input\", TAG+=\"uaccess\"' | sudo tee /etc/udev/rules.d/99-witnessd.rules");
        eprintln!("     sudo udevadm control --reload-rules && sudo udevadm trigger");
    }
    status
}

/// Check if all required permissions are granted.
pub fn has_required_permissions() -> bool {
    check_input_device_access()
}

// =============================================================================
// Device enumeration
// =============================================================================

/// Information about a Linux input device.
#[derive(Debug, Clone)]
pub struct LinuxInputDevice {
    /// Path to the device (e.g., /dev/input/event0)
    pub path: PathBuf,
    /// Device name
    pub name: String,
    /// Physical path (empty for virtual devices)
    pub phys: Option<String>,
    /// Unique identifier
    pub uniq: Option<String>,
    /// Vendor ID
    pub vendor_id: u16,
    /// Product ID
    pub product_id: u16,
    /// Whether this appears to be a physical device
    pub is_physical: bool,
}

impl LinuxInputDevice {
    /// Check if this device appears to be virtual/synthetic.
    pub fn appears_virtual(&self) -> bool {
        // Virtual device indicators
        let name_lower = self.name.to_lowercase();
        if name_lower.contains("uinput")
            || name_lower.contains("virtual")
            || name_lower.contains("xtest")
            || name_lower.contains("ydotool")
        {
            return true;
        }

        // Empty phys path usually indicates virtual device
        if self.phys.is_none() || self.phys.as_ref().is_some_and(|p| p.is_empty()) {
            return true;
        }

        // Zero VID:PID often indicates virtual
        if self.vendor_id == 0 && self.product_id == 0 {
            return true;
        }

        false
    }
}

/// Enumerate all keyboard input devices.
pub fn enumerate_keyboards() -> Result<Vec<LinuxInputDevice>> {
    let mut keyboards = Vec::new();

    let entries = fs::read_dir("/dev/input")?;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.to_string_lossy().contains("event") {
            continue;
        }

        let device = match Device::open(&path) {
            Ok(d) => d,
            Err(_) => continue,
        };

        // Check if it's a keyboard (has KEY_A)
        let is_keyboard = device
            .supported_keys()
            .is_some_and(|keys| keys.contains(Key::KEY_A));

        if !is_keyboard {
            continue;
        }

        let name = device.name().unwrap_or("Unknown").to_string();
        let phys = device.physical_path().map(|s| s.to_string());
        let uniq = device.unique_name().map(|s| s.to_string());

        let input_id = device.input_id();
        let vendor_id = input_id.vendor();
        let product_id = input_id.product();

        let info = LinuxInputDevice {
            path: path.clone(),
            name: name.clone(),
            phys: phys.clone(),
            uniq,
            vendor_id,
            product_id,
            is_physical: !is_virtual_device(&name, phys.as_deref(), vendor_id, product_id),
        };

        keyboards.push(info);
    }

    Ok(keyboards)
}

/// Check if a device appears to be virtual based on its properties.
fn is_virtual_device(name: &str, phys: Option<&str>, vendor_id: u16, product_id: u16) -> bool {
    let name_lower = name.to_lowercase();

    // Known virtual device indicators in name
    if name_lower.contains("uinput")
        || name_lower.contains("virtual")
        || name_lower.contains("xtest")
        || name_lower.contains("ydotool")
        || name_lower.contains("py-evdev")
        || name_lower.contains("synthetic")
    {
        return true;
    }

    // Empty or missing phys path indicates virtual
    if phys.is_none_or(|p| p.is_empty()) {
        return true;
    }

    // Zero VID:PID is suspicious (though some embedded keyboards have this)
    // Check if name looks like a real keyboard
    if vendor_id == 0
        && product_id == 0
        && !name_lower.contains("keyboard")
        && !name_lower.contains("kbd")
        && !name_lower.contains("usb")
        && !name_lower.contains("at translated")
    {
        return true;
    }

    false
}

// =============================================================================
// Focus tracking
// =============================================================================

/// Get information about the currently focused application and document.
/// This uses various methods depending on the display server.
pub fn get_active_focus() -> Result<FocusInfo> {
    // Try X11 first (most common)
    #[cfg(feature = "x11")]
    if let Ok(focus) = get_x11_focus() {
        return Ok(focus);
    }

    // Fallback: try reading from /proc
    get_focus_from_proc()
}

/// Get focus info by examining /proc.
/// This is a fallback method that may not work in all cases.
fn get_focus_from_proc() -> Result<FocusInfo> {
    // This is a simplified implementation
    // A full implementation would use X11 or D-Bus

    // Try to find the active terminal or text editor
    let entries = fs::read_dir("/proc")?;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let pid_str = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if pid_str.chars().all(|c| c.is_ascii_digit()) {
            if let Ok(cmdline) = fs::read_to_string(path.join("cmdline")) {
                // Look for common editors
                if cmdline.contains("vim")
                    || cmdline.contains("emacs")
                    || cmdline.contains("code")
                    || cmdline.contains("sublime")
                    || cmdline.contains("gedit")
                {
                    let pid: i32 = pid_str.parse().unwrap_or(0);
                    let app_name = cmdline
                        .split('\0')
                        .next()
                        .unwrap_or("")
                        .split('/')
                        .next_back()
                        .unwrap_or("unknown")
                        .to_string();

                    return Ok(FocusInfo {
                        app_name: app_name.clone(),
                        bundle_id: app_name,
                        pid,
                        doc_path: None,
                        doc_title: None,
                        window_title: None,
                    });
                }
            }
        }
    }

    Err(anyhow!("Could not determine focused application"))
}

#[cfg(feature = "x11")]
fn get_x11_focus() -> Result<FocusInfo> {
    use x11rb::connection::Connection;
    use x11rb::protocol::xproto::{AtomEnum, ConnectionExt};

    let (conn, screen_num) = x11rb::connect(None)?;
    let screen = &conn.setup().roots[screen_num];

    // Get _NET_ACTIVE_WINDOW atom
    let active_window_atom = conn
        .intern_atom(false, b"_NET_ACTIVE_WINDOW")?
        .reply()?
        .atom;

    // Get the active window
    let reply = conn
        .get_property(
            false,
            screen.root,
            active_window_atom,
            AtomEnum::WINDOW,
            0,
            1,
        )?
        .reply()?;

    if reply.value.is_empty() {
        return Err(anyhow!("No active window"));
    }

    let window_id = u32::from_ne_bytes(reply.value[0..4].try_into()?);

    // Get WM_NAME
    let wm_name_atom = conn.intern_atom(false, b"_NET_WM_NAME")?.reply()?.atom;
    let utf8_string_atom = conn.intern_atom(false, b"UTF8_STRING")?.reply()?.atom;

    let name_reply = conn
        .get_property(false, window_id, wm_name_atom, utf8_string_atom, 0, 1024)?
        .reply()?;

    let window_title = if !name_reply.value.is_empty() {
        Some(String::from_utf8_lossy(&name_reply.value).to_string())
    } else {
        None
    };

    // Get _NET_WM_PID
    let pid_atom = conn.intern_atom(false, b"_NET_WM_PID")?.reply()?.atom;
    let pid_reply = conn
        .get_property(false, window_id, pid_atom, AtomEnum::CARDINAL, 0, 1)?
        .reply()?;

    let pid = if !pid_reply.value.is_empty() {
        i32::from_ne_bytes(pid_reply.value[0..4].try_into()?)
    } else {
        0
    };

    // Get process name from /proc
    let app_name = if pid > 0 {
        fs::read_to_string(format!("/proc/{}/comm", pid))
            .unwrap_or_default()
            .trim()
            .to_string()
    } else {
        String::new()
    };

    Ok(FocusInfo {
        app_name: app_name.clone(),
        bundle_id: app_name,
        pid,
        doc_path: None,
        doc_title: window_title.clone(),
        window_title,
    })
}

// =============================================================================
// Keystroke capture
// =============================================================================

/// Linux keystroke capture implementation using evdev.
pub struct LinuxKeystrokeCapture {
    running: Arc<AtomicBool>,
    sender: Option<mpsc::Sender<KeystrokeEvent>>,
    threads: Vec<std::thread::JoinHandle<()>>,
    strict_mode: bool,
    stats: Arc<RwLock<SyntheticStats>>,
    physical_devices: Arc<RwLock<HashMap<PathBuf, LinuxInputDevice>>>,
}

impl LinuxKeystrokeCapture {
    /// Create a new Linux keystroke capture instance.
    pub fn new() -> Result<Self> {
        Ok(Self {
            running: Arc::new(AtomicBool::new(false)),
            sender: None,
            threads: Vec::new(),
            strict_mode: true,
            stats: Arc::new(RwLock::new(SyntheticStats::default())),
            physical_devices: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Enumerate and register physical keyboard devices.
    fn enumerate_physical_devices(&self) -> Result<Vec<PathBuf>> {
        let keyboards = enumerate_keyboards()?;
        let mut devices = self.physical_devices.write().unwrap();
        let mut physical_paths = Vec::new();

        for kbd in keyboards {
            if kbd.is_physical {
                physical_paths.push(kbd.path.clone());
            }
            devices.insert(kbd.path.clone(), kbd);
        }

        Ok(physical_paths)
    }
}

impl KeystrokeCapture for LinuxKeystrokeCapture {
    fn start(&mut self) -> Result<mpsc::Receiver<KeystrokeEvent>> {
        if self.running.load(Ordering::SeqCst) {
            return Err(anyhow!("Keystroke capture already running"));
        }

        // Check permissions
        if !check_input_device_access() {
            let _ = request_all_permissions();
            return Err(anyhow!(
                "No access to input devices. See error messages above for solutions."
            ));
        }

        let (tx, rx) = mpsc::channel();
        self.sender = Some(tx.clone());

        self.running.store(true, Ordering::SeqCst);

        // Enumerate physical devices
        let physical_paths = self.enumerate_physical_devices()?;
        if physical_paths.is_empty() {
            return Err(anyhow!("No physical keyboard devices found"));
        }

        let stats = Arc::clone(&self.stats);
        let strict = self.strict_mode;
        let running = Arc::clone(&self.running);
        let devices = Arc::clone(&self.physical_devices);

        // Start a reader thread for each physical device
        for path in physical_paths {
            let tx = tx.clone();
            let stats = Arc::clone(&stats);
            let running = Arc::clone(&running);
            let devices = Arc::clone(&devices);
            let path_clone = path.clone();

            let thread = std::thread::spawn(move || {
                Self::device_reader_thread(path_clone, tx, stats, running, devices, strict);
            });

            self.threads.push(thread);
        }

        Ok(rx)
    }

    fn stop(&mut self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);
        self.sender = None;

        // Wait for threads to finish
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }

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
    }

    fn get_strict_mode(&self) -> bool {
        self.strict_mode
    }
}

impl LinuxKeystrokeCapture {
    /// Reader thread for a single input device.
    fn device_reader_thread(
        path: PathBuf,
        tx: mpsc::Sender<KeystrokeEvent>,
        stats: Arc<RwLock<SyntheticStats>>,
        running: Arc<AtomicBool>,
        devices: Arc<RwLock<HashMap<PathBuf, LinuxInputDevice>>>,
        strict: bool,
    ) {
        let mut device = match Device::open(&path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Failed to open device {:?}: {}", path, e);
                return;
            }
        };

        // Get device info for synthetic detection
        let device_info = devices.read().unwrap().get(&path).cloned();
        let is_physical = device_info.as_ref().is_some_and(|d| d.is_physical);
        let device_id = device_info
            .as_ref()
            .map(|d| format!("{:04x}:{:04x}", d.vendor_id, d.product_id));

        while running.load(Ordering::SeqCst) {
            match device.fetch_events() {
                Ok(events) => {
                    for event in events {
                        // Only process key events
                        if event.event_type() != EventType::KEY {
                            continue;
                        }

                        // Only process key-down events (value = 1)
                        if event.value() != 1 {
                            continue;
                        }

                        let keycode = event.code();

                        // Update stats
                        {
                            let mut s = stats.write().unwrap();
                            s.total_events += 1;

                            if is_physical {
                                s.verified_hardware += 1;
                            } else {
                                s.rejected_synthetic += 1;
                                s.rejection_reasons.virtual_device += 1;
                            }
                        }

                        // In strict mode, reject virtual device events
                        if !is_physical && strict {
                            continue;
                        }

                        let now = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
                        let zone = linux_keycode_to_zone(keycode);

                        // Try to get character value
                        let char_value = keycode_to_char(keycode);

                        let keystroke = KeystrokeEvent {
                            timestamp_ns: now,
                            keycode,
                            zone,
                            char_value,
                            is_hardware: is_physical,
                            device_id: device_id.clone(),
                        };

                        if tx.send(keystroke).is_err() {
                            // Receiver dropped, exit thread
                            return;
                        }
                    }
                }
                Err(e) => {
                    if running.load(Ordering::SeqCst) {
                        eprintln!("Error reading from device {:?}: {}", path, e);
                    }
                    break;
                }
            }
        }
    }
}

/// Convert evdev keycode to character (basic implementation).
fn keycode_to_char(keycode: u16) -> Option<char> {
    // Basic mapping for common keys (lowercase, no modifiers)
    match keycode {
        16 => Some('q'),
        17 => Some('w'),
        18 => Some('e'),
        19 => Some('r'),
        20 => Some('t'),
        21 => Some('y'),
        22 => Some('u'),
        23 => Some('i'),
        24 => Some('o'),
        25 => Some('p'),
        30 => Some('a'),
        31 => Some('s'),
        32 => Some('d'),
        33 => Some('f'),
        34 => Some('g'),
        35 => Some('h'),
        36 => Some('j'),
        37 => Some('k'),
        38 => Some('l'),
        44 => Some('z'),
        45 => Some('x'),
        46 => Some('c'),
        47 => Some('v'),
        48 => Some('b'),
        49 => Some('n'),
        50 => Some('m'),
        2 => Some('1'),
        3 => Some('2'),
        4 => Some('3'),
        5 => Some('4'),
        6 => Some('5'),
        7 => Some('6'),
        8 => Some('7'),
        9 => Some('8'),
        10 => Some('9'),
        11 => Some('0'),
        57 => Some(' '),
        _ => None,
    }
}

impl Drop for LinuxKeystrokeCapture {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// Linux focus monitor implementation.
pub struct LinuxFocusMonitor {
    running: Arc<AtomicBool>,
    sender: Option<mpsc::Sender<FocusInfo>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl LinuxFocusMonitor {
    /// Create a new Linux focus monitor instance.
    pub fn new() -> Result<Self> {
        Ok(Self {
            running: Arc::new(AtomicBool::new(false)),
            sender: None,
            thread: None,
        })
    }
}

impl FocusMonitor for LinuxFocusMonitor {
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

/// Linux HID enumerator implementation.
#[derive(Default)]
pub struct LinuxHIDEnumerator;

impl LinuxHIDEnumerator {
    pub fn new() -> Self {
        Self
    }
}

impl HIDEnumerator for LinuxHIDEnumerator {
    fn enumerate_keyboards(&self) -> Result<Vec<HIDDeviceInfo>> {
        let devices = enumerate_keyboards()?;
        Ok(devices
            .into_iter()
            .map(|d| HIDDeviceInfo {
                vendor_id: d.vendor_id as u32,
                product_id: d.product_id as u32,
                product_name: d.name,
                manufacturer: String::new(), // Not easily available via evdev
                serial_number: d.uniq,
                transport: d.phys.unwrap_or_default(),
            })
            .collect())
    }

    fn is_device_connected(&self, vendor_id: u32, product_id: u32) -> bool {
        if let Ok(devices) = enumerate_keyboards() {
            devices
                .iter()
                .any(|d| d.vendor_id as u32 == vendor_id && d.product_id as u32 == product_id)
        } else {
            false
        }
    }
}

// =============================================================================
// Mouse capture
// =============================================================================

/// Enumerate all mouse/pointing input devices.
pub fn enumerate_mice() -> Result<Vec<LinuxInputDevice>> {
    let mut mice = Vec::new();

    let entries = fs::read_dir("/dev/input")?;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.to_string_lossy().contains("event") {
            continue;
        }

        let device = match Device::open(&path) {
            Ok(d) => d,
            Err(_) => continue,
        };

        // Check if it's a mouse (has REL_X and REL_Y)
        let is_mouse = device.supported_relative_axes().is_some_and(|axes| {
            axes.contains(RelativeAxisType::REL_X) && axes.contains(RelativeAxisType::REL_Y)
        });

        if !is_mouse {
            continue;
        }

        let name = device.name().unwrap_or("Unknown").to_string();
        let phys = device.physical_path().map(|s| s.to_string());
        let uniq = device.unique_name().map(|s| s.to_string());

        let input_id = device.input_id();
        let vendor_id = input_id.vendor();
        let product_id = input_id.product();

        let info = LinuxInputDevice {
            path: path.clone(),
            name: name.clone(),
            phys: phys.clone(),
            uniq,
            vendor_id,
            product_id,
            is_physical: !is_virtual_mouse(&name, phys.as_deref(), vendor_id, product_id),
        };

        mice.push(info);
    }

    Ok(mice)
}

/// Check if a mouse device appears to be virtual based on its properties.
fn is_virtual_mouse(name: &str, phys: Option<&str>, vendor_id: u16, product_id: u16) -> bool {
    let name_lower = name.to_lowercase();

    // Known virtual mouse indicators in name
    if name_lower.contains("uinput")
        || name_lower.contains("virtual")
        || name_lower.contains("xtest")
        || name_lower.contains("xdotool")
        || name_lower.contains("py-evdev")
        || name_lower.contains("synthetic")
        || name_lower.contains("wacom")
    // Exclude tablet devices
    {
        return true;
    }

    // Empty or missing phys path indicates virtual
    if phys.is_none_or(|p| p.is_empty()) {
        return true;
    }

    // Zero VID:PID is suspicious
    if vendor_id == 0
        && product_id == 0
        && !name_lower.contains("mouse")
        && !name_lower.contains("touchpad")
        && !name_lower.contains("trackpad")
        && !name_lower.contains("trackpoint")
    {
        return true;
    }

    false
}

/// Linux mouse capture implementation using evdev EV_REL events.
pub struct LinuxMouseCapture {
    running: Arc<AtomicBool>,
    sender: Option<mpsc::Sender<MouseEvent>>,
    threads: Vec<std::thread::JoinHandle<()>>,
    idle_only_mode: Arc<AtomicBool>,
    stats: Arc<RwLock<MouseIdleStats>>,
    stego_params: Arc<RwLock<MouseStegoParams>>,
    last_position: Arc<RwLock<(f64, f64)>>,
    physical_devices: Arc<RwLock<HashMap<PathBuf, LinuxInputDevice>>>,
}

impl LinuxMouseCapture {
    /// Create a new Linux mouse capture instance.
    pub fn new() -> Result<Self> {
        Ok(Self {
            running: Arc::new(AtomicBool::new(false)),
            sender: None,
            threads: Vec::new(),
            idle_only_mode: Arc::new(AtomicBool::new(true)),
            stats: Arc::new(RwLock::new(MouseIdleStats::default())),
            stego_params: Arc::new(RwLock::new(MouseStegoParams::default())),
            last_position: Arc::new(RwLock::new((0.0, 0.0))),
            physical_devices: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Enumerate and register physical mouse devices.
    fn enumerate_physical_devices(&self) -> Result<Vec<PathBuf>> {
        let mice = enumerate_mice()?;
        let mut devices = self.physical_devices.write().unwrap();
        let mut physical_paths = Vec::new();

        for mouse in mice {
            if mouse.is_physical {
                physical_paths.push(mouse.path.clone());
            }
            devices.insert(mouse.path.clone(), mouse);
        }

        Ok(physical_paths)
    }

    /// Reader thread for a single mouse device.
    fn device_reader_thread(
        path: PathBuf,
        tx: mpsc::Sender<MouseEvent>,
        stats: Arc<RwLock<MouseIdleStats>>,
        running: Arc<AtomicBool>,
        devices: Arc<RwLock<HashMap<PathBuf, LinuxInputDevice>>>,
        last_position: Arc<RwLock<(f64, f64)>>,
        idle_only_mode: Arc<AtomicBool>,
    ) {
        let mut device = match Device::open(&path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Failed to open mouse device {:?}: {}", path, e);
                return;
            }
        };

        // Get device info for synthetic detection
        let device_info = devices.read().unwrap().get(&path).cloned();
        let is_physical = device_info.as_ref().is_some_and(|d| d.is_physical);
        let device_id = device_info
            .as_ref()
            .map(|d| format!("{:04x}:{:04x}", d.vendor_id, d.product_id));

        // Track relative movement accumulation
        let mut pending_dx: f64 = 0.0;
        let mut pending_dy: f64 = 0.0;

        while running.load(Ordering::SeqCst) {
            match device.fetch_events() {
                Ok(events) => {
                    for event in events {
                        // Only process relative movement events
                        if event.event_type() != EventType::RELATIVE {
                            // SYN event indicates end of batch - emit accumulated movement
                            if event.event_type() == EventType::SYNCHRONIZATION
                                && (pending_dx != 0.0 || pending_dy != 0.0)
                            {
                                let now = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);

                                // Update position
                                let (x, y) = {
                                    let mut pos = last_position.write().unwrap();
                                    pos.0 += pending_dx;
                                    pos.1 += pending_dy;
                                    (pos.0, pos.1)
                                };

                                // Check if this is a micro-movement (idle jitter)
                                let magnitude =
                                    (pending_dx * pending_dx + pending_dy * pending_dy).sqrt();
                                let is_micro = magnitude < 5.0; // < 5 pixels

                                let mouse_event = MouseEvent {
                                    timestamp_ns: now,
                                    x,
                                    y,
                                    dx: pending_dx,
                                    dy: pending_dy,
                                    is_idle: is_micro,
                                    is_hardware: is_physical,
                                    device_id: device_id.clone(),
                                };

                                // Update stats for micro-movements
                                if is_micro {
                                    if let Ok(mut s) = stats.write() {
                                        s.record(&mouse_event);
                                    }
                                }

                                // Send if not in idle-only mode, or if it's idle movement
                                if (!idle_only_mode.load(Ordering::Relaxed) || is_micro)
                                    && tx.send(mouse_event).is_err()
                                {
                                    return;
                                }

                                pending_dx = 0.0;
                                pending_dy = 0.0;
                            }
                            continue;
                        }

                        // Accumulate relative movement
                        if let InputEventKind::RelAxis(axis) = event.kind() {
                            match axis {
                                RelativeAxisType::REL_X => {
                                    pending_dx += event.value() as f64;
                                }
                                RelativeAxisType::REL_Y => {
                                    pending_dy += event.value() as f64;
                                }
                                _ => {} // Ignore wheel, etc.
                            }
                        }
                    }
                }
                Err(e) => {
                    if running.load(Ordering::SeqCst) {
                        eprintln!("Error reading from mouse device {:?}: {}", path, e);
                    }
                    break;
                }
            }
        }
    }
}

impl MouseCapture for LinuxMouseCapture {
    fn start(&mut self) -> Result<mpsc::Receiver<MouseEvent>> {
        if self.running.load(Ordering::SeqCst) {
            return Err(anyhow!("Mouse capture already running"));
        }

        // Check permissions
        if !check_input_device_access() {
            let _ = request_all_permissions();
            return Err(anyhow!(
                "No access to input devices. See error messages above for solutions."
            ));
        }

        let (tx, rx) = mpsc::channel();
        self.sender = Some(tx.clone());

        self.running.store(true, Ordering::SeqCst);

        // Enumerate physical devices
        let physical_paths = self.enumerate_physical_devices()?;
        if physical_paths.is_empty() {
            // Not an error - mice may not be connected
            eprintln!("Warning: No physical mouse devices found");
        }

        let stats = Arc::clone(&self.stats);
        let running = Arc::clone(&self.running);
        let devices = Arc::clone(&self.physical_devices);
        let last_position = Arc::clone(&self.last_position);
        let idle_only_mode = Arc::clone(&self.idle_only_mode);

        // Start a reader thread for each physical device
        for path in physical_paths {
            let tx = tx.clone();
            let stats = Arc::clone(&stats);
            let running = Arc::clone(&running);
            let devices = Arc::clone(&devices);
            let last_position = Arc::clone(&last_position);
            let idle_only_mode = Arc::clone(&idle_only_mode);

            let thread = std::thread::spawn(move || {
                Self::device_reader_thread(
                    path,
                    tx,
                    stats,
                    running,
                    devices,
                    last_position,
                    idle_only_mode,
                );
            });

            self.threads.push(thread);
        }

        Ok(rx)
    }

    fn stop(&mut self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);
        self.sender = None;

        // Wait for threads to finish
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }

        Ok(())
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    fn idle_stats(&self) -> MouseIdleStats {
        self.stats.read().unwrap().clone()
    }

    fn reset_idle_stats(&mut self) {
        *self.stats.write().unwrap() = MouseIdleStats::default();
    }

    fn set_stego_params(&mut self, params: MouseStegoParams) {
        *self.stego_params.write().unwrap() = params;
    }

    fn get_stego_params(&self) -> MouseStegoParams {
        self.stego_params.read().unwrap().clone()
    }

    fn set_idle_only_mode(&mut self, enabled: bool) {
        self.idle_only_mode.store(enabled, Ordering::Relaxed);
    }

    fn is_idle_only_mode(&self) -> bool {
        self.idle_only_mode.load(Ordering::Relaxed)
    }
}

impl Drop for LinuxMouseCapture {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linux_keycode_to_zone() {
        // Test some known key mappings
        assert_eq!(linux_keycode_to_zone(30), 0); // A - left pinky
        assert_eq!(linux_keycode_to_zone(31), 1); // S - left ring
        assert_eq!(linux_keycode_to_zone(32), 2); // D - left middle
        assert_eq!(linux_keycode_to_zone(33), 3); // F - left index
        assert_eq!(linux_keycode_to_zone(36), 4); // J - right index
        assert_eq!(linux_keycode_to_zone(37), 5); // K - right middle
        assert_eq!(linux_keycode_to_zone(38), 6); // L - right ring
        assert_eq!(linux_keycode_to_zone(28), 7); // ENTER - right pinky
    }

    #[test]
    fn test_is_virtual_device() {
        assert!(is_virtual_device("uinput keyboard", None, 0, 0));
        assert!(is_virtual_device("Virtual Keyboard", Some(""), 0, 0));
        assert!(is_virtual_device(
            "xtest keyboard",
            Some("usb-0000:00:1d.0-1.4/input0"),
            0,
            0
        ));
        assert!(!is_virtual_device(
            "AT Translated Set 2 keyboard",
            Some("isa0060/serio0/input0"),
            1,
            1
        ));
    }

    #[test]
    fn test_keycode_to_char() {
        assert_eq!(keycode_to_char(30), Some('a'));
        assert_eq!(keycode_to_char(57), Some(' '));
        assert_eq!(keycode_to_char(255), None);
    }

    #[test]
    fn test_is_virtual_mouse() {
        // Virtual mice
        assert!(is_virtual_mouse("uinput mouse", None, 0, 0));
        assert!(is_virtual_mouse("Virtual Mouse", Some(""), 0, 0));
        assert!(is_virtual_mouse(
            "xtest pointer",
            Some("usb-0000:00:1d.0"),
            0,
            0
        ));
        assert!(is_virtual_mouse(
            "xdotool virtual mouse",
            Some("/dev/input/event0"),
            0,
            0
        ));

        // Physical mice
        assert!(!is_virtual_mouse(
            "Logitech USB Mouse",
            Some("usb-0000:00:1d.0-1.4/input0"),
            0x046d,
            0xc077
        ));
        assert!(!is_virtual_mouse(
            "Dell MS116 USB Mouse",
            Some("usb-0000:00:14.0-1/input0"),
            0x413c,
            0x301a
        ));
    }

    #[test]
    fn test_linux_mouse_capture_create() {
        let capture = LinuxMouseCapture::new();
        assert!(capture.is_ok());

        let capture = capture.unwrap();
        assert!(!capture.is_running());
        assert!(capture.is_idle_only_mode()); // Default is true
    }
}
