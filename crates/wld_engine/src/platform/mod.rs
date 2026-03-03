// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Platform-specific keystroke capture and focus monitoring.

pub mod device;
pub mod events;
pub mod mouse;
pub mod stats;
pub mod status;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "linux")]
pub mod linux;

pub mod broadcaster;
pub mod mouse_stego;
pub mod synthetic;

pub use broadcaster::{EventBroadcaster, SubscriptionId, SyncEventBroadcaster};
pub use mouse_stego::{compute_mouse_jitter, MouseStegoEngine};

pub use device::{HIDDeviceInfo, TransportType};
pub use events::{KeystrokeEvent, MouseEvent};
pub use mouse::{MouseIdleStats, MouseStegoMode, MouseStegoParams};
pub use stats::{DualLayerValidation, EventVerificationResult, RejectionReasons, SyntheticStats};
pub use status::{FocusInfo, PermissionStatus};

use anyhow::Result;
use std::sync::mpsc;

/// Platform-specific keystroke capture.
pub trait KeystrokeCapture: Send + Sync {
    fn start(&mut self) -> Result<mpsc::Receiver<KeystrokeEvent>>;
    fn stop(&mut self) -> Result<()>;
    fn synthetic_stats(&self) -> SyntheticStats;
    fn is_running(&self) -> bool;
    fn set_strict_mode(&mut self, strict: bool);
    fn get_strict_mode(&self) -> bool;
}

/// Platform-specific focus monitoring.
pub trait FocusMonitor: Send + Sync {
    fn get_active_focus(&self) -> Result<FocusInfo>;
    fn start_monitoring(&mut self) -> Result<mpsc::Receiver<FocusInfo>>;
    fn stop_monitoring(&mut self) -> Result<()>;
    fn is_monitoring(&self) -> bool;
}

/// HID device enumeration.
pub trait HIDEnumerator {
    fn enumerate_keyboards(&self) -> Result<Vec<HIDDeviceInfo>>;
    fn is_device_connected(&self, vendor_id: u32, product_id: u32) -> bool;
}

/// Platform-specific mouse capture with idle jitter and steganography support.
pub trait MouseCapture: Send + Sync {
    fn start(&mut self) -> Result<mpsc::Receiver<MouseEvent>>;
    fn stop(&mut self) -> Result<()>;
    fn is_running(&self) -> bool;
    fn idle_stats(&self) -> MouseIdleStats;
    fn reset_idle_stats(&mut self);
    fn set_stego_params(&mut self, params: MouseStegoParams);
    fn get_stego_params(&self) -> MouseStegoParams;
    fn set_idle_only_mode(&mut self, enabled: bool);
    fn is_idle_only_mode(&self) -> bool;
}

#[cfg(target_os = "macos")]
pub fn create_keystroke_capture() -> Result<Box<dyn KeystrokeCapture>> {
    Ok(Box::new(macos::MacOSKeystrokeCapture::new()?))
}

#[cfg(target_os = "windows")]
pub fn create_keystroke_capture() -> Result<Box<dyn KeystrokeCapture>> {
    Ok(Box::new(windows::WindowsKeystrokeCapture::new()?))
}

#[cfg(target_os = "linux")]
pub fn create_keystroke_capture() -> Result<Box<dyn KeystrokeCapture>> {
    Ok(Box::new(linux::LinuxKeystrokeCapture::new()?))
}

#[cfg(target_os = "macos")]
pub fn create_focus_monitor() -> Result<Box<dyn FocusMonitor>> {
    Ok(Box::new(macos::MacOSFocusMonitor::new()?))
}

#[cfg(target_os = "windows")]
pub fn create_focus_monitor() -> Result<Box<dyn FocusMonitor>> {
    Ok(Box::new(windows::WindowsFocusMonitor::new()?))
}

#[cfg(target_os = "linux")]
pub fn create_focus_monitor() -> Result<Box<dyn FocusMonitor>> {
    Ok(Box::new(linux::LinuxFocusMonitor::new()?))
}

#[cfg(target_os = "macos")]
pub fn create_mouse_capture() -> Result<Box<dyn MouseCapture>> {
    Ok(Box::new(macos::MacOSMouseCapture::new()?))
}

#[cfg(target_os = "windows")]
pub fn create_mouse_capture() -> Result<Box<dyn MouseCapture>> {
    Ok(Box::new(windows::WindowsMouseCapture::new()?))
}

#[cfg(target_os = "linux")]
pub fn create_mouse_capture() -> Result<Box<dyn MouseCapture>> {
    Ok(Box::new(linux::LinuxMouseCapture::new()?))
}

#[cfg(target_os = "macos")]
pub fn check_permissions() -> PermissionStatus {
    macos::get_permission_status()
}

#[cfg(target_os = "windows")]
pub fn check_permissions() -> PermissionStatus {
    windows::get_permission_status()
}

#[cfg(target_os = "linux")]
pub fn check_permissions() -> PermissionStatus {
    linux::get_permission_status()
}

#[cfg(target_os = "macos")]
pub fn request_permissions() -> PermissionStatus {
    macos::request_all_permissions()
}

#[cfg(target_os = "windows")]
pub fn request_permissions() -> PermissionStatus {
    windows::request_all_permissions()
}

#[cfg(target_os = "linux")]
pub fn request_permissions() -> PermissionStatus {
    linux::request_all_permissions()
}

pub fn has_required_permissions() -> bool {
    check_permissions().all_granted
}

// Legacy compatibility re-exports
#[cfg(target_os = "macos")]
pub use macos::{
    check_accessibility_permissions, check_input_monitoring_permissions, enumerate_hid_keyboards,
    get_active_focus as macos_get_active_focus, get_strict_mode, get_synthetic_stats,
    request_accessibility_permissions, request_input_monitoring_permissions, reset_synthetic_stats,
    set_strict_mode, verify_event_source, DualLayerValidation as MacOSDualLayerValidation,
    EventVerificationResult as MacOSEventVerificationResult, FocusInfo as MacOSFocusInfo,
    HIDDeviceInfo as MacOSHIDDeviceInfo, KeystrokeInfo, KeystrokeMonitor,
    PermissionStatus as MacOSPermissionStatus, SyntheticEventStats,
};
// HID count accessors and validate_dual_layer are test-only
#[cfg(all(target_os = "macos", test))]
pub use macos::{
    get_hid_keystroke_count, is_hid_monitoring_running, reset_hid_keystroke_count,
    validate_dual_layer,
};

#[cfg(target_os = "windows")]
pub use status::FocusInfo as WindowsFocusInfo;
#[cfg(target_os = "windows")]
pub use windows::get_active_focus as windows_get_active_focus;
