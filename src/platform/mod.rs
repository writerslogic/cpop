//! Platform-specific keystroke capture and focus monitoring.
//!
//! This module provides a unified interface for:
//! - System-wide keystroke capture
//! - Active window/document focus tracking
//! - Synthetic event detection
//! - HID device enumeration
//!
//! # Platform Support
//!
//! - **macOS**: CGEventTap + IOKit HID (dual-layer)
//! - **Windows**: WH_KEYBOARD_LL hook
//! - **Linux**: evdev + X11/Wayland focus tracking
//!
//! # Usage
//!
//! ```rust,ignore
//! use witnessd_core::platform::{KeystrokeCapture, create_keystroke_capture};
//!
//! let mut capture = create_keystroke_capture()?;
//! let receiver = capture.start()?;
//!
//! while let Ok(event) = receiver.recv() {
//!     if event.is_hardware {
//!         // Process verified hardware keystroke
//!     }
//! }
//! ```

pub mod types;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "linux")]
pub mod linux;

pub mod broadcaster;
pub mod mouse_stego;
pub mod synthetic;

// Re-export mouse steganography
pub use mouse_stego::{compute_mouse_jitter, MouseStegoEngine};

// Re-export event broadcaster
pub use broadcaster::{EventBroadcaster, SubscriptionId, SyncEventBroadcaster};

// Re-export common types
pub use types::{
    DualLayerValidation, EventVerificationResult, FocusInfo, HIDDeviceInfo, KeystrokeEvent,
    MouseEvent, MouseIdleStats, MouseStegoMode, MouseStegoParams, PermissionStatus,
    RejectionReasons, SyntheticStats,
};

use anyhow::Result;
use std::sync::mpsc;

// =============================================================================
// Common Traits
// =============================================================================

/// Trait for platform-specific keystroke capture implementations.
pub trait KeystrokeCapture: Send + Sync {
    /// Start capturing keystrokes.
    ///
    /// Returns a channel receiver for keystroke events.
    fn start(&mut self) -> Result<mpsc::Receiver<KeystrokeEvent>>;

    /// Stop capturing keystrokes.
    fn stop(&mut self) -> Result<()>;

    /// Get current synthetic event detection statistics.
    fn synthetic_stats(&self) -> SyntheticStats;

    /// Check if capture is currently running.
    fn is_running(&self) -> bool;

    /// Set strict mode for synthetic event detection.
    ///
    /// In strict mode, suspicious events are rejected.
    /// In permissive mode, suspicious events are accepted but flagged.
    fn set_strict_mode(&mut self, strict: bool);

    /// Get current strict mode setting.
    fn get_strict_mode(&self) -> bool;
}

/// Trait for platform-specific focus monitoring implementations.
pub trait FocusMonitor: Send + Sync {
    /// Get information about the currently focused application/document.
    fn get_active_focus(&self) -> Result<FocusInfo>;

    /// Start monitoring focus changes.
    ///
    /// Returns a channel receiver for focus change events.
    fn start_monitoring(&mut self) -> Result<mpsc::Receiver<FocusInfo>>;

    /// Stop monitoring focus changes.
    fn stop_monitoring(&mut self) -> Result<()>;

    /// Check if monitoring is currently running.
    fn is_monitoring(&self) -> bool;
}

/// Trait for HID device enumeration.
pub trait HIDEnumerator {
    /// Enumerate all connected keyboard devices.
    fn enumerate_keyboards(&self) -> Result<Vec<HIDDeviceInfo>>;

    /// Check if a specific device is connected.
    fn is_device_connected(&self, vendor_id: u32, product_id: u32) -> bool;
}

/// Trait for platform-specific mouse capture implementations.
///
/// This captures mouse movement events, particularly for:
/// - Idle jitter detection (mouse micro-movements during typing)
/// - Movement pattern fingerprinting
/// - Steganographic timing injection
pub trait MouseCapture: Send + Sync {
    /// Start capturing mouse events.
    ///
    /// Returns a channel receiver for mouse events.
    fn start(&mut self) -> Result<mpsc::Receiver<MouseEvent>>;

    /// Stop capturing mouse events.
    fn stop(&mut self) -> Result<()>;

    /// Check if capture is currently running.
    fn is_running(&self) -> bool;

    /// Get current idle jitter statistics.
    fn idle_stats(&self) -> MouseIdleStats;

    /// Reset idle statistics.
    fn reset_idle_stats(&mut self);

    /// Set the steganography parameters.
    fn set_stego_params(&mut self, params: MouseStegoParams);

    /// Get current steganography parameters.
    fn get_stego_params(&self) -> MouseStegoParams;

    /// Enable or disable idle-only mode.
    ///
    /// When enabled, only captures events when keyboard is active
    /// (mouse is presumably idle next to keyboard).
    fn set_idle_only_mode(&mut self, enabled: bool);

    /// Check if idle-only mode is enabled.
    fn is_idle_only_mode(&self) -> bool;
}

// =============================================================================
// Platform-Specific Factory Functions
// =============================================================================

/// Create a keystroke capture instance for the current platform.
#[cfg(target_os = "macos")]
pub fn create_keystroke_capture() -> Result<Box<dyn KeystrokeCapture>> {
    Ok(Box::new(macos::MacOSKeystrokeCapture::new()?))
}

/// Create a keystroke capture instance for the current platform.
#[cfg(target_os = "windows")]
pub fn create_keystroke_capture() -> Result<Box<dyn KeystrokeCapture>> {
    Ok(Box::new(windows::WindowsKeystrokeCapture::new()?))
}

/// Create a keystroke capture instance for the current platform.
#[cfg(target_os = "linux")]
pub fn create_keystroke_capture() -> Result<Box<dyn KeystrokeCapture>> {
    Ok(Box::new(linux::LinuxKeystrokeCapture::new()?))
}

/// Create a focus monitor instance for the current platform.
#[cfg(target_os = "macos")]
pub fn create_focus_monitor() -> Result<Box<dyn FocusMonitor>> {
    Ok(Box::new(macos::MacOSFocusMonitor::new()?))
}

/// Create a focus monitor instance for the current platform.
#[cfg(target_os = "windows")]
pub fn create_focus_monitor() -> Result<Box<dyn FocusMonitor>> {
    Ok(Box::new(windows::WindowsFocusMonitor::new()?))
}

/// Create a focus monitor instance for the current platform.
#[cfg(target_os = "linux")]
pub fn create_focus_monitor() -> Result<Box<dyn FocusMonitor>> {
    Ok(Box::new(linux::LinuxFocusMonitor::new()?))
}

/// Create a mouse capture instance for the current platform.
#[cfg(target_os = "macos")]
pub fn create_mouse_capture() -> Result<Box<dyn MouseCapture>> {
    Ok(Box::new(macos::MacOSMouseCapture::new()?))
}

/// Create a mouse capture instance for the current platform.
#[cfg(target_os = "windows")]
pub fn create_mouse_capture() -> Result<Box<dyn MouseCapture>> {
    Ok(Box::new(windows::WindowsMouseCapture::new()?))
}

/// Create a mouse capture instance for the current platform.
#[cfg(target_os = "linux")]
pub fn create_mouse_capture() -> Result<Box<dyn MouseCapture>> {
    Ok(Box::new(linux::LinuxMouseCapture::new()?))
}

// =============================================================================
// Permission Checking
// =============================================================================

/// Check if all required permissions are granted for the current platform.
#[cfg(target_os = "macos")]
pub fn check_permissions() -> PermissionStatus {
    macos::get_permission_status()
}

/// Check if all required permissions are granted for the current platform.
#[cfg(target_os = "windows")]
pub fn check_permissions() -> PermissionStatus {
    windows::get_permission_status()
}

/// Check if all required permissions are granted for the current platform.
#[cfg(target_os = "linux")]
pub fn check_permissions() -> PermissionStatus {
    linux::get_permission_status()
}

/// Request all required permissions for the current platform.
#[cfg(target_os = "macos")]
pub fn request_permissions() -> PermissionStatus {
    macos::request_all_permissions()
}

/// Request all required permissions for the current platform.
#[cfg(target_os = "windows")]
pub fn request_permissions() -> PermissionStatus {
    windows::request_all_permissions()
}

/// Request all required permissions for the current platform.
#[cfg(target_os = "linux")]
pub fn request_permissions() -> PermissionStatus {
    linux::request_all_permissions()
}

/// Check if all required permissions are granted.
pub fn has_required_permissions() -> bool {
    check_permissions().all_granted
}

// =============================================================================
// Legacy Compatibility Re-exports
// =============================================================================

// Re-export platform-specific modules for backward compatibility
#[cfg(target_os = "macos")]
pub use macos::{
    check_accessibility_permissions, check_input_monitoring_permissions, enumerate_hid_keyboards,
    get_active_focus as macos_get_active_focus, get_hid_keystroke_count, get_strict_mode,
    get_synthetic_stats, is_hid_monitoring_running, request_accessibility_permissions,
    request_input_monitoring_permissions, reset_hid_keystroke_count, reset_synthetic_stats,
    set_strict_mode, validate_dual_layer, verify_event_source,
    DualLayerValidation as MacOSDualLayerValidation,
    EventVerificationResult as MacOSEventVerificationResult, FocusInfo as MacOSFocusInfo,
    HIDDeviceInfo as MacOSHIDDeviceInfo, KeystrokeInfo, KeystrokeMonitor,
    PermissionStatus as MacOSPermissionStatus, SyntheticEventStats,
};

#[cfg(target_os = "windows")]
pub use types::FocusInfo as WindowsFocusInfo;
#[cfg(target_os = "windows")]
pub use windows::get_active_focus as windows_get_active_focus;
