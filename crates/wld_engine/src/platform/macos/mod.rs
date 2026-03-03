// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! macOS platform implementation using CGEventTap + IOKit HID.
//!
//! This module provides dual-layer keystroke verification:
//! 1. CGEventTap for key event interception with synthetic detection
//! 2. IOKit HID for direct hardware device access

mod ffi;
mod focus;
mod hid;
mod keystroke;
mod mouse_capture;
mod permissions;
mod synthetic;

#[cfg(test)]
mod tests;

// Re-export types from parent module
pub use super::{
    DualLayerValidation, EventVerificationResult, FocusInfo, HIDDeviceInfo, KeystrokeEvent,
    PermissionStatus, SyntheticStats, TransportType,
};

// Re-export all public items from submodules
pub use focus::{get_active_focus, MacOSFocusMonitor};
pub use hid::enumerate_hid_keyboards;
pub use keystroke::{
    KeystrokeCallback, KeystrokeInfo, KeystrokeMonitor, MacOSKeystrokeCapture, RunLoopHandle,
};
pub use mouse_capture::MacOSMouseCapture;
pub use permissions::{
    check_accessibility_permissions, check_input_monitoring_permissions, get_permission_status,
    has_required_permissions, request_accessibility_permissions, request_all_permissions,
    request_input_monitoring_permissions,
};
pub use synthetic::{
    get_strict_mode, get_synthetic_stats, reset_synthetic_stats, set_strict_mode,
    verify_event_source, SyntheticEventStats,
};
// HID count accessors and validate_dual_layer are test-only (IOKit HID callback
// was never registered, so these always returned 0 / false positives).
#[cfg(test)]
pub use synthetic::{
    get_hid_keystroke_count, is_hid_monitoring_running, reset_hid_keystroke_count,
    validate_dual_layer,
};
