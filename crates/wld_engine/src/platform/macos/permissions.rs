// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! macOS permission handling for Accessibility and Input Monitoring.

use super::ffi::{
    AXIsProcessTrustedWithOptions, CGPreflightListenEventAccess, CGRequestListenEventAccess,
};
use super::PermissionStatus;
use core_foundation::base::TCFType;
use core_foundation::boolean::CFBoolean;
use core_foundation::dictionary::CFDictionary;
use core_foundation::string::CFString;

/// Check if accessibility permissions are granted (without prompting).
pub fn check_accessibility_permissions() -> bool {
    let key = CFString::new("AXTrustedCheckOptionPrompt");
    let value = CFBoolean::false_value();
    let dict = CFDictionary::from_CFType_pairs(&[(key.as_CFType(), value.as_CFType())]);

    unsafe { AXIsProcessTrustedWithOptions(dict.as_concrete_TypeRef()) }
}

/// Request accessibility permissions (will prompt user if not granted).
pub fn request_accessibility_permissions() -> bool {
    let key = CFString::new("AXTrustedCheckOptionPrompt");
    let value = CFBoolean::true_value();
    let dict = CFDictionary::from_CFType_pairs(&[(key.as_CFType(), value.as_CFType())]);

    unsafe { AXIsProcessTrustedWithOptions(dict.as_concrete_TypeRef()) }
}

/// Check if Input Monitoring permissions are granted (without prompting).
pub fn check_input_monitoring_permissions() -> bool {
    unsafe { CGPreflightListenEventAccess() }
}

/// Request Input Monitoring permissions (will prompt user if not granted).
pub fn request_input_monitoring_permissions() -> bool {
    unsafe { CGRequestListenEventAccess() }
}

/// Get combined permission status.
pub fn get_permission_status() -> PermissionStatus {
    let accessibility = check_accessibility_permissions();
    let input_monitoring = check_input_monitoring_permissions();
    PermissionStatus {
        accessibility,
        input_monitoring,
        input_devices: true, // Always true on macOS
        all_granted: accessibility && input_monitoring,
    }
}

/// Request all required permissions, prompting user if needed.
pub fn request_all_permissions() -> PermissionStatus {
    let accessibility = request_accessibility_permissions();
    let input_monitoring = request_input_monitoring_permissions();
    PermissionStatus {
        accessibility,
        input_monitoring,
        input_devices: true,
        all_granted: accessibility && input_monitoring,
    }
}

/// Check if all required permissions are granted.
pub fn has_required_permissions() -> bool {
    check_accessibility_permissions() && check_input_monitoring_permissions()
}
