// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! macOS permission handling for Accessibility and Input Monitoring.

use super::ffi::{
    AXIsProcessTrustedWithOptions, CGPreflightListenEventAccess, CGRequestListenEventAccess,
};
use super::PermissionStatus;
use core_foundation::base::TCFType;
use core_foundation::boolean::CFBoolean;
use core_foundation::dictionary::CFDictionary;
use core_foundation::string::CFString;

pub fn check_accessibility_permissions() -> bool {
    let key = CFString::new("AXTrustedCheckOptionPrompt");
    let value = CFBoolean::false_value();
    let dict = CFDictionary::from_CFType_pairs(&[(key.as_CFType(), value.as_CFType())]);

    unsafe { AXIsProcessTrustedWithOptions(dict.as_concrete_TypeRef()) }
}

pub fn request_accessibility_permissions() -> bool {
    let key = CFString::new("AXTrustedCheckOptionPrompt");
    let value = CFBoolean::true_value();
    let dict = CFDictionary::from_CFType_pairs(&[(key.as_CFType(), value.as_CFType())]);

    unsafe { AXIsProcessTrustedWithOptions(dict.as_concrete_TypeRef()) }
}

pub fn check_input_monitoring_permissions() -> bool {
    unsafe { CGPreflightListenEventAccess() }
}

pub fn request_input_monitoring_permissions() -> bool {
    unsafe { CGRequestListenEventAccess() }
}

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

pub fn has_required_permissions() -> bool {
    check_accessibility_permissions() && check_input_monitoring_permissions()
}
