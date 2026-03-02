// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! FFI bindings for IOKit HID, Accessibility API, and CGEvent constants.

use core_foundation_sys::base::{CFAllocatorRef, CFIndex, CFTypeID, CFTypeRef};
use core_foundation_sys::dictionary::CFDictionaryRef;
use core_foundation_sys::string::CFStringRef;

// =============================================================================
// IOKit HID Framework bindings for device enumeration
// =============================================================================

#[allow(dead_code)]
#[link(name = "IOKit", kind = "framework")]
extern "C" {
    pub fn IOHIDManagerCreate(allocator: CFAllocatorRef, options: u32) -> *mut std::ffi::c_void;
    pub fn IOHIDManagerSetDeviceMatching(manager: *mut std::ffi::c_void, matching: CFDictionaryRef);
    pub fn IOHIDManagerCopyDevices(manager: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    pub fn IOHIDManagerOpen(manager: *mut std::ffi::c_void, options: u32) -> i32;
    pub fn IOHIDManagerClose(manager: *mut std::ffi::c_void, options: u32) -> i32;
    pub fn IOHIDManagerScheduleWithRunLoop(
        manager: *mut std::ffi::c_void,
        run_loop: *mut std::ffi::c_void,
        mode: CFStringRef,
    );
    pub fn IOHIDManagerUnscheduleFromRunLoop(
        manager: *mut std::ffi::c_void,
        run_loop: *mut std::ffi::c_void,
        mode: CFStringRef,
    );
    pub fn IOHIDManagerRegisterInputValueCallback(
        manager: *mut std::ffi::c_void,
        callback: extern "C" fn(
            *mut std::ffi::c_void,
            i32,
            *mut std::ffi::c_void,
            *mut std::ffi::c_void,
        ),
        context: *mut std::ffi::c_void,
    );

    pub fn IOHIDDeviceGetProperty(device: *mut std::ffi::c_void, key: CFStringRef) -> CFTypeRef;

    pub fn CFSetGetCount(set: *mut std::ffi::c_void) -> CFIndex;
    pub fn CFSetGetValues(set: *mut std::ffi::c_void, values: *mut *const std::ffi::c_void);
    pub fn CFRelease(cf: *mut std::ffi::c_void);
    pub fn CFRetain(cf: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    pub fn CFGetTypeID(cf: CFTypeRef) -> CFTypeID;
    pub fn CFStringGetTypeID() -> CFTypeID;
    pub fn CFURLGetTypeID() -> CFTypeID;
    pub fn CFRunLoopGetCurrent() -> *mut std::ffi::c_void;
    pub fn CFRunLoopStop(rl: *mut std::ffi::c_void);

    pub fn IOHIDValueGetElement(value: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    pub fn IOHIDValueGetIntegerValue(value: *mut std::ffi::c_void) -> CFIndex;
    pub fn IOHIDElementGetUsagePage(element: *mut std::ffi::c_void) -> u32;
    pub fn IOHIDElementGetUsage(element: *mut std::ffi::c_void) -> u32;
}

// IOKit HID constants
pub const K_HID_PAGE_GENERIC_DESKTOP: i32 = 0x01;
#[allow(dead_code)]
pub const K_HID_PAGE_KEYBOARD_OR_KEYPAD: u32 = 0x07;
pub const K_HID_USAGE_GD_KEYBOARD: i32 = 0x06;
pub const K_IO_HID_OPTIONS_TYPE_NONE: u32 = 0;

// IOKit property keys
pub const K_IO_HID_DEVICE_USAGE_PAGE_KEY: &str = "DeviceUsagePage";
pub const K_IO_HID_DEVICE_USAGE_KEY: &str = "DeviceUsage";
pub const K_IO_HID_VENDOR_ID_KEY: &str = "VendorID";
pub const K_IO_HID_PRODUCT_ID_KEY: &str = "ProductID";
pub const K_IO_HID_PRODUCT_KEY: &str = "Product";
pub const K_IO_HID_MANUFACTURER_KEY: &str = "Manufacturer";
pub const K_IO_HID_SERIAL_NUMBER_KEY: &str = "SerialNumber";
pub const K_IO_HID_TRANSPORT_KEY: &str = "Transport";

// =============================================================================
// Accessibility API bindings for focus and document tracking
// =============================================================================

#[allow(dead_code)]
#[link(name = "ApplicationServices", kind = "framework")]
extern "C" {
    pub fn AXIsProcessTrusted() -> bool;
    pub fn AXIsProcessTrustedWithOptions(options: CFDictionaryRef) -> bool;
    pub fn CGPreflightListenEventAccess() -> bool;
    pub fn CGRequestListenEventAccess() -> bool;

    pub fn AXUIElementCreateApplication(pid: i32) -> *mut std::ffi::c_void;
    pub fn AXUIElementCopyAttributeValue(
        element: *mut std::ffi::c_void,
        attribute: CFStringRef,
        value: *mut CFTypeRef,
    ) -> i32;
    pub fn AXUIElementCopyAttributeNames(
        element: *mut std::ffi::c_void,
        names: *mut CFTypeRef,
    ) -> i32;
}

// AXError codes
pub const K_AX_ERROR_SUCCESS: i32 = 0;

// AX attribute names
pub const K_AX_FOCUSED_WINDOW_ATTRIBUTE: &str = "AXFocusedWindow";
pub const K_AX_DOCUMENT_ATTRIBUTE: &str = "AXDocument";
pub const K_AX_TITLE_ATTRIBUTE: &str = "AXTitle";
pub const K_AX_DESCRIPTION_ATTRIBUTE: &str = "AXDescription";
pub const K_AX_FILENAME_ATTRIBUTE: &str = "AXFilename";
pub const K_AX_URL_ATTRIBUTE: &str = "AXURL";

// =============================================================================
// CGEvent field constants for synthetic event detection
// =============================================================================

// CGEventField constants (values from Apple's CGEventTypes.h / macOS SDK)
pub const K_CG_EVENT_SOURCE_STATE_ID: u32 = 45;
pub const K_CG_KEYBOARD_EVENT_KEYBOARD_TYPE: u32 = 10;
pub const K_CG_KEYBOARD_EVENT_KEYCODE: u32 = 9;
pub const K_CG_EVENT_SOURCE_UNIX_PROCESS_ID: u32 = 41;
#[allow(dead_code)]
pub const K_CG_KEYBOARD_EVENT_AUTOREPEAT: u32 = 8;

// CGEventSourceStateID values
pub const K_CG_EVENT_SOURCE_STATE_PRIVATE: i64 = -1;
#[allow(dead_code)]
pub const K_CG_EVENT_SOURCE_STATE_COMBINED_SESSION: i64 = 0;
pub const K_CG_EVENT_SOURCE_STATE_HID_SYSTEM: i64 = 1;
