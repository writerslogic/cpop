// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::focus::*;
use super::types::*;
use crate::config::SentinelConfig;
use crate::crypto::ObfuscatedString;
use objc::runtime::Object;
use std::sync::Arc;
use std::time::SystemTime;

/// macOS focus monitor using NSWorkspace and Accessibility APIs.
pub struct MacOSFocusMonitor {
    #[allow(dead_code)]
    config: Arc<SentinelConfig>,
}

impl MacOSFocusMonitor {
    pub fn new(config: Arc<SentinelConfig>) -> Self {
        Self { config }
    }

    pub fn new_monitor(config: Arc<SentinelConfig>) -> Box<dyn SentinelFocusTracker> {
        let provider = Arc::new(Self::new(Arc::clone(&config)));
        Box::new(PollingSentinelFocusTracker::new(provider, config))
    }

    fn get_active_window_info(&self) -> Option<WindowInfo> {
        unsafe {
            let workspace: *mut Object = msg_send![class!(NSWorkspace), sharedWorkspace];
            let active_app: *mut Object = msg_send![workspace, frontmostApplication];

            if active_app.is_null() {
                return None;
            }

            let name: *mut Object = msg_send![active_app, localizedName];
            let bundle_id: *mut Object = msg_send![active_app, bundleIdentifier];
            let pid: i32 = msg_send![active_app, processIdentifier];

            let app_name = nsstring_to_string(name);
            let bundle_id_str = nsstring_to_string(bundle_id);

            let doc_path = self.get_document_path_via_ax(pid);
            let window_title = self.get_window_title_via_ax(pid);
            let title_str = window_title.unwrap_or_default();

            let doc_path =
                doc_path.or_else(|| super::types::infer_document_path_from_title(&title_str));

            Some(WindowInfo {
                is_document: doc_path.is_some(),
                path: doc_path,
                application: if !bundle_id_str.is_empty() {
                    bundle_id_str
                } else {
                    app_name.clone()
                },
                title: ObfuscatedString::new(&title_str),
                pid: Some(pid as u32),
                timestamp: SystemTime::now(),
                is_unsaved: false,
                project_root: None,
            })
        }
    }

    /// Query the focused window's `AXDocument` attribute for its `file://` URL.
    fn get_document_path_via_ax(&self, pid: i32) -> Option<String> {
        unsafe {
            use core_foundation::base::{CFType, TCFType};
            use core_foundation::string::CFString;

            #[link(name = "ApplicationServices", kind = "framework")]
            extern "C" {
                fn AXUIElementCreateApplication(pid: i32) -> *mut std::ffi::c_void;
                fn AXUIElementCopyAttributeValue(
                    element: *mut std::ffi::c_void,
                    attribute: core_foundation::string::CFStringRef,
                    value: *mut *const std::ffi::c_void,
                ) -> i32;
                fn CFRelease(cf: *mut std::ffi::c_void);
            }

            let app_element = AXUIElementCreateApplication(pid);
            if app_element.is_null() {
                return None;
            }

            let attr_focused = CFString::new("AXFocusedWindow");
            let mut focused_window: *const std::ffi::c_void = std::ptr::null();
            let err = AXUIElementCopyAttributeValue(
                app_element,
                attr_focused.as_concrete_TypeRef(),
                &mut focused_window,
            );

            if err != 0 || focused_window.is_null() {
                CFRelease(app_element);
                return None;
            }

            let attr_doc = CFString::new("AXDocument");
            let mut doc_value: *const std::ffi::c_void = std::ptr::null();
            let err = AXUIElementCopyAttributeValue(
                focused_window as *mut _,
                attr_doc.as_concrete_TypeRef(),
                &mut doc_value,
            );

            let result = if err == 0 && !doc_value.is_null() {
                let cf_type = CFType::wrap_under_create_rule(doc_value as _);
                let url_str = if let Some(cf_str) = cf_type.downcast::<CFString>() {
                    cf_str.to_string()
                } else {
                    format!("{:?}", cf_type)
                };
                if url_str.starts_with("file://") {
                    let path = url_str.trim_start_matches("file://");
                    let decoded = urlencoding::decode(path).unwrap_or_default().into_owned();
                    if !decoded.is_empty() {
                        Some(decoded)
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            };

            CFRelease(focused_window as *mut _);
            CFRelease(app_element);
            result
        }
    }

    /// Query the focused window's `AXTitle` attribute.
    fn get_window_title_via_ax(&self, pid: i32) -> Option<String> {
        unsafe {
            use core_foundation::base::{CFType, TCFType};
            use core_foundation::string::CFString;

            #[link(name = "ApplicationServices", kind = "framework")]
            extern "C" {
                fn AXUIElementCreateApplication(pid: i32) -> *mut std::ffi::c_void;
                fn AXUIElementCopyAttributeValue(
                    element: *mut std::ffi::c_void,
                    attribute: core_foundation::string::CFStringRef,
                    value: *mut *const std::ffi::c_void,
                ) -> i32;
                fn CFRelease(cf: *mut std::ffi::c_void);
            }

            let app_element = AXUIElementCreateApplication(pid);
            if app_element.is_null() {
                return None;
            }

            let attr_focused = CFString::new("AXFocusedWindow");
            let mut focused_window: *const std::ffi::c_void = std::ptr::null();
            let err = AXUIElementCopyAttributeValue(
                app_element,
                attr_focused.as_concrete_TypeRef(),
                &mut focused_window,
            );

            if err != 0 || focused_window.is_null() {
                CFRelease(app_element);
                return None;
            }

            let attr_title = CFString::new("AXTitle");
            let mut title_value: *const std::ffi::c_void = std::ptr::null();
            let err = AXUIElementCopyAttributeValue(
                focused_window as *mut _,
                attr_title.as_concrete_TypeRef(),
                &mut title_value,
            );

            let result = if err == 0 && !title_value.is_null() {
                let cf_type = CFType::wrap_under_create_rule(title_value as _);
                let title = if let Some(cf_str) = cf_type.downcast::<CFString>() {
                    cf_str.to_string()
                } else {
                    format!("{:?}", cf_type)
                };
                if !title.is_empty() {
                    Some(title)
                } else {
                    None
                }
            } else {
                None
            };

            CFRelease(focused_window as *mut _);
            CFRelease(app_element);
            result
        }
    }
}

impl WindowProvider for MacOSFocusMonitor {
    fn get_active_window(&self) -> Option<WindowInfo> {
        self.get_active_window_info()
    }
}

unsafe fn nsstring_to_string(ns_str: *mut Object) -> String {
    if ns_str.is_null() {
        return String::new();
    }
    let char_ptr: *const std::os::raw::c_char = msg_send![ns_str, UTF8String];
    if char_ptr.is_null() {
        return String::new();
    }
    std::ffi::CStr::from_ptr(char_ptr)
        .to_string_lossy()
        .into_owned()
}

/// Check if accessibility permissions are granted (does not prompt).
pub fn check_accessibility_permissions() -> bool {
    use core_foundation::base::TCFType;
    use core_foundation::boolean::CFBoolean;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::string::CFString;

    #[link(name = "ApplicationServices", kind = "framework")]
    extern "C" {
        fn AXIsProcessTrustedWithOptions(
            options: core_foundation::dictionary::CFDictionaryRef,
        ) -> bool;
    }

    let key = CFString::new("AXTrustedCheckOptionPrompt");
    let value = CFBoolean::false_value();
    let dict = CFDictionary::from_CFType_pairs(&[(key.as_CFType(), value.as_CFType())]);

    unsafe { AXIsProcessTrustedWithOptions(dict.as_concrete_TypeRef()) }
}

/// Request accessibility permissions (shows system prompt dialog).
pub fn request_accessibility_permissions() -> bool {
    use core_foundation::base::TCFType;
    use core_foundation::boolean::CFBoolean;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::string::CFString;

    #[link(name = "ApplicationServices", kind = "framework")]
    extern "C" {
        fn AXIsProcessTrustedWithOptions(
            options: core_foundation::dictionary::CFDictionaryRef,
        ) -> bool;
    }

    let key = CFString::new("AXTrustedCheckOptionPrompt");
    let value = CFBoolean::true_value();
    let dict = CFDictionary::from_CFType_pairs(&[(key.as_CFType(), value.as_CFType())]);

    unsafe { AXIsProcessTrustedWithOptions(dict.as_concrete_TypeRef()) }
}
