// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::focus::*;
use super::types::*;
use crate::config::SentinelConfig;
use crate::crypto::ObfuscatedString;
use objc::runtime::Object;
use std::sync::Arc;
use std::time::SystemTime;

/// macOS focus monitor using NSWorkspace and Accessibility APIs.
pub struct MacOSFocusMonitor {
    _config: Arc<SentinelConfig>,
}

impl MacOSFocusMonitor {
    pub fn new(config: Arc<SentinelConfig>) -> Self {
        Self { _config: config }
    }

    pub fn new_monitor(config: Arc<SentinelConfig>) -> Box<dyn SentinelFocusTracker> {
        let provider = Arc::new(Self::new(Arc::clone(&config)));
        Box::new(PollingSentinelFocusTracker::new(provider, config))
    }

    fn get_active_window_info(&self) -> Option<WindowInfo> {
        // Wrap in an autorelease pool so Objective-C temporaries are freed
        // promptly when called from a tokio worker thread (which has no
        // default NSAutoreleasePool).
        let pool: *mut Object = unsafe { msg_send![class!(NSAutoreleasePool), new] };
        let result = unsafe {
            let workspace: *mut Object = msg_send![class!(NSWorkspace), sharedWorkspace];
            let active_app: *mut Object = msg_send![workspace, frontmostApplication];

            if active_app.is_null() {
                let _: () = msg_send![pool, drain];
                return None;
            }

            let name: *mut Object = msg_send![active_app, localizedName];
            let bundle_id: *mut Object = msg_send![active_app, bundleIdentifier];
            let pid: i32 = msg_send![active_app, processIdentifier];

            let app_name = nsstring_to_string(name);
            let bundle_id_str = nsstring_to_string(bundle_id);

            // Try AX first (works when Accessibility permission is granted),
            // fall back to CGWindowList (works in App Sandbox without special perms).
            let doc_path = self.get_document_path_via_ax(pid);
            let window_title = self
                .get_window_title_via_ax(pid)
                .or_else(|| self.get_window_title_via_cgwindow(pid));
            let title_str = window_title.unwrap_or_default();

            let doc_path = doc_path.or_else(|| {
                super::types::infer_document_path_from_title_with_bundle(
                    &title_str,
                    Some(&bundle_id_str),
                )
            });

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
        };
        unsafe {
            let _: () = msg_send![pool, drain];
        }
        result
    }

    /// Query the focused window's `AXDocument` attribute for its `file://` URL.
    fn get_document_path_via_ax(&self, pid: i32) -> Option<String> {
        let raw = self.query_focused_window_attribute(pid, "AXDocument")?;
        if raw.starts_with("file://") {
            let path = raw.trim_start_matches("file://");
            let decoded = urlencoding::decode(path).unwrap_or_default().into_owned();
            if !decoded.is_empty() {
                return Some(decoded);
            }
        }
        None
    }

    /// Query the focused window's `AXTitle` attribute.
    fn get_window_title_via_ax(&self, pid: i32) -> Option<String> {
        let title = self.query_focused_window_attribute(pid, "AXTitle")?;
        if !title.is_empty() {
            Some(title)
        } else {
            None
        }
    }

    /// Get the window title via CGWindowListCopyWindowInfo (works in App Sandbox).
    fn get_window_title_via_cgwindow(&self, pid: i32) -> Option<String> {
        unsafe {
            use core_foundation::base::TCFType;
            use core_foundation::string::CFString;
            use core_foundation_sys::dictionary::CFDictionaryGetValueIfPresent;

            #[link(name = "CoreGraphics", kind = "framework")]
            extern "C" {
                fn CGWindowListCopyWindowInfo(
                    option: u32,
                    relative_to_window: u32,
                ) -> core_foundation_sys::array::CFArrayRef;
            }

            // kCGWindowListOptionOnScreenOnly = 1, kCGNullWindowID = 0
            let list = CGWindowListCopyWindowInfo(1, 0);
            if list.is_null() {
                return None;
            }

            let count = core_foundation_sys::array::CFArrayGetCount(list);
            let key_pid = CFString::from_static_string("kCGWindowOwnerPID");
            let key_name = CFString::from_static_string("kCGWindowName");
            let key_layer = CFString::from_static_string("kCGWindowLayer");

            for i in 0..count {
                let raw_dict = core_foundation_sys::array::CFArrayGetValueAtIndex(list, i)
                    as core_foundation_sys::dictionary::CFDictionaryRef;
                if raw_dict.is_null() {
                    continue;
                }

                // Only look at layer 0 (normal windows)
                let mut layer_ptr: *const std::ffi::c_void = std::ptr::null();
                if CFDictionaryGetValueIfPresent(raw_dict, key_layer.as_CFTypeRef(), &mut layer_ptr)
                    != 0
                    && !layer_ptr.is_null()
                {
                    let layer_num = core_foundation::number::CFNumber::wrap_under_get_rule(
                        layer_ptr as core_foundation::number::CFNumberRef,
                    );
                    if layer_num.to_i32().unwrap_or(-1) != 0 {
                        continue;
                    }
                }

                let mut pid_ptr: *const std::ffi::c_void = std::ptr::null();
                if CFDictionaryGetValueIfPresent(raw_dict, key_pid.as_CFTypeRef(), &mut pid_ptr)
                    == 0
                    || pid_ptr.is_null()
                {
                    continue;
                }
                let pid_num = core_foundation::number::CFNumber::wrap_under_get_rule(
                    pid_ptr as core_foundation::number::CFNumberRef,
                );
                if pid_num.to_i32().unwrap_or(-1) != pid {
                    continue;
                }

                let mut name_ptr: *const std::ffi::c_void = std::ptr::null();
                if CFDictionaryGetValueIfPresent(raw_dict, key_name.as_CFTypeRef(), &mut name_ptr)
                    != 0
                    && !name_ptr.is_null()
                {
                    let name = CFString::wrap_under_get_rule(
                        name_ptr as core_foundation::string::CFStringRef,
                    );
                    let title = name.to_string();
                    if !title.is_empty() {
                        core_foundation_sys::base::CFRelease(list as _);
                        return Some(title);
                    }
                }
            }

            core_foundation_sys::base::CFRelease(list as _);
            None
        }
    }

    /// Query an arbitrary accessibility attribute from the focused window of a given pid.
    fn query_focused_window_attribute(&self, pid: i32, attribute: &str) -> Option<String> {
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

            let attr = CFString::new(attribute);
            let mut value: *const std::ffi::c_void = std::ptr::null();
            let err = AXUIElementCopyAttributeValue(
                focused_window as *mut _,
                attr.as_concrete_TypeRef(),
                &mut value,
            );

            let result = if err == 0 && !value.is_null() {
                let cf_type = CFType::wrap_under_create_rule(value as _);
                if let Some(cf_str) = cf_type.downcast::<CFString>() {
                    Some(cf_str.to_string())
                } else {
                    Some(format!("{:?}", cf_type))
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
