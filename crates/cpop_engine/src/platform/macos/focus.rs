// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Focus tracking with document path retrieval via Accessibility API.

use super::ffi::*;
use super::permissions::check_accessibility_permissions;
use super::FocusInfo;
use crate::platform::FocusMonitor;
use anyhow::{anyhow, Result};
use core_foundation::base::TCFType;
use core_foundation::string::CFString;
use core_foundation_sys::base::CFTypeRef;
use objc::runtime::Object;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};

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

/// Get information about the currently focused application and document.
pub fn get_active_focus() -> Result<FocusInfo> {
    unsafe {
        let workspace: *mut Object = msg_send![class!(NSWorkspace), sharedWorkspace];
        let active_app: *mut Object = msg_send![workspace, frontmostApplication];
        if active_app.is_null() {
            return Err(anyhow!("No active application found"));
        }

        let name: *mut Object = msg_send![active_app, localizedName];
        let bundle_id: *mut Object = msg_send![active_app, bundleIdentifier];
        let pid: i32 = msg_send![active_app, processIdentifier];

        let app_name = nsstring_to_string(name);
        let bundle_id_str = nsstring_to_string(bundle_id);

        let (doc_path, doc_title, window_title) = get_document_info_for_pid(pid);

        // Fallback: when AXDocument is unavailable (common with Electron editors),
        // infer the document path from the window title + bundle ID.
        let doc_path = doc_path.or_else(|| {
            window_title.as_deref().and_then(|title| {
                crate::sentinel::infer_document_path_from_title_with_bundle(
                    title,
                    Some(&bundle_id_str),
                )
            })
        });

        Ok(FocusInfo {
            app_name,
            bundle_id: bundle_id_str,
            pid,
            doc_path,
            doc_title,
            window_title,
        })
    }
}

/// Get document information for a specific process using Accessibility API.
fn get_document_info_for_pid(pid: i32) -> (Option<String>, Option<String>, Option<String>) {
    if !check_accessibility_permissions() {
        return (None, None, None);
    }

    unsafe {
        let app_element = AXUIElementCreateApplication(pid);
        if app_element.is_null() {
            return (None, None, None);
        }

        let mut window_value: CFTypeRef = null_mut();
        let window_attr = CFString::new(K_AX_FOCUSED_WINDOW_ATTRIBUTE);
        let result = AXUIElementCopyAttributeValue(
            app_element,
            window_attr.as_concrete_TypeRef(),
            &mut window_value,
        );

        if result != K_AX_ERROR_SUCCESS || window_value.is_null() {
            CFRelease(app_element);
            return (None, None, None);
        }

        let window_element = window_value as *mut std::ffi::c_void;

        let doc_path = get_ax_string_attribute(window_element, K_AX_DOCUMENT_ATTRIBUTE)
            .or_else(|| get_ax_url_as_path(window_element));

        let window_title = get_ax_string_attribute(window_element, K_AX_TITLE_ATTRIBUTE);

        let doc_title = get_ax_string_attribute(window_element, K_AX_DESCRIPTION_ATTRIBUTE)
            .or_else(|| get_ax_string_attribute(window_element, K_AX_FILENAME_ATTRIBUTE));

        CFRelease(window_element);
        CFRelease(app_element);

        (doc_path, doc_title, window_title)
    }
}

unsafe fn get_ax_string_attribute(
    element: *mut std::ffi::c_void,
    attribute: &str,
) -> Option<String> {
    let mut value: CFTypeRef = null_mut();
    let attr_name = CFString::new(attribute);
    let result =
        AXUIElementCopyAttributeValue(element, attr_name.as_concrete_TypeRef(), &mut value);

    if result != K_AX_ERROR_SUCCESS || value.is_null() {
        return None;
    }

    if CFGetTypeID(value) != CFStringGetTypeID() {
        CFRelease(value as *mut std::ffi::c_void);
        return None;
    }

    let cf_string =
        CFString::wrap_under_create_rule(value as core_foundation_sys::string::CFStringRef);
    let s = cf_string.to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

unsafe fn get_ax_url_as_path(element: *mut std::ffi::c_void) -> Option<String> {
    let mut value: CFTypeRef = null_mut();
    let attr_name = CFString::new(K_AX_URL_ATTRIBUTE);
    let result =
        AXUIElementCopyAttributeValue(element, attr_name.as_concrete_TypeRef(), &mut value);

    if result != K_AX_ERROR_SUCCESS || value.is_null() {
        return None;
    }

    if CFGetTypeID(value) != CFURLGetTypeID() {
        CFRelease(value as *mut std::ffi::c_void);
        return None;
    }

    extern "C" {
        fn CFURLCopyFileSystemPath(
            url: CFTypeRef,
            path_style: i32,
        ) -> core_foundation_sys::string::CFStringRef;
    }

    const K_CF_URL_POSIX_PATH_STYLE: i32 = 0;

    let path_ref = CFURLCopyFileSystemPath(value, K_CF_URL_POSIX_PATH_STYLE);
    CFRelease(value as *mut std::ffi::c_void);

    if path_ref.is_null() {
        return None;
    }

    let cf_string = CFString::wrap_under_create_rule(path_ref);
    let path = cf_string.to_string();
    if path.is_empty() {
        None
    } else {
        Some(path)
    }
}

/// macOS focus monitor implementation.
pub struct MacOSFocusMonitor {
    running: Arc<AtomicBool>,
    sender: Option<mpsc::Sender<FocusInfo>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl MacOSFocusMonitor {
    pub fn new() -> Result<Self> {
        Ok(Self {
            running: Arc::new(AtomicBool::new(false)),
            sender: None,
            thread: None,
        })
    }
}

impl FocusMonitor for MacOSFocusMonitor {
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
                // Wrap each iteration in an autorelease pool to prevent
                // memory leaks from Objective-C calls in get_active_focus()
                objc::rc::autoreleasepool(|| {
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
                });

                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        });

        self.thread = Some(thread);
        Ok(rx)
    }

    fn stop_monitoring(&mut self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);
        self.sender = None;
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        Ok(())
    }

    fn is_monitoring(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}
