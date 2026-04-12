// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Linux focus monitor using X11 or /proc polling.

use crate::platform::{FocusInfo, FocusMonitor};
use anyhow::{anyhow, Result};
use std::fs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};

/// Detect the currently focused application via X11 or /proc fallback.
pub fn get_active_focus() -> Result<FocusInfo> {
    #[cfg(feature = "x11")]
    if let Ok(focus) = get_x11_focus() {
        return Ok(focus);
    }

    get_focus_from_proc()
}

/// Known editor binary names for focus detection.
const KNOWN_EDITORS: &[&str] = &["vim", "nvim", "emacs", "code", "sublime_text", "gedit"];

/// Fallback: scan /proc for known editor processes.
fn get_focus_from_proc() -> Result<FocusInfo> {
    let entries = fs::read_dir("/proc")?;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let pid_str = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if pid_str.chars().all(|c| c.is_ascii_digit()) {
            // Use /proc/pid/exe readlink for reliable binary identification
            // instead of substring-matching the cmdline.
            let exe_link = path.join("exe");
            if let Ok(exe_path) = fs::read_link(&exe_link) {
                let exe_name = exe_path.file_name().and_then(|s| s.to_str()).unwrap_or("");
                if KNOWN_EDITORS.iter().any(|&ed| exe_name == ed) {
                    let pid: i32 = match pid_str.parse() {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    let app_name = exe_name.to_string();

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

    let active_window_atom = conn
        .intern_atom(false, b"_NET_ACTIVE_WINDOW")?
        .reply()?
        .atom;

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

    let wm_name_atom = conn.intern_atom(false, b"_NET_WM_NAME")?.reply()?.atom;
    let utf8_string_atom = conn.intern_atom(false, b"UTF8_STRING")?.reply()?.atom;

    let name_reply = conn
        .get_property(false, window_id, wm_name_atom, utf8_string_atom, 0, 1024)?
        .reply()?;

    let window_title = if !name_reply.value.is_empty() {
        Some(String::from_utf8_lossy(&name_reply.value).to_owned())
    } else {
        None
    };

    let pid_atom = conn.intern_atom(false, b"_NET_WM_PID")?.reply()?.atom;
    let pid_reply = conn
        .get_property(false, window_id, pid_atom, AtomEnum::CARDINAL, 0, 1)?
        .reply()?;

    let pid = if !pid_reply.value.is_empty() {
        i32::from_ne_bytes(pid_reply.value[0..4].try_into()?)
    } else {
        0
    };

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

/// Linux focus monitor using X11 or /proc polling.
pub struct LinuxFocusMonitor {
    running: Arc<AtomicBool>,
    sender: Option<mpsc::Sender<FocusInfo>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl LinuxFocusMonitor {
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
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        Ok(())
    }

    fn is_monitoring(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}

impl Drop for LinuxFocusMonitor {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
