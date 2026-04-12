// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::error::{Result, SentinelError};
use super::types::*;
use crate::config::SentinelConfig;
use crate::crypto::ObfuscatedString;
use crate::MutexRecover;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tokio::sync::mpsc;
use tokio::time::interval;

/// Platform-specific focus monitoring trait.
pub trait SentinelFocusTracker: Send + Sync {
    fn start(&self) -> Result<()>;
    fn stop(&self) -> Result<()>;
    fn active_window(&self) -> Option<WindowInfo>;
    fn available(&self) -> (bool, String);
    fn focus_events(&self) -> Result<mpsc::Receiver<FocusEvent>>;
    fn change_events(&self) -> Result<mpsc::Receiver<ChangeEvent>>;
}

/// Provider for active window information. Implemented per-platform.
pub trait WindowProvider: Send + Sync + 'static {
    fn get_active_window(&self) -> Option<WindowInfo>;
}

#[derive(Debug)]
/// Polling-based focus monitor backed by a `WindowProvider`.
pub struct PollingSentinelFocusTracker<P: WindowProvider + ?Sized> {
    provider: Arc<P>,
    config: Arc<SentinelConfig>,
    running: Arc<AtomicBool>,
    focus_tx: mpsc::Sender<FocusEvent>,
    focus_rx: Arc<Mutex<Option<mpsc::Receiver<FocusEvent>>>>,
    _change_tx: mpsc::Sender<ChangeEvent>,
    change_rx: Arc<Mutex<Option<mpsc::Receiver<ChangeEvent>>>>,
    poll_handle: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

impl<P: WindowProvider + ?Sized> PollingSentinelFocusTracker<P> {
    pub fn new(provider: Arc<P>, config: Arc<SentinelConfig>) -> Self {
        let (focus_tx, focus_rx) = mpsc::channel(100);
        let (change_tx, change_rx) = mpsc::channel(100);

        Self {
            provider,
            config,
            running: Arc::new(AtomicBool::new(false)),
            focus_tx,
            focus_rx: Arc::new(Mutex::new(Some(focus_rx))),
            _change_tx: change_tx,
            change_rx: Arc::new(Mutex::new(Some(change_rx))),
            poll_handle: Arc::new(Mutex::new(None)),
        }
    }
}

impl<P: WindowProvider + ?Sized> SentinelFocusTracker for PollingSentinelFocusTracker<P> {
    fn start(&self) -> Result<()> {
        if self.running.swap(true, Ordering::AcqRel) {
            return Err(SentinelError::AlreadyRunning);
        }

        let running_clone = Arc::clone(&self.running);
        let focus_tx = self.focus_tx.clone();
        let config = self.config.clone();
        let provider = Arc::clone(&self.provider);
        let poll_interval = Duration::from_millis(self.config.poll_interval_ms);

        let handle = tokio::spawn(async move {
            let mut last_app = String::new();
            let mut last_path: Option<String> = None;
            let mut interval_timer = interval(poll_interval);

            // Probe the currently focused window immediately on startup so
            // the sentinel knows what document is active before keystrokes
            // arrive.  This is critical after a stop/restart cycle where the
            // document was already open and no OS focus event will fire.
            if let Some(info) = provider.get_active_window() {
                let app = if !info.application.is_empty() {
                    info.application.clone()
                } else {
                    "unknown".to_string()
                };
                let app_name = info.application.clone();
                if config.is_app_allowed(&info.application, &app_name) {
                    if focus_tx
                        .send(FocusEvent {
                            event_type: FocusEventType::FocusGained,
                            path: info.path.clone().unwrap_or_default(),
                            shadow_id: String::new(),
                            app_bundle_id: info.application.clone(),
                            app_name: info.application.clone(),
                            window_title: info.title.clone(),
                            timestamp: SystemTime::now(),
                        })
                        .await
                        .is_err()
                    {
                        log::warn!("Focus event channel closed, stopping poll");
                        return;
                    }
                    last_path = info.path.clone();
                }
                last_app = app;
            }

            loop {
                interval_timer.tick().await;

                if !running_clone.load(Ordering::Acquire) {
                    break;
                }

                if let Some(info) = provider.get_active_window() {
                    let current_app = if !info.application.is_empty() {
                        info.application.clone()
                    } else {
                        "unknown".to_string()
                    };

                    if current_app != last_app {
                        if !last_app.is_empty()
                            && focus_tx
                                .send(FocusEvent {
                                    event_type: FocusEventType::FocusLost,
                                    path: String::new(),
                                    shadow_id: String::new(),
                                    app_bundle_id: last_app.clone(),
                                    app_name: String::new(),
                                    window_title: ObfuscatedString::default(),
                                    timestamp: SystemTime::now(),
                                })
                                .await
                                .is_err()
                        {
                            log::warn!("Focus event channel closed, stopping poll");
                            break;
                        }

                        let app_name = info.application.clone();
                        if config.is_app_allowed(&info.application, &app_name) {
                            if focus_tx
                                .send(FocusEvent {
                                    event_type: FocusEventType::FocusGained,
                                    path: info.path.clone().unwrap_or_default(),
                                    shadow_id: String::new(),
                                    app_bundle_id: info.application.clone(),
                                    app_name: info.application.clone(),
                                    window_title: info.title.clone(),
                                    timestamp: SystemTime::now(),
                                })
                                .await
                                .is_err()
                            {
                                log::warn!("Focus event channel closed, stopping poll");
                                break;
                            }
                            last_path = info.path.clone();
                        } else {
                            last_path = None;
                        }

                        last_app = current_app;
                    } else if info.path.is_some() && info.path != last_path {
                        // App unchanged but document path changed (intra-app document switch
                        // or AX query latency resolving the path for the first time).
                        // Send FocusLost for the old path first so the sentinel can close out
                        // the previous document session before opening the new one.
                        let app_name = info.application.clone();
                        if config.is_app_allowed(&info.application, &app_name) {
                            if let Some(ref old_path) = last_path {
                                if focus_tx
                                    .send(FocusEvent {
                                        event_type: FocusEventType::FocusLost,
                                        path: old_path.clone(),
                                        shadow_id: String::new(),
                                        app_bundle_id: info.application.clone(),
                                        app_name: info.application.clone(),
                                        window_title: ObfuscatedString::default(),
                                        timestamp: SystemTime::now(),
                                    })
                                    .await
                                    .is_err()
                                {
                                    log::warn!("Focus event channel closed, stopping poll");
                                    break;
                                }
                            }
                            if focus_tx
                                .send(FocusEvent {
                                    event_type: FocusEventType::FocusGained,
                                    path: info.path.clone().unwrap_or_default(),
                                    shadow_id: String::new(),
                                    app_bundle_id: info.application.clone(),
                                    app_name: info.application.clone(),
                                    window_title: info.title.clone(),
                                    timestamp: SystemTime::now(),
                                })
                                .await
                                .is_err()
                            {
                                log::warn!("Focus event channel closed, stopping poll");
                                break;
                            }
                            last_path = info.path.clone();
                        }
                    }
                }
            }
        });

        *self.poll_handle.lock_recover() = Some(handle);
        Ok(())
    }

    fn stop(&self) -> Result<()> {
        if !self.running.swap(false, Ordering::AcqRel) {
            return Ok(());
        }

        if let Some(handle) = self.poll_handle.lock_recover().take() {
            handle.abort();
        }

        Ok(())
    }

    fn active_window(&self) -> Option<WindowInfo> {
        self.provider.get_active_window()
    }

    fn available(&self) -> (bool, String) {
        (true, "Polling monitor available".to_string())
    }

    fn focus_events(&self) -> Result<mpsc::Receiver<FocusEvent>> {
        self.focus_rx
            .lock_recover()
            .take()
            .ok_or_else(|| SentinelError::Channel("focus receiver already consumed".to_string()))
    }

    fn change_events(&self) -> Result<mpsc::Receiver<ChangeEvent>> {
        self.change_rx
            .lock_recover()
            .take()
            .ok_or_else(|| SentinelError::Channel("change receiver already consumed".to_string()))
    }
}

impl<P: WindowProvider + ?Sized> Drop for PollingSentinelFocusTracker<P> {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(handle) = self.poll_handle.lock_recover().take() {
            handle.abort();
        }
    }
}
