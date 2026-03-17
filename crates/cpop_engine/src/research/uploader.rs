// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::collector::ResearchCollector;
use super::types::{UploadResult, DEFAULT_UPLOAD_INTERVAL_SECS};

/// Background task that periodically uploads buffered research sessions.
pub struct ResearchUploader {
    collector: Arc<tokio::sync::Mutex<ResearchCollector>>,
    running: Arc<AtomicBool>,
    upload_interval: Duration,
}

impl ResearchUploader {
    /// Create an uploader with the default upload interval.
    pub fn new(collector: Arc<tokio::sync::Mutex<ResearchCollector>>) -> Self {
        Self {
            collector,
            running: Arc::new(AtomicBool::new(false)),
            upload_interval: Duration::from_secs(DEFAULT_UPLOAD_INTERVAL_SECS),
        }
    }

    /// Create an uploader with a custom upload interval.
    pub fn with_interval(
        collector: Arc<tokio::sync::Mutex<ResearchCollector>>,
        interval: Duration,
    ) -> Self {
        Self {
            collector,
            running: Arc::new(AtomicBool::new(false)),
            upload_interval: interval,
        }
    }

    /// Spawn the periodic upload loop as a Tokio task.
    pub fn start(&self) -> tokio::task::JoinHandle<()> {
        let collector = Arc::clone(&self.collector);
        let running = Arc::clone(&self.running);
        let interval = self.upload_interval;

        running.store(true, Ordering::SeqCst);

        tokio::spawn(async move {
            while running.load(Ordering::SeqCst) {
                tokio::time::sleep(interval).await;

                if !running.load(Ordering::SeqCst) {
                    break;
                }

                let mut guard = collector.lock().await;
                if guard.should_upload() {
                    match guard.upload().await {
                        Ok(result) => {
                            if result.sessions_uploaded > 0 {
                                log::info!(
                                    "[research] Uploaded {} sessions ({} samples)",
                                    result.sessions_uploaded,
                                    result.samples_uploaded
                                );
                            }
                        }
                        Err(e) => {
                            log::error!("[research] Upload failed: {}", e);
                            let _ = guard.save();
                        }
                    }
                }
            }
        })
    }

    /// Signal the background upload loop to stop.
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Return `true` if the background upload loop is active.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Trigger an immediate upload outside the periodic schedule.
    pub async fn upload_now(&self) -> Result<UploadResult, String> {
        let mut guard = self.collector.lock().await;
        guard.upload().await
    }
}
