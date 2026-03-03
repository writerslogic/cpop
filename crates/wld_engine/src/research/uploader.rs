// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::collector::ResearchCollector;
use super::types::{UploadResult, DEFAULT_UPLOAD_INTERVAL_SECS};

pub struct ResearchUploader {
    collector: Arc<tokio::sync::Mutex<ResearchCollector>>,
    running: Arc<AtomicBool>,
    upload_interval: Duration,
}

impl ResearchUploader {
    pub fn new(collector: Arc<tokio::sync::Mutex<ResearchCollector>>) -> Self {
        Self {
            collector,
            running: Arc::new(AtomicBool::new(false)),
            upload_interval: Duration::from_secs(DEFAULT_UPLOAD_INTERVAL_SECS),
        }
    }

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
                                eprintln!(
                                    "[research] Uploaded {} sessions ({} samples)",
                                    result.sessions_uploaded, result.samples_uploaded
                                );
                            }
                        }
                        Err(e) => {
                            eprintln!("[research] Upload failed: {}", e);
                            let _ = guard.save();
                        }
                    }
                }
            }
        })
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    pub async fn upload_now(&self) -> Result<UploadResult, String> {
        let mut guard = self.collector.lock().await;
        guard.upload().await
    }
}
