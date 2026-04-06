// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Engine session management: pause, resume, status, report, config update.

use super::{Engine, EngineStatus, ReportFile};
use crate::MutexRecover;
use anyhow::Result;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;

#[cfg(target_os = "macos")]
use crate::platform;

impl Engine {
    /// Stop the engine (alias for `pause`).
    pub fn stop(&self) -> Result<()> {
        self.pause()
    }

    /// Pause monitoring: stop file watcher and keystroke capture.
    pub fn pause(&self) -> Result<()> {
        self.inner.running.store(false, Ordering::SeqCst);
        // Drop the watcher first so the channel closes and the thread unblocks.
        *self.inner.watcher.lock_recover() = None;
        if let Some(handle) = self.inner.watcher_thread.lock_recover().take() {
            let _ = handle.join();
        }
        #[cfg(target_os = "macos")]
        {
            *self.inner.keystroke_monitor.lock_recover() = None;
        }

        let mut status = self.inner.status.lock_recover();
        status.running = false;
        Ok(())
    }

    /// Resume monitoring after a pause, restarting watchers and capture.
    pub fn resume(&self) -> Result<()> {
        if self.inner.running.load(Ordering::SeqCst) {
            return Ok(());
        }

        self.inner.running.store(true, Ordering::SeqCst);

        #[cfg(target_os = "macos")]
        {
            let monitor =
                platform::macos::KeystrokeMonitor::start(Arc::clone(&self.inner.jitter_session))?;
            *self.inner.keystroke_monitor.lock_recover() = Some(monitor);
        }

        let dirs = self.inner.watch_dirs.lock_recover().clone();
        super::start_file_watcher(&self.inner, dirs)?;

        let mut status = self.inner.status.lock_recover();
        status.running = true;
        Ok(())
    }

    /// Return a snapshot of the engine's current status.
    pub fn status(&self) -> EngineStatus {
        let mut status = self.inner.status.lock_recover().clone();
        status.jitter_samples = self.inner.jitter_session.lock_recover().samples.len() as u64;
        status
    }

    /// List all monitored files with their event counts and timestamps.
    pub fn report_files(&self) -> Result<Vec<ReportFile>> {
        let rows = self.inner.store.lock_recover().list_files()?;
        Ok(rows
            .into_iter()
            .map(|(file_path, last_ts, count)| ReportFile {
                file_path,
                last_event_timestamp_ns: last_ts,
                event_count: count.max(0) as u64,
            })
            .collect())
    }

    /// Return the engine's data directory path.
    pub fn data_dir(&self) -> PathBuf {
        self.inner.data_dir.clone()
    }

    /// Apply a new configuration, restarting watchers if currently running.
    pub fn update_config(&self, mut config: crate::config::CpopConfig) -> Result<()> {
        config.data_dir = self.inner.data_dir.clone();
        config.persist()?;

        *self.inner.watch_dirs.lock_recover() = config.watch_dirs.clone();
        let mut status = self.inner.status.lock_recover();
        status.watch_dirs = config.watch_dirs.clone();
        drop(status);

        if self.inner.running.load(Ordering::SeqCst) {
            self.pause()?;
            self.resume()?;
        }
        Ok(())
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.inner.running.store(false, Ordering::SeqCst);
        // Drop the watcher first so the channel closes and the thread unblocks.
        *self.inner.watcher.lock_recover() = None;
        if let Some(handle) = self.inner.watcher_thread.lock_recover().take() {
            let _ = handle.join();
        }
    }
}
