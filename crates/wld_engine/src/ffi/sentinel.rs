// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Sentinel FFI — in-process sentinel lifecycle for GUI apps.
//!
//! Eliminates the CLI dependency by running the sentinel directly via FFI.
//! Uses a global `OnceLock<Arc<Sentinel>>` matching the `ephemeral.rs` pattern
//! and a lazy Tokio runtime for async operations.

use crate::config::SentinelConfig;
use crate::ffi::helpers::{get_data_dir, load_hmac_key};
use crate::ffi::types::{FfiResult, FfiSentinelStatus, FfiWitnessingStatus};
use crate::sentinel::Sentinel;
use crate::RwLockRecover;
use std::sync::{Arc, OnceLock};

static SENTINEL: OnceLock<Arc<Sentinel>> = OnceLock::new();
static FFI_RUNTIME: OnceLock<Result<tokio::runtime::Runtime, String>> = OnceLock::new();

fn ffi_runtime() -> Result<&'static tokio::runtime::Runtime, String> {
    FFI_RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .thread_name("wld-ffi")
                .build()
                .map_err(|e| format!("Failed to create FFI tokio runtime: {e}"))
        })
        .as_ref()
        .map_err(|e| e.clone())
}

/// Start the sentinel daemon in-process.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_start() -> FfiResult {
    if let Some(s) = SENTINEL.get() {
        if s.is_running() {
            return FfiResult {
                success: true,
                message: Some("Sentinel already running".to_string()),
                error_message: None,
            };
        }
    }

    let data_dir = match get_data_dir() {
        Some(d) => d,
        None => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some("Cannot determine data directory".to_string()),
            };
        }
    };

    // Auto-create data directory if it doesn't exist (replaces `wld init` dependency)
    if !data_dir.exists() {
        if let Err(e) = std::fs::create_dir_all(&data_dir) {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!(
                    "Cannot create data directory {}: {e}",
                    data_dir.display()
                )),
            };
        }
    }

    // Pre-check accessibility permissions on macOS — the sentinel will start
    // without them but keystroke/mouse capture will be silently skipped.
    #[cfg(target_os = "macos")]
    let accessibility_granted = crate::sentinel::macos_focus::check_accessibility_permissions();

    let config = SentinelConfig::default().with_writerslogic_dir(&data_dir);

    let sentinel = match Sentinel::new(config) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            let msg = format!("{e}");
            // Surface accessibility hint if that's the likely cause
            #[cfg(target_os = "macos")]
            if !accessibility_granted && msg.contains("accessibility") {
                return FfiResult {
                    success: false,
                    message: None,
                    error_message: Some(
                        "Accessibility permission required — grant access in System Settings > \
                         Privacy & Security > Accessibility"
                            .to_string(),
                    ),
                };
            }
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Failed to create sentinel: {e}")),
            };
        }
    };

    // Load and set HMAC key for event signing
    if let Some(mut key) = load_hmac_key() {
        sentinel.set_hmac_key(std::mem::take(&mut *key));
    }

    let rt = match ffi_runtime() {
        Ok(rt) => rt,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(e),
            };
        }
    };
    let start_result = rt.block_on(async {
        tokio::time::timeout(std::time::Duration::from_secs(10), sentinel.start()).await
    });
    match start_result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Failed to start sentinel: {e}")),
            };
        }
        Err(_) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(
                    "Sentinel start timed out — check accessibility permissions".to_string(),
                ),
            };
        }
    }

    // Store globally — if another thread raced us, stop the loser's sentinel
    // to avoid leaking tokio tasks and file watchers.
    if let Err(leaked) = SENTINEL.set(sentinel) {
        if let Err(e) = rt.block_on(leaked.stop()) {
            log::warn!("Failed to stop duplicate sentinel: {}", e);
        }
    }

    // Build success message with capability warnings
    #[allow(unused_mut)]
    let mut msg = "Sentinel started".to_string();
    #[cfg(target_os = "macos")]
    if !accessibility_granted {
        msg = "Sentinel started without keystroke capture — grant Accessibility permission \
               in System Settings for full monitoring"
            .to_string();
    }

    FfiResult {
        success: true,
        message: Some(msg),
        error_message: None,
    }
}

/// Stop the sentinel daemon.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_stop() -> FfiResult {
    let sentinel = match SENTINEL.get() {
        Some(s) => Arc::clone(s),
        None => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some("Sentinel not initialized".to_string()),
            };
        }
    };

    if !sentinel.is_running() {
        return FfiResult {
            success: true,
            message: Some("Sentinel already stopped".to_string()),
            error_message: None,
        };
    }

    let rt = match ffi_runtime() {
        Ok(rt) => rt,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(e),
            };
        }
    };
    if let Err(e) = rt.block_on(sentinel.stop()) {
        return FfiResult {
            success: false,
            message: None,
            error_message: Some(format!("Failed to stop sentinel: {e}")),
        };
    }

    FfiResult {
        success: true,
        message: Some("Sentinel stopped".to_string()),
        error_message: None,
    }
}

/// Check if the sentinel is currently running.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_is_running() -> bool {
    SENTINEL.get().is_some_and(|s| s.is_running())
}

/// Start witnessing a specific file path.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_start_witnessing(path: String) -> FfiResult {
    let sentinel = match SENTINEL.get() {
        Some(s) => s,
        None => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(
                    "Sentinel not initialized — call ffi_sentinel_start() first".to_string(),
                ),
            };
        }
    };

    if !sentinel.is_running() {
        return FfiResult {
            success: false,
            message: None,
            error_message: Some("Sentinel not running".to_string()),
        };
    }

    match sentinel.start_witnessing(std::path::Path::new(&path)) {
        Ok(()) => FfiResult {
            success: true,
            message: Some(format!("Now witnessing: {path}")),
            error_message: None,
        },
        Err((_code, msg)) => FfiResult {
            success: false,
            message: None,
            error_message: Some(msg),
        },
    }
}

/// Stop witnessing a specific file path.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_stop_witnessing(path: String) -> FfiResult {
    let sentinel = match SENTINEL.get() {
        Some(s) => s,
        None => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some("Sentinel not initialized".to_string()),
            };
        }
    };

    match sentinel.stop_witnessing(std::path::Path::new(&path)) {
        Ok(()) => FfiResult {
            success: true,
            message: Some(format!("Stopped witnessing: {path}")),
            error_message: None,
        },
        Err((_code, msg)) => FfiResult {
            success: false,
            message: None,
            error_message: Some(msg),
        },
    }
}

/// Get current sentinel status.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_status() -> FfiSentinelStatus {
    let sentinel = match SENTINEL.get() {
        Some(s) => s,
        None => {
            return FfiSentinelStatus {
                running: false,
                tracked_file_count: 0,
                tracked_files: vec![],
                uptime_secs: 0,
                keystroke_count: 0,
                focus_duration: String::new(),
            };
        }
    };

    let tracked = sentinel.tracked_files();

    // Keystroke count from activity accumulator
    let summary = sentinel
        .activity_accumulator
        .read_recover()
        .to_session_summary();

    // Sum focus duration across all active sessions
    let total_focus_ms: i64 = sentinel
        .sessions()
        .iter()
        .map(|s| s.total_focus_duration().as_millis() as i64)
        .sum();
    let total_secs = total_focus_ms / 1000;
    let focus_duration = if total_secs >= 3600 {
        format!(
            "{}h {}m {}s",
            total_secs / 3600,
            (total_secs % 3600) / 60,
            total_secs % 60
        )
    } else if total_secs >= 60 {
        format!("{}m {}s", total_secs / 60, total_secs % 60)
    } else {
        format!("{}s", total_secs)
    };

    FfiSentinelStatus {
        running: sentinel.is_running(),
        tracked_file_count: tracked.len() as u32,
        tracked_files: tracked,
        uptime_secs: summary.duration_secs,
        keystroke_count: summary.keystroke_count,
        focus_duration,
    }
}

/// Get live witnessing metrics for the first active session.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_witnessing_status() -> FfiWitnessingStatus {
    let sentinel = match SENTINEL.get() {
        Some(s) => s,
        None => {
            return FfiWitnessingStatus {
                is_tracking: false,
                document_path: None,
                keystroke_count: 0,
                elapsed_secs: 0.0,
                change_count: 0,
                save_count: 0,
                checkpoint_count: 0,
                forensic_score: 0.0,
                error_message: None,
            };
        }
    };

    let sessions = sentinel.sessions();
    let session = match sessions.first() {
        Some(s) => s,
        None => {
            return FfiWitnessingStatus {
                is_tracking: false,
                document_path: None,
                keystroke_count: 0,
                elapsed_secs: 0.0,
                change_count: 0,
                save_count: 0,
                checkpoint_count: 0,
                forensic_score: 0.0,
                error_message: None,
            };
        }
    };

    let keystroke_count = sentinel
        .activity_accumulator
        .read_recover()
        .to_session_summary()
        .keystroke_count;

    let elapsed_secs = session
        .start_time
        .elapsed()
        .unwrap_or_default()
        .as_secs_f64();

    // Checkpoint count and forensic score from the store
    let (checkpoint_count, forensic_score) = match crate::ffi::helpers::open_store() {
        Ok(store) => {
            let events = store.get_events_for_file(&session.path).unwrap_or_default();
            let count = events.len() as u64;
            let score = if events.len() >= 2 {
                let profile =
                    crate::forensics::ForensicEngine::evaluate_authorship(&session.path, &events);
                profile.metrics.edit_entropy / crate::ffi::helpers::ENTROPY_NORMALIZATION_FACTOR
            } else {
                0.0
            };
            (count, score)
        }
        Err(_) => (0, 0.0),
    };

    FfiWitnessingStatus {
        is_tracking: true,
        document_path: Some(session.path.clone()),
        keystroke_count,
        elapsed_secs,
        change_count: session.change_count,
        save_count: session.save_count,
        checkpoint_count,
        forensic_score,
        error_message: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sentinel_not_initialized() {
        // Before any initialization, is_running should return false
        assert!(!ffi_sentinel_is_running());
    }

    #[test]
    fn test_sentinel_status_not_initialized() {
        let status = ffi_sentinel_status();
        assert!(!status.running);
        assert_eq!(status.tracked_file_count, 0);
        assert!(status.tracked_files.is_empty());
        assert_eq!(status.keystroke_count, 0);
    }

    #[test]
    fn test_sentinel_start_witnessing_not_initialized() {
        let result = ffi_sentinel_start_witnessing("/tmp/test.txt".to_string());
        assert!(!result.success);
        assert!(result
            .error_message
            .unwrap_or_default()
            .contains("not initialized"));
    }

    #[test]
    fn test_witnessing_status_not_initialized() {
        let status = ffi_sentinel_witnessing_status();
        assert!(!status.is_tracking);
        assert!(status.document_path.is_none());
        assert_eq!(status.keystroke_count, 0);
        assert_eq!(status.checkpoint_count, 0);
    }

    #[test]
    fn test_sentinel_stop_not_initialized() {
        let result = ffi_sentinel_stop();
        assert!(!result.success);
        assert!(result
            .error_message
            .unwrap_or_default()
            .contains("not initialized"));
    }
}
