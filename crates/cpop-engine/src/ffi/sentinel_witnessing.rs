// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! FFI functions for witnessing start/stop/status.

use super::sentinel::get_sentinel;
use crate::ffi::types::{FfiResult, FfiSentinelStatus, FfiWitnessingStatus};
use crate::RwLockRecover;

/// Start witnessing a specific file path.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_start_witnessing(path: String) -> FfiResult {
    let sentinel_opt = get_sentinel();
    let sentinel = match sentinel_opt.as_ref() {
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

    // AUD-084: Validate path to prevent traversal attacks
    let p = std::path::Path::new(&path);
    if path.contains("..") || !p.is_absolute() {
        return FfiResult {
            success: false,
            message: None,
            error_message: Some("Invalid path: must be absolute with no traversal".to_string()),
        };
    }

    match sentinel.start_witnessing(p) {
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
    let sentinel_opt = get_sentinel();
    let sentinel = match sentinel_opt.as_ref() {
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
    let sentinel_opt = get_sentinel();
    let sentinel = match sentinel_opt.as_ref() {
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

    let summary = sentinel
        .activity_accumulator
        .read_recover()
        .to_session_summary();

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
    let sentinel_opt = get_sentinel();
    let sentinel = match sentinel_opt.as_ref() {
        Some(s) => s,
        None => {
            return FfiWitnessingStatus {
                is_tracking: false,
                document_path: None,
                keystroke_count: 0,
                elapsed_secs: 0.0,
                change_count: 0,
                save_count: 0,
                event_count: 0,
                forensic_score: 0.0,
                last_paste_chars: 0,
                event_confidence: 1.0,
                keystroke_capture_active: false,
                error_message: None,
            };
        }
    };

    let capture_active = sentinel.is_keystroke_capture_active();

    // Show the most relevant session:
    // 1. The currently focused document (if it has a session)
    // 2. A manually-tracked document (started via UI, has app_bundle_id = "cli")
    // 3. Any active session as fallback
    let current_path = sentinel.current_focus();
    let sessions = sentinel.sessions();
    let session = current_path
        .as_ref()
        .and_then(|p| sessions.iter().find(|s| &s.path == p))
        .or_else(|| {
            // Prefer manually-tracked sessions over auto-witnessed ones
            sessions
                .iter()
                .find(|s| s.app_bundle_id == "cli")
                .or_else(|| sessions.first())
        });
    let session = match session {
        Some(s) => s,
        None => {
            return FfiWitnessingStatus {
                is_tracking: false,
                document_path: None,
                keystroke_count: 0,
                elapsed_secs: 0.0,
                change_count: 0,
                save_count: 0,
                event_count: 0,
                forensic_score: 0.0,
                last_paste_chars: 0,
                event_confidence: 1.0,
                keystroke_capture_active: capture_active,
                error_message: None,
            };
        }
    };

    let keystroke_count = session.total_keystrokes();
    #[cfg(debug_assertions)]
    let global_keystrokes = sentinel.keystroke_count();
    #[cfg(debug_assertions)]
    {
        use std::io::Write;
        let debug_path = std::env::var("CPOP_DATA_DIR")
            .map(|d| format!("{}/status_debug.txt", d))
            .unwrap_or_else(|_| "/tmp/cpop_status_debug.txt".to_string());
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&debug_path)
        {
            let _ = writeln!(
                f,
                "WITNESSING: doc={} doc_keystrokes={} global_keystrokes={} focus={:?}",
                session.path,
                keystroke_count,
                global_keystrokes,
                sentinel.current_focus()
            );
        }
    }

    let elapsed_secs = session
        .start_time
        .elapsed()
        .unwrap_or_default()
        .as_secs_f64();

    // Check for host-reported paste (from NSPasteboard monitoring).
    // take_last_paste_chars atomically reads and clears the value.
    let host_paste_chars = sentinel.take_last_paste_chars();

    // Per-document jitter cadence score (available before checkpoints exist).
    let doc_samples = sentinel.document_jitter_samples(&session.path);
    let cadence_score = if doc_samples.len() >= 20 {
        crate::forensics::compute_cadence_score(&crate::forensics::analyze_cadence(&doc_samples))
    } else {
        0.0
    };

    // Focus-switching penalties from per-document focus records.
    let focus = crate::forensics::analysis::analyze_focus_patterns(
        &session.focus_switches,
        session.total_focus_ms,
    );
    let focus_penalty = if focus.reading_pattern_detected {
        0.15
    } else if focus.ai_app_switch_count > 3 {
        0.10
    } else {
        0.0
    };

    let (event_count, forensic_score, store_paste_chars) = match crate::ffi::helpers::open_store() {
        Ok(store) => {
            let events = store.get_events_for_file(&session.path).unwrap_or_default();
            let count = events.len() as u64;
            let store_score = if events.len() >= 2 {
                let profile =
                    crate::forensics::ForensicEngine::evaluate_authorship(&session.path, &events);
                profile.metrics.edit_entropy / crate::ffi::helpers::ENTROPY_NORMALIZATION_FACTOR
            } else {
                0.0
            };
            // Clear priority: store score (if meaningful) > cadence score > 0.
            const MIN_MEANINGFUL_SCORE: f64 = 0.01;
            let score = if store_score >= MIN_MEANINGFUL_SCORE {
                (store_score - focus_penalty).clamp(0.0, 1.0)
            } else if cadence_score > 0.0 {
                (cadence_score - focus_penalty).clamp(0.0, 1.0)
            } else {
                0.0
            };
            let paste = events
                .last()
                .filter(|e| e.is_paste)
                .map(|e| e.size_delta as i64)
                .unwrap_or(0);
            (count, score, paste)
        }
        Err(_) => {
            // No store; use cadence score if available.
            let score = if cadence_score > 0.0 {
                (cadence_score - focus_penalty).clamp(0.0, 1.0)
            } else {
                0.0
            };
            (0, score, 0)
        }
    };

    // Prefer host-reported paste (real-time) over store-derived (checkpoint-time)
    let last_paste_chars = if host_paste_chars > 0 {
        host_paste_chars
    } else {
        store_paste_chars
    };

    FfiWitnessingStatus {
        is_tracking: true,
        document_path: Some(session.path.clone()),
        keystroke_count,
        elapsed_secs,
        change_count: u64::from(session.change_count),
        save_count: u64::from(session.save_count),
        event_count,
        forensic_score,
        last_paste_chars,
        event_confidence: session.average_event_confidence(),
        keystroke_capture_active: capture_active,
        error_message: None,
    }
}
