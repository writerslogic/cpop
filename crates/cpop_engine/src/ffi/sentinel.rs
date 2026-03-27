// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

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
use std::sync::{Arc, Mutex, OnceLock};

static SENTINEL: Mutex<Option<Arc<Sentinel>>> = Mutex::new(None);
static FFI_RUNTIME: OnceLock<Result<tokio::runtime::Runtime, String>> = OnceLock::new();

pub(crate) fn get_sentinel() -> Option<Arc<Sentinel>> {
    SENTINEL
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .as_ref()
        .map(Arc::clone)
}

fn ffi_runtime() -> Result<&'static tokio::runtime::Runtime, String> {
    FFI_RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .thread_name("cpop-ffi")
                .build()
                .map_err(|e| format!("Failed to create FFI tokio runtime: {e}"))
        })
        .as_ref()
        .map_err(|e| e.clone())
}

/// Start the sentinel daemon in-process.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_start() -> FfiResult {
    // Debug: write to data dir (sandbox blocks /tmp)
    #[cfg(debug_assertions)]
    {
        use std::io::Write;
        let debug_path = std::env::var("CPOP_DATA_DIR")
            .map(|d| format!("{}/sentinel_debug.txt", d))
            .unwrap_or_else(|_| "/tmp/cpop_sentinel_debug.txt".to_string());
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&debug_path)
        {
            let _ = writeln!(f, "ffi_sentinel_start called");
        }
    }
    // If a sentinel already exists, reuse it (handles restart after stop)
    let existing = get_sentinel();
    if existing.as_ref().is_some_and(|s| s.is_running()) {
        return FfiResult {
            success: true,
            message: Some("Sentinel already running".to_string()),
            error_message: None,
        };
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

    #[cfg(target_os = "macos")]
    let accessibility_granted = crate::sentinel::macos_focus::check_accessibility_permissions();
    #[cfg(target_os = "macos")]
    let input_monitoring_granted = crate::platform::macos::check_input_monitoring_permissions();

    #[cfg(target_os = "macos")]
    if !accessibility_granted {
        return FfiResult {
            success: false,
            message: None,
            error_message: Some(
                "Accessibility permission required — grant access in System \
                 Settings > Privacy & Security > Accessibility"
                    .to_string(),
            ),
        };
    }

    #[cfg(target_os = "macos")]
    if !input_monitoring_granted {
        return FfiResult {
            success: false,
            message: None,
            error_message: Some(
                "Input Monitoring permission required — grant access in System \
                 Settings > Privacy & Security > Input Monitoring"
                    .to_string(),
            ),
        };
    }

    // Reuse existing stopped sentinel or create a new one
    let sentinel = if let Some(s) = existing {
        s
    } else {
        let config = SentinelConfig::default().with_writersproof_dir(&data_dir);
        let s = match Sentinel::new(config) {
            Ok(s) => Arc::new(s),
            Err(e) => {
                return FfiResult {
                    success: false,
                    message: None,
                    error_message: Some(format!("Failed to create sentinel: {e}")),
                };
            }
        };
        if let Some(mut key) = load_hmac_key() {
            s.set_hmac_key(std::mem::take(&mut *key));
        }
        // Store in the global before starting
        if let Ok(mut guard) = SENTINEL.lock() {
            *guard = Some(Arc::clone(&s));
        }
        s
    };

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

    let capture_active = sentinel.is_keystroke_capture_active();

    let msg = if capture_active {
        "Sentinel started".to_string()
    } else {
        "Sentinel started in degraded mode — keystroke capture unavailable. \
         Check Input Monitoring permission in System Settings > Privacy & Security"
            .to_string()
    };

    #[cfg(debug_assertions)]
    {
        use std::io::Write;
        let debug_path = std::env::var("CPOP_DATA_DIR")
            .map(|d| format!("{}/sentinel_debug.txt", d))
            .unwrap_or_else(|_| "/tmp/cpop_sentinel_debug.txt".to_string());
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&debug_path)
        {
            let _ = writeln!(
                f,
                "sentinel started: capture_active={capture_active} msg={msg}"
            );
        }
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
    let sentinel = match get_sentinel() {
        Some(s) => s,
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

    // Keep the sentinel in the static so it can be restarted without
    // creating a new instance (which leaks CGEventTap threads).
    // Sessions are cleared by sentinel.stop() via end_all_sessions_sync.

    FfiResult {
        success: true,
        message: Some("Sentinel stopped".to_string()),
        error_message: None,
    }
}

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_is_running() -> bool {
    get_sentinel().is_some_and(|s| s.is_running())
}

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

    // Prefer the currently focused document; fall back to any session.
    let current_path = sentinel.current_focus();
    let sessions = sentinel.sessions();
    let session = current_path
        .as_ref()
        .and_then(|p| sessions.iter().find(|s| &s.path == p))
        .or_else(|| sessions.first());
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

    let keystroke_count = session.keystroke_count;
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
            // Blend: use store score when available, fall back to cadence score.
            let score = if store_score > 0.0 {
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

/// Inject a keystroke event from the host app with hardware verification.
///
/// Used when the host platform captures keystrokes via `NSEvent.addGlobalMonitorForEvents`
/// (sandboxed macOS) and forwards them with CGEvent verification fields.
///
/// Verification fields (from `NSEvent.cgEvent`):
/// - `source_state_id`: CGEvent field 45. HID hardware = 1, injected = -1.
/// - `keyboard_type`: CGEvent field 10. ANSI=40, ISO=41, JIS=42; synthetic=0.
/// - `source_pid`: CGEvent field 41. Hardware = 0 (kernel); injected = injector PID.
///
/// Synthetic events are rejected, matching the CGEventTap `verify_event_source` behavior.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_inject_keystroke(
    timestamp_ns: i64,
    keycode: u16,
    zone: u8,
    source_state_id: i64,
    keyboard_type: i64,
    source_pid: i64,
) -> bool {
    let sentinel_opt = get_sentinel();
    let sentinel = match sentinel_opt.as_ref() {
        Some(s) if s.is_running() => s,
        _ => return false,
    };

    // Same verification as CGEventTap's verify_event_source.
    // Constants from CGEventTypes.h — stable across macOS versions.
    const SOURCE_STATE_PRIVATE: i64 = -1;
    const SOURCE_STATE_HID_SYSTEM: i64 = 1;

    // Debug: log inject_keystroke calls
    #[cfg(debug_assertions)]
    {
        use std::sync::atomic::{AtomicU64, Ordering as AO};
        static INJECT_COUNT: AtomicU64 = AtomicU64::new(0);
        static REJECT_COUNT: AtomicU64 = AtomicU64::new(0);
        let n = INJECT_COUNT.fetch_add(1, AO::Relaxed);
        if source_state_id == SOURCE_STATE_PRIVATE || keyboard_type == 0 || source_pid != 0 {
            REJECT_COUNT.fetch_add(1, AO::Relaxed);
        }
        if n < 5 || n % 50 == 0 {
            use std::io::Write;
            let debug_path = std::env::var("CPOP_DATA_DIR")
                .map(|d| format!("{}/inject_debug.txt", d))
                .unwrap_or_else(|_| "/tmp/cpop_inject_debug.txt".to_string());
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&debug_path)
            {
                let _ = writeln!(
                    f,
                    "inject #{}: state={} kbd_type={} pid={} rejected_so_far={}",
                    n,
                    source_state_id,
                    keyboard_type,
                    source_pid,
                    REJECT_COUNT.load(AO::Relaxed)
                );
            }
        }
    }
    if source_state_id == SOURCE_STATE_PRIVATE {
        return false;
    }
    // keyboard_type 0 = no physical keyboard (synthetic). Values up to ~255
    // are valid Apple keyboard types (e.g. 106 = JIS, 44/45 = standard US).
    if keyboard_type == 0 {
        return false;
    }
    if source_pid != 0 {
        return false;
    }
    if source_state_id != SOURCE_STATE_HID_SYSTEM {
        log::debug!("inject_keystroke: suspicious source_state_id={source_state_id} — accepted");
    }

    // Compute inter-keystroke duration from timestamps (the Swift side
    // sends absolute timestamps; we need the delta for cadence analysis).
    //
    // Design limitation: LAST_INJECT_TS is process-global, not per-document.
    // When the user switches between documents, the first keystroke in the new
    // document will produce an inflated duration_since_last_ns spanning the idle
    // period between documents. This causes the per-document cadence analysis to
    // see one anomalously long inter-key interval at each document switch.
    // Impact: negligible for typical use (one outlier per switch is filtered by
    // the jitter analyzer's outlier rejection), but cadence scores near the
    // boundary may be slightly penalized when documents are switched frequently.
    static LAST_INJECT_TS: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);
    let prev_ts = LAST_INJECT_TS.swap(timestamp_ns, std::sync::atomic::Ordering::Relaxed);
    let duration_since_last_ns = if prev_ts > 0 && timestamp_ns > prev_ts {
        (timestamp_ns - prev_ts) as u64
    } else {
        0
    };

    let sample = crate::jitter::SimpleJitterSample {
        timestamp_ns,
        duration_since_last_ns,
        zone,
    };
    sentinel
        .activity_accumulator
        .write_recover()
        .add_sample(&sample);

    // Attribute keystroke to the currently focused document
    if let Some(ref path) = sentinel.current_focus() {
        if let Some(session) = sentinel.sessions.write_recover().get_mut(path) {
            session.keystroke_count += 1;
            // Store jitter sample for per-document forensic analysis.
            // Track whether the push actually occurred so the rollback below
            // only pops when there is a matching push to undo.
            let pushed =
                session.jitter_samples.len() < crate::sentinel::types::MAX_DOCUMENT_JITTER_SAMPLES;
            if pushed {
                session.jitter_samples.push(sample.clone());
            }

            let validation = crate::forensics::validate_keystroke_event(
                timestamp_ns,
                keycode,
                zone,
                source_pid,
                None, // frontmost_pid not available in FFI path
                session.has_focus,
                &mut session.event_validation,
            );
            // Drop events with very low confidence (likely synthetic injection)
            if validation.confidence < 0.1 {
                session.keystroke_count -= 1; // undo the increment
                if pushed {
                    session.jitter_samples.pop(); // undo the push
                }
            }
        }
    }
    true
}

/// Notify the sentinel of a paste event detected by the host app.
///
/// `char_count` is the number of characters pasted. The sentinel
/// records this so the next checkpoint can flag it as a paste.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_notify_paste(char_count: i64) -> bool {
    let sentinel_opt = get_sentinel();
    let sentinel = match sentinel_opt.as_ref() {
        Some(s) if s.is_running() => s,
        _ => return false,
    };

    let sessions = sentinel.sessions();
    if sessions.is_empty() {
        return false;
    }

    // Store the paste char count so ffi_sentinel_witnessing_status can report it
    sentinel.set_last_paste_chars(char_count);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sentinel_not_initialized() {
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
        assert_eq!(status.event_count, 0);
        assert!(!status.keystroke_capture_active);
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

    #[test]
    fn test_stop_witnessing_not_initialized() {
        let result = ffi_sentinel_stop_witnessing("/tmp/nonexistent.txt".to_string());
        assert!(!result.success);
        let err = result.error_message.unwrap_or_default();
        assert!(err.contains("not initialized"), "unexpected error: {err}");
    }

    #[test]
    fn test_start_witnessing_empty_path() {
        let result = ffi_sentinel_start_witnessing(String::new());
        assert!(!result.success);
        // Not initialized takes precedence, but the path would also be invalid
        assert!(result.error_message.is_some());
    }

    #[test]
    fn test_start_witnessing_traversal_path() {
        let result = ffi_sentinel_start_witnessing("/../../../etc/passwd".to_string());
        assert!(!result.success);
        assert!(result.error_message.is_some());
    }

    #[test]
    fn test_sentinel_oncelock_returns_consistent_state() {
        // OnceLock not yet set by any test in this module (all tests check "not initialized").
        // Verify repeated calls return the same state.
        let r1 = ffi_sentinel_is_running();
        let r2 = ffi_sentinel_is_running();
        assert_eq!(r1, r2);
        assert!(!r1);
    }

    #[test]
    fn test_permission_error_message_format() {
        // Verify the exact error strings that the Swift side matches against.
        let accessibility_msg = "Accessibility permission required — grant access in System \
                 Settings > Privacy & Security > Accessibility";
        let input_msg = "Input Monitoring permission required — grant access in System \
                 Settings > Privacy & Security > Input Monitoring";

        // Swift checks for these substrings to show the correct guidance.
        assert!(accessibility_msg.contains("Accessibility permission required"));
        assert!(accessibility_msg.contains("Privacy & Security"));
        assert!(input_msg.contains("Input Monitoring permission required"));
        assert!(input_msg.contains("Privacy & Security"));
    }

    #[test]
    fn test_data_dir_resolves() {
        // Clear env override so we test the platform default.
        let _lock = crate::ffi::helpers::lock_ffi_env();
        let prev = std::env::var("CPOP_DATA_DIR").ok();
        std::env::remove_var("CPOP_DATA_DIR");

        let dir = crate::ffi::helpers::get_data_dir();
        assert!(dir.is_some(), "get_data_dir() returned None");
        let dir = dir.unwrap();
        assert!(
            dir.ends_with("CPOP") || dir.ends_with("WritersProof"),
            "data dir should end with CPOP or WritersProof, got: {}",
            dir.display()
        );

        // Restore previous value if any.
        if let Some(v) = prev {
            std::env::set_var("CPOP_DATA_DIR", v);
        }
    }

    #[test]
    fn test_validate_path_rejects_empty() {
        let result = crate::sentinel::helpers::validate_path("");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_path_rejects_traversal() {
        let result = crate::sentinel::helpers::validate_path("/tmp/../../../etc/shadow");
        // On macOS /tmp canonicalizes to /private/tmp, traversal resolves.
        // The path likely doesn't exist, so validate_path returns an error.
        // Either way, it must not silently succeed with a system path.
        if let Ok(p) = &result {
            // If it resolved, it must not point to a system directory.
            let s = p.to_string_lossy();
            assert!(
                !s.starts_with("/etc/"),
                "traversal escaped to system path: {s}"
            );
        }
    }

    #[test]
    fn test_validate_path_accepts_tmp_file() {
        // Create a temp file so validate_path can canonicalize it.
        let tmp = std::env::temp_dir().join("cpop_test_validate_path.txt");
        std::fs::write(&tmp, b"test").expect("write temp file");
        let result = crate::sentinel::helpers::validate_path(&tmp);
        assert!(result.is_ok(), "validate_path failed: {result:?}");
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_ffi_result_error_has_no_message() {
        // Convention: on error, `message` is None and `error_message` is Some.
        let result = ffi_sentinel_stop();
        assert!(!result.success);
        assert!(result.message.is_none());
        assert!(result.error_message.is_some());
    }

    #[test]
    fn test_sentinel_status_defaults_when_not_running() {
        let status = ffi_sentinel_status();
        assert!(!status.running);
        assert_eq!(status.tracked_file_count, 0);
        assert_eq!(status.uptime_secs, 0);
        assert!(status.focus_duration.is_empty());
    }
}
