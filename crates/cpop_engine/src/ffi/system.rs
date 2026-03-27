// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::ffi::helpers::{compute_streak_stats, get_data_dir, open_store};
use crate::ffi::types::{
    FfiActivityPoint, FfiDashboardMetrics, FfiLogEntry, FfiResult, FfiStatus, FfiTrackedFile,
};
use crate::DateTimeNanosExt;

/// Initialize the engine: create data directory, signing key, and event database.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_init() -> FfiResult {
    let data_dir = match get_data_dir() {
        Some(d) => d,
        None => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some("Failed to determine data directory".to_string()),
            };
        }
    };

    if let Err(e) = std::fs::create_dir_all(&data_dir) {
        return FfiResult {
            success: false,
            message: None,
            error_message: Some(format!("Failed to create data directory: {}", e)),
        };
    }

    // AUD-089/AUD-090: Atomic key file creation to prevent TOCTOU race
    // and world-readable window on crash
    let key_path = data_dir.join("signing_key");
    if !key_path.exists() {
        use ed25519_dalek::SigningKey;
        let mut seed = [0u8; 32];
        if let Err(e) = getrandom::getrandom(&mut seed) {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Failed to generate random seed: {}", e)),
            };
        }
        let signing_key = SigningKey::from_bytes(&seed);
        use zeroize::Zeroize;
        seed.zeroize();
        let key_bytes = zeroize::Zeroizing::new(signing_key.to_bytes());

        // Write to temp file first, restrict permissions, then atomic rename
        let tmp_path = key_path.with_extension("tmp");
        if let Err(e) = std::fs::write(&tmp_path, key_bytes.as_ref()) {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Failed to write signing key: {}", e)),
            };
        }
        if let Err(e) = crate::crypto::restrict_permissions(&tmp_path, 0o600) {
            let _ = std::fs::remove_file(&tmp_path);
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Failed to set key file permissions: {}", e)),
            };
        }
        if let Err(e) = std::fs::rename(&tmp_path, &key_path) {
            let _ = std::fs::remove_file(&tmp_path);
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Failed to finalize signing key: {}", e)),
            };
        }
    }

    let db_path = data_dir.join("events.db");
    match crate::ffi::helpers::open_store_at(&db_path) {
        Ok(_) => FfiResult {
            success: true,
            message: Some(format!("Initialized at {}", data_dir.display())),
            error_message: None,
        },
        Err(e) => FfiResult {
            success: false,
            message: None,
            error_message: Some(format!("Failed to initialize database: {}", e)),
        },
    }
}

/// Return the current engine status including tracked file count and SWF calibration.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_status() -> FfiStatus {
    // SWF calibration is independent of engine init — always report it.
    // Report 0 if not yet calibrated so the UI shows "Not calibrated".
    let swf_iters = crate::ffi::forensics::calibrated_params()
        .map(|p| p.iterations_per_second)
        .unwrap_or(0);

    let data_dir = match get_data_dir() {
        Some(d) => d,
        None => {
            return FfiStatus {
                initialized: false,
                data_dir: String::new(),
                tracked_file_count: 0,
                total_checkpoints: 0,
                swf_iterations_per_second: swf_iters,
                error_message: Some("Data directory not found".to_string()),
            };
        }
    };

    let initialized = data_dir.exists() && data_dir.join("events.db").exists();
    if !initialized {
        return FfiStatus {
            initialized: false,
            data_dir: data_dir.display().to_string(),
            tracked_file_count: 0,
            total_checkpoints: 0,
            swf_iterations_per_second: swf_iters,
            error_message: None,
        };
    }

    let store = match open_store() {
        Ok(s) => s,
        Err(e) => {
            return FfiStatus {
                initialized: true,
                data_dir: data_dir.display().to_string(),
                tracked_file_count: 0,
                total_checkpoints: 0,
                swf_iterations_per_second: swf_iters,
                error_message: Some(e),
            };
        }
    };

    let files = store.list_files().unwrap_or_default();
    let total_checkpoints: u64 = files.iter().map(|(_, _, count)| *count as u64).sum();

    FfiStatus {
        initialized: true,
        data_dir: data_dir.display().to_string(),
        tracked_file_count: files.len() as u32,
        total_checkpoints,
        swf_iterations_per_second: swf_iters,
        error_message: None,
    }
}

/// List all tracked files with their checkpoint counts and forensic scores.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_list_tracked_files() -> Vec<FfiTrackedFile> {
    let store = match open_store() {
        Ok(s) => s,
        Err(_) => return vec![],
    };

    let files = store.list_files().unwrap_or_default();
    let mut seen_paths = std::collections::HashSet::new();
    let mut result = Vec::with_capacity(files.len());

    // Get sentinel sessions for keystroke count enrichment
    let sentinel_opt = crate::ffi::sentinel::get_sentinel();
    let sentinel_sessions: Vec<_> = sentinel_opt
        .as_ref()
        .map(|s| s.sessions())
        .unwrap_or_default();

    for (path, last_ts, count) in files {
        seen_paths.insert(path.clone());
        let events = store.get_events_for_file(&path).unwrap_or_default();

        let event_data = crate::ffi::helpers::events_to_forensic_data(&events);
        let regions = std::collections::HashMap::new();
        let metrics = crate::forensics::analyze_forensics(&event_data, &regions, None, None, None);

        // Enrich with keystroke count from sentinel session
        let session_keystrokes = sentinel_sessions
            .iter()
            .find(|s| s.path == path)
            .map(|s| s.keystroke_count)
            .unwrap_or(0);

        // Apply keystroke-to-content penalty: if the document grew significantly
        // but has very few keystrokes, the content was likely injected/pasted.
        let total_content_added: i64 = events.iter().map(|e| e.size_delta.max(0) as i64).sum();
        let keystroke_ratio_penalty = if total_content_added > 50 && session_keystrokes < 10 {
            // Content was added but barely any keystrokes recorded
            let ratio = session_keystrokes as f64 / total_content_added as f64;
            // A human types ~1 byte per keystroke; ratio < 0.1 is suspicious
            if ratio < 0.1 {
                0.8 // Severe penalty
            } else if ratio < 0.3 {
                0.4
            } else {
                0.0
            }
        } else {
            0.0
        };

        let adjusted_score = (metrics.assessment_score - keystroke_ratio_penalty).clamp(0.0, 1.0);
        let adjusted_risk = if keystroke_ratio_penalty >= 0.4 {
            "HIGH".to_string()
        } else {
            metrics.risk_level.to_string()
        };

        result.push(FfiTrackedFile {
            path,
            last_checkpoint_ns: last_ts,
            checkpoint_count: count,
            forensic_score: adjusted_score,
            risk_level: adjusted_risk,
            keystroke_count: session_keystrokes as u64,
        });
    }

    // Include sentinel auto-detected sessions that don't yet have checkpoints
    if let Some(sentinel) = sentinel_opt.as_ref() {
        let all_sessions = sentinel.sessions();
        #[cfg(debug_assertions)]
        {
            use std::io::Write;
            let debug_path = std::env::var("CPOP_DATA_DIR")
                .map(|d| format!("{}/list_debug.txt", d))
                .unwrap_or_else(|_| "/tmp/cpop_list_debug.txt".to_string());
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&debug_path)
            {
                let _ = writeln!(
                    f,
                    "sentinel sessions: {} store files: {}",
                    all_sessions.len(),
                    result.len()
                );
                for s in &all_sessions {
                    let _ = writeln!(
                        f,
                        "  session: path={} keystrokes={} seen={}",
                        s.path,
                        s.keystroke_count,
                        seen_paths.contains(&s.path)
                    );
                }
            }
        }
        for session in all_sessions {
            if session.path.starts_with("shadow://") {
                continue; // Skip browser shadow sessions
            }
            if seen_paths.contains(&session.path) {
                continue; // Already in the store results
            }
            let elapsed_ns = session
                .start_time
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as i64)
                .unwrap_or(0);
            // Compute forensic score from per-document jitter samples.
            let doc_samples = sentinel.document_jitter_samples(&session.path);
            let cadence_score = if doc_samples.len() >= 20 {
                crate::forensics::compute_cadence_score(&crate::forensics::analyze_cadence(
                    &doc_samples,
                ))
            } else {
                0.0
            };

            // Apply focus-switching penalties.
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
            let forensic_score = (cadence_score - focus_penalty).clamp(0.0, 1.0);

            result.push(FfiTrackedFile {
                path: session.path.clone(),
                last_checkpoint_ns: elapsed_ns,
                checkpoint_count: 0,
                forensic_score,
                risk_level: "pending".to_string(),
                keystroke_count: session.keystroke_count,
            });
        }
    }

    result
}

/// Return the checkpoint event log for a specific tracked file.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_log(path: String) -> Vec<FfiLogEntry> {
    let path = match crate::sentinel::helpers::validate_path(&path) {
        Ok(p) => p.to_string_lossy().to_string(),
        Err(_) => return vec![],
    };

    let store = match open_store() {
        Ok(s) => s,
        Err(_) => return vec![],
    };

    store
        .get_events_for_file(&path)
        .unwrap_or_default()
        .into_iter()
        .enumerate()
        .map(|(i, ev)| FfiLogEntry {
            ordinal: i as u64,
            timestamp_ns: ev.timestamp_ns,
            content_hash: hex::encode(ev.content_hash),
            file_size: ev.file_size,
            size_delta: ev.size_delta,
            message: ev.context_note,
        })
        .collect()
}

/// Compute aggregate dashboard metrics: files, checkpoints, streaks, activity.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_dashboard_metrics() -> FfiDashboardMetrics {
    let store = match open_store() {
        Ok(s) => s,
        Err(e) => {
            return FfiDashboardMetrics {
                success: false,
                total_files: 0,
                total_checkpoints: 0,
                total_words_witnessed: 0,
                current_streak_days: 0,
                longest_streak_days: 0,
                active_days_30d: 0,
                error_message: Some(e),
            };
        }
    };

    let files = store.list_files().unwrap_or_default();
    let total_checkpoints: u64 = files.iter().map(|(_, _, c)| *c as u64).sum();

    let summary = store.get_all_events_summary().unwrap_or_default();
    let total_chars_added: u64 = summary
        .iter()
        .map(|(_, delta)| (*delta).max(0) as u64)
        .sum();
    let total_words_witnessed = total_chars_added / 5;

    let ninety_days_ago_ns =
        (chrono::Utc::now() - chrono::Duration::days(90)).timestamp_nanos_safe();
    let timestamps = store
        .get_all_event_timestamps(ninety_days_ago_ns)
        .unwrap_or_default();

    let today_day = chrono::Utc::now().timestamp() / 86400;
    let streaks = compute_streak_stats(&timestamps, today_day, 30);

    FfiDashboardMetrics {
        success: true,
        total_files: files.len() as u32,
        total_checkpoints,
        total_words_witnessed,
        current_streak_days: streaks.current_streak_days,
        longest_streak_days: streaks.longest_streak_days,
        active_days_30d: streaks.active_days_in_window,
        error_message: None,
    }
}

/// Return per-day checkpoint counts for the last N days (activity heatmap data).
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_activity_data(days: u32) -> Vec<FfiActivityPoint> {
    let store = match open_store() {
        Ok(s) => s,
        Err(_) => return vec![],
    };

    let start_ns =
        (chrono::Utc::now() - chrono::Duration::days(days as i64)).timestamp_nanos_safe();

    let timestamps = store.get_all_event_timestamps(start_ns).unwrap_or_default();

    let mut day_counts: std::collections::BTreeMap<i64, u32> = std::collections::BTreeMap::new();
    for ts in timestamps {
        let day_start = (ts / (86400 * 1_000_000_000)) * 86400;
        *day_counts.entry(day_start).or_insert(0) += 1;
    }

    day_counts
        .into_iter()
        .map(|(day_timestamp, checkpoint_count)| FfiActivityPoint {
            day_timestamp,
            checkpoint_count,
        })
        .collect()
}

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_identity_mnemonic() -> FfiResult {
    match crate::identity::secure_storage::SecureStorage::load_mnemonic() {
        Ok(Some(phrase)) => FfiResult {
            success: true,
            message: Some((*phrase).clone()),
            error_message: None,
        },
        Ok(None) => FfiResult {
            success: false,
            message: None,
            error_message: Some("No identity mnemonic found".to_string()),
        },
        Err(e) => FfiResult {
            success: false,
            message: None,
            error_message: Some(format!("Failed to load mnemonic: {e}")),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::evidence::ffi_create_checkpoint;
    use tempfile::TempDir;

    /// Point CPOP_DATA_DIR at a fresh temp directory and return the TempDir guard.
    fn setup_temp_data_dir() -> TempDir {
        let dir = TempDir::new().expect("create temp dir");
        std::env::set_var("CPOP_DATA_DIR", dir.path());
        dir
    }

    // ── ffi_init ────────────────────────────────────────────────────────

    #[test]
    fn init_creates_signing_key_and_db() {
        let _lock = crate::ffi::helpers::lock_ffi_env();
        let dir = setup_temp_data_dir();

        let result = ffi_init();
        assert!(
            result.success,
            "ffi_init failed: {:?}",
            result.error_message
        );

        assert!(
            dir.path().join("signing_key").exists(),
            "signing_key not created"
        );
        assert!(
            dir.path().join("events.db").exists(),
            "events.db not created"
        );
    }

    #[test]
    fn init_is_idempotent() {
        let _lock = crate::ffi::helpers::lock_ffi_env();
        let _dir = setup_temp_data_dir();

        let first = ffi_init();
        assert!(
            first.success,
            "first init failed: {:?}",
            first.error_message
        );

        let second = ffi_init();
        assert!(
            second.success,
            "second init failed: {:?}",
            second.error_message
        );
    }

    #[test]
    fn init_signing_key_has_correct_length() {
        let _lock = crate::ffi::helpers::lock_ffi_env();
        let dir = setup_temp_data_dir();

        let result = ffi_init();
        assert!(result.success);

        let key_data = std::fs::read(dir.path().join("signing_key")).expect("read key");
        assert_eq!(key_data.len(), 32, "Ed25519 seed should be 32 bytes");
    }

    // ── ffi_get_status ──────────────────────────────────────────────────

    #[test]
    fn status_before_init_shows_not_initialized() {
        let _lock = crate::ffi::helpers::lock_ffi_env();
        let _dir = setup_temp_data_dir();
        // No ffi_init() — data dir exists but is empty.

        let status = ffi_get_status();
        assert!(!status.initialized);
        assert_eq!(status.tracked_file_count, 0);
        assert_eq!(status.total_checkpoints, 0);
    }

    #[test]
    fn status_after_init_shows_initialized() {
        let _lock = crate::ffi::helpers::lock_ffi_env();
        let dir = setup_temp_data_dir();

        let init = ffi_init();
        assert!(init.success, "init failed: {:?}", init.error_message);

        let status = ffi_get_status();
        assert!(status.initialized);
        assert_eq!(
            status.data_dir,
            dir.path().display().to_string(),
            "data_dir should match temp path"
        );
        assert_eq!(status.tracked_file_count, 0);
        assert_eq!(status.total_checkpoints, 0);
        assert!(status.error_message.is_none());
    }

    // ── ffi_create_checkpoint ───────────────────────────────────────────

    #[test]
    fn create_checkpoint_for_temp_file() {
        let _lock = crate::ffi::helpers::lock_ffi_env();
        let dir = setup_temp_data_dir();

        let init = ffi_init();
        assert!(init.success, "init failed: {:?}", init.error_message);

        // Create a file to checkpoint.
        let file_path = dir.path().join("test_document.txt");
        std::fs::write(&file_path, "Hello, CPOP!").expect("write test file");

        let result = ffi_create_checkpoint(
            file_path.to_string_lossy().to_string(),
            "test checkpoint".to_string(),
        );
        assert!(
            result.success,
            "checkpoint failed: {:?}",
            result.error_message
        );
        assert!(result.message.is_some());

        // Status should now reflect the tracked file.
        let status = ffi_get_status();
        assert_eq!(status.tracked_file_count, 1);
        assert_eq!(status.total_checkpoints, 1);
    }

    #[test]
    fn create_checkpoint_missing_file_fails() {
        let _lock = crate::ffi::helpers::lock_ffi_env();
        let dir = setup_temp_data_dir();

        let init = ffi_init();
        assert!(init.success);

        let bogus = dir.path().join("nonexistent.txt");
        let result = ffi_create_checkpoint(bogus.to_string_lossy().to_string(), String::new());
        assert!(!result.success);
        assert!(result.error_message.is_some());
    }

    #[test]
    fn create_checkpoint_with_tool_declaration() {
        let _lock = crate::ffi::helpers::lock_ffi_env();
        let dir = setup_temp_data_dir();

        let init = ffi_init();
        assert!(init.success, "init failed: {:?}", init.error_message);

        let file_path = dir.path().join("ai_assisted.txt");
        std::fs::write(&file_path, "Some content with AI assistance").expect("write test file");

        let result = ffi_create_checkpoint(
            file_path.to_string_lossy().to_string(),
            "[tool:ai:ChatGPT]".to_string(),
        );
        assert!(
            result.success,
            "checkpoint with tool declaration failed: {:?}",
            result.error_message
        );
    }

    #[test]
    fn create_multiple_checkpoints_increments_count() {
        let _lock = crate::ffi::helpers::lock_ffi_env();
        let dir = setup_temp_data_dir();

        let init = ffi_init();
        assert!(init.success);

        let file_path = dir.path().join("multi.txt");
        std::fs::write(&file_path, "version 1").expect("write v1");
        let path_str = file_path.to_string_lossy().to_string();

        let r1 = ffi_create_checkpoint(path_str.clone(), "v1".to_string());
        assert!(r1.success, "cp1 failed: {:?}", r1.error_message);

        std::fs::write(&file_path, "version 2 with more content").expect("write v2");
        let r2 = ffi_create_checkpoint(path_str, "v2".to_string());
        assert!(r2.success, "cp2 failed: {:?}", r2.error_message);

        let status = ffi_get_status();
        assert_eq!(status.tracked_file_count, 1);
        assert_eq!(status.total_checkpoints, 2);
    }
}
