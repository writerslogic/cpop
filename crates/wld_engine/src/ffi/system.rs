// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::ffi::helpers::{compute_streak_stats, get_data_dir, load_hmac_key, open_store};
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
        if let Err(e) = std::fs::write(&key_path, signing_key.to_bytes()) {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Failed to write signing key: {}", e)),
            };
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) =
                std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
            {
                return FfiResult {
                    success: false,
                    message: None,
                    error_message: Some(format!("Failed to set key file permissions: {}", e)),
                };
            }
        }
    }

    let db_path = data_dir.join("events.db");
    let mut hmac_key = match load_hmac_key() {
        Some(k) => k,
        None => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some("Failed to derive HMAC key".to_string()),
            };
        }
    };

    match crate::store::SecureStore::open(&db_path, std::mem::take(&mut *hmac_key)) {
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
    let mut result = Vec::with_capacity(files.len());

    for (path, last_ts, count) in files {
        let events = store.get_events_for_file(&path).unwrap_or_default();
        let profile = crate::forensics::ForensicEngine::evaluate_authorship(&path, &events);

        let _score = profile.metrics.edit_entropy;

        let event_data = crate::ffi::helpers::events_to_forensic_data(&events);
        let regions = std::collections::HashMap::new();
        let metrics = crate::forensics::analyze_forensics(&event_data, &regions, None, None, None);

        result.push(FfiTrackedFile {
            path,
            last_checkpoint_ns: last_ts,
            checkpoint_count: count,
            forensic_score: metrics.assessment_score,
            risk_level: metrics.risk_level.to_string(),
        });
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

/// Get the identity recovery mnemonic phrase.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_identity_mnemonic() -> FfiResult {
    match crate::identity::secure_storage::SecureStorage::load_mnemonic() {
        Ok(Some(phrase)) => FfiResult {
            success: true,
            message: Some(phrase),
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
