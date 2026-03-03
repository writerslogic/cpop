// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::ffi::helpers::{get_data_dir, load_hmac_key, open_store};
use crate::ffi::types::{
    FfiActivityPoint, FfiDashboardMetrics, FfiLogEntry, FfiResult, FfiStatus, FfiTrackedFile,
};
use crate::DateTimeNanosExt;

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
        if let Err(e) = std::fs::write(&key_path, signing_key.to_bytes()) {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Failed to write signing key: {}", e)),
            };
        }
    }

    let db_path = data_dir.join("events.db");
    let hmac_key = match load_hmac_key() {
        Some(k) => k,
        None => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some("Failed to derive HMAC key".to_string()),
            };
        }
    };

    match crate::store::SecureStore::open(&db_path, hmac_key) {
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

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_status() -> FfiStatus {
    let data_dir = match get_data_dir() {
        Some(d) => d,
        None => {
            return FfiStatus {
                initialized: false,
                data_dir: String::new(),
                tracked_file_count: 0,
                total_checkpoints: 0,
                swf_iterations_per_second: 0,
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
            swf_iterations_per_second: 0,
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
                swf_iterations_per_second: 0,
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
        swf_iterations_per_second: crate::vdf::default_parameters().iterations_per_second,
        error_message: None,
    }
}

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
        // Wait, AuthorshipProfile has assessment: Assessment
        // I need a numerical score and a string risk level.

        // Let's use analyze_forensics for now as it gives a composite score
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

    let thirty_days_ago_ns =
        (chrono::Utc::now() - chrono::Duration::days(90)).timestamp_nanos_safe();
    let timestamps = store
        .get_all_event_timestamps(thirty_days_ago_ns)
        .unwrap_or_default();

    let mut active_days: std::collections::BTreeSet<i64> = std::collections::BTreeSet::new();
    for ts in &timestamps {
        let day = ts / (86400 * 1_000_000_000);
        active_days.insert(day);
    }

    let now_day = chrono::Utc::now().timestamp() / 86400;
    let active_days_30d = active_days.iter().filter(|d| **d >= now_day - 30).count() as u32;

    let today = now_day;
    let mut longest_streak: u32 = 0;
    let mut streak: u32 = 0;
    let mut prev_day: Option<i64> = None;

    for &day in active_days.iter().rev() {
        if let Some(prev) = prev_day {
            if prev - day == 1 {
                streak += 1;
            } else {
                longest_streak = longest_streak.max(streak);
                streak = 1;
            }
        } else {
            streak = 1;
        }
        prev_day = Some(day);
    }
    longest_streak = longest_streak.max(streak);

    let mut current_streak: u32 = 0;
    let mut check_day = today;
    while active_days.contains(&check_day) {
        current_streak += 1;
        check_day -= 1;
    }
    if current_streak == 0 {
        check_day = today - 1;
        while active_days.contains(&check_day) {
            current_streak += 1;
            check_day -= 1;
        }
    }

    FfiDashboardMetrics {
        success: true,
        total_files: files.len() as u32,
        total_checkpoints,
        total_words_witnessed,
        current_streak_days: current_streak,
        longest_streak_days: longest_streak,
        active_days_30d,
        error_message: None,
    }
}

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
