// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::watcher::{load_or_create_device_identity, load_or_create_hmac_key};
use super::*;
use crate::utils::now_ns;
use std::collections::HashMap;
use std::path::Path;
use tempfile::TempDir;

#[test]
fn test_now_ns_returns_positive() {
    let ts = now_ns();
    assert!(
        ts > 0,
        "now_ns() should return a positive nanosecond timestamp, got {ts}"
    );
}

#[test]
fn test_now_ns_monotonic_across_calls() {
    let t1 = now_ns();
    let t2 = now_ns();
    assert!(t2 >= t1, "second call should be >= first: {t2} < {t1}");
}

#[test]
fn test_resolve_project_path_regular() {
    let path = Path::new("/home/user/documents/essay.docx");
    let resolved = watcher::resolve_project_path(path);
    assert_eq!(resolved, path.to_path_buf());
}

#[test]
fn test_resolve_project_path_scriv() {
    let path = Path::new("/home/user/Novel.scriv/Files/Draft/chapter1.rtf");
    let resolved = watcher::resolve_project_path(path);
    assert_eq!(resolved, Path::new("/home/user/Novel.scriv"));
}

#[test]
fn test_resolve_project_path_scrivx() {
    let path = Path::new("/home/user/Novel.scrivx/content/file.txt");
    let resolved = watcher::resolve_project_path(path);
    assert_eq!(resolved, Path::new("/home/user/Novel.scrivx"));
}

#[test]
fn test_resolve_project_path_nested_scriv() {
    let path = Path::new("/a/b/Project.scriv/c/d/e/deep.txt");
    let resolved = watcher::resolve_project_path(path);
    assert_eq!(resolved, Path::new("/a/b/Project.scriv"));
}

#[test]
fn test_resolve_project_path_no_extension() {
    let path = Path::new("/a/b/c/file.txt");
    let resolved = watcher::resolve_project_path(path);
    assert_eq!(resolved, path.to_path_buf());
}

#[test]
fn test_process_file_event_size_delta() {
    // Verify size delta computation logic by exercising the file_sizes map directly
    let mut file_sizes: HashMap<PathBuf, i64> = HashMap::new();
    let path = PathBuf::from("/test/file.txt");

    // First event: delta = 0 (previous defaults to current size)
    let file_size: i64 = 100;
    let previous = file_sizes
        .insert(path.clone(), file_size)
        .unwrap_or(file_size);
    let delta = (file_size - previous) as i32;
    assert_eq!(delta, 0, "first event should have zero delta");

    // Second event: file grew
    let file_size: i64 = 150;
    let previous = file_sizes
        .insert(path.clone(), file_size)
        .unwrap_or(file_size);
    let delta = (file_size - previous) as i32;
    assert_eq!(delta, 50, "delta should reflect growth");

    // Third event: file shrank
    let file_size: i64 = 120;
    let previous = file_sizes
        .insert(path.clone(), file_size)
        .unwrap_or(file_size);
    let delta = (file_size - previous) as i32;
    assert_eq!(delta, -30, "delta should reflect shrinkage");
}

#[test]
fn test_content_hash_map_eviction() {
    let mut hash_map: HashMap<[u8; 32], (PathBuf, i64)> = HashMap::new();
    let now = now_ns();

    // Insert entries older than the rename window
    let stale_ts = now - RENAME_WINDOW_NS - 1;
    for i in 0..10u8 {
        let mut key = [0u8; 32];
        key[0] = i;
        hash_map.insert(key, (PathBuf::from(format!("/old/{i}")), stale_ts));
    }

    // Insert a fresh entry
    let mut fresh_key = [0u8; 32];
    fresh_key[0] = 255;
    hash_map.insert(fresh_key, (PathBuf::from("/fresh"), now));

    assert_eq!(hash_map.len(), 11);

    // Simulate eviction logic from process_file_event
    if hash_map.len() > CONTENT_HASH_MAP_MAX_ENTRIES {
        let cutoff = now - RENAME_WINDOW_NS;
        hash_map.retain(|_, (_, ts)| *ts >= cutoff);
    }
    // Map is under the limit, so no eviction yet
    assert_eq!(hash_map.len(), 11);

    // Now fill beyond the limit and trigger eviction
    for i in 0..CONTENT_HASH_MAP_MAX_ENTRIES {
        let mut key = [0u8; 32];
        key[0..4].copy_from_slice(&(i as u32).to_be_bytes());
        hash_map.insert(key, (PathBuf::from(format!("/stale/{i}")), stale_ts));
    }
    assert!(hash_map.len() > CONTENT_HASH_MAP_MAX_ENTRIES);

    let cutoff = now - RENAME_WINDOW_NS;
    hash_map.retain(|_, (_, ts)| *ts >= cutoff);
    // Only the fresh entry should survive
    assert_eq!(hash_map.len(), 1);
    assert!(hash_map.contains_key(&fresh_key));
}

#[test]
fn test_load_or_create_device_identity() {
    let dir = TempDir::new().expect("create temp dir");
    let (device_id, machine_id) =
        load_or_create_device_identity(dir.path()).expect("create device identity");

    assert_ne!(
        device_id, [0u8; 16],
        "device_id should be random, not zeros"
    );
    assert!(!machine_id.is_empty(), "machine_id should not be empty");

    // Reload should return the same identity (via file fallback)
    let (device_id2, machine_id2) =
        load_or_create_device_identity(dir.path()).expect("reload device identity");
    assert_eq!(device_id, device_id2);
    assert_eq!(machine_id, machine_id2);
}

#[test]
fn test_load_or_create_hmac_key() {
    let dir = TempDir::new().expect("create temp dir");
    let key = load_or_create_hmac_key(dir.path()).expect("create HMAC key");

    assert_eq!(key.len(), 32, "HMAC key should be 32 bytes");
    assert_ne!(*key, vec![0u8; 32], "HMAC key should be random, not zeros");

    // Reload should return the same key (via file fallback)
    let key2 = load_or_create_hmac_key(dir.path()).expect("reload HMAC key");
    assert_eq!(key, key2);
}

#[test]
fn test_engine_start_creates_store() {
    let dir = TempDir::new().expect("create temp dir");
    let watch_dir = dir.path().join("watched");
    std::fs::create_dir_all(&watch_dir).expect("create watch dir");

    let data_dir = dir.path().join("data");
    std::env::set_var("CPOP_SKIP_PERMISSIONS", "1");

    let config = crate::config::CpopConfig {
        data_dir: data_dir.clone(),
        watch_dirs: vec![watch_dir],
        ..crate::config::CpopConfig::default()
    };

    let engine = Engine::start(config).expect("start engine");

    assert!(data_dir.exists(), "data directory should be created");
    assert!(
        data_dir.join("writerslogic.sqlite3").exists(),
        "SQLite store should be created"
    );

    drop(engine);
}

#[test]
fn test_engine_status_reflects_state() {
    let dir = TempDir::new().expect("create temp dir");
    let watch_dir = dir.path().join("watched");
    std::fs::create_dir_all(&watch_dir).expect("create watch dir");

    std::env::set_var("CPOP_SKIP_PERMISSIONS", "1");

    let config = crate::config::CpopConfig {
        data_dir: dir.path().join("data"),
        watch_dirs: vec![watch_dir.clone()],
        ..crate::config::CpopConfig::default()
    };

    let engine = Engine::start(config).expect("start engine");
    let status = engine.status();

    assert!(status.running);
    assert_eq!(status.events_written, 0);
    assert_eq!(status.jitter_samples, 0);
    assert!(status.last_event_timestamp_ns.is_none());
    assert_eq!(status.watch_dirs, vec![watch_dir]);

    drop(engine);
}

#[test]
fn test_engine_pause_resume() {
    let dir = TempDir::new().expect("create temp dir");
    let watch_dir = dir.path().join("watched");
    std::fs::create_dir_all(&watch_dir).expect("create watch dir");

    std::env::set_var("CPOP_SKIP_PERMISSIONS", "1");

    let config = crate::config::CpopConfig {
        data_dir: dir.path().join("data"),
        watch_dirs: vec![watch_dir],
        ..crate::config::CpopConfig::default()
    };

    let engine = Engine::start(config).expect("start engine");
    assert!(engine.status().running);

    engine.pause().expect("pause engine");
    assert!(!engine.status().running);

    engine.resume().expect("resume engine");
    assert!(engine.status().running);

    drop(engine);
}
