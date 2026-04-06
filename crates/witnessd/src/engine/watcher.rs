// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! File watcher and event processing logic.

use super::{EngineInner, CONTENT_HASH_MAP_MAX_ENTRIES, RENAME_WINDOW_NS};
use crate::identity::SecureStorage;
use crate::store::SecureEvent;
use crate::utils::now_ns;
use crate::MutexRecover;
use anyhow::{anyhow, Result};
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use rand::RngCore;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{mpsc, Arc};
use std::time::Duration;

pub(super) fn start_file_watcher(inner: &Arc<EngineInner>, watch_dirs: Vec<PathBuf>) -> Result<()> {
    // Drop the old watcher first so the channel closes and the thread unblocks.
    *inner.watcher.lock_recover() = None;
    if let Some(handle) = inner.watcher_thread.lock_recover().take() {
        let _ = handle.join();
    }

    let (tx, rx) = mpsc::channel();
    let mut watcher: RecommendedWatcher = RecommendedWatcher::new(tx, notify::Config::default())?;

    for dir in &watch_dirs {
        if dir.exists() {
            watcher.watch(dir, RecursiveMode::Recursive)?;
        }
    }

    let inner_clone = Arc::clone(inner);
    let handle = std::thread::spawn(move || {
        while inner_clone.running.load(Ordering::SeqCst) {
            let event = match rx.recv_timeout(Duration::from_millis(500)) {
                Ok(event) => event,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            };

            if let Ok(event) = event {
                if matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                    for path in event.paths {
                        if let Err(err) = process_file_event(&inner_clone, &path) {
                            log::error!("file event error: {err}");
                        }
                    }
                }
            }
        }
    });

    *inner.watcher.lock_recover() = Some(watcher);
    *inner.watcher_thread.lock_recover() = Some(handle);
    Ok(())
}

/// If the file is inside a known project bundle (.scriv, .scrivx),
/// return the bundle path instead. Otherwise return the original path.
pub(super) fn resolve_project_path(path: &Path) -> PathBuf {
    let mut current = path.parent();
    while let Some(parent) = current {
        if let Some(ext) = parent.extension() {
            if ext == "scriv" || ext == "scrivx" {
                return parent.to_path_buf();
            }
        }
        current = parent.parent();
    }
    path.to_path_buf()
}

fn process_file_event(inner: &Arc<EngineInner>, path: &Path) -> Result<()> {
    if !path.is_file() {
        return Ok(());
    }

    // Capture the event timestamp before any I/O so it reflects when the OS event arrived.
    let event_timestamp_ns = now_ns();
    if event_timestamp_ns == 0 {
        log::error!(
            "now_ns() returned 0; skipping event recording to avoid corrupting the event chain"
        );
        return Ok(());
    }

    // Open once: get both hash and size from the same file handle to avoid TOCTOU.
    let (content_hash, file_size_u64) = crate::crypto::hash_file_with_size(path)?;
    let file_size = file_size_u64 as i64;

    // Group events under the project bundle path when inside .scriv/.scrivx
    let resolved_path = resolve_project_path(path);

    // Rename detection: if this content hash was recently seen at a different path
    // that no longer exists, treat it as a file rename.
    {
        let now = now_ns();

        // Extract candidate rename info under the lock, then drop lock before filesystem I/O.
        let rename_candidate = {
            let hash_map = inner.content_hash_map.lock_recover();
            if let Some((old_path, ts)) = hash_map.get(&content_hash) {
                let is_different_path = *old_path != resolved_path;
                let is_recent = (now - ts) < RENAME_WINDOW_NS;
                if is_different_path && is_recent {
                    Some(old_path.clone())
                } else {
                    None
                }
            } else {
                None
            }
        };

        if let Some(old_path) = rename_candidate {
            // Filesystem check outside the lock
            if !old_path.exists() {
                let old_str = old_path.to_string_lossy().to_string();
                let new_str = resolved_path.to_string_lossy().to_string();
                log::info!("File rename detected: {} -> {}", old_str, new_str);

                // Migrate stored events to the new path
                match inner
                    .store
                    .lock_recover()
                    .update_file_path(&old_str, &new_str)
                {
                    Ok(count) => log::info!("Updated {count} events from old path to new path"),
                    Err(e) => log::warn!("Could not migrate file path: {e}"),
                }

                // Copy file_sizes entry from old path to new path
                let mut sizes = inner.file_sizes.lock_recover();
                if let Some(&old_size) = sizes.get(&old_path) {
                    sizes.insert(resolved_path.clone(), old_size);
                    sizes.remove(&old_path);
                }
            }
        }

        // Re-acquire lock for hash map update
        let mut hash_map = inner.content_hash_map.lock_recover();

        // Record this hash → path mapping
        hash_map.insert(content_hash, (resolved_path.clone(), now));

        // Evict stale entries if the map is too large
        if hash_map.len() > CONTENT_HASH_MAP_MAX_ENTRIES {
            let cutoff = now - RENAME_WINDOW_NS;
            hash_map.retain(|_, (_, ts)| *ts >= cutoff);
        }
    }

    let size_delta = {
        let mut map = inner.file_sizes.lock_recover();
        // Use entry so a rename migration (which already inserted the new path with the old size)
        // is not overwritten here, preserving the correct previous size for delta computation.
        let previous = *map.entry(resolved_path.clone()).or_insert(file_size);
        map.insert(resolved_path.clone(), file_size);
        i32::try_from((file_size - previous).clamp(i32::MIN as i64, i32::MAX as i64)).unwrap_or(
            if file_size > previous {
                i32::MAX
            } else {
                i32::MIN
            },
        )
    };

    let (forensic_score, is_paste) = {
        let session = inner.jitter_session.lock_recover();
        if session.samples.is_empty() {
            // No keystrokes but file grew significantly → paste or dictation
            let is_paste = size_delta > 20;
            (1.0, is_paste)
        } else {
            let cadence = crate::forensics::analyze_cadence(&session.samples);
            let score = crate::forensics::compute_cadence_score(&cadence);

            let keystroke_count = session.samples.len() as i64;
            // Bytes-per-keystroke ratio: normal typing ≈ 1 byte/key, paste >> 3
            let avg_bytes_per_key = if keystroke_count > 0 {
                i64::from(size_delta).max(0) as f64 / keystroke_count as f64
            } else {
                0.0
            };
            let is_paste = (avg_bytes_per_key > 3.0 && size_delta > 20)
                || (i64::from(size_delta) > (keystroke_count * 5) && size_delta > 50);

            // Samples accumulate across the full session so every checkpoint
            // has enough data for meaningful cadence analysis. The session
            // is cleared on stop/start, not per-checkpoint.

            (score, is_paste)
        }
    };

    let mut event = SecureEvent::new(
        resolved_path.to_string_lossy().to_string(),
        content_hash,
        file_size,
        None,
    );
    event.device_id = inner.device_id;
    event.machine_id = inner.machine_id.clone();
    event.timestamp_ns = event_timestamp_ns;
    event.size_delta = size_delta;
    event.forensic_score = forensic_score;
    event.is_paste = is_paste;

    inner.store.lock_recover().add_secure_event(&mut event)?;

    let mut status = inner.status.lock_recover();
    status.events_written += 1;
    status.last_event_timestamp_ns = Some(event.timestamp_ns);
    Ok(())
}

pub(super) fn load_or_create_device_identity(data_dir: &Path) -> Result<([u8; 16], String)> {
    let path = data_dir.join("device.json");

    if let Ok(Some(identity)) = SecureStorage::load_device_identity() {
        return Ok(identity);
    }

    if path.exists() {
        let content = fs::read_to_string(&path)?;
        let value: serde_json::Value = serde_json::from_str(&content)?;
        let device_hex = value["device_id"].as_str().unwrap_or_default();
        let machine_id = value["machine_id"].as_str().unwrap_or_default().to_string();
        let decoded = hex::decode(device_hex)?;
        let device_id: [u8; 16] = decoded
            .try_into()
            .map_err(|_| crate::error::Error::validation("device_id must be exactly 16 bytes"))?;

        if let Err(e) = SecureStorage::save_device_identity(&device_id, &machine_id) {
            log::warn!("Failed to migrate device identity to secure storage: {e}");
        } else {
            let _ = fs::remove_file(&path);
        }

        return Ok((device_id, machine_id));
    }

    let mut device_id = [0u8; 16];
    rand::rng().fill_bytes(&mut device_id);
    let machine_id = sysinfo::System::host_name().unwrap_or_else(|| "unknown".to_string());

    if let Err(e) = SecureStorage::save_device_identity(&device_id, &machine_id) {
        log::warn!("Secure storage unavailable ({e}), using file-based storage");
        let payload = serde_json::json!({
            "device_id": hex::encode(device_id),
            "machine_id": machine_id,
        });
        fs::write(
            &path,
            serde_json::to_string_pretty(&payload).unwrap_or_else(|_| payload.to_string()),
        )?;
        if let Err(e) = crate::crypto::restrict_permissions(&path, 0o600) {
            log::warn!("Failed to set device identity permissions: {}", e);
        }
    }

    Ok((device_id, machine_id))
}

pub(super) fn load_or_create_hmac_key(data_dir: &Path) -> Result<Vec<u8>> {
    let path = data_dir.join("hmac.key");

    if let Ok(Some(key)) = SecureStorage::load_hmac_key() {
        return Ok(key.to_vec());
    }

    if path.exists() {
        let key = fs::read(&path)?;
        if key.len() == 32 {
            if let Err(e) = SecureStorage::save_hmac_key(&key) {
                log::warn!("Failed to migrate HMAC key to secure storage: {e}");
            } else {
                // Confirm the key actually persisted before removing the file copy.
                match SecureStorage::load_hmac_key() {
                    Ok(Some(_)) => {
                        let _ = fs::remove_file(&path);
                    }
                    _ => {
                        log::warn!(
                            "HMAC key save reported success but reload failed; keeping file copy"
                        );
                    }
                }
            }
            return Ok(key);
        }
        log::error!(
            "HMAC key file has wrong length ({} bytes, expected 32): {}",
            key.len(),
            path.display()
        );
        return Err(anyhow!(
            "HMAC key file has wrong length ({} bytes, expected 32)",
            key.len()
        ));
    }

    let mut key = vec![0u8; 32];
    rand::rng().fill_bytes(&mut key);

    if let Err(e) = SecureStorage::save_hmac_key(&key) {
        log::warn!("Secure storage unavailable ({e}), using file-based storage");
        fs::write(&path, &key)?;
        if let Err(e) = crate::crypto::restrict_permissions(&path, 0o600) {
            log::warn!("Failed to set HMAC key permissions: {}", e);
        }
    }

    Ok(key)
}
