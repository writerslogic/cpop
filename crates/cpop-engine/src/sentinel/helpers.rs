// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::shadow::ShadowManager;
use super::types::*;
use crate::config::SentinelConfig;
use crate::wal::{EntryType, Wal};

use crate::RwLockRecover;
use ed25519_dalek::SigningKey;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;

// Synchronous event handlers — avoids Send issues with RwLock guards across .await
#[allow(clippy::too_many_arguments)]
pub fn handle_focus_event_sync(
    event: FocusEvent,
    sessions: &Arc<RwLock<HashMap<String, DocumentSession>>>,
    config: &SentinelConfig,
    shadow: &Arc<ShadowManager>,
    signing_key: &Arc<RwLock<Option<SigningKey>>>,
    current_focus: &Arc<RwLock<Option<String>>>,
    wal_dir: &Path,
    session_events_tx: &broadcast::Sender<SessionEvent>,
) {
    #[cfg(debug_assertions)]
    {
        use std::io::Write;
        if let Ok(d) = std::env::var("CPOP_DATA_DIR") {
            let debug_path = format!("{}/event_debug.txt", d);
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&debug_path)
            {
                let _ = writeln!(
                    f,
                    "HANDLE_FOCUS: type={:?} bundle={} path={:?} shadow={}",
                    event.event_type, event.app_bundle_id, event.path, event.shadow_id
                );
            }
        }
    }

    super::trace!(
        "[FOCUS] type={:?} bundle={} path={:?} app={}",
        event.event_type,
        event.app_bundle_id,
        event.path,
        event.app_name
    );

    if !config.is_app_allowed(&event.app_bundle_id, &event.app_name) {
        super::trace!(
            "[FOCUS] BLOCKED app={} bundle={}",
            event.app_name,
            event.app_bundle_id
        );
        let path_to_unfocus = {
            let focus = current_focus.read_recover();
            focus.clone()
        };
        if let Some(path) = path_to_unfocus {
            super::trace!("[FOCUS] unfocusing {:?} due to blocked app", path);
            unfocus_document_sync(&path, sessions, session_events_tx);
            *current_focus.write_recover() = None;
        }
        return;
    }

    match event.event_type {
        FocusEventType::FocusGained => {
            let doc_path = if event.path.is_empty() {
                if !event.shadow_id.is_empty() {
                    super::trace!("[FOCUS] using shadow://{}", event.shadow_id);
                    format!("shadow://{}", event.shadow_id)
                } else {
                    let fallback = { current_focus.read_recover().clone() };
                    if let Some(path) = fallback {
                        super::trace!("[FOCUS] empty path, fallback to {:?}", path);
                        if let Some(session) = sessions.write_recover().get_mut(path.as_str()) {
                            session.focus_gained();
                        }
                        return;
                    }
                    super::trace!("[FOCUS] empty path, no fallback, dropping");
                    return;
                }
            } else {
                event.path.clone()
            };

            super::trace!("[FOCUS] doc_path={:?}", doc_path);

            let path_to_unfocus = {
                let focus = current_focus.read_recover();
                if let Some(ref current) = *focus {
                    if *current != doc_path {
                        Some(current.clone())
                    } else {
                        None
                    }
                } else {
                    None
                }
            };

            // Single write lock for the entire unfocus + regained_at stamp
            // to prevent TOCTOU races between lock acquisitions.
            {
                let mut sessions_map = sessions.write_recover();

                // Record focus switch and unfocus the previous document.
                if let Some(ref path) = path_to_unfocus {
                    if let Some(session) = sessions_map.get_mut(path.as_str()) {
                        session.focus_switches.push(FocusSwitchRecord {
                            lost_at: SystemTime::now(),
                            regained_at: None,
                            target_app: event.app_name.clone(),
                            target_bundle_id: event.app_bundle_id.clone(),
                        });
                        session.focus_lost();
                        let _ = session_events_tx.send(SessionEvent {
                            event_type: SessionEventType::Unfocused,
                            session_id: session.session_id.clone(),
                            document_path: path.to_string(),
                            timestamp: SystemTime::now(),
                        });
                    }
                }

                // If this document is regaining focus, stamp regained_at on its
                // most recent open switch record.
                if let Some(session) = sessions_map.get_mut(doc_path.as_str()) {
                    if let Some(last) = session.focus_switches.last_mut() {
                        if last.regained_at.is_none() {
                            last.regained_at = Some(SystemTime::now());
                        }
                    }
                }
            }

            if path_to_unfocus.is_some() {
                *current_focus.write_recover() = None;
            }

            focus_document_sync(
                &doc_path,
                &event,
                sessions,
                config,
                shadow,
                signing_key,
                wal_dir,
                session_events_tx,
            );
            super::trace!("[FOCUS] set current_focus={:?}", doc_path);
            *current_focus.write_recover() = Some(doc_path);
        }
        FocusEventType::FocusLost | FocusEventType::FocusUnknown => {
            let prev_path = {
                let focus = current_focus.read_recover();
                focus.clone()
            };
            super::trace!(
                "[FOCUS] FocusLost, clearing current_focus (was {:?})",
                prev_path
            );
            if let Some(path) = prev_path {
                unfocus_document_sync(&path, sessions, session_events_tx);
                *current_focus.write_recover() = None;
            }
        }
    }
}

/// Maximum file size (10 MB) for initial hash computation during focus tracking.
/// Files larger than this are skipped to avoid blocking the sessions write lock.
const MAX_HASH_FILE_SIZE: u64 = 10 * 1024 * 1024;

/// File extensions that should never be tracked as authored documents.
const NON_DOCUMENT_EXTENSIONS: &[&str] = &[
    "mov", "mp4", "avi", "mkv", "webm", // video
    "mp3", "wav", "aac", "flac", "ogg", // audio
    "dmg", "iso", "img", "pkg", // disk images
    "zip", "tar", "gz", "bz2", "xz", "7z", "rar", // archives
    "app", "exe", "dll", "dylib", "so", // binaries
    "o", "a", "lib", // object files
];

#[allow(clippy::too_many_arguments)]
pub fn focus_document_sync(
    path: &str,
    event: &FocusEvent,
    sessions: &Arc<RwLock<HashMap<String, DocumentSession>>>,
    _config: &SentinelConfig,
    _shadow: &Arc<ShadowManager>,
    signing_key: &Arc<RwLock<Option<SigningKey>>>,
    wal_dir: &Path,
    session_events_tx: &broadcast::Sender<SessionEvent>,
) {
    // Skip directories and paths that don't look like documents.
    // Virtual keys (shadow://, title://) bypass filesystem checks.
    if !path.starts_with("shadow://") {
        let p = std::path::Path::new(path);
        if p.is_dir() {
            return;
        }
        // Block known non-document extensions (media, archives, binaries).
        // Files without extensions are allowed through; many legitimate
        // documents (README, Makefile, cloud app exports) have no extension.
        if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
            if NON_DOCUMENT_EXTENSIONS.contains(&ext.to_lowercase().as_str()) {
                return;
            }
        }
    }

    // Compute file hash BEFORE acquiring write lock to avoid blocking FFI.
    // Open once, check size from the handle to avoid TOCTOU race.
    let pre_hash = {
        match std::fs::File::open(path) {
            Ok(file) => match file.metadata() {
                Ok(meta) if meta.len() <= MAX_HASH_FILE_SIZE => {
                    crate::crypto::hash_file_handle(file)
                        .ok()
                        .map(|(hash, _)| hex::encode(hash))
                }
                _ => None,
            },
            Err(_) => None,
        }
    };
    let key = signing_key.read_recover().clone();

    let new_session_info = {
        let mut sessions_map = sessions.write_recover();
        let was_new = !sessions_map.contains_key(path);

        let session = sessions_map.entry(path.to_string()).or_insert_with(|| {
            let mut session = DocumentSession::new(
                path.to_string(),
                event.app_bundle_id.clone(),
                event.app_name.clone(),
                event.window_title.clone(),
            );

            if let Some(ref hash) = pre_hash {
                session.initial_hash = Some(hash.clone());
                session.current_hash = Some(hash.clone());
            }

            // Load cumulative stats so total_keystrokes() returns lifetime count.
            // Use the already-cloned `key` to avoid re-acquiring signing_key
            // lock while sessions write lock is held (AUD-041 lock ordering).
            let db_path = wal_dir.parent().unwrap_or(wal_dir).join("events.db");
            if let Some(ref sk) = key {
                if let Ok(store) = crate::store::open_store_with_signing_key(sk, &db_path) {
                    if let Ok(Some(stats)) = store.load_document_stats(path) {
                        session.cumulative_keystrokes_base =
                            u64::try_from(stats.total_keystrokes).unwrap_or(0);
                        session.cumulative_focus_ms_base = stats.total_focus_ms;
                        session.session_number = u32::try_from(stats.session_count).unwrap_or(0);
                    }
                }
            }

            session
        });

        session.focus_gained();
        session.window_title = event.window_title.clone();

        if was_new {
            Some((
                session.session_id.clone(),
                create_session_start_payload(session),
            ))
        } else {
            None
        }
    }; // write lock released here

    // WAL append and event broadcast happen outside the lock
    if let Some((session_id, payload)) = new_session_info {
        wal_append_session_event(&session_id, wal_dir, key, EntryType::SessionStart, payload);

        // Intentionally ignored: broadcast send fails only when no receivers are subscribed
        let _ = session_events_tx.send(SessionEvent {
            event_type: SessionEventType::Started,
            session_id: session_id.clone(),
            document_path: path.to_string(),
            timestamp: SystemTime::now(),
        });
    }

    #[cfg(debug_assertions)]
    let focus_count = sessions
        .read_recover()
        .get(path)
        .map(|s| s.focus_count)
        .unwrap_or(0);

    #[cfg(debug_assertions)]
    {
        use std::io::Write;
        if let Ok(d) = std::env::var("CPOP_DATA_DIR") {
            let debug_path = format!("{}/event_debug.txt", d);
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&debug_path)
            {
                let _ = writeln!(
                    f,
                    "SESSION_FOCUSED: path={} focus_count={}",
                    path, focus_count
                );
            }
        }
    }

    // Read back session_id for the Focused event
    if let Some(session_id) = sessions
        .read_recover()
        .get(path)
        .map(|s| s.session_id.clone())
    {
        // Intentionally ignored: broadcast send fails only when no receivers are subscribed
        let _ = session_events_tx.send(SessionEvent {
            event_type: SessionEventType::Focused,
            session_id,
            document_path: path.to_string(),
            timestamp: SystemTime::now(),
        });
    }
}

pub fn unfocus_document_sync(
    path: &str,
    sessions: &Arc<RwLock<HashMap<String, DocumentSession>>>,
    session_events_tx: &broadcast::Sender<SessionEvent>,
) {
    let mut sessions_map = sessions.write_recover();

    if let Some(session) = sessions_map.get_mut(path) {
        session.focus_lost();

        // Intentionally ignored: broadcast send fails only when no receivers are subscribed
        let _ = session_events_tx.send(SessionEvent {
            event_type: SessionEventType::Unfocused,
            session_id: session.session_id.clone(),
            document_path: path.to_string(),
            timestamp: SystemTime::now(),
        });
    }
}

pub fn handle_change_event_sync(
    event: &ChangeEvent,
    sessions: &Arc<RwLock<HashMap<String, DocumentSession>>>,
    signing_key: &Arc<RwLock<Option<SigningKey>>>,
    wal_dir: &Path,
    session_events_tx: &broadcast::Sender<SessionEvent>,
) {
    // Acquire signing_key before sessions to match lock order in focus_document_sync
    let key = signing_key.read_recover().clone();
    let mut sessions_map = sessions.write_recover();

    if let Some(session) = sessions_map.get_mut(&event.path) {
        match event.event_type {
            ChangeEventType::Saved => {
                session.save_count += 1;

                let current_hash = event
                    .hash
                    .clone()
                    .or_else(|| compute_file_hash(&event.path).ok());
                session.current_hash = current_hash.clone();

                if let Some(hash) = current_hash {
                    match create_document_hash_payload(&hash, event.size.unwrap_or(0)) {
                        Ok(payload) => wal_append_session_event(
                            &session.session_id,
                            wal_dir,
                            key.clone(),
                            EntryType::DocumentHash,
                            payload,
                        ),
                        Err(e) => log::error!("Failed to build document hash payload: {e}"),
                    }
                }

                // Intentionally ignored: broadcast send fails only when no receivers are subscribed
                let _ = session_events_tx.send(SessionEvent {
                    event_type: SessionEventType::Saved,
                    session_id: session.session_id.clone(),
                    document_path: event.path.clone(),
                    timestamp: SystemTime::now(),
                });
            }
            ChangeEventType::Modified => {
                session.change_count += 1;
                if let Some(hash) = &event.hash {
                    session.current_hash = Some(hash.clone());
                }
            }
            ChangeEventType::Deleted => {
                // Remove within existing lock scope to avoid TOCTOU race
                let removed = sessions_map.remove(&event.path);
                drop(sessions_map);
                if let Some(session) = removed {
                    // Intentionally ignored: broadcast send fails only when no receivers are subscribed
                    let _ = session_events_tx.send(SessionEvent {
                        event_type: SessionEventType::Ended,
                        session_id: session.session_id,
                        document_path: event.path.clone(),
                        timestamp: SystemTime::now(),
                    });
                }
            }
            ChangeEventType::Created => {
                // Picked up on next focus event
            }
        }
    }
}

pub fn check_idle_sessions_sync(
    sessions: &Arc<RwLock<HashMap<String, DocumentSession>>>,
    idle_timeout: std::time::Duration,
    session_events_tx: &broadcast::Sender<SessionEvent>,
) {
    let sessions_to_end: Vec<String> = {
        let sessions_map = sessions.read_recover();
        sessions_map
            .iter()
            .filter(|(_, session)| {
                !session.is_focused()
                    && session
                        .last_focus_time
                        .elapsed()
                        .map(|d| d > idle_timeout)
                        .unwrap_or(false)
            })
            .map(|(path, _)| path.clone())
            .collect()
    };

    for path in sessions_to_end {
        end_session_sync(&path, sessions, session_events_tx);
    }
}

pub fn end_session_sync(
    path: &str,
    sessions: &Arc<RwLock<HashMap<String, DocumentSession>>>,
    session_events_tx: &broadcast::Sender<SessionEvent>,
) {
    let session = sessions.write_recover().remove(path);

    if let Some(session) = session {
        // Intentionally ignored: broadcast send fails only when no receivers are subscribed
        let _ = session_events_tx.send(SessionEvent {
            event_type: SessionEventType::Ended,
            session_id: session.session_id,
            document_path: path.to_string(),
            timestamp: SystemTime::now(),
        });
    }
}

pub fn end_all_sessions_sync(
    sessions: &Arc<RwLock<HashMap<String, DocumentSession>>>,
    shadow: &Arc<ShadowManager>,
    session_events_tx: &broadcast::Sender<SessionEvent>,
) {
    let all_sessions: Vec<_> = sessions.write_recover().drain().collect();

    for (path, session) in all_sessions {
        // Intentionally ignored: broadcast send fails only when no receivers are subscribed
        let _ = session_events_tx.send(SessionEvent {
            event_type: SessionEventType::Ended,
            session_id: session.session_id,
            document_path: path,
            timestamp: SystemTime::now(),
        });

        if let Some(shadow_id) = session.shadow_id {
            if let Err(e) = shadow.delete(&shadow_id) {
                log::warn!("shadow buffer cleanup failed for {shadow_id}: {e}");
            }
        }
    }
}

/// Append an entry to the session's WAL file, handling hex decode, key check, and errors.
fn wal_append_session_event(
    session_id: &str,
    wal_dir: &Path,
    key: Option<SigningKey>,
    entry_type: EntryType,
    payload: Vec<u8>,
) {
    let mut session_id_bytes = [0u8; 32];
    let hex_str = session_id
        .get(..64.min(session_id.len()))
        .unwrap_or(session_id);
    if hex::decode_to_slice(hex_str, &mut session_id_bytes).is_ok() {
        if let Some(key) = key {
            let wal_path = wal_dir.join(format!("{}.wal", session_id));
            if let Ok(wal) = Wal::open(&wal_path, session_id_bytes, key) {
                if let Err(e) = wal.append(entry_type, payload) {
                    log::error!("WAL append failed for session {}: {}", session_id, e);
                }
            }
        } else {
            log::warn!(
                "Signing key not initialized, skipping WAL for session {}",
                session_id
            );
        }
    } else {
        log::warn!("Invalid session ID hex: {}", session_id);
    }
}

pub fn compute_file_hash(path: &str) -> std::io::Result<String> {
    let meta = std::fs::metadata(path)?;
    if meta.len() > MAX_HASH_FILE_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "file too large to hash ({} bytes, limit {})",
                meta.len(),
                MAX_HASH_FILE_SIZE
            ),
        ));
    }
    let hash = crate::crypto::hash_file(Path::new(path))?;
    Ok(hex::encode(hash))
}

pub fn create_session_start_payload(session: &DocumentSession) -> Vec<u8> {
    // Binary format: path_len(4) | path | hash(32) | timestamp(8)
    let path_bytes = session.path.as_bytes();
    let mut payload = Vec::with_capacity(4 + path_bytes.len() + 32 + 8);

    payload.extend_from_slice(
        &u32::try_from(path_bytes.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    payload.extend_from_slice(path_bytes);

    let hash_bytes = session
        .initial_hash
        .as_ref()
        .and_then(|h| match hex::decode(h) {
            Ok(bytes) if bytes.len() == 32 => Some(bytes),
            Ok(bytes) => {
                log::warn!(
                    "Initial hash '{}' decoded to {} bytes, expected 32",
                    h,
                    bytes.len()
                );
                None
            }
            Err(e) => {
                log::warn!("Failed to decode initial hash '{}': {}", h, e);
                None
            }
        })
        .unwrap_or_else(|| {
            log::debug!("No initial hash available for session, using zero hash");
            vec![0u8; 32]
        });
    let hash_fixed: [u8; 32] = hash_bytes.as_slice().try_into().unwrap_or_default();
    payload.extend_from_slice(&hash_fixed);

    let timestamp = session
        .start_time
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    payload.extend_from_slice(&timestamp.to_be_bytes());

    payload
}

pub fn create_document_hash_payload(hash: &str, size: i64) -> Result<Vec<u8>, String> {
    let hash_bytes =
        hex::decode(hash).map_err(|e| format!("Failed to decode hash '{}': {}", hash, e))?;
    if hash_bytes.len() != 32 {
        return Err(format!(
            "Hash '{}' decoded to {} bytes, expected 32",
            hash,
            hash_bytes.len()
        ));
    }
    let mut payload = Vec::with_capacity(32 + 8 + 8);

    let mut hash_fixed = [0u8; 32];
    hash_fixed.copy_from_slice(&hash_bytes);
    payload.extend_from_slice(&hash_fixed);
    payload.extend_from_slice(&(size.max(0) as u64).to_be_bytes());

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    payload.extend_from_slice(&timestamp.to_be_bytes());

    Ok(payload)
}

/// Canonicalize and validate a user-provided path against traversal attacks.
pub fn validate_path(path: impl AsRef<Path>) -> Result<PathBuf, String> {
    let path = path.as_ref();

    if path.exists() {
        let canonical = path
            .canonicalize()
            .map_err(|e| format!("Invalid path '{}': {}", path.display(), e))?;
        validate_canonical_path(&canonical)?;
        return Ok(canonical);
    }

    let parent = path
        .parent()
        .ok_or_else(|| "Invalid path: no parent".to_string())?;
    let canonical_parent = parent
        .canonicalize()
        .map_err(|e| format!("Invalid parent directory for '{}': {}", path.display(), e))?;

    let file_name = path
        .file_name()
        .ok_or_else(|| "Invalid path: no file name".to_string())?;
    let canonical = canonical_parent.join(file_name);

    validate_canonical_path(&canonical)?;
    Ok(canonical)
}

/// Key material file names that must never be overwritten via export paths.
const KEY_MATERIAL_NAMES: &[&str] = &[
    "signing_key",
    ".storage_key",
    "puf_seed",
    "sealed_identity",
    "identity.key",
    "session.key",
];

fn validate_canonical_path(path: &Path) -> Result<(), String> {
    if crate::ipc::messages::is_blocked_system_path(path)? {
        return Err("Access to system directory denied".to_string());
    }
    // EH-046: Reject paths that would overwrite key material files.
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        for &key_name in KEY_MATERIAL_NAMES {
            if name == key_name {
                return Err(format!("Refusing to overwrite key material file: {}", name));
            }
        }
    }
    Ok(())
}
