// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

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
    if !config.is_app_allowed(&event.app_bundle_id, &event.app_name) {
        let path_to_unfocus = {
            let focus = current_focus.read_recover();
            focus.clone()
        };
        if let Some(path) = path_to_unfocus {
            unfocus_document_sync(&path, sessions, session_events_tx);
            *current_focus.write_recover() = None;
        }
        return;
    }

    match event.event_type {
        FocusEventType::FocusGained => {
            let doc_path = if event.path.is_empty() {
                if !event.shadow_id.is_empty() {
                    format!("shadow://{}", event.shadow_id)
                } else {
                    return;
                }
            } else {
                event.path.clone()
            };

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

            if let Some(path) = path_to_unfocus {
                unfocus_document_sync(&path, sessions, session_events_tx);
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
            *current_focus.write_recover() = Some(doc_path);
        }
        FocusEventType::FocusLost => {
            let prev_path = {
                let focus = current_focus.read_recover();
                focus.clone()
            };
            if let Some(path) = prev_path {
                unfocus_document_sync(&path, sessions, session_events_tx);
                *current_focus.write_recover() = None;
            }
        }
        FocusEventType::FocusUnknown => {
            let prev_path = {
                let focus = current_focus.read_recover();
                focus.clone()
            };
            if let Some(path) = prev_path {
                unfocus_document_sync(&path, sessions, session_events_tx);
                *current_focus.write_recover() = None;
            }
        }
    }
}

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
    let key = signing_key.read_recover().clone();
    let mut sessions_map = sessions.write_recover();

    let session = sessions_map.entry(path.to_string()).or_insert_with(|| {
        let mut session = DocumentSession::new(
            path.to_string(),
            event.app_bundle_id.clone(),
            event.app_name.clone(),
            event.window_title.clone(),
        );

        if let Ok(hash) = compute_file_hash(path) {
            session.initial_hash = Some(hash.clone());
            session.current_hash = Some(hash);
        }

        let payload = create_session_start_payload(&session);
        wal_append_session_event(
            &session.session_id,
            wal_dir,
            key,
            EntryType::SessionStart,
            payload,
        );

        // Intentionally ignored: broadcast send fails only when no receivers are subscribed
        let _ = session_events_tx.send(SessionEvent {
            event_type: SessionEventType::Started,
            session_id: session.session_id.clone(),
            document_path: path.to_string(),
            timestamp: SystemTime::now(),
        });

        session
    });

    session.focus_gained();
    session.window_title = event.window_title.clone();

    // Intentionally ignored: broadcast send fails only when no receivers are subscribed
    let _ = session_events_tx.send(SessionEvent {
        event_type: SessionEventType::Focused,
        session_id: session.session_id.clone(),
        document_path: path.to_string(),
        timestamp: SystemTime::now(),
    });
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
                    let payload = create_document_hash_payload(&hash, event.size.unwrap_or(0));
                    wal_append_session_event(
                        &session.session_id,
                        wal_dir,
                        key.clone(),
                        EntryType::DocumentHash,
                        payload,
                    );
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
    let hex_str = &session_id[..64.min(session_id.len())];
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
    let hash = crate::crypto::hash_file(Path::new(path))?;
    Ok(hex::encode(hash))
}

pub fn create_session_start_payload(session: &DocumentSession) -> Vec<u8> {
    // Binary format: path_len(4) | path | hash(32) | timestamp(8)
    let path_bytes = session.path.as_bytes();
    let mut payload = Vec::with_capacity(4 + path_bytes.len() + 32 + 8);

    payload.extend_from_slice(&(path_bytes.len() as u32).to_be_bytes());
    payload.extend_from_slice(path_bytes);

    let hash_bytes = session
        .initial_hash
        .as_ref()
        .and_then(|h| {
            hex::decode(h)
                .map_err(|e| {
                    log::warn!("Failed to decode initial hash '{}': {}", h, e);
                    e
                })
                .ok()
        })
        .unwrap_or_else(|| {
            log::debug!("No initial hash available for session, using zero hash");
            vec![0u8; 32]
        });
    payload.extend_from_slice(&hash_bytes[..32.min(hash_bytes.len())]);
    payload.resize(payload.len() + (32 - hash_bytes.len().min(32)), 0);

    let timestamp = session
        .start_time
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0);
    payload.extend_from_slice(&timestamp.to_be_bytes());

    payload
}

pub fn create_document_hash_payload(hash: &str, size: i64) -> Vec<u8> {
    let hash_bytes = hex::decode(hash).unwrap_or_else(|e| {
        log::warn!("Failed to decode hash '{}': {}, using zero hash", hash, e);
        vec![0u8; 32]
    });
    let mut payload = Vec::with_capacity(32 + 8 + 8);

    payload.extend_from_slice(&hash_bytes[..32.min(hash_bytes.len())]);
    payload.resize(payload.len() + (32 - hash_bytes.len().min(32)), 0);
    payload.extend_from_slice(&(size as u64).to_be_bytes());

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0);
    payload.extend_from_slice(&timestamp.to_be_bytes());

    payload
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

fn validate_canonical_path(path: &Path) -> Result<(), String> {
    if crate::ipc::messages::is_blocked_system_path(path)? {
        return Err("Access to system directory denied".to_string());
    }
    Ok(())
}
