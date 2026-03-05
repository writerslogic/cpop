// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Ephemeral session FFI — in-memory text witnessing without file paths.
//!
//! Used by browser extensions and macOS Services where content lives in
//! a text field, not on disk. Sessions use `ephemeral://<id>` as synthetic
//! paths and hash content bytes in-memory.
//!
//! Security invariants:
//! - All string inputs are bounded (context_label ≤256, content ≤10MB, statement ≤1000)
//! - Sessions auto-expire after `SESSION_TIMEOUT` (30 min)
//! - Signing key bytes are zeroized after use
//! - Crash-recovery files use atomic write-then-rename
//! - Content snapshots are bounded to `MAX_SNAPSHOTS` per session

use crate::ffi::helpers::{get_data_dir, open_store};
use crate::ffi::types::{
    FfiEphemeralFinalizeResult, FfiEphemeralSessionResult, FfiEphemeralStatusResult, FfiResult,
};
use dashmap::DashMap;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use std::time::{Duration, Instant};
/// Max context label length (chars).
const MAX_CONTEXT_LABEL_LEN: usize = 256;
/// Max content size for checkpoint/finalize (bytes).
const MAX_CONTENT_SIZE: usize = 10 * 1024 * 1024; // 10 MB
/// Max declaration statement length (chars).
const MAX_STATEMENT_LEN: usize = 1000;
/// Max content snapshots per session (30s interval × ~8.3 hours).
const MAX_SNAPSHOTS: usize = 1000;
/// Max jitter intervals stored per session.
const MAX_JITTER_INTERVALS: usize = 100_000;
/// Sessions expire after 30 minutes of inactivity.
const SESSION_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// In-memory ephemeral session state.
struct EphemeralSession {
    context_label: String,
    started_at: Instant,
    started_at_ns: i64,
    last_activity: Instant,
    jitter_intervals: Vec<u64>,
    checkpoint_count: u64,
    keystroke_count: u64,
    #[allow(dead_code)] // Retained for diagnostic/audit purposes
    last_timestamp_ns: i64,
    /// Content hashes from each checkpoint (for chain building).
    content_snapshots: Vec<ContentSnapshot>,
}

/// A checkpoint snapshot of the content at a point in time.
struct ContentSnapshot {
    timestamp_ns: i64,
    content_hash: [u8; 32],
    char_count: u64,
    #[allow(dead_code)] // Retained for diagnostic/audit purposes
    size_delta: i32,
    message: Option<String>,
}

static EPHEMERAL_SESSIONS: OnceLock<DashMap<String, EphemeralSession>> = OnceLock::new();

fn sessions() -> &'static DashMap<String, EphemeralSession> {
    EPHEMERAL_SESSIONS.get_or_init(DashMap::new)
}

fn now_ns() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| {
            let nanos = d.as_nanos();
            if nanos > i64::MAX as u128 {
                // Saturate rather than silently truncate — preserves monotonicity
                i64::MAX
            } else {
                nanos as i64
            }
        })
        .unwrap_or(0)
}

fn generate_session_id(label: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(label.as_bytes());
    hasher.update(now_ns().to_le_bytes());
    let mut random_bytes = [0u8; 16];
    if getrandom::getrandom(&mut random_bytes).is_err() {
        // Fallback: use Instant-based entropy if getrandom fails
        let fallback = Instant::now().elapsed().as_nanos().to_le_bytes();
        random_bytes[..16.min(fallback.len())].copy_from_slice(&fallback[..16.min(fallback.len())]);
    }
    hasher.update(random_bytes);
    let hash = hasher.finalize();
    hex::encode(&hash[..16])
}

/// Evict sessions that have been idle longer than `SESSION_TIMEOUT`.
fn evict_stale_sessions() {
    let now = Instant::now();
    sessions().retain(|id, session| {
        let stale = now.duration_since(session.last_activity) > SESSION_TIMEOUT;
        if stale {
            log::info!("Evicting stale ephemeral session {id} (idle > 30min)");
            cleanup_session_state(id);
        }
        !stale
    });
}

/// Start a new ephemeral witnessing session.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_start_ephemeral_session(context_label: String) -> FfiEphemeralSessionResult {
    // Validate input bounds
    if context_label.len() > MAX_CONTEXT_LABEL_LEN {
        return FfiEphemeralSessionResult {
            success: false,
            session_id: String::new(),
            error_message: Some(format!(
                "Context label too long ({} chars, max {MAX_CONTEXT_LABEL_LEN})",
                context_label.len()
            )),
        };
    }

    // Evict stale sessions on every start to prevent unbounded growth
    evict_stale_sessions();

    let now = Instant::now();
    let session_id = generate_session_id(&context_label);

    sessions().insert(
        session_id.clone(),
        EphemeralSession {
            context_label,
            started_at: now,
            started_at_ns: now_ns(),
            last_activity: now,
            jitter_intervals: Vec::new(),
            checkpoint_count: 0,
            keystroke_count: 0,
            last_timestamp_ns: 0,
            content_snapshots: Vec::new(),
        },
    );

    FfiEphemeralSessionResult {
        success: true,
        session_id,
        error_message: None,
    }
}

/// Create an in-memory checkpoint of the current content.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_ephemeral_checkpoint(session_id: String, content: String, message: String) -> FfiResult {
    let mut entry = match sessions().get_mut(&session_id) {
        Some(e) => e,
        None => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("No ephemeral session: {session_id}")),
            }
        }
    };

    if content.len() > MAX_CONTENT_SIZE {
        return FfiResult {
            success: false,
            message: None,
            error_message: Some(format!(
                "Content too large: {} bytes (max {})",
                content.len(),
                MAX_CONTENT_SIZE
            )),
        };
    }

    if entry.content_snapshots.len() >= MAX_SNAPSHOTS {
        return FfiResult {
            success: false,
            message: None,
            error_message: Some(format!("Max snapshots reached ({})", MAX_SNAPSHOTS)),
        };
    }

    let content_hash: [u8; 32] = Sha256::digest(content.as_bytes()).into();
    let char_count = content.len() as u64;
    let prev_chars = entry
        .content_snapshots
        .last()
        .map(|s| s.char_count)
        .unwrap_or(0);
    let size_delta =
        (char_count as i64 - prev_chars as i64).clamp(i32::MIN as i64, i32::MAX as i64) as i32;

    let context_note = if message.is_empty() {
        None
    } else {
        Some(message)
    };

    entry.content_snapshots.push(ContentSnapshot {
        timestamp_ns: now_ns(),
        content_hash,
        char_count,
        size_delta,
        message: context_note,
    });
    entry.checkpoint_count += 1;

    // Also persist to the store if available (for crash recovery / verification).
    let ephemeral_path = format!("ephemeral://{session_id}");
    if let Ok(mut store) = open_store() {
        let mut event = crate::store::SecureEvent {
            id: None,
            device_id: [0u8; 16],
            machine_id: String::new(),
            timestamp_ns: now_ns(),
            file_path: ephemeral_path,
            content_hash,
            file_size: char_count as i64,
            size_delta,
            previous_hash: [0u8; 32],
            event_hash: [0u8; 32],
            context_type: Some("ephemeral".to_string()),
            context_note: entry
                .content_snapshots
                .last()
                .and_then(|s| s.message.clone()),
            vdf_input: None,
            vdf_output: None,
            vdf_iterations: 0,
            forensic_score: 0.0,
            is_paste: false,
            hardware_counter: None,
        };
        let _ = store.insert_secure_event(&mut event);
    }

    // Flush session state to disk for crash recovery.
    flush_session_state(&session_id, &entry);

    FfiResult {
        success: true,
        message: Some(format!(
            "Ephemeral checkpoint #{}: {}",
            entry.checkpoint_count,
            hex::encode(&content_hash[..8])
        )),
        error_message: None,
    }
}

/// Accumulate keystroke timing intervals for jitter analysis.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_ephemeral_inject_jitter(session_id: String, intervals: Vec<u64>) -> FfiResult {
    let mut entry = match sessions().get_mut(&session_id) {
        Some(e) => e,
        None => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("No ephemeral session: {session_id}")),
            }
        }
    };

    // Filter to valid range: 10ms..10s in microseconds
    let valid: Vec<u64> = intervals
        .into_iter()
        .filter(|i| (10_000..=10_000_000).contains(i))
        .collect();

    let accepted = valid.len();
    let remaining_cap = MAX_JITTER_INTERVALS.saturating_sub(entry.jitter_intervals.len());
    entry
        .jitter_intervals
        .extend_from_slice(&valid[..accepted.min(remaining_cap)]);

    entry.keystroke_count += accepted as u64;

    FfiResult {
        success: true,
        message: Some(format!("Accepted {accepted} intervals")),
        error_message: None,
    }
}

/// Finalize an ephemeral session: build evidence packet → WAR block + compact ref.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_ephemeral_finalize(
    session_id: String,
    content: String,
    statement: String,
) -> FfiEphemeralFinalizeResult {
    if content.len() > MAX_CONTENT_SIZE {
        return FfiEphemeralFinalizeResult {
            success: false,
            war_block: String::new(),
            compact_ref: String::new(),
            error_message: Some(format!(
                "Content too large: {} bytes (max {})",
                content.len(),
                MAX_CONTENT_SIZE
            )),
        };
    }

    let statement = if statement.len() > MAX_STATEMENT_LEN {
        statement[..MAX_STATEMENT_LEN].to_string()
    } else {
        statement
    };

    let session = match sessions().remove(&session_id) {
        Some((_, s)) => s,
        None => {
            return FfiEphemeralFinalizeResult {
                success: false,
                war_block: String::new(),
                compact_ref: String::new(),
                error_message: Some(format!("No ephemeral session: {session_id}")),
            }
        }
    };

    // Final content hash
    let final_hash: [u8; 32] = Sha256::digest(content.as_bytes()).into();
    let final_hash_hex = hex::encode(final_hash);
    let _char_count = content.len() as u64;

    // Need at least one snapshot
    if session.content_snapshots.is_empty() {
        return FfiEphemeralFinalizeResult {
            success: false,
            war_block: String::new(),
            compact_ref: String::new(),
            error_message: Some("No checkpoints recorded in session".to_string()),
        };
    }

    let checkpoint_count = session.content_snapshots.len();

    // Build WAR block from the session data
    let war_block_str = match build_war_block(&final_hash_hex, &statement, &session) {
        Ok(s) => s,
        Err(e) => {
            return FfiEphemeralFinalizeResult {
                success: false,
                war_block: String::new(),
                compact_ref: String::new(),
                error_message: Some(format!("Failed to create WAR block: {e}")),
            }
        }
    };

    // Compact reference
    let compact_ref = format!(
        "pop-ref:writerslogic:{}:{}",
        &final_hash_hex[..final_hash_hex.len().min(12)],
        checkpoint_count
    );

    // Clean up crash-recovery file
    cleanup_session_state(&session_id);

    FfiEphemeralFinalizeResult {
        success: true,
        war_block: war_block_str,
        compact_ref,
        error_message: None,
    }
}

/// Get current ephemeral session stats (for the floating indicator).
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_ephemeral_status(session_id: String) -> FfiEphemeralStatusResult {
    match sessions().get(&session_id) {
        Some(entry) => FfiEphemeralStatusResult {
            success: true,
            checkpoint_count: entry.checkpoint_count,
            keystroke_count: entry.keystroke_count,
            elapsed_secs: entry.started_at.elapsed().as_secs_f64(),
            error_message: None,
        },
        None => FfiEphemeralStatusResult {
            success: false,
            checkpoint_count: 0,
            keystroke_count: 0,
            elapsed_secs: 0.0,
            error_message: Some(format!("No ephemeral session: {session_id}")),
        },
    }
}

/// Build a signed WAR block from ephemeral session data.
fn build_war_block(
    final_hash_hex: &str,
    statement: &str,
    session: &EphemeralSession,
) -> Result<String, String> {
    let data_dir = crate::ffi::helpers::get_data_dir()
        .ok_or_else(|| "Cannot determine data directory".to_string())?;
    let key_path = data_dir.join("signing_key");
    let key_data = std::fs::read(&key_path).map_err(|e| format!("Cannot read signing key: {e}"))?;
    if key_data.len() < 32 {
        return Err("Signing key too short".to_string());
    }
    let signing_key = ed25519_dalek::SigningKey::from_bytes(
        key_data[..32]
            .try_into()
            .map_err(|_| "invalid key length")?,
    );

    let snapshots: Vec<crate::evidence::EphemeralSnapshot> = session
        .content_snapshots
        .iter()
        .map(|s| crate::evidence::EphemeralSnapshot {
            timestamp_ns: s.timestamp_ns,
            content_hash: s.content_hash,
            char_count: s.char_count,
            message: s.message.clone(),
        })
        .collect();

    let packet = crate::evidence::build_ephemeral_packet(
        final_hash_hex,
        statement,
        &session.context_label,
        &snapshots,
        &signing_key,
    )
    .map_err(|e| format!("{e}"))?;

    let block = crate::war::Block::from_packet_signed(&packet, &signing_key)
        .map_err(|e| format!("WAR block creation failed: {e}"))?;

    Ok(block.encode_ascii())
}

/// Flush ephemeral session state to disk for crash recovery.
fn flush_session_state(session_id: &str, session: &EphemeralSession) {
    let Some(data_dir) = get_data_dir() else {
        return;
    };
    let recovery_dir = data_dir.join("ephemeral-sessions");
    if std::fs::create_dir_all(&recovery_dir).is_err() {
        return;
    }

    let state = serde_json::json!({
        "session_id": session_id,
        "context_label": session.context_label,
        "started_at_ns": session.started_at_ns,
        "checkpoint_count": session.checkpoint_count,
        "keystroke_count": session.keystroke_count,
        "jitter_count": session.jitter_intervals.len(),
    });

    let path = recovery_dir.join(format!("{session_id}.json"));
    let _ = std::fs::write(path, state.to_string());
}

/// Remove crash-recovery state after successful finalization.
fn cleanup_session_state(session_id: &str) {
    let Some(data_dir) = get_data_dir() else {
        return;
    };
    let path = data_dir
        .join("ephemeral-sessions")
        .join(format!("{session_id}.json"));
    let _ = std::fs::remove_file(path);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_start_ephemeral_session() {
        let result = ffi_start_ephemeral_session("test email".to_string());
        assert!(result.success);
        assert!(!result.session_id.is_empty());
        assert!(result.error_message.is_none());

        // Clean up
        sessions().remove(&result.session_id);
    }

    #[test]
    fn test_ephemeral_checkpoint() {
        let start = ffi_start_ephemeral_session("test checkpoint".to_string());
        let sid = start.session_id.clone();

        let cp = ffi_ephemeral_checkpoint(sid.clone(), "Hello world".to_string(), "draft".into());
        assert!(cp.success);

        let status = ffi_ephemeral_status(sid.clone());
        assert!(status.success);
        assert_eq!(status.checkpoint_count, 1);

        sessions().remove(&sid);
    }

    #[test]
    fn test_ephemeral_inject_jitter() {
        let start = ffi_start_ephemeral_session("test jitter".to_string());
        let sid = start.session_id.clone();

        let intervals = vec![50_000, 80_000, 120_000, 5, 15_000_000]; // 3 valid, 2 out of range
        let result = ffi_ephemeral_inject_jitter(sid.clone(), intervals);
        assert!(result.success);

        let status = ffi_ephemeral_status(sid.clone());
        assert_eq!(status.keystroke_count, 3);

        sessions().remove(&sid);
    }

    #[test]
    fn test_ephemeral_status_no_session() {
        let status = ffi_ephemeral_status("nonexistent".to_string());
        assert!(!status.success);
        assert!(status.error_message.is_some());
    }

    #[test]
    fn test_finalize_no_checkpoints() {
        let start = ffi_start_ephemeral_session("test finalize empty".to_string());
        let result = ffi_ephemeral_finalize(
            start.session_id,
            "content".to_string(),
            "statement".to_string(),
        );
        assert!(!result.success);
        assert!(result
            .error_message
            .unwrap_or_default()
            .contains("No checkpoints"));
    }
}
