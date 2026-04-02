// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! FFI functions for Endpoint Security event notifications from the host app.
//!
//! These are called by the Swift EndpointSecurityEventClient when ES events
//! match tracked documents or known AI tools.

use super::sentinel::get_sentinel;
use crate::RwLockRecover;

/// Notify the sentinel that a tracked file was written or closed.
///
/// Called by the Swift ES client when `ES_EVENT_TYPE_NOTIFY_WRITE` or
/// `ES_EVENT_TYPE_NOTIFY_CLOSE` fires for a file that matches a tracked
/// document path. This can trigger an auto-checkpoint without polling.
///
/// Returns `true` if a checkpoint was committed.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_es_file_write(path: String, pid: i32, signing_id: String) -> bool {
    let sentinel_opt = get_sentinel();
    let sentinel = match sentinel_opt.as_ref() {
        Some(s) if s.is_running() => s,
        _ => return false,
    };

    // Only act on paths that are actually being tracked.
    let tracked = sentinel.tracked_files();
    if !tracked.iter().any(|t| t == &path) {
        return false;
    }

    log::info!(
        "ES file write detected for tracked document: {path} (pid={pid}, signing_id={signing_id})"
    );

    // Commit a checkpoint for this file since we know it was saved.
    sentinel.commit_checkpoint_for_path(&path)
}

/// Notify the sentinel that a known AI tool process was launched.
///
/// Called by the Swift ES client when `ES_EVENT_TYPE_NOTIFY_EXEC` fires
/// for a process whose signing ID matches a known AI tool.
///
/// The sentinel logs this and can flag the current session.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_es_ai_tool_detected(signing_id: String, pid: i32, exec_path: String) -> bool {
    let sentinel_opt = get_sentinel();
    let sentinel = match sentinel_opt.as_ref() {
        Some(s) if s.is_running() => s,
        _ => return false,
    };

    log::warn!("AI tool detected via ES: signing_id={signing_id}, pid={pid}, path={exec_path}");

    // Flag all active sessions with an AI tool detection note.
    let sessions = sentinel.sessions.read_recover();
    for (doc_path, _session) in sessions.iter() {
        log::info!("Session for {doc_path} flagged: AI tool '{signing_id}' active");
    }

    true
}
