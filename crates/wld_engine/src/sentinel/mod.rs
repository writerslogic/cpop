// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Background document tracking daemon.
//!
//! Monitors focused documents and manages tracking sessions automatically.
//! Operates invisibly during writing, surfacing only on explicit status requests.
//!
//! - Debounced focus change handling (500ms default)
//! - Multi-document session management with shadow buffers
//! - Platform-specific focus detection (macOS, Linux, Windows)

pub mod core;
pub mod daemon;
pub mod error;
pub mod focus;
pub mod helpers;
pub mod ipc_handler;
pub mod shadow;
pub mod types;

#[cfg(target_os = "macos")]
pub mod macos_focus;

#[cfg(not(target_os = "macos"))]
pub mod stub_focus;

#[cfg(target_os = "windows")]
pub mod windows_focus;

#[cfg(test)]
mod tests;

pub use self::core::Sentinel;
pub use self::daemon::{
    cmd_start, cmd_start_foreground, cmd_status, cmd_stop, cmd_track, cmd_untrack, DaemonHandle,
    DaemonManager, DaemonState, DaemonStatus,
};
pub use self::error::{Result, SentinelError};
pub use self::focus::{PollingSentinelFocusTracker, SentinelFocusTracker, WindowProvider};
pub use self::helpers::{
    check_idle_sessions_sync, compute_file_hash, create_document_hash_payload,
    create_session_start_payload, end_all_sessions_sync, end_session_sync, focus_document_sync,
    handle_change_event_sync, handle_focus_event_sync, unfocus_document_sync,
};
pub use self::ipc_handler::SentinelIpcHandler;
pub use self::shadow::ShadowManager;
pub use self::types::{
    generate_session_id, hash_string, infer_document_path_from_title, normalize_document_path,
    parse_url_parts, ChangeEvent, ChangeEventType, DocumentSession, FocusEvent, FocusEventType,
    SessionBinding, SessionEvent, SessionEventType, WindowInfo,
};
