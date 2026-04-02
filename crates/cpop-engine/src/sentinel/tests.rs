// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::*;
use crate::config::SentinelConfig;
use crate::crypto::ObfuscatedString;
use ed25519_dalek::SigningKey;
use std::collections::HashMap;
use std::fs;
use std::sync::{Arc, RwLock};
use tokio::sync::broadcast;

#[test]
fn test_config_default() {
    let config = SentinelConfig::default();
    assert!(!config.allowed_apps.is_empty());
    assert!(!config.blocked_apps.is_empty());
    assert!(config.track_unknown_apps);
}

#[test]
fn test_config_app_allowed() {
    let config = SentinelConfig::default();

    assert!(config.is_app_allowed("com.microsoft.VSCode", "Visual Studio Code"));
    assert!(!config.is_app_allowed("com.apple.finder", "Finder"));
}

#[test]
fn test_document_session() {
    let mut session = DocumentSession::new(
        "/path/to/doc.txt".to_string(),
        "com.test.app".to_string(),
        "Test App".to_string(),
        ObfuscatedString::new("doc.txt"),
    );

    assert!(!session.is_focused());
    assert_eq!(session.focus_count, 0);

    session.focus_gained();
    assert!(session.is_focused());
    assert_eq!(session.focus_count, 1);

    session.focus_lost();
    assert!(!session.is_focused());
    assert!(session.total_focus_ms >= 0);
}

#[test]
fn test_sentinel_keystroke_capture_defaults_inactive() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = SentinelConfig::default().with_writersproof_dir(dir.path());
    let sentinel = Sentinel::new(config).expect("sentinel creation");
    // Before start(), keystroke capture should be inactive
    assert!(!sentinel.is_keystroke_capture_active());
}

#[test]
fn test_infer_document_path_standard_title() {
    let result = infer_document_path_from_title("Document.txt - Notepad");
    assert_eq!(result, Some("Document.txt".to_string()));
}

#[test]
fn test_infer_document_path_with_full_path() {
    let result = infer_document_path_from_title("C:\\Users\\me\\doc.txt - Notepad");
    assert_eq!(result, Some("C:\\Users\\me\\doc.txt".to_string()));
}

#[test]
fn test_infer_document_path_unix() {
    let result = infer_document_path_from_title("/home/user/file.rs - VSCode");
    assert_eq!(result, Some("/home/user/file.rs".to_string()));
}

#[test]
fn test_infer_document_path_no_extension() {
    let result = infer_document_path_from_title("Settings");
    assert_eq!(result, None);
}

#[test]
fn test_infer_document_path_pipe_separator() {
    let result = infer_document_path_from_title("main.rs | myproject");
    assert_eq!(result, Some("main.rs".to_string()));
}

#[test]
fn test_infer_document_path_empty() {
    assert_eq!(infer_document_path_from_title(""), None);
}

// --- Electron editor title inference tests ---

#[test]
fn test_infer_typora_em_dash_title() {
    let result = infer_document_path_from_title_with_bundle(
        "document.md \u{2014} Typora",
        Some("abnerworks.Typora"),
    );
    assert_eq!(result, Some("document.md".to_string()));
}

#[test]
fn test_infer_zettlr_em_dash_title() {
    let result = infer_document_path_from_title_with_bundle(
        "README.md \u{2014} Zettlr",
        Some("com.zettlr.app"),
    );
    assert_eq!(result, Some("README.md".to_string()));
}

#[test]
fn test_infer_obsidian_no_extension() {
    // Obsidian shows "My Note - Obsidian" with no extension; Electron-aware
    // inference accepts this as a document name.
    let result =
        infer_document_path_from_title_with_bundle("My Note - Obsidian", Some("md.obsidian"));
    assert_eq!(result, Some("My Note".to_string()));
}

#[test]
fn test_infer_obsidian_with_extension() {
    let result =
        infer_document_path_from_title_with_bundle("notes.md - Obsidian", Some("md.obsidian"));
    assert_eq!(result, Some("notes.md".to_string()));
}

#[test]
fn test_infer_electron_skips_untitled() {
    let result =
        infer_document_path_from_title_with_bundle("Untitled - Typora", Some("abnerworks.Typora"));
    assert_eq!(result, None);
}

#[test]
fn test_infer_electron_skips_settings() {
    let result =
        infer_document_path_from_title_with_bundle("Settings - Obsidian", Some("md.obsidian"));
    assert_eq!(result, None);
}

#[test]
fn test_infer_electron_skips_graph_view() {
    let result =
        infer_document_path_from_title_with_bundle("Graph View - Obsidian", Some("md.obsidian"));
    assert_eq!(result, None);
}

#[test]
fn test_infer_non_electron_app_no_extension() {
    // Non-Electron apps without a recognized bundle should not match bare names.
    let result = infer_document_path_from_title_with_bundle(
        "My Note - SomeApp",
        Some("com.example.someapp"),
    );
    assert_eq!(result, None);
}

#[test]
fn test_infer_logseq_title() {
    let result = infer_document_path_from_title_with_bundle(
        "Project Plan - Logseq",
        Some("com.logseq.logseq"),
    );
    assert_eq!(result, Some("Project Plan".to_string()));
}

#[test]
fn test_infer_marktext_title() {
    let result = infer_document_path_from_title_with_bundle(
        "draft.md \u{2014} Mark Text",
        Some("com.github.marktext"),
    );
    assert_eq!(result, Some("draft.md".to_string()));
}

#[test]
fn test_infer_with_bundle_none_delegates_to_basic() {
    // Passing None for bundle_id should behave like the original function.
    let result = infer_document_path_from_title_with_bundle("file.rs - VSCode", None);
    assert_eq!(result, Some("file.rs".to_string()));

    let result = infer_document_path_from_title_with_bundle("My Note - SomeApp", None);
    assert_eq!(result, None);
}

#[test]
fn test_normalize_path_existing() {
    let result = normalize_document_path("/");
    assert!(result.is_some());
}

#[test]
fn test_normalize_path_rejects_traversal() {
    assert!(normalize_document_path("../../../etc/passwd").is_none());
    assert!(normalize_document_path("/tmp/../etc/shadow").is_none());
}

#[test]
fn test_normalize_path_nonexistent_returns_none() {
    assert!(normalize_document_path("/nonexistent/fakefile.txt").is_none());
}

#[tokio::test]
async fn test_shadow_manager() {
    let temp_dir = std::env::temp_dir().join("writerslogic-test-shadow");
    let _ = fs::remove_dir_all(&temp_dir);

    let shadow_mgr = ShadowManager::new(&temp_dir).unwrap();

    let id = shadow_mgr.create("Test App", "Untitled").unwrap();
    assert!(!id.is_empty());

    shadow_mgr.update(&id, b"test content").unwrap();

    let path = shadow_mgr.get_path(&id);
    assert!(path.is_some());

    shadow_mgr.delete(&id).unwrap();
    assert!(shadow_mgr.get_path(&id).is_none());

    let _ = fs::remove_dir_all(&temp_dir);
}

// --- handle_focus_event_sync tests ---

type FocusTestHarness = (
    Arc<RwLock<HashMap<String, DocumentSession>>>,
    SentinelConfig,
    Arc<ShadowManager>,
    Arc<RwLock<Option<SigningKey>>>,
    Arc<RwLock<Option<String>>>,
    tempfile::TempDir,
    broadcast::Sender<SessionEvent>,
);

fn make_focus_test_harness() -> FocusTestHarness {
    let sessions = Arc::new(RwLock::new(HashMap::new()));
    let config = SentinelConfig::default();
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let shadow = Arc::new(ShadowManager::new(temp_dir.path()).expect("shadow manager"));
    let signing_key: Arc<RwLock<Option<SigningKey>>> = Arc::new(RwLock::new(None));
    let current_focus: Arc<RwLock<Option<String>>> = Arc::new(RwLock::new(None));
    let (tx, _rx) = broadcast::channel(16);
    (
        sessions,
        config,
        shadow,
        signing_key,
        current_focus,
        temp_dir,
        tx,
    )
}

fn make_focus_event(
    event_type: FocusEventType,
    path: &str,
    shadow_id: &str,
    bundle_id: &str,
    app_name: &str,
) -> FocusEvent {
    FocusEvent {
        event_type,
        path: path.to_string(),
        shadow_id: shadow_id.to_string(),
        app_bundle_id: bundle_id.to_string(),
        app_name: app_name.to_string(),
        window_title: ObfuscatedString::new("Test Window"),
        timestamp: std::time::SystemTime::now(),
    }
}

#[test]
fn test_handle_focus_gained_creates_session() {
    let (sessions, config, shadow, signing_key, current_focus, temp_dir, tx) =
        make_focus_test_harness();

    let event = make_focus_event(
        FocusEventType::FocusGained,
        "/tmp/test_doc.txt",
        "",
        "com.microsoft.VSCode",
        "Visual Studio Code",
    );

    handle_focus_event_sync(
        event,
        &sessions,
        &config,
        &shadow,
        &signing_key,
        &current_focus,
        temp_dir.path(),
        &tx,
    );

    let sessions_map = sessions.read().unwrap();
    assert!(sessions_map.contains_key("/tmp/test_doc.txt"));
    let session = &sessions_map["/tmp/test_doc.txt"];
    assert!(session.is_focused());
    assert_eq!(session.focus_count, 1);
}

#[test]
fn test_handle_focus_gained_empty_path_skipped() {
    let (sessions, config, shadow, signing_key, current_focus, temp_dir, tx) =
        make_focus_test_harness();

    // Empty path, empty shadow_id: no document to track, should be skipped.
    let event = make_focus_event(
        FocusEventType::FocusGained,
        "",
        "",
        "com.microsoft.VSCode",
        "Visual Studio Code",
    );

    handle_focus_event_sync(
        event,
        &sessions,
        &config,
        &shadow,
        &signing_key,
        &current_focus,
        temp_dir.path(),
        &tx,
    );

    let sessions_map = sessions.read().unwrap();
    assert!(sessions_map.is_empty());
}

#[test]
fn test_handle_focus_gained_with_real_path() {
    let (sessions, config, shadow, signing_key, current_focus, temp_dir, tx) =
        make_focus_test_harness();

    let real_path = temp_dir.path().join("saved_doc.txt");
    std::fs::write(&real_path, "test content").unwrap();
    let gain_event = make_focus_event(
        FocusEventType::FocusGained,
        real_path.to_str().unwrap(),
        "",
        "com.microsoft.VSCode",
        "Visual Studio Code",
    );
    handle_focus_event_sync(
        gain_event,
        &sessions,
        &config,
        &shadow,
        &signing_key,
        &current_focus,
        temp_dir.path(),
        &tx,
    );

    let map = sessions.read().unwrap();
    let real_path_str = real_path.to_str().unwrap();
    assert!(map.contains_key(real_path_str));
    assert!(map[real_path_str].is_focused());
}

#[test]
fn test_handle_focus_lost_clears_current() {
    let (sessions, config, shadow, signing_key, current_focus, temp_dir, tx) =
        make_focus_test_harness();

    // First, gain focus on a document
    let gain_event = make_focus_event(
        FocusEventType::FocusGained,
        "/tmp/test_doc.txt",
        "",
        "com.microsoft.VSCode",
        "Visual Studio Code",
    );
    handle_focus_event_sync(
        gain_event,
        &sessions,
        &config,
        &shadow,
        &signing_key,
        &current_focus,
        temp_dir.path(),
        &tx,
    );
    assert!(current_focus.read().unwrap().is_some());

    // Now lose focus
    let lost_event = make_focus_event(
        FocusEventType::FocusLost,
        "/tmp/test_doc.txt",
        "",
        "com.microsoft.VSCode",
        "Visual Studio Code",
    );
    handle_focus_event_sync(
        lost_event,
        &sessions,
        &config,
        &shadow,
        &signing_key,
        &current_focus,
        temp_dir.path(),
        &tx,
    );

    assert!(current_focus.read().unwrap().is_none());
}

#[test]
fn test_handle_focus_blocked_app_ignored() {
    let (sessions, config, shadow, signing_key, current_focus, temp_dir, tx) =
        make_focus_test_harness();

    let event = make_focus_event(
        FocusEventType::FocusGained,
        "/tmp/test_doc.txt",
        "",
        "com.apple.finder",
        "Finder",
    );

    handle_focus_event_sync(
        event,
        &sessions,
        &config,
        &shadow,
        &signing_key,
        &current_focus,
        temp_dir.path(),
        &tx,
    );

    let sessions_map = sessions.read().unwrap();
    assert!(sessions_map.is_empty());
}
