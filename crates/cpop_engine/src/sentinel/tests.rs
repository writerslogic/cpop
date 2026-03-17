// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::*;
use crate::config::SentinelConfig;
use crate::crypto::ObfuscatedString;
use std::fs;

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
