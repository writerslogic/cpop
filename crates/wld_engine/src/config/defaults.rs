// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::path::PathBuf;

pub(super) fn default_true() -> bool {
    true
}

pub(super) fn default_false() -> bool {
    false
}

pub(super) fn default_data_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        dirs::home_dir()
            .map(|h| h.join("Library/Application Support/WritersLogic"))
            .unwrap_or_else(|| PathBuf::from(".writerslogic"))
    }
    #[cfg(not(target_os = "macos"))]
    {
        dirs::home_dir()
            .map(|h| h.join(".writerslogic"))
            .unwrap_or_else(|| PathBuf::from(".writerslogic"))
    }
}

pub(super) fn default_watch_dirs() -> Vec<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        dirs::home_dir()
            .map(|h| vec![h.join("Documents"), h.join("Desktop")])
            .unwrap_or_default()
    }
    #[cfg(not(target_os = "macos"))]
    {
        Vec::new()
    }
}

pub(super) fn default_retention_days() -> u32 {
    30
}

pub(super) fn default_interval() -> u64 {
    600
}

pub(super) fn default_window() -> u64 {
    60
}

pub(super) fn default_ips() -> u64 {
    1_000_000
}

pub(super) fn default_min_iter() -> u64 {
    100_000
}

pub(super) fn default_max_iter() -> u64 {
    3_600_000_000
}

pub(super) fn default_heartbeat() -> u64 {
    60
}

pub(super) fn default_checkpoint() -> u64 {
    60
}

pub(super) fn default_writerslogic_dir() -> PathBuf {
    dirs::home_dir()
        .map(|h| h.join(".writerslogic"))
        .unwrap_or_else(|| PathBuf::from(".writerslogic"))
}

pub(super) fn default_allowed_apps() -> Vec<String> {
    vec![
        // macOS
        "com.apple.TextEdit".to_string(),
        "com.apple.iWork.Pages".to_string(),
        // MS Office
        "com.microsoft.Word".to_string(),
        "com.microsoft.Excel".to_string(),
        "com.microsoft.Powerpoint".to_string(),
        // Editors / IDEs
        "code".to_string(),
        "com.microsoft.VSCode".to_string(),
        "com.sublimetext.4".to_string(),
        "com.jetbrains.intellij".to_string(),
        "com.googlecode.iterm2".to_string(),
        "org.vim.MacVim".to_string(),
        // Writing tools
        "com.typora.Typora".to_string(),
        "md.obsidian".to_string(),
        "com.notion.Notion".to_string(),
        // Browser-based (matched by app_name)
        "Google Docs".to_string(),
        "org.libreoffice.LibreOffice".to_string(),
        // Linux terminals
        "org.gnome.Terminal".to_string(),
        "org.kde.konsole".to_string(),
    ]
}

pub(super) fn default_blocked_apps() -> Vec<String> {
    vec!["com.apple.finder".to_string(), "explorer".to_string()]
}

pub(super) fn default_research_dir() -> PathBuf {
    dirs::home_dir()
        .map(|h| h.join(".writerslogic").join("research"))
        .unwrap_or_else(|| PathBuf::from(".writerslogic/research"))
}

pub(super) fn default_max_research_sessions() -> usize {
    100
}

pub(super) fn default_min_samples_for_research() -> usize {
    10
}

pub(super) fn default_upload_interval() -> u64 {
    4 * 60 * 60
}

pub(super) fn default_fingerprint_retention() -> u32 {
    365
}

pub(super) fn default_min_fingerprint_samples() -> u32 {
    100
}

pub(super) fn default_fingerprint_dir() -> PathBuf {
    dirs::home_dir()
        .map(|h| h.join(".writerslogic").join("fingerprints"))
        .unwrap_or_else(|| PathBuf::from(".writerslogic/fingerprints"))
}

pub(super) fn default_privacy_excluded() -> Vec<String> {
    vec![
        "1Password".to_string(),
        "Keychain Access".to_string(),
        "System Preferences".to_string(),
        "Terminal".to_string(),
    ]
}

pub(super) fn default_writersproof_url() -> String {
    "https://api.writersproof.com".to_string()
}

pub(super) fn default_debounce() -> u64 {
    500
}

pub(super) fn default_idle() -> u64 {
    1800
}

pub(super) fn default_poll() -> u64 {
    100
}
