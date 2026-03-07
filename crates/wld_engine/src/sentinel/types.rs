// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::crypto::ObfuscatedString;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FocusEventType {
    FocusGained,
    FocusLost,
    FocusUnknown,
}

#[derive(Debug, Clone)]
pub struct FocusEvent {
    pub event_type: FocusEventType,
    pub path: String,
    pub shadow_id: String,
    pub app_bundle_id: String,
    pub app_name: String,
    pub window_title: ObfuscatedString,
    pub timestamp: SystemTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeEventType {
    Modified,
    Saved,
    Created,
    Deleted,
}

/// File change event from the platform monitor.
#[derive(Debug, Clone)]
pub struct ChangeEvent {
    pub event_type: ChangeEventType,
    pub path: String,
    pub hash: Option<String>,
    pub size: Option<i64>,
    pub timestamp: SystemTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEventType {
    Started,
    Focused,
    Unfocused,
    Saved,
    Ended,
}

/// Session lifecycle event broadcast to subscribers.
#[derive(Debug, Clone)]
pub struct SessionEvent {
    pub event_type: SessionEventType,
    pub session_id: String,
    pub document_path: String,
    pub timestamp: SystemTime,
}

/// Information about the currently focused window.
#[derive(Debug, Clone)]
pub struct WindowInfo {
    pub path: Option<String>,
    pub application: String,
    pub title: ObfuscatedString,
    pub pid: Option<u32>,
    pub timestamp: SystemTime,
    pub is_document: bool,
    pub is_unsaved: bool,
    /// IDE workspace/project root, if detected
    pub project_root: Option<String>,
}

impl Default for WindowInfo {
    fn default() -> Self {
        Self {
            path: None,
            application: String::new(),
            title: ObfuscatedString::default(),
            pid: None,
            timestamp: SystemTime::now(),
            is_document: false,
            is_unsaved: false,
            project_root: None,
        }
    }
}

/// Tracks a single document's editing session.
#[derive(Debug, Clone)]
pub struct DocumentSession {
    pub path: String,
    pub session_id: String,
    /// Shadow buffer ID for unsaved documents
    pub shadow_id: Option<String>,
    pub start_time: SystemTime,
    pub last_focus_time: SystemTime,
    /// Total focused time in milliseconds
    pub total_focus_ms: i64,
    pub focus_count: u32,
    pub initial_hash: Option<String>,
    pub current_hash: Option<String>,
    pub save_count: u32,
    pub change_count: u32,
    pub app_bundle_id: String,
    pub app_name: String,
    pub window_title: ObfuscatedString,
    pub(crate) has_focus: bool,
    pub(crate) focus_started: Option<Instant>,
}

impl DocumentSession {
    pub fn new(
        path: String,
        app_bundle_id: String,
        app_name: String,
        window_title: ObfuscatedString,
    ) -> Self {
        let session_id = generate_session_id();
        let now = SystemTime::now();

        Self {
            path,
            session_id,
            shadow_id: None,
            start_time: now,
            last_focus_time: now,
            total_focus_ms: 0,
            focus_count: 0,
            initial_hash: None,
            current_hash: None,
            save_count: 0,
            change_count: 0,
            app_bundle_id,
            app_name,
            window_title,
            has_focus: false,
            focus_started: None,
        }
    }

    /// Record focus gained; starts the focus timer.
    pub fn focus_gained(&mut self) {
        if !self.has_focus {
            self.has_focus = true;
            self.focus_started = Some(Instant::now());
            self.last_focus_time = SystemTime::now();
            self.focus_count += 1;
        }
    }

    /// Record focus lost; accumulates elapsed focus time.
    pub fn focus_lost(&mut self) {
        if self.has_focus {
            if let Some(started) = self.focus_started.take() {
                self.total_focus_ms += started.elapsed().as_millis() as i64;
            }
            self.has_focus = false;
        }
    }

    pub fn is_focused(&self) -> bool {
        self.has_focus
    }

    /// Total focus duration, including currently active focus interval.
    pub fn total_focus_duration(&self) -> Duration {
        let mut total = Duration::from_millis(self.total_focus_ms as u64);
        if let Some(started) = self.focus_started {
            total += started.elapsed();
        }
        total
    }
}

pub fn generate_session_id() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    let bytes: [u8; 16] = rng.random();
    hex::encode(bytes)
}

/// Binding context for sessions that may lack a traditional file path
/// (unsaved documents, browser editors, universal keystrokes).
#[derive(Debug, Clone)]
pub enum SessionBinding {
    FilePath(PathBuf),

    AppContext {
        bundle_id: String,
        window_hash: String,
        shadow_id: String,
    },

    /// Browser-based editors; components are hashed for privacy
    UrlContext {
        domain_hash: String,
        page_hash: String,
    },

    /// No specific document (universal keystroke capture)
    Universal {
        session_id: String,
    },
}

impl SessionBinding {
    /// Bind to a file path.
    pub fn file(path: impl Into<PathBuf>) -> Self {
        Self::FilePath(path.into())
    }

    /// Bind to an app context (unsaved document).
    pub fn app_context(bundle_id: impl Into<String>, window_title: &str) -> Self {
        let window_hash = hash_string(window_title);
        let shadow_id = generate_session_id();
        Self::AppContext {
            bundle_id: bundle_id.into(),
            window_hash,
            shadow_id,
        }
    }

    /// Bind to a URL context (browser editor). Components are hashed.
    pub fn url_context(url: &str) -> Self {
        let (domain, path) = parse_url_parts(url);
        Self::UrlContext {
            domain_hash: hash_string(&domain),
            page_hash: hash_string(&path),
        }
    }

    /// Bind to a universal session (no specific document).
    pub fn universal() -> Self {
        Self::Universal {
            session_id: generate_session_id(),
        }
    }

    /// Unique key for session map lookup.
    pub fn key(&self) -> String {
        match self {
            Self::FilePath(path) => path.to_string_lossy().to_string(),
            Self::AppContext { shadow_id, .. } => format!("app:{}", shadow_id),
            Self::UrlContext {
                domain_hash,
                page_hash,
            } => format!("url:{}:{}", domain_hash, page_hash),
            Self::Universal { session_id } => format!("universal:{}", session_id),
        }
    }

    pub fn has_file_path(&self) -> bool {
        matches!(self, Self::FilePath(_))
    }

    pub fn file_path(&self) -> Option<&Path> {
        match self {
            Self::FilePath(path) => Some(path),
            _ => None,
        }
    }
}

pub fn hash_string(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let result = hasher.finalize();
    hex::encode(&result[..8])
}

pub fn parse_url_parts(url: &str) -> (String, String) {
    let url = url
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let parts: Vec<&str> = url.splitn(2, '/').collect();
    let domain = parts.first().unwrap_or(&"").to_string();
    let path = parts.get(1).unwrap_or(&"").to_string();

    // Validate domain looks plausible (non-empty, contains at least one dot).
    // Malformed inputs get a distinguishing prefix so their hash never
    // collides with a legitimate domain hash.
    if domain.is_empty() || !domain.contains('.') {
        log::warn!(
            "parse_url_parts: malformed domain {:?}, prefixing hash input",
            domain
        );
        return (format!("invalid:{}", domain), path);
    }

    (domain, path)
}

/// Known document file extensions for heuristic title-based path inference.
const DOC_EXTENSIONS: &[&str] = &[
    ".docx", ".doc", ".txt", ".md", ".rtf", ".odt", ".tex", ".pdf", ".xlsx", ".xls", ".csv",
    ".pptx", ".ppt", ".rs", ".py", ".js", ".ts", ".jsx", ".tsx", ".c", ".cpp", ".h", ".java",
    ".go", ".rb", ".swift", ".kt", ".html", ".css", ".json", ".xml", ".yaml", ".yml", ".toml",
    ".sh", ".bat", ".ps1",
];

/// Infer a document file path from a window title like `"file.rs - VSCode"`.
///
/// Splits on common separators (`" - "`, `" | "`) and checks segments
/// for known file extensions or absolute path patterns.
pub fn infer_document_path_from_title(title: &str) -> Option<String> {
    if title.is_empty() {
        return None;
    }

    let separators = [" - ", " \u{2014} ", " | "];
    for sep in &separators {
        if title.contains(sep) {
            let segments: Vec<&str> = title.split(sep).collect();
            for segment in &segments {
                let segment = segment.trim();
                if looks_like_file_path(segment) {
                    return Some(segment.to_string());
                }
            }
        }
    }

    // Last resort: check the entire title
    if looks_like_file_path(title.trim()) {
        return Some(title.trim().to_string());
    }

    None
}

/// Heuristic: looks like a file path (absolute path prefix or known extension).
fn looks_like_file_path(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }

    if s.len() >= 3
        && s.as_bytes().get(1) == Some(&b':')
        && matches!(s.as_bytes().get(2), Some(&b'\\') | Some(&b'/'))
    {
        return true;
    }
    if s.starts_with('/') && s.len() > 1 {
        return true;
    }

    let lower = s.to_lowercase();
    for ext in DOC_EXTENSIONS {
        if lower.ends_with(ext) {
            return true;
        }
    }

    false
}

/// Normalize a document path to an absolute canonical form.
/// Returns `None` if the path contains traversal components or cannot be resolved.
pub fn normalize_document_path(path: &str) -> Option<String> {
    let p = Path::new(path);

    // Reject path traversal components before any filesystem interaction
    for component in p.components() {
        if matches!(component, std::path::Component::ParentDir) {
            log::warn!("Rejected path with traversal component: '{path}'");
            return None;
        }
    }

    match p.canonicalize() {
        Ok(canonical) => Some(canonical.to_string_lossy().to_string()),
        Err(e) => {
            // Path doesn't exist or can't be resolved — refuse to guess
            log::warn!("Failed to canonicalize path '{path}': {e}");
            None
        }
    }
}
