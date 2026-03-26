// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

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

#[derive(Debug, Clone)]
pub struct SessionEvent {
    pub event_type: SessionEventType,
    pub session_id: String,
    pub document_path: String,
    pub timestamp: SystemTime,
}

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

/// Max jitter samples retained per document to bound memory.
///
/// Memory implication: 50,000 samples * ~24 bytes each = ~1.2 MB per active document.
/// This is intentional; the full session is retained so that post-hoc forensic analysis
/// has access to the complete typing timeline without lossy downsampling. Sessions that
/// exceed this limit drop the oldest samples via the sliding-window eviction in the
/// sentinel. For typical writing sessions (< 10,000 keystrokes) the limit is never hit.
pub const MAX_DOCUMENT_JITTER_SAMPLES: usize = 50_000;

/// Record of a focus switch away from the tracked document.
#[derive(Debug, Clone)]
pub struct FocusSwitchRecord {
    /// When focus was lost.
    pub lost_at: SystemTime,
    /// When focus was regained (None if not yet regained).
    pub regained_at: Option<SystemTime>,
    /// App that received focus.
    pub target_app: String,
    /// Bundle ID of the app that received focus.
    pub target_bundle_id: String,
}

#[derive(Debug, Clone)]
pub struct DocumentSession {
    pub path: String,
    pub session_id: String,
    pub shadow_id: Option<String>,
    pub start_time: SystemTime,
    pub last_focus_time: SystemTime,
    pub total_focus_ms: i64,
    pub focus_count: u32,
    pub initial_hash: Option<String>,
    pub current_hash: Option<String>,
    pub save_count: u32,
    pub change_count: u32,
    pub keystroke_count: u64,
    pub app_bundle_id: String,
    pub app_name: String,
    pub window_title: ObfuscatedString,
    /// Per-document jitter samples for forensic analysis.
    pub jitter_samples: Vec<crate::jitter::SimpleJitterSample>,
    /// Focus loss events during this session (timestamps when user switched away).
    pub focus_switches: Vec<FocusSwitchRecord>,
    pub(crate) has_focus: bool,
    pub(crate) focus_started: Option<Instant>,
    pub event_validation: crate::forensics::event_validation::EventValidationState,
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
            keystroke_count: 0,
            app_bundle_id,
            app_name,
            window_title,
            jitter_samples: Vec::new(),
            focus_switches: Vec::new(),
            has_focus: false,
            focus_started: None,
            event_validation: Default::default(),
        }
    }

    pub fn focus_gained(&mut self) {
        if !self.has_focus {
            self.has_focus = true;
            self.focus_started = Some(Instant::now());
            self.last_focus_time = SystemTime::now();
            self.focus_count += 1;
        }
    }

    pub fn focus_lost(&mut self) {
        if self.has_focus {
            if let Some(started) = self.focus_started.take() {
                self.total_focus_ms +=
                    i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX);
            }
            self.has_focus = false;
        }
    }

    pub fn is_focused(&self) -> bool {
        self.has_focus
    }

    pub fn average_event_confidence(&self) -> f64 {
        self.event_validation.average_confidence()
    }

    /// Includes currently active focus interval if focused.
    pub fn total_focus_duration(&self) -> Duration {
        let mut total = Duration::from_millis(self.total_focus_ms as u64);
        if let Some(started) = self.focus_started {
            total += started.elapsed();
        }
        total
    }
}

/// Generate a 64-char hex session ID (32 random bytes).
/// Wal::open requires a `[u8; 32]` session key, so 32 bytes ensures
/// the hex string decodes without truncation or padding.
pub fn generate_session_id() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    let bytes: [u8; 32] = rng.random();
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
    pub fn file(path: impl Into<PathBuf>) -> Self {
        Self::FilePath(path.into())
    }

    pub fn app_context(bundle_id: impl Into<String>, window_title: &str) -> Self {
        let window_hash = hash_string(window_title);
        let shadow_id = generate_session_id();
        Self::AppContext {
            bundle_id: bundle_id.into(),
            window_hash,
            shadow_id,
        }
    }

    pub fn url_context(url: &str) -> Self {
        let (domain, path) = parse_url_parts(url);
        Self::UrlContext {
            domain_hash: hash_string(&domain),
            page_hash: hash_string(&path),
        }
    }

    pub fn universal() -> Self {
        Self::Universal {
            session_id: generate_session_id(),
        }
    }

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

/// Electron-based editors that don't expose `AXDocument` and need title parsing.
const ELECTRON_EDITORS: &[&str] = &[
    "abnerworks.Typora",
    "com.typora.Typora",
    "md.obsidian",
    "com.zettlr.app",
    "com.github.marktext",
    "com.logseq.logseq",
];

/// Window title fragments that indicate no real document is open.
const SKIP_TITLE_FRAGMENTS: &[&str] = &[
    "untitled",
    "no file",
    "welcome",
    "settings",
    "preferences",
    "get started",
    "graph view",
    "daily note", // Obsidian/Logseq generated view, not a user file
];

/// Infer a document file path from a window title like `"file.rs - VSCode"`.
///
/// Splits on common separators (`" - "`, `" \u{2014} "`, `" | "`) and checks
/// segments for known file extensions or absolute path patterns.
pub fn infer_document_path_from_title(title: &str) -> Option<String> {
    infer_document_path_from_title_with_bundle(title, None)
}

/// Enhanced title inference that uses the app bundle ID for app-specific parsing.
///
/// When `bundle_id` identifies an Electron editor that never exposes `AXDocument`,
/// the function relaxes its heuristic: it will accept a bare filename even without
/// a recognized extension, as long as it doesn't look like a non-document title
/// (e.g. "Untitled", "Settings", "Graph View").
pub fn infer_document_path_from_title_with_bundle(
    title: &str,
    bundle_id: Option<&str>,
) -> Option<String> {
    if title.is_empty() {
        return None;
    }

    let is_electron_editor = bundle_id
        .map(|id| ELECTRON_EDITORS.iter().any(|e| e.eq_ignore_ascii_case(id)))
        .unwrap_or(false);

    // Try standard separator-based extraction first.
    let separators = [" \u{2014} ", " - ", " | "];
    for sep in &separators {
        if let Some(idx) = title.find(sep) {
            let left = title[..idx].trim();
            if looks_like_file_path(left) {
                return Some(left.to_string());
            }
            // For Electron editors, accept the left segment as a document name
            // even without a recognized extension, unless it's a skip-title.
            if is_electron_editor && looks_like_document_name(left) {
                return Some(left.to_string());
            }
            // Also check remaining segments (right side, further splits).
            let rest = &title[idx + sep.len()..];
            let remaining: Vec<&str> = rest.split(sep).collect();
            for segment in &remaining {
                let segment = segment.trim();
                if looks_like_file_path(segment) {
                    return Some(segment.to_string());
                }
            }
        }
    }

    // No separator found — check the whole title.
    let trimmed = title.trim();
    if looks_like_file_path(trimmed) {
        return Some(trimmed.to_string());
    }
    if is_electron_editor && looks_like_document_name(trimmed) {
        return Some(trimmed.to_string());
    }

    None
}

fn looks_like_file_path(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }

    // Windows absolute path: C:\... or C:/...
    if s.len() >= 3
        && s.as_bytes().get(1) == Some(&b':')
        && matches!(s.as_bytes().get(2), Some(&b'\\') | Some(&b'/'))
    {
        return true;
    }
    // Unix absolute path
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

/// Check if `s` looks like a plausible document name for an Electron editor.
///
/// Rejects known non-document titles ("Untitled", "Settings", etc.) and
/// strings that are too short or suspiciously long.
fn looks_like_document_name(s: &str) -> bool {
    if s.is_empty() || s.len() > 260 {
        return false;
    }

    let lower = s.to_lowercase();

    // Reject known non-document fragments.
    for frag in SKIP_TITLE_FRAGMENTS {
        if lower.contains(frag) {
            return false;
        }
    }

    // Must contain at least one alphanumeric character.
    if !s.chars().any(|c| c.is_alphanumeric()) {
        return false;
    }

    true
}

/// Returns `None` if the path contains traversal components or cannot be resolved.
pub fn normalize_document_path(path: &str) -> Option<String> {
    let p = Path::new(path);

    for component in p.components() {
        if matches!(component, std::path::Component::ParentDir) {
            log::warn!("Rejected path with traversal component: '{path}'");
            return None;
        }
    }

    match p.canonicalize() {
        Ok(canonical) => Some(canonical.to_string_lossy().to_string()),
        Err(e) => {
            log::warn!("Failed to canonicalize path '{path}': {e}");
            None
        }
    }
}
