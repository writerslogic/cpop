#![allow(dead_code)]
//! Active Document Sentinel - Background document tracking daemon
//!
//! The Active Document Sentinel monitors which documents have user focus and
//! manages tracking sessions automatically. It operates invisibly during
//! normal writing, only surfacing when the user explicitly requests status.
//!
//! Key features:
//!   - Automatic detection of focused documents across applications
//!   - Debounced focus change handling (500ms default)
//!   - Multi-document session management
//!   - Shadow buffers for unsaved documents
//!   - Platform-specific focus detection (macOS, Linux, Windows)

use crate::config::SentinelConfig;
use crate::crypto::ObfuscatedString;
use crate::wal::{EntryType, Wal, WalError};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::{broadcast, mpsc};
use tokio::time::interval;

// ============================================================================
// Error Types
// ============================================================================

#[derive(Debug, Error)]
pub enum SentinelError {
    #[error("sentinel: not available on this platform - {0}")]
    NotAvailable(String),

    #[error("sentinel: already running")]
    AlreadyRunning,

    #[error("sentinel: not running")]
    NotRunning,

    #[error("sentinel: session not found for {0}")]
    SessionNotFound(String),

    #[error("sentinel: invalid configuration - {0}")]
    InvalidConfig(String),

    #[error("sentinel: daemon not running")]
    DaemonNotRunning,

    #[error("sentinel: daemon already running (PID {0})")]
    DaemonAlreadyRunning(i32),

    #[error("sentinel: shadow buffer not found - {0}")]
    ShadowNotFound(String),

    #[error("sentinel: io error - {0}")]
    Io(#[from] std::io::Error),

    #[error("sentinel: wal error - {0}")]
    Wal(#[from] WalError),

    #[error("sentinel: serialization error - {0}")]
    Serialization(String),

    #[error("sentinel: channel error - {0}")]
    Channel(String),

    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, SentinelError>;

// ============================================================================
// Configuration (Moved to config.rs)
// ============================================================================

// Methods moved to config.rs

// Defaults moved to config.rs

// ============================================================================
// Event Types
// ============================================================================

/// Focus event type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FocusEventType {
    /// Document gained focus
    FocusGained,
    /// Document lost focus
    FocusLost,
    /// Focus moved to unknown/non-trackable window
    FocusUnknown,
}

/// Focus change event
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

/// Change event type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeEventType {
    /// Document was modified
    Modified,
    /// Document was saved
    Saved,
    /// New document was created
    Created,
    /// Document was deleted
    Deleted,
}

/// File change event
#[derive(Debug, Clone)]
pub struct ChangeEvent {
    pub event_type: ChangeEventType,
    pub path: String,
    pub hash: Option<String>,
    pub size: Option<i64>,
    pub timestamp: SystemTime,
}

/// Session event type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEventType {
    /// New tracking session started
    Started,
    /// Session gained focus
    Focused,
    /// Session lost focus
    Unfocused,
    /// Document was saved
    Saved,
    /// Session ended
    Ended,
}

/// Session state change event
#[derive(Debug, Clone)]
pub struct SessionEvent {
    pub event_type: SessionEventType,
    pub session_id: String,
    pub document_path: String,
    pub timestamp: SystemTime,
}

// ============================================================================
// Window Information (for focus tracking)
// ============================================================================

/// Information about the currently focused window
#[derive(Debug, Clone)]
pub struct WindowInfo {
    /// Resolved file path of the document (if available)
    pub path: Option<String>,
    /// Application name or bundle ID
    pub application: String,
    /// Window title
    pub title: ObfuscatedString,
    /// Process ID of the owning application
    pub pid: Option<u32>,
    /// Timestamp when focus info was captured
    pub timestamp: SystemTime,
    /// Whether this appears to be a document window
    pub is_document: bool,
    /// Whether the document appears to be unsaved
    pub is_unsaved: bool,
    /// Project/workspace root if detected (for IDEs)
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

// ============================================================================
// Document Session
// ============================================================================

/// Tracks a single document's editing session
#[derive(Debug, Clone)]
pub struct DocumentSession {
    /// Document file path
    pub path: String,

    /// Unique session identifier
    pub session_id: String,

    /// Shadow buffer ID for unsaved documents
    pub shadow_id: Option<String>,

    /// Session start time
    pub start_time: SystemTime,

    /// Last focus time
    pub last_focus_time: SystemTime,

    /// Total time focused (milliseconds)
    pub total_focus_ms: i64,

    /// Number of times focused
    pub focus_count: u32,

    /// Initial document hash
    pub initial_hash: Option<String>,

    /// Current document hash
    pub current_hash: Option<String>,

    /// Number of saves
    pub save_count: u32,

    /// Number of changes detected
    pub change_count: u32,

    /// Application bundle ID
    pub app_bundle_id: String,

    /// Application name
    pub app_name: String,

    /// Window title
    pub window_title: ObfuscatedString,

    // Internal state
    has_focus: bool,
    focus_started: Option<Instant>,
}

impl DocumentSession {
    /// Create a new document session
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

    /// Record focus gained
    pub fn focus_gained(&mut self) {
        if !self.has_focus {
            self.has_focus = true;
            self.focus_started = Some(Instant::now());
            self.last_focus_time = SystemTime::now();
            self.focus_count += 1;
        }
    }

    /// Record focus lost
    pub fn focus_lost(&mut self) {
        if self.has_focus {
            if let Some(started) = self.focus_started.take() {
                self.total_focus_ms += started.elapsed().as_millis() as i64;
            }
            self.has_focus = false;
        }
    }

    /// Check if session currently has focus
    pub fn is_focused(&self) -> bool {
        self.has_focus
    }

    /// Get total focus duration
    pub fn total_focus_duration(&self) -> Duration {
        let mut total = Duration::from_millis(self.total_focus_ms as u64);
        if let Some(started) = self.focus_started {
            total += started.elapsed();
        }
        total
    }
}

fn generate_session_id() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    let bytes: [u8; 16] = rng.random();
    hex::encode(bytes)
}

// ============================================================================
// Shadow Buffer Manager
// ============================================================================

/// Shadow buffer for tracking unsaved document content
#[derive(Debug, Clone)]
struct ShadowBuffer {
    id: String,
    app_name: String,
    window_title: ObfuscatedString,
    path: PathBuf,
    created_at: SystemTime,
    updated_at: SystemTime,
    size: i64,
}

/// Manages shadow buffers for unsaved documents
pub struct ShadowManager {
    base_dir: PathBuf,
    shadows: RwLock<HashMap<String, ShadowBuffer>>,
}

impl ShadowManager {
    /// Create a new shadow manager
    pub fn new(base_dir: impl AsRef<Path>) -> Result<Self> {
        let base_dir = base_dir.as_ref().to_path_buf();
        fs::create_dir_all(&base_dir)?;

        Ok(Self {
            base_dir,
            shadows: RwLock::new(HashMap::new()),
        })
    }

    /// Create a new shadow buffer for an unsaved document
    pub fn create(&self, app_name: &str, window_title: &str) -> Result<String> {
        use rand::Rng;
        let mut rng = rand::rng();
        let id_bytes: [u8; 16] = rng.random();
        let id = hex::encode(id_bytes);

        let path = self.base_dir.join(format!("{}.shadow", id));
        File::create(&path)?;

        let shadow = ShadowBuffer {
            id: id.clone(),
            app_name: app_name.to_string(),
            window_title: ObfuscatedString::new(window_title),
            path,
            created_at: SystemTime::now(),
            updated_at: SystemTime::now(),
            size: 0,
        };

        self.shadows.write().unwrap().insert(id.clone(), shadow);

        Ok(id)
    }

    /// Update the content of a shadow buffer
    pub fn update(&self, id: &str, content: &[u8]) -> Result<()> {
        let mut shadows = self.shadows.write().unwrap();
        let shadow = shadows
            .get_mut(id)
            .ok_or_else(|| SentinelError::ShadowNotFound(id.to_string()))?;

        fs::write(&shadow.path, content)?;
        shadow.updated_at = SystemTime::now();
        shadow.size = content.len() as i64;

        Ok(())
    }

    /// Get the file path for a shadow buffer
    pub fn get_path(&self, id: &str) -> Option<PathBuf> {
        self.shadows.read().unwrap().get(id).map(|s| s.path.clone())
    }

    /// Delete a shadow buffer
    pub fn delete(&self, id: &str) -> Result<()> {
        if let Some(shadow) = self.shadows.write().unwrap().remove(id) {
            let _ = fs::remove_file(&shadow.path);
        }
        Ok(())
    }

    /// Migrate a shadow buffer to a real file path (when unsaved document is saved)
    pub fn migrate(&self, id: &str, _new_path: &str) -> Result<()> {
        if let Some(shadow) = self.shadows.write().unwrap().remove(id) {
            let _ = fs::remove_file(&shadow.path);
        }
        Ok(())
    }

    /// Remove all shadow buffers
    pub fn cleanup_all(&self) {
        let mut shadows = self.shadows.write().unwrap();
        for shadow in shadows.values() {
            let _ = fs::remove_file(&shadow.path);
        }
        shadows.clear();
    }

    /// Remove shadow buffers older than max_age
    pub fn cleanup_old(&self, max_age: Duration) -> u32 {
        let cutoff = SystemTime::now() - max_age;
        let mut shadows = self.shadows.write().unwrap();
        let mut removed = 0u32;

        shadows.retain(|_, shadow| {
            if shadow.updated_at < cutoff {
                let _ = fs::remove_file(&shadow.path);
                removed += 1;
                false
            } else {
                true
            }
        });

        removed
    }

    /// List all active shadow buffers
    pub fn list(&self) -> Vec<(String, String, String)> {
        self.shadows
            .read()
            .unwrap()
            .values()
            .map(|s| (s.id.clone(), s.app_name.clone(), s.window_title.reveal()))
            .collect()
    }
}

// ============================================================================
// Focus Monitor Trait
// ============================================================================

/// Platform-specific focus monitoring
pub trait FocusMonitor: Send + Sync {
    /// Start monitoring for focus changes
    fn start(&self) -> Result<()>;

    /// Stop monitoring
    fn stop(&self) -> Result<()>;

    /// Get the current window info
    fn active_window(&self) -> Option<WindowInfo>;

    /// Check if monitoring is available on this platform
    fn available(&self) -> (bool, String);

    /// Get focus events receiver
    fn focus_events(&self) -> mpsc::Receiver<FocusEvent>;

    /// Get change events receiver
    fn change_events(&self) -> mpsc::Receiver<ChangeEvent>;
}

/// Provider for active window information (platform-specific)
pub trait WindowProvider: Send + Sync + 'static {
    fn get_active_window(&self) -> Option<WindowInfo>;
}

/// Generic polling focus monitor that uses a WindowProvider
pub struct PollingFocusMonitor<P: WindowProvider + ?Sized> {
    provider: Arc<P>,
    config: SentinelConfig,
    running: Arc<RwLock<bool>>,
    focus_tx: mpsc::Sender<FocusEvent>,
    focus_rx: Arc<Mutex<Option<mpsc::Receiver<FocusEvent>>>>,
    change_tx: mpsc::Sender<ChangeEvent>,
    change_rx: Arc<Mutex<Option<mpsc::Receiver<ChangeEvent>>>>,
    poll_handle: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

impl<P: WindowProvider + ?Sized> PollingFocusMonitor<P> {
    pub fn new(provider: Arc<P>, config: SentinelConfig) -> Self {
        let (focus_tx, focus_rx) = mpsc::channel(100);
        let (change_tx, change_rx) = mpsc::channel(100);

        Self {
            provider,
            config,
            running: Arc::new(RwLock::new(false)),
            focus_tx,
            focus_rx: Arc::new(Mutex::new(Some(focus_rx))),
            change_tx,
            change_rx: Arc::new(Mutex::new(Some(change_rx))),
            poll_handle: Arc::new(Mutex::new(None)),
        }
    }
}

impl<P: WindowProvider + ?Sized> FocusMonitor for PollingFocusMonitor<P> {
    fn start(&self) -> Result<()> {
        let mut running = self.running.write().unwrap();
        if *running {
            return Err(SentinelError::AlreadyRunning);
        }
        *running = true;
        drop(running);

        let running_clone = Arc::clone(&self.running);
        let focus_tx = self.focus_tx.clone();
        let config = self.config.clone();
        let provider = Arc::clone(&self.provider);
        let poll_interval = Duration::from_millis(self.config.poll_interval_ms);

        // Start polling loop
        let handle = tokio::spawn(async move {
            let mut last_app = String::new();
            let mut interval_timer = interval(poll_interval);

            loop {
                interval_timer.tick().await;

                if !*running_clone.read().unwrap() {
                    break;
                }

                if let Some(info) = provider.get_active_window() {
                    let current_app = if !info.application.is_empty() {
                        info.application.clone()
                    } else {
                        "unknown".to_string()
                    };

                    // Check if focus changed
                    if current_app != last_app {
                        // Send focus lost for previous app
                        if !last_app.is_empty() {
                            let _ = focus_tx
                                .send(FocusEvent {
                                    event_type: FocusEventType::FocusLost,
                                    path: String::new(),
                                    shadow_id: String::new(),
                                    app_bundle_id: last_app.clone(),
                                    app_name: String::new(),
                                    window_title: ObfuscatedString::default(),
                                    timestamp: SystemTime::now(),
                                })
                                .await;
                        }

                        // Check if new app should be tracked
                        let app_name = info.application.clone();
                        if config.is_app_allowed(&info.application, &app_name) {
                            let _ = focus_tx
                                .send(FocusEvent {
                                    event_type: FocusEventType::FocusGained,
                                    path: info.path.clone().unwrap_or_default(),
                                    shadow_id: String::new(),
                                    app_bundle_id: info.application.clone(),
                                    app_name: info.application.clone(),
                                    window_title: info.title.clone(),
                                    timestamp: SystemTime::now(),
                                })
                                .await;
                        }

                        last_app = current_app;
                    }
                }
            }
        });

        *self.poll_handle.lock().unwrap() = Some(handle);
        Ok(())
    }

    fn stop(&self) -> Result<()> {
        let mut running = self.running.write().unwrap();
        if !*running {
            return Ok(());
        }
        *running = false;
        drop(running);

        if let Some(handle) = self.poll_handle.lock().unwrap().take() {
            handle.abort();
        }

        Ok(())
    }

    fn active_window(&self) -> Option<WindowInfo> {
        self.provider.get_active_window()
    }

    fn available(&self) -> (bool, String) {
        (true, "Polling monitor available".to_string())
    }

    fn focus_events(&self) -> mpsc::Receiver<FocusEvent> {
        self.focus_rx.lock().unwrap().take().unwrap()
    }

    fn change_events(&self) -> mpsc::Receiver<ChangeEvent> {
        self.change_rx.lock().unwrap().take().unwrap()
    }
}

// ============================================================================
// macOS Focus Monitor
// ============================================================================

#[cfg(target_os = "macos")]
pub mod macos_focus {
    use super::*;
    use objc::runtime::Object;
    use std::ptr::null_mut;

    /// macOS-specific focus monitor using NSWorkspace and Accessibility APIs
    pub struct MacOSFocusMonitor {
        config: SentinelConfig,
    }

    impl MacOSFocusMonitor {
        pub fn new(config: SentinelConfig) -> Self {
            Self { config }
        }

        pub fn new_monitor(config: SentinelConfig) -> Box<dyn FocusMonitor> {
            let provider = Arc::new(Self::new(config.clone()));
            Box::new(PollingFocusMonitor::new(provider, config))
        }

        /// Get the active window info using NSWorkspace
        fn get_active_window_info(&self) -> Option<WindowInfo> {
            unsafe {
                let workspace: *mut Object = msg_send![class!(NSWorkspace), sharedWorkspace];
                let active_app: *mut Object = msg_send![workspace, frontmostApplication];

                if active_app == null_mut() {
                    return None;
                }

                let name: *mut Object = msg_send![active_app, localizedName];
                let bundle_id: *mut Object = msg_send![active_app, bundleIdentifier];
                let pid: i32 = msg_send![active_app, processIdentifier];

                let app_name = nsstring_to_string(name);
                let bundle_id_str = nsstring_to_string(bundle_id);

                // Try to get document path via Accessibility API
                let doc_path = self.get_document_path_via_ax(pid);
                let window_title = self.get_window_title_via_ax(pid);

                Some(WindowInfo {
                    path: doc_path.clone(),
                    application: if !bundle_id_str.is_empty() {
                        bundle_id_str
                    } else {
                        app_name.clone()
                    },
                    title: ObfuscatedString::new(&window_title.unwrap_or_default()),
                    pid: Some(pid as u32),
                    timestamp: SystemTime::now(),
                    is_document: doc_path.is_some(),
                    is_unsaved: false,
                    project_root: None,
                })
            }
        }

        /// Get document path using Accessibility API
        fn get_document_path_via_ax(&self, pid: i32) -> Option<String> {
            // This would use AXUIElement to get the document path
            // For now, returning None as the full implementation requires
            // linking against ApplicationServices framework
            let _ = pid;
            None
        }

        /// Get window title using Accessibility API
        fn get_window_title_via_ax(&self, pid: i32) -> Option<String> {
            let _ = pid;
            None
        }
    }

    impl WindowProvider for MacOSFocusMonitor {
        fn get_active_window(&self) -> Option<WindowInfo> {
            self.get_active_window_info()
        }
    }

    unsafe fn nsstring_to_string(ns_str: *mut Object) -> String {
        if ns_str == null_mut() {
            return String::new();
        }
        let char_ptr: *const std::os::raw::c_char = msg_send![ns_str, UTF8String];
        if char_ptr.is_null() {
            return String::new();
        }
        std::ffi::CStr::from_ptr(char_ptr)
            .to_string_lossy()
            .into_owned()
    }

    /// Check if accessibility permissions are granted
    pub fn check_accessibility_permissions() -> bool {
        use core_foundation::base::TCFType;
        use core_foundation::boolean::CFBoolean;
        use core_foundation::dictionary::CFDictionary;
        use core_foundation::string::CFString;

        #[link(name = "ApplicationServices", kind = "framework")]
        extern "C" {
            fn AXIsProcessTrustedWithOptions(
                options: core_foundation::dictionary::CFDictionaryRef,
            ) -> bool;
        }

        let key = CFString::new("AXTrustedCheckOptionPrompt");
        let value = CFBoolean::false_value();
        let dict = CFDictionary::from_CFType_pairs(&[(key.as_CFType(), value.as_CFType())]);

        unsafe { AXIsProcessTrustedWithOptions(dict.as_concrete_TypeRef()) }
    }

    /// Request accessibility permissions (shows system dialog)
    pub fn request_accessibility_permissions() -> bool {
        use core_foundation::base::TCFType;
        use core_foundation::boolean::CFBoolean;
        use core_foundation::dictionary::CFDictionary;
        use core_foundation::string::CFString;

        #[link(name = "ApplicationServices", kind = "framework")]
        extern "C" {
            fn AXIsProcessTrustedWithOptions(
                options: core_foundation::dictionary::CFDictionaryRef,
            ) -> bool;
        }

        let key = CFString::new("AXTrustedCheckOptionPrompt");
        let value = CFBoolean::true_value();
        let dict = CFDictionary::from_CFType_pairs(&[(key.as_CFType(), value.as_CFType())]);

        unsafe { AXIsProcessTrustedWithOptions(dict.as_concrete_TypeRef()) }
    }
}

// ============================================================================
// Stub Focus Monitor (for unsupported platforms)
// ============================================================================

#[cfg(not(target_os = "macos"))]
pub mod stub_focus {
    use super::*;

    /// Stub focus monitor for unsupported platforms
    pub struct StubFocusMonitor {
        focus_rx: Arc<Mutex<Option<mpsc::Receiver<FocusEvent>>>>,
        change_rx: Arc<Mutex<Option<mpsc::Receiver<ChangeEvent>>>>,
    }

    impl StubFocusMonitor {
        pub fn new(_config: SentinelConfig) -> Self {
            let (_focus_tx, focus_rx) = mpsc::channel(1);
            let (_change_tx, change_rx) = mpsc::channel(1);
            Self {
                focus_rx: Arc::new(Mutex::new(Some(focus_rx))),
                change_rx: Arc::new(Mutex::new(Some(change_rx))),
            }
        }
    }

    impl FocusMonitor for StubFocusMonitor {
        fn start(&self) -> Result<()> {
            Err(SentinelError::NotAvailable(
                "Focus monitoring not available on this platform".to_string(),
            ))
        }

        fn stop(&self) -> Result<()> {
            Ok(())
        }

        fn active_window(&self) -> Option<WindowInfo> {
            None
        }

        fn available(&self) -> (bool, String) {
            (
                false,
                "Focus monitoring not available on this platform".to_string(),
            )
        }

        fn focus_events(&self) -> mpsc::Receiver<FocusEvent> {
            self.focus_rx.lock().unwrap().take().unwrap()
        }

        fn change_events(&self) -> mpsc::Receiver<ChangeEvent> {
            self.change_rx.lock().unwrap().take().unwrap()
        }
    }
}

// ============================================================================
// Windows Focus Monitor
// ============================================================================

#[cfg(target_os = "windows")]
pub mod windows_focus {
    use super::*;
    use windows::Win32::UI::WindowsAndMessaging::{
        GetForegroundWindow, GetWindowThreadProcessId, GetWindowTextW,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    use windows::core::PWSTR;

    pub struct WindowsFocusMonitor {
        config: SentinelConfig,
    }

    impl WindowsFocusMonitor {
        pub fn new(config: SentinelConfig) -> Self {
            Self { config }
        }

        pub fn new_monitor(config: SentinelConfig) -> Box<dyn FocusMonitor> {
            let provider = Arc::new(Self::new(config.clone()));
            Box::new(PollingFocusMonitor::new(provider, config))
        }
    }

    impl WindowProvider for WindowsFocusMonitor {
        fn get_active_window(&self) -> Option<WindowInfo> {
            unsafe {
                let hwnd = GetForegroundWindow();
                if hwnd.0 == 0 {
                    return None;
                }

                let mut pid = 0u32;
                GetWindowThreadProcessId(hwnd, Some(&mut pid));

                let path = get_process_path(pid).ok()?;
                let app_name = Path::new(&path)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();

                // Get window title
                let mut title_buf = [0u16; 512];
                let len = GetWindowTextW(hwnd, &mut title_buf);
                let title = String::from_utf16_lossy(&title_buf[..len as usize]);

                // Try to infer document path from title if possible (heuristic)
                // Real document path extraction on Windows often requires UI Automation (complex)
                let doc_path = if title.contains(" - ") {
                    // Very naive heuristic: "Document.txt - Notepad"
                    // Just a placeholder for now
                    None
                } else {
                    None
                };

                Some(WindowInfo {
                    path: doc_path,
                    application: app_name,
                    title: ObfuscatedString::new(&title),
                    pid: Some(pid),
                    timestamp: SystemTime::now(),
                    is_document: false, // Default to false until better heuristics
                    is_unsaved: false,
                    project_root: None,
                })
            }
        }
    }

    fn get_process_path(pid: u32) -> Result<String, std::io::Error> {
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)?;
            let mut path = [0u16; 1024];
            let mut size = path.len() as u32;
            QueryFullProcessImageNameW(handle, Default::default(), PWSTR(path.as_mut_ptr()), &mut size)?;
            Ok(String::from_utf16_lossy(&path[..size as usize]))
        }
    }
}

// ============================================================================
// Sentinel Daemon
// ============================================================================

/// The Active Document Sentinel daemon
pub struct Sentinel {
    config: SentinelConfig,
    sessions: Arc<RwLock<HashMap<String, DocumentSession>>>,
    shadow: Arc<ShadowManager>,
    current_focus: Arc<RwLock<Option<String>>>,
    running: Arc<RwLock<bool>>,
    signing_key: Arc<RwLock<SigningKey>>,
    session_events_tx: broadcast::Sender<SessionEvent>,
    shutdown_tx: Arc<Mutex<Option<mpsc::Sender<()>>>>,
}

impl Sentinel {
    /// Create a new Sentinel with the given configuration
    pub fn new(config: SentinelConfig) -> Result<Self> {
        config.validate().map_err(SentinelError::Anyhow)?;
        config.ensure_directories().map_err(SentinelError::Anyhow)?;

        let shadow = ShadowManager::new(&config.shadow_dir)?;
        let (session_events_tx, _) = broadcast::channel(100);

        Ok(Self {
            config,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            shadow: Arc::new(shadow),
            current_focus: Arc::new(RwLock::new(None)),
            running: Arc::new(RwLock::new(false)),
            signing_key: Arc::new(RwLock::new(SigningKey::from_bytes(&[0u8; 32]))),
            session_events_tx,
            shutdown_tx: Arc::new(Mutex::new(None)),
        })
    }

    /// Set the signing key for WAL integrity
    pub fn set_signing_key(&self, key: SigningKey) {
        *self.signing_key.write().unwrap() = key;
    }

    /// Set the HMAC key for WAL integrity
    pub fn set_hmac_key(&self, key: Vec<u8>) {
        if key.len() == 32 {
            let bytes: [u8; 32] = key.try_into().unwrap();
            *self.signing_key.write().unwrap() = SigningKey::from_bytes(&bytes);
        }
    }

    /// Start the sentinel daemon
    pub async fn start(&self) -> Result<()> {
        {
            let mut running = self.running.write().unwrap();
            if *running {
                return Err(SentinelError::AlreadyRunning);
            }
            *running = true;
        }

        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        *self.shutdown_tx.lock().unwrap() = Some(shutdown_tx);

        // Create platform-specific focus monitor
        #[cfg(target_os = "macos")]
        let focus_monitor: Box<dyn FocusMonitor> =
            macos_focus::MacOSFocusMonitor::new_monitor(self.config.clone());

        #[cfg(target_os = "windows")]
        let focus_monitor: Box<dyn FocusMonitor> =
            windows_focus::WindowsFocusMonitor::new_monitor(self.config.clone());

        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        let focus_monitor: Box<dyn FocusMonitor> =
            Box::new(stub_focus::StubFocusMonitor::new(self.config.clone()));

        // Check availability
        let (available, reason) = focus_monitor.available();
        if !available {
            *self.running.write().unwrap() = false;
            return Err(SentinelError::NotAvailable(reason));
        }

        // Start focus monitoring
        focus_monitor.start()?;

        let sessions = Arc::clone(&self.sessions);
        let current_focus = Arc::clone(&self.current_focus);
        let config = self.config.clone();
        let shadow = Arc::clone(&self.shadow);
        let signing_key = Arc::clone(&self.signing_key);
        let session_events_tx = self.session_events_tx.clone();
        let running = Arc::clone(&self.running);
        let debounce_duration = Duration::from_millis(config.debounce_duration_ms);
        let idle_timeout = Duration::from_secs(config.idle_timeout_secs);
        let wal_dir = config.wal_dir.clone();

        // Get event receivers
        let mut focus_rx = focus_monitor.focus_events();
        let mut change_rx = focus_monitor.change_events();

        // Main event loop
        tokio::spawn(async move {
            let mut debounce_timer: Option<tokio::time::Instant> = None;
            let mut pending_focus: Option<FocusEvent> = None;
            let mut idle_check_interval = interval(Duration::from_secs(60));

            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        // Graceful shutdown
                        break;
                    }

                    Some(event) = focus_rx.recv() => {
                        // Debounce focus changes
                        pending_focus = Some(event);
                        debounce_timer = Some(tokio::time::Instant::now() + debounce_duration);
                    }

                    Some(event) = change_rx.recv() => {
                        // Handle file change events (synchronously)
                            handle_change_event_sync(
                                &event,
                                &sessions,
                                &signing_key,
                                &wal_dir,
                                &session_events_tx,
                            );

                    }

                    _ = idle_check_interval.tick() => {
                        // Check for idle sessions (synchronously)
                        check_idle_sessions_sync(&sessions, idle_timeout, &session_events_tx);
                    }

                    _ = async {
                        if let Some(deadline) = debounce_timer {
                            tokio::time::sleep_until(deadline).await;
                            true
                        } else {
                            std::future::pending::<bool>().await
                        }
                    } => {
                        // Apply debounced focus change (synchronously)
                        if let Some(event) = pending_focus.take() {
                            handle_focus_event_sync(
                                event,
                                &sessions,
                                &config,
                                &shadow,
                                &signing_key,
                                &current_focus,
                                &wal_dir,
                                &session_events_tx,
                            );
                        }
                        debounce_timer = None;
                    }
                }

                if !*running.read().unwrap() {
                    break;
                }
            }

            // Stop focus monitor
            let _ = focus_monitor.stop();

            // End all sessions (synchronously)
            end_all_sessions_sync(&sessions, &shadow, &session_events_tx);
        });

        Ok(())
    }

    /// Stop the sentinel daemon
    pub async fn stop(&self) -> Result<()> {
        {
            let mut running = self.running.write().unwrap();
            if !*running {
                return Ok(());
            }
            *running = false;
        }

        // Signal shutdown
        if let Some(tx) = self.shutdown_tx.lock().unwrap().take() {
            let _ = tx.send(()).await;
        }

        // Clean up shadow buffers
        self.shadow.cleanup_all();

        Ok(())
    }

    /// Check if sentinel is running
    pub fn is_running(&self) -> bool {
        *self.running.read().unwrap()
    }

    /// Get all active sessions
    pub fn sessions(&self) -> Vec<DocumentSession> {
        self.sessions.read().unwrap().values().cloned().collect()
    }

    /// Get a specific session by path
    pub fn session(&self, path: &str) -> Result<DocumentSession> {
        self.sessions
            .read()
            .unwrap()
            .get(path)
            .cloned()
            .ok_or_else(|| SentinelError::SessionNotFound(path.to_string()))
    }

    /// Get the currently focused document path
    pub fn current_focus(&self) -> Option<String> {
        self.current_focus.read().unwrap().clone()
    }

    /// Subscribe to session events
    pub fn subscribe(&self) -> broadcast::Receiver<SessionEvent> {
        self.session_events_tx.subscribe()
    }

    /// Create a shadow buffer for an unsaved document
    pub fn create_shadow(&self, app_name: &str, window_title: &str) -> Result<String> {
        self.shadow.create(app_name, window_title)
    }

    /// Update shadow buffer content
    pub fn update_shadow_content(&self, shadow_id: &str, content: &[u8]) -> Result<()> {
        self.shadow.update(shadow_id, content)
    }

    /// Check if sentinel is available on this platform
    pub fn available(&self) -> (bool, String) {
        #[cfg(target_os = "macos")]
        {
            if macos_focus::check_accessibility_permissions() {
                (true, "macOS Accessibility API available".to_string())
            } else {
                (false, "Accessibility permission required".to_string())
            }
        }

        #[cfg(target_os = "windows")]
        {
            (true, "Windows Focus API available".to_string())
        }

        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            (
                false,
                "Sentinel not available on this platform".to_string(),
            )
        }
    }
}

// Event handling functions (synchronous to avoid Send issues with RwLock guards)
fn handle_focus_event_sync(
    event: FocusEvent,
    sessions: &Arc<RwLock<HashMap<String, DocumentSession>>>,
    config: &SentinelConfig,
    shadow: &Arc<ShadowManager>,
    signing_key: &Arc<RwLock<SigningKey>>,
    current_focus: &Arc<RwLock<Option<String>>>,
    wal_dir: &Path,
    session_events_tx: &broadcast::Sender<SessionEvent>,
) {
    // Check if app should be tracked
    if !config.is_app_allowed(&event.app_bundle_id, &event.app_name) {
        // Unfocus current document if moving to untracked app
        let path_to_unfocus = {
            let focus = current_focus.read().unwrap();
            focus.clone()
        };
        if let Some(path) = path_to_unfocus {
            unfocus_document_sync(&path, sessions, session_events_tx);
            *current_focus.write().unwrap() = None;
        }
        return;
    }

    match event.event_type {
        FocusEventType::FocusGained => {
            let doc_path = if event.path.is_empty() {
                // If path is empty but we have a shadow ID, use the shadow ID as the path
                if !event.shadow_id.is_empty() {
                    format!("shadow://{}", event.shadow_id)
                } else {
                    return;
                }
            } else {
                event.path.clone()
            };

            // If switching documents, unfocus the old one
            let path_to_unfocus = {
                let focus = current_focus.read().unwrap();
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
                *current_focus.write().unwrap() = None;
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
            *current_focus.write().unwrap() = Some(doc_path);
        }
        FocusEventType::FocusLost => {
            let prev_path = {
                let focus = current_focus.read().unwrap();
                focus.clone()
            };
            if let Some(path) = prev_path {
                unfocus_document_sync(&path, sessions, session_events_tx);
                *current_focus.write().unwrap() = None;
            }
        }
        FocusEventType::FocusUnknown => {
            let prev_path = {
                let focus = current_focus.read().unwrap();
                focus.clone()
            };
            if let Some(path) = prev_path {
                unfocus_document_sync(&path, sessions, session_events_tx);
                *current_focus.write().unwrap() = None;
            }
        }
    }
}

fn focus_document_sync(
    path: &str,
    event: &FocusEvent,
    sessions: &Arc<RwLock<HashMap<String, DocumentSession>>>,
    _config: &SentinelConfig,
    _shadow: &Arc<ShadowManager>,
    signing_key: &Arc<RwLock<SigningKey>>,
    wal_dir: &Path,
    session_events_tx: &broadcast::Sender<SessionEvent>,
) {
    let mut sessions_map = sessions.write().unwrap();

    let session = sessions_map.entry(path.to_string()).or_insert_with(|| {
        let mut session = DocumentSession::new(
            path.to_string(),
            event.app_bundle_id.clone(),
            event.app_name.clone(),
            event.window_title.clone(),
        );

        // Compute initial hash if file exists
        if let Ok(hash) = compute_file_hash(path) {
            session.initial_hash = Some(hash.clone());
            session.current_hash = Some(hash);
        }

        // Open WAL for session
        let wal_path = wal_dir.join(format!("{}.wal", session.session_id));
        let mut session_id_bytes = [0u8; 32];
        if session.session_id.len() >= 32 {
            hex::decode_to_slice(&session.session_id[..64.min(session.session_id.len() * 2)], &mut session_id_bytes).ok();
        }
        let key = signing_key.read().unwrap().clone();

        if let Ok(wal) = Wal::open(&wal_path, session_id_bytes, key) {
            // Write session start entry
            let payload = create_session_start_payload(&session);
            let _ = wal.append(EntryType::SessionStart, payload);
        }

        // Emit session started event
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

    let _ = session_events_tx.send(SessionEvent {
        event_type: SessionEventType::Focused,
        session_id: session.session_id.clone(),
        document_path: path.to_string(),
        timestamp: SystemTime::now(),
    });
}

fn unfocus_document_sync(
    path: &str,
    sessions: &Arc<RwLock<HashMap<String, DocumentSession>>>,
    session_events_tx: &broadcast::Sender<SessionEvent>,
) {
    let mut sessions_map = sessions.write().unwrap();

    if let Some(session) = sessions_map.get_mut(path) {
        session.focus_lost();

        let _ = session_events_tx.send(SessionEvent {
            event_type: SessionEventType::Unfocused,
            session_id: session.session_id.clone(),
            document_path: path.to_string(),
            timestamp: SystemTime::now(),
        });
    }
}

fn handle_change_event_sync(
    event: &ChangeEvent,
    sessions: &Arc<RwLock<HashMap<String, DocumentSession>>>,
    signing_key: &Arc<RwLock<SigningKey>>,
    wal_dir: &Path,
    session_events_tx: &broadcast::Sender<SessionEvent>,
) {
    let mut sessions_map = sessions.write().unwrap();

    if let Some(session) = sessions_map.get_mut(&event.path) {
        match event.event_type {
            ChangeEventType::Saved => {
                session.save_count += 1;

                // Compute new hash
                let current_hash = event
                    .hash
                    .clone()
                    .or_else(|| compute_file_hash(&event.path).ok());
                session.current_hash = current_hash.clone();

                // Write to WAL
                if let Some(hash) = current_hash {
                    let wal_path = wal_dir.join(format!("{}.wal", session.session_id));
                    let mut session_id_bytes = [0u8; 32];
                    hex::decode_to_slice(
                        &session.session_id[..64.min(session.session_id.len() * 2)],
                        &mut session_id_bytes,
                    )
                    .ok();
                    let key = signing_key.read().unwrap().clone();

                    if let Ok(wal) = Wal::open(&wal_path, session_id_bytes, key) {
                        let payload = create_document_hash_payload(&hash, event.size.unwrap_or(0));
                        let _ = wal.append(EntryType::DocumentHash, payload);
                    }
                }

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
                // End the session - need to drop lock first
                let event_path = event.path.clone();
                drop(sessions_map);
                end_session_sync(&event_path, sessions, session_events_tx);
                return;
            }
            ChangeEventType::Created => {
                // New document - will be picked up on focus
            }
        }
    }
}

fn check_idle_sessions_sync(
    sessions: &Arc<RwLock<HashMap<String, DocumentSession>>>,
    idle_timeout: Duration,
    session_events_tx: &broadcast::Sender<SessionEvent>,
) {
    let sessions_to_end: Vec<String> = {
        let sessions_map = sessions.read().unwrap();
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

fn end_session_sync(
    path: &str,
    sessions: &Arc<RwLock<HashMap<String, DocumentSession>>>,
    session_events_tx: &broadcast::Sender<SessionEvent>,
) {
    let session = sessions.write().unwrap().remove(path);

    if let Some(session) = session {
        let _ = session_events_tx.send(SessionEvent {
            event_type: SessionEventType::Ended,
            session_id: session.session_id,
            document_path: path.to_string(),
            timestamp: SystemTime::now(),
        });
    }
}

fn end_all_sessions_sync(
    sessions: &Arc<RwLock<HashMap<String, DocumentSession>>>,
    shadow: &Arc<ShadowManager>,
    session_events_tx: &broadcast::Sender<SessionEvent>,
) {
    let all_sessions: Vec<_> = sessions.write().unwrap().drain().collect();

    for (path, session) in all_sessions {
        let _ = session_events_tx.send(SessionEvent {
            event_type: SessionEventType::Ended,
            session_id: session.session_id,
            document_path: path,
            timestamp: SystemTime::now(),
        });

        // Clean up shadow buffer if exists
        if let Some(shadow_id) = session.shadow_id {
            let _ = shadow.delete(&shadow_id);
        }
    }
}

// Helper functions
fn compute_file_hash(path: &str) -> std::io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(hex::encode(hasher.finalize()))
}

fn create_session_start_payload(session: &DocumentSession) -> Vec<u8> {
    // Simple binary format: path_len(4) + path + hash(32) + timestamp(8)
    let path_bytes = session.path.as_bytes();
    let mut payload = Vec::with_capacity(4 + path_bytes.len() + 32 + 8);

    payload.extend_from_slice(&(path_bytes.len() as u32).to_be_bytes());
    payload.extend_from_slice(path_bytes);

    let hash_bytes = session
        .initial_hash
        .as_ref()
        .and_then(|h| hex::decode(h).ok())
        .unwrap_or_else(|| vec![0u8; 32]);
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

fn create_document_hash_payload(hash: &str, size: i64) -> Vec<u8> {
    let hash_bytes = hex::decode(hash).unwrap_or_else(|_| vec![0u8; 32]);
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

/// Normalize a document path for consistent session keys
pub fn normalize_document_path(path: &str) -> String {
    let path = Path::new(path);

    // Try to get absolute path
    let abs = path
        .canonicalize()
        .unwrap_or_else(|_| path.to_path_buf());

    abs.to_string_lossy().to_string()
}

// ============================================================================
// Daemon Manager
// ============================================================================

/// Persistent state of the sentinel daemon
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DaemonState {
    pub pid: i32,
    pub started_at: i64, // Unix timestamp
    pub version: String,
    pub identity: Option<String>,
}

/// Status information for display
#[derive(Debug, Clone)]
pub struct DaemonStatus {
    pub running: bool,
    pub pid: Option<i32>,
    pub started_at: Option<SystemTime>,
    pub uptime: Option<Duration>,
    pub version: Option<String>,
    pub identity: Option<String>,
}

/// Manages daemon lifecycle operations
pub struct DaemonManager {
    witnessd_dir: PathBuf,
    pid_file: PathBuf,
    state_file: PathBuf,
    socket_path: PathBuf,
}

impl DaemonManager {
    /// Create a new daemon manager
    pub fn new(witnessd_dir: impl AsRef<Path>) -> Self {
        let witnessd_dir = witnessd_dir.as_ref().to_path_buf();
        let sentinel_dir = witnessd_dir.join("sentinel");

        Self {
            witnessd_dir,
            pid_file: sentinel_dir.join("daemon.pid"),
            state_file: sentinel_dir.join("daemon.state"),
            socket_path: sentinel_dir.join("daemon.sock"),
        }
    }

    /// Check if the sentinel daemon is running
    pub fn is_running(&self) -> bool {
        if let Ok(pid) = self.read_pid() {
            is_process_running(pid)
        } else {
            false
        }
    }

    /// Read the daemon's PID from the PID file
    pub fn read_pid(&self) -> Result<i32> {
        let data = fs::read_to_string(&self.pid_file)?;
        data.trim()
            .parse()
            .map_err(|_| SentinelError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid PID file",
            )))
    }

    /// Write the current process PID to the PID file
    pub fn write_pid(&self) -> Result<()> {
        fs::create_dir_all(self.pid_file.parent().unwrap())?;
        fs::write(&self.pid_file, std::process::id().to_string())?;
        Ok(())
    }

    /// Remove the PID file
    pub fn remove_pid(&self) -> Result<()> {
        fs::remove_file(&self.pid_file)?;
        Ok(())
    }

    /// Write the daemon state
    pub fn write_state(&self, state: &DaemonState) -> Result<()> {
        let json = serde_json::to_string_pretty(state)
            .map_err(|e| SentinelError::Serialization(e.to_string()))?;
        fs::write(&self.state_file, json)?;
        Ok(())
    }

    /// Read the daemon state
    pub fn read_state(&self) -> Result<DaemonState> {
        let data = fs::read_to_string(&self.state_file)?;
        serde_json::from_str(&data).map_err(|e| SentinelError::Serialization(e.to_string()))
    }

    /// Signal the daemon to stop (SIGTERM)
    #[cfg(unix)]
    pub fn signal_stop(&self) -> Result<()> {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;

        let pid = self.read_pid()?;
        kill(Pid::from_raw(pid), Signal::SIGTERM)
            .map_err(|e| SentinelError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;
        Ok(())
    }

    #[cfg(not(unix))]
    pub fn signal_stop(&self) -> Result<()> {
        Err(SentinelError::NotAvailable(
            "Signal handling not available on this platform".to_string(),
        ))
    }

    /// Signal the daemon to reload (SIGHUP)
    #[cfg(unix)]
    pub fn signal_reload(&self) -> Result<()> {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;

        let pid = self.read_pid()?;
        kill(Pid::from_raw(pid), Signal::SIGHUP)
            .map_err(|e| SentinelError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;
        Ok(())
    }

    #[cfg(not(unix))]
    pub fn signal_reload(&self) -> Result<()> {
        Err(SentinelError::NotAvailable(
            "Signal handling not available on this platform".to_string(),
        ))
    }

    /// Wait for the daemon to stop
    pub fn wait_for_stop(&self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;

        while Instant::now() < deadline {
            if !self.is_running() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        Err(SentinelError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("daemon did not stop within {:?}", timeout),
        )))
    }

    /// Clean up PID and state files
    pub fn cleanup(&self) {
        let _ = fs::remove_file(&self.pid_file);
        let _ = fs::remove_file(&self.state_file);
        let _ = fs::remove_file(&self.socket_path);
    }

    /// Get the current daemon status
    pub fn status(&self) -> DaemonStatus {
        let mut status = DaemonStatus {
            running: false,
            pid: None,
            started_at: None,
            uptime: None,
            version: None,
            identity: None,
        };

        // Check if running
        if let Ok(pid) = self.read_pid() {
            if is_process_running(pid) {
                status.running = true;
                status.pid = Some(pid);
            }
        }

        // Read state if available
        if let Ok(state) = self.read_state() {
            let started_at = UNIX_EPOCH + Duration::from_secs(state.started_at as u64);
            status.started_at = Some(started_at);
            status.version = Some(state.version);
            status.identity = state.identity;

            if status.running {
                status.uptime = started_at.elapsed().ok();
            }
        }

        status
    }

    /// Get the sentinel directory path
    pub fn sentinel_dir(&self) -> PathBuf {
        self.witnessd_dir.join("sentinel")
    }

    /// Get the WAL directory path
    pub fn wal_dir(&self) -> PathBuf {
        self.witnessd_dir.join("sentinel").join("wal")
    }
}

/// Check if a process with the given PID is running
#[cfg(unix)]
fn is_process_running(pid: i32) -> bool {
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;

    kill(Pid::from_raw(pid), Signal::SIGCONT).is_ok()
}

#[cfg(not(unix))]
fn is_process_running(_pid: i32) -> bool {
    false
}

// ============================================================================
// CLI Command Handlers
// ============================================================================

/// Start the sentinel daemon
pub async fn cmd_start(witnessd_dir: &Path) -> Result<()> {
    let daemon_mgr = DaemonManager::new(witnessd_dir);

    if daemon_mgr.is_running() {
        let status = daemon_mgr.status();
        if let Some(pid) = status.pid {
            return Err(SentinelError::DaemonAlreadyRunning(pid));
        }
    }

    // Create config
    let config = SentinelConfig::default().with_witnessd_dir(witnessd_dir);

    // Create and start sentinel
    let sentinel = Sentinel::new(config)?;
    sentinel.start().await?;

    // Write PID and state
    daemon_mgr.write_pid()?;
    daemon_mgr.write_state(&DaemonState {
        pid: std::process::id() as i32,
        started_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
        version: env!("CARGO_PKG_VERSION").to_string(),
        identity: None,
    })?;

    Ok(())
}

/// Stop the sentinel daemon
pub fn cmd_stop(witnessd_dir: &Path) -> Result<()> {
    let daemon_mgr = DaemonManager::new(witnessd_dir);

    if !daemon_mgr.is_running() {
        return Err(SentinelError::DaemonNotRunning);
    }

    daemon_mgr.signal_stop()?;
    daemon_mgr.wait_for_stop(Duration::from_secs(10))?;
    daemon_mgr.cleanup();

    Ok(())
}

/// Get sentinel status
pub fn cmd_status(witnessd_dir: &Path) -> DaemonStatus {
    let daemon_mgr = DaemonManager::new(witnessd_dir);
    daemon_mgr.status()
}

/// Track a file (placeholder for IPC implementation)
pub fn cmd_track(witnessd_dir: &Path, file_path: &Path) -> Result<()> {
    let daemon_mgr = DaemonManager::new(witnessd_dir);

    if !daemon_mgr.is_running() {
        return Err(SentinelError::DaemonNotRunning);
    }

    // TODO: Implement IPC to send track command to running daemon
    let abs_path = file_path.canonicalize()?;
    println!("Would track: {}", abs_path.display());
    println!("Note: IPC to running daemon not yet implemented.");

    Ok(())
}

/// Untrack a file (placeholder for IPC implementation)
pub fn cmd_untrack(witnessd_dir: &Path, file_path: &Path) -> Result<()> {
    let daemon_mgr = DaemonManager::new(witnessd_dir);

    if !daemon_mgr.is_running() {
        return Err(SentinelError::DaemonNotRunning);
    }

    // TODO: Implement IPC to send untrack command to running daemon
    let abs_path = file_path.canonicalize()?;
    println!("Would untrack: {}", abs_path.display());
    println!("Note: IPC to running daemon not yet implemented.");

    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

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

        // Allowed app should be tracked
        assert!(config.is_app_allowed("com.microsoft.VSCode", "Visual Studio Code"));

        // Blocked app should not be tracked
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
    fn test_normalize_path() {
        let path = normalize_document_path("./test.txt");
        assert!(path.contains("test.txt"));
    }

    #[tokio::test]
    async fn test_shadow_manager() {
        let temp_dir = std::env::temp_dir().join("witnessd-test-shadow");
        let _ = fs::remove_dir_all(&temp_dir);

        let shadow_mgr = ShadowManager::new(&temp_dir).unwrap();

        // Create shadow
        let id = shadow_mgr.create("Test App", "Untitled").unwrap();
        assert!(!id.is_empty());

        // Update shadow
        shadow_mgr.update(&id, b"test content").unwrap();

        // Get path
        let path = shadow_mgr.get_path(&id);
        assert!(path.is_some());

        // Delete shadow
        shadow_mgr.delete(&id).unwrap();
        assert!(shadow_mgr.get_path(&id).is_none());

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
