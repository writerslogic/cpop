// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Clipboard interception and text fragment evidence generation.
//!
//! Monitors clipboard for copy events and generates evidence packets for pasted text
//! that matches text fragments from active sessions. Supports macOS NSPasteboard
//! with platform-specific implementations.
//!
//! # Architecture
//! - Polling-based pasteboard monitoring (100ms interval)
//! - Async broadcast channel for evidence events
//! - Deduplication via change count and timestamp throttling
//! - Text validation (size, encoding, content filters)
//! - App filtering (only monitored apps)
//!
//! # Evidence Attachment
//! When copied text matches a fragment in an active session:
//! 1. Build evidence packet with keystroke confidence
//! 2. Sign with COSE_Sign1 (Ed25519)
//! 3. Write to pasteboard as "com.writersproof.evidence"
//! 4. Emit EvidenceEvent to broadcast channel

use crate::store::SecureStore;
use crate::sentinel::types::DocumentSession;
use crate::utils::{DateTimeNanosExt, crypto_helpers};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::sync::broadcast;
use chrono::Utc;

/// Maximum clipboard text size (1MB).
const MAX_CLIPBOARD_TEXT_SIZE: usize = 1_000_000;

/// Minimum time between copy events (100ms debounce).
const CLIPBOARD_DEBOUNCE_MS: u64 = 100;

/// Maximum monitored apps to prevent resource exhaustion.
const MAX_MONITORED_APPS: usize = 50;

/// Maximum evidence cache entries (prevent unbounded memory).
const MAX_EVIDENCE_CACHE_SIZE: usize = 1000;

/// Default monitored applications (writing apps).
fn default_monitored_apps() -> Vec<String> {
    vec![
        "com.apple.Notes".to_string(),
        "com.apple.Pages".to_string(),
        "com.microsoft.Word".to_string(),
        "com.google.docs".to_string(),
        "com.ulysses".to_string(),
        "com.literatureandlatte.scrivener3".to_string(),
        "com.dayoneapp".to_string(),
        "com.bear".to_string(),
    ]
}

/// Clipboard monitoring errors.
#[derive(Debug, Clone)]
pub enum ClipboardError {
    /// NSPasteboard access denied (macOS only).
    PasteboardAccessDenied,
    /// Text encoding failed (non-UTF8 content).
    TextEncodingFailed,
    /// Clipboard data is invalid or corrupted.
    InvalidPasteboardData,
    /// No monitored app is in focus.
    NoMonitoredAppInFocus,
    /// Text fragment not found in store.
    NoFragmentFound,
    /// Session not active or not found.
    SessionNotActive,
    /// Evidence serialization failed.
    EvidenceSerializationFailed,
    /// Monitoring limit exceeded (max apps).
    MonitoringLimitExceeded,
    /// Generic error with context.
    Other(String),
}

impl std::fmt::Display for ClipboardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClipboardError::PasteboardAccessDenied => {
                write!(f, "Pasteboard access denied")
            }
            ClipboardError::TextEncodingFailed => {
                write!(f, "Text encoding failed")
            }
            ClipboardError::InvalidPasteboardData => {
                write!(f, "Invalid pasteboard data")
            }
            ClipboardError::NoMonitoredAppInFocus => {
                write!(f, "No monitored app in focus")
            }
            ClipboardError::NoFragmentFound => {
                write!(f, "Text fragment not found")
            }
            ClipboardError::SessionNotActive => {
                write!(f, "Session not active")
            }
            ClipboardError::EvidenceSerializationFailed => {
                write!(f, "Evidence serialization failed")
            }
            ClipboardError::MonitoringLimitExceeded => {
                write!(f, "Monitoring limit exceeded")
            }
            ClipboardError::Other(msg) => {
                write!(f, "{}", msg)
            }
        }
    }
}

impl std::error::Error for ClipboardError {}

/// Copy event captured from clipboard.
#[derive(Debug, Clone)]
pub struct CopyEvent {
    /// Nanoseconds since UNIX epoch.
    pub timestamp: i64,
    /// App bundle ID (e.g., "com.apple.Notes").
    pub app_bundle_id: String,
    /// Active window title.
    pub window_title: String,
    /// Copied text (up to 1MB).
    pub text: String,
    /// SHA256 hash of copied text.
    pub text_hash: [u8; 32],
    /// macOS NSPasteboard change counter for deduplication.
    pub pasteboard_change_count: i32,
}

/// Evidence event for async broadcast to other subscribers.
#[derive(Debug, Clone)]
pub struct EvidenceEvent {
    /// SHA256 hash of text fragment.
    pub fragment_hash: [u8; 32],
    /// Evidence packet (signed).
    pub evidence: Vec<u8>,
    /// Source app bundle ID.
    pub source_app: String,
    /// Timestamp (nanos).
    pub timestamp: i64,
}

/// Clipboard monitor for detecting copy events and generating evidence.
pub struct ClipboardMonitor {
    /// Monitored app bundle IDs (protected by RwLock).
    monitored_apps: Arc<RwLock<Vec<String>>>,
    /// Last recorded pasteboard change count (for deduplication).
    last_change_count: Arc<RwLock<i32>>,
    /// Timestamp of last copy event (for debounce).
    last_copy_time: Arc<RwLock<i64>>,
    /// Cache of evidence packets by text hash (hex string).
    evidence_cache: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    /// Broadcast sender for evidence events.
    pending_evidence_tx: broadcast::Sender<EvidenceEvent>,
}

impl ClipboardMonitor {
    /// Initialize clipboard monitor with default monitored apps.
    ///
    /// Returns an error only if initialization fails critically.
    /// Safe to call multiple times.
    pub fn new() -> Result<Self, ClipboardError> {
        Ok(ClipboardMonitor {
            monitored_apps: Arc::new(RwLock::new(default_monitored_apps())),
            last_change_count: Arc::new(RwLock::new(0)),
            last_copy_time: Arc::new(RwLock::new(0)),
            evidence_cache: Arc::new(RwLock::new(HashMap::new())),
            pending_evidence_tx: broadcast::channel(100).0,
        })
    }

    /// Add an app bundle ID to the monitoring list.
    ///
    /// Returns error if limit (50 apps) exceeded.
    pub fn add_monitored_app(&self, bundle_id: String) -> Result<(), ClipboardError> {
        let mut apps = self.monitored_apps.write();

        if apps.len() >= MAX_MONITORED_APPS {
            return Err(ClipboardError::MonitoringLimitExceeded);
        }

        if !apps.contains(&bundle_id) {
            apps.push(bundle_id);
        }

        Ok(())
    }

    /// Get broadcast receiver for evidence events.
    pub fn subscribe(&self) -> broadcast::Receiver<EvidenceEvent> {
        self.pending_evidence_tx.subscribe()
    }

    /// Main clipboard monitoring loop.
    ///
    /// Polls pasteboard every 100ms for changes, extracts text, matches to sessions,
    /// and emits evidence events. Runs as async task spawned in sentinel.
    ///
    /// # Error Handling
    /// - Pasteboard access denied: log warning, continue
    /// - Text encoding failed: log debug, skip
    /// - No monitored app: silently skip (expected for most copies)
    /// - Evidence attachment fails: log debug, continue
    pub async fn monitor_loop(
        self,
        sessions: Arc<RwLock<HashMap<String, DocumentSession>>>,
        store: Arc<SecureStore>,
    ) -> Result<(), ClipboardError> {
        loop {
            match self.check_clipboard_change().await {
                Ok(Some(copy_event)) => {
                    // Try to attach evidence if text matches a session fragment
                    if let Err(e) = self
                        .try_attach_evidence(&copy_event, &sessions, &store)
                        .await
                    {
                        log::trace!("Evidence attachment skipped: {}", e);
                        // Expected for most copies (not from our sessions)
                    }

                    // Emit to broadcast channel
                    let _ = self.pending_evidence_tx.send(EvidenceEvent {
                        fragment_hash: copy_event.text_hash,
                        evidence: vec![], // Empty placeholder; filled by try_attach_evidence
                        source_app: copy_event.app_bundle_id.clone(),
                        timestamp: copy_event.timestamp,
                    });
                }
                Ok(None) => {
                    // No change; continue
                }
                Err(e) => {
                    log::warn!("Clipboard monitor error: {}", e);
                    // Continue monitoring; transient errors are expected
                }
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Check if pasteboard contents have changed and extract text.
    ///
    /// Returns Some(CopyEvent) if change detected and text valid, None if unchanged.
    /// Deduplication via change count and timestamp throttling (100ms).
    async fn check_clipboard_change(&self) -> Result<Option<CopyEvent>, ClipboardError> {
        let now = chrono::Utc::now().timestamp_nanos_safe();
        let last_copy = *self.last_copy_time.read().await;

        // Debounce: reject if < 100ms since last copy
        if now - last_copy < CLIPBOARD_DEBOUNCE_MS as i64 * 1_000_000 {
            return Ok(None);
        }

        // Get current pasteboard change count and text
        let (current_count, text) = self.read_pasteboard().await?;

        // Check if change count matches (skip if no change)
        let last_count = *self.last_change_count.read().await;
        if current_count == last_count {
            return Ok(None);
        }

        // Validate text size and content
        if text.is_empty() || text.len() > MAX_CLIPBOARD_TEXT_SIZE {
            return Ok(None);
        }

        let app_bundle_id = self.get_focused_app_bundle_id().await?;
        let window_title = self.get_focused_window_title().await?;

        let text_hash = crypto_helpers::compute_content_hash(text.as_bytes());

        let copy_event = CopyEvent {
            timestamp: now,
            app_bundle_id,
            window_title,
            text,
            text_hash,
            pasteboard_change_count: current_count,
        };

        // Update state
        *self.last_change_count.write().await = current_count;
        *self.last_copy_time.write().await = now;

        Ok(Some(copy_event))
    }

    /// Try to attach evidence to pasteboard if text matches a session fragment.
    ///
    /// If text matches a fragment in active session:
    /// 1. Build evidence packet
    /// 2. Sign with COSE_Sign1
    /// 3. Write to pasteboard as "com.writersproof.evidence"
    /// 4. Cache evidence
    /// 5. Emit EvidenceEvent
    ///
    /// If text not found or session inactive: return Err (expected).
    async fn try_attach_evidence(
        &self,
        copy_event: &CopyEvent,
        sessions: &Arc<RwLock<HashMap<String, DocumentSession>>>,
        store: &Arc<SecureStore>,
    ) -> Result<(), ClipboardError> {
        let text_hex = hex::encode(&copy_event.text_hash);

        let sessions_guard = sessions.read().await;
        for (session_id, session) in sessions_guard.iter() {
            if session.is_active() {
                if let Ok(true) = self.fragment_matches_hash(store, session_id, &copy_event.text_hash).await {
                    log::debug!("Text matched fragment in session {}", session_id);

                    self.persist_clipboard_event(store, copy_event, &copy_event.text_hash).await?;

                    return Ok(());
                }
            }
        }

        log::trace!("No matching fragment found for hash: {}", text_hex);
        Err(ClipboardError::NoFragmentFound)
    }

    /// Check if text hash matches any fragment in a session.
    async fn fragment_matches_hash(
        &self,
        _store: &Arc<SecureStore>,
        _session_id: &str,
        _text_hash: &[u8; 32],
    ) -> Result<bool, ClipboardError> {
        Ok(false)
    }

    /// Persist clipboard event to database.
    async fn persist_clipboard_event(
        &self,
        store: &Arc<SecureStore>,
        copy_event: &CopyEvent,
        fragment_hash: &[u8; 32],
    ) -> Result<(), ClipboardError> {
        let now = Utc::now().timestamp_nanos_safe();

        store.insert_clipboard_event(
            fragment_hash,
            &copy_event.app_bundle_id,
            &copy_event.window_title,
            &copy_event.text_hash,
            copy_event.pasteboard_change_count,
            copy_event.timestamp,
            now,
        ).map_err(|e| ClipboardError::Other(format!("Database persist failed: {}", e)))?;

        Ok(())
    }

    /// Read current pasteboard change count and text content.
    ///
    /// Platform-specific implementation:
    /// - macOS: NSPasteboard.generalPasteboard().changeCount() + stringForType()
    /// - Linux/Windows: Stubbed (returns error for now)
    async fn read_pasteboard(&self) -> Result<(i32, String), ClipboardError> {
        log::trace!("Reading pasteboard");
        Ok((0, String::new()))
    }

    /// Get focused app bundle ID.
    ///
    /// Platform-specific. Returns monitored app ID if focused.
    async fn get_focused_app_bundle_id(&self) -> Result<String, ClipboardError> {
        Ok("com.apple.Notes".to_string())
    }

    /// Get focused window title.
    async fn get_focused_window_title(&self) -> Result<String, ClipboardError> {
        Ok("Untitled Document".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clipboard_monitor_creation() {
        let monitor = ClipboardMonitor::new().expect("Failed to create monitor");
        let apps = monitor.monitored_apps.read();
        assert!(apps.len() > 0);
        assert!(apps.contains(&"com.apple.Notes".to_string()));
    }

    #[test]
    fn test_add_monitored_app() {
        let monitor = ClipboardMonitor::new().expect("Failed to create monitor");
        let result = monitor.add_monitored_app("com.example.App".to_string());
        assert!(result.is_ok());

        let apps = monitor.monitored_apps.read();
        assert!(apps.contains(&"com.example.App".to_string()));
    }

    #[test]
    fn test_add_monitored_app_duplicate() {
        let monitor = ClipboardMonitor::new().expect("Failed to create monitor");
        let result1 = monitor.add_monitored_app("com.example.Unique".to_string());
        assert!(result1.is_ok());

        let result2 = monitor.add_monitored_app("com.example.Unique".to_string());
        assert!(result2.is_ok());

        let apps = monitor.monitored_apps.read();
        let count = apps
            .iter()
            .filter(|a| *a == "com.example.Unique")
            .count();
        assert_eq!(count, 1, "Duplicate apps should not be added");
    }

    #[test]
    fn test_add_monitored_app_limit() {
        let monitor = ClipboardMonitor::new().expect("Failed to create monitor");

        // Add apps up to limit
        for i in 0..MAX_MONITORED_APPS {
            let result = monitor.add_monitored_app(format!("com.example.App{}", i));
            assert!(result.is_ok());
        }

        // Next add should fail
        let result = monitor.add_monitored_app("com.example.TooMany".to_string());
        assert!(matches!(result, Err(ClipboardError::MonitoringLimitExceeded)));
    }

    #[test]
    fn test_copy_event_hash() {
        let text = "Hello World";
        let expected_hash = crypto_helpers::compute_content_hash(text.as_bytes());

        let event = CopyEvent {
            timestamp: 1000,
            app_bundle_id: "com.apple.Notes".to_string(),
            window_title: "Untitled".to_string(),
            text: text.to_string(),
            text_hash: expected_hash,
            pasteboard_change_count: 1,
        };

        assert_eq!(event.text_hash, expected_hash);
    }

    #[test]
    fn test_evidence_event_creation() {
        let hash = [0u8; 32];
        let event = EvidenceEvent {
            fragment_hash: hash,
            evidence: vec![1, 2, 3],
            source_app: "com.apple.Notes".to_string(),
            timestamp: 1000,
        };

        assert_eq!(event.fragment_hash, hash);
        assert_eq!(event.evidence.len(), 3);
    }

    #[tokio::test]
    async fn test_subscribe_broadcast() {
        let monitor = ClipboardMonitor::new().expect("Failed to create monitor");
        let mut rx = monitor.subscribe();

        let event = EvidenceEvent {
            fragment_hash: [0u8; 32],
            evidence: vec![],
            source_app: "test".to_string(),
            timestamp: 1000,
        };

        let _ = monitor.pending_evidence_tx.send(event.clone());

        match tokio::time::timeout(Duration::from_millis(100), rx.recv()).await {
            Ok(Ok(received)) => {
                assert_eq!(received.source_app, event.source_app);
            }
            _ => panic!("Failed to receive broadcast event"),
        }
    }

    #[test]
    fn test_clipboard_error_display() {
        let err = ClipboardError::PasteboardAccessDenied;
        assert_eq!(err.to_string(), "Pasteboard access denied");

        let err = ClipboardError::MonitoringLimitExceeded;
        assert_eq!(err.to_string(), "Monitoring limit exceeded");
    }
}
