// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! FFI bindings for text fragment evidence storage and retrieval.
//!
//! Swift captures text content natively (NSPasteboard, NSEvent) and pushes
//! it here for hashing, signing, and storage. Rust never reads the pasteboard
//! directly — the platform stubs in `sentinel/clipboard.rs` are intentional.

use super::helpers::{load_signing_key, open_store};
use crate::store::text_fragments::{KeystrokeContext, TextFragment};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// FFI types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiTextFragment {
    pub id: i64,
    pub fragment_hash_hex: String,
    pub session_id: String,
    pub source_app_bundle_id: Option<String>,
    pub source_window_title: Option<String>,
    pub keystroke_context: Option<String>,
    pub keystroke_confidence: Option<f64>,
    pub timestamp_ms: i64,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiTextFragmentStoreResult {
    pub success: bool,
    pub fragment_hash_hex: Option<String>,
    pub fragment_id: i64,
    pub error_message: Option<String>,
}

impl FfiTextFragmentStoreResult {
    fn ok(hash_hex: String, id: i64) -> Self {
        Self { success: true, fragment_hash_hex: Some(hash_hex), fragment_id: id, error_message: None }
    }
    fn err(msg: impl Into<String>) -> Self {
        Self { success: false, fragment_hash_hex: None, fragment_id: -1, error_message: Some(msg.into()) }
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiPasteRecordResult {
    pub success: bool,
    pub text_hash_hex: Option<String>,
    pub matched_existing: bool,
    pub matched_session_id: Option<String>,
    pub error_message: Option<String>,
}

impl FfiPasteRecordResult {
    fn ok(hash_hex: String, matched_session_id: Option<String>) -> Self {
        Self {
            success: true,
            text_hash_hex: Some(hash_hex),
            matched_existing: matched_session_id.is_some(),
            matched_session_id,
            error_message: None,
        }
    }
    fn err(msg: impl Into<String>) -> Self {
        Self {
            success: false,
            text_hash_hex: None,
            matched_existing: false,
            matched_session_id: None,
            error_message: Some(msg.into()),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn to_ffi(f: &TextFragment) -> FfiTextFragment {
    FfiTextFragment {
        id: f.id.unwrap_or(-1),
        fragment_hash_hex: hex::encode(&f.fragment_hash),
        session_id: f.session_id.clone(),
        source_app_bundle_id: f.source_app_bundle_id.clone(),
        source_window_title: f.source_window_title.clone(),
        keystroke_context: f.keystroke_context.map(|c| c.as_str().to_string()),
        keystroke_confidence: f.keystroke_confidence,
        timestamp_ms: f.timestamp,
    }
}

fn hash_text(text: &str) -> [u8; 32] {
    Sha256::digest(text.as_bytes()).into()
}

/// Sign the fragment payload: session_id || fragment_hash || timestamp || nonce.
fn sign_fragment(
    signing_key: &ed25519_dalek::SigningKey,
    session_id: &str,
    fragment_hash: &[u8; 32],
    timestamp: i64,
    nonce: &[u8; 16],
) -> [u8; 64] {
    use ed25519_dalek::Signer;
    let mut payload = Vec::with_capacity(session_id.len() + 32 + 8 + 16);
    payload.extend_from_slice(session_id.as_bytes());
    payload.extend_from_slice(fragment_hash);
    payload.extend_from_slice(&timestamp.to_le_bytes());
    payload.extend_from_slice(nonce);
    signing_key.sign(&payload).to_bytes()
}

fn current_timestamp_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn generate_nonce() -> [u8; 16] {
    let mut nonce = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut nonce);
    nonce
}

// ---------------------------------------------------------------------------
// Exported FFI functions
// ---------------------------------------------------------------------------

/// Store a text fragment with computed hash, signature, and nonce.
///
/// Called by Swift when text is typed or pasted. The `text_content` is hashed
/// (SHA-256) but NOT stored — only the hash persists for privacy.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_text_fragment_store(
    text_content: String,
    session_id: String,
    app_bundle_id: String,
    window_title: String,
    keystroke_context: String,
    confidence: f64,
) -> FfiTextFragmentStoreResult {
    if text_content.is_empty() {
        return FfiTextFragmentStoreResult::err("Text content is empty");
    }
    if session_id.is_empty() {
        return FfiTextFragmentStoreResult::err("Session ID is required");
    }

    let context = match keystroke_context.parse::<KeystrokeContext>() {
        Ok(c) => c,
        Err(_) => return FfiTextFragmentStoreResult::err(
            format!("Invalid keystroke_context: {keystroke_context}. Expected OriginalComposition, PastedContent, or AfterPaste")
        ),
    };

    let confidence = confidence.clamp(0.0, 1.0);
    let fragment_hash = hash_text(&text_content);
    let timestamp = current_timestamp_ms();
    let nonce = generate_nonce();

    let signing_key = match load_signing_key() {
        Ok(k) => k,
        Err(e) => return FfiTextFragmentStoreResult::err(format!("Signing key unavailable: {e}")),
    };

    let signature = sign_fragment(&signing_key, &session_id, &fragment_hash, timestamp, &nonce);

    let fragment = TextFragment {
        id: None,
        fragment_hash: fragment_hash.to_vec(),
        session_id,
        source_app_bundle_id: Some(app_bundle_id).filter(|s| !s.is_empty()),
        source_window_title: Some(window_title).filter(|s| !s.is_empty()),
        source_signature: signature.to_vec(),
        nonce: nonce.to_vec(),
        timestamp,
        keystroke_context: Some(context),
        keystroke_confidence: Some(confidence),
        keystroke_sequence_hash: None,
        source_session_id: None,
        source_evidence_packet: None,
        wal_entry_hash: None,
        cloudkit_record_id: None,
        sync_state: None,
    };

    let mut store = match open_store() {
        Ok(s) => s,
        Err(e) => return FfiTextFragmentStoreResult::err(e),
    };

    match store.insert_text_fragment(&fragment) {
        Ok(id) => FfiTextFragmentStoreResult::ok(hex::encode(fragment_hash), id),
        Err(e) => FfiTextFragmentStoreResult::err(format!("Failed to store fragment: {e}")),
    }
}

/// Look up a text fragment by its hex-encoded SHA-256 hash.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_text_fragment_lookup(fragment_hash_hex: String) -> Option<FfiTextFragment> {
    let hash_bytes = match hex::decode(&fragment_hash_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            log::warn!("ffi_text_fragment_lookup: invalid hash hex (expected 64 hex chars)");
            return None;
        }
    };

    let store = match open_store() {
        Ok(s) => s,
        Err(e) => {
            log::warn!("ffi_text_fragment_lookup: failed to open store: {e}");
            return None;
        }
    };

    match store.lookup_fragment_by_hash(&hash_bytes) {
        Ok(Some(f)) => Some(to_ffi(&f)),
        Ok(None) => None,
        Err(e) => {
            log::warn!("ffi_text_fragment_lookup: query failed: {e}");
            None
        }
    }
}

/// Get all text fragments for a session, ordered by timestamp.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_text_fragment_list_for_session(session_id: String) -> Vec<FfiTextFragment> {
    let store = match open_store() {
        Ok(s) => s,
        Err(e) => {
            log::warn!("ffi_text_fragment_list_for_session: failed to open store: {e}");
            return Vec::new();
        }
    };

    match store.get_fragments_for_session(&session_id) {
        Ok(frags) => frags.iter().map(to_ffi).collect(),
        Err(e) => {
            log::warn!("ffi_text_fragment_list_for_session: query failed: {e}");
            Vec::new()
        }
    }
}

/// Record a paste event with full text content for evidence tracking.
///
/// Replaces `ffi_sentinel_notify_paste`. Swift passes the pasted text, which
/// is hashed (SHA-256) and checked against existing fragments. The sentinel's
/// paste-char counter and keystroke context window are also updated.
///
/// The pasted text itself is NOT stored — only the hash.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_record_paste(
    char_count: i64,
    pasted_text: String,
    timestamp_ns: i64,
    app_bundle_id: String,
    window_title: String,
    detection_confidence: f64,
) -> FfiPasteRecordResult {
    if char_count < 0 {
        return FfiPasteRecordResult::err("char_count must be non-negative");
    }

    // Update sentinel paste counter (same as old ffi_sentinel_notify_paste).
    let sentinel_opt = super::sentinel::get_sentinel();
    let sentinel = match sentinel_opt.as_ref() {
        Some(s) if s.is_running() => s,
        _ => return FfiPasteRecordResult::err("Sentinel not running"),
    };
    sentinel.set_last_paste_chars(char_count);

    // Hash the pasted text.
    let text_hash = hash_text(&pasted_text);
    let text_hash_hex = hex::encode(text_hash);

    // Open store once for both lookup and insert.
    let mut store = match open_store() {
        Ok(s) => s,
        Err(e) => {
            log::warn!("Cannot open store for paste recording: {e}");
            return FfiPasteRecordResult::ok(text_hash_hex, None);
        }
    };

    // Check if this text matches an existing fragment (cross-session provenance).
    let matched_session_id = match store.lookup_fragment_by_hash(&text_hash) {
        Ok(Some(f)) => Some(f.session_id),
        _ => None,
    };

    // Store a fragment for this paste event in the current session.
    let focus = sentinel.current_focus();
    if let Some(ref focused_path) = focus {
        if let Ok(session) = sentinel.session(focused_path) {
            let signing_key = match load_signing_key() {
                Ok(k) => k,
                Err(e) => {
                    log::warn!("Cannot sign paste fragment: {e}");
                    return FfiPasteRecordResult::ok(text_hash_hex, matched_session_id);
                }
            };

            let timestamp_ms = timestamp_ns / 1_000_000;
            let nonce = generate_nonce();
            let signature = sign_fragment(
                &signing_key,
                &session.session_id,
                &text_hash,
                timestamp_ms,
                &nonce,
            );

            let fragment = TextFragment {
                id: None,
                fragment_hash: text_hash.to_vec(),
                session_id: session.session_id.clone(),
                source_app_bundle_id: Some(app_bundle_id).filter(|s| !s.is_empty()),
                source_window_title: Some(window_title).filter(|s| !s.is_empty()),
                source_signature: signature.to_vec(),
                nonce: nonce.to_vec(),
                timestamp: timestamp_ms,
                keystroke_context: Some(KeystrokeContext::PastedContent),
                keystroke_confidence: Some(detection_confidence.clamp(0.0, 1.0)),
                keystroke_sequence_hash: None,
                source_session_id: matched_session_id.clone(),
                source_evidence_packet: None,
                wal_entry_hash: None,
                cloudkit_record_id: None,
                sync_state: None,
            };

            if let Err(e) = store.insert_text_fragment(&fragment) {
                log::warn!("Failed to store paste fragment: {e}");
            }
        }
    }

    FfiPasteRecordResult::ok(text_hash_hex, matched_session_id)
}
