// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::ffi::helpers::{load_api_key, load_did, load_signing_key, open_store};
use crate::ffi::types::FfiResult;

/// Anchor a document's latest checkpoint to the WritersProof transparency log.
///
/// Uses the latest event_hash from the store (matching CLI behavior), signs
/// the raw hash bytes with Ed25519, and submits to the WritersProof API.
/// Requires a valid API key stored at `~/.writersproof/writersproof_api_key`.
///
/// Note: Function named with underscore in `writers_proof` so UniFFI generates
/// `ffiAnchorToWritersProof` (capital P) matching the Swift call site.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_anchor_to_writers_proof(document_path: String) -> FfiResult {
    let doc_path = match crate::sentinel::helpers::validate_path(&document_path) {
        Ok(p) => p,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Invalid document path: {e}")),
            };
        }
    };

    // Load events from store to get the latest event_hash (matches CLI behavior)
    let store = match open_store() {
        Ok(s) => s,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(e),
            };
        }
    };
    let events = match store.get_events_for_file(&document_path) {
        Ok(e) => e,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Failed to load events: {e}")),
            };
        }
    };
    let latest = match events.last() {
        Some(ev) => ev,
        None => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some("No checkpoints found for this document".to_string()),
            };
        }
    };

    // Use event_hash directly (matches CLI: hex::encode(latest.event_hash))
    let evidence_hash = hex::encode(latest.event_hash);

    // Load signing key and sign the raw hash bytes (matches CLI: signing_key.sign(latest.event_hash.as_slice()))
    let signing_key = match load_signing_key() {
        Ok(k) => k,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(e),
            };
        }
    };
    let signature = {
        use ed25519_dalek::Signer;
        hex::encode(signing_key.sign(latest.event_hash.as_slice()).to_bytes())
    };
    // signing_key implements Zeroize on Drop via ed25519-dalek

    let did = load_did().unwrap_or_else(|_| "unknown".into());
    let api_key = match load_api_key() {
        Ok(k) => k,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("WritersProof API key not configured. {e}")),
            };
        }
    };

    let doc_name = doc_path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_string());

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Failed to create async runtime: {e}")),
            };
        }
    };

    let client = match crate::writersproof::WritersProofClient::new("https://api.writerslogic.com")
    {
        Ok(c) => c.with_jwt((*api_key).clone()),
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Failed to create API client: {e}")),
            };
        }
    };

    let result = rt.block_on(async {
        use crate::writersproof::{AnchorMetadata, AnchorRequest};

        tokio::time::timeout(
            std::time::Duration::from_secs(30),
            client.anchor(AnchorRequest {
                evidence_hash,
                author_did: did,
                signature,
                metadata: Some(AnchorMetadata {
                    document_name: doc_name,
                    tier: Some("anchored".into()),
                }),
            }),
        )
        .await
    });

    match result {
        Err(_) => FfiResult {
            success: false,
            message: None,
            error_message: Some("Anchor request timed out after 30s".to_string()),
        },
        Ok(Err(e)) => FfiResult {
            success: false,
            message: None,
            error_message: Some(format!("Anchor request failed: {e}")),
        },
        Ok(Ok(resp)) => FfiResult {
            success: true,
            message: Some(format!(
                "Anchored: {} (log index {})",
                resp.anchor_id, resp.log_index
            )),
            error_message: None,
        },
    }
}
