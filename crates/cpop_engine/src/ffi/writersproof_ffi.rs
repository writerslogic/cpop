// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::ffi::helpers::{get_data_dir, open_store};
use crate::ffi::types::FfiResult;
use zeroize::Zeroize;

/// Load the Ed25519 signing key from the data directory, zeroizing intermediates.
fn load_signing_key() -> Result<ed25519_dalek::SigningKey, String> {
    let data_dir = get_data_dir().ok_or_else(|| "Data directory not found".to_string())?;
    let key_path = data_dir.join("signing_key");
    let mut key_data =
        std::fs::read(&key_path).map_err(|e| format!("Failed to read signing key: {e}"))?;
    if key_data.len() < 32 {
        key_data.zeroize();
        return Err("Signing key is too short".to_string());
    }
    let mut secret: [u8; 32] = key_data[..32]
        .try_into()
        .map_err(|_| "Invalid signing key length".to_string())?;
    key_data.zeroize();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
    secret.zeroize();
    Ok(signing_key)
}

/// Load the DID string from identity.json.
fn load_did() -> Result<String, String> {
    let data_dir = get_data_dir().ok_or_else(|| "Data directory not found".to_string())?;
    let identity_path = data_dir.join("identity.json");
    let data = std::fs::read_to_string(&identity_path)
        .map_err(|e| format!("Failed to read identity.json: {e}"))?;
    let v: serde_json::Value =
        serde_json::from_str(&data).map_err(|e| format!("Invalid identity.json: {e}"))?;
    v.get("did")
        .and_then(|d| d.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "DID not found in identity.json".to_string())
}

/// Load the WritersProof API key, if available.
fn load_api_key() -> Result<String, String> {
    let data_dir = get_data_dir().ok_or_else(|| "Data directory not found".to_string())?;
    let key_path = data_dir.join("writersproof_api_key");
    std::fs::read_to_string(&key_path)
        .map(|s| s.trim().to_string())
        .map_err(|e| format!("Failed to read API key: {e}"))
}

/// Anchor a document's latest checkpoint to the WritersProof transparency log.
///
/// Uses the latest event_hash from the store (matching CLI behavior), signs
/// the raw hash bytes with Ed25519, and submits to the WritersProof API.
/// Requires a valid API key stored at `~/.writerslogic/writersproof_api_key`.
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

    let result = rt.block_on(async {
        use crate::writersproof::{AnchorMetadata, AnchorRequest, WritersProofClient};

        let client = WritersProofClient::new("https://api.writersproof.com").with_jwt(api_key);

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
