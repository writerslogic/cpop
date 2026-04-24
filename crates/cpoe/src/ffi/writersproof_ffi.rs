// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::ffi::helpers::{load_api_key, load_did, load_signing_key, open_store};
use crate::ffi::types::FfiResult;

/// Anchor a document's latest checkpoint to the WritersProof transparency log.
///
/// Uses the latest event_hash from the store (matching CLI behavior), signs
/// the raw hash bytes with Ed25519, and submits to the WritersProof API.
/// Requires a valid API key stored at `~/Library/Application Support/WritersProof/writersproof_api_key`.
///
/// Note: Function named with underscore in `writers_proof` so UniFFI generates
/// `ffiAnchorToWritersProof` (capital P) matching the Swift call site.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_anchor_to_writers_proof(document_path: String) -> FfiResult {
    if document_path.len() > 4096 {
        return FfiResult::err("Document path too long".to_string());
    }
    let doc_path = match crate::sentinel::helpers::validate_path(&document_path) {
        Ok(p) => p,
        Err(e) => {
            return FfiResult::err(format!("Invalid document path: {e}"));
        }
    };

    let doc_path = match doc_path.canonicalize() {
        Ok(p) => p,
        Err(e) => {
            return FfiResult::err(format!("Cannot resolve document path: {e}"));
        }
    };

    // Load events from store to get the latest event_hash (matches CLI behavior)
    let store = match open_store() {
        Ok(s) => s,
        Err(e) => {
            return FfiResult::err(e);
        }
    };
    let doc_path_str = doc_path.to_string_lossy().into_owned();
    let events = match store.get_events_for_file(&doc_path_str) {
        Ok(e) => e,
        Err(e) => {
            return FfiResult::err(format!("Failed to load events: {e}"));
        }
    };
    let latest = match events.last() {
        Some(ev) => ev,
        None => {
            return FfiResult::err("No checkpoints found for this document".to_string());
        }
    };

    if latest.content_hash.len() != 32 || latest.event_hash.len() != 32 {
        return FfiResult::err("Corrupt checkpoint: invalid hash length".to_string());
    }

    // EH-011: evidence_hash must bind to document content, not duplicate event_hash.
    let evidence_hash = hex::encode(latest.content_hash);

    // Load signing key and sign the raw hash bytes (matches CLI: signing_key.sign(latest.event_hash.as_slice()))
    let signing_key = match load_signing_key() {
        Ok(k) => k,
        Err(e) => {
            return FfiResult::err(e);
        }
    };
    let signature = {
        use ed25519_dalek::Signer;
        hex::encode(signing_key.sign(latest.event_hash.as_slice()).to_bytes())
    };
    // signing_key implements Zeroize on Drop via ed25519-dalek

    let did = match load_did() {
        Ok(d) => d,
        Err(e) => {
            return FfiResult::err(format!("DID identity required for anchor: {e}"));
        }
    };
    let api_key = match load_api_key() {
        Ok(k) if k.is_empty() => {
            return FfiResult::err("WritersProof API key is empty".to_string());
        }
        Ok(k) => k,
        Err(e) => {
            return FfiResult::err(format!("WritersProof API key not configured. {e}"));
        }
    };

    let doc_name = doc_path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_string());

    let rt = match crate::ffi::beacon::beacon_runtime() {
        Ok(rt) => rt,
        Err(e) => {
            return FfiResult::err(format!("Failed to get async runtime: {e}"));
        }
    };

    let client = match crate::writersproof::WritersProofClient::new(
        crate::writersproof::client::DEFAULT_API_URL,
    ) {
        Ok(c) => c.with_jwt(api_key),
        Err(e) => {
            return FfiResult::err(format!("Failed to create API client: {e}"));
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
        Err(_) => FfiResult::err("Anchor request timed out after 30s".to_string()),
        Ok(Err(e)) => FfiResult::err(format!("Anchor request failed: {e}")),
        Ok(Ok(resp)) => FfiResult::ok(format!(
            "Anchored: {} (log index {})",
            resp.anchor_id, resp.log_index
        )),
    }
}

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_publish_evidence(
    document_path: String,
    attestation: String,
    ai_declaration: Option<String>,
) -> crate::ffi::types::FfiPublishResult {
    use crate::ffi::types::FfiPublishResult;

    let fail = |msg: String| FfiPublishResult {
        success: false,
        canonical_url: None,
        record_id: None,
        verification_passed: false,
        checkpoint_count: 0,
        error_message: Some(msg),
    };

    const MAX_ATTESTATION_LEN: usize = 1_000_000;
    if attestation.is_empty() {
        return fail("Author attestation is required to publish".to_string());
    }
    if attestation.len() > MAX_ATTESTATION_LEN {
        return fail(format!("Attestation too large: {} bytes (max {MAX_ATTESTATION_LEN})", attestation.len()));
    }
    if let Some(ref decl) = ai_declaration {
        if decl.len() > MAX_ATTESTATION_LEN {
            return fail(format!("AI declaration too large: {} bytes (max {MAX_ATTESTATION_LEN})", decl.len()));
        }
    }

    if document_path.len() > 4096 {
        return fail("Document path too long".to_string());
    }
    let doc_path = match crate::sentinel::helpers::validate_path(&document_path) {
        Ok(p) => p,
        Err(e) => return fail(format!("Invalid document path: {e}")),
    };
    let doc_path = match doc_path.canonicalize() {
        Ok(p) => p,
        Err(e) => return fail(format!("Cannot resolve document path: {e}")),
    };
    let doc_path_str = doc_path.to_string_lossy().into_owned();

    // Flush a final checkpoint to capture the latest document state.
    if let Some(sentinel) = crate::ffi::sentinel::get_sentinel() {
        if !sentinel.commit_checkpoint_for_path(&doc_path_str) {
            log::warn!("final checkpoint flush failed; publishing with existing data");
        }
    }

    let store = match open_store() {
        Ok(s) => s,
        Err(e) => return fail(e),
    };
    let events = match store.get_events_for_file(&doc_path_str) {
        Ok(e) => e,
        Err(e) => return fail(format!("Failed to load events: {e}")),
    };
    let latest = match events.last() {
        Some(ev) => ev,
        None => return fail("No checkpoints found for this document".to_string()),
    };
    let checkpoint_count = events.len() as u64;

    if checkpoint_count < 2 {
        return fail("At least 2 checkpoints are required before publishing".to_string());
    }

    if latest.content_hash.len() != 32 || latest.event_hash.len() != 32 {
        return fail("Corrupt checkpoint: invalid hash length".to_string());
    }

    // Verify chain integrity: each event's previous_hash must match prior event_hash.
    let chain_valid = events.windows(2).all(|w| w[1].previous_hash == w[0].event_hash);
    if !chain_valid {
        return FfiPublishResult {
            success: false,
            canonical_url: None,
            record_id: None,
            verification_passed: false,
            checkpoint_count,
            error_message: Some("Evidence chain verification failed. Cannot publish tampered evidence.".to_string()),
        };
    }

    let evidence_hash = hex::encode(latest.content_hash);

    let signing_key = match load_signing_key() {
        Ok(k) => k,
        Err(e) => return fail(e),
    };
    let signature = {
        use ed25519_dalek::Signer;
        hex::encode(signing_key.sign(latest.event_hash.as_slice()).to_bytes())
    };

    let did = match load_did() {
        Ok(d) => d,
        Err(e) => return fail(format!("Author identity required to publish. {e}")),
    };
    let api_key = match load_api_key() {
        Ok(k) => k,
        Err(e) => return fail(format!("WritersProof account required to publish. {e}")),
    };

    let doc_name = doc_path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_string());

    let rt = match crate::ffi::beacon::beacon_runtime() {
        Ok(rt) => rt,
        Err(e) => return fail(format!("Failed to get async runtime: {e}")),
    };

    let client = match crate::writersproof::WritersProofClient::new(
        crate::writersproof::client::DEFAULT_API_URL,
    ) {
        Ok(c) => c.with_jwt(api_key),
        Err(e) => return fail(format!("Failed to create API client: {e}")),
    };

    let result = rt.block_on(async {
        tokio::time::timeout(
            std::time::Duration::from_secs(30),
            client.publish(crate::writersproof::types::PublishRequest {
                evidence_hash,
                author_did: did,
                signature,
                attestation,
                checkpoint_count,
                document_name: doc_name,
                ai_declaration,
            }),
        )
        .await
    });

    match result {
        Err(_) => fail("Publish request timed out after 30s".to_string()),
        Ok(Err(e)) => fail(format!("Publish failed: {e}")),
        Ok(Ok(resp)) => FfiPublishResult {
            success: true,
            canonical_url: Some(resp.canonical_url),
            record_id: Some(resp.record_id),
            verification_passed: true,
            checkpoint_count,
            error_message: None,
        },
    }
}

/// Sync a text attestation to the WritersProof API for public verification.
///
/// Called after `ffi_attest_text` stores the attestation locally. Submits the
/// hash, tier, and signature so verifiers can look it up at
/// `verify.writersproof.com`.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sync_text_attestation(
    content_hash: String,
    tier: String,
    writersproof_id: String,
    attested_at: String,
    app_bundle_id: String,
) -> FfiResult {
    if content_hash.len() != 64 || !content_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return FfiResult::err("content_hash must be 64 hex characters".to_string());
    }
    if writersproof_id.len() != 8 {
        return FfiResult::err("writersproof_id must be 8 hex characters".to_string());
    }

    let signing_key = match load_signing_key() {
        Ok(k) => zeroize::Zeroizing::new(k),
        Err(e) => return FfiResult::err(format!("Signing key unavailable: {e}")),
    };

    let public_key_hex = hex::encode(signing_key.verifying_key().as_bytes());

    // Sign with domain separation: DST || content_hash_bytes.
    let signature_hex = {
        use ed25519_dalek::Signer;
        const DST: &[u8] = b"witnessd-text-attest-v1";
        let hash_bytes = match hex::decode(&content_hash) {
            Ok(b) => b,
            Err(e) => return FfiResult::err(format!("Invalid content_hash hex: {e}")),
        };
        let mut payload = Vec::with_capacity(DST.len() + hash_bytes.len());
        payload.extend_from_slice(DST);
        payload.extend_from_slice(&hash_bytes);
        hex::encode(signing_key.sign(&payload).to_bytes())
    };
    drop(signing_key);

    let api_key = match load_api_key() {
        Ok(k) if k.is_empty() => {
            return FfiResult::err("WritersProof API key is empty".to_string());
        }
        Ok(k) => k,
        Err(_) => {
            // No API key — skip sync silently (offline/unauthenticated mode).
            return FfiResult::ok("Skipped: no API key configured".to_string());
        }
    };

    let rt = match crate::ffi::beacon::beacon_runtime() {
        Ok(rt) => rt,
        Err(e) => return FfiResult::err(format!("Failed to get async runtime: {e}")),
    };

    let client = match crate::writersproof::WritersProofClient::new(
        crate::writersproof::client::DEFAULT_API_URL,
    ) {
        Ok(c) => c.with_jwt(api_key),
        Err(e) => return FfiResult::err(format!("Failed to create API client: {e}")),
    };

    let req = crate::writersproof::types::TextAttestationRequest {
        content_hash,
        tier,
        writersproof_id: writersproof_id.clone(),
        signature_hex,
        public_key_hex,
        attested_at,
        app_bundle_id: Some(app_bundle_id).filter(|s| !s.is_empty()),
        device_id: None,
    };

    let result = rt.block_on(async {
        tokio::time::timeout(std::time::Duration::from_secs(15), client.submit_text_attestation(req)).await
    });

    match result {
        Err(_) => FfiResult::err("Text attestation sync timed out".to_string()),
        Ok(Err(e)) => FfiResult::err(format!("Text attestation sync failed: {e}")),
        Ok(Ok(_)) => FfiResult::ok(format!("Synced: {writersproof_id}")),
    }
}
