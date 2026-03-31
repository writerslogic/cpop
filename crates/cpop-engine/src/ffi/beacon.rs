// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::ffi::helpers::{load_api_key, load_did, load_signing_key, open_store};
use std::sync::OnceLock;

static BEACON_RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

fn beacon_runtime() -> Result<&'static tokio::runtime::Runtime, String> {
    if let Some(rt) = BEACON_RUNTIME.get() {
        return Ok(rt);
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .thread_name("cpop-beacon")
        .build()
        .map_err(|e| format!("Failed to create beacon tokio runtime: {e}"))?;
    Ok(BEACON_RUNTIME.get_or_init(|| rt))
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiBeaconResult {
    pub success: bool,
    pub anchor_id: Option<String>,
    pub timestamp_epoch_ms: Option<i64>,
    pub drand_round: Option<u64>,
    pub nist_pulse: Option<u64>,
    pub wp_signature_hex: Option<String>,
    pub verification_url: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiBeaconListResult {
    pub success: bool,
    pub beacons: Vec<FfiBeaconResult>,
    pub error_message: Option<String>,
}

fn err_beacon(msg: String) -> FfiBeaconResult {
    FfiBeaconResult {
        success: false,
        anchor_id: None,
        timestamp_epoch_ms: None,
        drand_round: None,
        nist_pulse: None,
        wp_signature_hex: None,
        verification_url: None,
        error_message: Some(msg),
    }
}

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_submit_beacon(document_path: String, timeout_secs: u64) -> FfiBeaconResult {
    let canonical = match crate::sentinel::helpers::validate_path(&document_path) {
        Ok(p) => p.to_string_lossy().to_string(),
        Err(e) => return err_beacon(e),
    };

    let store = match open_store() {
        Ok(s) => s,
        Err(e) => return err_beacon(e),
    };

    let events = match store.get_events_for_file(&canonical) {
        Ok(e) => e,
        Err(e) => return err_beacon(format!("Failed to load events: {e}")),
    };

    let latest = match events.last() {
        Some(ev) => ev,
        None => return err_beacon("No checkpoints found for this document".to_string()),
    };

    let checkpoint_hash = hex::encode(latest.event_hash);
    // EH-011: evidence_hash must bind to the document content, not duplicate event_hash.
    let evidence_hash = hex::encode(latest.content_hash);

    let signing_key = match load_signing_key() {
        Ok(k) => k,
        Err(e) => return err_beacon(e),
    };
    let signature = {
        use ed25519_dalek::Signer;
        hex::encode(signing_key.sign(latest.event_hash.as_slice()).to_bytes())
    };

    let did = load_did().unwrap_or_else(|_| "unknown".into());
    let api_key = match load_api_key() {
        Ok(k) => k,
        Err(e) => return err_beacon(format!("WritersProof API key not configured. {e}")),
    };
    if api_key.trim().is_empty() {
        return err_beacon("WritersProof API key is empty".to_string());
    }

    let rt = match beacon_runtime() {
        Ok(rt) => rt,
        Err(e) => return err_beacon(format!("Failed to create async runtime: {e}")),
    };

    let effective_timeout = timeout_secs.max(5);

    let client = match crate::writersproof::WritersProofClient::new("https://api.writersproof.com")
    {
        Ok(c) => c.with_jwt((*api_key).clone()),
        Err(e) => return err_beacon(format!("Failed to create API client: {e}")),
    };

    let result = rt.block_on(async {
        let beacon_future = client.fetch_beacon(&checkpoint_hash, effective_timeout);

        let anchor_future = async {
            use crate::writersproof::{AnchorMetadata, AnchorRequest};

            let doc_name = std::path::Path::new(&canonical)
                .file_name()
                .and_then(|n| n.to_str())
                .map(|s| s.to_string());

            client
                .anchor(AnchorRequest {
                    evidence_hash: evidence_hash.clone(),
                    author_did: did.clone(),
                    signature: signature.clone(),
                    metadata: Some(AnchorMetadata {
                        document_name: doc_name,
                        tier: Some("beacon".into()),
                    }),
                })
                .await
        };

        let timeout = std::time::Duration::from_secs(effective_timeout);
        tokio::time::timeout(timeout, async {
            let (beacon_res, anchor_res) = tokio::join!(beacon_future, anchor_future);
            (beacon_res, anchor_res)
        })
        .await
    });

    match result {
        Err(_) => err_beacon(format!(
            "Beacon request timed out after {effective_timeout}s"
        )),
        Ok((beacon_res, anchor_res)) => {
            let anchor_id = anchor_res.ok().map(|r| r.anchor_id);

            match beacon_res {
                Err(e) => err_beacon(format!("Beacon fetch failed: {e}")),
                Ok(beacon) => {
                    let ts_ms = chrono::DateTime::parse_from_rfc3339(&beacon.fetched_at)
                        .map(|dt| dt.timestamp_millis())
                        .ok();

                    FfiBeaconResult {
                        success: true,
                        verification_url: anchor_id
                            .as_ref()
                            .map(|id| format!("https://writerslogic.com/verify/{id}")),
                        anchor_id,
                        timestamp_epoch_ms: ts_ms,
                        drand_round: Some(beacon.drand_round),
                        nist_pulse: Some(beacon.nist_pulse_index),
                        wp_signature_hex: Some(beacon.wp_signature),
                        error_message: None,
                    }
                }
            }
        }
    }
}

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_check_beacon_status(document_path: String) -> FfiBeaconResult {
    let canonical = match crate::sentinel::helpers::validate_path(&document_path) {
        Ok(p) => p.to_string_lossy().to_string(),
        Err(e) => return err_beacon(e),
    };

    let data = match std::fs::read(&canonical) {
        Ok(d) => d,
        Err(e) => return err_beacon(format!("Failed to read file: {e}")),
    };

    let packet = match crate::evidence::Packet::decode(&data) {
        Ok(p) => p,
        Err(_) => {
            return check_beacon_from_store(&canonical);
        }
    };

    match packet.beacon_attestation {
        Some(beacon) => {
            let ts_ms = chrono::DateTime::parse_from_rfc3339(&beacon.fetched_at)
                .map(|dt| dt.timestamp_millis())
                .ok();

            FfiBeaconResult {
                success: true,
                anchor_id: None,
                timestamp_epoch_ms: ts_ms,
                drand_round: Some(beacon.drand_round),
                nist_pulse: Some(beacon.nist_pulse_index),
                wp_signature_hex: Some(beacon.wp_signature),
                verification_url: None,
                error_message: None,
            }
        }
        None => FfiBeaconResult {
            success: true,
            anchor_id: None,
            timestamp_epoch_ms: None,
            drand_round: None,
            nist_pulse: None,
            wp_signature_hex: None,
            verification_url: None,
            error_message: Some("No beacon attestation found in evidence".to_string()),
        },
    }
}

fn check_beacon_from_store(canonical: &str) -> FfiBeaconResult {
    let store = match open_store() {
        Ok(s) => s,
        Err(e) => return err_beacon(e),
    };

    let events = match store.get_events_for_file(canonical) {
        Ok(e) => e,
        Err(e) => return err_beacon(format!("Failed to load events: {e}")),
    };

    if events.is_empty() {
        return err_beacon("No checkpoints found for this document".to_string());
    }

    FfiBeaconResult {
        success: true,
        anchor_id: None,
        timestamp_epoch_ms: None,
        drand_round: None,
        nist_pulse: None,
        wp_signature_hex: None,
        verification_url: None,
        error_message: Some("No beacon attestation submitted yet".to_string()),
    }
}

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_list_beacons(document_path: String) -> FfiBeaconListResult {
    let canonical = match crate::sentinel::helpers::validate_path(&document_path) {
        Ok(p) => p.to_string_lossy().to_string(),
        Err(e) => {
            return FfiBeaconListResult {
                success: false,
                beacons: vec![],
                error_message: Some(e),
            };
        }
    };

    let data = match std::fs::read(&canonical) {
        Ok(d) => d,
        Err(_) => {
            return FfiBeaconListResult {
                success: true,
                beacons: vec![],
                error_message: None,
            };
        }
    };

    let packet = match crate::evidence::Packet::decode(&data) {
        Ok(p) => p,
        Err(_) => {
            return FfiBeaconListResult {
                success: true,
                beacons: vec![],
                error_message: None,
            };
        }
    };

    let mut beacons = Vec::new();
    if let Some(beacon) = packet.beacon_attestation {
        let ts_ms = chrono::DateTime::parse_from_rfc3339(&beacon.fetched_at)
            .map(|dt| dt.timestamp_millis())
            .ok();

        beacons.push(FfiBeaconResult {
            success: true,
            anchor_id: None,
            timestamp_epoch_ms: ts_ms,
            drand_round: Some(beacon.drand_round),
            nist_pulse: Some(beacon.nist_pulse_index),
            wp_signature_hex: Some(beacon.wp_signature),
            verification_url: None,
            error_message: None,
        });
    }

    FfiBeaconListResult {
        success: true,
        beacons,
        error_message: None,
    }
}
