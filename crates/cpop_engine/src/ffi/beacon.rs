// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::ffi::helpers::{get_data_dir, open_store};
use zeroize::Zeroize;

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

fn load_api_key() -> Result<zeroize::Zeroizing<String>, String> {
    let data_dir = get_data_dir().ok_or_else(|| "Data directory not found".to_string())?;
    let key_path = data_dir.join("writersproof_api_key");
    let key = std::fs::read_to_string(&key_path)
        .map(|s| s.trim().to_string())
        .map_err(|e| format!("Failed to read API key: {e}"))?;
    Ok(zeroize::Zeroizing::new(key))
}

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
    let evidence_hash = hex::encode(latest.event_hash);

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

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => return err_beacon(format!("Failed to create async runtime: {e}")),
    };

    let effective_timeout = timeout_secs.max(5);

    let client = match crate::writersproof::WritersProofClient::new("https://api.writerslogic.com")
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
