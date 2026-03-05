// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::forensics::EventData;
use crate::rfc::wire_types::AttestationTier;
use crate::store::SecureStore;
use std::path::PathBuf;
use zeroize::Zeroizing;

/// Maximum Shannon entropy for the edit-position histogram (log2(20 bins)).
pub const ENTROPY_NORMALIZATION_FACTOR: f64 = 4.321928;

pub(crate) fn get_data_dir() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        dirs::home_dir().map(|h| h.join("Library/Application Support/WritersLogic"))
    }
    #[cfg(not(target_os = "macos"))]
    {
        dirs::data_local_dir().map(|d| d.join("WritersLogic"))
    }
}

pub(crate) fn get_db_path() -> Option<PathBuf> {
    get_data_dir().map(|d| d.join("events.db"))
}

pub(crate) fn load_hmac_key() -> Option<Zeroizing<Vec<u8>>> {
    if let Ok(Some(key)) = crate::identity::SecureStorage::load_hmac_key() {
        return Some(key);
    }

    let data_dir = get_data_dir()?;
    let key_path = data_dir.join("signing_key");
    let key_data = Zeroizing::new(std::fs::read(&key_path).ok()?);
    let seed = if key_data.len() >= 32 {
        &key_data[..32]
    } else {
        return None;
    };
    let key = Zeroizing::new(crate::crypto::derive_hmac_key(seed));

    if let Err(e) = crate::identity::SecureStorage::save_hmac_key(&key) {
        log::warn!("Failed to migrate signing key to secure storage: {}", e);
    }

    Some(key)
}

pub(crate) fn open_store() -> Result<SecureStore, String> {
    let db_path = get_db_path()
        .filter(|p| p.exists())
        .ok_or_else(|| "Database not found".to_string())?;
    let mut hmac_key = load_hmac_key().ok_or_else(|| "Failed to load signing key".to_string())?;
    SecureStore::open(&db_path, std::mem::take(&mut *hmac_key))
        .map_err(|e| format!("Failed to open database: {}", e))
}

pub(crate) fn detect_attestation_tier() -> AttestationTier {
    let (tier, _, _) = detect_attestation_tier_info();
    tier
}

pub(crate) fn detect_attestation_tier_info() -> (AttestationTier, u8, String) {
    let provider = crate::tpm::detect_provider();
    let caps = provider.capabilities();
    if caps.hardware_backed && caps.supports_sealing {
        (
            AttestationTier::HardwareBound,
            3,
            "hardware-bound".to_string(),
        )
    } else if caps.hardware_backed && caps.supports_attestation {
        (
            AttestationTier::AttestedSoftware,
            2,
            "attested-software".to_string(),
        )
    } else {
        (
            AttestationTier::SoftwareOnly,
            1,
            "software-only".to_string(),
        )
    }
}

pub(crate) fn events_to_forensic_data(events: &[crate::store::SecureEvent]) -> Vec<EventData> {
    events
        .iter()
        .enumerate()
        .map(|(i, e)| EventData {
            id: e.id.unwrap_or(i64::try_from(i).unwrap_or(i64::MAX)),
            timestamp_ns: e.timestamp_ns,
            file_size: e.file_size,
            size_delta: e.size_delta,
            file_path: e.file_path.clone(),
        })
        .collect()
}
