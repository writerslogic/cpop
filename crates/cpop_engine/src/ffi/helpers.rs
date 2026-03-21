// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::forensics::EventData;
use crate::store::SecureStore;
use cpop_protocol::rfc::wire_types::AttestationTier;
use std::path::PathBuf;
use zeroize::Zeroizing;

/// Maximum Shannon entropy for the edit-position histogram (log2(20 bins)).
pub const ENTROPY_NORMALIZATION_FACTOR: f64 = 4.321928;

/// Shared lock for tests that modify `CPOP_DATA_DIR`.
/// All FFI test modules must use this to avoid env var races.
/// Uses a helper that recovers from poisoned state (previous test panics).
#[cfg(test)]
pub static FFI_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
pub fn lock_ffi_env() -> std::sync::MutexGuard<'static, ()> {
    FFI_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub(crate) fn get_data_dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("CPOP_DATA_DIR") {
        return Some(PathBuf::from(dir));
    }
    #[cfg(target_os = "macos")]
    {
        dirs::home_dir().map(|h| h.join("Library/Application Support/CPOP"))
    }
    #[cfg(not(target_os = "macos"))]
    {
        dirs::data_local_dir().map(|d| d.join("CPOP"))
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
    // Reject files >1KB to guard against symlink-to-large-file DoS
    if let Ok(meta) = std::fs::metadata(&key_path) {
        if meta.len() > 1024 {
            log::error!("Signing key file too large: {} bytes", meta.len());
            return None;
        }
    }
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

/// Load the Ed25519 signing key from the data directory, zeroizing intermediates.
#[allow(dead_code)]
pub(crate) fn load_signing_key() -> Result<ed25519_dalek::SigningKey, String> {
    use zeroize::Zeroize;

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
#[allow(dead_code)]
pub(crate) fn load_did() -> Result<String, String> {
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
#[allow(dead_code)]
pub(crate) fn load_api_key() -> Result<String, String> {
    let data_dir = get_data_dir().ok_or_else(|| "Data directory not found".to_string())?;
    let key_path = data_dir.join("writersproof_api_key");
    std::fs::read_to_string(&key_path)
        .map(|s| s.trim().to_string())
        .map_err(|e| format!("Failed to read API key: {e}"))
}

pub(crate) fn open_store() -> Result<SecureStore, String> {
    let db_path = get_db_path()
        .filter(|p| p.exists())
        .ok_or_else(|| "Database not found".to_string())?;
    open_store_at(&db_path)
}

/// Open or recover a SecureStore at the given path.
///
/// Recovery strategy on HMAC mismatch:
/// 1. Try the signing-key-derived HMAC (handles keychain key transitions)
/// 2. Verify a fresh key is available, THEN delete the stale DB and recreate
pub(crate) fn open_store_at(db_path: &std::path::Path) -> Result<SecureStore, String> {
    let mut hmac_key = load_hmac_key().ok_or_else(|| "Failed to load signing key".to_string())?;
    match SecureStore::open(db_path, std::mem::take(&mut *hmac_key)) {
        Ok(store) => Ok(store),
        Err(primary_err) => {
            let err_msg = primary_err.to_string();
            let is_hmac_mismatch =
                err_msg.contains("HMAC mismatch") || err_msg.contains("hmac mismatch");

            // Strategy 1: try signing-key-derived HMAC
            if let Some(mut key) = derive_hmac_from_signing_key() {
                if let Ok(store) = SecureStore::open(db_path, std::mem::take(&mut *key)) {
                    log::info!("Opened database with signing-key-derived HMAC");
                    if let Some(k) = derive_hmac_from_signing_key() {
                        let _ = crate::identity::SecureStorage::save_hmac_key(&k);
                    }
                    return Ok(store);
                }
            }

            // Strategy 2: verify key available BEFORE deleting, then recreate
            if is_hmac_mismatch {
                // Reset the cache so load_hmac_key re-derives from signing_key
                crate::identity::SecureStorage::reset_hmac_cache();
                let fresh_key = load_hmac_key();
                if let Some(mut k) = fresh_key {
                    log::warn!("HMAC mismatch unrecoverable; deleting stale database");
                    let _ = std::fs::remove_file(db_path);
                    return SecureStore::open(db_path, std::mem::take(&mut *k))
                        .map_err(|e| format!("Failed to recreate database: {}", e));
                }
                // Key unavailable; do NOT delete the DB (preserve data)
                log::error!("HMAC key unavailable; cannot recover database");
            }

            Err(format!("Failed to open database: {}", primary_err))
        }
    }
}

/// Derive HMAC key directly from the signing_key file, bypassing keychain.
pub(crate) fn derive_hmac_from_signing_key() -> Option<Zeroizing<Vec<u8>>> {
    let data_dir = get_data_dir()?;
    let key_path = data_dir.join("signing_key");
    if let Ok(meta) = std::fs::metadata(&key_path) {
        if meta.len() > 1024 {
            return None;
        }
    }
    let key_data = Zeroizing::new(std::fs::read(&key_path).ok()?);
    if key_data.len() >= 32 {
        Some(Zeroizing::new(crate::crypto::derive_hmac_key(
            &key_data[..32],
        )))
    } else {
        None
    }
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

/// Streak statistics computed from a set of active days.
pub(crate) struct StreakStats {
    pub current_streak_days: u32,
    pub longest_streak_days: u32,
    pub active_days_in_window: u32,
}

/// Compute streak and activity stats from nanosecond timestamps.
///
/// `timestamps_ns`: event timestamps in nanoseconds.
/// `today_day`: the current day as Unix epoch / 86400.
/// `window_days`: how many days back to count active days (e.g. 30).
pub(crate) fn compute_streak_stats(
    timestamps_ns: &[i64],
    today_day: i64,
    window_days: i64,
) -> StreakStats {
    let mut active_days: std::collections::BTreeSet<i64> = std::collections::BTreeSet::new();
    for ts in timestamps_ns {
        let day = ts / (86400 * 1_000_000_000);
        active_days.insert(day);
    }

    let active_days_in_window = active_days
        .iter()
        .filter(|d| **d >= today_day - window_days)
        .count() as u32;

    let mut longest_streak: u32 = 0;
    let mut streak: u32 = 0;
    let mut prev_day: Option<i64> = None;

    for &day in active_days.iter().rev() {
        if let Some(prev) = prev_day {
            if prev - day == 1 {
                streak += 1;
            } else {
                longest_streak = longest_streak.max(streak);
                streak = 1;
            }
        } else {
            streak = 1;
        }
        prev_day = Some(day);
    }
    longest_streak = longest_streak.max(streak);

    let mut current_streak: u32 = 0;
    let mut check_day = today_day;
    while active_days.contains(&check_day) {
        current_streak += 1;
        check_day -= 1;
    }
    if current_streak == 0 {
        check_day = today_day - 1;
        while active_days.contains(&check_day) {
            current_streak += 1;
            check_day -= 1;
        }
    }

    StreakStats {
        current_streak_days: current_streak,
        longest_streak_days: longest_streak,
        active_days_in_window,
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
