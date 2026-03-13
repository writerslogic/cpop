// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use keyring::Entry;
#[cfg_attr(not(target_os = "macos"), allow(unused_imports))]
use std::sync::{Once, OnceLock};
#[cfg_attr(not(target_os = "macos"), allow(unused_imports))]
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::ProtectedBuf;

const SERVICE_NAME: &str = "com.writerslogic.identity";
const SEED_ACCOUNT: &str = "default_seed";
const HMAC_ACCOUNT: &str = "hmac_key";
const MNEMONIC_ACCOUNT: &str = "mnemonic_phrase";
const DEVICE_ID_ACCOUNT: &str = "device_id";
const MACHINE_ID_ACCOUNT: &str = "machine_id";
const FINGERPRINT_KEY_ACCOUNT: &str = "fingerprint_key";

static SEED_CACHE: OnceLock<ProtectedBuf> = OnceLock::new();
static HMAC_CACHE: OnceLock<ProtectedBuf> = OnceLock::new();
static FINGERPRINT_KEY_CACHE: OnceLock<ProtectedBuf> = OnceLock::new();
static MNEMONIC_CACHE: OnceLock<String> = OnceLock::new();
static IDENTITY_CACHE: OnceLock<([u8; 16], String)> = OnceLock::new();
#[cfg(target_os = "macos")]
static MIGRATION_ONCE: Once = Once::new();

pub struct SecureStorage;

#[cfg(not(target_os = "macos"))]
fn keyring_entry(account: &str) -> Result<Entry> {
    Entry::new(SERVICE_NAME, account).map_err(|e| anyhow!("Failed to access keyring: {}", e))
}

impl SecureStorage {
    fn save(account: &str, data: &[u8]) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            Self::save_macos(account, data)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let entry = keyring_entry(account)?;
            let encoded = general_purpose::STANDARD.encode(data);
            entry
                .set_password(&encoded)
                .map_err(|e| anyhow!("Failed to save to keyring: {}", e))?;
            Ok(())
        }
    }

    fn load(account: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        #[cfg(target_os = "macos")]
        {
            Self::migrate_macos_keychain();
            Self::load_macos(account)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let entry = keyring_entry(account)?;
            match entry.get_password() {
                Ok(encoded) => {
                    let data = general_purpose::STANDARD
                        .decode(&encoded)
                        .map_err(|e| anyhow!("Failed to decode data from keyring: {}", e))?;
                    Ok(Some(Zeroizing::new(data)))
                }
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(e) => Err(anyhow!("Keyring error: {}", e)),
            }
        }
    }

    fn delete(account: &str) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            Self::delete_macos(account)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let entry = keyring_entry(account)?;
            match entry.delete_password() {
                Ok(_) => Ok(()),
                Err(keyring::Error::NoEntry) => Ok(()),
                Err(e) => Err(anyhow!("Failed to delete from keyring: {}", e)),
            }
        }
    }

    #[cfg(target_os = "macos")]
    fn save_macos(account: &str, data: &[u8]) -> Result<()> {
        use core_foundation::base::TCFType;
        use core_foundation::data::CFData;
        use core_foundation::dictionary::CFDictionary;
        use core_foundation::string::CFString;
        use security_framework_sys::item::{
            kSecAttrAccount, kSecAttrService, kSecClass, kSecClassGenericPassword, kSecValueData,
        };
        use security_framework_sys::keychain_item::SecItemAdd;

        let _ = Self::delete_macos(account);

        let encoded = general_purpose::STANDARD.encode(data);
        let encoded_cf = CFData::from_buffer(encoded.as_bytes());
        let service_cf = CFString::new(SERVICE_NAME);
        let account_cf = CFString::new(account);

        let k_sec_attr_accessible = CFString::new("pdmn");
        let v_sec_attr_accessible = unsafe {
            core_foundation::base::CFType::wrap_under_get_rule(
                security_framework_sys::access_control::kSecAttrAccessibleWhenUnlockedThisDeviceOnly
                    as _,
            )
        };

        let dict = CFDictionary::from_CFType_pairs(&[
            (
                unsafe { CFString::wrap_under_get_rule(kSecClass as _) },
                unsafe {
                    core_foundation::base::CFType::wrap_under_get_rule(
                        kSecClassGenericPassword as _,
                    )
                },
            ),
            (
                unsafe { CFString::wrap_under_get_rule(kSecAttrService as _) },
                service_cf.as_CFType(),
            ),
            (
                unsafe { CFString::wrap_under_get_rule(kSecAttrAccount as _) },
                account_cf.as_CFType(),
            ),
            (
                unsafe { CFString::wrap_under_get_rule(kSecValueData as _) },
                encoded_cf.as_CFType(),
            ),
            (k_sec_attr_accessible, v_sec_attr_accessible),
        ]);

        let status = unsafe { SecItemAdd(dict.as_concrete_TypeRef(), std::ptr::null_mut()) };
        if status != security_framework_sys::base::errSecSuccess {
            return Err(anyhow!("Keychain add failed with status: {}", status));
        }

        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn load_macos(account: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        use core_foundation::base::{CFType, TCFType};
        use core_foundation::boolean::CFBoolean;
        use core_foundation::dictionary::CFDictionary;
        use core_foundation::string::CFString;
        use security_framework_sys::item::{
            kSecAttrAccount, kSecAttrService, kSecClass, kSecClassGenericPassword, kSecMatchLimit,
        };
        use security_framework_sys::keychain_item::SecItemCopyMatching;

        let service_cf = CFString::new(SERVICE_NAME);
        let account_cf = CFString::new(account);

        let k_sec_match_limit = unsafe { CFString::wrap_under_get_rule(kSecMatchLimit as _) };
        let v_sec_match_limit_one = core_foundation::number::CFNumber::from(1).as_CFType();

        let k_sec_return_data = CFString::new("r_Data");

        let query = CFDictionary::from_CFType_pairs(&[
            (
                unsafe { CFString::wrap_under_get_rule(kSecClass as _) },
                unsafe { CFType::wrap_under_get_rule(kSecClassGenericPassword as _) },
            ),
            (
                unsafe { CFString::wrap_under_get_rule(kSecAttrService as _) },
                service_cf.as_CFType(),
            ),
            (
                unsafe { CFString::wrap_under_get_rule(kSecAttrAccount as _) },
                account_cf.as_CFType(),
            ),
            (k_sec_return_data, CFBoolean::true_value().as_CFType()),
            (k_sec_match_limit, v_sec_match_limit_one),
        ]);

        let mut result: core_foundation_sys::base::CFTypeRef = std::ptr::null_mut();
        let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result) };

        if status == security_framework_sys::base::errSecSuccess && !result.is_null() {
            let data_cf =
                unsafe { core_foundation::data::CFData::wrap_under_create_rule(result as _) };
            let mut encoded = String::from_utf8(data_cf.bytes().to_vec())
                .map_err(|e| anyhow!("Invalid UTF-8 in keychain data: {}", e))?;
            let decoded = general_purpose::STANDARD.decode(&encoded).map_err(|e| {
                encoded.zeroize();
                anyhow!("Failed to decode base64 from keychain: {}", e)
            })?;
            encoded.zeroize();
            Ok(Some(Zeroizing::new(decoded)))
        } else if status == -25300
        /* errSecItemNotFound */
        {
            Ok(None)
        } else {
            Err(anyhow!("Keychain search failed with status: {}", status))
        }
    }

    #[cfg(target_os = "macos")]
    fn delete_macos(account: &str) -> Result<()> {
        use core_foundation::base::TCFType;
        use core_foundation::dictionary::CFDictionary;
        use core_foundation::string::CFString;
        use security_framework_sys::item::{
            kSecAttrAccount, kSecAttrService, kSecClass, kSecClassGenericPassword,
        };
        use security_framework_sys::keychain_item::SecItemDelete;

        let service_cf = CFString::new(SERVICE_NAME);
        let account_cf = CFString::new(account);

        let query = CFDictionary::from_CFType_pairs(&[
            (
                unsafe { CFString::wrap_under_get_rule(kSecClass as _) },
                unsafe {
                    core_foundation::base::CFType::wrap_under_get_rule(
                        kSecClassGenericPassword as _,
                    )
                },
            ),
            (
                unsafe { CFString::wrap_under_get_rule(kSecAttrService as _) },
                service_cf.as_CFType(),
            ),
            (
                unsafe { CFString::wrap_under_get_rule(kSecAttrAccount as _) },
                account_cf.as_CFType(),
            ),
        ]);

        let status = unsafe { SecItemDelete(query.as_concrete_TypeRef()) };
        if status == security_framework_sys::base::errSecSuccess || status == -25300
        /* errSecItemNotFound */
        {
            Ok(())
        } else {
            Err(anyhow!("Keychain delete failed with status: {}", status))
        }
    }

    #[cfg(target_os = "macos")]
    fn migrate_macos_keychain() {
        MIGRATION_ONCE.call_once(|| {
            let home_dir = match dirs::home_dir() {
                Some(h) => h,
                None => return,
            };
            let data_dir = home_dir.join(".writerslogic");

            if data_dir
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                log::warn!(
                    "Migration path contains traversal components, skipping: {}",
                    data_dir.display()
                );
                return;
            }

            // If data_dir already exists, resolve symlinks and verify it's
            // still under the home directory to prevent redirection attacks.
            if data_dir.exists() {
                match std::fs::canonicalize(&data_dir) {
                    Ok(resolved) => {
                        let canonical_home =
                            std::fs::canonicalize(&home_dir).unwrap_or_else(|_| home_dir.clone());
                        if !resolved.starts_with(&canonical_home) {
                            log::warn!(
                                "Migration path resolves outside home directory, skipping: \
                                 {} -> {}",
                                data_dir.display(),
                                resolved.display()
                            );
                            return;
                        }
                    }
                    Err(e) => {
                        log::warn!(
                            "Cannot resolve migration path, skipping: {}: {}",
                            data_dir.display(),
                            e
                        );
                        return;
                    }
                }
            }

            let flag_path = data_dir.join(".keychain_migrated_v1");
            if flag_path.exists() {
                // Refuse to read/trust a symlinked flag file
                if flag_path
                    .symlink_metadata()
                    .is_ok_and(|m| m.file_type().is_symlink())
                {
                    log::warn!(
                        "Migration flag is a symlink, skipping: {}",
                        flag_path.display()
                    );
                    return;
                }
                return;
            }

            log::info!("Starting one-time macOS keychain access policy migration...");

            let accounts = [
                SEED_ACCOUNT,
                HMAC_ACCOUNT,
                MNEMONIC_ACCOUNT,
                DEVICE_ID_ACCOUNT,
                MACHINE_ID_ACCOUNT,
                FINGERPRINT_KEY_ACCOUNT,
            ];

            for account in accounts {
                if let Ok(entry) = Entry::new(SERVICE_NAME, account) {
                    if let Ok(encoded) = entry.get_password() {
                        if let Ok(data) = general_purpose::STANDARD.decode(&encoded) {
                            let data = Zeroizing::new(data);
                            if Self::save_macos(account, &data).is_ok() {
                                let _ = entry.delete_password();
                            }
                        }
                    }
                }
            }

            let _ = std::fs::create_dir_all(&data_dir);

            // Verify flag_path is not a symlink before writing (race window
            // is narrow but check anyway as a defense-in-depth measure)
            if flag_path
                .symlink_metadata()
                .is_ok_and(|m| m.file_type().is_symlink())
            {
                log::warn!(
                    "Migration flag appeared as symlink during write, skipping: {}",
                    flag_path.display()
                );
                return;
            }
            let _ = std::fs::write(&flag_path, "done");
            log::info!("macOS keychain migration complete.");
        });
    }

    pub fn save_seed(seed: &[u8]) -> Result<()> {
        Self::save(SEED_ACCOUNT, seed)
    }

    pub fn load_seed() -> Result<Option<Vec<u8>>> {
        if let Some(cached) = SEED_CACHE.get() {
            return Ok(Some(cached.as_slice().to_vec()));
        }
        let res = Self::load(SEED_ACCOUNT)?;
        if let Some(data) = res {
            let _ = SEED_CACHE.set(ProtectedBuf::new(data.to_vec()));
            Ok(Some(data.to_vec()))
        } else {
            Ok(None)
        }
    }

    pub fn delete_seed() -> Result<()> {
        Self::delete(SEED_ACCOUNT)
    }

    pub fn save_hmac_key(key: &[u8]) -> Result<()> {
        Self::save(HMAC_ACCOUNT, key)
    }

    pub fn load_hmac_key() -> Result<Option<Zeroizing<Vec<u8>>>> {
        if let Some(cached) = HMAC_CACHE.get() {
            return Ok(Some(Zeroizing::new(cached.as_slice().to_vec())));
        }
        let res = Self::load(HMAC_ACCOUNT)?;
        if let Some(data) = res {
            let _ = HMAC_CACHE.set(ProtectedBuf::new(data.to_vec()));
            Ok(Some(data))
        } else {
            Ok(None)
        }
    }

    pub fn save_mnemonic(phrase: &str) -> Result<()> {
        Self::save(MNEMONIC_ACCOUNT, phrase.as_bytes())
    }

    pub fn load_mnemonic() -> Result<Option<String>> {
        if let Some(cached) = MNEMONIC_CACHE.get() {
            return Ok(Some(cached.clone()));
        }
        let bytes = Self::load(MNEMONIC_ACCOUNT)?;
        if let Some(b) = bytes {
            let s = String::from_utf8(b.to_vec())
                .map_err(|e| anyhow!("Invalid UTF-8 in mnemonic: {}", e))?;
            let _ = MNEMONIC_CACHE.set(s.clone());
            Ok(Some(s))
        } else {
            Ok(None)
        }
    }

    pub fn save_device_identity(device_id: &[u8; 16], machine_id: &str) -> Result<()> {
        Self::save(DEVICE_ID_ACCOUNT, device_id)?;
        Self::save(MACHINE_ID_ACCOUNT, machine_id.as_bytes())?;
        Ok(())
    }

    pub fn load_device_identity() -> Result<Option<([u8; 16], String)>> {
        if let Some(cached) = IDENTITY_CACHE.get() {
            return Ok(Some(cached.clone()));
        }
        let device_id_bytes = Self::load(DEVICE_ID_ACCOUNT)?;
        let machine_id_bytes = Self::load(MACHINE_ID_ACCOUNT)?;

        match (device_id_bytes, machine_id_bytes) {
            (Some(did), Some(mid)) => {
                let mut device_id = [0u8; 16];
                if did.len() == 16 {
                    device_id.copy_from_slice(&did);
                } else {
                    return Err(anyhow!("Invalid device ID length in keyring"));
                }
                let machine_id = String::from_utf8(mid.to_vec())
                    .map_err(|e| anyhow!("Invalid UTF-8 in machine ID from keyring: {}", e))?;
                let _ = IDENTITY_CACHE.set((device_id, machine_id.clone()));
                Ok(Some((device_id, machine_id)))
            }
            _ => Ok(None),
        }
    }

    pub fn delete_device_identity() -> Result<()> {
        Self::delete(DEVICE_ID_ACCOUNT)?;
        Self::delete(MACHINE_ID_ACCOUNT)?;
        Ok(())
    }

    pub fn save_fingerprint_key(key: &[u8]) -> Result<()> {
        Self::save(FINGERPRINT_KEY_ACCOUNT, key)
    }

    pub fn load_fingerprint_key() -> Result<Option<Vec<u8>>> {
        if let Some(cached) = FINGERPRINT_KEY_CACHE.get() {
            return Ok(Some(cached.as_slice().to_vec()));
        }
        let res = Self::load(FINGERPRINT_KEY_ACCOUNT)?;
        if let Some(data) = res {
            let _ = FINGERPRINT_KEY_CACHE.set(ProtectedBuf::new(data.to_vec()));
            Ok(Some(data.to_vec()))
        } else {
            Ok(None)
        }
    }
}
