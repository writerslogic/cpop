// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
#[cfg(not(target_os = "macos"))]
use keyring::Entry;
use std::collections::HashMap;
#[cfg_attr(not(target_os = "macos"), allow(unused_imports))]
use std::sync::{Mutex, Once, OnceLock};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::ProtectedBuf;
use crate::MutexRecover;

const SERVICE_NAME: &str = "com.writerslogic.identity";
const SEED_ACCOUNT: &str = "default_seed";
const HMAC_ACCOUNT: &str = "hmac_key";
const MNEMONIC_ACCOUNT: &str = "mnemonic_phrase";
const DEVICE_ID_ACCOUNT: &str = "device_id";
const MACHINE_ID_ACCOUNT: &str = "machine_id";
const FINGERPRINT_KEY_ACCOUNT: &str = "fingerprint_key";

// Lock ordering: SEED_CACHE, HMAC_CACHE, FINGERPRINT_KEY_CACHE, and MNEMONIC_CACHE
// are independent caches. No function acquires more than one of these locks.
/// Mutex instead of OnceLock so the cache can be invalidated after delete_seed().
static SEED_CACHE: Mutex<Option<ProtectedBuf>> = Mutex::new(None);
/// Mutex instead of OnceLock so the cache can be reset after HMAC key recovery.
static HMAC_CACHE: Mutex<Option<ProtectedBuf>> = Mutex::new(None);
/// Mutex instead of OnceLock so the cache can be invalidated after delete.
static FINGERPRINT_KEY_CACHE: Mutex<Option<ProtectedBuf>> = Mutex::new(None);
/// Mutex instead of OnceLock so the cache can be invalidated after re-generation.
static MNEMONIC_CACHE: Mutex<Option<Zeroizing<String>>> = Mutex::new(None);
/// Accepted risk: machine_id (String) is not zeroized. It is a non-secret device
/// identifier, so the residual exposure does not warrant switching to Mutex.
static IDENTITY_CACHE: OnceLock<([u8; 16], String)> = OnceLock::new();
#[cfg(all(target_os = "macos", not(test)))]
static MIGRATION_ONCE: Once = Once::new();

// =========================================================================
// Pluggable keychain backend
// =========================================================================

/// Storage backend for identity secrets. Implementations handle the actual
/// read/write of bytes; `SecureStorage` layers caching and serialization on
/// top. Use `set_backend` to inject a mock in integration tests.
pub trait KeychainBackend: Send + Sync {
    fn save(&self, account: &str, data: &[u8]) -> Result<()>;
    fn load(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>>;
    fn delete(&self, account: &str) -> Result<()>;
    /// True if this backend does not touch an OS-managed keychain. The PUF
    /// module uses this to decide whether the on-disk seed file must remain
    /// as the primary copy.
    fn is_ephemeral(&self) -> bool {
        false
    }
}

#[derive(Debug)]
/// In-memory backend used by unit tests and when `CPOP_NO_KEYCHAIN=1`.
/// State is process-global so writes from one call site are observable by
/// subsequent loads (matching real keychain semantics).
pub struct InMemoryBackend {
    store: Mutex<HashMap<String, Vec<u8>>>,
}

impl InMemoryBackend {
    pub fn new() -> Self {
        Self {
            store: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl KeychainBackend for InMemoryBackend {
    fn save(&self, account: &str, data: &[u8]) -> Result<()> {
        let mut guard = self.store.lock_recover();
        guard.insert(account.to_string(), data.to_vec());
        Ok(())
    }

    fn load(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let guard = self.store.lock_recover();
        Ok(guard.get(account).cloned().map(Zeroizing::new))
    }

    fn delete(&self, account: &str) -> Result<()> {
        let mut guard = self.store.lock_recover();
        guard.remove(account);
        Ok(())
    }

    fn is_ephemeral(&self) -> bool {
        true
    }
}

/// Non-macOS backend using the `keyring` crate (delegates to libsecret/
/// credential-manager/etc. via the platform keyring API).
#[cfg(not(target_os = "macos"))]
pub struct KeyringBackend;

#[cfg(not(target_os = "macos"))]
impl KeychainBackend for KeyringBackend {
    fn save(&self, account: &str, data: &[u8]) -> Result<()> {
        let entry = keyring_entry(account)?;
        let mut encoded = general_purpose::STANDARD.encode(data);
        let result = entry
            .set_password(&encoded)
            .map_err(|e| anyhow!("Failed to save to keyring: {}", e));
        encoded.zeroize();
        result
    }

    fn load(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
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

    fn delete(&self, account: &str) -> Result<()> {
        let entry = keyring_entry(account)?;
        match entry.delete_password() {
            Ok(_) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(anyhow!("Failed to delete from keyring: {}", e)),
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn keyring_entry(account: &str) -> Result<Entry> {
    Entry::new(SERVICE_NAME, account).map_err(|e| anyhow!("Failed to access keyring: {}", e))
}

/// Real macOS Keychain backend using Security.framework `SecItem*` APIs.
/// Calling any of its methods from a `cargo test` session may surface a
/// keychain-access prompt, so tests should install `InMemoryBackend` instead.
#[cfg(target_os = "macos")]
#[derive(Debug)]
pub struct MacosKeychainBackend;

#[cfg(target_os = "macos")]
impl KeychainBackend for MacosKeychainBackend {
    fn save(&self, account: &str, data: &[u8]) -> Result<()> {
        save_macos(account, data)
    }

    fn load(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        #[cfg(not(test))]
        migrate_macos_keychain();
        load_macos(account)
    }

    fn delete(&self, account: &str) -> Result<()> {
        delete_macos(account)
    }
}

/// Global backend selector. Populated lazily by `backend()` on first access.
/// Tests can override via `SecureStorage::set_backend` before the first call.
static BACKEND: OnceLock<Box<dyn KeychainBackend>> = OnceLock::new();

fn default_backend() -> Box<dyn KeychainBackend> {
    // Under `cargo test --lib`, cfg(test) is set for the crate being tested
    // and the in-memory backend becomes the default so unit tests never
    // reach the OS keychain.
    if cfg!(test) || env_disables_keychain() {
        return Box::new(InMemoryBackend::new());
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(MacosKeychainBackend)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Box::new(KeyringBackend)
    }
}

fn env_disables_keychain() -> bool {
    std::env::var("CPOP_NO_KEYCHAIN").is_ok_and(|v| v == "1" || v == "true")
}

fn backend() -> &'static dyn KeychainBackend {
    BACKEND.get_or_init(default_backend).as_ref()
}

/// Platform keychain/keyring abstraction for storing identity secrets.
#[derive(Debug)]
pub struct SecureStorage;

impl SecureStorage {
    /// Install a custom backend. Must be called before any other
    /// `SecureStorage` method; subsequent calls are ignored because the
    /// backend is a `OnceLock`.
    pub fn set_backend(backend: Box<dyn KeychainBackend>) -> std::result::Result<(), &'static str> {
        BACKEND
            .set(backend)
            .map_err(|_| "SecureStorage backend already initialized")
    }

    /// Returns true if keychain access is disabled or routed to an in-memory
    /// store. Callers that rely on real OS persistence (e.g., PUF seed file
    /// migration) use this to decide whether the file-based copy must be
    /// kept as the primary.
    pub fn is_keychain_disabled() -> bool {
        backend().is_ephemeral()
    }

    fn save(account: &str, data: &[u8]) -> Result<()> {
        backend().save(account, data)
    }

    fn load(account: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        backend().load(account)
    }

    fn delete(account: &str) -> Result<()> {
        backend().delete(account)
    }

    /// Store the identity seed in the platform keychain.
    pub fn save_seed(seed: &[u8]) -> Result<()> {
        Self::save(SEED_ACCOUNT, seed)
    }

    /// Load the identity seed from the platform keychain, with caching.
    pub fn load_seed() -> Result<Option<Zeroizing<Vec<u8>>>> {
        if SEED_CACHE.is_poisoned() {
            log::warn!("SEED_CACHE mutex poisoned; recovering");
        }
        let guard = SEED_CACHE.lock_recover();
        if let Some(ref cached) = *guard {
            return Ok(Some(Zeroizing::new(cached.as_slice().to_vec())));
        }
        drop(guard);

        let res = Self::load(SEED_ACCOUNT)?;
        if let Some(data) = res {
            if SEED_CACHE.is_poisoned() {
                log::warn!("SEED_CACHE mutex poisoned; recovering for cache write");
            }
            let mut guard = SEED_CACHE.lock_recover();
            *guard = Some(ProtectedBuf::new(data.to_vec()));
            Ok(Some(data))
        } else {
            Ok(None)
        }
    }

    /// Delete the identity seed from the platform keychain.
    pub fn delete_seed() -> Result<()> {
        Self::delete(SEED_ACCOUNT)?;
        Self::reset_seed_cache();
        Ok(())
    }

    /// Reset the seed cache, forcing the next load to read from keychain.
    pub fn reset_seed_cache() {
        if SEED_CACHE.is_poisoned() {
            log::warn!("SEED_CACHE mutex poisoned; recovering for cache reset");
        }
        *SEED_CACHE.lock_recover() = None;
    }

    /// Store the HMAC key in the platform keychain and update the cache.
    pub fn save_hmac_key(key: &[u8]) -> Result<()> {
        Self::save(HMAC_ACCOUNT, key)?;
        *HMAC_CACHE.lock_recover() = Some(ProtectedBuf::new(key.to_vec()));
        Ok(())
    }

    /// Reset the HMAC key cache, forcing the next load to read from keychain.
    pub fn reset_hmac_cache() {
        *HMAC_CACHE.lock_recover() = None;
    }

    /// Load the HMAC key from the platform keychain, with caching.
    pub fn load_hmac_key() -> Result<Option<Zeroizing<Vec<u8>>>> {
        {
            let guard = HMAC_CACHE.lock_recover();
            if let Some(ref cached) = *guard {
                return Ok(Some(Zeroizing::new(cached.as_slice().to_vec())));
            }
        }
        let res = Self::load(HMAC_ACCOUNT)?;
        if let Some(data) = res {
            *HMAC_CACHE.lock_recover() = Some(ProtectedBuf::new(data.to_vec()));
            Ok(Some(data))
        } else {
            Ok(None)
        }
    }

    /// Store the mnemonic phrase in the platform keychain.
    pub fn save_mnemonic(phrase: &str) -> Result<()> {
        Self::save(MNEMONIC_ACCOUNT, phrase.as_bytes())?;
        *MNEMONIC_CACHE.lock_recover() = Some(Zeroizing::new(phrase.to_string()));
        Ok(())
    }

    /// Load the mnemonic phrase from the platform keychain, with caching.
    /// Returns `Zeroizing<String>` so callers zeroize the mnemonic when done.
    pub fn load_mnemonic() -> Result<Option<Zeroizing<String>>> {
        {
            let guard = MNEMONIC_CACHE.lock_recover();
            if let Some(ref cached) = *guard {
                return Ok(Some(Zeroizing::new(cached.as_str().to_owned())));
            }
        }
        let bytes = Self::load(MNEMONIC_ACCOUNT)?;
        if let Some(b) = bytes {
            let s = String::from_utf8(b.to_vec())
                .map_err(|e| anyhow!("Invalid UTF-8 in mnemonic: {}", e))?;
            *MNEMONIC_CACHE.lock_recover() = Some(Zeroizing::new(s.clone()));
            Ok(Some(Zeroizing::new(s)))
        } else {
            Ok(None)
        }
    }

    /// Reset the mnemonic cache, forcing the next load to read from keychain.
    pub fn reset_mnemonic_cache() {
        *MNEMONIC_CACHE.lock_recover() = None;
    }

    /// Store the device ID and machine ID in the platform keychain.
    pub fn save_device_identity(device_id: &[u8; 16], machine_id: &str) -> Result<()> {
        Self::save(DEVICE_ID_ACCOUNT, device_id)?;
        Self::save(MACHINE_ID_ACCOUNT, machine_id.as_bytes())?;
        Ok(())
    }

    /// Load the device identity (device_id, machine_id) from the platform keychain.
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
                const MAX_MACHINE_ID_LEN: usize = 256;
                if mid.len() > MAX_MACHINE_ID_LEN {
                    return Err(anyhow!(
                        "Machine ID from keyring exceeds maximum length ({} > {})",
                        mid.len(),
                        MAX_MACHINE_ID_LEN
                    ));
                }
                let machine_id = String::from_utf8(mid.to_vec())
                    .map_err(|e| anyhow!("Invalid UTF-8 in machine ID from keyring: {}", e))?;
                let _ = IDENTITY_CACHE.set((device_id, machine_id.clone()));
                Ok(Some((device_id, machine_id)))
            }
            _ => Ok(None),
        }
    }

    /// Delete the device identity from the platform keychain.
    pub fn delete_device_identity() -> Result<()> {
        Self::delete(DEVICE_ID_ACCOUNT)?;
        Self::delete(MACHINE_ID_ACCOUNT)?;
        Ok(())
    }

    /// Store the fingerprint key in the platform keychain.
    pub fn save_fingerprint_key(key: &[u8]) -> Result<()> {
        Self::save(FINGERPRINT_KEY_ACCOUNT, key)
    }

    /// Load the fingerprint key from the platform keychain, with caching.
    pub fn load_fingerprint_key() -> Result<Option<Zeroizing<Vec<u8>>>> {
        {
            let guard = FINGERPRINT_KEY_CACHE.lock_recover();
            if let Some(ref cached) = *guard {
                return Ok(Some(Zeroizing::new(cached.as_slice().to_vec())));
            }
        }
        let res = Self::load(FINGERPRINT_KEY_ACCOUNT)?;
        if let Some(data) = res {
            *FINGERPRINT_KEY_CACHE.lock_recover() = Some(ProtectedBuf::new(data.to_vec()));
            Ok(Some(Zeroizing::new(data.to_vec())))
        } else {
            Ok(None)
        }
    }

    /// Reset the fingerprint key cache, forcing the next load to read from keychain.
    pub fn reset_fingerprint_key_cache() {
        *FINGERPRINT_KEY_CACHE.lock_recover() = None;
    }
}

// =========================================================================
// macOS Security.framework implementation
// =========================================================================

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

    let _ = delete_macos(account);

    let mut encoded = general_purpose::STANDARD.encode(data);
    let encoded_cf = CFData::from_buffer(encoded.as_bytes());
    encoded.zeroize();
    let service_cf = CFString::new(SERVICE_NAME);
    let account_cf = CFString::new(account);

    // "pdmn" is the Keychain schema column name for kSecAttrAccessible
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
                core_foundation::base::CFType::wrap_under_get_rule(kSecClassGenericPassword as _)
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

    // "r_Data" is the Keychain schema column name for kSecReturnData
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
        let data_cf = unsafe { core_foundation::data::CFData::wrap_under_create_rule(result as _) };
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
                core_foundation::base::CFType::wrap_under_get_rule(kSecClassGenericPassword as _)
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

#[cfg(all(target_os = "macos", not(test)))]
fn migrate_macos_keychain() {
    MIGRATION_ONCE.call_once(|| {
        let home_dir = match dirs::home_dir() {
            Some(h) => h,
            None => return,
        };
        let data_dir = home_dir.join(".writersproof");

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

        let mut any_failed = false;
        for account in accounts {
            if let Ok(entry) = keyring::Entry::new(SERVICE_NAME, account) {
                if let Ok(mut encoded) = entry.get_password() {
                    if let Ok(data) = general_purpose::STANDARD.decode(&encoded) {
                        encoded.zeroize();
                        let data = Zeroizing::new(data);
                        match save_macos(account, &data) {
                            Ok(()) => {
                                let _ = entry.delete_password();
                            }
                            Err(e) => {
                                log::warn!("Keychain migration failed for {account}: {e}");
                                any_failed = true;
                            }
                        }
                    } else {
                        encoded.zeroize();
                    }
                }
            }
        }

        if any_failed {
            log::warn!("Keychain migration incomplete; will retry on next launch");
            return;
        }

        if let Err(e) = std::fs::create_dir_all(&data_dir) {
            log::error!(
                "Failed to create data directory {}: {e}",
                data_dir.display()
            );
            return;
        }

        // After create_dir_all, verify data_dir is a real directory
        // (not a symlink someone raced in during creation)
        match data_dir.symlink_metadata() {
            Ok(m) if m.file_type().is_symlink() => {
                log::warn!(
                    "Data directory is a symlink after creation, skipping: {}",
                    data_dir.display()
                );
                return;
            }
            Ok(m) if !m.is_dir() => {
                log::warn!(
                    "Data path is not a directory after creation, skipping: {}",
                    data_dir.display()
                );
                return;
            }
            Err(e) => {
                log::warn!(
                    "Cannot verify data directory after creation: {}: {e}",
                    data_dir.display()
                );
                return;
            }
            _ => {}
        }

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
        let _ = {
            #[cfg(unix)]
            {
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                std::fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(&flag_path)
                    .and_then(|mut f| f.write_all(b"done"))
            }
            #[cfg(not(unix))]
            std::fs::write(&flag_path, "done")
        };
        log::info!("macOS keychain migration complete.");
    });
}

#[cfg(test)]
mod backend_tests {
    use super::*;

    #[test]
    fn in_memory_backend_round_trip() {
        let b = InMemoryBackend::new();
        b.save("acct", b"hello").unwrap();
        let loaded = b.load("acct").unwrap().expect("some");
        assert_eq!(loaded.as_slice(), b"hello");
        b.delete("acct").unwrap();
        assert!(b.load("acct").unwrap().is_none());
    }

    #[test]
    fn in_memory_backend_is_ephemeral() {
        assert!(InMemoryBackend::new().is_ephemeral());
    }

    #[test]
    fn default_backend_under_test_is_ephemeral() {
        // Under cfg(test) the global backend must be in-memory so cargo
        // test never reaches the OS keychain.
        assert!(SecureStorage::is_keychain_disabled());
    }
}
