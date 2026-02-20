use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use keyring::Entry;

const SERVICE_NAME: &str = "com.witnessd.identity";
const SEED_ACCOUNT: &str = "default_seed";
const HMAC_ACCOUNT: &str = "hmac_key";
const MNEMONIC_ACCOUNT: &str = "mnemonic_phrase";

pub struct SecureStorage;

impl SecureStorage {
    // --- Generic Helpers ---

    fn save(account: &str, data: &[u8]) -> Result<()> {
        let entry = Entry::new(SERVICE_NAME, account)
            .map_err(|e| anyhow!("Failed to access keyring: {}", e))?;

        let encoded = general_purpose::STANDARD.encode(data);
        entry
            .set_password(&encoded)
            .map_err(|e| anyhow!("Failed to save to keyring: {}", e))?;
        Ok(())
    }

    fn load(account: &str) -> Result<Option<Vec<u8>>> {
        let entry = Entry::new(SERVICE_NAME, account)
            .map_err(|e| anyhow!("Failed to access keyring: {}", e))?;

        match entry.get_password() {
            Ok(encoded) => {
                let data = general_purpose::STANDARD
                    .decode(&encoded)
                    .map_err(|e| anyhow!("Failed to decode data from keyring: {}", e))?;
                Ok(Some(data))
            }
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(anyhow!("Keyring error: {}", e)),
        }
    }

    fn delete(account: &str) -> Result<()> {
        let entry = Entry::new(SERVICE_NAME, account)
            .map_err(|e| anyhow!("Failed to access keyring: {}", e))?;

        match entry.delete_password() {
            Ok(_) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(anyhow!("Failed to delete from keyring: {}", e)),
        }
    }

    // --- Specific Accessors ---

    pub fn save_seed(seed: &[u8]) -> Result<()> {
        Self::save(SEED_ACCOUNT, seed)
    }

    pub fn load_seed() -> Result<Option<Vec<u8>>> {
        Self::load(SEED_ACCOUNT)
    }

    pub fn delete_seed() -> Result<()> {
        Self::delete(SEED_ACCOUNT)
    }

    pub fn save_hmac_key(key: &[u8]) -> Result<()> {
        Self::save(HMAC_ACCOUNT, key)
    }

    pub fn load_hmac_key() -> Result<Option<Vec<u8>>> {
        Self::load(HMAC_ACCOUNT)
    }

    pub fn save_mnemonic(phrase: &str) -> Result<()> {
        Self::save(MNEMONIC_ACCOUNT, phrase.as_bytes())
    }

    pub fn load_mnemonic() -> Result<Option<String>> {
        let bytes = Self::load(MNEMONIC_ACCOUNT)?;
        if let Some(b) = bytes {
            let s =
                String::from_utf8(b).map_err(|e| anyhow!("Invalid UTF-8 in mnemonic: {}", e))?;
            Ok(Some(s))
        } else {
            Ok(None)
        }
    }
}
