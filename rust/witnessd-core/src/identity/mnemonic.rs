use crate::physics::SiliconPUF;
use anyhow::{anyhow, Result};
use bip39::{Language, Mnemonic};
use rand::Rng;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SensitiveSeed([u8; 64]);

impl AsRef<[u8]> for SensitiveSeed {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub struct MnemonicHandler;

impl MnemonicHandler {
    pub fn generate() -> String {
        let mut entropy = [0u8; 16];
        rand::rng().fill(&mut entropy);
        let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
        mnemonic.to_string()
    }

    pub fn derive_silicon_seed(phrase: &str) -> Result<SensitiveSeed> {
        let mut phrase_owned = phrase.to_string();
        let mnemonic = Mnemonic::parse_in(Language::English, &phrase_owned).map_err(|_| {
            phrase_owned.zeroize();
            anyhow!("Invalid mnemonic phrase")
        })?;

        let seed = mnemonic.to_seed("");
        let seed_bytes = seed.as_ref();

        let puf = SiliconPUF::generate_fingerprint();

        let mut hasher = Sha256::new();
        hasher.update(seed_bytes);
        hasher.update(puf);

        let mut out = [0u8; 64];
        let hash_result = hasher.finalize();
        out[..32].copy_from_slice(&hash_result);

        let mut hasher2 = Sha256::new();
        hasher2.update(hash_result);
        hasher2.update(b"expansion");
        out[32..].copy_from_slice(&hasher2.finalize());

        phrase_owned.zeroize();
        Ok(SensitiveSeed(out))
    }

    pub fn get_machine_fingerprint(phrase: &str) -> Result<String> {
        let seed = Self::derive_silicon_seed(phrase)?;
        let mut hasher = Sha256::new();
        hasher.update(seed.as_ref());
        Ok(hex::encode(&hasher.finalize()[..8]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mnemonic_generation_and_validation() {
        let phrase = MnemonicHandler::generate();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        assert_eq!(words.len(), 12); // 128-bit entropy = 12 words

        // Validate it works with BIP39 library directly
        let mnemonic = Mnemonic::parse_in(Language::English, &phrase);
        assert!(mnemonic.is_ok());
    }

    #[test]
    fn test_invalid_mnemonic() {
        let invalid_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invalid";
        let result = MnemonicHandler::derive_silicon_seed(invalid_phrase);
        assert!(result.is_err());
    }

    #[test]
    fn test_silicon_seed_derivation_structure() {
        let phrase = MnemonicHandler::generate();
        let seed_result = MnemonicHandler::derive_silicon_seed(&phrase);
        assert!(seed_result.is_ok());
        let seed = seed_result.unwrap();
        assert_eq!(seed.as_ref().len(), 64);

        // Ensure it's not all zeros
        assert_ne!(seed.as_ref(), &[0u8; 64]);
    }

    #[test]
    fn test_machine_fingerprint_structure() {
        let phrase = MnemonicHandler::generate();
        let fp_result = MnemonicHandler::get_machine_fingerprint(&phrase);
        assert!(fp_result.is_ok());
        let fp = fp_result.unwrap();

        // 8 bytes hex encoded = 16 chars
        assert_eq!(fp.len(), 16);
        // Should be valid hex
        assert!(hex::decode(&fp).is_ok());
    }

    #[test]
    fn test_derive_silicon_seed_determinism_fail() {
        // This documents the current behavior: derivation is NOT deterministic due to PUF jitter.
        // If the implementation changes to be deterministic, this test should be updated to assert_eq!.
        let phrase = MnemonicHandler::generate();
        let seed1 = MnemonicHandler::derive_silicon_seed(&phrase).unwrap();
        let seed2 = MnemonicHandler::derive_silicon_seed(&phrase).unwrap();

        // Currently expected to be different because of SiliconPUF::generate_fingerprint()
        // If this starts failing (i.e., they ARE equal), it means the PUF became stable or mocked.
        assert_ne!(seed1.as_ref(), seed2.as_ref(), "Warning: Seed derivation is unexpectedly deterministic (PUF might be broken or mocked)");
    }
}
