// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::physics::SiliconPUF;
use anyhow::{anyhow, Result};
use bip39::{Language, Mnemonic};
use rand::Rng;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// 64-byte seed derived from a mnemonic and silicon PUF, zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SensitiveSeed([u8; 64]);

impl AsRef<[u8]> for SensitiveSeed {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// BIP-39 mnemonic generation and PUF-bound seed derivation.
pub struct MnemonicHandler;

impl MnemonicHandler {
    /// Generate a random 12-word BIP-39 mnemonic phrase, zeroized on drop.
    pub fn generate() -> Zeroizing<String> {
        let mut entropy = [0u8; 16];
        rand::rng().fill(&mut entropy);
        let mnemonic = Mnemonic::from_entropy(&entropy).expect("16-byte entropy is valid BIP-39");
        entropy.zeroize();
        Zeroizing::new(mnemonic.to_string())
    }

    /// Derive a 64-byte seed by combining mnemonic entropy with silicon PUF.
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

    /// Compute a short hex fingerprint binding the mnemonic to this machine.
    pub fn get_machine_fingerprint(phrase: &str) -> Result<String> {
        let seed = Self::derive_silicon_seed(phrase)?;
        let mut hasher = Sha256::new();
        hasher.update(seed.as_ref());
        Ok(hex::encode(&hasher.finalize()[..8]))
    }

    /// Extract raw entropy bytes from a BIP-39 mnemonic phrase.
    pub fn phrase_to_entropy(phrase: &str) -> Result<Vec<u8>> {
        let mnemonic = Mnemonic::parse_in(Language::English, phrase)
            .map_err(|_| anyhow!("Invalid mnemonic"))?;
        Ok(mnemonic.to_entropy())
    }

    /// Convert raw entropy bytes into a BIP-39 mnemonic phrase, zeroized on drop.
    pub fn entropy_to_phrase(entropy: &[u8]) -> Result<Zeroizing<String>> {
        let mnemonic = Mnemonic::from_entropy(entropy).map_err(|_| anyhow!("Invalid entropy"))?;
        Ok(Zeroizing::new(mnemonic.to_string()))
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
        let mnemonic = Mnemonic::parse_in(Language::English, &*phrase);
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

        assert_ne!(seed.as_ref(), &[0u8; 64]);
    }

    #[test]
    fn test_machine_fingerprint_structure() {
        let phrase = MnemonicHandler::generate();
        let fp_result = MnemonicHandler::get_machine_fingerprint(&phrase);
        assert!(fp_result.is_ok());
        let fp = fp_result.unwrap();

        assert_eq!(fp.len(), 16); // 8 bytes hex-encoded
        assert!(hex::decode(&fp).is_ok());
    }

    #[test]
    fn test_derive_silicon_seed_determinism() {
        let phrase = MnemonicHandler::generate();
        let seed1 = MnemonicHandler::derive_silicon_seed(&phrase).unwrap();
        let seed2 = MnemonicHandler::derive_silicon_seed(&phrase).unwrap();

        assert_eq!(
            seed1.as_ref(),
            seed2.as_ref(),
            "Seed derivation must be deterministic on the same machine"
        );
    }

    #[test]
    fn test_generate_uniqueness() {
        let p1 = MnemonicHandler::generate();
        let p2 = MnemonicHandler::generate();
        assert_ne!(*p1, *p2, "Two generated mnemonics should differ");
    }

    #[test]
    fn test_generate_all_words_valid_bip39() {
        let phrase = MnemonicHandler::generate();
        // Every word must be in the BIP-39 English wordlist
        let wordlist = bip39::Language::English.word_list();
        for word in phrase.split_whitespace() {
            assert!(
                wordlist.contains(&word),
                "Word '{}' is not in BIP-39 English wordlist",
                word
            );
        }
    }

    #[test]
    fn test_phrase_to_entropy_roundtrip() {
        let phrase = MnemonicHandler::generate();
        let entropy = MnemonicHandler::phrase_to_entropy(&phrase).unwrap();
        assert_eq!(
            entropy.len(),
            16,
            "12-word mnemonic should yield 16 bytes of entropy"
        );

        let recovered = MnemonicHandler::entropy_to_phrase(&entropy).unwrap();
        assert_eq!(
            *phrase, *recovered,
            "entropy -> phrase should recover the original"
        );
    }

    #[test]
    fn test_entropy_to_phrase_roundtrip() {
        let entropy = [42u8; 16];
        let phrase = MnemonicHandler::entropy_to_phrase(&entropy).unwrap();
        let recovered_entropy = MnemonicHandler::phrase_to_entropy(&phrase).unwrap();
        assert_eq!(recovered_entropy, entropy);
    }

    #[test]
    fn test_phrase_to_entropy_invalid() {
        let result = MnemonicHandler::phrase_to_entropy("not a valid mnemonic");
        assert!(result.is_err());
    }

    #[test]
    fn test_entropy_to_phrase_invalid_length() {
        // 15 bytes is not a valid BIP-39 entropy length
        let result = MnemonicHandler::entropy_to_phrase(&[0u8; 15]);
        assert!(result.is_err());
    }

    #[test]
    fn test_derive_silicon_seed_length() {
        let phrase = MnemonicHandler::generate();
        let seed = MnemonicHandler::derive_silicon_seed(&phrase).unwrap();
        assert_eq!(seed.as_ref().len(), 64, "Seed must be exactly 64 bytes");
    }

    #[test]
    fn test_derive_silicon_seed_different_phrases_differ() {
        let p1 = MnemonicHandler::generate();
        let p2 = MnemonicHandler::generate();
        let s1 = MnemonicHandler::derive_silicon_seed(&p1).unwrap();
        let s2 = MnemonicHandler::derive_silicon_seed(&p2).unwrap();
        assert_ne!(
            s1.as_ref(),
            s2.as_ref(),
            "Different mnemonics must produce different seeds"
        );
    }

    #[test]
    fn test_machine_fingerprint_hex_chars() {
        let phrase = MnemonicHandler::generate();
        let fp = MnemonicHandler::get_machine_fingerprint(&phrase).unwrap();
        assert_eq!(fp.len(), 16);
        assert!(
            fp.chars().all(|c| c.is_ascii_hexdigit()),
            "Fingerprint must contain only hex characters, got: {}",
            fp
        );
    }

    #[test]
    fn test_machine_fingerprint_deterministic() {
        let phrase = MnemonicHandler::generate();
        let fp1 = MnemonicHandler::get_machine_fingerprint(&phrase).unwrap();
        let fp2 = MnemonicHandler::get_machine_fingerprint(&phrase).unwrap();
        assert_eq!(
            fp1, fp2,
            "Fingerprint must be deterministic for the same phrase"
        );
    }

    #[test]
    fn test_machine_fingerprint_invalid_phrase() {
        let result = MnemonicHandler::get_machine_fingerprint("invalid phrase");
        assert!(result.is_err());
    }
}
