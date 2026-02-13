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
