// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use chrono::Utc;
use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::physics::puf::SiliconPUF;

use super::error::KeyHierarchyError;
use super::types::PUFProvider;

const SOFTWARE_PUF_SEED_NAME: &str = "puf_seed";

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SoftwarePUF {
    device_id: String,
    #[zeroize(skip)]
    seed_path: PathBuf,
    seed: Vec<u8>,
}

impl SoftwarePUF {
    pub fn new() -> Result<Self, KeyHierarchyError> {
        let seed_path = writerslogic_dir().join(SOFTWARE_PUF_SEED_NAME);
        Self::new_with_path(seed_path)
    }

    pub fn new_with_path(seed_path: impl AsRef<Path>) -> Result<Self, KeyHierarchyError> {
        let seed_path = seed_path.as_ref().to_path_buf();
        let mut puf = SoftwarePUF {
            device_id: String::new(),
            seed: Vec::new(),
            seed_path,
        };
        puf.load_or_create_seed()?;
        Ok(puf)
    }

    pub fn new_from_seed(
        device_id: impl Into<String>,
        seed: Vec<u8>,
    ) -> Result<Self, KeyHierarchyError> {
        if seed.len() != 32 {
            return Err(KeyHierarchyError::Crypto(format!(
                "PUF seed must be 32 bytes, got {}",
                seed.len()
            )));
        }
        Ok(SoftwarePUF {
            device_id: device_id.into(),
            seed,
            seed_path: PathBuf::new(),
        })
    }

    fn load_or_create_seed(&mut self) -> Result<(), KeyHierarchyError> {
        if let Ok(Some(seed)) = crate::identity::SecureStorage::load_seed() {
            let mut seed = Zeroizing::new(seed);
            if seed.len() == 32 {
                self.seed = std::mem::take(&mut *seed);
                self.device_id = self.compute_device_id();
                return Ok(());
            }
        }

        if let Ok(data) = fs::read(&self.seed_path) {
            let mut data = Zeroizing::new(data);
            if data.len() == 32 {
                if let Err(e) = crate::identity::SecureStorage::save_seed(&data) {
                    eprintln!(
                        "Warning: Failed to migrate PUF seed to secure storage: {}",
                        e
                    );
                } else {
                    let _ = fs::remove_file(&self.seed_path);
                }
                self.seed = std::mem::take(&mut *data);
                self.device_id = self.compute_device_id();
                return Ok(());
            }
        }

        let seed = self.generate_seed()?;

        if let Err(e) = crate::identity::SecureStorage::save_seed(&seed) {
            eprintln!(
                "Warning: Secure storage unavailable ({}), using file-based storage",
                e
            );
            if let Some(parent) = self.seed_path.parent() {
                fs::create_dir_all(parent)?;
            }
            let tmp_path = self.seed_path.with_extension("tmp");
            fs::write(&tmp_path, &seed)?;
            fs::rename(tmp_path, &self.seed_path)?;
        }

        self.seed = seed;
        self.device_id = self.compute_device_id();
        Ok(())
    }

    fn generate_seed(&self) -> Result<Vec<u8>, KeyHierarchyError> {
        let mut hasher = Sha256::new();

        let mut random_bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut random_bytes);
        hasher.update(random_bytes);
        hasher.update(b"witnessd-software-puf-v1");

        if let Ok(hostname) = hostname::get() {
            hasher.update(hostname.to_string_lossy().as_bytes());
        }

        if let Some(home) = dirs::home_dir() {
            hasher.update(home.to_string_lossy().as_bytes());
        }

        if let Ok(exe) = std::env::current_exe() {
            hasher.update(exe.to_string_lossy().as_bytes());
        }

        hasher.update(std::env::consts::OS.as_bytes());
        hasher.update(std::env::consts::ARCH.as_bytes());
        hasher.update(Utc::now().to_rfc3339().as_bytes());

        Ok(hasher.finalize().to_vec())
    }

    fn compute_device_id(&self) -> String {
        let digest = Sha256::digest(&self.seed);
        format!("swpuf-{}", hex::encode(&digest[0..4]))
    }

    pub fn seed(&self) -> Vec<u8> {
        self.seed.clone()
    }

    pub fn seed_path(&self) -> PathBuf {
        self.seed_path.clone()
    }

    pub fn get_seed(&self) -> [u8; 32] {
        let mut arr = [0u8; 32];
        if self.seed.len() == 32 {
            arr.copy_from_slice(&self.seed);
        }
        arr
    }

    pub fn get_mnemonic(&self) -> Result<String, KeyHierarchyError> {
        crate::identity::mnemonic::MnemonicHandler::entropy_to_phrase(&self.seed)
            .map_err(|e| KeyHierarchyError::Crypto(e.to_string()))
    }

    pub fn recover_from_mnemonic(
        seed_path: &Path,
        phrase: &str,
    ) -> Result<Self, KeyHierarchyError> {
        let entropy = crate::identity::mnemonic::MnemonicHandler::phrase_to_entropy(phrase)
            .map_err(|e| KeyHierarchyError::Crypto(e.to_string()))?;

        if entropy.len() != 16 && entropy.len() != 32 {
            return Err(KeyHierarchyError::Crypto("Invalid entropy length".into()));
        }

        let seed = if entropy.len() == 32 {
            entropy
        } else {
            Sha256::digest(&entropy).to_vec()
        };

        if let Err(e) = crate::identity::SecureStorage::save_seed(&seed) {
            eprintln!(
                "Warning: Secure storage unavailable ({}), using file-based storage",
                e
            );
            if let Some(parent) = seed_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(seed_path, &seed)?;
        } else {
            if seed_path.exists() {
                let _ = fs::remove_file(seed_path);
            }
        }

        Self::new_with_path(seed_path)
    }
}

impl PUFProvider for SoftwarePUF {
    fn get_response(&self, challenge: &[u8]) -> Result<Vec<u8>, KeyHierarchyError> {
        if self.seed.is_empty() {
            return Err(KeyHierarchyError::SoftwarePUFInit);
        }

        let hk = Hkdf::<Sha256>::new(Some(challenge), &self.seed);
        let mut response = [0u8; 32];
        hk.expand(b"puf-response-v1", &mut response)
            .map_err(|_| KeyHierarchyError::Crypto("HKDF expand failed".to_string()))?;
        Ok(response.to_vec())
    }

    fn device_id(&self) -> String {
        self.device_id.clone()
    }
}

/// Returns the preferred PUF provider: hardware-based (SiliconPUF) when available,
/// falling back to software PUF (random seed persisted to disk).
///
/// Hardware PUF derives identity from stable hardware identifiers (CPU, system info),
/// providing deterministic machine identity without persistent state.
pub fn get_or_create_puf() -> Result<Box<dyn PUFProvider>, KeyHierarchyError> {
    Ok(Box::new(HardwarePUF::new()?))
}

fn writerslogic_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("WLD_DATA_DIR") {
        return PathBuf::from(dir);
    }
    if let Some(home) = dirs::home_dir() {
        return home.join(".writerslogic");
    }
    PathBuf::from(".writerslogic")
}

struct HardwarePUF {
    device_id: String,
    seed: [u8; 32],
}

impl Drop for HardwarePUF {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

impl HardwarePUF {
    fn new() -> Result<Self, KeyHierarchyError> {
        let seed = SiliconPUF::generate_fingerprint();
        let digest = Sha256::digest(seed);
        Ok(Self {
            device_id: format!("puf-{}", hex::encode(&digest[0..4])),
            seed,
        })
    }
}

impl PUFProvider for HardwarePUF {
    fn get_response(&self, challenge: &[u8]) -> Result<Vec<u8>, KeyHierarchyError> {
        let hk = Hkdf::<Sha256>::new(Some(challenge), &self.seed);
        let mut response = [0u8; 32];
        hk.expand(b"puf-response-v1", &mut response)
            .map_err(|_| KeyHierarchyError::Crypto("HKDF expand failed".to_string()))?;
        Ok(response.to_vec())
    }

    fn device_id(&self) -> String {
        self.device_id.clone()
    }
}
