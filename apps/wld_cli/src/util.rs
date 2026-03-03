// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Shared utility functions for the WritersLogic CLI.

use anyhow::{anyhow, Result};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use wld_engine::config::WLDConfig;
use wld_engine::vdf::params::Parameters as VdfParameters;
use wld_engine::{derive_hmac_key, SecureStore};
use zeroize::Zeroize;

pub fn writerslogic_dir() -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("WLD_DATA_DIR") {
        return Ok(PathBuf::from(dir));
    }
    let home = dirs::home_dir().ok_or_else(|| anyhow!("Could not determine home directory"))?;
    Ok(home.join(".writerslogic"))
}

pub fn ensure_dirs() -> Result<WLDConfig> {
    let dir = writerslogic_dir()?;
    let config = WLDConfig::load_or_default(&dir)?;

    let dirs = [
        config.data_dir.clone(),
        config.data_dir.join("chains"),
        config.data_dir.join("sessions"),
        config.data_dir.join("tracking"),
        config.data_dir.join("sentinel"),
        config.data_dir.join("sentinel").join("wal"),
    ];

    for d in &dirs {
        fs::create_dir_all(d).map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                anyhow!(
                    "Permission denied creating directory: {}\n\n\
                     Check that you have write access to this location.",
                    d.display()
                )
            } else {
                anyhow!("Failed to create directory {}: {}", d.display(), e)
            }
        })?;

        // The .writerslogic directory contains keys, events, and other sensitive data.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(d, fs::Permissions::from_mode(0o700)).map_err(|e| {
                anyhow!(
                    "Failed to set restrictive permissions on {}: {}",
                    d.display(),
                    e
                )
            })?;
        }
    }

    Ok(config)
}

pub fn load_vdf_params(config: &WLDConfig) -> VdfParameters {
    VdfParameters::from(config.clone())
}

pub fn load_signing_key(dir: &Path) -> Result<SigningKey> {
    let key_path = dir.join("signing_key");
    let mut key_data = fs::read(&key_path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => anyhow!(
            "WitnessD has not been initialized yet.\n\n\
             Run 'wld init' to set up WitnessD for the first time."
        ),
        std::io::ErrorKind::PermissionDenied => anyhow!(
            "Permission denied: {}\n\n\
             Check that you have read access to the WitnessD data directory.",
            key_path.display()
        ),
        _ => anyhow!("Failed to read signing key: {}", e),
    })?;
    let mut seed: [u8; 32] = if key_data.len() == 32 {
        let arr: [u8; 32] = key_data[..32]
            .try_into()
            .map_err(|_| anyhow!("Invalid signing key"))?;
        key_data.zeroize();
        arr
    } else if key_data.len() == 64 {
        let s: [u8; 32] = key_data[..32]
            .try_into()
            .map_err(|_| anyhow!("Invalid signing key"))?;
        key_data.zeroize();
        s
    } else {
        let actual_len = key_data.len();
        key_data.zeroize();
        return Err(anyhow!(
            "Invalid signing key: expected 32 or 64 bytes, got {}",
            actual_len
        ));
    };
    let key = SigningKey::from_bytes(&seed);
    seed.zeroize();
    Ok(key)
}

pub fn open_secure_store() -> Result<SecureStore> {
    let config = ensure_dirs()?;
    let dir = config.data_dir;
    let db_path = dir.join("events.db");

    if let Ok(Some(hmac_key)) = wld_engine::identity::SecureStorage::load_hmac_key() {
        return SecureStore::open(&db_path, hmac_key).map_err(|e| {
            anyhow!(
                "Database error: {}\n\n\
                 If this persists, check if another process is using the database.",
                e
            )
        });
    }

    let signing_key = load_signing_key(&dir)?;
    let hmac_key = derive_hmac_key(&signing_key.to_bytes());

    if let Err(e) = wld_engine::identity::SecureStorage::save_hmac_key(&hmac_key) {
        eprintln!(
            "Warning: Failed to migrate signing key to secure storage: {}",
            e
        );
    }

    SecureStore::open(&db_path, hmac_key).map_err(|e| {
        anyhow!(
            "Database error: {}\n\n\
             If this persists, check if another process is using the database.",
            e
        )
    })
}

pub fn get_device_id() -> Result<[u8; 16]> {
    let dir = writerslogic_dir()?;
    let key_path = dir.join("signing_key.pub");
    let pub_key = fs::read(&key_path)
        .map_err(|e| anyhow::anyhow!("Cannot read signing_key.pub (run `wld init` first): {e}"))?;
    let h = Sha256::digest(&pub_key);
    let mut id = [0u8; 16];
    id.copy_from_slice(&h[..16]);
    Ok(id)
}

pub fn validate_session_id(id: &str) -> Result<&str> {
    if id.is_empty() {
        anyhow::bail!("Session ID cannot be empty");
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        anyhow::bail!(
            "Session ID contains invalid characters \
             (only alphanumeric, hyphens, and underscores allowed)"
        );
    }
    Ok(id)
}

pub fn get_machine_id() -> String {
    hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}
