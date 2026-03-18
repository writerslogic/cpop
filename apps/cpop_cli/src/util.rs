// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{anyhow, Result};
use cpop_engine::config::CpopConfig;
use cpop_engine::vdf::params::Parameters as VdfParameters;
use cpop_engine::{derive_hmac_key, SecureStore};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

/// 500 MB — maximum allowed file size.
pub(crate) const MAX_FILE_SIZE: u64 = 500_000_000;

/// 50 MB — warning threshold for large files.
pub(crate) const LARGE_FILE_WARNING_THRESHOLD: u64 = 50_000_000;

/// File extensions excluded from tracking.
pub(crate) const BLOCKED_EXTENSIONS: &[&str] = &[
    "exe", "dll", "so", "dylib", "o", "a", "obj", "lib", "class", "pyc", "pyo", "wasm", "zip",
    "tar", "gz", "tgz", "bz2", "xz", "zst", "rar", "7z", "dmg", "iso", "jpg", "jpeg", "png", "gif",
    "bmp", "ico", "tiff", "tif", "webp", "heic", "heif", "raw", "svg", "mp3", "mp4", "avi", "mov",
    "wav", "webm", "flac", "aac", "ogg", "mkv", "wmv", "pdf", "db", "sqlite", "sqlite3", "mdb",
    "lock", "tmp", "bak", "swp", "swo", "DS_Store",
];

pub fn writersproof_dir() -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("CPOP_DATA_DIR") {
        return Ok(PathBuf::from(dir));
    }
    let home = dirs::home_dir().ok_or_else(|| anyhow!("Could not determine home directory"))?;
    Ok(home.join(".writersproof"))
}

pub fn ensure_dirs() -> Result<CpopConfig> {
    let dir = writersproof_dir()?;
    let config = CpopConfig::load_or_default(&dir)?;

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
                anyhow!("Permission denied creating directory: {}", d.display())
            } else {
                anyhow!("mkdir {}: {}", d.display(), e)
            }
        })?;

        cpop_engine::restrict_permissions(d, 0o700)
            .map_err(|e| anyhow!("chmod {}: {}", d.display(), e))?;
    }

    Ok(config)
}

pub fn load_vdf_params(config: &CpopConfig) -> VdfParameters {
    VdfParameters {
        iterations_per_second: config.vdf.iterations_per_second,
        min_iterations: config.vdf.min_iterations,
        max_iterations: config.vdf.max_iterations,
    }
}

pub fn load_signing_key(dir: &Path) -> Result<SigningKey> {
    let key_path = dir.join("signing_key");
    let mut key_data = fs::read(&key_path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => anyhow!("CPOP not initialized. Run 'cpop init'."),
        std::io::ErrorKind::PermissionDenied => {
            anyhow!("Permission denied: {}", key_path.display())
        }
        _ => anyhow!("read signing key: {}", e),
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

    if let Ok(Some(hmac_key)) = cpop_engine::identity::SecureStorage::load_hmac_key() {
        let key_vec = Zeroizing::new(hmac_key.to_vec());
        return SecureStore::open(&db_path, (*key_vec).clone())
            .map_err(|e| anyhow!("Database error: {}", e));
    }

    let signing_key = load_signing_key(&dir)?;
    let hmac_key = Zeroizing::new(derive_hmac_key(&signing_key.to_bytes()));

    if let Err(e) = cpop_engine::identity::SecureStorage::save_hmac_key(&hmac_key) {
        eprintln!("Warning: HMAC key migration: {}", e);
    }

    SecureStore::open(&db_path, (*hmac_key).clone()).map_err(|e| anyhow!("Database error: {}", e))
}

pub fn get_device_id() -> Result<[u8; 16]> {
    let dir = writersproof_dir()?;
    let key_path = dir.join("signing_key.pub");
    let pub_key = fs::read(&key_path)
        .map_err(|e| anyhow::anyhow!("Cannot read signing_key.pub (run `cpop init` first): {e}"))?;
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
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "unknown".to_string())
}

pub fn load_did(dir: &Path) -> Result<String> {
    let identity_path = dir.join("identity.json");
    let data = fs::read_to_string(&identity_path)
        .map_err(|_| anyhow!("No identity found. Run 'cpop identity' to create one."))?;
    let identity: serde_json::Value = serde_json::from_str(&data)?;
    identity
        .get("did")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("Identity file missing 'did' field"))
}

pub fn write_restrictive(path: &Path, data: &[u8]) -> Result<()> {
    // Write to temp file first, set permissions, then atomic rename.
    // This prevents a window where the file exists with wrong permissions.
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, data).map_err(|e| anyhow!("write {}: {}", tmp.display(), e))?;
    cpop_engine::restrict_permissions(&tmp, 0o600).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        anyhow!("chmod {}: {}", tmp.display(), e)
    })?;
    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        anyhow!("rename {} → {}: {}", tmp.display(), path.display(), e)
    })?;
    Ok(())
}

pub fn normalize_path(path: &Path) -> Result<PathBuf> {
    let path_str = path.to_string_lossy();
    let expanded = if path_str.starts_with("~/") || path_str == "~" {
        let home = dirs::home_dir().ok_or_else(|| anyhow!("Could not determine home directory"))?;
        if path_str == "~" {
            home
        } else {
            home.join(&path_str[2..])
        }
    } else {
        path.to_path_buf()
    };

    let cleaned = clean_path(&expanded);

    if cleaned.exists() {
        let canonical = fs::canonicalize(&cleaned)
            .map_err(|e| anyhow!("Cannot access path {}: {}", cleaned.display(), e))?;

        #[cfg(target_os = "windows")]
        {
            let s = canonical.to_string_lossy();
            if let Some(stripped) = s.strip_prefix(r"\\?\") {
                return Ok(PathBuf::from(stripped));
            }
        }

        Ok(canonical)
    } else {
        Ok(cleaned)
    }
}

fn clean_path(path: &Path) -> PathBuf {
    let mut cleaned = PathBuf::new();
    for component in path.components() {
        cleaned.push(component);
    }
    cleaned
}

/// Maximum retries for SQLite BUSY errors.
const SQLITE_BUSY_MAX_RETRIES: u32 = 5;

/// Base delay in milliseconds for SQLite BUSY retry backoff.
const SQLITE_BUSY_BASE_DELAY_MS: u64 = 100;

/// Retry a fallible operation with exponential backoff when SQLite is busy.
///
/// Retries up to [`SQLITE_BUSY_MAX_RETRIES`] times with exponential backoff
/// starting at [`SQLITE_BUSY_BASE_DELAY_MS`] when the error message indicates
/// a locked database.
pub(crate) fn retry_on_busy<T, F: FnMut() -> Result<T>>(mut op: F) -> Result<T> {
    let mut last_err = None;
    for attempt in 0..SQLITE_BUSY_MAX_RETRIES {
        match op() {
            Ok(v) => return Ok(v),
            Err(e) => {
                let msg = e.to_string();
                if (msg.contains("database is locked") || msg.contains("SQLITE_BUSY"))
                    && attempt < SQLITE_BUSY_MAX_RETRIES - 1
                {
                    std::thread::sleep(std::time::Duration::from_millis(
                        SQLITE_BUSY_BASE_DELAY_MS * (1 << attempt),
                    ));
                    last_err = Some(e);
                    continue;
                }
                return Err(e);
            }
        }
    }
    Err(last_err.expect("MAX_RETRIES must be > 0"))
}

pub fn load_api_key(dir: &Path) -> Result<String> {
    let key_path = dir.join("api_key");
    fs::read_to_string(&key_path)
        .map(|s| s.trim().to_string())
        .map_err(|_| anyhow!("No WritersProof API key found at: {}", key_path.display()))
}
