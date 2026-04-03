// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use rusqlite::Connection;
use std::path::Path;
use zeroize::Zeroize;

pub mod access_log;
pub mod baselines;
pub mod document_stats;
pub mod events;
pub mod fingerprints;
pub mod integrity;
pub mod types;

#[cfg(test)]
mod tests;

pub use document_stats::DocumentStats;
pub use types::SecureEvent;

/// SQLite busy timeout in milliseconds. Shared with `AccessLog` (see `access_log.rs`).
pub(crate) const BUSY_TIMEOUT_MS: u32 = 5000;

/// HMAC-integrity-protected SQLite event store with hash chaining.
pub struct SecureStore {
    pub(crate) conn: Connection,
    pub(crate) hmac_key: Vec<u8>,
    pub(crate) last_hash: [u8; 32],
}

impl SecureStore {
    /// Open or create a secure store at `path`, initializing schema and verifying integrity.
    pub fn open<P: AsRef<Path>>(path: P, hmac_key: Vec<u8>) -> anyhow::Result<Self> {
        if hmac_key.len() != 32 {
            anyhow::bail!("HMAC key must be exactly 32 bytes, got {}", hmac_key.len());
        }
        let path = path.as_ref();
        let conn = Connection::open(path)?;
        #[cfg(unix)]
        crate::crypto::restrict_permissions(path, 0o600)?;

        let _: String = conn.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
        conn.execute_batch(&format!(
            "PRAGMA busy_timeout={BUSY_TIMEOUT_MS}; PRAGMA foreign_keys=ON; \
             PRAGMA synchronous=FULL;"
        ))?;

        let mut store = Self {
            conn,
            hmac_key,
            last_hash: [0u8; 32],
        };

        store.init_schema()?;
        store.verify_integrity()?;

        Ok(store)
    }
}

/// Open a [`SecureStore`] by deriving the HMAC key from an Ed25519 signing key.
///
/// Extracts the key bytes, derives the HMAC key via [`crate::crypto::derive_hmac_key`],
/// zeroizes intermediates, and opens the store at `db_path`.
pub fn open_store_with_signing_key(
    signing_key: &ed25519_dalek::SigningKey,
    db_path: &Path,
) -> anyhow::Result<SecureStore> {
    let mut key_bytes = signing_key.to_bytes();
    let hmac_key = crate::crypto::derive_hmac_key(&key_bytes);
    key_bytes.zeroize();
    SecureStore::open(db_path, hmac_key.to_vec())
}

impl Drop for SecureStore {
    fn drop(&mut self) {
        self.hmac_key.zeroize();
    }
}
