// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use rusqlite::Connection;
use std::path::Path;
use zeroize::Zeroize;

pub mod baselines;
pub mod events;
pub mod fingerprints;
pub mod integrity;
pub mod types;

#[cfg(test)]
mod tests;

pub use types::SecureEvent;

/// HMAC-integrity-protected SQLite event store with hash chaining.
pub struct SecureStore {
    pub(crate) conn: Connection,
    pub(crate) hmac_key: Vec<u8>,
    pub(crate) last_hash: [u8; 32],
}

impl SecureStore {
    /// Open or create a secure store at `path`, initializing schema and verifying integrity.
    pub fn open<P: AsRef<Path>>(path: P, hmac_key: Vec<u8>) -> anyhow::Result<Self> {
        let conn = Connection::open(path)?;

        let _: String = conn.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
        conn.execute_batch("PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON;")?;

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

impl Drop for SecureStore {
    fn drop(&mut self) {
        self.hmac_key.zeroize();
    }
}
