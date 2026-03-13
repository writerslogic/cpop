// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::fingerprint::AuthorFingerprint;
use crate::store::SecureStore;
use rusqlite::params;

impl SecureStore {
    /// Load a stored author fingerprint by profile ID.
    pub fn get_fingerprint(&self, profile_id: &str) -> anyhow::Result<Option<AuthorFingerprint>> {
        let mut stmt = self
            .conn
            .prepare("SELECT data_json FROM fingerprints WHERE profile_id = ?")?;
        let mut rows = stmt.query([profile_id])?;

        if let Some(row) = rows.next()? {
            let json: String = row.get(0)?;
            let fingerprint: AuthorFingerprint = serde_json::from_str(&json)?;
            Ok(Some(fingerprint))
        } else {
            Ok(None)
        }
    }

    /// Persist an author fingerprint, replacing any existing one with the same ID.
    pub fn save_fingerprint(&self, fingerprint: &AuthorFingerprint) -> anyhow::Result<()> {
        let json = serde_json::to_string(fingerprint)?;
        let now = chrono::Utc::now().timestamp();

        self.conn.execute(
            "INSERT OR REPLACE INTO fingerprints (profile_id, data_json, updated_at) VALUES (?, ?, ?)",
            params![fingerprint.id, json, now]
        )?;
        Ok(())
    }
}
