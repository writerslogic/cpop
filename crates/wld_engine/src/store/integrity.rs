// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::crypto;
use crate::store::SecureStore;
use crate::DateTimeNanosExt;
use anyhow::anyhow;
use rusqlite::params;
use subtle::ConstantTimeEq;

impl SecureStore {
    pub(crate) fn init_schema(&self) -> anyhow::Result<()> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS integrity (
                id              INTEGER PRIMARY KEY CHECK (id = 1),
                chain_hash      BLOB NOT NULL,
                event_count     INTEGER NOT NULL DEFAULT 0,
                last_verified   INTEGER,
                hmac            BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS secure_events (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id       BLOB NOT NULL,
                machine_id      TEXT NOT NULL,
                timestamp_ns    INTEGER NOT NULL,
                file_path       TEXT NOT NULL,
                content_hash    BLOB NOT NULL,
                file_size       INTEGER NOT NULL,
                size_delta      INTEGER NOT NULL,
                previous_hash   BLOB NOT NULL,
                event_hash      BLOB NOT NULL UNIQUE,
                hmac            BLOB NOT NULL,
                context_type    TEXT,
                context_note    TEXT,
                vdf_input       BLOB,
                vdf_output      BLOB,
                vdf_iterations  INTEGER DEFAULT 0,
                forensic_score  REAL DEFAULT 1.0,
                is_paste        INTEGER DEFAULT 0,
                hardware_counter INTEGER
            );

            CREATE TABLE IF NOT EXISTS physical_baselines (
                signal_name     TEXT PRIMARY KEY,
                sample_count    INTEGER NOT NULL DEFAULT 0,
                mean            REAL NOT NULL DEFAULT 0.0,
                m2              REAL NOT NULL DEFAULT 0.0
            );

            CREATE TABLE IF NOT EXISTS fingerprints (
                profile_id      TEXT PRIMARY KEY,
                data_json       TEXT NOT NULL,
                updated_at      INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS baseline_digests (
                identity_fingerprint BLOB PRIMARY KEY,
                digest_cbor          BLOB NOT NULL,
                signature            BLOB NOT NULL,
                updated_at           INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_secure_events_timestamp ON secure_events(timestamp_ns);
            CREATE INDEX IF NOT EXISTS idx_secure_events_file ON secure_events(file_path, timestamp_ns);"
        )?;

        // Migration: add `hardware_counter` to pre-existing schemas
        let has_column: bool = self
            .conn
            .prepare("SELECT hardware_counter FROM secure_events LIMIT 0")
            .is_ok();
        if !has_column {
            self.conn
                .execute_batch("ALTER TABLE secure_events ADD COLUMN hardware_counter INTEGER;")?;
        }

        Ok(())
    }

    pub fn verify_integrity(&mut self) -> anyhow::Result<()> {
        let res = self.conn.query_row(
            "SELECT chain_hash, event_count, hmac FROM integrity WHERE id = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        );

        match res {
            Ok((chain_hash, event_count, stored_hmac)) => {
                let chain_hash_arr: [u8; 32] = chain_hash
                    .try_into()
                    .map_err(|_| anyhow!("Invalid chain_hash length in integrity record"))?;

                let expected_hmac =
                    crypto::compute_integrity_hmac(&self.hmac_key, &chain_hash_arr, event_count);
                if stored_hmac.ct_eq(&expected_hmac).unwrap_u8() == 0 {
                    return Err(anyhow!("Integrity record HMAC mismatch"));
                }

                let mut stmt = self.conn.prepare(
                    "SELECT id, event_hash, previous_hash, hmac, device_id, timestamp_ns, file_path, content_hash, file_size, size_delta 
                     FROM secure_events ORDER BY id ASC"
                )?;

                let mut rows = stmt.query([])?;
                let mut last_hash = [0u8; 32];
                let mut count = 0i64;

                while let Some(row) = rows.next()? {
                    let id: i64 = row.get(0)?;
                    let event_hash: Vec<u8> = row.get(1)?;
                    let previous_hash: Vec<u8> = row.get(2)?;
                    let stored_event_hmac: Vec<u8> = row.get(3)?;
                    let device_id: Vec<u8> = row.get(4)?;
                    let timestamp_ns: i64 = row.get(5)?;
                    let file_path: String = row.get(6)?;
                    let content_hash: Vec<u8> = row.get(7)?;
                    let file_size: i64 = row.get(8)?;
                    let size_delta: i32 = row.get(9)?;

                    let device_id_arr = device_id
                        .try_into()
                        .map_err(|_| anyhow!("Invalid device_id"))?;
                    let content_hash_arr = content_hash
                        .try_into()
                        .map_err(|_| anyhow!("Invalid content_hash"))?;
                    let previous_hash_arr = previous_hash
                        .try_into()
                        .map_err(|_| anyhow!("Invalid previous_hash"))?;

                    if count > 0 && previous_hash_arr != last_hash {
                        return Err(anyhow!("Chain break at event {}", id));
                    }

                    let expected_event_hash = crypto::compute_event_hash(
                        &device_id_arr,
                        timestamp_ns,
                        &file_path,
                        &content_hash_arr,
                        file_size,
                        size_delta,
                        &previous_hash_arr,
                    );
                    if event_hash.ct_eq(&expected_event_hash).unwrap_u8() == 0 {
                        return Err(anyhow!("Event {} hash mismatch", id));
                    }

                    let expected_event_hmac = crypto::compute_event_hmac(
                        &self.hmac_key,
                        &device_id_arr,
                        timestamp_ns,
                        &file_path,
                        &content_hash_arr,
                        file_size,
                        size_delta,
                        &previous_hash_arr,
                    );
                    if stored_event_hmac.ct_eq(&expected_event_hmac).unwrap_u8() == 0 {
                        return Err(anyhow!("Event {} HMAC mismatch", id));
                    }

                    last_hash = expected_event_hash;
                    count += 1;
                }

                if count != event_count {
                    return Err(anyhow!("Event count mismatch"));
                }
                self.last_hash = last_hash;
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                self.last_hash = [0u8; 32];
                let initial_hmac =
                    crypto::compute_integrity_hmac(&self.hmac_key, &self.last_hash, 0);
                self.conn.execute(
                    "INSERT INTO integrity (id, chain_hash, event_count, last_verified, hmac) VALUES (1, ?, 0, ?, ?)",
                    params![&self.last_hash[..], chrono::Utc::now().timestamp_nanos_safe(), &initial_hmac[..]]
                )?;
            }
            Err(e) => return Err(e.into()),
        }
        Ok(())
    }
}
