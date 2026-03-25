// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::crypto;
use crate::store::{SecureEvent, SecureStore};
use crate::DateTimeNanosExt;
use rusqlite::params;

impl SecureStore {
    /// Add an event, computing its hash chain link and HMAC, then update integrity.
    pub fn add_secure_event(&mut self, e: &mut SecureEvent) -> anyhow::Result<()> {
        let previous_hash = self.last_hash;
        e.previous_hash = previous_hash;

        e.event_hash = crypto::compute_event_hash(
            &e.device_id,
            e.timestamp_ns,
            &e.file_path,
            &e.content_hash,
            e.file_size,
            e.size_delta,
            &e.previous_hash,
        );

        let hmac = crypto::compute_event_hmac(
            &self.hmac_key,
            &e.device_id,
            e.timestamp_ns,
            &e.file_path,
            &e.content_hash,
            e.file_size,
            e.size_delta,
            &e.previous_hash,
        );

        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO secure_events (
                device_id, machine_id, timestamp_ns, file_path, content_hash, file_size, size_delta,
                previous_hash, event_hash, hmac, context_type, context_note, vdf_input, vdf_output,
                vdf_iterations, forensic_score, is_paste, hardware_counter, input_method
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                &e.device_id[..],
                &e.machine_id,
                e.timestamp_ns,
                &e.file_path,
                &e.content_hash[..],
                e.file_size,
                e.size_delta,
                &e.previous_hash[..],
                &e.event_hash[..],
                &hmac[..],
                e.context_type,
                e.context_note,
                e.vdf_input.as_ref().map(|h| &h[..]),
                e.vdf_output.as_ref().map(|h| &h[..]),
                i64::try_from(e.vdf_iterations).unwrap_or(i64::MAX),
                e.forensic_score,
                e.is_paste as i32,
                e.hardware_counter.map(|c| c as i64),
                e.input_method
            ],
        )?;

        let id = tx.last_insert_rowid();
        e.id = Some(id);

        let event_count: i64 =
            tx.query_row("SELECT COUNT(*) FROM secure_events", [], |row| row.get(0))?;
        let new_integrity_hmac =
            crypto::compute_integrity_hmac(&self.hmac_key, &e.event_hash, event_count);
        tx.execute(
            "UPDATE integrity SET chain_hash = ?, event_count = ?, last_verified = ?, hmac = ? WHERE id = 1",
            params![&e.event_hash[..], event_count, chrono::Utc::now().timestamp_nanos_safe(), &new_integrity_hmac[..]]
        )?;

        tx.commit()?;
        self.last_hash = e.event_hash;
        Ok(())
    }

    /// Retrieve all events for a file path, ordered by insertion.
    pub fn get_events_for_file(&self, path: &str) -> anyhow::Result<Vec<SecureEvent>> {
        self.get_events_for_file_limited(path, None)
    }

    /// Retrieve events for a file path, ordered by insertion, with an optional limit.
    pub fn get_events_for_file_limited(
        &self,
        path: &str,
        limit: Option<u32>,
    ) -> anyhow::Result<Vec<SecureEvent>> {
        let query = match limit {
            Some(n) => format!(
                "SELECT id, device_id, machine_id, timestamp_ns, file_path, content_hash, file_size, size_delta,
                        previous_hash, event_hash, context_type, context_note, vdf_input, vdf_output,
                        vdf_iterations, forensic_score, is_paste, hardware_counter, input_method
                 FROM secure_events WHERE file_path = ? ORDER BY id ASC LIMIT {}",
                n
            ),
            None => "SELECT id, device_id, machine_id, timestamp_ns, file_path, content_hash, file_size, size_delta,
                    previous_hash, event_hash, context_type, context_note, vdf_input, vdf_output,
                    vdf_iterations, forensic_score, is_paste, hardware_counter, input_method
             FROM secure_events WHERE file_path = ? ORDER BY id ASC".to_string(),
        };
        let mut stmt = self.conn.prepare(&query)?;

        let rows = stmt.query_map([path], |row| {
            let device_id: Vec<u8> = row.get(1)?;
            let content_hash: Vec<u8> = row.get(5)?;
            let previous_hash: Vec<u8> = row.get(8)?;
            let event_hash: Vec<u8> = row.get(9)?;
            let vdf_input: Option<Vec<u8>> = row.get(12)?;
            let vdf_output: Option<Vec<u8>> = row.get(13)?;

            Ok(SecureEvent {
                id: Some(row.get(0)?),
                device_id: device_id.try_into().map_err(|_| {
                    rusqlite::Error::InvalidColumnType(
                        1,
                        "device_id".into(),
                        rusqlite::types::Type::Blob,
                    )
                })?,
                machine_id: row.get(2)?,
                timestamp_ns: row.get(3)?,
                file_path: row.get(4)?,
                content_hash: content_hash.try_into().map_err(|_| {
                    rusqlite::Error::InvalidColumnType(
                        5,
                        "content_hash".into(),
                        rusqlite::types::Type::Blob,
                    )
                })?,
                file_size: row.get(6)?,
                size_delta: row.get(7)?,
                previous_hash: previous_hash.try_into().map_err(|_| {
                    rusqlite::Error::InvalidColumnType(
                        8,
                        "previous_hash".into(),
                        rusqlite::types::Type::Blob,
                    )
                })?,
                event_hash: event_hash.try_into().map_err(|_| {
                    rusqlite::Error::InvalidColumnType(
                        9,
                        "event_hash".into(),
                        rusqlite::types::Type::Blob,
                    )
                })?,
                context_type: row.get(10)?,
                context_note: row.get(11)?,
                vdf_input: vdf_input
                    .map(|v| {
                        v.try_into().map_err(|_| {
                            rusqlite::Error::InvalidColumnType(
                                12,
                                "vdf_input".into(),
                                rusqlite::types::Type::Blob,
                            )
                        })
                    })
                    .transpose()?,
                vdf_output: vdf_output
                    .map(|v| {
                        v.try_into().map_err(|_| {
                            rusqlite::Error::InvalidColumnType(
                                13,
                                "vdf_output".into(),
                                rusqlite::types::Type::Blob,
                            )
                        })
                    })
                    .transpose()?,
                vdf_iterations: u64::try_from(row.get::<_, i64>(14)?).unwrap_or(0),
                forensic_score: row.get(15)?,
                is_paste: row.get::<_, i32>(16)? != 0,
                hardware_counter: row
                    .get::<_, Option<i64>>(17)?
                    .map(|v| u64::try_from(v).unwrap_or(0)),
                input_method: row.get(18)?,
            })
        })?;

        rows.map(|r| r.map_err(anyhow::Error::from)).collect()
    }

    /// List tracked files with their latest timestamp and event count.
    pub fn list_files(&self) -> anyhow::Result<Vec<(String, i64, i64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT file_path, MAX(timestamp_ns) as last_ts, COUNT(*) as event_count
             FROM secure_events
             GROUP BY file_path
             ORDER BY last_ts DESC",
        )?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
        rows.map(|r| r.map_err(anyhow::Error::from)).collect()
    }

    /// Return (timestamp, 1) pairs for all events after `start_ts`.
    pub fn get_global_activity(&self, start_ts: i64) -> anyhow::Result<Vec<(i64, i64)>> {
        Ok(self
            .get_all_event_timestamps(start_ts)?
            .into_iter()
            .map(|ts| (ts, 1i64))
            .collect())
    }

    /// Return all event timestamps after `start_ts`, ascending.
    pub fn get_all_event_timestamps(&self, start_ts: i64) -> anyhow::Result<Vec<i64>> {
        let mut stmt = self.conn.prepare(
            "SELECT timestamp_ns FROM secure_events WHERE timestamp_ns >= ? ORDER BY timestamp_ns ASC"
        )?;

        let rows = stmt.query_map([start_ts], |row| row.get(0))?;
        rows.map(|r| r.map_err(anyhow::Error::from)).collect()
    }

    /// Return (timestamp, size_delta) pairs for all events, ascending.
    pub fn get_all_events_summary(&self) -> anyhow::Result<Vec<(i64, i32)>> {
        let mut stmt = self.conn.prepare(
            "SELECT timestamp_ns, size_delta FROM secure_events ORDER BY timestamp_ns ASC",
        )?;

        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        rows.map(|r| r.map_err(anyhow::Error::from)).collect()
    }

    /// Update the file path for all events matching `old_path` to `new_path`.
    /// Used when a rename is detected via content hash continuity.
    ///
    /// # Warning
    ///
    /// This mutates `file_path` without recomputing event hashes or HMACs.
    /// It **MUST NOT** be called on events that have already been stored with
    /// HMAC verification, because `verify_integrity()` will fail afterwards.
    /// The function checks whether the store has any verified events and returns
    /// an error if so.
    pub fn update_file_path(&self, old_path: &str, new_path: &str) -> anyhow::Result<usize> {
        let has_integrity: bool = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM integrity WHERE id = 1 AND event_count > 0",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map(|c| c > 0)
            .unwrap_or(false);
        if has_integrity {
            return Err(anyhow::anyhow!(
                "cannot update file_path: store has HMAC-verified events; \
                 this would break integrity verification"
            ));
        }
        let count = self.conn.execute(
            "UPDATE secure_events SET file_path = ? WHERE file_path = ?",
            params![new_path, old_path],
        )?;
        Ok(count)
    }

    /// Null out context notes and VDF data for events older than `days_to_keep`.
    ///
    /// Pruned fields (`vdf_input`, `vdf_output`) are NOT included in event HMAC
    /// computation, so pruning does not break integrity verification.
    pub fn prune_payloads(&self, days_to_keep: i64) -> anyhow::Result<usize> {
        if days_to_keep < 1 {
            return Err(anyhow::anyhow!("days_to_keep must be >= 1"));
        }
        let cutoff = chrono::Utc::now() - chrono::Duration::days(days_to_keep);
        let cutoff_ns = cutoff.timestamp_nanos_safe();

        let count = self.conn.execute(
            "UPDATE secure_events 
             SET context_note = NULL, vdf_input = NULL, vdf_output = NULL 
             WHERE timestamp_ns < ?",
            [cutoff_ns],
        )?;

        Ok(count)
    }
}
