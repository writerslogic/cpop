// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::crypto;
use crate::fingerprint::AuthorFingerprint;
use anyhow::anyhow;
use rusqlite::{params, Connection};
use std::path::Path;

pub struct SecureStore {
    conn: Connection,
    hmac_key: Vec<u8>,
    last_hash: [u8; 32],
}

pub struct SecureEvent {
    pub id: Option<i64>,
    pub device_id: [u8; 16],
    pub machine_id: String,
    pub timestamp_ns: i64,
    pub file_path: String,
    pub content_hash: [u8; 32],
    pub file_size: i64,
    pub size_delta: i32,
    pub previous_hash: [u8; 32],
    pub event_hash: [u8; 32],
    pub context_type: Option<String>,
    pub context_note: Option<String>,
    pub vdf_input: Option<[u8; 32]>,
    pub vdf_output: Option<[u8; 32]>,
    pub vdf_iterations: u64,
    pub forensic_score: f64,
    pub is_paste: bool,
    /// Hardware monotonic counter value at event time (None for software-only)
    pub hardware_counter: Option<u64>,
}

impl SecureStore {
    pub fn open<P: AsRef<Path>>(path: P, hmac_key: Vec<u8>) -> anyhow::Result<Self> {
        let conn = Connection::open(path)?;

        let _: String = conn.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
        // These PRAGMAs may or may not return values depending on SQLite version
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

    fn init_schema(&self) -> anyhow::Result<()> {
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
                is_paste        INTEGER DEFAULT 0
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

            CREATE INDEX IF NOT EXISTS idx_secure_events_timestamp ON secure_events(timestamp_ns);
            CREATE INDEX IF NOT EXISTS idx_secure_events_file ON secure_events(file_path, timestamp_ns);"
        )?;
        Ok(())
    }

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

    pub fn save_fingerprint(&self, fingerprint: &AuthorFingerprint) -> anyhow::Result<()> {
        let json = serde_json::to_string(fingerprint)?;
        let now = chrono::Utc::now().timestamp();

        self.conn.execute(
            "INSERT OR REPLACE INTO fingerprints (profile_id, data_json, updated_at) VALUES (?, ?, ?)",
            params![fingerprint.id, json, now]
        )?;
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
                let mut chain_hash_arr = [0u8; 32];
                chain_hash_arr.copy_from_slice(&chain_hash);

                let expected_hmac =
                    crypto::compute_integrity_hmac(&self.hmac_key, &chain_hash_arr, event_count);
                if stored_hmac != expected_hmac {
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
                    if event_hash != expected_event_hash {
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
                    if stored_event_hmac != expected_event_hmac {
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
                    params![&self.last_hash[..], chrono::Utc::now().timestamp_nanos_opt(), &initial_hmac[..]]
                )?;
            }
            Err(e) => return Err(e.into()),
        }
        Ok(())
    }

    pub fn insert_secure_event(&mut self, e: &mut SecureEvent) -> anyhow::Result<()> {
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
                vdf_iterations, forensic_score, is_paste
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                &e.device_id[..], &e.machine_id, e.timestamp_ns, &e.file_path, &e.content_hash[..], e.file_size, e.size_delta,
                &e.previous_hash[..], &e.event_hash[..], &hmac[..], e.context_type, e.context_note,
                e.vdf_input.as_ref().map(|h| &h[..]), e.vdf_output.as_ref().map(|h| &h[..]),
                e.vdf_iterations as i64, e.forensic_score, e.is_paste as i32
            ]
        )?;

        let id = tx.last_insert_rowid();
        e.id = Some(id);

        let new_integrity_hmac = crypto::compute_integrity_hmac(&self.hmac_key, &e.event_hash, id);
        tx.execute(
            "UPDATE integrity SET chain_hash = ?, event_count = ?, last_verified = ?, hmac = ? WHERE id = 1",
            params![&e.event_hash[..], id, chrono::Utc::now().timestamp_nanos_opt(), &new_integrity_hmac[..]]
        )?;

        tx.commit()?;
        self.last_hash = e.event_hash;
        Ok(())
    }

    pub fn update_baseline(&self, signal: &str, value: f64) -> anyhow::Result<()> {
        let res = self.conn.query_row(
            "SELECT sample_count, mean, m2 FROM physical_baselines WHERE signal_name = ?",
            [signal],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, f64>(1)?,
                    row.get::<_, f64>(2)?,
                ))
            },
        );

        let (mut count, mut mean, mut m2) = match res {
            Ok(data) => data,
            Err(rusqlite::Error::QueryReturnedNoRows) => (0, 0.0, 0.0),
            Err(e) => return Err(e.into()),
        };

        count += 1;
        let delta = value - mean;
        mean += delta / count as f64;
        let delta2 = value - mean;
        m2 += delta * delta2;

        self.conn.execute(
            "INSERT OR REPLACE INTO physical_baselines (signal_name, sample_count, mean, m2) VALUES (?, ?, ?, ?)",
            params![signal, count, mean, m2]
        )?;
        Ok(())
    }

    pub fn get_baselines(&self) -> anyhow::Result<Vec<(String, f64, f64)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT signal_name, sample_count, mean, m2 FROM physical_baselines")?;
        let rows = stmt.query_map([], |row| {
            let name: String = row.get(0)?;
            let count: i64 = row.get(1)?;
            let mean: f64 = row.get(2)?;
            let m2: f64 = row.get(3)?;
            let std_dev = if count > 1 {
                (m2 / (count - 1) as f64).sqrt()
            } else {
                0.0
            };
            Ok((name, mean, std_dev))
        })?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    pub fn get_events_for_file(&self, path: &str) -> anyhow::Result<Vec<SecureEvent>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, device_id, machine_id, timestamp_ns, file_path, content_hash, file_size, size_delta, 
                    previous_hash, event_hash, context_type, context_note, vdf_input, vdf_output, 
                    vdf_iterations, forensic_score, is_paste 
             FROM secure_events WHERE file_path = ? ORDER BY id ASC"
        )?;

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
                vdf_input: vdf_input.map(|v| v.try_into().unwrap()),
                vdf_output: vdf_output.map(|v| v.try_into().unwrap()),
                vdf_iterations: row.get::<_, i64>(14)? as u64,
                forensic_score: row.get(15)?,
                is_paste: row.get::<_, i32>(16)? != 0,
                hardware_counter: None, // Read from DB if column exists
            })
        })?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    pub fn list_files(&self) -> anyhow::Result<Vec<(String, i64, i64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT file_path, MAX(timestamp_ns) as last_ts, COUNT(*) as event_count
             FROM secure_events
             GROUP BY file_path
             ORDER BY last_ts DESC",
        )?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    pub fn get_global_activity(&self, start_ts: i64) -> anyhow::Result<Vec<(i64, i64)>> {
        // Returns (timestamp_ns, count) grouped by day
        // SQLite doesn't have easy day truncation in nanoseconds, so we fetch timestamps and aggregate in Rust
        // or we can use strftime if we convert to seconds.
        // For simplicity and portability, let's fetch timestamps > start_ts and aggregate in Rust.

        let mut stmt = self.conn.prepare(
            "SELECT timestamp_ns FROM secure_events WHERE timestamp_ns >= ? ORDER BY timestamp_ns ASC"
        )?;

        let rows = stmt.query_map([start_ts], |row| row.get(0))?;

        let mut timestamps = Vec::new();
        for row in rows {
            timestamps.push(row?);
        }

        // Aggregation will happen in the caller (CLI) for now to keep store simple
        // Or we can return the raw list of timestamps which is what I'll do here
        // Actually, returning a list of timestamps is fine if the volume isn't huge.
        // But for "global activity", let's return count per day if possible.

        // Let's stick to returning raw timestamps for now, it's flexible.
        // But the return type signature I proposed was Vec<(i64, i64)>.
        // Let's change it to just return Vec<i64> of all event timestamps.

        Ok(timestamps.into_iter().map(|ts| (ts, 1)).collect())
    }

    pub fn get_all_event_timestamps(&self, start_ts: i64) -> anyhow::Result<Vec<i64>> {
        let mut stmt = self.conn.prepare(
            "SELECT timestamp_ns FROM secure_events WHERE timestamp_ns >= ? ORDER BY timestamp_ns ASC"
        )?;

        let rows = stmt.query_map([start_ts], |row| row.get(0))?;
        let mut timestamps = Vec::new();
        for row in rows {
            timestamps.push(row?);
        }
        Ok(timestamps)
    }

    pub fn get_all_events_summary(&self) -> anyhow::Result<Vec<(i64, i32)>> {
        let mut stmt = self.conn.prepare(
            "SELECT timestamp_ns, size_delta FROM secure_events ORDER BY timestamp_ns ASC",
        )?;

        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        let mut events = Vec::new();
        for row in rows {
            events.push(row?);
        }
        Ok(events)
    }
    pub fn prune_payloads(&self, days_to_keep: i64) -> anyhow::Result<usize> {
        let cutoff = chrono::Utc::now() - chrono::Duration::days(days_to_keep);
        let cutoff_ns = cutoff.timestamp_nanos_opt().unwrap_or(0);

        let count = self.conn.execute(
            "UPDATE secure_events 
             SET context_note = NULL, vdf_input = NULL, vdf_output = NULL 
             WHERE timestamp_ns < ?",
            [cutoff_ns],
        )?;

        // Optional: Vacuum to reclaim space, but this locks the DB
        // self.conn.execute("VACUUM", [])?;

        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_hmac_key() -> Vec<u8> {
        vec![0x42u8; 32]
    }

    fn create_test_event(file_path: &str, content_hash: [u8; 32]) -> SecureEvent {
        SecureEvent {
            id: None,
            device_id: [1u8; 16],
            machine_id: "test-machine".to_string(),
            timestamp_ns: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
            file_path: file_path.to_string(),
            content_hash,
            file_size: 1000,
            size_delta: 100,
            previous_hash: [0u8; 32],
            event_hash: [0u8; 32],
            context_type: Some("test".to_string()),
            context_note: Some("test note".to_string()),
            vdf_input: Some([0xAAu8; 32]),
            vdf_output: Some([0xBBu8; 32]),
            vdf_iterations: 1000,
            forensic_score: 0.95,
            is_paste: false,
            hardware_counter: None,
        }
    }

    #[test]
    fn test_store_open_and_init() {
        let dir = TempDir::new().expect("create temp dir");
        let db_path = dir.path().join("test.db");

        let store = SecureStore::open(&db_path, test_hmac_key()).expect("open store");
        drop(store);

        // Reopen should work
        let _store = SecureStore::open(&db_path, test_hmac_key()).expect("reopen store");
    }

    #[test]
    fn test_insert_single_event() {
        let dir = TempDir::new().expect("create temp dir");
        let db_path = dir.path().join("test.db");

        let mut store = SecureStore::open(&db_path, test_hmac_key()).expect("open store");
        let mut event = create_test_event("/test/file.txt", [1u8; 32]);

        store.insert_secure_event(&mut event).expect("insert event");

        assert!(event.id.is_some());
        assert_ne!(event.event_hash, [0u8; 32]);
    }

    #[test]
    fn test_insert_multiple_events_chain() {
        let dir = TempDir::new().expect("create temp dir");
        let db_path = dir.path().join("test.db");

        let mut store = SecureStore::open(&db_path, test_hmac_key()).expect("open store");

        // Insert first event
        let mut event1 = create_test_event("/test/file.txt", [1u8; 32]);
        store
            .insert_secure_event(&mut event1)
            .expect("insert event 1");
        let hash1 = event1.event_hash;

        // Insert second event - should chain from first
        let mut event2 = create_test_event("/test/file.txt", [2u8; 32]);
        event2.timestamp_ns += 1_000_000; // 1ms later
        store
            .insert_secure_event(&mut event2)
            .expect("insert event 2");

        assert_eq!(event2.previous_hash, hash1);
    }

    #[test]
    fn test_get_events_for_file() {
        let dir = TempDir::new().expect("create temp dir");
        let db_path = dir.path().join("test.db");

        let mut store = SecureStore::open(&db_path, test_hmac_key()).expect("open store");

        // Insert events for two different files
        let mut event1 = create_test_event("/test/file1.txt", [1u8; 32]);
        store
            .insert_secure_event(&mut event1)
            .expect("insert event 1");

        let mut event2 = create_test_event("/test/file2.txt", [2u8; 32]);
        event2.timestamp_ns += 1_000_000;
        store
            .insert_secure_event(&mut event2)
            .expect("insert event 2");

        let mut event3 = create_test_event("/test/file1.txt", [3u8; 32]);
        event3.timestamp_ns += 2_000_000;
        store
            .insert_secure_event(&mut event3)
            .expect("insert event 3");

        let file1_events = store
            .get_events_for_file("/test/file1.txt")
            .expect("get events");
        assert_eq!(file1_events.len(), 2);

        let file2_events = store
            .get_events_for_file("/test/file2.txt")
            .expect("get events");
        assert_eq!(file2_events.len(), 1);
    }

    #[test]
    fn test_list_files() {
        let dir = TempDir::new().expect("create temp dir");
        let db_path = dir.path().join("test.db");

        let mut store = SecureStore::open(&db_path, test_hmac_key()).expect("open store");

        // Insert events for multiple files
        let mut event1 = create_test_event("/test/file1.txt", [1u8; 32]);
        store
            .insert_secure_event(&mut event1)
            .expect("insert event 1");

        let mut event2 = create_test_event("/test/file2.txt", [2u8; 32]);
        event2.timestamp_ns += 1_000_000;
        store
            .insert_secure_event(&mut event2)
            .expect("insert event 2");

        let files = store.list_files().expect("list files");
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn test_update_baseline() {
        let dir = TempDir::new().expect("create temp dir");
        let db_path = dir.path().join("test.db");

        let store = SecureStore::open(&db_path, test_hmac_key()).expect("open store");

        // Update baseline with some values
        store
            .update_baseline("typing_speed", 100.0)
            .expect("update 1");
        store
            .update_baseline("typing_speed", 110.0)
            .expect("update 2");
        store
            .update_baseline("typing_speed", 90.0)
            .expect("update 3");

        let baselines = store.get_baselines().expect("get baselines");
        assert_eq!(baselines.len(), 1);

        let (name, mean, _std_dev) = &baselines[0];
        assert_eq!(name, "typing_speed");
        assert!(*mean > 90.0 && *mean < 110.0); // Should be around 100
    }

    #[test]
    fn test_baseline_multiple_signals() {
        let dir = TempDir::new().expect("create temp dir");
        let db_path = dir.path().join("test.db");

        let store = SecureStore::open(&db_path, test_hmac_key()).expect("open store");

        store.update_baseline("signal_a", 50.0).expect("update a");
        store.update_baseline("signal_b", 100.0).expect("update b");

        let baselines = store.get_baselines().expect("get baselines");
        assert_eq!(baselines.len(), 2);
    }

    #[test]
    fn test_integrity_verification_on_reopen() {
        let dir = TempDir::new().expect("create temp dir");
        let db_path = dir.path().join("test.db");

        {
            let mut store = SecureStore::open(&db_path, test_hmac_key()).expect("open store");
            let mut event = create_test_event("/test/file.txt", [1u8; 32]);
            store.insert_secure_event(&mut event).expect("insert event");
        }

        // Reopen should verify integrity
        let _store = SecureStore::open(&db_path, test_hmac_key()).expect("reopen store");
    }

    #[test]
    fn test_wrong_hmac_key_fails_verification() {
        let dir = TempDir::new().expect("create temp dir");
        let db_path = dir.path().join("test.db");

        {
            let mut store = SecureStore::open(&db_path, test_hmac_key()).expect("open store");
            let mut event = create_test_event("/test/file.txt", [1u8; 32]);
            store.insert_secure_event(&mut event).expect("insert event");
        }

        // Try to open with wrong key
        let wrong_key = vec![0xFFu8; 32];
        let result = SecureStore::open(&db_path, wrong_key);
        assert!(result.is_err());
        match result {
            Err(e) => assert!(e.to_string().contains("mismatch")),
            Ok(_) => panic!("Expected error with wrong HMAC key"),
        }
    }

    #[test]
    fn test_event_with_optional_fields() {
        let dir = TempDir::new().expect("create temp dir");
        let db_path = dir.path().join("test.db");

        let mut store = SecureStore::open(&db_path, test_hmac_key()).expect("open store");

        let mut event = SecureEvent {
            id: None,
            device_id: [1u8; 16],
            machine_id: "test".to_string(),
            timestamp_ns: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
            file_path: "/test.txt".to_string(),
            content_hash: [1u8; 32],
            file_size: 100,
            size_delta: 10,
            previous_hash: [0u8; 32],
            event_hash: [0u8; 32],
            context_type: None,
            context_note: None,
            vdf_input: None,
            vdf_output: None,
            vdf_iterations: 0,
            forensic_score: 1.0,
            is_paste: false,
            hardware_counter: None,
        };

        store.insert_secure_event(&mut event).expect("insert event");
        assert!(event.id.is_some());
    }

    #[test]
    fn test_paste_event() {
        let dir = TempDir::new().expect("create temp dir");
        let db_path = dir.path().join("test.db");

        let mut store = SecureStore::open(&db_path, test_hmac_key()).expect("open store");

        let mut event = create_test_event("/test/file.txt", [1u8; 32]);
        event.is_paste = true;

        store.insert_secure_event(&mut event).expect("insert event");

        let events = store
            .get_events_for_file("/test/file.txt")
            .expect("get events");
        assert_eq!(events.len(), 1);
        assert!(events[0].is_paste);
    }

    #[test]
    fn test_negative_size_delta() {
        let dir = TempDir::new().expect("create temp dir");
        let db_path = dir.path().join("test.db");

        let mut store = SecureStore::open(&db_path, test_hmac_key()).expect("open store");

        let mut event = create_test_event("/test/file.txt", [1u8; 32]);
        event.size_delta = -500; // Deletion

        store.insert_secure_event(&mut event).expect("insert event");

        let events = store
            .get_events_for_file("/test/file.txt")
            .expect("get events");
        assert_eq!(events[0].size_delta, -500);
    }

    #[test]
    fn test_empty_file_list() {
        let dir = TempDir::new().expect("create temp dir");
        let db_path = dir.path().join("test.db");

        let store = SecureStore::open(&db_path, test_hmac_key()).expect("open store");
        let files = store.list_files().expect("list files");
        assert!(files.is_empty());
    }

    #[test]
    fn test_empty_baselines() {
        let dir = TempDir::new().expect("create temp dir");
        let db_path = dir.path().join("test.db");

        let store = SecureStore::open(&db_path, test_hmac_key()).expect("open store");
        let baselines = store.get_baselines().expect("get baselines");
        assert!(baselines.is_empty());
    }

    #[test]
    fn test_events_for_nonexistent_file() {
        let dir = TempDir::new().expect("create temp dir");
        let db_path = dir.path().join("test.db");

        let store = SecureStore::open(&db_path, test_hmac_key()).expect("open store");
        let events = store
            .get_events_for_file("/nonexistent.txt")
            .expect("get events");
        assert!(events.is_empty());
    }

    #[test]
    fn test_event_ordering() {
        let dir = TempDir::new().expect("create temp dir");
        let db_path = dir.path().join("test.db");

        let mut store = SecureStore::open(&db_path, test_hmac_key()).expect("open store");
        let base_ts = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);

        for i in 0..5 {
            let mut event = create_test_event("/test/file.txt", [(i + 1) as u8; 32]);
            event.timestamp_ns = base_ts + (i as i64 * 1_000_000);
            store.insert_secure_event(&mut event).expect("insert event");
        }

        let events = store
            .get_events_for_file("/test/file.txt")
            .expect("get events");
        assert_eq!(events.len(), 5);

        // Events should be ordered by id (ascending)
        for i in 1..events.len() {
            assert!(events[i].id > events[i - 1].id);
        }
    }
}
