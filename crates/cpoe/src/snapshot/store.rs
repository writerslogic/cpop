// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use std::path::Path;
use zeroize::Zeroizing;

use super::crypto;
use super::types::{SnapshotEntry, SnapshotMeta, StoreSizeInfo, SIZE_WARNING_THRESHOLD};

const BUSY_TIMEOUT_MS: u32 = 5000;

/// 30-minute gap in nanoseconds defines a session boundary.
const SESSION_GAP_NS: i64 = 30 * 60 * 1_000_000_000;

pub struct SnapshotStore {
    pub(crate) conn: Connection,
    pub(crate) signing_key_bytes: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for SnapshotStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnapshotStore")
            .field("signing_key_bytes", &"[REDACTED]")
            .finish()
    }
}

impl SnapshotStore {
    pub fn open<P: AsRef<Path>>(
        path: P,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<Self, String> {
        let path = path.as_ref();
        let conn = Connection::open(path)
            .map_err(|e| format!("failed to open snapshot db: {e}"))?;

        #[cfg(unix)]
        crate::crypto::restrict_permissions(path, 0o600)
            .map_err(|e| format!("failed to set db permissions: {e}"))?;

        let _: String = conn
            .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
            .map_err(|e| format!("WAL pragma failed: {e}"))?;
        conn.execute_batch(&format!(
            "PRAGMA busy_timeout={BUSY_TIMEOUT_MS}; PRAGMA foreign_keys=ON; \
             PRAGMA synchronous=FULL;"
        ))
        .map_err(|e| format!("pragma setup failed: {e}"))?;

        let key_bytes = Zeroizing::new(signing_key.to_bytes());

        let store = Self {
            conn,
            signing_key_bytes: key_bytes,
        };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&self) -> Result<(), String> {
        self.conn
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS snapshot_blobs (
                    content_hash BLOB NOT NULL PRIMARY KEY,
                    encrypted_data BLOB NOT NULL,
                    original_size INTEGER NOT NULL,
                    compressed_size INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS snapshot_meta (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    document_path TEXT NOT NULL,
                    content_hash BLOB NOT NULL,
                    timestamp_ns INTEGER NOT NULL,
                    word_count INTEGER NOT NULL,
                    draft_label TEXT,
                    is_restore INTEGER NOT NULL DEFAULT 0,
                    FOREIGN KEY (content_hash) REFERENCES snapshot_blobs(content_hash)
                );
                CREATE INDEX IF NOT EXISTS idx_snap_meta_doc_ts
                    ON snapshot_meta(document_path, timestamp_ns DESC);",
            )
            .map_err(|e| format!("schema init failed: {e}"))?;
        Ok(())
    }

    /// Save a snapshot atomically. Returns the snapshot meta id.
    /// If the content already exists as a blob, deduplicates (only adds meta).
    pub fn save(
        &mut self,
        document_path: &str,
        plaintext: &str,
        is_restore: bool,
    ) -> Result<i64, String> {
        let plaintext_bytes = plaintext.as_bytes();
        let content_hash: [u8; 32] = Sha256::digest(plaintext_bytes).into();
        let word_count = count_words(plaintext);
        let timestamp_ns = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);

        // Encrypt outside the transaction (CPU-bound, don't hold the DB lock)
        let blob_exists: bool = self
            .conn
            .query_row(
                "SELECT 1 FROM snapshot_blobs WHERE content_hash = ?",
                params![&content_hash[..]],
                |_| Ok(true),
            )
            .unwrap_or(false);

        let encrypted = if !blob_exists {
            Some(crypto::encrypt_blob(
                &self.signing_key_bytes,
                &content_hash,
                plaintext_bytes,
            )?)
        } else {
            None
        };

        // Atomic: blob insert (if needed) + meta insert
        let tx = self.conn.transaction()
            .map_err(|e| format!("transaction begin failed: {e}"))?;

        if let Some(ref enc) = encrypted {
            tx.execute(
                "INSERT OR IGNORE INTO snapshot_blobs \
                 (content_hash, encrypted_data, original_size, compressed_size) \
                 VALUES (?, ?, ?, ?)",
                params![
                    &content_hash[..],
                    enc.as_slice(),
                    plaintext_bytes.len() as i64,
                    enc.len() as i64,
                ],
            )
            .map_err(|e| format!("blob insert failed: {e}"))?;
        }

        tx.execute(
            "INSERT INTO snapshot_meta \
             (document_path, content_hash, timestamp_ns, word_count, is_restore) \
             VALUES (?, ?, ?, ?, ?)",
            params![
                document_path,
                &content_hash[..],
                timestamp_ns,
                word_count,
                is_restore as i32,
            ],
        )
        .map_err(|e| format!("meta insert failed: {e}"))?;

        let id = tx.last_insert_rowid();

        tx.commit()
            .map_err(|e| format!("transaction commit failed: {e}"))?;

        Ok(id)
    }

    /// List snapshots for a document, reverse chronological, with session grouping
    /// and word count deltas.
    pub fn list(&self, document_path: &str) -> Result<Vec<SnapshotEntry>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, document_path, content_hash, timestamp_ns, word_count,
                        draft_label, is_restore
                 FROM snapshot_meta
                 WHERE document_path = ?
                 ORDER BY timestamp_ns ASC",
            )
            .map_err(|e| format!("list prepare failed: {e}"))?;

        let mut rows = Vec::new();
        let mapped = stmt
            .query_map(params![document_path], |row| {
                let hash_vec: Vec<u8> = row.get(2)?;
                let mut content_hash = [0u8; 32];
                if hash_vec.len() == 32 {
                    content_hash.copy_from_slice(&hash_vec);
                }
                Ok(SnapshotMeta {
                    id: row.get(0)?,
                    document_path: row.get(1)?,
                    content_hash,
                    timestamp_ns: row.get(3)?,
                    word_count: row.get(4)?,
                    draft_label: row.get(5)?,
                    is_restore: row.get::<_, i32>(6)? != 0,
                })
            })
            .map_err(|e| format!("list query failed: {e}"))?;

        for row_result in mapped {
            match row_result {
                Ok(meta) => rows.push(meta),
                Err(e) => {
                    log::warn!("skipping corrupt snapshot row: {e}");
                }
            }
        }

        // Compute session groups (30-min gap) and word count deltas
        let mut entries = Vec::with_capacity(rows.len());
        let mut session_group: u32 = 0;
        let mut prev_ts: Option<i64> = None;
        let mut prev_word_count: Option<i32> = None;

        for meta in &rows {
            if let Some(prev) = prev_ts {
                if meta.timestamp_ns - prev > SESSION_GAP_NS {
                    session_group += 1;
                }
            }
            let word_count_delta = match prev_word_count {
                Some(prev) => meta.word_count - prev,
                None => meta.word_count,
            };
            entries.push(SnapshotEntry {
                id: meta.id,
                document_path: meta.document_path.clone(),
                content_hash: meta.content_hash,
                timestamp_ns: meta.timestamp_ns,
                word_count: meta.word_count,
                word_count_delta,
                draft_label: meta.draft_label.clone(),
                is_restore: meta.is_restore,
                session_group,
            });
            prev_ts = Some(meta.timestamp_ns);
            prev_word_count = Some(meta.word_count);
        }

        // Reverse to get newest-first for the caller
        entries.reverse();
        Ok(entries)
    }

    /// Retrieve and decrypt a snapshot's plaintext by meta id.
    pub fn get(&self, snapshot_id: i64) -> Result<String, String> {
        let content_hash: Vec<u8> = self
            .conn
            .query_row(
                "SELECT content_hash FROM snapshot_meta WHERE id = ?",
                params![snapshot_id],
                |row| row.get(0),
            )
            .map_err(|e| format!("snapshot not found: {e}"))?;

        if content_hash.len() != 32 {
            return Err("corrupt content hash length".to_string());
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&content_hash);

        self.get_by_hash(&hash)
    }

    fn get_by_hash(&self, content_hash: &[u8; 32]) -> Result<String, String> {
        let encrypted: Vec<u8> = self
            .conn
            .query_row(
                "SELECT encrypted_data FROM snapshot_blobs WHERE content_hash = ?",
                params![&content_hash[..]],
                |row| row.get(0),
            )
            .map_err(|e| format!("blob not found: {e}"))?;

        let plaintext_bytes =
            crypto::decrypt_blob(&self.signing_key_bytes, content_hash, &encrypted)?;

        String::from_utf8(plaintext_bytes)
            .map_err(|e| format!("snapshot is not valid UTF-8: {e}"))
    }

    /// Mark a snapshot as a named draft. Passing empty string clears the label.
    pub fn mark_draft(&self, snapshot_id: i64, label: &str) -> Result<(), String> {
        let label_val = if label.is_empty() {
            None
        } else {
            Some(label)
        };
        let updated = self
            .conn
            .execute(
                "UPDATE snapshot_meta SET draft_label = ? WHERE id = ?",
                params![label_val, snapshot_id],
            )
            .map_err(|e| format!("mark draft failed: {e}"))?;
        if updated == 0 {
            return Err("snapshot not found".to_string());
        }
        Ok(())
    }

    /// Restore: atomically saves the current text as a new snapshot, retrieves the
    /// target version, and records a restore marker. The caller writes the returned
    /// plaintext to disk.
    pub fn restore(
        &mut self,
        document_path: &str,
        snapshot_id: i64,
        current_text: &str,
    ) -> Result<String, String> {
        // Decrypt target outside transaction (CPU-bound)
        let restored = self.get(snapshot_id)?;

        // Pre-compute encryption for current text and restore marker
        let current_bytes = current_text.as_bytes();
        let current_hash: [u8; 32] = Sha256::digest(current_bytes).into();
        let current_wc = count_words(current_text);

        let restored_bytes = restored.as_bytes();
        let restored_hash: [u8; 32] = Sha256::digest(restored_bytes).into();
        let restored_wc = count_words(&restored);

        let now_ns = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);

        // Encrypt blobs outside transaction
        let current_enc = if !self.blob_exists(&current_hash)? {
            Some(crypto::encrypt_blob(&self.signing_key_bytes, &current_hash, current_bytes)?)
        } else {
            None
        };
        let restored_enc = if !self.blob_exists(&restored_hash)? {
            Some(crypto::encrypt_blob(&self.signing_key_bytes, &restored_hash, restored_bytes)?)
        } else {
            None
        };

        // Atomic: insert both blobs (if needed) + both meta rows
        let tx = self.conn.transaction()
            .map_err(|e| format!("restore transaction begin failed: {e}"))?;

        if let Some(ref enc) = current_enc {
            tx.execute(
                "INSERT OR IGNORE INTO snapshot_blobs \
                 (content_hash, encrypted_data, original_size, compressed_size) \
                 VALUES (?, ?, ?, ?)",
                params![&current_hash[..], enc.as_slice(), current_bytes.len() as i64, enc.len() as i64],
            ).map_err(|e| format!("restore: current blob insert failed: {e}"))?;
        }
        if let Some(ref enc) = restored_enc {
            tx.execute(
                "INSERT OR IGNORE INTO snapshot_blobs \
                 (content_hash, encrypted_data, original_size, compressed_size) \
                 VALUES (?, ?, ?, ?)",
                params![&restored_hash[..], enc.as_slice(), restored_bytes.len() as i64, enc.len() as i64],
            ).map_err(|e| format!("restore: target blob insert failed: {e}"))?;
        }

        // Pre-restore save (is_restore=false)
        tx.execute(
            "INSERT INTO snapshot_meta \
             (document_path, content_hash, timestamp_ns, word_count, is_restore) \
             VALUES (?, ?, ?, ?, 0)",
            params![document_path, &current_hash[..], now_ns, current_wc],
        ).map_err(|e| format!("restore: pre-save insert failed: {e}"))?;

        // Restore marker (is_restore=true, timestamp 1ns later to preserve ordering)
        tx.execute(
            "INSERT INTO snapshot_meta \
             (document_path, content_hash, timestamp_ns, word_count, is_restore) \
             VALUES (?, ?, ?, ?, 1)",
            params![document_path, &restored_hash[..], now_ns + 1, restored_wc],
        ).map_err(|e| format!("restore: marker insert failed: {e}"))?;

        tx.commit()
            .map_err(|e| format!("restore transaction commit failed: {e}"))?;

        Ok(restored)
    }

    fn blob_exists(&self, content_hash: &[u8; 32]) -> Result<bool, String> {
        self.conn
            .query_row(
                "SELECT 1 FROM snapshot_blobs WHERE content_hash = ?",
                params![&content_hash[..]],
                |_| Ok(true),
            )
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(false),
                other => Err(format!("blob exists check failed: {other}")),
            })
    }

    /// Total encrypted blob storage size and whether it exceeds the warning threshold.
    pub fn storage_size(&self) -> Result<StoreSizeInfo, String> {
        let total_bytes: i64 = self
            .conn
            .query_row(
                "SELECT COALESCE(SUM(LENGTH(encrypted_data)), 0) FROM snapshot_blobs",
                [],
                |row| row.get(0),
            )
            .map_err(|e| format!("size query failed: {e}"))?;
        let total_bytes = total_bytes.max(0) as u64;
        Ok(StoreSizeInfo {
            total_bytes,
            over_threshold: total_bytes > SIZE_WARNING_THRESHOLD,
        })
    }
}

/// Count words by splitting on whitespace. Matches typical writer expectations.
fn count_words(text: &str) -> i32 {
    text.split_whitespace().count() as i32
}
