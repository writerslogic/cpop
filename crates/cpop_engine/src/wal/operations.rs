// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::MutexRecover;
use blake3::Hasher;
use ed25519_dalek::{Signature, Signer, Verifier};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use subtle::ConstantTimeEq;

use super::serialization::{
    deserialize_entry, deserialize_header, now_nanos, serialize_entry, serialize_header,
};
use super::types::*;

impl Wal {
    /// Open or create a WAL file, replaying existing entries to restore state.
    ///
    /// Uses [`DEFAULT_SYNC_INTERVAL`] for batched fdatasync. Use
    /// [`open_with_sync_interval`](Self::open_with_sync_interval) to override.
    pub fn open(
        path: impl AsRef<Path>,
        session_id: [u8; 32],
        signing_key: ed25519_dalek::SigningKey,
    ) -> Result<Self, WalError> {
        Self::open_with_sync_interval(path, session_id, signing_key, DEFAULT_SYNC_INTERVAL)
    }

    /// Open or create a WAL file with an explicit sync interval.
    ///
    /// `sync_interval` controls how many appends are batched before an fdatasync.
    /// Pass `1` for the legacy per-append sync behaviour.
    pub fn open_with_sync_interval(
        path: impl AsRef<Path>,
        session_id: [u8; 32],
        signing_key: ed25519_dalek::SigningKey,
        sync_interval: u64,
    ) -> Result<Self, WalError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;

        // Restrict WAL to owner-only access (contains signed evidence entries)
        crate::crypto::restrict_permissions(path, 0o600)?;

        let sync_interval = sync_interval.max(1);
        let mut state = WalState {
            path: path.to_path_buf(),
            file,
            session_id,
            signing_key,
            next_sequence: 0,
            last_hash: [0u8; 32],
            cumulative_hasher: Hasher::new(),
            closed: false,
            inconsistent: false,
            entry_count: 0,
            byte_count: 0,
            sync_interval,
            pending_syncs: 0,
        };

        let metadata = state.file.metadata()?;
        if metadata.len() == 0 {
            Self::write_header(&mut state)?;
            state.byte_count = HEADER_SIZE as u64;
            state.file.seek(SeekFrom::Start(HEADER_SIZE as u64))?;
        } else {
            Self::read_header(&mut state)?;
            Self::scan_to_end(&mut state)?;
        }

        Ok(Self {
            inner: Mutex::new(state),
        })
    }

    /// Append a new entry, extending the hash chain and signing.
    ///
    /// fdatasync is batched: it fires every `sync_interval` appends, or
    /// immediately when `entry_type` is [`EntryType::Checkpoint`] (force_sync).
    pub fn append(&self, entry_type: EntryType, payload: Vec<u8>) -> Result<(), WalError> {
        let mut state = self.inner.lock_recover();
        if state.closed {
            return Err(WalError::Closed);
        }
        if state.inconsistent {
            return Err(WalError::Inconsistent);
        }
        if state.byte_count >= MAX_WAL_SIZE {
            return Err(WalError::TooLarge(state.byte_count));
        }

        let timestamp = now_nanos();
        let mut entry = Entry {
            length: 0,
            sequence: state.next_sequence,
            timestamp,
            entry_type,
            payload,
            prev_hash: state.last_hash,
            cumulative_hash: [0u8; 32],
            signature: [0u8; 64],
        };

        let entry_hash = entry.compute_hash();
        state.cumulative_hasher.update(&entry_hash);
        entry.cumulative_hash = *state.cumulative_hasher.finalize().as_bytes();

        let sig = state.signing_key.sign(&entry.cumulative_hash);
        entry.signature = sig.to_bytes();

        let data = serialize_entry(&entry)?;
        let length = data.len() as u32;

        // Pre-assemble length prefix + entry into a single buffer to avoid
        // partial writes that could corrupt the WAL on crash.
        let mut frame = Vec::with_capacity(4 + data.len());
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(&data);
        state.file.write_all(&frame)?;

        state.pending_syncs += 1;
        // Force sync for checkpoint entries or when the batch threshold is reached.
        let force_sync = entry_type == EntryType::Checkpoint;
        if force_sync || state.pending_syncs >= state.sync_interval {
            state.file.sync_data()?;
            state.pending_syncs = 0;
        }

        state.last_hash = entry_hash;
        state.next_sequence += 1;
        state.entry_count += 1;
        state.byte_count += (4 + data.len()) as u64;

        Ok(())
    }

    /// Flush any buffered (unsynced) appends to disk immediately.
    ///
    /// Call this at session boundaries or before handing off evidence to ensure
    /// no pending writes are lost even when the batch threshold has not been reached.
    pub fn flush(&self) -> Result<(), WalError> {
        let mut state = self.inner.lock_recover();
        if state.closed {
            return Ok(());
        }
        if state.pending_syncs > 0 {
            state.file.sync_data()?;
            state.pending_syncs = 0;
        }
        Ok(())
    }

    /// Verify the WAL's integrity by replaying the hash chain and signatures.
    ///
    /// Returns `WalVerification { valid: false, .. }` (not `Err`) when integrity
    /// checks fail, because this is a read-only inspection — the caller needs the
    /// partial result (entry count, final hash) to decide how to recover. Compare
    /// with [`scan_to_end`](Self::scan_to_end) which returns `Err` on the same
    /// conditions because it cannot proceed with state reconstruction.
    pub fn verify(&self) -> Result<WalVerification, WalError> {
        let state = self.inner.lock_recover();
        let verifying_key = state.signing_key.verifying_key();

        let mut file = state.file.try_clone()?;

        file.seek(SeekFrom::Start(0))?;
        let mut header_buf = vec![0u8; HEADER_SIZE];
        file.read_exact(&mut header_buf)?;
        let header = deserialize_header(&header_buf)?;

        file.seek(SeekFrom::Start(HEADER_SIZE as u64))?;

        let mut prev_hash = [0u8; 32];
        let mut cumulative_hasher = Hasher::new();
        let mut expected_sequence = header.last_checkpoint_seq;
        let mut last_timestamp = 0i64;
        let mut count = 0u64;

        loop {
            if count >= MAX_WAL_ENTRIES {
                return Ok(WalVerification {
                    valid: false,
                    entries: count,
                    final_hash: prev_hash,
                    error: Some(WalError::TooManyEntries(MAX_WAL_ENTRIES)),
                });
            }

            let mut len_buf = [0u8; 4];
            if let Err(err) = file.read_exact(&mut len_buf) {
                if err.kind() == std::io::ErrorKind::UnexpectedEof {
                    break;
                }
                return Err(err.into());
            }

            let entry_len = u32::from_be_bytes(len_buf);
            if entry_len > MAX_ENTRY_SIZE {
                return Ok(WalVerification {
                    valid: false,
                    entries: count,
                    final_hash: prev_hash,
                    error: Some(WalError::CorruptedEntry),
                });
            }
            let mut entry_buf = vec![0u8; entry_len as usize];
            file.read_exact(&mut entry_buf)?;

            let entry = deserialize_entry(&entry_buf)?;

            if entry.sequence != expected_sequence {
                return Ok(WalVerification {
                    valid: false,
                    entries: count,
                    final_hash: prev_hash,
                    error: Some(WalError::SequenceGap),
                });
            }

            if entry.timestamp < last_timestamp {
                return Ok(WalVerification {
                    valid: false,
                    entries: count,
                    final_hash: prev_hash,
                    error: Some(WalError::TimestampRegression),
                });
            }

            if entry.prev_hash.ct_eq(&prev_hash).unwrap_u8() == 0 {
                return Ok(WalVerification {
                    valid: false,
                    entries: count,
                    final_hash: prev_hash,
                    error: Some(WalError::BrokenChain),
                });
            }

            let entry_hash = entry.compute_hash();
            cumulative_hasher.update(&entry_hash);
            let expected_cumulative = *cumulative_hasher.finalize().as_bytes();

            if entry
                .cumulative_hash
                .ct_eq(&expected_cumulative)
                .unwrap_u8()
                == 0
            {
                return Ok(WalVerification {
                    valid: false,
                    entries: count,
                    final_hash: prev_hash,
                    error: Some(WalError::CumulativeMismatch),
                });
            }

            let sig = Signature::from_bytes(&entry.signature);
            if verifying_key.verify(&entry.cumulative_hash, &sig).is_err() {
                return Ok(WalVerification {
                    valid: false,
                    entries: count,
                    final_hash: prev_hash,
                    error: Some(WalError::InvalidSignature),
                });
            }

            prev_hash = entry_hash;
            expected_sequence += 1;
            last_timestamp = entry.timestamp;
            count += 1;
        }

        Ok(WalVerification {
            valid: true,
            entries: count,
            final_hash: prev_hash,
            error: None,
        })
    }

    /// Truncate entries before `before_seq`, rewriting the file with a new header.
    ///
    /// Retained entries are re-signed with the current signing key because the
    /// original key may differ after key rotation. This is intentional: the WAL
    /// guarantees integrity from this point forward, not provenance of historical keys.
    pub fn truncate(&self, before_seq: u64) -> Result<(), WalError> {
        let mut state = self.inner.lock_recover();
        let mut file = state.file.try_clone()?;
        file.seek(SeekFrom::Start(HEADER_SIZE as u64))?;

        // Stream through the file in one pass: validate the chain and collect only
        // retained entries (sequence >= before_seq), avoiding a full in-memory load.
        let mut expected_prev = [0u8; 32];
        let mut entries: Vec<Entry> = Vec::new();
        let mut entry_count: u64 = 0;

        loop {
            if entry_count >= MAX_WAL_ENTRIES {
                return Err(WalError::TooManyEntries(MAX_WAL_ENTRIES));
            }
            let mut len_buf = [0u8; 4];
            if file.read_exact(&mut len_buf).is_err() {
                break;
            }
            let entry_len = u32::from_be_bytes(len_buf);
            if entry_len > MAX_ENTRY_SIZE {
                return Err(WalError::CorruptedEntry);
            }
            let mut entry_buf = vec![0u8; entry_len as usize];
            file.read_exact(&mut entry_buf)?;
            let entry = deserialize_entry(&entry_buf)?;

            // Validate chain integrity for every entry regardless of whether it is retained.
            if entry.prev_hash.ct_eq(&expected_prev).unwrap_u8() == 0 {
                return Err(WalError::BrokenChain);
            }
            expected_prev = entry.compute_hash();
            entry_count += 1;

            // Only keep entries that fall within the retained range.
            if entry.sequence >= before_seq {
                entries.push(entry);
            }
        }

        // Verify ordinal continuity: retained entries must have sequential ordinals.
        for pair in entries.windows(2) {
            if pair[1].sequence != pair[0].sequence + 1 {
                return Err(WalError::SequenceGap);
            }
        }

        let new_path = state.path.with_extension("wal.new");
        let mut new_file = File::create(&new_path)?;

        crate::crypto::restrict_permissions(&new_path, 0o600)?;

        let header = Header {
            magic: *MAGIC,
            version: VERSION,
            session_id: state.session_id,
            created_at: now_nanos(),
            last_checkpoint_seq: before_seq,
            reserved: [0u8; 8],
        };

        new_file.write_all(&serialize_header(&header))?;

        let mut last_hash = [0u8; 32];
        let mut cumulative_hasher = Hasher::new();

        for entry in &entries {
            let mut entry = entry.clone();
            entry.prev_hash = last_hash;
            let entry_hash = entry.compute_hash();
            cumulative_hasher.update(&entry_hash);
            entry.cumulative_hash = *cumulative_hasher.finalize().as_bytes();
            let sig = state.signing_key.sign(&entry.cumulative_hash);
            entry.signature = sig.to_bytes();

            let data = serialize_entry(&entry)?;
            let length = data.len() as u32;
            new_file.write_all(&length.to_be_bytes())?;
            new_file.write_all(&data)?;
            last_hash = entry_hash;
        }

        new_file.sync_all()?;
        drop(new_file);

        fs::rename(&new_path, &state.path)?;

        // Open the new file first. If this fails the rename already committed,
        // so mark the WAL inconsistent before returning to prevent further writes
        // against the now-stale file handle.
        let mut reopened = match OpenOptions::new().read(true).write(true).open(&state.path) {
            Ok(f) => f,
            Err(e) => {
                state.inconsistent = true;
                return Err(WalError::Io(e));
            }
        };
        if let Err(e) = reopened.seek(SeekFrom::End(0)) {
            state.inconsistent = true;
            return Err(WalError::Io(e));
        }

        // Assign new file handle before updating other fields so state stays consistent.
        state.file = reopened;
        state.last_hash = last_hash;
        state.cumulative_hasher = cumulative_hasher;
        state.next_sequence = if let Some(last) = entries.last() {
            last.sequence + 1
        } else {
            before_seq
        };
        state.entry_count = entries.len() as u64;
        state.byte_count = state.file.metadata()?.len();

        Ok(())
    }

    /// Return the total byte size of the WAL file.
    pub fn size(&self) -> u64 {
        let state = self.inner.lock_recover();
        state.byte_count
    }

    /// Return the number of entries in the WAL.
    pub fn entry_count(&self) -> u64 {
        let state = self.inner.lock_recover();
        state.entry_count
    }

    /// Return the sequence number of the last written entry.
    pub fn last_sequence(&self) -> u64 {
        let state = self.inner.lock_recover();
        if state.next_sequence == 0 {
            0
        } else {
            state.next_sequence - 1
        }
    }

    /// Flush and close the WAL, preventing further appends.
    pub fn close(&self) -> Result<(), WalError> {
        let mut state = self.inner.lock_recover();
        if state.closed {
            return Ok(());
        }
        state.closed = true;
        state.file.sync_all()?;
        Ok(())
    }

    /// Return the filesystem path of the WAL file.
    pub fn path(&self) -> PathBuf {
        let state = self.inner.lock_recover();
        state.path.clone()
    }

    /// Rotate the WAL if it exceeds `max_size_bytes`.
    ///
    /// Renames the current WAL to `{name}.{timestamp_nanos}.archive`, then
    /// creates a fresh WAL with a new header. Returns `Some(archive_path)` if
    /// rotation occurred, `None` otherwise.
    pub fn rotate_if_needed(&self, max_size_bytes: u64) -> Result<Option<PathBuf>, WalError> {
        let mut state = self.inner.lock_recover();
        if state.byte_count < max_size_bytes {
            return Ok(None);
        }
        if state.closed {
            return Err(WalError::Closed);
        }

        // Flush before archiving.
        state.file.sync_all()?;

        let timestamp = now_nanos();
        let archive_name = format!(
            "{}.{}.archive",
            state
                .path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "wal".to_string()),
            timestamp
        );
        let archive_path = state
            .path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(archive_name);

        fs::rename(&state.path, &archive_path)?;

        // Preserve the sequence number so the new WAL continues where the old one
        // left off (AUD-108). This prevents sequence reuse across rotations.
        let continued_sequence = state.next_sequence;

        // Create a fresh WAL file.
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&state.path)?;
        crate::crypto::restrict_permissions(&state.path, 0o600)?;

        state.file = file;
        state.next_sequence = continued_sequence;
        state.last_hash = [0u8; 32];
        state.cumulative_hasher = Hasher::new();
        state.entry_count = 0;
        state.byte_count = 0;

        // Write header with last_checkpoint_seq so verify() knows the starting offset.
        let header = Header {
            magic: *MAGIC,
            version: VERSION,
            session_id: state.session_id,
            created_at: now_nanos(),
            last_checkpoint_seq: continued_sequence,
            reserved: [0u8; 8],
        };
        let buf = serialize_header(&header);
        state.file.write_all(&buf)?;
        state.file.sync_all()?;
        state.byte_count = HEADER_SIZE as u64;
        state.file.seek(SeekFrom::Start(HEADER_SIZE as u64))?;

        Ok(Some(archive_path))
    }

    /// List WAL archive files in the given directory, sorted oldest-first.
    pub fn list_archives(wal_dir: &Path) -> Vec<PathBuf> {
        let mut archives: Vec<PathBuf> = fs::read_dir(wal_dir)
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.to_string_lossy().ends_with(".archive"))
            .collect();
        archives.sort();
        archives
    }

    /// Keep only the `max_archives` most recent archive files; delete the rest.
    pub fn prune_archives(wal_dir: &Path, max_archives: usize) {
        let archives = Self::list_archives(wal_dir);
        if archives.len() <= max_archives {
            return;
        }
        let to_remove = archives.len() - max_archives;
        for path in archives.into_iter().take(to_remove) {
            if let Err(e) = fs::remove_file(&path) {
                log::warn!("Failed to prune WAL archive {}: {}", path.display(), e);
            }
        }
    }

    pub fn exists(path: impl AsRef<Path>) -> bool {
        path.as_ref().exists()
    }

    fn write_header(state: &mut WalState) -> Result<(), WalError> {
        let header = Header {
            magic: *MAGIC,
            version: VERSION,
            session_id: state.session_id,
            created_at: now_nanos(),
            last_checkpoint_seq: 0,
            reserved: [0u8; 8],
        };
        let buf = serialize_header(&header);
        state.file.write_all(&buf)?;
        state.file.sync_all()?;
        Ok(())
    }

    fn read_header(state: &mut WalState) -> Result<(), WalError> {
        let mut buf = vec![0u8; HEADER_SIZE];
        state.file.seek(SeekFrom::Start(0))?;
        state.file.read_exact(&mut buf)?;
        let header = deserialize_header(&buf)?;
        if header.magic != *MAGIC {
            return Err(WalError::InvalidMagic);
        }
        if header.version != VERSION {
            return Err(WalError::InvalidVersion(header.version));
        }
        if header.session_id != state.session_id {
            return Err(WalError::SessionMismatch);
        }
        Ok(())
    }

    /// Replay the WAL to reconstruct in-memory state (next sequence, last hash).
    ///
    /// Returns `Err` (not `WalVerification`) when limits are hit because the
    /// caller (`open`) cannot proceed without valid state. Contrast with
    /// [`verify`](Self::verify) which returns a result struct for inspection.
    fn scan_to_end(state: &mut WalState) -> Result<(), WalError> {
        let mut offset = HEADER_SIZE as u64;
        loop {
            if state.entry_count >= MAX_WAL_ENTRIES {
                return Err(WalError::TooManyEntries(MAX_WAL_ENTRIES));
            }

            let mut len_buf = [0u8; 4];
            if state.file.read_exact(&mut len_buf).is_err() {
                break;
            }

            let entry_len = u32::from_be_bytes(len_buf);
            if entry_len == 0 {
                break;
            }
            if entry_len > MAX_ENTRY_SIZE {
                break;
            }

            let mut entry_buf = vec![0u8; entry_len as usize];
            if state.file.read_exact(&mut entry_buf).is_err() {
                break;
            }

            let entry = match deserialize_entry(&entry_buf) {
                Ok(entry) => entry,
                Err(_) => break,
            };

            // Verify hash chain linkage (prev_hash must match our running last_hash).
            if entry.prev_hash.ct_eq(&state.last_hash).unwrap_u8() == 0 {
                log::warn!(
                    "WAL broken chain at seq {}: truncating to last valid entry (offset {})",
                    entry.sequence,
                    offset,
                );
                break;
            }

            let entry_hash = entry.compute_hash();
            state.cumulative_hasher.update(&entry_hash);
            let expected_cumulative = *state.cumulative_hasher.finalize().as_bytes();

            if entry
                .cumulative_hash
                .ct_eq(&expected_cumulative)
                .unwrap_u8()
                == 0
            {
                log::warn!(
                    "WAL cumulative hash mismatch at seq {}: truncating to last valid entry \
                     (offset {})",
                    entry.sequence,
                    offset,
                );
                break;
            }

            let sig = Signature::from_bytes(&entry.signature);
            let verifying_key = state.signing_key.verifying_key();
            if verifying_key.verify(&entry.cumulative_hash, &sig).is_err() {
                log::warn!(
                    "WAL signature invalid at seq {}: truncating to last valid entry (offset {})",
                    entry.sequence,
                    offset,
                );
                break;
            }

            state.next_sequence = entry.sequence + 1;
            state.last_hash = entry_hash;
            state.entry_count += 1;
            offset += (4 + entry_len) as u64;
        }

        // Truncate file to last valid entry to avoid appending after corrupt data
        state.file.set_len(offset)?;
        state.byte_count = offset;
        state.file.seek(SeekFrom::Start(offset))?;
        Ok(())
    }
}
