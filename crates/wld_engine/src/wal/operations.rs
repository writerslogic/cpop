// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

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
    pub fn open(
        path: impl AsRef<Path>,
        session_id: [u8; 32],
        signing_key: ed25519_dalek::SigningKey,
    ) -> Result<Self, WalError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false) // WAL files are appended to, not truncated
            .open(path)?;

        let mut state = WalState {
            path: path.to_path_buf(),
            file,
            session_id,
            signing_key,
            next_sequence: 0,
            last_hash: [0u8; 32],
            cumulative_hasher: Hasher::new(),
            closed: false,
            entry_count: 0,
            byte_count: 0,
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

    pub fn append(&self, entry_type: EntryType, payload: Vec<u8>) -> Result<(), WalError> {
        let mut state = self.inner.lock().unwrap();
        if state.closed {
            return Err(WalError::Closed);
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

        state.file.write_all(&length.to_be_bytes())?;
        state.file.write_all(&data)?;
        // fdatasync: flush data without metadata update (cheaper than sync_all).
        // Batch sync is left as future work.
        state.file.sync_data()?;

        state.last_hash = entry_hash;
        state.next_sequence += 1;
        state.entry_count += 1;
        state.byte_count += (4 + data.len()) as u64;

        Ok(())
    }

    pub fn verify(&self) -> Result<WalVerification, WalError> {
        let state = self.inner.lock().unwrap();
        let verifying_key = state.signing_key.verifying_key();

        let mut file = state.file.try_clone()?;

        // Read header to get last_checkpoint_seq for truncated WALs
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

    pub fn truncate(&self, before_seq: u64) -> Result<(), WalError> {
        let mut state = self.inner.lock().unwrap();
        // Read all entries, verify hash chain linkage, then re-write retained entries.
        let mut all_entries = Vec::new();
        let mut file = state.file.try_clone()?;
        file.seek(SeekFrom::Start(HEADER_SIZE as u64))?;

        loop {
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
            all_entries.push(entry);
        }

        // Verify prev_hash chain linkage before re-signing
        let mut expected_prev = [0u8; 32];
        for entry in &all_entries {
            if entry.prev_hash.ct_eq(&expected_prev).unwrap_u8() == 0 {
                return Err(WalError::BrokenChain);
            }
            expected_prev = entry.compute_hash();
        }

        let entries: Vec<_> = all_entries
            .into_iter()
            .filter(|e| e.sequence >= before_seq)
            .collect();

        let new_path = state.path.with_extension("wal.new");
        let mut new_file = File::create(&new_path)?;

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
        state.file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&state.path)?;
        state.file.seek(SeekFrom::End(0))?;
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

    pub fn size(&self) -> u64 {
        let state = self.inner.lock().unwrap();
        state.byte_count
    }

    pub fn entry_count(&self) -> u64 {
        let state = self.inner.lock().unwrap();
        state.entry_count
    }

    pub fn last_sequence(&self) -> u64 {
        let state = self.inner.lock().unwrap();
        if state.next_sequence == 0 {
            0
        } else {
            state.next_sequence - 1
        }
    }

    pub fn close(&self) -> Result<(), WalError> {
        let mut state = self.inner.lock().unwrap();
        if state.closed {
            return Ok(());
        }
        state.closed = true;
        state.file.sync_all()?;
        Ok(())
    }

    pub fn path(&self) -> PathBuf {
        let state = self.inner.lock().unwrap();
        state.path.clone()
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
        state.session_id = header.session_id;
        Ok(())
    }

    fn scan_to_end(state: &mut WalState) -> Result<(), WalError> {
        let mut offset = HEADER_SIZE as u64;
        loop {
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
            // Ed25519 signatures are NOT verified here because the verifying key
            // may differ from the signing key provided at open() time.
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
