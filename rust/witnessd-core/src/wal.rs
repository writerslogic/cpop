use blake3::Hasher;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

const VERSION: u32 = 2;
const MAGIC: &[u8; 4] = b"SWAL"; // Secure WAL
const HEADER_SIZE: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryType {
    KeystrokeBatch = 1,
    DocumentHash = 2,
    JitterSample = 3,
    Heartbeat = 4,
    SessionStart = 5,
    SessionEnd = 6,
    Checkpoint = 7,
}

impl TryFrom<u8> for EntryType {
    type Error = WalError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(EntryType::KeystrokeBatch),
            2 => Ok(EntryType::DocumentHash),
            3 => Ok(EntryType::JitterSample),
            4 => Ok(EntryType::Heartbeat),
            5 => Ok(EntryType::SessionStart),
            6 => Ok(EntryType::SessionEnd),
            7 => Ok(EntryType::Checkpoint),
            _ => Err(WalError::InvalidEntryType(value)),
        }
    }
}

#[derive(Debug, Error)]
pub enum WalError {
    #[error("wal: invalid magic number")]
    InvalidMagic,
    #[error("wal: unsupported version {0}")]
    InvalidVersion(u32),
    #[error("wal: corrupted entry")]
    CorruptedEntry,
    #[error("wal: broken hash chain")]
    BrokenChain,
    #[error("wal: cumulative hash mismatch")]
    CumulativeMismatch,
    #[error("wal: invalid signature")]
    InvalidSignature,
    #[error("wal: timestamp regression")]
    TimestampRegression,
    #[error("wal: log is closed")]
    Closed,
    #[error("wal: sequence number gap detected")]
    SequenceGap,
    #[error("wal: invalid entry type {0}")]
    InvalidEntryType(u8),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(String),
}

#[derive(Debug, Clone)]
pub struct Header {
    pub magic: [u8; 4],
    pub version: u32,
    pub session_id: [u8; 32],
    pub created_at: i64,
    pub last_checkpoint_seq: u64,
    pub reserved: [u8; 8],
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub length: u32,
    pub sequence: u64,
    pub timestamp: i64,
    pub entry_type: EntryType,
    pub payload: Vec<u8>,
    pub prev_hash: [u8; 32],
    pub cumulative_hash: [u8; 32],
    pub signature: [u8; 64],
}

impl Entry {
    fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(&self.sequence.to_le_bytes());
        hasher.update(&(self.timestamp as u64).to_le_bytes());
        hasher.update(&[self.entry_type as u8]);
        hasher.update(&self.payload);
        hasher.update(&self.prev_hash);
        *hasher.finalize().as_bytes()
    }
}

pub struct Wal {
    inner: Mutex<WalState>,
}

struct WalState {
    path: PathBuf,
    file: File,
    session_id: [u8; 32],
    signing_key: SigningKey,
    next_sequence: u64,
    last_hash: [u8; 32],
    cumulative_hasher: Hasher,
    closed: bool,
    entry_count: u64,
    byte_count: i64,
}

pub struct WalVerification {
    pub valid: bool,
    pub entries: u64,
    pub final_hash: [u8; 32],
    pub error: Option<WalError>,
}

impl Wal {
    pub fn open(
        path: impl AsRef<Path>,
        session_id: [u8; 32],
        signing_key: SigningKey,
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
            state.byte_count = HEADER_SIZE as i64;
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

        // Sign the cumulative hash
        let sig = state.signing_key.sign(&entry.cumulative_hash);
        entry.signature = sig.to_bytes();

        let data = serialize_entry(&entry)?;
        let length = data.len() as u32;

        // Write length prefix then data
        state.file.write_all(&length.to_be_bytes())?;
        state.file.write_all(&data)?;
        state.file.sync_all()?;

        state.last_hash = entry_hash;
        state.next_sequence += 1;
        state.entry_count += 1;
        state.byte_count += (4 + data.len()) as i64;

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
            // ... (read entry)
            let mut len_buf = [0u8; 4];
            if let Err(err) = file.read_exact(&mut len_buf) {
                if err.kind() == std::io::ErrorKind::UnexpectedEof {
                    break;
                }
                return Err(err.into());
            }

            let entry_len = u32::from_be_bytes(len_buf);
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

            if entry.prev_hash != prev_hash {
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

            if entry.cumulative_hash != expected_cumulative {
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
        let state = self.inner.lock().unwrap();
        // For simplicity, read all entries and re-write them.
        // In a real system we'd do this more efficiently.
        let mut entries = Vec::new();
        let mut file = state.file.try_clone()?;
        file.seek(SeekFrom::Start(HEADER_SIZE as u64))?;

        loop {
            let mut len_buf = [0u8; 4];
            if file.read_exact(&mut len_buf).is_err() {
                break;
            }
            let entry_len = u32::from_be_bytes(len_buf);
            let mut entry_buf = vec![0u8; entry_len as usize];
            file.read_exact(&mut entry_buf)?;
            let entry = deserialize_entry(&entry_buf)?;
            if entry.sequence >= before_seq {
                entries.push(entry);
            }
        }
        drop(state);

        let mut state = self.inner.lock().unwrap();
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
        state.last_hash = last_hash;
        state.cumulative_hasher = cumulative_hasher;
        state.next_sequence = if let Some(last) = entries.last() {
            last.sequence + 1
        } else {
            before_seq
        };
        state.entry_count = entries.len() as u64;
        state.byte_count = state.file.metadata()?.len() as i64;

        Ok(())
    }

    pub fn size(&self) -> i64 {
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

            let mut entry_buf = vec![0u8; entry_len as usize];
            if state.file.read_exact(&mut entry_buf).is_err() {
                break;
            }

            let entry = match deserialize_entry(&entry_buf) {
                Ok(entry) => entry,
                Err(_) => break,
            };

            let entry_hash = entry.compute_hash();
            state.cumulative_hasher.update(&entry_hash);

            state.next_sequence = entry.sequence + 1;
            state.last_hash = entry_hash;
            state.entry_count += 1;
            offset += (4 + entry_len) as u64;
        }

        state.byte_count = offset as i64;
        state.file.seek(SeekFrom::Start(offset))?;
        Ok(())
    }
}

fn serialize_header(header: &Header) -> Vec<u8> {
    let mut buf = vec![0u8; HEADER_SIZE];
    buf[0..4].copy_from_slice(&header.magic);
    buf[4..8].copy_from_slice(&header.version.to_be_bytes());
    buf[8..40].copy_from_slice(&header.session_id);
    buf[40..48].copy_from_slice(&(header.created_at as u64).to_be_bytes());
    buf[48..56].copy_from_slice(&header.last_checkpoint_seq.to_be_bytes());
    buf[56..64].copy_from_slice(&header.reserved);
    buf
}

fn deserialize_header(data: &[u8]) -> Result<Header, WalError> {
    if data.len() < HEADER_SIZE {
        return Err(WalError::Serialization("header too short".to_string()));
    }
    let mut magic = [0u8; 4];
    magic.copy_from_slice(&data[0..4]);
    let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(&data[8..40]);
    let created_at = u64::from_be_bytes(data[40..48].try_into().unwrap()) as i64;
    let last_checkpoint_seq = u64::from_be_bytes(data[48..56].try_into().unwrap());
    let mut reserved = [0u8; 8];
    reserved.copy_from_slice(&data[56..64]);

    Ok(Header {
        magic,
        version,
        session_id,
        created_at,
        last_checkpoint_seq,
        reserved,
    })
}

fn serialize_entry(entry: &Entry) -> Result<Vec<u8>, WalError> {
    let payload_len = entry.payload.len();
    // sequence(8) + timestamp(8) + type(1) + payload_len(4) + payload(N) + prev_hash(32) + cumulative_hash(32) + signature(64)
    let size = 8 + 8 + 1 + 4 + payload_len + 32 + 32 + 64;
    let mut buf = vec![0u8; size];
    let mut offset = 0usize;

    buf[offset..offset + 8].copy_from_slice(&entry.sequence.to_be_bytes());
    offset += 8;
    buf[offset..offset + 8].copy_from_slice(&(entry.timestamp as u64).to_be_bytes());
    offset += 8;
    buf[offset] = entry.entry_type as u8;
    offset += 1;
    buf[offset..offset + 4].copy_from_slice(&(payload_len as u32).to_be_bytes());
    offset += 4;
    buf[offset..offset + payload_len].copy_from_slice(&entry.payload);
    offset += payload_len;
    buf[offset..offset + 32].copy_from_slice(&entry.prev_hash);
    offset += 32;
    buf[offset..offset + 32].copy_from_slice(&entry.cumulative_hash);
    offset += 32;
    buf[offset..offset + 64].copy_from_slice(&entry.signature);

    Ok(buf)
}

fn deserialize_entry(data: &[u8]) -> Result<Entry, WalError> {
    if data.len() < 8 + 8 + 1 + 4 + 32 + 32 + 64 {
        return Err(WalError::Serialization("entry too short".to_string()));
    }
    let mut offset = 0usize;
    let sequence = u64::from_be_bytes(data[offset..offset + 8].try_into().unwrap());
    offset += 8;
    let timestamp = u64::from_be_bytes(data[offset..offset + 8].try_into().unwrap()) as i64;
    offset += 8;
    let entry_type = EntryType::try_from(data[offset])?;
    offset += 1;
    let payload_len = u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
    offset += 4;

    if data.len() < offset + payload_len + 32 + 32 + 64 {
        return Err(WalError::Serialization("entry truncated".to_string()));
    }

    let payload = data[offset..offset + payload_len].to_vec();
    offset += payload_len;
    let mut prev_hash = [0u8; 32];
    prev_hash.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;
    let mut cumulative_hash = [0u8; 32];
    cumulative_hash.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&data[offset..offset + 64]);

    Ok(Entry {
        length: (offset + 64) as u32,
        sequence,
        timestamp,
        entry_type,
        payload,
        prev_hash,
        cumulative_hash,
        signature,
    })
}

fn now_nanos() -> i64 {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0));
    dur.as_nanos() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_wal_path() -> PathBuf {
        let name = format!("witnessd-wal-{}.log", uuid::Uuid::new_v4());
        std::env::temp_dir().join(name)
    }

    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[0u8; 32])
    }

    #[test]
    fn test_wal_append_and_verify() {
        let path = temp_wal_path();
        let session_id = [7u8; 32];
        let signing_key = test_signing_key();

        let wal = Wal::open(&path, session_id, signing_key).expect("open wal");
        wal.append(EntryType::Heartbeat, vec![1, 2, 3])
            .expect("append");
        wal.append(EntryType::DocumentHash, vec![4, 5, 6])
            .expect("append");

        let verification = wal.verify().expect("verify");
        assert!(verification.valid);
        assert_eq!(verification.entries, 2);

        let _ = wal.close();
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_wal_truncate() {
        let path = temp_wal_path();
        let session_id = [3u8; 32];
        let signing_key = test_signing_key();

        let wal = Wal::open(&path, session_id, signing_key).expect("open wal");
        wal.append(EntryType::Heartbeat, vec![1]).expect("append");
        wal.append(EntryType::Heartbeat, vec![2]).expect("append");
        wal.append(EntryType::Heartbeat, vec![3]).expect("append");

        wal.truncate(1).expect("truncate");
        let verification = wal.verify().expect("verify");
        assert!(verification.valid);
        assert_eq!(verification.entries, 2);

        let _ = wal.close();
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_wal_reopen_after_close() {
        let path = temp_wal_path();
        let session_id = [8u8; 32];
        let signing_key = test_signing_key();

        // Create and populate WAL
        {
            let wal = Wal::open(&path, session_id, signing_key.clone()).expect("open wal");
            wal.append(EntryType::Heartbeat, vec![1, 2, 3])
                .expect("append");
            wal.append(EntryType::DocumentHash, vec![4, 5, 6])
                .expect("append");
            wal.close().expect("close");
        }

        // Reopen and verify
        {
            let wal = Wal::open(&path, session_id, signing_key).expect("reopen wal");
            let verification = wal.verify().expect("verify");
            assert!(verification.valid);
            assert_eq!(verification.entries, 2);
            wal.close().expect("close");
        }

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_wal_append_to_closed() {
        let path = temp_wal_path();
        let session_id = [9u8; 32];
        let signing_key = test_signing_key();

        let wal = Wal::open(&path, session_id, signing_key).expect("open wal");
        wal.close().expect("close");

        // Appending to closed WAL should fail
        let result = wal.append(EntryType::Heartbeat, vec![1, 2, 3]);
        assert!(result.is_err());
        match result {
            Err(WalError::Closed) => {} // Expected
            Err(e) => panic!("Expected WalError::Closed, got {:?}", e),
            Ok(_) => panic!("Expected error on append to closed WAL"),
        }

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_wal_all_entry_types() {
        let path = temp_wal_path();
        let session_id = [10u8; 32];
        let signing_key = test_signing_key();

        let wal = Wal::open(&path, session_id, signing_key).expect("open wal");

        // Append all entry types
        wal.append(EntryType::Heartbeat, vec![1])
            .expect("append heartbeat");
        wal.append(EntryType::DocumentHash, vec![2])
            .expect("append document hash");
        wal.append(EntryType::KeystrokeBatch, vec![3])
            .expect("append keystroke batch");
        wal.append(EntryType::JitterSample, vec![4])
            .expect("append jitter sample");
        wal.append(EntryType::SessionStart, vec![5])
            .expect("append session start");
        wal.append(EntryType::SessionEnd, vec![6])
            .expect("append session end");
        wal.append(EntryType::Checkpoint, vec![7])
            .expect("append checkpoint");

        let verification = wal.verify().expect("verify");
        assert!(verification.valid);
        assert_eq!(verification.entries, 7);
        assert_eq!(wal.entry_count(), 7);

        let _ = wal.close();
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_wal_large_payload() {
        let path = temp_wal_path();
        let session_id = [11u8; 32];
        let signing_key = test_signing_key();

        let wal = Wal::open(&path, session_id, signing_key).expect("open wal");

        // Append a large payload (1MB)
        let large_payload = vec![0xABu8; 1024 * 1024];
        wal.append(EntryType::KeystrokeBatch, large_payload.clone())
            .expect("append large payload");

        let verification = wal.verify().expect("verify");
        assert!(verification.valid);
        assert_eq!(verification.entries, 1);

        // Check size is reasonable
        let size = wal.size();
        assert!(size > 1024 * 1024, "Size should be at least 1MB");

        let _ = wal.close();
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_wal_exists() {
        let path = temp_wal_path();
        let session_id = [12u8; 32];
        let signing_key = test_signing_key();

        // Should not exist yet
        assert!(!Wal::exists(&path));

        // Create WAL
        let wal = Wal::open(&path, session_id, signing_key).expect("open wal");
        wal.append(EntryType::Heartbeat, vec![1]).expect("append");
        wal.close().expect("close");

        // Should exist now
        assert!(Wal::exists(&path));

        let _ = fs::remove_file(&path);

        // Should not exist after deletion
        assert!(!Wal::exists(&path));
    }

    #[test]
    fn test_wal_size_and_entry_count() {
        let path = temp_wal_path();
        let session_id = [13u8; 32];
        let signing_key = test_signing_key();

        let wal = Wal::open(&path, session_id, signing_key).expect("open wal");

        assert_eq!(wal.entry_count(), 0);

        wal.append(EntryType::Heartbeat, vec![1, 2, 3])
            .expect("append 1");
        assert_eq!(wal.entry_count(), 1);

        wal.append(EntryType::Heartbeat, vec![4, 5, 6])
            .expect("append 2");
        assert_eq!(wal.entry_count(), 2);

        let size = wal.size();
        assert!(size > 0, "Size should be positive");

        let _ = wal.close();
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_wal_last_sequence() {
        let path = temp_wal_path();
        let session_id = [14u8; 32];
        let signing_key = test_signing_key();

        let wal = Wal::open(&path, session_id, signing_key).expect("open wal");

        // Fresh WAL with no entries should have last_sequence 0
        assert_eq!(wal.last_sequence(), 0);

        wal.append(EntryType::Heartbeat, vec![1]).expect("append 1");
        // After first append (sequence 0), last_sequence should be 0
        assert_eq!(wal.last_sequence(), 0);

        wal.append(EntryType::Heartbeat, vec![2]).expect("append 2");
        // After second append (sequence 1), last_sequence should be 1
        assert_eq!(wal.last_sequence(), 1);

        wal.append(EntryType::Heartbeat, vec![3]).expect("append 3");
        assert_eq!(wal.last_sequence(), 2);

        let _ = wal.close();
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_wal_path() {
        let path = temp_wal_path();
        let session_id = [15u8; 32];
        let signing_key = test_signing_key();

        let wal = Wal::open(&path, session_id, signing_key).expect("open wal");
        assert_eq!(wal.path(), path);

        let _ = wal.close();
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_wal_truncate_empty() {
        let path = temp_wal_path();
        let session_id = [16u8; 32];
        let signing_key = test_signing_key();

        let wal = Wal::open(&path, session_id, signing_key).expect("open wal");

        // Truncate empty WAL should succeed without error
        wal.truncate(0).expect("truncate empty");

        let verification = wal.verify().expect("verify");
        assert!(verification.valid);
        assert_eq!(verification.entries, 0);

        let _ = wal.close();
        let _ = fs::remove_file(&path);
    }
}
