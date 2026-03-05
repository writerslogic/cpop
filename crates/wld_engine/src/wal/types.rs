// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use blake3::Hasher;
use ed25519_dalek::SigningKey;
use std::fs::File;
use std::path::PathBuf;
use std::sync::Mutex;
use thiserror::Error;

pub(super) const VERSION: u32 = 2;
pub(super) const MAGIC: &[u8; 4] = b"SWAL"; // Secure WAL
pub(super) const HEADER_SIZE: usize = 64;
pub(super) const MAX_ENTRY_SIZE: u32 = 16 * 1024 * 1024; // 16 MiB
/// Reject WAL files claiming more entries than this to prevent OOM on corrupt data.
pub(super) const MAX_WAL_ENTRIES: u64 = 10_000_000;

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
    #[error("wal: entry count exceeds maximum ({0})")]
    TooManyEntries(u64),
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
    pub(super) fn compute_hash(&self) -> [u8; 32] {
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
    pub(super) inner: Mutex<WalState>,
}

pub(super) struct WalState {
    pub(super) path: PathBuf,
    pub(super) file: File,
    pub(super) session_id: [u8; 32],
    pub(super) signing_key: SigningKey,
    pub(super) next_sequence: u64,
    pub(super) last_hash: [u8; 32],
    pub(super) cumulative_hasher: Hasher,
    pub(super) closed: bool,
    pub(super) entry_count: u64,
    pub(super) byte_count: u64,
}

pub struct WalVerification {
    pub valid: bool,
    pub entries: u64,
    pub final_hash: [u8; 32],
    pub error: Option<WalError>,
}
