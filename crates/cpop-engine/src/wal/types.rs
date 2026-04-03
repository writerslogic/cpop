// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

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
/// Maximum WAL file size in bytes (256 MiB). Prevents unbounded disk growth.
pub(super) const MAX_WAL_SIZE: u64 = 256 * 1024 * 1024;

/// WAL entry type discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryType {
    /// Batch of keystroke events
    KeystrokeBatch = 1,
    /// Document content hash snapshot
    DocumentHash = 2,
    /// Timing jitter entropy sample
    JitterSample = 3,
    /// Periodic liveness heartbeat
    Heartbeat = 4,
    /// Session start marker
    SessionStart = 5,
    /// Session end marker
    SessionEnd = 6,
    /// Checkpoint with VDF proof
    Checkpoint = 7,
    /// Document path changed (rename/move)
    PathChange = 8,
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
            8 => Ok(EntryType::PathChange),
            _ => Err(WalError::InvalidEntryType(value)),
        }
    }
}

/// Errors from WAL operations.
#[derive(Debug, Error)]
pub enum WalError {
    /// File header has wrong magic bytes
    #[error("invalid magic number")]
    InvalidMagic,
    /// WAL version not supported by this build
    #[error("unsupported version {0}")]
    InvalidVersion(u32),
    /// Entry data failed integrity check
    #[error("corrupted entry")]
    CorruptedEntry,
    /// prev_hash does not match prior entry
    #[error("broken hash chain")]
    BrokenChain,
    /// Running cumulative hash does not match stored value
    #[error("cumulative hash mismatch")]
    CumulativeMismatch,
    /// Ed25519 signature over cumulative hash is invalid
    #[error("invalid signature")]
    InvalidSignature,
    /// Entry timestamp is earlier than its predecessor
    #[error("timestamp regression")]
    TimestampRegression,
    /// Attempted write to a closed WAL
    #[error("log is closed")]
    Closed,
    /// Non-contiguous sequence number detected
    #[error("sequence number gap detected")]
    SequenceGap,
    /// Unrecognized entry type discriminant
    #[error("invalid entry type {0}")]
    InvalidEntryType(u8),
    /// WAL exceeds the maximum allowed entry count
    #[error("entry count exceeds maximum ({0})")]
    TooManyEntries(u64),
    /// WAL file exceeds the maximum allowed size
    #[error("WAL size exceeds maximum ({0} bytes)")]
    TooLarge(u64),
    /// WAL header session_id does not match the session_id passed to open()
    #[error("WAL session_id mismatch")]
    SessionMismatch,
    /// Underlying I/O error
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// Binary serialization/deserialization failure
    #[error("serialization error: {0}")]
    Serialization(String),
    /// WAL state is inconsistent after a failed truncation; further writes are unsafe
    #[error("WAL is inconsistent and must be recovered or discarded")]
    Inconsistent,
}

/// WAL file header (64 bytes, written once at creation).
#[derive(Debug, Clone)]
pub struct Header {
    pub magic: [u8; 4],
    pub version: u32,
    pub session_id: [u8; 32],
    /// Creation timestamp (nanoseconds since epoch)
    pub created_at: i64,
    /// Sequence number of the last checkpoint before truncation
    pub last_checkpoint_seq: u64,
    /// Reserved for future use
    pub reserved: [u8; 8],
}

/// Single WAL entry with hash-chain linkage and signature.
#[derive(Debug, Clone)]
pub struct Entry {
    /// Serialized byte length of this entry
    pub length: u32,
    /// Monotonically increasing sequence number
    pub sequence: u64,
    /// Timestamp (nanoseconds since epoch)
    pub timestamp: i64,
    /// Discriminant identifying the payload kind
    pub entry_type: EntryType,
    /// Raw payload bytes
    pub payload: Vec<u8>,
    /// BLAKE3 hash of the previous entry (zero for the first)
    pub prev_hash: [u8; 32],
    /// Running BLAKE3 hash over all entries up to and including this one
    pub cumulative_hash: [u8; 32],
    /// Ed25519 signature over the cumulative hash
    pub signature: [u8; 64],
}

impl Entry {
    pub(super) fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(&self.sequence.to_le_bytes());
        hasher.update(&self.timestamp.to_le_bytes());
        hasher.update(&[self.entry_type as u8]);
        hasher.update(&self.payload);
        hasher.update(&self.prev_hash);
        *hasher.finalize().as_bytes()
    }
}

/// Append-only write-ahead log with hash-chain integrity and Ed25519 signatures.
pub struct Wal {
    pub(super) inner: Mutex<WalState>,
}

/// Number of appends between automatic fdatasyncs when no force_sync is requested.
pub const DEFAULT_SYNC_INTERVAL: u64 = 10;

pub(super) struct WalState {
    pub(super) path: PathBuf,
    pub(super) file: File,
    pub(super) session_id: [u8; 32],
    pub(super) signing_key: SigningKey,
    pub(super) next_sequence: u64,
    pub(super) last_hash: [u8; 32],
    pub(super) cumulative_hasher: Hasher,
    pub(super) closed: bool,
    pub(super) inconsistent: bool,
    pub(super) entry_count: u64,
    pub(super) byte_count: u64,
    /// Sync after every N appends (0 = sync every append, same as legacy behaviour).
    pub(super) sync_interval: u64,
    /// Appends written since the last fdatasync.
    pub(super) pending_syncs: u64,
}

/// Result of a full WAL integrity verification pass.
pub struct WalVerification {
    /// Whether all checks passed
    pub valid: bool,
    /// Number of entries successfully verified
    pub entries: u64,
    /// Hash of the last valid entry
    pub final_hash: [u8; 32],
    /// First error encountered, if any
    pub error: Option<WalError>,
}
