// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use thiserror::Error;

/// Errors from Merkle Mountain Range operations.
#[derive(Debug, Error)]
pub enum MmrError {
    /// MMR contains no nodes
    #[error("empty")]
    Empty,
    /// Backing store data is inconsistent
    #[error("corrupted store")]
    CorruptedStore,
    /// Requested position exceeds the MMR size
    #[error("index out of range")]
    IndexOutOfRange,
    /// Node binary data could not be parsed
    #[error("invalid node data")]
    InvalidNodeData,
    /// Proof verification failed (path does not match root)
    #[error("invalid proof")]
    InvalidProof,
    /// Computed hash does not match expected value
    #[error("hash mismatch")]
    HashMismatch,
    /// Requested node does not exist in the store
    #[error("node not found")]
    NodeNotFound,
    /// Proof path or peaks exceed the u16 serialization limit
    #[error("proof component exceeds u16::MAX elements")]
    ProofTooLarge,
    /// Underlying I/O error
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
