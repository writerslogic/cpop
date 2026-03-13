// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use thiserror::Error;

/// Errors from Merkle Mountain Range operations.
#[derive(Debug, Error)]
pub enum MmrError {
    /// MMR contains no nodes
    #[error("mmr: empty")]
    Empty,
    /// Backing store data is inconsistent
    #[error("mmr: corrupted store")]
    CorruptedStore,
    /// Requested position exceeds the MMR size
    #[error("mmr: index out of range")]
    IndexOutOfRange,
    /// Node binary data could not be parsed
    #[error("mmr: invalid node data")]
    InvalidNodeData,
    /// Proof verification failed (path does not match root)
    #[error("mmr: invalid proof")]
    InvalidProof,
    /// Computed hash does not match expected value
    #[error("mmr: hash mismatch")]
    HashMismatch,
    /// Requested node does not exist in the store
    #[error("mmr: node not found")]
    NodeNotFound,
    /// Proof path or peaks exceed the u16 serialization limit
    #[error("mmr: proof component exceeds u16::MAX elements")]
    ProofTooLarge,
    /// Underlying I/O error
    #[error("mmr: io error: {0}")]
    Io(#[from] std::io::Error),
}
