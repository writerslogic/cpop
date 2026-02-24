use thiserror::Error;

#[derive(Debug, Error)]
pub enum MmrError {
    #[error("mmr: empty")]
    Empty,
    #[error("mmr: corrupted store")]
    CorruptedStore,
    #[error("mmr: index out of range")]
    IndexOutOfRange,
    #[error("mmr: invalid node data")]
    InvalidNodeData,
    #[error("mmr: invalid proof")]
    InvalidProof,
    #[error("mmr: hash mismatch")]
    HashMismatch,
    #[error("mmr: node not found")]
    NodeNotFound,
    #[error("mmr: io error: {0}")]
    Io(#[from] std::io::Error),
}
