use crate::mmr::errors::MmrError;
use sha2::{Digest, Sha256};

pub const HASH_SIZE: usize = 32;
pub const NODE_SIZE: usize = 41;

const LEAF_PREFIX: u8 = 0x00;
const INTERNAL_PREFIX: u8 = 0x01;

#[derive(Debug, Clone)]
pub struct Node {
    pub index: u64,
    pub height: u8,
    pub hash: [u8; HASH_SIZE],
}

pub fn hash_leaf(data: &[u8]) -> [u8; HASH_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_PREFIX]);
    hasher.update(data);
    let digest = hasher.finalize();
    let mut out = [0u8; HASH_SIZE];
    out.copy_from_slice(&digest);
    out
}

pub fn hash_internal(left: [u8; HASH_SIZE], right: [u8; HASH_SIZE]) -> [u8; HASH_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update([INTERNAL_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    let digest = hasher.finalize();
    let mut out = [0u8; HASH_SIZE];
    out.copy_from_slice(&digest);
    out
}

impl Node {
    pub fn new_leaf(index: u64, data: &[u8]) -> Self {
        Self {
            index,
            height: 0,
            hash: hash_leaf(data),
        }
    }

    pub fn new_internal(index: u64, height: u8, left: &Node, right: &Node) -> Self {
        Self {
            index,
            height,
            hash: hash_internal(left.hash, right.hash),
        }
    }

    pub fn serialize(&self) -> [u8; NODE_SIZE] {
        let mut buf = [0u8; NODE_SIZE];
        buf[0..8].copy_from_slice(&self.index.to_be_bytes());
        buf[8] = self.height;
        buf[9..].copy_from_slice(&self.hash);
        buf
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, MmrError> {
        if data.len() < NODE_SIZE {
            return Err(MmrError::InvalidNodeData);
        }
        let mut hash = [0u8; HASH_SIZE];
        hash.copy_from_slice(&data[9..41]);
        Ok(Self {
            index: u64::from_be_bytes(data[0..8].try_into().unwrap()),
            height: data[8],
            hash,
        })
    }
}
