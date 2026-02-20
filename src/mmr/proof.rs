use crate::mmr::errors::MmrError;
use crate::mmr::node::{hash_internal, hash_leaf, HASH_SIZE};

const PROOF_VERSION: u8 = 1;
const PROOF_TYPE_INCLUSION: u8 = 0x01;
const PROOF_TYPE_RANGE: u8 = 0x02;

#[derive(Debug, Clone)]
pub struct ProofElement {
    pub hash: [u8; HASH_SIZE],
    pub is_left: bool,
}

#[derive(Debug, Clone)]
pub struct InclusionProof {
    pub leaf_index: u64,
    pub leaf_hash: [u8; HASH_SIZE],
    pub merkle_path: Vec<ProofElement>,
    pub peaks: Vec<[u8; HASH_SIZE]>,
    pub peak_position: usize,
    pub mmr_size: u64,
    pub root: [u8; HASH_SIZE],
}

impl InclusionProof {
    pub fn verify(&self, leaf_data: &[u8]) -> Result<(), MmrError> {
        let expected = hash_leaf(leaf_data);
        if expected != self.leaf_hash {
            return Err(MmrError::HashMismatch);
        }
        let mut current = self.leaf_hash;
        for elem in &self.merkle_path {
            current = if elem.is_left {
                hash_internal(elem.hash, current)
            } else {
                hash_internal(current, elem.hash)
            };
        }
        if self.peak_position >= self.peaks.len() {
            return Err(MmrError::InvalidProof);
        }
        if current != self.peaks[self.peak_position] {
            return Err(MmrError::InvalidProof);
        }
        if self.peaks.len() == 1 {
            if self.peaks[0] != self.root {
                return Err(MmrError::InvalidProof);
            }
            return Ok(());
        }
        let mut root = self.peaks[self.peaks.len() - 1];
        for i in (0..self.peaks.len() - 1).rev() {
            root = hash_internal(self.peaks[i], root);
        }
        if root != self.root {
            return Err(MmrError::InvalidProof);
        }
        Ok(())
    }

    pub fn serialize(&self) -> Vec<u8> {
        let path_size = self.merkle_path.len() * 33;
        let peaks_size = self.peaks.len() * 32;
        let total = 1 + 1 + 8 + 32 + 2 + path_size + 2 + peaks_size + 2 + 8 + 32;
        let mut buf = vec![0u8; total];
        let mut offset = 0;
        buf[offset] = PROOF_VERSION;
        offset += 1;
        buf[offset] = PROOF_TYPE_INCLUSION;
        offset += 1;
        buf[offset..offset + 8].copy_from_slice(&self.leaf_index.to_be_bytes());
        offset += 8;
        buf[offset..offset + 32].copy_from_slice(&self.leaf_hash);
        offset += 32;
        buf[offset..offset + 2].copy_from_slice(&(self.merkle_path.len() as u16).to_be_bytes());
        offset += 2;
        for elem in &self.merkle_path {
            buf[offset..offset + 32].copy_from_slice(&elem.hash);
            offset += 32;
            buf[offset] = if elem.is_left { 1 } else { 0 };
            offset += 1;
        }
        buf[offset..offset + 2].copy_from_slice(&(self.peaks.len() as u16).to_be_bytes());
        offset += 2;
        for peak in &self.peaks {
            buf[offset..offset + 32].copy_from_slice(peak);
            offset += 32;
        }
        buf[offset..offset + 2].copy_from_slice(&(self.peak_position as u16).to_be_bytes());
        offset += 2;
        buf[offset..offset + 8].copy_from_slice(&self.mmr_size.to_be_bytes());
        offset += 8;
        buf[offset..offset + 32].copy_from_slice(&self.root);
        buf
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, MmrError> {
        if data.len() < 86 {
            return Err(MmrError::InvalidNodeData);
        }
        let mut offset = 0;
        let version = data[offset];
        offset += 1;
        if version != PROOF_VERSION {
            return Err(MmrError::InvalidProof);
        }
        let proof_type = data[offset];
        offset += 1;
        if proof_type != PROOF_TYPE_INCLUSION {
            return Err(MmrError::InvalidProof);
        }
        let leaf_index = u64::from_be_bytes(data[offset..offset + 8].try_into().unwrap());
        offset += 8;
        let mut leaf_hash = [0u8; HASH_SIZE];
        leaf_hash.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;
        let path_len = u16::from_be_bytes(data[offset..offset + 2].try_into().unwrap()) as usize;
        offset += 2;
        let mut merkle_path = Vec::with_capacity(path_len);
        for _ in 0..path_len {
            if offset + 33 > data.len() {
                return Err(MmrError::InvalidNodeData);
            }
            let mut hash = [0u8; HASH_SIZE];
            hash.copy_from_slice(&data[offset..offset + 32]);
            offset += 32;
            let is_left = data[offset] == 1;
            offset += 1;
            merkle_path.push(ProofElement { hash, is_left });
        }
        if offset + 2 > data.len() {
            return Err(MmrError::InvalidNodeData);
        }
        let peaks_len = u16::from_be_bytes(data[offset..offset + 2].try_into().unwrap()) as usize;
        offset += 2;
        let mut peaks = Vec::with_capacity(peaks_len);
        for _ in 0..peaks_len {
            if offset + 32 > data.len() {
                return Err(MmrError::InvalidNodeData);
            }
            let mut peak = [0u8; HASH_SIZE];
            peak.copy_from_slice(&data[offset..offset + 32]);
            offset += 32;
            peaks.push(peak);
        }
        if offset + 2 > data.len() {
            return Err(MmrError::InvalidNodeData);
        }
        let peak_position =
            u16::from_be_bytes(data[offset..offset + 2].try_into().unwrap()) as usize;
        offset += 2;
        if peaks.is_empty() || peak_position >= peaks.len() {
            return Err(MmrError::InvalidProof);
        }
        if offset + 8 + 32 > data.len() {
            return Err(MmrError::InvalidNodeData);
        }
        let mmr_size = u64::from_be_bytes(data[offset..offset + 8].try_into().unwrap());
        offset += 8;
        let mut root = [0u8; HASH_SIZE];
        root.copy_from_slice(&data[offset..offset + 32]);
        Ok(Self {
            leaf_index,
            leaf_hash,
            merkle_path,
            peaks,
            peak_position,
            mmr_size,
            root,
        })
    }
}

#[derive(Debug, Clone)]
pub struct RangeProof {
    pub start_leaf: u64,
    pub end_leaf: u64,
    pub leaf_indices: Vec<u64>,
    pub leaf_hashes: Vec<[u8; HASH_SIZE]>,
    pub sibling_path: Vec<ProofElement>,
    pub peaks: Vec<[u8; HASH_SIZE]>,
    pub peak_position: usize,
    pub mmr_size: u64,
    pub root: [u8; HASH_SIZE],
}

impl RangeProof {
    pub fn verify(&self, leaf_data: &[Vec<u8>]) -> Result<(), MmrError> {
        let expected = (self.end_leaf - self.start_leaf + 1) as usize;
        if leaf_data.len() != expected {
            return Err(MmrError::InvalidProof);
        }
        if self.leaf_hashes.len() != expected {
            return Err(MmrError::InvalidProof);
        }
        for (i, data) in leaf_data.iter().enumerate() {
            let h = hash_leaf(data);
            if h != self.leaf_hashes[i] {
                return Err(MmrError::HashMismatch);
            }
        }
        if self.leaf_indices.len() != self.leaf_hashes.len() {
            return Err(MmrError::InvalidProof);
        }

        use std::collections::HashMap;
        let mut current: HashMap<u64, [u8; HASH_SIZE]> = HashMap::new();
        for (i, hash) in self.leaf_hashes.iter().enumerate() {
            current.insert(self.leaf_indices[i], *hash);
        }

        let mut sibling_idx = 0usize;
        let mut height: u8 = 0;
        while current.len() > 1 || sibling_idx < self.sibling_path.len() {
            let mut next: HashMap<u64, [u8; HASH_SIZE]> = HashMap::new();
            let mut processed: HashMap<u64, bool> = HashMap::new();
            let mut positions: Vec<u64> = current.keys().copied().collect();
            positions.sort_unstable();
            for pos in positions {
                if *processed.get(&pos).unwrap_or(&false) {
                    continue;
                }
                let hash = current[&pos];
                let offset = 1u64 << (height + 1);
                let left_parent = pos + offset;
                let right_sibling = left_parent - 1;
                let parent_pos;
                let combined;
                if let Some(sib_hash) = current.get(&right_sibling) {
                    if right_sibling != pos {
                        combined = hash_internal(hash, *sib_hash);
                        parent_pos = left_parent;
                        processed.insert(right_sibling, true);
                    } else {
                        combined = hash;
                        parent_pos = pos;
                    }
                } else {
                    let right_parent = pos + 1;
                    if offset <= pos + 1 {
                        let left_sibling = right_parent - offset;
                        if let Some(sib_hash) = current.get(&left_sibling) {
                            combined = hash_internal(*sib_hash, hash);
                            parent_pos = right_parent;
                            processed.insert(left_sibling, true);
                        } else {
                            if sibling_idx >= self.sibling_path.len() {
                                next.insert(pos, hash);
                                processed.insert(pos, true);
                                continue;
                            }
                            let elem = &self.sibling_path[sibling_idx];
                            sibling_idx += 1;
                            if elem.is_left {
                                combined = hash_internal(elem.hash, hash);
                                parent_pos = right_parent;
                            } else {
                                combined = hash_internal(hash, elem.hash);
                                parent_pos = left_parent;
                            }
                        }
                    } else {
                        if sibling_idx >= self.sibling_path.len() {
                            next.insert(pos, hash);
                            processed.insert(pos, true);
                            continue;
                        }
                        let elem = &self.sibling_path[sibling_idx];
                        sibling_idx += 1;
                        combined = if elem.is_left {
                            hash_internal(elem.hash, hash)
                        } else {
                            hash_internal(hash, elem.hash)
                        };
                        parent_pos = left_parent;
                    }
                }
                processed.insert(pos, true);
                next.insert(parent_pos, combined);
            }
            if next.is_empty() {
                break;
            }
            current = next;
            height += 1;
        }

        if current.len() != 1 {
            return Err(MmrError::InvalidProof);
        }
        let computed_peak = *current.values().next().unwrap();
        if self.peak_position >= self.peaks.len() {
            return Err(MmrError::InvalidProof);
        }
        if computed_peak != self.peaks[self.peak_position] {
            return Err(MmrError::InvalidProof);
        }
        if self.peaks.len() == 1 {
            if self.peaks[0] != self.root {
                return Err(MmrError::InvalidProof);
            }
            return Ok(());
        }
        let mut root = self.peaks[self.peaks.len() - 1];
        for i in (0..self.peaks.len() - 1).rev() {
            root = hash_internal(self.peaks[i], root);
        }
        if root != self.root {
            return Err(MmrError::InvalidProof);
        }
        Ok(())
    }

    pub fn serialize(&self) -> Vec<u8> {
        let leaves_count = self.leaf_hashes.len();
        let indices_size = leaves_count * 8;
        let hashes_size = leaves_count * 32;
        let path_size = self.sibling_path.len() * 33;
        let peaks_size = self.peaks.len() * 32;
        let total = 1
            + 1
            + 8
            + 8
            + 2
            + indices_size
            + hashes_size
            + 2
            + path_size
            + 2
            + peaks_size
            + 2
            + 8
            + 32;
        let mut buf = vec![0u8; total];
        let mut offset = 0;
        buf[offset] = PROOF_VERSION;
        offset += 1;
        buf[offset] = PROOF_TYPE_RANGE;
        offset += 1;
        buf[offset..offset + 8].copy_from_slice(&self.start_leaf.to_be_bytes());
        offset += 8;
        buf[offset..offset + 8].copy_from_slice(&self.end_leaf.to_be_bytes());
        offset += 8;
        buf[offset..offset + 2].copy_from_slice(&(leaves_count as u16).to_be_bytes());
        offset += 2;
        for idx in &self.leaf_indices {
            buf[offset..offset + 8].copy_from_slice(&idx.to_be_bytes());
            offset += 8;
        }
        for hash in &self.leaf_hashes {
            buf[offset..offset + 32].copy_from_slice(hash);
            offset += 32;
        }
        buf[offset..offset + 2].copy_from_slice(&(self.sibling_path.len() as u16).to_be_bytes());
        offset += 2;
        for elem in &self.sibling_path {
            buf[offset..offset + 32].copy_from_slice(&elem.hash);
            offset += 32;
            buf[offset] = if elem.is_left { 1 } else { 0 };
            offset += 1;
        }
        buf[offset..offset + 2].copy_from_slice(&(self.peaks.len() as u16).to_be_bytes());
        offset += 2;
        for peak in &self.peaks {
            buf[offset..offset + 32].copy_from_slice(peak);
            offset += 32;
        }
        buf[offset..offset + 2].copy_from_slice(&(self.peak_position as u16).to_be_bytes());
        offset += 2;
        buf[offset..offset + 8].copy_from_slice(&self.mmr_size.to_be_bytes());
        offset += 8;
        buf[offset..offset + 32].copy_from_slice(&self.root);
        buf
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, MmrError> {
        if data.len() < 1 + 1 + 8 + 8 + 2 + 2 + 2 + 8 + 32 {
            return Err(MmrError::InvalidNodeData);
        }
        let mut offset = 0;
        let version = data[offset];
        offset += 1;
        if version != PROOF_VERSION {
            return Err(MmrError::InvalidProof);
        }
        let proof_type = data[offset];
        offset += 1;
        if proof_type != PROOF_TYPE_RANGE {
            return Err(MmrError::InvalidProof);
        }
        let start_leaf = u64::from_be_bytes(data[offset..offset + 8].try_into().unwrap());
        offset += 8;
        let end_leaf = u64::from_be_bytes(data[offset..offset + 8].try_into().unwrap());
        offset += 8;
        let leaves_len = u16::from_be_bytes(data[offset..offset + 2].try_into().unwrap()) as usize;
        offset += 2;
        let mut leaf_indices = Vec::with_capacity(leaves_len);
        for _ in 0..leaves_len {
            leaf_indices.push(u64::from_be_bytes(
                data[offset..offset + 8].try_into().unwrap(),
            ));
            offset += 8;
        }
        let mut leaf_hashes = Vec::with_capacity(leaves_len);
        for _ in 0..leaves_len {
            let mut hash = [0u8; HASH_SIZE];
            hash.copy_from_slice(&data[offset..offset + 32]);
            offset += 32;
            leaf_hashes.push(hash);
        }
        let path_len = u16::from_be_bytes(data[offset..offset + 2].try_into().unwrap()) as usize;
        offset += 2;
        let mut sibling_path = Vec::with_capacity(path_len);
        for _ in 0..path_len {
            let mut hash = [0u8; HASH_SIZE];
            hash.copy_from_slice(&data[offset..offset + 32]);
            offset += 32;
            let is_left = data[offset] == 1;
            offset += 1;
            sibling_path.push(ProofElement { hash, is_left });
        }
        let peaks_len = u16::from_be_bytes(data[offset..offset + 2].try_into().unwrap()) as usize;
        offset += 2;
        let mut peaks = Vec::with_capacity(peaks_len);
        for _ in 0..peaks_len {
            let mut peak = [0u8; HASH_SIZE];
            peak.copy_from_slice(&data[offset..offset + 32]);
            offset += 32;
            peaks.push(peak);
        }
        let peak_position =
            u16::from_be_bytes(data[offset..offset + 2].try_into().unwrap()) as usize;
        offset += 2;
        if peaks.is_empty() || peak_position >= peaks.len() {
            return Err(MmrError::InvalidProof);
        }
        let mmr_size = u64::from_be_bytes(data[offset..offset + 8].try_into().unwrap());
        offset += 8;
        let mut root = [0u8; HASH_SIZE];
        root.copy_from_slice(&data[offset..offset + 32]);
        Ok(Self {
            start_leaf,
            end_leaf,
            leaf_indices,
            leaf_hashes,
            sibling_path,
            peaks,
            peak_position,
            mmr_size,
            root,
        })
    }
}
