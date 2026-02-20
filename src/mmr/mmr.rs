use crate::mmr::errors::MmrError;
use crate::mmr::node::Node;
use crate::mmr::proof::{InclusionProof, ProofElement, RangeProof};
use crate::mmr::store::Store;
use std::sync::RwLock;

pub struct MMR {
    store: Box<dyn Store>,
    state: RwLock<MmrState>,
}

struct MmrState {
    size: u64,
    peaks: Vec<u64>,
}

impl MMR {
    pub fn new(store: Box<dyn Store>) -> Result<Self, MmrError> {
        let size = store.size()?;
        let peaks = if size == 0 {
            Vec::new()
        } else {
            find_peaks(size)
        };
        Ok(Self {
            store,
            state: RwLock::new(MmrState { size, peaks }),
        })
    }

    pub fn append(&self, data: &[u8]) -> Result<u64, MmrError> {
        let mut state = self.state.write().unwrap();
        let leaf_index = state.size;
        let leaf = Node::new_leaf(leaf_index, data);
        self.store.append(&leaf)?;
        state.size += 1;

        loop {
            let peaks = find_peaks(state.size);
            if peaks.len() < 2 {
                state.peaks = peaks;
                break;
            }
            let last_idx = peaks[peaks.len() - 1];
            let prev_idx = peaks[peaks.len() - 2];
            let last = self.store.get(last_idx)?;
            let prev = self.store.get(prev_idx)?;
            if last.height != prev.height {
                state.peaks = peaks;
                break;
            }
            let new_node = Node::new_internal(state.size, last.height + 1, &prev, &last);
            self.store.append(&new_node)?;
            state.size += 1;
        }

        Ok(leaf_index)
    }

    pub fn get_peaks(&self) -> Result<Vec<[u8; 32]>, MmrError> {
        let state = self.state.read().unwrap();
        if state.size == 0 {
            return Ok(Vec::new());
        }
        let peaks = find_peaks(state.size);
        let mut hashes = Vec::with_capacity(peaks.len());
        for idx in peaks {
            hashes.push(self.store.get(idx)?.hash);
        }
        Ok(hashes)
    }

    pub fn get_root(&self) -> Result<[u8; 32], MmrError> {
        let peaks = self.get_peaks()?;
        if peaks.is_empty() {
            return Err(MmrError::Empty);
        }
        if peaks.len() == 1 {
            return Ok(peaks[0]);
        }
        let mut root = peaks[peaks.len() - 1];
        for i in (0..peaks.len() - 1).rev() {
            root = crate::mmr::node::hash_internal(peaks[i], root);
        }
        Ok(root)
    }

    pub fn size(&self) -> u64 {
        self.state.read().unwrap().size
    }

    pub fn leaf_count(&self) -> u64 {
        leaf_count_from_size(self.state.read().unwrap().size)
    }

    pub fn get(&self, index: u64) -> Result<Node, MmrError> {
        let state = self.state.read().unwrap();
        if index >= state.size {
            return Err(MmrError::IndexOutOfRange);
        }
        self.store.get(index)
    }

    pub fn get_leaf_index(&self, leaf_ordinal: u64) -> Result<u64, MmrError> {
        let state = self.state.read().unwrap();
        if state.size == 0 {
            return Err(MmrError::Empty);
        }
        let leaf_count = leaf_count_from_size(state.size);
        if leaf_ordinal >= leaf_count {
            return Err(MmrError::IndexOutOfRange);
        }
        let mut current_leaf = 0u64;
        for idx in 0..state.size {
            let node = self.store.get(idx)?;
            if node.height == 0 {
                if current_leaf == leaf_ordinal {
                    return Ok(idx);
                }
                current_leaf += 1;
            }
        }
        Err(MmrError::IndexOutOfRange)
    }

    pub fn get_leaf_indices(&self, start: u64, end: u64) -> Result<Vec<u64>, MmrError> {
        let state = self.state.read().unwrap();
        if start > end {
            return Err(MmrError::InvalidProof);
        }
        let leaf_count = leaf_count_from_size(state.size);
        if end >= leaf_count {
            return Err(MmrError::IndexOutOfRange);
        }
        let mut indices = Vec::with_capacity((end - start + 1) as usize);
        let mut current_leaf = 0u64;
        for idx in 0..state.size {
            let node = self.store.get(idx)?;
            if node.height == 0 {
                if current_leaf >= start && current_leaf <= end {
                    indices.push(idx);
                }
                current_leaf += 1;
                if current_leaf > end {
                    break;
                }
            }
        }
        Ok(indices)
    }

    pub fn generate_proof(&self, leaf_index: u64) -> Result<InclusionProof, MmrError> {
        let state = self.state.read().unwrap();
        if state.size == 0 {
            return Err(MmrError::Empty);
        }
        if leaf_index >= state.size {
            return Err(MmrError::IndexOutOfRange);
        }
        let node = self.store.get(leaf_index)?;
        if node.height != 0 {
            return Err(MmrError::InvalidProof);
        }
        let (path, peak_index) = self.generate_merkle_path(leaf_index)?;
        let peaks = self.get_peaks()?;
        let peak_indices = find_peaks(state.size);
        let mut peak_position = None;
        for (i, idx) in peak_indices.iter().enumerate() {
            if *idx == peak_index {
                peak_position = Some(i);
                break;
            }
        }
        let peak_position = peak_position.ok_or(MmrError::InvalidProof)?;
        let root = self.get_root()?;
        Ok(InclusionProof {
            leaf_index,
            leaf_hash: node.hash,
            merkle_path: path,
            peaks,
            peak_position,
            mmr_size: state.size,
            root,
        })
    }

    pub fn generate_range_proof(
        &self,
        start_leaf: u64,
        end_leaf: u64,
    ) -> Result<RangeProof, MmrError> {
        let state = self.state.read().unwrap();
        if state.size == 0 {
            return Err(MmrError::Empty);
        }
        if start_leaf > end_leaf {
            return Err(MmrError::InvalidProof);
        }
        let leaf_count = leaf_count_from_size(state.size);
        if end_leaf >= leaf_count {
            return Err(MmrError::IndexOutOfRange);
        }
        let leaf_indices = self.get_leaf_indices(start_leaf, end_leaf)?;
        let mut leaf_hashes = Vec::with_capacity(leaf_indices.len());
        for idx in &leaf_indices {
            leaf_hashes.push(self.store.get(*idx)?.hash);
        }
        let (sibling_path, peak_index) = self.generate_range_merkle_path(&leaf_indices)?;
        let peaks = self.get_peaks()?;
        let peak_indices = find_peaks(state.size);
        let mut peak_position = None;
        for (i, idx) in peak_indices.iter().enumerate() {
            if *idx == peak_index {
                peak_position = Some(i);
                break;
            }
        }
        let peak_position = peak_position.ok_or(MmrError::InvalidProof)?;
        let root = self.get_root()?;
        Ok(RangeProof {
            start_leaf,
            end_leaf,
            leaf_indices,
            leaf_hashes,
            sibling_path,
            peaks,
            peak_position,
            mmr_size: state.size,
            root,
        })
    }

    fn generate_merkle_path(&self, leaf_index: u64) -> Result<(Vec<ProofElement>, u64), MmrError> {
        let mut path = Vec::new();
        let mut pos = leaf_index;
        let node = self.store.get(pos)?;
        let mut height = node.height;

        loop {
            let (sibling_pos, parent_pos, is_right_child, found) = self.find_family(pos, height)?;
            if !found {
                return Ok((path, pos));
            }
            let sibling = self.store.get(sibling_pos)?;
            path.push(ProofElement {
                hash: sibling.hash,
                is_left: is_right_child,
            });
            pos = parent_pos;
            height += 1;
        }
    }

    fn find_family(&self, pos: u64, height: u8) -> Result<(u64, u64, bool, bool), MmrError> {
        let state = self.state.read().unwrap();
        let offset = 1u64 << (height + 1);

        let left_parent = pos + offset;
        let right_sibling = left_parent.saturating_sub(1);
        if right_sibling < state.size && right_sibling != pos {
            let right_node = self.store.get(right_sibling)?;
            if right_node.height == height && left_parent < state.size {
                let parent = self.store.get(left_parent)?;
                if parent.height == height + 1 {
                    return Ok((right_sibling, left_parent, false, true));
                }
            }
        }

        let right_parent = pos + 1;
        if offset <= pos + 1 {
            let left_sibling = right_parent - offset;
            if left_sibling < state.size && left_sibling != pos {
                let left_node = self.store.get(left_sibling)?;
                if left_node.height == height && right_parent < state.size {
                    let parent = self.store.get(right_parent)?;
                    if parent.height == height + 1 {
                        return Ok((left_sibling, right_parent, true, true));
                    }
                }
            }
        }

        Ok((0, 0, false, false))
    }

    fn generate_range_merkle_path(
        &self,
        leaf_indices: &[u64],
    ) -> Result<(Vec<ProofElement>, u64), MmrError> {
        use std::collections::HashMap;
        if leaf_indices.is_empty() {
            return Err(MmrError::InvalidProof);
        }
        let mut covered: HashMap<u64, bool> = HashMap::new();
        for idx in leaf_indices {
            covered.insert(*idx, true);
        }
        let mut path: Vec<ProofElement> = Vec::new();
        let mut current_level: Vec<u64> = leaf_indices.to_vec();
        let mut height: u8 = 0;
        let mut peak_index = 0u64;

        while !current_level.is_empty() {
            current_level.sort_unstable();
            let mut next_level = Vec::new();
            let mut processed_parents: HashMap<u64, bool> = HashMap::new();
            for pos in &current_level {
                let (sibling_pos, parent_pos, is_right_child, found) =
                    self.find_family(*pos, height)?;
                if !found {
                    peak_index = *pos;
                    continue;
                }
                if *processed_parents.get(&parent_pos).unwrap_or(&false) {
                    continue;
                }
                processed_parents.insert(parent_pos, true);
                if !covered.get(&sibling_pos).copied().unwrap_or(false) {
                    let sibling = self.store.get(sibling_pos)?;
                    path.push(ProofElement {
                        hash: sibling.hash,
                        is_left: is_right_child,
                    });
                }
                covered.insert(parent_pos, true);
                next_level.push(parent_pos);
            }
            current_level = next_level;
            height += 1;
        }

        Ok((path, peak_index))
    }
}

pub fn find_peaks(size: u64) -> Vec<u64> {
    if size == 0 {
        return Vec::new();
    }
    let mut peaks = Vec::new();
    let mut pos = 0u64;
    while pos < size {
        let mut height = highest_peak(size - pos);
        if height == 0 {
            peaks.push(pos);
            pos += 1;
            continue;
        }
        let mut tree_size = (1u64 << (height + 1)) - 1;
        if pos + tree_size > size {
            height -= 1;
            tree_size = (1u64 << (height + 1)) - 1;
        }
        let peak_pos = pos + tree_size - 1;
        peaks.push(peak_pos);
        pos += tree_size;
    }
    peaks
}

pub fn highest_peak(size: u64) -> u8 {
    if size == 0 {
        return 0;
    }
    let bits_len = 64 - (size + 1).leading_zeros() as u8;
    let mut h = bits_len.saturating_sub(1);
    while h > 0 {
        let tree_size = (1u64 << (h + 1)) - 1;
        if tree_size <= size {
            return h;
        }
        h -= 1;
    }
    0
}

pub fn leaf_count_from_size(size: u64) -> u64 {
    if size == 0 {
        return 0;
    }
    let mut count = 0u64;
    let mut pos = 0u64;
    while pos < size {
        let mut height = highest_peak(size - pos);
        let mut tree_size = (1u64 << (height + 1)) - 1;
        if pos + tree_size > size {
            height -= 1;
            tree_size = (1u64 << (height + 1)) - 1;
        }
        if tree_size == 0 {
            tree_size = 1;
        }
        count += 1u64 << height;
        pos += tree_size;
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmr::store::MemoryStore;

    #[test]
    fn test_find_peaks() {
        assert_eq!(find_peaks(0), Vec::<u64>::new());
        assert_eq!(find_peaks(1), vec![0]);
        // Size 3 (perfect tree) -> peak at 2
        assert_eq!(find_peaks(3), vec![2]);
        // Size 4: 3 (perfect) + 1 leaf (idx 3)
        assert_eq!(find_peaks(4), vec![2, 3]);
        // Size 7: 3 (perfect) + 3 (perfect) + 1 parent = 7 (perfect)
        assert_eq!(find_peaks(7), vec![6]);
    }

    #[test]
    fn test_mmr_append_and_root() {
        let store = Box::new(MemoryStore::new());
        let mmr = MMR::new(store).unwrap();

        // 1. Append first leaf
        let idx1 = mmr.append(b"1").unwrap();
        assert_eq!(idx1, 0);
        assert_eq!(mmr.size(), 1);
        let root1 = mmr.get_root().unwrap();

        // 2. Append second leaf -> creates parent
        let idx2 = mmr.append(b"2").unwrap();
        assert_eq!(idx2, 1);
        assert_eq!(mmr.size(), 3); // 0, 1, and parent 2
        let root2 = mmr.get_root().unwrap();
        assert_ne!(root1, root2);

        // 3. Append third leaf
        let idx3 = mmr.append(b"3").unwrap();
        assert_eq!(idx3, 3);
        assert_eq!(mmr.size(), 4);
    }

    #[test]
    fn test_leaf_count_from_size() {
        assert_eq!(leaf_count_from_size(0), 0);
        assert_eq!(leaf_count_from_size(1), 1);
        assert_eq!(leaf_count_from_size(3), 2);
        assert_eq!(leaf_count_from_size(4), 3);
        assert_eq!(leaf_count_from_size(7), 4);
    }

    #[test]
    fn test_inclusion_proof() {
        let store = Box::new(MemoryStore::new());
        let mmr = MMR::new(store).unwrap();

        for i in 0..10 {
            mmr.append(&[i as u8]).unwrap();
        }

        // Verify proof for a few leaves
        for i in 0..10 {
            // Note: leaf index in MMR != leaf ordinal (0..N)
            // We need to find the node index for leaf ordinal i
            let leaf_idx = mmr.get_leaf_index(i).unwrap();
            let proof = mmr.generate_proof(leaf_idx).unwrap();

            assert_eq!(proof.leaf_index, leaf_idx);
            assert_eq!(proof.root, mmr.get_root().unwrap());
        }
    }
}
