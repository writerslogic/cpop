// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::mmr::errors::MmrError;
use crate::mmr::node::Node;
use crate::mmr::proof::{InclusionProof, ProofElement, RangeProof};
use crate::mmr::store::Store;
use crate::RwLockRecover;
use std::sync::RwLock;

pub struct Mmr {
    store: Box<dyn Store>,
    state: RwLock<MmrState>,
}

struct MmrState {
    size: u64,
    peaks: Vec<u64>,
}

impl Mmr {
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
        let mut state = self.state.write_recover();
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
        let state = self.state.read_recover();
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
        self.state.read_recover().size
    }

    pub fn leaf_count(&self) -> u64 {
        leaf_count_from_size(self.state.read_recover().size)
    }

    /// Sync the underlying store to disk.
    pub fn sync(&self) -> Result<(), MmrError> {
        self.store.sync()
    }

    pub fn get(&self, index: u64) -> Result<Node, MmrError> {
        let state = self.state.read_recover();
        if index >= state.size {
            return Err(MmrError::IndexOutOfRange);
        }
        self.store.get(index)
    }

    pub fn get_leaf_index(&self, leaf_ordinal: u64) -> Result<u64, MmrError> {
        let state = self.state.read_recover();
        if state.size == 0 {
            return Err(MmrError::Empty);
        }
        let leaf_count = leaf_count_from_size(state.size);
        if leaf_ordinal >= leaf_count {
            return Err(MmrError::IndexOutOfRange);
        }

        // The MMR index of the n-th leaf (0-indexed) is: 2n - popcount(n)
        // This is O(1) instead of the previous O(N) scan.
        Ok(2 * leaf_ordinal - leaf_ordinal.count_ones() as u64)
    }

    pub fn get_leaf_indices(&self, start: u64, end: u64) -> Result<Vec<u64>, MmrError> {
        let state = self.state.read_recover();
        if start > end {
            return Err(MmrError::InvalidProof);
        }
        let leaf_count = leaf_count_from_size(state.size);
        if end >= leaf_count {
            return Err(MmrError::IndexOutOfRange);
        }

        let mut indices = Vec::with_capacity((end - start + 1) as usize);
        for ordinal in start..=end {
            // I(n) = 2n - popcount(n)
            indices.push(2 * ordinal - ordinal.count_ones() as u64);
        }
        Ok(indices)
    }

    pub fn generate_proof(&self, leaf_index: u64) -> Result<InclusionProof, MmrError> {
        let state = self.state.read_recover();
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
        let state = self.state.read_recover();
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
        let state = self.state.read_recover();
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

pub fn find_peaks(mut size: u64) -> Vec<u64> {
    let mut peaks = Vec::new();
    let mut offset = 0;
    while size > 0 {
        let h = highest_peak(size);
        let tree_size = (1u64 << (h + 1)) - 1;
        peaks.push(offset + tree_size - 1);
        offset += tree_size;
        size -= tree_size;
    }
    peaks
}

pub fn highest_peak(size: u64) -> u8 {
    if size == 0 {
        return 0;
    }
    (63 - (size + 1).leading_zeros() as u8).saturating_sub(1)
}

pub fn leaf_count_from_size(mut size: u64) -> u64 {
    let mut count = 0u64;
    while size > 0 {
        let h = highest_peak(size);
        let tree_size = (1u64 << (h + 1)) - 1;
        count += 1u64 << h;
        size -= tree_size;
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
        assert_eq!(find_peaks(3), vec![2]);
        assert_eq!(find_peaks(4), vec![2, 3]);
        assert_eq!(find_peaks(7), vec![6]);
    }

    #[test]
    fn test_mmr_append_and_root() {
        let store = Box::new(MemoryStore::new());
        let mmr = Mmr::new(store).unwrap();

        let idx1 = mmr.append(b"1").unwrap();
        assert_eq!(idx1, 0);
        assert_eq!(mmr.size(), 1);
        let root1 = mmr.get_root().unwrap();

        let idx2 = mmr.append(b"2").unwrap();
        assert_eq!(idx2, 1);
        assert_eq!(mmr.size(), 3);
        let root2 = mmr.get_root().unwrap();
        assert_ne!(root1, root2);

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
        let mmr = Mmr::new(store).unwrap();

        for i in 0..10 {
            mmr.append(&[i as u8]).unwrap();
        }

        for i in 0..10 {
            let leaf_idx = mmr.get_leaf_index(i).unwrap();
            let proof = mmr.generate_proof(leaf_idx).unwrap();

            assert_eq!(proof.leaf_index, leaf_idx);
            assert_eq!(proof.root, mmr.get_root().unwrap());
        }
    }

    #[test]
    fn test_inclusion_proof_verify_valid() {
        let store = Box::new(MemoryStore::new());
        let mmr = Mmr::new(store).unwrap();

        for i in 0..10u8 {
            mmr.append(&[i]).unwrap();
        }

        for i in 0..10u64 {
            let leaf_idx = mmr.get_leaf_index(i).unwrap();
            let proof = mmr.generate_proof(leaf_idx).unwrap();
            proof.verify(&[i as u8]).expect("valid proof should verify");
        }
    }

    #[test]
    fn test_inclusion_proof_verify_wrong_data() {
        let store = Box::new(MemoryStore::new());
        let mmr = Mmr::new(store).unwrap();

        for i in 0..5u8 {
            mmr.append(&[i]).unwrap();
        }

        let leaf_idx = mmr.get_leaf_index(2).unwrap();
        let proof = mmr.generate_proof(leaf_idx).unwrap();
        let err = proof.verify(b"wrong data").unwrap_err();
        assert!(
            matches!(err, MmrError::HashMismatch),
            "expected HashMismatch, got {err:?}"
        );
    }

    #[test]
    fn test_inclusion_proof_verify_tampered_root() {
        let store = Box::new(MemoryStore::new());
        let mmr = Mmr::new(store).unwrap();

        for i in 0..4u8 {
            mmr.append(&[i]).unwrap();
        }

        let leaf_idx = mmr.get_leaf_index(0).unwrap();
        let mut proof = mmr.generate_proof(leaf_idx).unwrap();
        proof.root = [0xffu8; 32];
        let err = proof.verify(&[0u8]).unwrap_err();
        assert!(
            matches!(err, MmrError::InvalidProof),
            "expected InvalidProof, got {err:?}"
        );
    }

    #[test]
    fn test_inclusion_proof_serialize_deserialize_roundtrip() {
        let store = Box::new(MemoryStore::new());
        let mmr = Mmr::new(store).unwrap();

        for i in 0..8u8 {
            mmr.append(&[i]).unwrap();
        }

        for i in 0..8u64 {
            let leaf_idx = mmr.get_leaf_index(i).unwrap();
            let proof = mmr.generate_proof(leaf_idx).unwrap();
            let bytes = proof.serialize().expect("serialize should succeed");
            let restored = InclusionProof::deserialize(&bytes).expect("deserialize should succeed");

            assert_eq!(proof.leaf_index, restored.leaf_index);
            assert_eq!(proof.leaf_hash, restored.leaf_hash);
            assert_eq!(proof.merkle_path.len(), restored.merkle_path.len());
            for (a, b) in proof.merkle_path.iter().zip(restored.merkle_path.iter()) {
                assert_eq!(a.hash, b.hash);
                assert_eq!(a.is_left, b.is_left);
            }
            assert_eq!(proof.peaks, restored.peaks);
            assert_eq!(proof.peak_position, restored.peak_position);
            assert_eq!(proof.mmr_size, restored.mmr_size);
            assert_eq!(proof.root, restored.root);

            // Deserialized proof should still verify
            restored
                .verify(&[i as u8])
                .expect("deserialized proof should verify");
        }
    }

    #[test]
    fn test_inclusion_proof_deserialize_too_short() {
        let err = InclusionProof::deserialize(&[0u8; 10]).unwrap_err();
        assert!(matches!(err, MmrError::InvalidNodeData));
    }

    #[test]
    fn test_inclusion_proof_deserialize_wrong_version() {
        let store = Box::new(MemoryStore::new());
        let mmr = Mmr::new(store).unwrap();
        mmr.append(b"a").unwrap();
        let leaf_idx = mmr.get_leaf_index(0).unwrap();
        let proof = mmr.generate_proof(leaf_idx).unwrap();
        let mut bytes = proof.serialize().unwrap();
        bytes[0] = 0xff; // corrupt version
        let err = InclusionProof::deserialize(&bytes).unwrap_err();
        assert!(matches!(err, MmrError::InvalidProof));
    }

    #[test]
    fn test_single_element_proof() {
        let store = Box::new(MemoryStore::new());
        let mmr = Mmr::new(store).unwrap();

        mmr.append(b"only").unwrap();
        let proof = mmr.generate_proof(0).unwrap();

        assert!(
            proof.merkle_path.is_empty(),
            "single leaf should have empty path"
        );
        assert_eq!(proof.peaks.len(), 1);
        proof
            .verify(b"only")
            .expect("single-element proof should verify");

        let bytes = proof.serialize().unwrap();
        let restored = InclusionProof::deserialize(&bytes).unwrap();
        restored
            .verify(b"only")
            .expect("roundtripped single-element proof should verify");
    }

    #[test]
    fn test_range_proof_verify_valid() {
        let store = Box::new(MemoryStore::new());
        let mmr = Mmr::new(store).unwrap();

        for i in 0..8u8 {
            mmr.append(&[i]).unwrap();
        }

        let proof = mmr.generate_range_proof(1, 3).unwrap();
        let leaf_data: Vec<Vec<u8>> = (1..=3u8).map(|i| vec![i]).collect();
        proof
            .verify(&leaf_data)
            .expect("valid range proof should verify");
    }

    #[test]
    fn test_range_proof_verify_wrong_data() {
        let store = Box::new(MemoryStore::new());
        let mmr = Mmr::new(store).unwrap();

        for i in 0..8u8 {
            mmr.append(&[i]).unwrap();
        }

        let proof = mmr.generate_range_proof(0, 2).unwrap();
        let bad_data: Vec<Vec<u8>> = vec![vec![0], vec![1], vec![99]];
        let err = proof.verify(&bad_data).unwrap_err();
        assert!(matches!(err, MmrError::HashMismatch));
    }

    #[test]
    fn test_range_proof_wrong_count() {
        let store = Box::new(MemoryStore::new());
        let mmr = Mmr::new(store).unwrap();

        for i in 0..4u8 {
            mmr.append(&[i]).unwrap();
        }

        let proof = mmr.generate_range_proof(0, 1).unwrap();
        // Pass wrong number of leaves
        let err = proof.verify(&[vec![0]]).unwrap_err();
        assert!(matches!(err, MmrError::InvalidProof));
    }

    #[test]
    fn test_range_proof_serialize_deserialize_roundtrip() {
        let store = Box::new(MemoryStore::new());
        let mmr = Mmr::new(store).unwrap();

        for i in 0..8u8 {
            mmr.append(&[i]).unwrap();
        }

        let proof = mmr.generate_range_proof(2, 5).unwrap();
        let bytes = proof.serialize().expect("serialize should succeed");
        let restored = RangeProof::deserialize(&bytes).expect("deserialize should succeed");

        assert_eq!(proof.start_leaf, restored.start_leaf);
        assert_eq!(proof.end_leaf, restored.end_leaf);
        assert_eq!(proof.leaf_indices, restored.leaf_indices);
        assert_eq!(proof.leaf_hashes, restored.leaf_hashes);
        assert_eq!(proof.sibling_path.len(), restored.sibling_path.len());
        for (a, b) in proof.sibling_path.iter().zip(restored.sibling_path.iter()) {
            assert_eq!(a.hash, b.hash);
            assert_eq!(a.is_left, b.is_left);
        }
        assert_eq!(proof.peaks, restored.peaks);
        assert_eq!(proof.peak_position, restored.peak_position);
        assert_eq!(proof.mmr_size, restored.mmr_size);
        assert_eq!(proof.root, restored.root);

        // Deserialized proof should still verify
        let leaf_data: Vec<Vec<u8>> = (2..=5u8).map(|i| vec![i]).collect();
        restored
            .verify(&leaf_data)
            .expect("deserialized range proof should verify");
    }

    #[test]
    fn test_range_proof_deserialize_too_short() {
        let err = RangeProof::deserialize(&[0u8; 5]).unwrap_err();
        assert!(matches!(err, MmrError::InvalidNodeData));
    }

    #[test]
    fn test_range_proof_deserialize_wrong_version() {
        let store = Box::new(MemoryStore::new());
        let mmr = Mmr::new(store).unwrap();
        for i in 0..4u8 {
            mmr.append(&[i]).unwrap();
        }
        let proof = mmr.generate_range_proof(0, 1).unwrap();
        let mut bytes = proof.serialize().unwrap();
        bytes[0] = 0xff;
        let err = RangeProof::deserialize(&bytes).unwrap_err();
        assert!(matches!(err, MmrError::InvalidProof));
    }

    #[test]
    fn test_mmr_error_variants() {
        // Verify Display output for each variant
        let cases: Vec<(MmrError, &str)> = vec![
            (MmrError::Empty, "empty"),
            (MmrError::CorruptedStore, "corrupted store"),
            (MmrError::IndexOutOfRange, "index out of range"),
            (MmrError::InvalidNodeData, "invalid node data"),
            (MmrError::InvalidProof, "invalid proof"),
            (MmrError::HashMismatch, "hash mismatch"),
            (MmrError::NodeNotFound, "node not found"),
            (
                MmrError::ProofTooLarge,
                "proof component exceeds u16::MAX elements",
            ),
        ];
        for (err, expected) in cases {
            assert_eq!(err.to_string(), expected);
        }
    }

    #[test]
    fn test_empty_mmr_operations() {
        let store = Box::new(MemoryStore::new());
        let mmr = Mmr::new(store).unwrap();

        assert_eq!(mmr.size(), 0);
        assert_eq!(mmr.leaf_count(), 0);
        assert!(matches!(mmr.get_root(), Err(MmrError::Empty)));
        assert!(matches!(mmr.generate_proof(0), Err(MmrError::Empty)));
        assert!(matches!(
            mmr.generate_range_proof(0, 0),
            Err(MmrError::Empty)
        ));
        assert!(matches!(mmr.get_leaf_index(0), Err(MmrError::Empty)));
    }

    #[test]
    fn test_index_out_of_range() {
        let store = Box::new(MemoryStore::new());
        let mmr = Mmr::new(store).unwrap();
        mmr.append(b"a").unwrap();
        mmr.append(b"b").unwrap();

        // Leaf ordinal beyond leaf count
        assert!(matches!(
            mmr.get_leaf_index(5),
            Err(MmrError::IndexOutOfRange)
        ));
        // MMR position beyond size
        assert!(matches!(mmr.get(99), Err(MmrError::IndexOutOfRange)));
        // Range proof beyond leaf count
        assert!(matches!(
            mmr.generate_range_proof(0, 99),
            Err(MmrError::IndexOutOfRange)
        ));
    }

    #[test]
    fn test_large_mmr_proof_integrity() {
        let store = Box::new(MemoryStore::new());
        let mmr = Mmr::new(store).unwrap();

        for i in 0..64u64 {
            mmr.append(&i.to_le_bytes()).unwrap();
        }

        assert_eq!(mmr.leaf_count(), 64);

        // Verify proofs at boundaries: first, last, middle
        for &ordinal in &[0u64, 31, 63] {
            let leaf_idx = mmr.get_leaf_index(ordinal).unwrap();
            let proof = mmr.generate_proof(leaf_idx).unwrap();
            proof
                .verify(&ordinal.to_le_bytes())
                .expect("large MMR proof should verify");
        }

        // Range proof spanning multiple subtrees
        let range_proof = mmr.generate_range_proof(10, 20).unwrap();
        let leaf_data: Vec<Vec<u8>> = (10..=20u64).map(|i| i.to_le_bytes().to_vec()).collect();
        range_proof
            .verify(&leaf_data)
            .expect("large range proof should verify");
    }

    #[test]
    fn test_inclusion_proof_tampered_peak() {
        let store = Box::new(MemoryStore::new());
        let mmr = Mmr::new(store).unwrap();

        for i in 0..4u8 {
            mmr.append(&[i]).unwrap();
        }

        let leaf_idx = mmr.get_leaf_index(1).unwrap();
        let mut proof = mmr.generate_proof(leaf_idx).unwrap();
        // Corrupt the peak at peak_position
        proof.peaks[proof.peak_position] = [0xaa; 32];
        let err = proof.verify(&[1u8]).unwrap_err();
        assert!(matches!(err, MmrError::InvalidProof));
    }

    #[test]
    fn test_inclusion_proof_invalid_peak_position() {
        let store = Box::new(MemoryStore::new());
        let mmr = Mmr::new(store).unwrap();
        mmr.append(b"x").unwrap();
        mmr.append(b"y").unwrap();

        let leaf_idx = mmr.get_leaf_index(0).unwrap();
        let mut proof = mmr.generate_proof(leaf_idx).unwrap();
        proof.peak_position = 999;
        let err = proof.verify(b"x").unwrap_err();
        assert!(matches!(err, MmrError::InvalidProof));
    }

    #[test]
    fn test_get_leaf_indices_range() {
        let store = Box::new(MemoryStore::new());
        let mmr = Mmr::new(store).unwrap();

        for i in 0..8u8 {
            mmr.append(&[i]).unwrap();
        }

        let indices = mmr.get_leaf_indices(0, 7).unwrap();
        assert_eq!(indices.len(), 8);

        // Each should match the individual get_leaf_index
        for ordinal in 0..8u64 {
            let single = mmr.get_leaf_index(ordinal).unwrap();
            assert_eq!(indices[ordinal as usize], single);
        }

        // start > end is an error
        assert!(matches!(
            mmr.get_leaf_indices(5, 3),
            Err(MmrError::InvalidProof)
        ));
    }

    #[test]
    fn test_node_serialize_deserialize_roundtrip() {
        use crate::mmr::node::Node;

        let node = Node::new_leaf(42, b"test data");
        let bytes = node.serialize();
        let restored = Node::deserialize(&bytes).expect("node deserialize should succeed");

        assert_eq!(node.index, restored.index);
        assert_eq!(node.height, restored.height);
        assert_eq!(node.hash, restored.hash);
    }
}
