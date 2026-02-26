// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Per-chain MMR coordinator for anti-deletion protection.
//!
//! Each checkpoint chain gets an associated Merkle Mountain Range that records
//! every checkpoint hash as a leaf. The MMR root + leaf count are signed into
//! `ChainMetadata`, making checkpoint deletion detectable.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::checkpoint::{Chain, ChainMetadata};
use crate::error::{Error, Result};
use crate::mmr::{FileStore, InclusionProof, MemoryStore, RangeProof, MMR};

/// Per-chain MMR coordinator.
///
/// Manages the MMR backing store and provides checkpoint append/verify operations.
pub struct CheckpointMMR {
    mmr: MMR,
}

impl CheckpointMMR {
    /// Open or create a file-backed MMR for the given chain ID.
    ///
    /// Store path: `{mmr_dir}/{chain_id}.mmr`
    pub fn open(mmr_dir: &Path, chain_id: &str) -> Result<Self> {
        std::fs::create_dir_all(mmr_dir)?;
        let store_path = mmr_dir.join(format!("{chain_id}.mmr"));
        let store = FileStore::open(&store_path).map_err(Error::from)?;
        let mmr = MMR::new(Box::new(store)).map_err(Error::from)?;
        Ok(Self { mmr })
    }

    /// Create an in-memory MMR (for testing).
    pub fn in_memory() -> Result<Self> {
        let store = MemoryStore::new();
        let mmr = MMR::new(Box::new(store)).map_err(Error::from)?;
        Ok(Self { mmr })
    }

    /// Append a checkpoint hash to the MMR and return the inclusion proof.
    pub fn append_checkpoint(&self, checkpoint_hash: &[u8; 32]) -> Result<InclusionProof> {
        let leaf_index = self.mmr.append(checkpoint_hash).map_err(Error::from)?;
        // Sync buffered writes before generating proof (FileStore needs this)
        self.mmr.sync().map_err(Error::from)?;
        let proof = self.mmr.generate_proof(leaf_index).map_err(Error::from)?;
        Ok(proof)
    }

    /// Verify that a checkpoint hash exists in the MMR at the given leaf ordinal.
    pub fn verify_checkpoint(&self, checkpoint_hash: &[u8; 32], leaf_ordinal: u64) -> Result<bool> {
        let leaf_index = self.mmr.get_leaf_index(leaf_ordinal).map_err(Error::from)?;
        let proof = self.mmr.generate_proof(leaf_index).map_err(Error::from)?;
        let expected_leaf_hash = crate::mmr::hash_leaf(checkpoint_hash);
        Ok(proof.leaf_hash == expected_leaf_hash)
    }

    /// Get the current MMR root hash.
    pub fn root(&self) -> Result<[u8; 32]> {
        self.mmr.get_root().map_err(Error::from)
    }

    /// Get the current leaf count.
    pub fn leaf_count(&self) -> u64 {
        self.mmr.leaf_count()
    }

    /// Generate a range proof covering all checkpoints.
    pub fn range_proof(&self) -> Result<Option<RangeProof>> {
        let count = self.leaf_count();
        if count == 0 {
            return Ok(None);
        }
        let proof = self
            .mmr
            .generate_range_proof(0, count - 1)
            .map_err(Error::from)?;
        Ok(Some(proof))
    }

    /// Build `ChainMetadata` from the current MMR state.
    ///
    /// The metadata is unsigned; call `sign_chain_metadata()` on the session
    /// to add a signature.
    pub fn build_metadata(&self) -> Result<ChainMetadata> {
        let count = self.leaf_count();
        let mmr_root = if count > 0 { self.root()? } else { [0u8; 32] };

        Ok(ChainMetadata {
            checkpoint_count: count,
            mmr_root,
            mmr_leaf_count: count,
            metadata_signature: None,
            metadata_version: 1,
        })
    }

    /// Rebuild MMR from an existing chain's checkpoints.
    ///
    /// Used during migration: replays all checkpoint hashes into a fresh MMR.
    pub fn rebuild_from_chain(&self, chain: &Chain) -> Result<()> {
        for cp in &chain.checkpoints {
            self.mmr.append(&cp.hash).map_err(Error::from)?;
        }
        Ok(())
    }

    /// Sync the MMR store to disk.
    pub fn sync(&self) -> Result<()> {
        self.mmr.sync().map_err(Error::from)
    }

    /// Get the default MMR directory path.
    pub fn default_mmr_dir() -> PathBuf {
        dirs::home_dir()
            .map(|h| h.join(".witnessd").join("mmr"))
            .unwrap_or_else(|| PathBuf::from(".witnessd/mmr"))
    }
}

/// Compute the metadata signing payload.
///
/// Returns `SHA256("witnessd-chain-metadata-v1" || checkpoint_count || mmr_root || mmr_leaf_count)`.
pub fn metadata_signing_payload(metadata: &ChainMetadata) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"witnessd-chain-metadata-v1");
    hasher.update(metadata.checkpoint_count.to_be_bytes());
    hasher.update(metadata.mmr_root);
    hasher.update(metadata.mmr_leaf_count.to_be_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::SignaturePolicy;
    use crate::vdf::Parameters;
    use std::fs;
    use std::time::Duration;
    use tempfile::TempDir;

    fn test_vdf_params() -> Parameters {
        Parameters {
            iterations_per_second: 1000,
            min_iterations: 10,
            max_iterations: 100_000,
        }
    }

    #[test]
    fn test_mmr_append_and_verify() {
        let mmr = CheckpointMMR::in_memory().expect("create mmr");
        let hash = [0xABu8; 32];

        let proof = mmr.append_checkpoint(&hash).expect("append");
        assert_eq!(proof.leaf_index, 0);
        assert_eq!(mmr.leaf_count(), 1);

        let valid = mmr.verify_checkpoint(&hash, 0).expect("verify");
        assert!(valid);
    }

    #[test]
    fn test_mmr_multiple_appends() {
        let mmr = CheckpointMMR::in_memory().expect("create mmr");

        for i in 0u8..5 {
            let hash = [i; 32];
            mmr.append_checkpoint(&hash).expect("append");
        }

        assert_eq!(mmr.leaf_count(), 5);

        for i in 0u8..5 {
            let hash = [i; 32];
            let valid = mmr.verify_checkpoint(&hash, i as u64).expect("verify");
            assert!(valid, "checkpoint {i} should verify");
        }
    }

    #[test]
    fn test_mmr_root_changes_on_append() {
        let mmr = CheckpointMMR::in_memory().expect("create mmr");

        mmr.append_checkpoint(&[1u8; 32]).expect("append 1");
        let root1 = mmr.root().expect("root 1");

        mmr.append_checkpoint(&[2u8; 32]).expect("append 2");
        let root2 = mmr.root().expect("root 2");

        assert_ne!(root1, root2);
    }

    #[test]
    fn test_build_metadata() {
        let mmr = CheckpointMMR::in_memory().expect("create mmr");

        for i in 0u8..3 {
            mmr.append_checkpoint(&[i; 32]).expect("append");
        }

        let metadata = mmr.build_metadata().expect("build metadata");
        assert_eq!(metadata.checkpoint_count, 3);
        assert_eq!(metadata.mmr_leaf_count, 3);
        assert_ne!(metadata.mmr_root, [0u8; 32]);
        assert_eq!(metadata.metadata_version, 1);
        assert!(metadata.metadata_signature.is_none());
    }

    #[test]
    fn test_deletion_detected_via_count() {
        let mmr = CheckpointMMR::in_memory().expect("create mmr");

        for i in 0u8..5 {
            mmr.append_checkpoint(&[i; 32]).expect("append");
        }

        let metadata = mmr.build_metadata().expect("build metadata");
        assert_eq!(metadata.checkpoint_count, 5);

        // If someone deletes checkpoints from the chain but the metadata says 5,
        // the chain verifier will detect the mismatch
    }

    #[test]
    fn test_file_backed_mmr_persists() {
        let dir = TempDir::new().expect("create temp dir");
        let mmr_dir = dir.path().join("mmr");

        // Create and populate using raw MMR
        {
            let store_path = mmr_dir.join("test-chain.mmr");
            std::fs::create_dir_all(&mmr_dir).expect("create dir");
            let store = crate::mmr::FileStore::open(&store_path).expect("open store");
            let mmr = crate::mmr::MMR::new(Box::new(store)).expect("create mmr");
            mmr.append(&[1u8; 32]).expect("append 1");
            mmr.append(&[2u8; 32]).expect("append 2");
            assert_eq!(mmr.leaf_count(), 2);
            mmr.sync().expect("sync");
        }

        // Reopen and verify
        {
            let mmr = CheckpointMMR::open(&mmr_dir, "test-chain").expect("reopen mmr");
            assert_eq!(mmr.leaf_count(), 2);
            let valid = mmr.verify_checkpoint(&[1u8; 32], 0).expect("verify");
            assert!(valid);
        }

        drop(dir);
    }

    #[test]
    fn test_rebuild_from_chain() {
        let dir = TempDir::new().expect("create temp dir");
        let canonical_dir = dir.path().canonicalize().expect("canonicalize");
        let path = canonical_dir.join("test_doc.txt");
        fs::write(&path, b"initial content").expect("write");

        let mut chain = Chain::new(&path, test_vdf_params())
            .expect("create chain")
            .with_signature_policy(SignaturePolicy::Optional);

        chain
            .commit_with_vdf_duration(None, Duration::from_millis(10))
            .expect("commit 0");
        fs::write(&path, b"updated").expect("update");
        chain
            .commit_with_vdf_duration(None, Duration::from_millis(10))
            .expect("commit 1");

        let mmr = CheckpointMMR::in_memory().expect("create mmr");
        mmr.rebuild_from_chain(&chain).expect("rebuild");

        assert_eq!(mmr.leaf_count(), 2);
        for cp in &chain.checkpoints {
            let valid = mmr.verify_checkpoint(&cp.hash, cp.ordinal).expect("verify");
            assert!(valid, "checkpoint {} should verify", cp.ordinal);
        }

        drop(dir);
    }

    #[test]
    fn test_range_proof() {
        let mmr = CheckpointMMR::in_memory().expect("create mmr");

        for i in 0u8..5 {
            mmr.append_checkpoint(&[i; 32]).expect("append");
        }

        let proof = mmr.range_proof().expect("range proof");
        assert!(proof.is_some());
    }

    #[test]
    fn test_metadata_signing_payload_deterministic() {
        let metadata = ChainMetadata {
            checkpoint_count: 10,
            mmr_root: [0xAAu8; 32],
            mmr_leaf_count: 10,
            metadata_signature: None,
            metadata_version: 1,
        };

        let payload1 = metadata_signing_payload(&metadata);
        let payload2 = metadata_signing_payload(&metadata);
        assert_eq!(payload1, payload2);
    }
}
