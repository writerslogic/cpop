// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Argon2id-based Sequential Work Function (SWF) per draft-condrey-rats-pop.
//!
//! Replaces the legacy SHA-256 chain with a memory-hard Argon2id function.
//! Each iteration produces an output that is accumulated into a Merkle tree.
//! Fiat-Shamir challenge selects sampled indices for compact verification.

use argon2::{Algorithm, Argon2, Params, Version};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

/// Argon2id SWF parameters.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct Argon2SwfParams {
    /// Argon2id time cost (number of passes)
    pub time_cost: u32,
    /// Argon2id memory cost in KiB
    pub memory_cost: u32,
    /// Argon2id parallelism
    pub parallelism: u32,
    /// Number of Argon2id iterations forming the chain
    pub iterations: u64,
}

impl Default for Argon2SwfParams {
    fn default() -> Self {
        Self {
            time_cost: 3,
            memory_cost: 65536, // 64 MiB
            parallelism: 1,
            iterations: 10,
        }
    }
}

/// Test parameters with low memory for fast execution.
pub fn test_params() -> Argon2SwfParams {
    Argon2SwfParams {
        time_cost: 1,
        memory_cost: 1024, // 1 MiB
        parallelism: 1,
        iterations: 3,
    }
}

/// Proof from Argon2id SWF computation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Argon2SwfProof {
    pub input: [u8; 32],
    pub merkle_root: [u8; 32],
    pub params: Argon2SwfParams,
    pub sampled_proofs: Vec<MerkleSampleProof>,
    pub claimed_duration: Duration,
    /// The Fiat-Shamir challenge used to select sample indices.
    pub challenge: [u8; 32],
}

/// A single Merkle inclusion proof for a sampled iteration.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MerkleSampleProof {
    pub leaf_index: u64,
    pub leaf_value: [u8; 32],
    pub sibling_path: Vec<[u8; 32]>,
}

/// Number of Merkle samples selected by Fiat-Shamir challenge.
const SAMPLE_COUNT: usize = 8;

/// Compute an Argon2id SWF proof.
///
/// Runs `params.iterations` sequential Argon2id evaluations, builds a
/// Merkle tree over the outputs, derives a Fiat-Shamir challenge, and
/// returns sampled inclusion proofs.
pub fn compute(input: [u8; 32], params: Argon2SwfParams) -> Result<Argon2SwfProof, String> {
    let argon2 = build_argon2(&params)?;

    let start = Instant::now();
    let mut leaves = Vec::with_capacity(params.iterations as usize);
    let mut current = input;

    for i in 0..params.iterations {
        let mut salt = [0u8; 16];
        salt[..8].copy_from_slice(&i.to_be_bytes());
        salt[8..].copy_from_slice(&current[..8]);

        let mut output = [0u8; 32];
        argon2
            .hash_password_into(&current, &salt, &mut output)
            .map_err(|e| format!("Argon2id iteration {i}: {e}"))?;

        let leaf = Sha256::digest(output).into();
        leaves.push(leaf);
        current = output;
    }

    let merkle_root = build_merkle_root(&leaves);

    // Fiat-Shamir challenge: deterministic sample selection
    let challenge = fiat_shamir_challenge(&merkle_root, &input, params.iterations);

    let indices = select_indices(&challenge, params.iterations, SAMPLE_COUNT);

    // Rebuild tree for proof generation
    let tree = build_merkle_tree(&leaves);
    let sampled_proofs = indices
        .iter()
        .map(|&idx| {
            let path = merkle_proof(&tree, idx as usize, leaves.len());
            MerkleSampleProof {
                leaf_index: idx,
                leaf_value: leaves[idx as usize],
                sibling_path: path,
            }
        })
        .collect();

    Ok(Argon2SwfProof {
        input,
        merkle_root,
        params,
        sampled_proofs,
        claimed_duration: start.elapsed(),
        challenge,
    })
}

/// Verify an Argon2id SWF proof by checking:
/// 1. Fiat-Shamir challenge is correctly derived
/// 2. Each sampled Merkle proof verifies against the root
pub fn verify(proof: &Argon2SwfProof) -> Result<bool, String> {
    // 1. Verify Fiat-Shamir challenge
    let expected_challenge =
        fiat_shamir_challenge(&proof.merkle_root, &proof.input, proof.params.iterations);
    if proof.challenge != expected_challenge {
        return Ok(false);
    }

    // 2. Verify expected sample indices match
    let expected_indices = select_indices(&proof.challenge, proof.params.iterations, SAMPLE_COUNT);
    for (sample, &expected_idx) in proof.sampled_proofs.iter().zip(expected_indices.iter()) {
        if sample.leaf_index != expected_idx {
            return Ok(false);
        }
    }

    // 3. Verify each Merkle inclusion proof
    for sample in &proof.sampled_proofs {
        if !verify_merkle_proof(
            &proof.merkle_root,
            sample.leaf_index as usize,
            &sample.leaf_value,
            &sample.sibling_path,
        ) {
            return Ok(false);
        }
    }

    Ok(true)
}

/// Calibrate Argon2id iterations per second for given cost parameters.
pub fn calibrate(params: &Argon2SwfParams, duration: Duration) -> Result<u64, String> {
    let argon2 = build_argon2(params)?;

    let mut current = [0u8; 32];
    let salt = [0u8; 16];
    let mut iterations = 0u64;
    let start = Instant::now();

    while start.elapsed() < duration {
        let mut output = [0u8; 32];
        argon2
            .hash_password_into(&current, &salt, &mut output)
            .map_err(|e| format!("calibration: {e}"))?;
        current = output;
        iterations += 1;
    }

    let elapsed_secs = start.elapsed().as_secs_f64();
    if elapsed_secs < 0.001 {
        return Err("calibration duration too short".into());
    }

    Ok((iterations as f64 / elapsed_secs) as u64)
}

fn build_argon2(params: &Argon2SwfParams) -> Result<Argon2<'static>, String> {
    let argon2_params = Params::new(
        params.memory_cost,
        params.time_cost,
        params.parallelism,
        Some(32),
    )
    .map_err(|e| format!("invalid Argon2id params: {e}"))?;

    Ok(Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        argon2_params,
    ))
}

// --- Fiat-Shamir ---

/// Derive a Fiat-Shamir challenge from the Merkle root and proof input.
fn fiat_shamir_challenge(merkle_root: &[u8; 32], input: &[u8; 32], iterations: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"witnessd-fiat-shamir-v1");
    hasher.update(merkle_root);
    hasher.update(input);
    hasher.update(iterations.to_be_bytes());
    hasher.finalize().into()
}

/// Select `count` unique leaf indices from the challenge hash.
fn select_indices(challenge: &[u8; 32], num_leaves: u64, count: usize) -> Vec<u64> {
    let mut indices = Vec::with_capacity(count);
    let mut hasher_seed = *challenge;

    while indices.len() < count && indices.len() < num_leaves as usize {
        let idx = u64::from_be_bytes(hasher_seed[..8].try_into().unwrap()) % num_leaves;
        if !indices.contains(&idx) {
            indices.push(idx);
        }
        hasher_seed = Sha256::digest(hasher_seed).into();
    }

    indices
}

// --- Merkle tree ---

fn build_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let tree = build_merkle_tree(leaves);
    tree[1] // root is at index 1 in 1-indexed tree
}

/// Build a complete binary Merkle tree (1-indexed array).
/// tree[1] = root, tree[n..2n] = leaves (right-padded).
fn build_merkle_tree(leaves: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let n = leaves.len().next_power_of_two();
    let mut tree = vec![[0u8; 32]; 2 * n];

    // Place leaves
    for (i, leaf) in leaves.iter().enumerate() {
        tree[n + i] = *leaf;
    }
    // Pad remaining leaves with last leaf (or zeros)
    if let Some(last) = leaves.last() {
        for i in leaves.len()..n {
            tree[n + i] = *last;
        }
    }

    // Build up
    for i in (1..n).rev() {
        let mut hasher = Sha256::new();
        hasher.update(tree[2 * i]);
        hasher.update(tree[2 * i + 1]);
        tree[i] = hasher.finalize().into();
    }

    tree
}

fn merkle_proof(tree: &[[u8; 32]], leaf_idx: usize, num_leaves: usize) -> Vec<[u8; 32]> {
    let n = num_leaves.next_power_of_two();
    let mut path = Vec::new();
    let mut idx = n + leaf_idx;

    while idx > 1 {
        let sibling = idx ^ 1;
        path.push(tree[sibling]);
        idx /= 2;
    }

    path
}

fn verify_merkle_proof(
    root: &[u8; 32],
    leaf_idx: usize,
    leaf_value: &[u8; 32],
    sibling_path: &[[u8; 32]],
) -> bool {
    let mut current = *leaf_value;
    let mut idx = leaf_idx;

    for sibling in sibling_path {
        let mut hasher = Sha256::new();
        if idx % 2 == 0 {
            hasher.update(current);
            hasher.update(sibling);
        } else {
            hasher.update(sibling);
            hasher.update(current);
        }
        current = hasher.finalize().into();
        idx /= 2;
    }

    current == *root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2_swf_compute_verify() {
        let input = [42u8; 32];
        let params = test_params();

        let proof = compute(input, params).expect("compute");
        assert_eq!(proof.input, input);
        assert_ne!(proof.merkle_root, [0u8; 32]);
        assert!(!proof.sampled_proofs.is_empty());

        let valid = verify(&proof).expect("verify");
        assert!(valid, "proof should verify");
    }

    #[test]
    fn test_deterministic_fiat_shamir() {
        let root = [1u8; 32];
        let input = [2u8; 32];
        let c1 = fiat_shamir_challenge(&root, &input, 10);
        let c2 = fiat_shamir_challenge(&root, &input, 10);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_fiat_shamir_sensitive_to_root() {
        let input = [2u8; 32];
        let c1 = fiat_shamir_challenge(&[1u8; 32], &input, 10);
        let c2 = fiat_shamir_challenge(&[3u8; 32], &input, 10);
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_tampered_leaf_rejected() {
        let input = [42u8; 32];
        let params = test_params();

        let mut proof = compute(input, params).expect("compute");
        if let Some(sample) = proof.sampled_proofs.first_mut() {
            sample.leaf_value[0] ^= 0xFF;
        }

        let valid = verify(&proof).expect("verify");
        assert!(!valid, "tampered proof should not verify");
    }

    #[test]
    fn test_tampered_challenge_rejected() {
        let input = [42u8; 32];
        let params = test_params();

        let mut proof = compute(input, params).expect("compute");
        proof.challenge[0] ^= 0xFF;

        let valid = verify(&proof).expect("verify");
        assert!(!valid, "tampered challenge should not verify");
    }

    #[test]
    fn test_merkle_tree_roundtrip() {
        let leaves: Vec<[u8; 32]> = (0..4u8).map(|i| [i; 32]).collect();
        let root = build_merkle_root(&leaves);
        let tree = build_merkle_tree(&leaves);

        for (i, leaf) in leaves.iter().enumerate() {
            let path = merkle_proof(&tree, i, leaves.len());
            assert!(
                verify_merkle_proof(&root, i, leaf, &path),
                "proof for leaf {i} should verify"
            );
        }
    }

    #[test]
    fn test_different_inputs_different_roots() {
        let params = test_params();
        let p1 = compute([1u8; 32], params).expect("compute");
        let p2 = compute([2u8; 32], params).expect("compute");
        assert_ne!(p1.merkle_root, p2.merkle_root);
    }

    #[test]
    fn test_select_indices_unique() {
        let challenge = [0xAB; 32];
        let indices = select_indices(&challenge, 100, 8);
        let unique: std::collections::HashSet<_> = indices.iter().collect();
        assert_eq!(unique.len(), indices.len(), "indices should be unique");
    }

    #[test]
    fn test_select_indices_bounded() {
        let challenge = [0xAB; 32];
        let indices = select_indices(&challenge, 5, 8);
        assert!(indices.len() <= 5, "can't have more indices than leaves");
        for &idx in &indices {
            assert!(idx < 5, "index should be < num_leaves");
        }
    }
}
