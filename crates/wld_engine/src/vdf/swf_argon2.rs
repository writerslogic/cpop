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
    /// CORE profile defaults per draft-condrey-rats-pop §mandatory-swf-params.
    fn default() -> Self {
        Self {
            time_cost: 1,
            memory_cost: 65536, // 64 MiB
            parallelism: 1,
            iterations: 90,
        }
    }
}

/// ENHANCED profile per draft-condrey-rats-pop §7.5 table.
pub fn enhanced_params() -> Argon2SwfParams {
    Argon2SwfParams {
        time_cost: 1,
        memory_cost: 65536, // 64 MiB
        parallelism: 1,
        iterations: 150,
    }
}

/// MAXIMUM profile per draft-condrey-rats-pop §7.5 table.
pub fn maximum_params() -> Argon2SwfParams {
    Argon2SwfParams {
        time_cost: 1,
        memory_cost: 65536, // 64 MiB
        parallelism: 1,
        iterations: 210,
    }
}

/// Select SWF parameters for a given content tier (1=CORE, 2=ENHANCED, 3=MAXIMUM).
pub fn params_for_tier(content_tier: u8) -> Argon2SwfParams {
    match content_tier {
        3 => maximum_params(),
        2 => enhanced_params(),
        _ => Argon2SwfParams::default(), // CORE
    }
}

/// Low memory for fast test execution.
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
    pub challenge: [u8; 32],
}

/// Merkle inclusion proof for a single sampled SWF iteration.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MerkleSampleProof {
    pub leaf_index: u64,
    pub leaf_value: [u8; 32],
    pub sibling_path: Vec<[u8; 32]>,
}

/// Default Merkle samples for CORE tier (k=20).
/// ENHANCED=50, MAXIMUM=100 per draft-condrey-rats-pop §4.4.
const DEFAULT_SAMPLE_COUNT: usize = 20;

/// Compute an Argon2id SWF proof.
///
/// Runs `params.iterations` sequential Argon2id evaluations, builds a
/// Merkle tree over the outputs, derives a Fiat-Shamir challenge, and
/// returns sampled inclusion proofs.
pub fn compute(input: [u8; 32], params: Argon2SwfParams) -> Result<Argon2SwfProof, String> {
    compute_with_samples(input, params, DEFAULT_SAMPLE_COUNT)
}

/// Compute with explicit sample count (k=20 CORE, k=50 ENHANCED, k=100 MAXIMUM).
pub fn compute_with_samples(
    input: [u8; 32],
    params: Argon2SwfParams,
    sample_count: usize,
) -> Result<Argon2SwfProof, String> {
    let argon2 = build_argon2(&params)?;

    let start = Instant::now();
    let mut leaves = Vec::with_capacity(params.iterations as usize);
    let mut current = input;

    for i in 0..params.iterations {
        // Salt per draft-condrey-rats-pop §4.2:
        //   state_0:   salt = H(0x00 || "PoP-salt-v1" || seed)
        //   state_i:   salt = H(0x01 || "PoP-salt-v1" || I2OSP(i, 4))
        let salt_hash = if i == 0 {
            let mut h = Sha256::new();
            h.update([0x00u8]);
            h.update(b"PoP-salt-v1");
            h.update(input);
            h.finalize()
        } else {
            let mut h = Sha256::new();
            h.update([0x01u8]);
            h.update(b"PoP-salt-v1");
            h.update((i as u32).to_be_bytes()); // I2OSP(i, 4)
            h.finalize()
        };
        let salt = salt_hash.as_slice(); // §7.1: full 32-byte SHA-256 output

        let mut output = [0u8; 32];
        argon2
            .hash_password_into(&current, salt, &mut output)
            .map_err(|e| format!("Argon2id iteration {i}: {e}"))?;

        // RFC 6962 leaf: H(0x00 || data)
        let leaf = {
            let mut h = Sha256::new();
            h.update([0x00u8]);
            h.update(output);
            h.finalize().into()
        };
        leaves.push(leaf);
        current = output;
    }

    let merkle_root = build_merkle_root(&leaves, params.iterations);

    let challenge = fiat_shamir_challenge(&merkle_root, &input, &params);

    let indices = select_indices(&challenge, params.iterations, sample_count);

    let tree = build_merkle_tree(&leaves, params.iterations);
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
    verify_with_samples(proof, proof.sampled_proofs.len())
}

/// Verify with explicit expected sample count.
pub fn verify_with_samples(proof: &Argon2SwfProof, sample_count: usize) -> Result<bool, String> {
    let expected_challenge = fiat_shamir_challenge(&proof.merkle_root, &proof.input, &proof.params);
    if proof.challenge != expected_challenge {
        return Ok(false);
    }

    let expected_indices = select_indices(&proof.challenge, proof.params.iterations, sample_count);
    for (sample, &expected_idx) in proof.sampled_proofs.iter().zip(expected_indices.iter()) {
        if sample.leaf_index != expected_idx {
            return Ok(false);
        }
    }

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

/// Measure Argon2id iterations per second.
pub fn calibrate(params: &Argon2SwfParams, duration: Duration) -> Result<u64, String> {
    let argon2 = build_argon2(params)?;

    let mut current = [0u8; 32];
    let salt = [0u8; 32];
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

/// Derive Fiat-Shamir sample seed per draft-condrey-rats-pop §7.3:
///   H("PoP-Fiat-Shamir-v1" || I2OSP(proof_algorithm, 2) ||
///     CBOR-encode(proof_params) || process_proof_input || merkle_root)
fn fiat_shamir_challenge(
    merkle_root: &[u8; 32],
    input: &[u8; 32],
    params: &Argon2SwfParams,
) -> [u8; 32] {
    /// proof_algorithm = 20 (SwfArgon2id) per §7.3
    const PROOF_ALGORITHM: u16 = 20;
    let params_map = ciborium::Value::Map(vec![
        (1.into(), ciborium::Value::Integer(params.time_cost.into())),
        (
            2.into(),
            ciborium::Value::Integer(params.memory_cost.into()),
        ),
        (
            3.into(),
            ciborium::Value::Integer(params.parallelism.into()),
        ),
        (4.into(), ciborium::Value::Integer(params.iterations.into())),
    ]);
    let mut params_cbor = Vec::new();
    ciborium::into_writer(&params_map, &mut params_cbor).expect("CBOR encoding proof params");

    let mut hasher = Sha256::new();
    hasher.update(b"PoP-Fiat-Shamir-v1");
    hasher.update(PROOF_ALGORITHM.to_be_bytes());
    hasher.update(&params_cbor);
    hasher.update(input);
    hasher.update(merkle_root);
    hasher.finalize().into()
}

/// Select `count` unique leaf indices via HKDF-Expand per §7.3:
///   okm_j = HKDF-Expand(sample_seed, I2OSP(j, 4), 4)
///   index_j = OS2IP(okm_j) mod (steps + 1)
fn select_indices(sample_seed: &[u8; 32], num_leaves: u64, count: usize) -> Vec<u64> {
    use hkdf::Hkdf;

    use std::collections::HashSet;

    let hk = Hkdf::<Sha256>::from_prk(sample_seed).expect("sample seed is valid PRK length");
    let mut indices = Vec::with_capacity(count);
    let mut seen = HashSet::with_capacity(count);
    let mut j: u32 = 0;

    // Rejection sampling to eliminate modulo bias
    let n = num_leaves.min(u32::MAX as u64) as u32;
    let reject_above = u32::MAX - (u32::MAX % n);

    while indices.len() < count && indices.len() < num_leaves as usize {
        let mut okm = [0u8; 4];
        hk.expand(&j.to_be_bytes(), &mut okm)
            .expect("4 bytes is valid HKDF-Expand length");
        j += 1;
        let raw = u32::from_be_bytes(okm);
        if raw >= reject_above {
            continue;
        }
        let idx = (raw % n) as u64;
        if seen.insert(idx) {
            indices.push(idx);
        }
    }

    indices
}

/// Sentinel padding per §4.3: H(0x02 || I2OSP(steps + 1, 4))
fn padding_value(steps: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x02u8]);
    h.update(((steps + 1) as u32).to_be_bytes());
    h.finalize().into()
}

fn build_merkle_root(leaves: &[[u8; 32]], steps: u64) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let tree = build_merkle_tree(leaves, steps);
    tree[1]
}

/// 1-indexed Merkle tree with RFC 6962 domain separation.
/// tree[1] = root, tree[n..2n] = leaves.
fn build_merkle_tree(leaves: &[[u8; 32]], steps: u64) -> Vec<[u8; 32]> {
    let n = leaves.len().next_power_of_two();
    let mut tree = vec![[0u8; 32]; 2 * n];

    for (i, leaf) in leaves.iter().enumerate() {
        tree[n + i] = *leaf;
    }
    let pad = padding_value(steps);
    for i in leaves.len()..n {
        tree[n + i] = pad;
    }

    for i in (1..n).rev() {
        let mut hasher = Sha256::new();
        hasher.update([0x01u8]);
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
        // RFC 6962 internal node: H(0x01 || left || right)
        let mut hasher = Sha256::new();
        hasher.update([0x01u8]);
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
        let params = test_params();
        let c1 = fiat_shamir_challenge(&root, &input, &params);
        let c2 = fiat_shamir_challenge(&root, &input, &params);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_fiat_shamir_sensitive_to_root() {
        let input = [2u8; 32];
        let params = test_params();
        let c1 = fiat_shamir_challenge(&[1u8; 32], &input, &params);
        let c2 = fiat_shamir_challenge(&[3u8; 32], &input, &params);
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
        let steps = 4u64;
        let root = build_merkle_root(&leaves, steps);
        let tree = build_merkle_tree(&leaves, steps);

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
    fn test_core_default_params_match_spec() {
        let p = Argon2SwfParams::default();
        assert_eq!(p.time_cost, 1);
        assert_eq!(p.memory_cost, 65536);
        assert_eq!(p.parallelism, 1);
        assert_eq!(p.iterations, 90);
    }

    #[test]
    fn test_enhanced_params_match_spec() {
        let p = enhanced_params();
        assert_eq!(p.time_cost, 1);
        assert_eq!(p.memory_cost, 65536);
        assert_eq!(p.parallelism, 1);
        assert_eq!(p.iterations, 150);
    }

    #[test]
    fn test_maximum_params_match_spec() {
        let p = maximum_params();
        assert_eq!(p.time_cost, 1);
        assert_eq!(p.memory_cost, 65536);
        assert_eq!(p.parallelism, 1);
        assert_eq!(p.iterations, 210);
    }

    #[test]
    fn test_params_for_tier_selects_correctly() {
        assert_eq!(params_for_tier(1).iterations, 90);
        assert_eq!(params_for_tier(2).iterations, 150);
        assert_eq!(params_for_tier(3).iterations, 210);
        assert_eq!(params_for_tier(0).iterations, 90);
        assert_eq!(params_for_tier(255).iterations, 90);
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
