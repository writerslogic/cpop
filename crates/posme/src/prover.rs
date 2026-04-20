// SPDX-License-Identifier: Apache-2.0

//! PoSME proof generation: execute K steps, derive challenges, build proof.
//!
//! Memory strategy: the initial execution pass stores only lightweight metadata
//! per step (32 bytes root + 32 bytes transcript + 4 bytes write_addr = 68 bytes).
//! For K=16M steps that's ~1 GB of metadata plus the arena itself (~256 MiB-1 GiB).
//! Challenged steps are replayed individually to regenerate full witness data.

use std::time::Instant;

use crate::block::LAMBDA;
use crate::error::Result;
use crate::hash::{i2osp, posme_hash, DST_FIAT_SHAMIR};
use crate::init::initialize;
use crate::merkle::MerkleTree;
use crate::params::PosmeParams;
use crate::proof::*;
use crate::step::{posme_step, StepLog};

/// Root chain Merkle tree: commits to all K+1 arena roots.
struct RootChain {
    nodes: Vec<[u8; LAMBDA]>,
    n: usize,
}

impl RootChain {
    fn build(roots: &[[u8; LAMBDA]]) -> Self {
        let n = roots.len().next_power_of_two();
        let mut nodes = vec![[0u8; LAMBDA]; 2 * n];
        for (i, root) in roots.iter().enumerate() {
            nodes[n + i] = *root;
        }
        for i in (1..n).rev() {
            nodes[i] = posme_hash(&[&nodes[2 * i], &nodes[2 * i + 1]]);
        }
        Self { nodes, n }
    }

    fn root(&self) -> [u8; LAMBDA] {
        self.nodes[1]
    }

    fn prove(&self, index: usize) -> Vec<[u8; LAMBDA]> {
        let depth = (self.n as u32).trailing_zeros() as usize;
        let mut path = Vec::with_capacity(depth);
        let mut pos = self.n + index;
        for _ in 0..depth {
            path.push(self.nodes[pos ^ 1]);
            pos /= 2;
        }
        path
    }
}

/// Derive Q unique Fiat-Shamir challenge step indices from (T_K, C_roots, params).
///
/// The params are bound into sigma so that a proof generated at one difficulty
/// tier cannot be replayed as a proof for a different tier.
pub(crate) fn derive_challenges(
    final_transcript: &[u8; LAMBDA],
    root_chain_commitment: &[u8; LAMBDA],
    params: &PosmeParams,
) -> Vec<u32> {
    let param_bytes = params.to_challenge_bytes();
    let sigma = posme_hash(&[DST_FIAT_SHAMIR, final_transcript, root_chain_commitment, &param_bytes]);
    let q = params.challenges;
    let k = params.total_steps;
    let mut seen = std::collections::BTreeSet::new();
    let mut challenges = Vec::with_capacity(q as usize);
    let mut counter = 0u32;
    while challenges.len() < q as usize {
        let h = posme_hash(&[&sigma, &i2osp(counter)]);
        let val = u32::from_be_bytes([h[0], h[1], h[2], h[3]]) % k;
        let step = val + 1;
        if seen.insert(step) {
            challenges.push(step);
        }
        counter += 1;
    }
    challenges
}

/// Track which step last wrote each block.
struct WriteIndex {
    last_writer: Vec<u32>,
}

impl WriteIndex {
    fn new(n: u32) -> Self {
        Self { last_writer: vec![0; n as usize] }
    }

    fn record(&mut self, addr: u32, step: u32) {
        self.last_writer[addr as usize] = step;
    }

    fn last_writer_of(&self, addr: u32) -> u32 {
        self.last_writer[addr as usize]
    }
}

struct ProofBuildCtx<'a> {
    root_chain: &'a RootChain,
    write_index: &'a WriteIndex,
    init_tree: &'a MerkleTree,
}

fn build_step_proof(
    log: &StepLog,
    tree_before: &MerkleTree,
    cursor_in: [u8; LAMBDA],
    ctx: &ProofBuildCtx<'_>,
    depth: u8,
) -> StepProof {
    let rc_path_before = ctx.root_chain.prove(log.step_id as usize - 1);
    let rc_path_after = ctx.root_chain.prove(log.step_id as usize);

    let reads: Vec<ReadWitness> = log.read_addrs.iter().zip(&log.read_blocks).map(|(&addr, &block)| {
        ReadWitness {
            address: addr,
            block,
            merkle_path: tree_before.prove(addr),
        }
    }).collect();

    let write = WriteWitness {
        address: log.write_addr,
        old_block: log.old_block,
        new_block: log.new_block,
        merkle_path: tree_before.prove(log.write_addr),
    };

    let _depth = depth; // reserved for future recursive provenance replay
    let writers: Vec<WriterProof> = log.read_addrs.iter().map(|&addr| {
        let ws = ctx.write_index.last_writer_of(addr);
        if ws == 0 {
            WriterProof {
                proof_type: 0,
                writer_step_id: 0,
                step_witness: None,
                init_merkle_path: Some(ctx.init_tree.prove(addr)),
            }
        } else {
            WriterProof {
                proof_type: 1,
                writer_step_id: ws,
                step_witness: None,
                init_merkle_path: None,
            }
        }
    }).collect();

    StepProof {
        step_id: log.step_id,
        cursor_in,
        cursor_out: log.cursor,
        root_before: log.root_before,
        root_after: log.root_after,
        root_chain_paths: (rc_path_before, rc_path_after),
        reads,
        write,
        writers,
    }
}

/// Generate init block witnesses for seed binding.
/// Uses Fiat-Shamir to select INIT_WITNESS_COUNT block indices deterministically.
fn generate_init_witnesses(
    seed: &[u8],
    init_tree: &MerkleTree,
    arena: &[crate::block::Block],
    n: u32,
) -> Vec<InitWitness> {
    let root = init_tree.root();
    let sigma = posme_hash(&[b"PoSME-init-witness-v1", seed, &root]);
    let mut witnesses = Vec::with_capacity(INIT_WITNESS_COUNT);
    let mut counter = 0u32;
    while witnesses.len() < INIT_WITNESS_COUNT {
        let h = posme_hash(&[&sigma, &i2osp(counter)]);
        let idx = u32::from_be_bytes([h[0], h[1], h[2], h[3]]) % n;
        counter += 1;
        if witnesses.iter().any(|w: &InitWitness| w.index == idx) {
            continue;
        }
        witnesses.push(InitWitness {
            index: idx,
            block: arena[idx as usize],
            merkle_path: init_tree.prove(idx),
        });
    }
    witnesses
}

/// Execute the full PoSME computation and generate a proof.
///
/// Two-pass strategy:
/// 1. Execute all K steps, storing only per-step metadata (transcript + write_addr).
/// 2. Sort challenged steps, replay from init up to each one to get correct Merkle paths.
pub fn execute(seed: &[u8], params: &PosmeParams) -> Result<PosmeProof> {
    params.validate()?;

    let n = params.arena_blocks;
    let k = params.total_steps;
    let d = params.reads_per_step;

    // Phase 1: Initialize arena and snapshot the init tree.
    let (mut arena, mut tree, root_0, t_0) = initialize(seed, n);
    let init_tree = MerkleTree::build(&arena);
    let init_witnesses = generate_init_witnesses(seed, &init_tree, &arena, n);

    // Phase 2: Execute K steps, storing only roots.
    // write_index is not needed here -- rebuilt during replay.
    let mut transcript = t_0;
    let mut roots: Vec<[u8; LAMBDA]> = Vec::with_capacity(k as usize + 1);
    roots.push(root_0);

    let start = Instant::now();
    for t in 1..=k {
        let log = posme_step(&mut arena, &mut tree, &transcript, t, d);
        transcript = log.transcript;
        roots.push(log.root_after);
    }
    let elapsed = start.elapsed();
    let final_transcript = transcript;

    // Phase 3: Build root chain commitment.
    let root_chain = RootChain::build(&roots);
    let root_chain_commitment = root_chain.root();

    // Phase 4: Derive Fiat-Shamir challenges.
    let challenges = derive_challenges(
        &final_transcript,
        &root_chain_commitment,
        params,
    );

    // Phase 5: Replay challenged steps to build proofs.
    // Sort challenges so we replay forward once, stopping at each.
    // cursor_in for each step is known from the replay transcript.
    let mut sorted_challenges: Vec<(usize, u32)> = challenges.iter().enumerate().map(|(i, &s)| (i, s)).collect();
    sorted_challenges.sort_by_key(|&(_, step)| step);

    let mut step_proofs: Vec<(usize, StepProof)> = Vec::with_capacity(challenges.len());

    let (mut replay_arena, mut replay_tree, _, mut replay_t) = initialize(seed, n);
    let mut replay_wi = WriteIndex::new(n);
    let mut current_step = 0u32;

    for &(orig_idx, target_step) in &sorted_challenges {
        while current_step < target_step - 1 {
            current_step += 1;
            let log = posme_step(&mut replay_arena, &mut replay_tree, &replay_t, current_step, d);
            replay_t = log.transcript;
            replay_wi.record(log.write_addr, current_step);
        }

        let tree_before = replay_tree.clone();
        let cursor_in = replay_t; // transcript before this step = cursor_in

        current_step += 1;
        debug_assert_eq!(current_step, target_step);
        let log = posme_step(&mut replay_arena, &mut replay_tree, &replay_t, current_step, d);
        replay_t = log.transcript;
        replay_wi.record(log.write_addr, current_step);

        let build_ctx = ProofBuildCtx {
            root_chain: &root_chain,
            write_index: &replay_wi,
            init_tree: &init_tree,
        };
        let sp = build_step_proof(&log, &tree_before, cursor_in, &build_ctx, params.recursion_depth);
        step_proofs.push((orig_idx, sp));
    }

    // Restore original challenge order.
    step_proofs.sort_by_key(|&(orig_idx, _)| orig_idx);
    let challenged_steps: Vec<StepProof> = step_proofs.into_iter().map(|(_, sp)| sp).collect();

    let root_0_path = root_chain.prove(0);

    Ok(PosmeProof {
        params: *params,
        final_transcript,
        root_chain_commitment,
        root_0,
        root_0_path,
        init_witnesses,
        challenged_steps,
        claimed_duration: elapsed,
        proof_algorithm: PROOF_ALGORITHM_POSME,
        entanglement_points: Vec::new(),
    })
}

const ENTANGLE_DST: &[u8] = b"PoSME-entangle-v1";

/// Execute PoSME with jitter entanglement (algorithm 31).
///
/// At evenly-spaced intervals during execution, a jitter sample hash is mixed
/// into the transcript chain: `T_t = H("PoSME-entangle-v1" || T_t || jitter_hash)`.
/// The injection points and hashes are recorded in the proof for verification.
///
/// `jitter_samples`: one or more 32-byte jitter hashes collected during the session.
/// Injection occurs every `K / jitter_samples.len()` steps.
pub fn execute_entangled(
    seed: &[u8],
    params: &PosmeParams,
    jitter_samples: &[[u8; 32]],
) -> Result<PosmeProof> {
    if jitter_samples.is_empty() {
        return execute(seed, params);
    }
    params.validate()?;

    let n = params.arena_blocks;
    let k = params.total_steps;
    let d = params.reads_per_step;
    let interval = (k as usize) / jitter_samples.len();

    let (mut arena, mut tree, root_0, t_0) = initialize(seed, n);
    let init_tree = MerkleTree::build(&arena);
    let init_witnesses = generate_init_witnesses(seed, &init_tree, &arena, n);

    let mut transcript = t_0;
    let mut roots: Vec<[u8; LAMBDA]> = Vec::with_capacity(k as usize + 1);
    let mut entanglement_points: Vec<(u32, [u8; 32])> = Vec::new();
    roots.push(root_0);

    let start = Instant::now();
    let mut jitter_idx = 0usize;
    for t in 1..=k {
        let log = posme_step(&mut arena, &mut tree, &transcript, t, d);
        transcript = log.transcript;

        if interval > 0 && (t as usize).is_multiple_of(interval) && jitter_idx < jitter_samples.len() {
            let jh = jitter_samples[jitter_idx];
            transcript = posme_hash(&[ENTANGLE_DST, &transcript, &jh]);
            entanglement_points.push((t, jh));
            jitter_idx += 1;
        }

        roots.push(log.root_after);
    }
    let elapsed = start.elapsed();
    let final_transcript = transcript;

    let root_chain = RootChain::build(&roots);
    let root_chain_commitment = root_chain.root();

    let challenges = derive_challenges(
        &final_transcript,
        &root_chain_commitment,
        params,
    );

    let mut sorted_challenges: Vec<(usize, u32)> = challenges.iter().enumerate().map(|(i, &s)| (i, s)).collect();
    sorted_challenges.sort_by_key(|&(_, step)| step);

    let mut step_proofs: Vec<(usize, StepProof)> = Vec::with_capacity(challenges.len());
    let (mut replay_arena, mut replay_tree, _, mut replay_t) = initialize(seed, n);
    let mut replay_wi = WriteIndex::new(n);
    let mut current_step = 0u32;
    let mut replay_jitter_idx = 0usize;

    for &(orig_idx, target_step) in &sorted_challenges {
        while current_step < target_step - 1 {
            current_step += 1;
            let log = posme_step(&mut replay_arena, &mut replay_tree, &replay_t, current_step, d);
            replay_t = log.transcript;
            if interval > 0 && (current_step as usize).is_multiple_of(interval) && replay_jitter_idx < jitter_samples.len() {
                replay_t = posme_hash(&[ENTANGLE_DST, &replay_t, &jitter_samples[replay_jitter_idx]]);
                replay_jitter_idx += 1;
            }
            replay_wi.record(log.write_addr, current_step);
        }

        let tree_before = replay_tree.clone();
        let cursor_in = replay_t;

        current_step += 1;
        let log = posme_step(&mut replay_arena, &mut replay_tree, &replay_t, current_step, d);
        replay_t = log.transcript;
        if interval > 0 && (current_step as usize).is_multiple_of(interval) && replay_jitter_idx < jitter_samples.len() {
            replay_t = posme_hash(&[ENTANGLE_DST, &replay_t, &jitter_samples[replay_jitter_idx]]);
            replay_jitter_idx += 1;
        }
        replay_wi.record(log.write_addr, current_step);

        let build_ctx = ProofBuildCtx {
            root_chain: &root_chain,
            write_index: &replay_wi,
            init_tree: &init_tree,
        };
        let sp = build_step_proof(&log, &tree_before, cursor_in, &build_ctx, params.recursion_depth);
        step_proofs.push((orig_idx, sp));
    }

    step_proofs.sort_by_key(|&(orig_idx, _)| orig_idx);
    let challenged_steps: Vec<StepProof> = step_proofs.into_iter().map(|(_, sp)| sp).collect();
    let root_0_path = root_chain.prove(0);

    Ok(PosmeProof {
        params: *params,
        final_transcript,
        root_chain_commitment,
        root_0,
        root_0_path,
        init_witnesses,
        challenged_steps,
        claimed_duration: elapsed,
        proof_algorithm: PROOF_ALGORITHM_POSME_ENTANGLED,
        entanglement_points,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_params() -> PosmeParams {
        PosmeParams::test()
    }

    #[test]
    fn execute_produces_proof() {
        let proof = execute(b"test-seed", &test_params()).unwrap();
        assert_eq!(proof.params, test_params());
        assert_eq!(proof.challenged_steps.len(), test_params().challenges as usize);
        assert_eq!(proof.proof_algorithm, PROOF_ALGORITHM_POSME);
        assert_eq!(proof.init_witnesses.len(), INIT_WITNESS_COUNT);
    }

    #[test]
    fn execute_deterministic() {
        let p1 = execute(b"det-seed", &test_params()).unwrap();
        let p2 = execute(b"det-seed", &test_params()).unwrap();
        assert_eq!(p1.final_transcript, p2.final_transcript);
        assert_eq!(p1.root_chain_commitment, p2.root_chain_commitment);
        assert_eq!(p1.init_witnesses.len(), p2.init_witnesses.len());
        for (a, b) in p1.init_witnesses.iter().zip(&p2.init_witnesses) {
            assert_eq!(a.index, b.index);
            assert_eq!(a.block, b.block);
        }
    }

    #[test]
    fn execute_different_seeds_differ() {
        let p1 = execute(b"seed-a", &test_params()).unwrap();
        let p2 = execute(b"seed-b", &test_params()).unwrap();
        assert_ne!(p1.final_transcript, p2.final_transcript);
    }

    #[test]
    fn challenges_are_unique() {
        let proof = execute(b"test", &test_params()).unwrap();
        let step_ids: Vec<u32> = proof.challenged_steps.iter().map(|s| s.step_id).collect();
        let mut deduped = step_ids.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(step_ids.len(), deduped.len());
    }

    #[test]
    fn challenges_in_range() {
        let params = test_params();
        let proof = execute(b"test", &params).unwrap();
        for sp in &proof.challenged_steps {
            assert!(sp.step_id >= 1 && sp.step_id <= params.total_steps);
        }
    }

    #[test]
    fn init_witnesses_in_range() {
        let params = test_params();
        let proof = execute(b"test", &params).unwrap();
        for w in &proof.init_witnesses {
            assert!(w.index < params.arena_blocks);
        }
    }

    #[test]
    fn entangled_produces_proof() {
        let jitter = [[0xAAu8; 32], [0xBBu8; 32], [0xCCu8; 32]];
        let proof = execute_entangled(b"entangle-test", &test_params(), &jitter).unwrap();
        assert_eq!(proof.proof_algorithm, PROOF_ALGORITHM_POSME_ENTANGLED);
        assert_eq!(proof.entanglement_points.len(), 3);
    }

    #[test]
    fn entangled_differs_from_standard() {
        let seed = b"compare";
        let standard = execute(seed, &test_params()).unwrap();
        let jitter = [[0x11u8; 32]];
        let entangled = execute_entangled(seed, &test_params(), &jitter).unwrap();
        assert_ne!(standard.final_transcript, entangled.final_transcript);
    }

    #[test]
    fn entangled_deterministic() {
        let jitter = [[0x42u8; 32], [0x43u8; 32]];
        let p1 = execute_entangled(b"det", &test_params(), &jitter).unwrap();
        let p2 = execute_entangled(b"det", &test_params(), &jitter).unwrap();
        assert_eq!(p1.final_transcript, p2.final_transcript);
        assert_eq!(p1.entanglement_points, p2.entanglement_points);
    }

    #[test]
    fn empty_jitter_falls_back_to_standard() {
        let standard = execute(b"fb", &test_params()).unwrap();
        let entangled = execute_entangled(b"fb", &test_params(), &[]).unwrap();
        assert_eq!(standard.final_transcript, entangled.final_transcript);
        assert_eq!(entangled.proof_algorithm, PROOF_ALGORITHM_POSME);
    }
}
