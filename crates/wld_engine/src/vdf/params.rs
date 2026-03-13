// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::vdf::VdfProof;
use crate::MutexRecover;

/// VDF/SWF computation parameters: iteration rate and bounds.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct Parameters {
    pub iterations_per_second: u64,
    pub min_iterations: u64,
    pub max_iterations: u64,
}

/// Return default VDF parameters (1M iter/s, 100K min, 3.6B max).
pub fn default_parameters() -> Parameters {
    Parameters {
        iterations_per_second: 1_000_000,
        min_iterations: 100_000,
        max_iterations: 3_600_000_000,
    }
}

/// Benchmark SHA-256 hash rate for the given duration, returning calibrated parameters.
pub fn calibrate(duration: Duration) -> Result<Parameters, String> {
    if duration < Duration::from_millis(100) {
        return Err("calibration duration too short".to_string());
    }

    let mut hash: [u8; 32] = Sha256::digest(b"witnessd-calibration-input-v1").into();

    let mut iterations = 0u64;
    let start = Instant::now();
    let deadline = start + duration;

    while Instant::now() < deadline {
        for _ in 0..1000 {
            hash = Sha256::digest(hash).into();
            iterations += 1;
        }
    }

    let elapsed = start.elapsed().as_secs_f64();
    let iterations_per_second = (iterations as f64 / elapsed) as u64;

    Ok(Parameters {
        iterations_per_second,
        min_iterations: iterations_per_second / 10, // ~0.1 seconds of work
        max_iterations: iterations_per_second * 3600, // ~1 hour maximum
    })
}

/// Compute a VDF proof targeting the given wall-clock duration.
pub fn compute(
    input: [u8; 32],
    duration: Duration,
    params: Parameters,
) -> Result<VdfProof, String> {
    VdfProof::compute(input, duration, params)
}

/// Compute a VDF proof with an exact iteration count.
pub fn compute_iterations(input: [u8; 32], iterations: u64) -> VdfProof {
    VdfProof::compute_iterations(input, iterations)
}

/// Verify a VDF proof by recomputing the hash chain.
pub fn verify(proof: &VdfProof) -> bool {
    proof.verify()
}

/// Verify a VDF proof, reporting progress via callback.
pub fn verify_with_progress<F>(proof: &VdfProof, progress: Option<F>) -> bool
where
    F: FnMut(f64),
{
    proof.verify_with_progress(progress)
}

/// Derive VDF input from content hash, previous hash, and ordinal.
pub fn chain_input(content_hash: [u8; 32], previous_hash: [u8; 32], ordinal: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"witnessd-vdf-v1");
    hasher.update(content_hash);
    hasher.update(previous_hash);
    hasher.update(ordinal.to_be_bytes());
    hasher.finalize().into()
}

/// Compute VDF input with full entanglement for WAR/1.1 chained evidence.
///
/// The entangled input combines:
/// - Previous checkpoint's VDF output (temporal chain)
/// - Current jitter evidence hash (behavioral entropy)
/// - Current document state hash (content binding)
/// - Ordinal (sequence position)
///
/// This creates a cryptographic entanglement where each checkpoint's VDF
/// depends on the previous checkpoint's computed output, making the chain
/// impossible to precompute and requiring genuine sequential authorship.
pub fn chain_input_entangled(
    previous_vdf_output: [u8; 32],
    jitter_hash: [u8; 32],
    content_hash: [u8; 32],
    ordinal: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"witnessd-vdf-entangled-v1");
    hasher.update(previous_vdf_output);
    hasher.update(jitter_hash);
    hasher.update(content_hash);
    hasher.update(ordinal.to_be_bytes());
    hasher.finalize().into()
}

// --- Spec-conformant SWF seed derivation (draft-condrey-rats-pop) ---

/// Domain separation tag for SWF seed derivation per spec.
const SWF_SEED_DST: &[u8] = b"PoP-SWF-Seed-v1";

/// Genesis (first-checkpoint) SWF seed per spec:
/// `H("PoP-SWF-Seed-v1" || CBOR-encode(document-ref) || initial-jitter-sample)`.
///
/// When no jitter sample is available (CORE tier), `jitter_sample` should be
/// a 32-byte local nonce.
pub fn swf_seed_genesis(doc_ref_cbor: &[u8], jitter_or_nonce: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SWF_SEED_DST);
    hasher.update(doc_ref_cbor);
    hasher.update(jitter_or_nonce);
    hasher.finalize().into()
}

/// ENHANCED+ SWF seed per spec:
/// `H("PoP-SWF-Seed-v1" || prev-hash || CBOR-encode(jitter-binding.intervals) || CBOR-encode(physical-state))`.
///
/// `physical_state_cbor` may be empty if no physical state is available.
pub fn swf_seed_enhanced(
    prev_hash: &[u8; 32],
    jitter_intervals_cbor: &[u8],
    physical_state_cbor: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SWF_SEED_DST);
    hasher.update(prev_hash);
    hasher.update(jitter_intervals_cbor);
    hasher.update(physical_state_cbor);
    hasher.finalize().into()
}

/// CORE fallback SWF seed per spec:
/// `H("PoP-SWF-Seed-v1" || prev-hash || local-nonce)`.
pub fn swf_seed_core(prev_hash: &[u8; 32], local_nonce: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SWF_SEED_DST);
    hasher.update(prev_hash);
    hasher.update(local_nonce);
    hasher.finalize().into()
}

/// Parallel VDF proof verifier using a worker thread pool.
pub struct BatchVerifier {
    workers: usize,
}

impl BatchVerifier {
    /// Create a verifier with the given worker count (0 = auto-detect).
    pub fn new(workers: usize) -> Self {
        let workers = if workers == 0 {
            std::thread::available_parallelism()
                .map(|v| v.get())
                .unwrap_or(1)
        } else {
            workers
        };
        Self { workers }
    }

    /// Verify all proofs in parallel, returning per-index results.
    pub fn verify_all(&self, proofs: &[Option<VdfProof>]) -> Vec<VerifyResult> {
        let results = Arc::new(Mutex::new(vec![
            VerifyResult {
                index: 0,
                valid: false,
                error: None,
            };
            proofs.len()
        ]));

        let semaphore = Arc::new((Mutex::new(self.workers), Condvar::new()));
        let mut handles = Vec::new();

        for (index, proof) in proofs.iter().cloned().enumerate() {
            let results = Arc::clone(&results);
            let semaphore = Arc::clone(&semaphore);

            let handle = thread::spawn(move || {
                {
                    let (lock, cvar) = &*semaphore;
                    let mut count = cvar
                        .wait_while(lock.lock_recover(), |c| *c == 0)
                        .unwrap_or_else(|p| p.into_inner());
                    *count -= 1;
                }

                let outcome = if let Some(p) = proof {
                    VerifyResult {
                        index,
                        valid: p.verify(),
                        error: None,
                    }
                } else {
                    VerifyResult {
                        index,
                        valid: false,
                        error: Some("nil proof".to_string()),
                    }
                };

                let mut res = results.lock_recover();
                res[index] = outcome;
                let (lock, cvar) = &*semaphore;
                let mut count = lock.lock_recover();
                *count += 1;
                cvar.notify_one();
            });

            handles.push(handle);
        }

        for handle in handles {
            let _ = handle.join();
        }

        match Arc::try_unwrap(results) {
            Ok(mutex) => mutex.into_inner().unwrap_or_else(|p| p.into_inner()),
            Err(arc) => arc.lock_recover().clone(),
        }
    }
}

/// Result of a single VDF proof verification.
#[derive(Debug, Clone)]
pub struct VerifyResult {
    pub index: usize,
    pub valid: bool,
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_input_deterministic() {
        let input1 = chain_input([1u8; 32], [2u8; 32], 7);
        let input2 = chain_input([1u8; 32], [2u8; 32], 7);
        assert_eq!(input1, input2);
    }

    #[test]
    fn test_compute_verify_iterations() {
        let params = default_parameters();
        let input = [9u8; 32];
        let proof = compute(input, Duration::from_millis(5), params).expect("compute");
        assert!(verify(&proof));
    }

    #[test]
    fn test_chain_input_entangled_deterministic() {
        let input1 = chain_input_entangled([1u8; 32], [2u8; 32], [3u8; 32], 7);
        let input2 = chain_input_entangled([1u8; 32], [2u8; 32], [3u8; 32], 7);
        assert_eq!(input1, input2);
    }

    #[test]
    fn test_chain_input_entangled_differs_from_legacy() {
        let legacy = chain_input([1u8; 32], [2u8; 32], 7);
        let entangled = chain_input_entangled([2u8; 32], [3u8; 32], [1u8; 32], 7);
        assert_ne!(legacy, entangled);
    }

    #[test]
    fn test_chain_input_entangled_sensitive_to_vdf_output() {
        let input1 = chain_input_entangled([1u8; 32], [2u8; 32], [3u8; 32], 7);
        let input2 = chain_input_entangled([4u8; 32], [2u8; 32], [3u8; 32], 7);
        assert_ne!(input1, input2);
    }

    #[test]
    fn test_chain_input_entangled_sensitive_to_jitter() {
        let input1 = chain_input_entangled([1u8; 32], [2u8; 32], [3u8; 32], 7);
        let input2 = chain_input_entangled([1u8; 32], [5u8; 32], [3u8; 32], 7);
        assert_ne!(input1, input2);
    }

    #[test]
    fn test_chain_input_entangled_sensitive_to_content() {
        let input1 = chain_input_entangled([1u8; 32], [2u8; 32], [3u8; 32], 7);
        let input2 = chain_input_entangled([1u8; 32], [2u8; 32], [6u8; 32], 7);
        assert_ne!(input1, input2);
    }

    #[test]
    fn test_chain_input_entangled_sensitive_to_ordinal() {
        let input1 = chain_input_entangled([1u8; 32], [2u8; 32], [3u8; 32], 7);
        let input2 = chain_input_entangled([1u8; 32], [2u8; 32], [3u8; 32], 8);
        assert_ne!(input1, input2);
    }

    #[test]
    fn test_swf_seed_genesis_deterministic() {
        let doc_cbor = b"fake-cbor-doc-ref";
        let nonce = [0xAA; 32];
        let s1 = swf_seed_genesis(doc_cbor, &nonce);
        let s2 = swf_seed_genesis(doc_cbor, &nonce);
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_swf_seed_genesis_sensitive_to_nonce() {
        let doc_cbor = b"fake-cbor";
        let s1 = swf_seed_genesis(doc_cbor, &[1u8; 32]);
        let s2 = swf_seed_genesis(doc_cbor, &[2u8; 32]);
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_swf_seed_enhanced_includes_all_fields() {
        let prev = [1u8; 32];
        let intervals = b"intervals-cbor";
        let phys = b"phys-cbor";
        let s1 = swf_seed_enhanced(&prev, intervals, phys);
        let s2 = swf_seed_enhanced(&prev, intervals, b"different-phys");
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_swf_seed_core_deterministic() {
        let prev = [3u8; 32];
        let nonce = [4u8; 32];
        let s1 = swf_seed_core(&prev, &nonce);
        let s2 = swf_seed_core(&prev, &nonce);
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_swf_seed_genesis_differs_from_core_with_different_structure() {
        // Genesis uses variable-length doc_cbor; core uses fixed 32-byte prev_hash.
        // With structurally different inputs they must diverge.
        let nonce = [5u8; 32];
        let genesis = swf_seed_genesis(b"short-cbor", &nonce);
        let core = swf_seed_core(&nonce, &nonce);
        assert_ne!(genesis, core);
    }
}
