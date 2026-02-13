use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::vdf::VdfProof;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct Parameters {
    pub iterations_per_second: u64,
    pub min_iterations: u64,
    pub max_iterations: u64,
}

pub fn default_parameters() -> Parameters {
    Parameters {
        iterations_per_second: 1_000_000,
        min_iterations: 100_000,
        max_iterations: 3_600_000_000,
    }
}

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
        min_iterations: iterations_per_second / 10,
        max_iterations: iterations_per_second * 3600,
    })
}

pub fn compute(
    input: [u8; 32],
    duration: Duration,
    params: Parameters,
) -> Result<VdfProof, String> {
    VdfProof::compute(input, duration, params)
}

pub fn compute_iterations(input: [u8; 32], iterations: u64) -> VdfProof {
    VdfProof::compute_iterations(input, iterations)
}

pub fn verify(proof: &VdfProof) -> bool {
    proof.verify()
}

pub fn verify_with_progress<F>(proof: &VdfProof, progress: Option<F>) -> bool
where
    F: FnMut(f64),
{
    proof.verify_with_progress(progress)
}

pub fn chain_input(content_hash: [u8; 32], previous_hash: [u8; 32], ordinal: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"witnessd-vdf-v1");
    hasher.update(content_hash);
    hasher.update(previous_hash);
    hasher.update(ordinal.to_be_bytes());
    hasher.finalize().into()
}

pub struct BatchVerifier {
    workers: usize,
}

impl BatchVerifier {
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

    pub fn verify_all(&self, proofs: &[Option<VdfProof>]) -> Vec<VerifyResult> {
        let results = Arc::new(Mutex::new(vec![
            VerifyResult {
                index: 0,
                valid: false,
                error: None,
            };
            proofs.len()
        ]));

        let semaphore = Arc::new(Mutex::new(self.workers));
        let mut handles = Vec::new();

        for (index, proof) in proofs.iter().cloned().enumerate() {
            let results = Arc::clone(&results);
            let semaphore = Arc::clone(&semaphore);

            let handle = thread::spawn(move || {
                loop {
                    let mut count = semaphore.lock().unwrap();
                    if *count > 0 {
                        *count -= 1;
                        break;
                    }
                    drop(count);
                    thread::yield_now();
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

                let mut res = results.lock().unwrap();
                res[index] = outcome;
                let mut count = semaphore.lock().unwrap();
                *count += 1;
            });

            handles.push(handle);
        }

        for handle in handles {
            let _ = handle.join();
        }

        Arc::try_unwrap(results).unwrap().into_inner().unwrap()
    }
}

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
}
