use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

use crate::vdf::Parameters;

/// Verifiable Delay Function (VDF) proof.
#[derive(Debug, Clone, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct VdfProof {
    pub input: [u8; 32],
    pub output: [u8; 32],
    pub iterations: u64,
    pub duration: Duration,
}

impl VdfProof {
    pub fn compute(
        input: [u8; 32],
        target_duration: Duration,
        params: Parameters,
    ) -> Result<Self, String> {
        let mut iterations =
            (target_duration.as_secs_f64() * params.iterations_per_second as f64) as u64;

        if iterations < params.min_iterations {
            iterations = params.min_iterations;
        }
        if iterations > params.max_iterations {
            return Err(format!(
                "target duration exceeds maximum ({} iterations)",
                params.max_iterations
            ));
        }

        let start = Instant::now();
        let output = compute_chain(input, iterations);
        let elapsed = start.elapsed();

        Ok(Self {
            input,
            output,
            iterations,
            duration: elapsed,
        })
    }

    pub fn compute_iterations(input: [u8; 32], iterations: u64) -> Self {
        let start = Instant::now();
        let output = compute_chain(input, iterations);
        let elapsed = start.elapsed();

        Self {
            input,
            output,
            iterations,
            duration: elapsed,
        }
    }

    pub fn verify(&self) -> bool {
        compute_chain(self.input, self.iterations) == self.output
    }

    pub fn verify_with_progress<F>(&self, mut progress: Option<F>) -> bool
    where
        F: FnMut(f64),
    {
        let mut hash = self.input;
        let report_interval = std::cmp::max(1, self.iterations / 100);

        for i in 0..self.iterations {
            hash = Sha256::digest(hash).into();
            if let Some(ref mut callback) = progress {
                if i % report_interval == 0 {
                    callback(i as f64 / self.iterations as f64);
                }
            }
        }

        if let Some(ref mut callback) = progress {
            callback(1.0);
        }

        hash == self.output
    }

    pub fn min_elapsed_time(&self, params: Parameters) -> Duration {
        let seconds = self.iterations as f64 / params.iterations_per_second as f64;
        Duration::from_secs_f64(seconds)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = vec![0u8; 32 + 32 + 8 + 8];
        buf[0..32].copy_from_slice(&self.input);
        buf[32..64].copy_from_slice(&self.output);
        buf[64..72].copy_from_slice(&self.iterations.to_be_bytes());
        buf[72..80].copy_from_slice(&(self.duration.as_nanos() as u64).to_be_bytes());
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self, String> {
        if data.len() < 80 {
            return Err("proof data too short".to_string());
        }

        let mut input = [0u8; 32];
        let mut output = [0u8; 32];
        input.copy_from_slice(&data[0..32]);
        output.copy_from_slice(&data[32..64]);
        let iterations = u64::from_be_bytes(data[64..72].try_into().unwrap());
        let duration_nanos = u64::from_be_bytes(data[72..80].try_into().unwrap());

        Ok(Self {
            input,
            output,
            iterations,
            duration: Duration::from_nanos(duration_nanos),
        })
    }
}

fn compute_chain(input: [u8; 32], iterations: u64) -> [u8; 32] {
    let mut hash = input;
    for _ in 0..iterations {
        hash = Sha256::digest(hash).into();
    }
    hash
}

#[cfg(test)]
#[allow(clippy::needless_borrows_for_generic_args)]
mod tests {
    use super::*;
    use crate::vdf::default_parameters;

    #[test]
    fn test_compute_and_verify() {
        let params = default_parameters();
        let input = [7u8; 32];
        let proof = VdfProof::compute(input, Duration::from_millis(10), params).expect("compute");
        assert!(proof.verify());
        assert_eq!(proof.input, input);
        assert_eq!(proof.output, compute_chain(input, proof.iterations));
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let input = [1u8; 32];
        let proof = VdfProof::compute_iterations(input, 1000);
        let encoded = proof.encode();
        let decoded = VdfProof::decode(&encoded).expect("decode");
        assert_eq!(decoded.input, proof.input);
        assert_eq!(decoded.output, proof.output);
        assert_eq!(decoded.iterations, proof.iterations);
    }

    #[test]
    fn test_compute_iterations_directly() {
        let input = [0xABu8; 32];
        let iterations = 500;
        let proof = VdfProof::compute_iterations(input, iterations);

        assert_eq!(proof.input, input);
        assert_eq!(proof.iterations, iterations);
        assert!(proof.verify());
    }

    #[test]
    fn test_verify_fails_with_wrong_output() {
        let input = [5u8; 32];
        let mut proof = VdfProof::compute_iterations(input, 100);

        // Tamper with output
        proof.output[0] ^= 0xFF;

        assert!(!proof.verify());
    }

    #[test]
    fn test_verify_fails_with_wrong_iterations() {
        let input = [5u8; 32];
        let proof = VdfProof::compute_iterations(input, 100);

        // Create a proof with wrong iterations but same output
        let tampered = VdfProof {
            input: proof.input,
            output: proof.output,
            iterations: 99, // Wrong!
            duration: proof.duration,
        };

        assert!(!tampered.verify());
    }

    #[test]
    fn test_verify_fails_with_wrong_input() {
        let input = [5u8; 32];
        let proof = VdfProof::compute_iterations(input, 100);

        // Create a proof with wrong input
        let tampered = VdfProof {
            input: [6u8; 32], // Wrong!
            output: proof.output,
            iterations: proof.iterations,
            duration: proof.duration,
        };

        assert!(!tampered.verify());
    }

    #[test]
    fn test_min_iterations_enforcement() {
        let params = Parameters {
            iterations_per_second: 1_000_000,
            min_iterations: 1000,
            max_iterations: 100_000,
        };
        let input = [1u8; 32];

        // Very short duration should still use min_iterations
        let proof = VdfProof::compute(input, Duration::from_nanos(1), params).expect("compute");
        assert!(proof.iterations >= params.min_iterations);
        assert!(proof.verify());
    }

    #[test]
    fn test_max_iterations_enforcement() {
        let params = Parameters {
            iterations_per_second: 100,
            min_iterations: 10,
            max_iterations: 1000,
        };
        let input = [1u8; 32];

        // Very long duration should fail due to max_iterations
        let err = VdfProof::compute(input, Duration::from_secs(1000), params).unwrap_err();
        assert!(err.contains("exceeds maximum"));
    }

    #[test]
    fn test_decode_too_short() {
        let short_data = vec![0u8; 50]; // Should be at least 80
        let err = VdfProof::decode(&short_data).unwrap_err();
        assert!(err.contains("too short"));
    }

    #[test]
    fn test_min_elapsed_time() {
        let params = Parameters {
            iterations_per_second: 1000,
            min_iterations: 100,
            max_iterations: 10_000,
        };

        let proof = VdfProof {
            input: [0u8; 32],
            output: [0u8; 32],
            iterations: 5000,
            duration: Duration::from_secs(0),
        };

        let min_time = proof.min_elapsed_time(params);
        // 5000 iterations at 1000/sec = 5 seconds
        assert_eq!(min_time, Duration::from_secs(5));
    }

    #[test]
    fn test_verify_with_progress() {
        let input = [3u8; 32];
        let proof = VdfProof::compute_iterations(input, 100);

        let mut progress_updates = Vec::new();
        let valid = proof.verify_with_progress(Some(|p| {
            progress_updates.push(p);
        }));

        assert!(valid);
        assert!(!progress_updates.is_empty());
        // Last update should be 100%
        assert!(progress_updates.last().map(|&p| p >= 0.99).unwrap_or(false));
    }

    #[test]
    fn test_verify_with_progress_no_callback() {
        let input = [3u8; 32];
        let proof = VdfProof::compute_iterations(input, 100);

        let valid = proof.verify_with_progress::<fn(f64)>(None);
        assert!(valid);
    }

    #[test]
    fn test_zero_iterations() {
        let input = [0u8; 32];
        let proof = VdfProof::compute_iterations(input, 0);

        // Zero iterations means output equals input
        assert_eq!(proof.input, proof.output);
        assert!(proof.verify());
    }

    #[test]
    fn test_single_iteration() {
        let input = [42u8; 32];
        let proof = VdfProof::compute_iterations(input, 1);

        // One iteration is just one hash
        let expected_output: [u8; 32] = Sha256::digest(&input).into();
        assert_eq!(proof.output, expected_output);
        assert!(proof.verify());
    }

    #[test]
    fn test_different_inputs_produce_different_outputs() {
        let proof1 = VdfProof::compute_iterations([1u8; 32], 100);
        let proof2 = VdfProof::compute_iterations([2u8; 32], 100);

        assert_ne!(proof1.output, proof2.output);
    }

    #[test]
    fn test_same_input_produces_same_output() {
        let input = [99u8; 32];
        let proof1 = VdfProof::compute_iterations(input, 100);
        let proof2 = VdfProof::compute_iterations(input, 100);

        assert_eq!(proof1.output, proof2.output);
    }

    #[test]
    fn test_encode_preserves_all_fields() {
        let proof = VdfProof {
            input: [0xAAu8; 32],
            output: [0xBBu8; 32],
            iterations: 12345678,
            duration: Duration::from_nanos(987654321),
        };

        let encoded = proof.encode();
        let decoded = VdfProof::decode(&encoded).expect("decode");

        assert_eq!(decoded.input, proof.input);
        assert_eq!(decoded.output, proof.output);
        assert_eq!(decoded.iterations, proof.iterations);
        assert_eq!(decoded.duration, proof.duration);
    }

    #[test]
    fn test_encode_length() {
        let proof = VdfProof::compute_iterations([0u8; 32], 100);
        let encoded = proof.encode();

        // 32 (input) + 32 (output) + 8 (iterations) + 8 (duration) = 80
        assert_eq!(encoded.len(), 80);
    }

    #[test]
    fn test_sequential_verification() {
        // Verify that doing iterations 0..50 then 50..100 equals 0..100
        let input = [7u8; 32];
        let half = compute_chain(input, 50);
        let full_via_half = compute_chain(half, 50);
        let full_direct = compute_chain(input, 100);

        assert_eq!(full_via_half, full_direct);
    }

    #[test]
    fn test_compute_with_exact_boundary_duration() {
        let params = Parameters {
            iterations_per_second: 1000,
            min_iterations: 100,
            max_iterations: 10_000,
        };

        // Duration that would give exactly max_iterations
        let duration = Duration::from_secs(10); // 1000 iter/sec * 10 sec = 10000
        let input = [1u8; 32];

        let proof = VdfProof::compute(input, duration, params).expect("compute");
        assert!(proof.iterations <= params.max_iterations);
        assert!(proof.verify());
    }
}
