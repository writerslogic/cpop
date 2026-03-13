// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Hardware-based entropy source using TSC/CNTVCT timing measurements.

use sha2::{Digest, Sha256};

use crate::{EntropySource, Error, Jitter, JitterEngine, PhysHash};

/// Hardware entropy source using CPU timing counter measurements.
#[derive(Debug, Clone)]
pub struct PhysJitter {
    /// Minimum entropy bits required for a valid sample.
    pub min_entropy_bits: u8,
    /// Minimum jitter output in microseconds.
    pub jmin: u32,
    /// Range of jitter values above `jmin`.
    pub range: u32,
}

impl Default for PhysJitter {
    fn default() -> Self {
        Self {
            min_entropy_bits: 0,
            jmin: 500,
            range: 2500,
        }
    }
}

impl PhysJitter {
    /// Create a physics jitter source with the given minimum entropy requirement.
    pub fn new(min_entropy_bits: u8) -> Self {
        Self {
            min_entropy_bits,
            ..Default::default()
        }
    }

    /// Set the jitter output range.
    ///
    /// # Panics
    /// Panics if `range` is 0.
    pub fn with_jitter_range(mut self, jmin: u32, range: u32) -> Self {
        assert!(range > 0, "range must be greater than 0");
        self.jmin = jmin;
        self.range = range;
        self
    }

    /// Set the jitter output range, returning `None` if `range` is 0.
    pub fn try_with_jitter_range(mut self, jmin: u32, range: u32) -> Option<Self> {
        if range == 0 {
            None
        } else {
            self.jmin = jmin;
            self.range = range;
            Some(self)
        }
    }

    #[cfg(feature = "hardware")]
    fn capture_timing_samples(&self, count: usize) -> Result<Vec<u64>, Error> {
        let mut samples = Vec::with_capacity(count);

        for _ in 0..count {
            #[cfg(target_arch = "x86_64")]
            {
                let tsc: u64;
                // SAFETY: _mm_lfence and _rdtsc are safe CPU intrinsics for reading the timestamp counter
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                unsafe {
                    core::arch::x86_64::_mm_lfence();
                    tsc = core::arch::x86_64::_rdtsc();
                }
                samples.push(tsc);
            }

            #[cfg(target_arch = "aarch64")]
            {
                let cntvct: u64;
                // SAFETY: Reading cntvct_el0 is a safe operation to get the virtual timer count
                // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                unsafe {
                    core::arch::asm!("mrs {}, cntvct_el0", out(reg) cntvct);
                }
                samples.push(cntvct);
            }

            #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
            {
                use std::time::Instant;
                let now = Instant::now();
                samples.push(now.elapsed().as_nanos() as u64);
            }
        }

        Ok(samples)
    }

    #[cfg(not(feature = "hardware"))]
    fn capture_timing_samples(&self, count: usize) -> Result<Vec<u64>, Error> {
        use std::time::Instant;

        let mut samples = Vec::with_capacity(count);
        let start = Instant::now();

        let mut kernel_entropy = [0u8; 8];
        getrandom::fill(&mut kernel_entropy).map_err(|e| Error::HardwareUnavailable {
            reason: format!("getrandom failed: {}", e),
        })?;
        let kernel_seed = u64::from_le_bytes(kernel_entropy);

        for i in 0..count {
            let timing = start.elapsed().as_nanos() as u64;
            samples.push(timing ^ kernel_seed.wrapping_add(i as u64));
            std::hint::spin_loop();
        }

        Ok(samples)
    }

    /// Welford's single-pass variance of inter-sample deltas.
    fn estimate_entropy(&self, samples: &[u64]) -> u8 {
        if samples.len() < 2 {
            return 0;
        }

        let mut mean = 0.0f64;
        let mut m2 = 0.0f64;

        for (i, w) in samples.windows(2).enumerate() {
            let delta = (w[1] as i64).wrapping_sub(w[0] as i64) as f64;
            let k = (i + 1) as f64;
            let d1 = delta - mean;
            mean += d1 / k;
            let d2 = delta - mean;
            m2 += d1 * d2;
        }

        let n = (samples.len() - 1) as f64;
        let std_dev = (m2 / n).sqrt();
        if std_dev < 1.0 {
            0
        } else {
            (std_dev.log2().ceil() as u8).min(64)
        }
    }
}

impl EntropySource for PhysJitter {
    fn sample(&self, inputs: &[u8]) -> Result<PhysHash, Error> {
        let samples = self.capture_timing_samples(64)?;
        let entropy_bits = self.estimate_entropy(&samples);
        if entropy_bits < self.min_entropy_bits {
            return Err(Error::InsufficientEntropy {
                required: self.min_entropy_bits,
                found: entropy_bits,
            });
        }

        let mut hasher = Sha256::new();
        for sample in &samples {
            hasher.update(sample.to_le_bytes());
        }
        hasher.update(inputs);

        let result = hasher.finalize();
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&result);

        Ok(PhysHash {
            hash: hash_bytes,
            entropy_bits,
        })
    }

    fn validate(&self, hash: PhysHash) -> bool {
        hash.entropy_bits >= self.min_entropy_bits
    }
}

impl JitterEngine for PhysJitter {
    fn compute_jitter(&self, secret: &[u8; 32], inputs: &[u8], entropy: PhysHash) -> Jitter {
        crate::traits::hmac_jitter(secret, inputs, &entropy.hash, self.jmin, self.range)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_collection() {
        let phys = PhysJitter::new(0);
        let result = phys.sample(b"test");
        assert!(result.is_ok());
    }

    #[test]
    fn test_entropy_estimation() {
        let phys = PhysJitter::default();

        let constant_delta: Vec<u64> = (0..64).map(|i| 1000 + i * 100).collect();
        let low_entropy = phys.estimate_entropy(&constant_delta);

        let varying_delta: Vec<u64> = (0..64)
            .map(|i| 1000 + (i * i * 37 + i * 17) % 10000)
            .collect();
        let high_entropy = phys.estimate_entropy(&varying_delta);

        assert!(
            high_entropy >= low_entropy,
            "Expected high_entropy ({}) >= low_entropy ({})",
            high_entropy,
            low_entropy
        );
    }

    #[test]
    fn test_validate_checks_embedded_entropy() {
        let phys = PhysJitter::new(0);
        let hash = phys.sample(b"test").unwrap();
        let embedded_entropy = hash.entropy_bits;

        assert!(phys.validate(hash));

        let strict_phys = PhysJitter::new(embedded_entropy + 1);
        assert!(!strict_phys.validate(hash));

        let lenient_phys = PhysJitter::new(embedded_entropy);
        assert!(lenient_phys.validate(hash));
    }

    #[test]
    fn test_estimate_entropy_single_sample() {
        let phys = PhysJitter::default();
        assert_eq!(phys.estimate_entropy(&[100]), 0);
    }

    #[test]
    fn test_estimate_entropy_two_samples() {
        let phys = PhysJitter::default();
        let entropy = phys.estimate_entropy(&[0, 1000000]);
        assert_eq!(entropy, 0);
    }

    #[test]
    fn test_estimate_entropy_three_samples_with_variance() {
        let phys = PhysJitter::default();
        let entropy = phys.estimate_entropy(&[0, 100, 1000100]);
        assert!(entropy > 0);
    }

    #[test]
    fn test_estimate_entropy_empty() {
        let phys = PhysJitter::default();
        assert_eq!(phys.estimate_entropy(&[]), 0);
    }

    #[test]
    #[should_panic(expected = "range must be greater than 0")]
    fn test_with_jitter_range_zero_panics() {
        PhysJitter::default().with_jitter_range(500, 0);
    }

    #[test]
    fn test_try_with_jitter_range() {
        assert!(PhysJitter::default()
            .try_with_jitter_range(500, 0)
            .is_none());
        assert!(PhysJitter::default()
            .try_with_jitter_range(500, 100)
            .is_some());
    }
}
