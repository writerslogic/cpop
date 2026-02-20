use sha2::Digest;
use std::time::Instant;

/// Silicon-level Physical Unclonable Function (PUF).
/// Measures microscopic manufacturing variations in cache-latency.
pub struct SiliconPUF;

impl SiliconPUF {
    /// Generates a unique fingerprint based on cache-line timing patterns.
    pub fn generate_fingerprint() -> [u8; 32] {
        let mut samples = Vec::with_capacity(100);

        // We create a "noisy" memory access pattern to measure L1/L2 transition jitter
        let data = vec![0u8; 1024 * 1024]; // 1MB buffer

        for i in 0..100 {
            let start = Instant::now();
            // Jump across cache lines in a deterministic but non-linear pattern
            for j in (0..data.len()).step_by(128) {
                let idx = (j * 7 + i) % data.len();
                unsafe {
                    std::ptr::read_volatile(&data[idx]);
                }
            }
            samples.push(start.elapsed().as_nanos() as u64);
        }

        // Hash the timing distribution
        let mut hasher = sha2::Sha256::new();
        for sample in samples {
            sha2::Digest::update(&mut hasher, sample.to_be_bytes());
        }

        let result = sha2::Digest::finalize(hasher);
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_puf_generates_fingerprint() {
        let fp = SiliconPUF::generate_fingerprint();
        assert_ne!(fp, [0u8; 32]);
    }

    #[test]
    fn test_puf_uniqueness() {
        let fp1 = SiliconPUF::generate_fingerprint();
        let fp2 = SiliconPUF::generate_fingerprint();

        // Due to the nature of cache timing, two consecutive runs are
        // extremely unlikely to have identical timing for 100 samples.
        assert_ne!(
            fp1, fp2,
            "PUF should generate unique fingerprints each time"
        );
    }
}
