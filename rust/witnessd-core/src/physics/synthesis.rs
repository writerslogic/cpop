use crate::jitter::SimpleJitterSample;
use crate::physics::clock::ClockSkew;
use crate::physics::puf::SiliconPUF;
use sha2::{Digest, Sha256};

/// The "Contextual Salt" generated from multi-source physical synthesis.
pub struct PhysicalContext {
    pub clock_skew: u64,
    pub thermal_proxy: u32,
    pub silicon_puf: [u8; 32],
    pub io_latency_ns: u64,
    pub combined_hash: [u8; 32],
}

impl PhysicalContext {
    /// Aggregates samples from all physical sources to generate a unique fingerprint.
    pub fn capture(biological_cadence: &[SimpleJitterSample]) -> Self {
        let skew = ClockSkew::measure();
        let io_latency = measure_io_latency();
        let puf = SiliconPUF::generate_fingerprint();

        let thermal = measure_thermal_proxy();

        let mut hasher = Sha256::new();
        hasher.update(b"witnessd-physics-v2"); // Versioned
        hasher.update(skew.to_be_bytes());
        hasher.update(thermal.to_be_bytes());
        hasher.update(puf);
        hasher.update(io_latency.to_be_bytes());

        // Bind the biological signature
        for sample in biological_cadence.iter().take(10) {
            hasher.update(sample.duration_since_last_ns.to_be_bytes());
        }

        let result = hasher.finalize();
        let mut combined_hash = [0u8; 32];
        combined_hash.copy_from_slice(&result);

        Self {
            clock_skew: skew,
            thermal_proxy: thermal,
            silicon_puf: puf,
            io_latency_ns: io_latency,
            combined_hash,
        }
    }
}

fn measure_io_latency() -> u64 {
    let start = std::time::Instant::now();
    // Perform a tiny, non-destructive read from a system file to measure bus latency
    let _ = std::fs::metadata("/etc/hosts").map(|m| m.len());
    start.elapsed().as_nanos() as u64
}

fn measure_thermal_proxy() -> u32 {
    // Measure how many TSC cycles occur in exactly 1ms of wall time.
    // Variations in this number (jitter) correlate with CPU thermal throttling and phonon noise.
    let start_wall = std::time::Instant::now();
    let start_tsc = ClockSkew::measure();

    while start_wall.elapsed() < std::time::Duration::from_millis(1) {}

    let end_tsc = ClockSkew::measure();
    (end_tsc.wrapping_sub(start_tsc)) as u32
}
