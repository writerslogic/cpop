// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::jitter::SimpleJitterSample;
use crate::physics::clock::ClockSkew;
use crate::physics::environment::AmbientSensing;
use crate::physics::puf::SiliconPUF;
use sha2::{Digest, Sha256};

/// The "Contextual Salt" generated from multi-source physical synthesis.
pub struct PhysicalContext {
    pub clock_skew: u64,
    pub thermal_proxy: u32,
    pub silicon_puf: [u8; 32],
    pub io_latency_ns: u64,
    pub ambient_hash: [u8; 32],
    pub is_virtualized: bool,
    pub combined_hash: [u8; 32],
}

impl PhysicalContext {
    /// Aggregates samples from all physical sources to generate a unique fingerprint.
    pub fn capture(biological_cadence: &[SimpleJitterSample]) -> Self {
        let skew = ClockSkew::measure();
        let io_latency = measure_io_latency();
        let puf = SiliconPUF::generate_fingerprint();
        let thermal = measure_thermal_proxy();
        let ambient = AmbientSensing::capture();

        let mut hasher = Sha256::new();
        hasher.update(b"witnessd-physics-v2");
        hasher.update(skew.to_be_bytes());
        hasher.update(thermal.to_be_bytes());
        hasher.update(puf);
        hasher.update(io_latency.to_be_bytes());
        hasher.update(ambient.hash);

        for sample in biological_cadence.iter().take(10) {
            hasher.update(sample.duration_since_last_ns.to_be_bytes());
        }

        Self {
            clock_skew: skew,
            thermal_proxy: thermal,
            silicon_puf: puf,
            io_latency_ns: io_latency,
            ambient_hash: ambient.hash,
            is_virtualized: ambient.is_virtualized,
            combined_hash: hasher.finalize().into(),
        }
    }
}

fn measure_io_latency() -> u64 {
    let start = std::time::Instant::now();
    let _ = std::fs::metadata("/etc/hosts").map(|m| m.len());
    start.elapsed().as_nanos().min(u64::MAX as u128) as u64
}

fn measure_thermal_proxy() -> u32 {
    let start_wall = std::time::Instant::now();
    let start_tsc = ClockSkew::measure();

    while start_wall.elapsed() < std::time::Duration::from_millis(1) {}

    let end_tsc = ClockSkew::measure();
    end_tsc.wrapping_sub(start_tsc).min(u32::MAX as u64) as u32
}
