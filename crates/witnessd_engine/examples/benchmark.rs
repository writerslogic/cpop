//! Benchmark program for generating empirical data for research papers.
//!
//! Measures: VDF calibration, computation, verification, checkpoint overhead,
//! and evidence sizes across multiple parameter configurations.

use std::time::{Duration, Instant};
use witnessd_engine::vdf::{self, VdfProof};

fn main() {
    println!("=== witnessd Empirical Benchmark Suite ===\n");

    // 1. VDF Calibration
    println!("--- VDF Calibration (SHA-256 hash chain throughput) ---");
    for duration_ms in [500, 1000, 2000, 5000] {
        let dur = Duration::from_millis(duration_ms);
        let start = Instant::now();
        let params = vdf::calibrate(dur).expect("calibrate");
        let elapsed = start.elapsed();
        println!(
            "  Calibration ({:>4}ms target): {:>12} iter/sec  (actual: {:.3}s)",
            duration_ms,
            params.iterations_per_second,
            elapsed.as_secs_f64()
        );
    }

    // Use a stable calibration for remaining benchmarks
    let params = vdf::calibrate(Duration::from_secs(2)).expect("calibrate");
    println!(
        "\n  Using calibrated rate: {} iterations/sec",
        params.iterations_per_second
    );

    // 2. VDF Computation at various target durations
    println!("\n--- VDF Computation (per-checkpoint SWF cost) ---");
    let input = [0xABu8; 32];
    for target_ms in [10, 50, 100, 500, 1000, 5000, 30000] {
        let target = Duration::from_millis(target_ms);
        let start = Instant::now();
        let proof = vdf::compute(input, target, params).expect("compute");
        let elapsed = start.elapsed();
        let encoded_size = proof.encode().len();
        println!(
            "  Target {:>6}ms: {:>12} iterations, actual {:.3}s, proof size {} bytes",
            target_ms,
            proof.iterations,
            elapsed.as_secs_f64(),
            encoded_size,
        );
    }

    // 3. VDF Verification timing
    println!("\n--- VDF Verification (Verifier cost) ---");
    for iter_count in [50_000u64, 500_000, 5_000_000, 50_000_000, 150_000_000] {
        let proof = vdf::compute_iterations(input, iter_count);
        let start = Instant::now();
        let valid = vdf::verify(&proof);
        let elapsed = start.elapsed();
        assert!(valid, "verification must succeed");
        println!(
            "  {:>12} iterations: verify {:.3}s  ({:.1} iter/sec)",
            iter_count,
            elapsed.as_secs_f64(),
            iter_count as f64 / elapsed.as_secs_f64(),
        );
    }

    // 4. Chain input computation (entangled vs legacy)
    println!("\n--- Chain Input Computation (entanglement overhead) ---");
    let n_chains = 100_000;
    let prev_hash = [1u8; 32];
    let content_hash = [2u8; 32];
    let jitter_hash = [3u8; 32];

    let start = Instant::now();
    for i in 0..n_chains {
        let _ = vdf::chain_input(content_hash, prev_hash, i);
    }
    let legacy_elapsed = start.elapsed();

    let start = Instant::now();
    for i in 0..n_chains {
        let _ = vdf::chain_input_entangled(prev_hash, jitter_hash, content_hash, i);
    }
    let entangled_elapsed = start.elapsed();

    println!(
        "  Legacy    chain_input ({} calls): {:.3}ms  ({:.0} ns/call)",
        n_chains,
        legacy_elapsed.as_secs_f64() * 1000.0,
        legacy_elapsed.as_nanos() as f64 / n_chains as f64,
    );
    println!(
        "  Entangled chain_input ({} calls): {:.3}ms  ({:.0} ns/call)",
        n_chains,
        entangled_elapsed.as_secs_f64() * 1000.0,
        entangled_elapsed.as_nanos() as f64 / n_chains as f64,
    );

    // 5. Batch verification
    println!("\n--- Batch Verification (parallel) ---");
    let batch_sizes = [10, 50, 100];
    for &batch_size in &batch_sizes {
        let proofs: Vec<Option<VdfProof>> = (0..batch_size)
            .map(|i| {
                let inp = [(i as u8).wrapping_add(1); 32];
                Some(vdf::compute_iterations(inp, 10_000))
            })
            .collect();

        let verifier = vdf::params::BatchVerifier::new(0); // auto-detect workers

        let start = Instant::now();
        let results = verifier.verify_all(&proofs);
        let elapsed = start.elapsed();

        let all_valid = results.iter().all(|r| r.valid);
        println!(
            "  Batch of {:>3} proofs (10K iter each): {:.3}s  all_valid={}",
            batch_size,
            elapsed.as_secs_f64(),
            all_valid,
        );
    }

    // 6. VDF proof size analysis
    println!("\n--- Evidence Size Analysis ---");
    let proof = vdf::compute_iterations(input, 150_000_000);
    let encoded = proof.encode();
    println!("  VDF proof binary encoding: {} bytes", encoded.len());
    let json = serde_json::to_string(&proof).expect("json");
    println!("  VDF proof JSON encoding: {} bytes", json.len());

    // Simulate checkpoint evidence sizes
    println!("\n--- Simulated Checkpoint Evidence Sizes ---");
    // Content hash: 32, edit delta (avg): 200, prev hash: 32, timestamp: 8
    // VDF proof: 80, Merkle samples: variable, jitter binding: ~200, entangled MAC: 32
    let fixed_fields = 32 + 200 + 32 + 8; // 272 bytes
    let vdf_proof_size = 80; // binary encoded
    let jitter_binding = 200; // 50 intervals * 4 bytes
    let entangled_mac = 32;
    let metadata = 48;

    for merkle_samples in [8, 20, 50, 100] {
        let merkle_proof_size = merkle_samples * 32; // each sample is a hash
        let total = fixed_fields
            + vdf_proof_size
            + jitter_binding
            + entangled_mac
            + metadata
            + merkle_proof_size;
        println!(
            "  k={:>3} Merkle samples: {:>6} bytes/checkpoint  ({:.1} KiB)",
            merkle_samples,
            total,
            total as f64 / 1024.0,
        );
    }

    // Session totals
    println!("\n--- Session Evidence Totals ---");
    for (hours, interval_sec) in [(1, 30), (2, 30), (4, 30), (8, 30)] {
        let checkpoints = hours * 3600 / interval_sec;
        let per_ckpt =
            fixed_fields + vdf_proof_size + jitter_binding + entangled_mac + metadata + 20 * 32; // k=20
        let total_bytes = checkpoints * per_ckpt;
        let seed_metadata = 4096 + 1024 + 2048; // seed + session + signatures
        let total = total_bytes + seed_metadata;
        println!(
            "  {:>2}h session ({:>4} ckpts @ {}s): {:>8} bytes ({:.1} KiB, {:.2} MiB)",
            hours,
            checkpoints,
            interval_sec,
            total,
            total as f64 / 1024.0,
            total as f64 / (1024.0 * 1024.0),
        );
    }

    // 7. Acceleration gap analysis (for Paper 5)
    println!("\n--- Hardware Acceleration Gap Analysis ---");
    let base_rate = params.iterations_per_second;
    println!("  Baseline (consumer CPU): {} SHA-256 iter/sec", base_rate);
    println!("  For a 30-second checkpoint interval:");
    let iters_30s = base_rate * 30;
    println!("    Iterations per checkpoint: {}", iters_30s);

    for (accel_name, accel_factor) in [
        ("ASIC (BitMain S19)", 64),
        ("GPU (RTX 4090)", 8),
        ("FPGA (high-end)", 16),
        ("Multi-core (8 threads)", 1), // sequential, no speedup
    ] {
        let accel_rate = base_rate * accel_factor;
        let accel_time = iters_30s as f64 / accel_rate as f64;
        let _speedup = 30.0 / accel_time;
        println!(
            "    {:<25}: {:>12} iter/sec  → {:.2}s to replay ({}× faster than wall clock = {:.1}s floor)",
            accel_name,
            accel_rate,
            accel_time,
            accel_factor,
            30.0 / accel_factor as f64,
        );
    }

    // Argon2id memory hardness (estimated, not benchmarked here)
    println!("\n--- Argon2id Memory Hardness (per-checkpoint) ---");
    println!("  m=65536 KiB (64 MiB), t=1, p=1:");
    println!("    Estimated compute time: 50-100ms on consumer hardware");
    println!("    Memory bandwidth required: 64 MiB × 3 passes = 192 MiB sequential reads");
    println!("    GPU parallelism limited by: 64 MiB per instance (12 instances on 1GB GPU)");

    println!("\n=== Benchmark complete ===");
}
