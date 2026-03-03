//! Custom engine configuration example.
//!
//! Run with: `cargo run --example custom_engine --features hardware`

use wld_jitter::{HybridEngine, PhysJitter, PureJitter};

fn main() {
    // Create custom engines with specific parameters
    let phys = PhysJitter::new(8) // Require 8 bits minimum entropy
        .with_jitter_range(1000, 2000); // 1000-3000μs range

    let pure = PureJitter::new(1000, 2000); // Matching range for fallback

    let engine = HybridEngine::new(phys, pure).with_min_entropy(8);

    println!("Custom engine created");
    println!("  Physics available: {}", engine.phys_available());

    // Sample some jitter
    let secret = [42u8; 32];
    for i in 0..5 {
        let (jitter, evidence) = engine
            .sample(&secret, format!("input{}", i).as_bytes())
            .unwrap();
        println!(
            "  Sample {}: {}μs ({})",
            i,
            jitter,
            if evidence.is_phys() {
                "physics"
            } else {
                "pure"
            }
        );
    }
}
