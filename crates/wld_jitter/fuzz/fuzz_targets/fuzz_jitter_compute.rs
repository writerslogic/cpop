#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use wld_jitter::{JitterEngine, PhysHash, PhysJitter, PureJitter};

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    secret: [u8; 32],
    inputs: Vec<u8>,
    entropy_hash: [u8; 32],
    entropy_bits: u8,
    jmin: u32,
    range: u32,
}

fuzz_target!(|input: FuzzInput| {
    // Ensure range is valid (> 0)
    let range = if input.range == 0 { 1 } else { input.range };
    let jmin = input.jmin % 10000; // Keep reasonable
    let range = range % 10000;

    // Test PureJitter with try_new (safe construction)
    if let Some(pure) = PureJitter::try_new(jmin, range) {
        let entropy = PhysHash {
            hash: input.entropy_hash,
            entropy_bits: input.entropy_bits,
        };

        let jitter = pure.compute_jitter(&input.secret, &input.inputs, entropy);

        // Verify jitter is in expected range
        assert!(jitter >= jmin, "jitter {} < jmin {}", jitter, jmin);
        assert!(
            jitter < jmin.saturating_add(range),
            "jitter {} >= jmin + range {}",
            jitter,
            jmin.saturating_add(range)
        );
    }

    // Test PhysJitter with try_with_jitter_range (safe construction)
    if let Some(phys) = PhysJitter::default().try_with_jitter_range(jmin, range) {
        let entropy = PhysHash {
            hash: input.entropy_hash,
            entropy_bits: input.entropy_bits,
        };

        let jitter = phys.compute_jitter(&input.secret, &input.inputs, entropy);

        // Verify jitter is in expected range
        assert!(jitter >= jmin, "jitter {} < jmin {}", jitter, jmin);
        assert!(
            jitter < jmin.saturating_add(range),
            "jitter {} >= jmin + range {}",
            jitter,
            jmin.saturating_add(range)
        );
    }

    // Test default configurations
    let default_pure = PureJitter::default();
    let default_phys = PhysJitter::default();

    let entropy = PhysHash {
        hash: input.entropy_hash,
        entropy_bits: input.entropy_bits,
    };

    let pure_jitter = default_pure.compute_jitter(&input.secret, &input.inputs, entropy);
    let phys_jitter = default_phys.compute_jitter(&input.secret, &input.inputs, entropy);

    // Default range is 500-3000
    assert!((500..3000).contains(&pure_jitter));
    assert!((500..3000).contains(&phys_jitter));

    // Test with empty inputs
    let _ = default_pure.compute_jitter(&input.secret, &[], entropy);
    let _ = default_phys.compute_jitter(&input.secret, &[], entropy);

    // Test with large inputs
    if input.inputs.len() > 100 {
        let large_inputs: Vec<u8> = input.inputs.iter().cycle().take(10000).copied().collect();
        let _ = default_pure.compute_jitter(&input.secret, &large_inputs, entropy);
    }

    // Test determinism: same inputs should produce same output
    let j1 = default_pure.compute_jitter(&input.secret, &input.inputs, entropy);
    let j2 = default_pure.compute_jitter(&input.secret, &input.inputs, entropy);
    assert_eq!(j1, j2, "PureJitter should be deterministic");
});
