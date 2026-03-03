#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use wld_jitter::{Evidence, EvidenceChain, PhysHash, PureJitter};

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    secret: [u8; 32],
    inputs: Vec<u8>,
    jitter: u32,
    chain_records: u8, // Number of records to add
    phys_hash: [u8; 32],
    entropy_bits: u8,
}

fuzz_target!(|input: FuzzInput| {
    let engine = PureJitter::default();

    // Bound jitter to reasonable range
    let jitter = 500 + (input.jitter % 2500);

    // Create Pure evidence and verify
    let pure_evidence = Evidence::pure(jitter);
    let _ = pure_evidence.verify(&input.secret, &input.inputs, &engine);

    // Create Phys evidence and verify
    let phys_hash = PhysHash {
        hash: input.phys_hash,
        entropy_bits: input.entropy_bits,
    };
    let phys_evidence = Evidence::phys(phys_hash, jitter);
    let _ = phys_evidence.verify(&input.secret, &input.inputs, &engine);

    // Verify with potentially wrong inputs
    let _ = pure_evidence.verify(&input.secret, b"wrong inputs", &engine);
    let _ = phys_evidence.verify(&input.secret, b"wrong inputs", &engine);

    // Test chain integrity
    let mut chain = EvidenceChain::with_secret(input.secret);
    let num_records = input.chain_records.min(100) as u32;
    for i in 0..num_records {
        let record_jitter = 500 + (i * 17) % 2500;
        chain.append(Evidence::pure(record_jitter));
    }

    // Verify integrity with correct secret
    let _ = chain.verify_integrity(&input.secret);

    // Verify integrity with wrong secret
    let mut wrong_secret = input.secret;
    wrong_secret[0] = wrong_secret[0].wrapping_add(1);
    let _ = chain.verify_integrity(&wrong_secret);

    // Test chain verification with inputs
    if !input.inputs.is_empty() && num_records > 0 {
        // Create inputs matching the number of records
        let inputs: Vec<&[u8]> = (0..num_records)
            .map(|_| input.inputs.as_slice())
            .collect();
        let _ = chain.verify_chain(&input.secret, &inputs, &engine);
    }

    // Test empty chain
    let empty_chain = EvidenceChain::with_secret(input.secret);
    let _ = empty_chain.verify_integrity(&input.secret);
    let empty_inputs: Vec<&[u8]> = vec![];
    let _ = empty_chain.verify_chain(&input.secret, &empty_inputs, &engine);
});
