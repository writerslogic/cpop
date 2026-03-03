#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use wld_jitter::{HumanModel, Jitter};

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    jitters: Vec<u32>,
    iki_values: Vec<u64>,
}

fuzz_target!(|input: FuzzInput| {
    let model = HumanModel::default();

    // Fuzz jitter validation with raw values
    let jitters: Vec<Jitter> = input.jitters.clone();
    let _ = model.validate(&jitters);

    // Fuzz jitter validation with values in reasonable range
    let bounded_jitters: Vec<Jitter> = input
        .jitters
        .iter()
        .map(|&j| j % 10000) // Keep in reasonable range
        .collect();
    let _ = model.validate(&bounded_jitters);

    // Fuzz IKI validation with raw values
    let _ = model.validate_iki(&input.iki_values);

    // Fuzz IKI validation with values in reasonable range
    let bounded_iki: Vec<u64> = input
        .iki_values
        .iter()
        .map(|&iki| iki % 5_000_000) // Keep in reasonable range (0-5s)
        .collect();
    let _ = model.validate_iki(&bounded_iki);

    // Test edge cases: empty sequences
    let _ = model.validate(&[]);
    let _ = model.validate_iki(&[]);

    // Test with single element
    if !input.jitters.is_empty() {
        let _ = model.validate(&[input.jitters[0]]);
    }
    if !input.iki_values.is_empty() {
        let _ = model.validate_iki(&[input.iki_values[0]]);
    }
});
