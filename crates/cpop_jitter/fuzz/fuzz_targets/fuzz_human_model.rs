#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use cpop_jitter::{HumanModel, Jitter};

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    jitters: Vec<u32>,
    iki_values: Vec<u64>,
}

fuzz_target!(|input: FuzzInput| {
    let model = HumanModel::default();

    let jitters: Vec<Jitter> = input.jitters.clone();
    let _ = model.validate(&jitters);

    let bounded_jitters: Vec<Jitter> = input.jitters.iter().map(|&j| j % 10000).collect();
    let _ = model.validate(&bounded_jitters);

    let _ = model.validate_iki(&input.iki_values);

    let bounded_iki: Vec<u64> = input
        .iki_values
        .iter()
        .map(|&iki| iki % 5_000_000)
        .collect();
    let _ = model.validate_iki(&bounded_iki);

    let _ = model.validate(&[]);
    let _ = model.validate_iki(&[]);

    if !input.jitters.is_empty() {
        let _ = model.validate(&[input.jitters[0]]);
    }
    if !input.iki_values.is_empty() {
        let _ = model.validate_iki(&[input.iki_values[0]]);
    }
});
