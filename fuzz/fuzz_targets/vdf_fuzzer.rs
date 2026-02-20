#![no_main]
use libfuzzer_sys::fuzz_target;
use witnessd_core::vdf;
use std::time::Duration;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 { return; }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&data[..32]);
    
    let params = vdf::default_parameters();
    let _ = vdf::compute(seed, Duration::from_millis(10), params);
});
