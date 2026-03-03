#![no_main]
use libfuzzer_sys::fuzz_target;
use wld_protocol::codec::decode_evidence;

fuzz_target!(|data: &[u8]| {
    // Attempt to decode any random byte stream
    let _ = decode_evidence(data);
});
