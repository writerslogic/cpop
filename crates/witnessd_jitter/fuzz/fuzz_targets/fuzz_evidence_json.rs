#![no_main]

use libfuzzer_sys::fuzz_target;
use witnessd_jitter::{Evidence, EvidenceChain};

fuzz_target!(|data: &[u8]| {
    // Fuzz Evidence deserialization
    if let Ok(s) = std::str::from_utf8(data) {
        // Try to parse as Evidence
        let _ = serde_json::from_str::<Evidence>(s);

        // Try to parse as EvidenceChain
        let _ = serde_json::from_str::<EvidenceChain>(s);
    }

    // Also test with raw bytes interpreted as potentially valid JSON
    let _ = serde_json::from_slice::<Evidence>(data);
    let _ = serde_json::from_slice::<EvidenceChain>(data);
});
