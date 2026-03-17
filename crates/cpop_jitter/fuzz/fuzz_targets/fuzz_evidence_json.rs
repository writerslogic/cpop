#![no_main]

use libfuzzer_sys::fuzz_target;
use cpop_jitter::{Evidence, EvidenceChain};

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<Evidence>(s);
        let _ = serde_json::from_str::<EvidenceChain>(s);
    }

    let _ = serde_json::from_slice::<Evidence>(data);
    let _ = serde_json::from_slice::<EvidenceChain>(data);
});
