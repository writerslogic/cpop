// SPDX-License-Identifier: Apache-2.0

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::{Error, Jitter, PhysHash};

type HmacSha256 = Hmac<Sha256>;

/// Compute jitter via HMAC-SHA256 with domain separation.
#[inline]
pub(crate) fn hmac_jitter(
    secret: &[u8; 32],
    inputs: &[u8],
    extra: &[u8],
    jmin: u32,
    range: u32,
) -> Jitter {
    debug_assert!(range > 0, "range must be > 0");
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key size");
    mac.update(b"cpop_jitter/v1/jitter");
    // Length-prefix each field to prevent concatenation ambiguity:
    // HMAC("AB", "CD") != HMAC("ABC", "D")
    // Truncation to u32 is safe: inputs are keystroke data (never >4 GiB).
    // Debug-assert guards against misuse; release builds saturate harmlessly.
    debug_assert!(
        inputs.len() <= u32::MAX as usize,
        "inputs exceeds u32 length prefix"
    );
    debug_assert!(
        extra.len() <= u32::MAX as usize,
        "extra exceeds u32 length prefix"
    );
    mac.update(&(inputs.len() as u32).to_be_bytes());
    mac.update(inputs);
    mac.update(&(extra.len() as u32).to_be_bytes());
    mac.update(extra);
    let result = mac.finalize().into_bytes();
    let hash_val = u32::from_be_bytes([result[0], result[1], result[2], result[3]]);
    // Bias-free reduction: multiply-then-shift avoids modulo bias
    let jitter = ((hash_val as u64 * range as u64) >> 32) as u32;
    jmin.saturating_add(jitter)
}

pub trait EntropySource {
    /// Collect entropy sample, binding hardware state to `inputs` context.
    fn sample(&self, inputs: &[u8]) -> Result<PhysHash, Error>;

    fn validate(&self, hash: PhysHash) -> bool;
}

/// Compute jitter delays from entropy. Must use constant-time ops on secrets.
pub trait JitterEngine {
    fn compute_jitter(&self, secret: &[u8; 32], inputs: &[u8], entropy: PhysHash) -> Jitter;
}
