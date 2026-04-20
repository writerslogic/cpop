// SPDX-License-Identifier: Apache-2.0

//! JitterEngine trait, clock abstractions
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::{Error, Jitter, PhysHash};

type HmacSha256 = Hmac<Sha256>;

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
    mac.update(b"cpoe_jitter/v1/jitter");

    // Length-prefix each field to prevent concatenation ambiguity.
    // Safe truncation: turns silent integer wrap in release builds into a secure panic.
    // Cast to u64 natively to prevent panic on massive inputs
    let input_len = inputs.len() as u64;
    let extra_len = extra.len() as u64;

    mac.update(&input_len.to_be_bytes());
    mac.update(inputs);
    mac.update(&extra_len.to_be_bytes());
    mac.update(extra);

    let result = mac.finalize().into_bytes();
    let hash_val = u32::from_be_bytes([result[0], result[1], result[2], result[3]]);
    let jitter = ((hash_val as u64 * range as u64) >> 32) as u32;
    jmin.saturating_add(jitter)
}

/// Hardware entropy abstraction for timing-based entropy collection.
///
/// Implementations sample physical timing jitter and return a hash with an
/// entropy estimate. `validate` checks whether a sample meets sufficiency
/// thresholds.
pub trait EntropySource {
    /// Collect a hardware entropy sample, mixing `inputs` into the result.
    fn sample(&self, inputs: &[u8]) -> Result<PhysHash, Error>;
    /// Return `true` if `hash` meets the minimum entropy threshold.
    fn validate(&self, hash: PhysHash) -> bool;
}

/// Compute deterministic jitter from a secret, caller inputs, and an entropy hash.
///
/// The output is a jitter value in microseconds, derived via HMAC so that
/// identical inputs always produce the same result.
pub trait JitterEngine {
    /// Compute jitter in microseconds from `secret`, `inputs`, and `entropy`.
    fn compute_jitter(&self, secret: &[u8; 32], inputs: &[u8], entropy: PhysHash) -> Jitter;
}
