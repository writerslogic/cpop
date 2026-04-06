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
    mac.update(b"cpop_jitter/v1/jitter");
    
    // Length-prefix each field to prevent concatenation ambiguity.
    // Safe truncation: turns silent integer wrap in release builds into a secure panic.
    let input_len: u32 = inputs.len().try_into().expect("inputs exceeds u32 length prefix");
    let extra_len: u32 = extra.len().try_into().expect("extra exceeds u32 length prefix");
    
    mac.update(&input_len.to_be_bytes());
    mac.update(inputs);
    mac.update(&extra_len.to_be_bytes());
    mac.update(extra);
    
    let result = mac.finalize().into_bytes();
    let hash_val = u32::from_be_bytes([result[0], result[1], result[2], result[3]]);
    let jitter = ((hash_val as u64 * range as u64) >> 32) as u32;
    jmin.saturating_add(jitter)
}

pub trait EntropySource {
    fn sample(&self, inputs: &[u8]) -> Result<PhysHash, Error>;
    fn validate(&self, hash: PhysHash) -> bool;
}

pub trait JitterEngine {
    fn compute_jitter(&self, secret: &[u8; 32], inputs: &[u8], entropy: PhysHash) -> Jitter;
}