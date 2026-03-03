// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Core traits for entropy sources and jitter engines.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::{Error, Jitter, PhysHash};

type HmacSha256 = Hmac<Sha256>;

/// Compute jitter via HMAC-SHA256 with domain separation.
pub(crate) fn hmac_jitter(
    secret: &[u8; 32],
    inputs: &[u8],
    extra: &[u8],
    jmin: u32,
    range: u32,
) -> Jitter {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key size");
    mac.update(b"witnessd_jitter/v1/jitter");
    mac.update(inputs);
    mac.update(extra);
    let result = mac.finalize().into_bytes();
    let hash_val = u32::from_be_bytes([result[0], result[1], result[2], result[3]]);
    jmin + (hash_val % range)
}

/// Source of physical entropy from hardware or environment.
pub trait EntropySource {
    /// Collect entropy sample, binding hardware state to `inputs` context.
    fn sample(&self, inputs: &[u8]) -> Result<PhysHash, Error>;

    /// Check that a captured hash meets the minimum entropy threshold.
    fn validate(&self, hash: PhysHash) -> bool;
}

/// Compute jitter delays from entropy. Must use constant-time ops on secrets.
pub trait JitterEngine {
    /// Compute jitter delay in microseconds.
    fn compute_jitter(&self, secret: &[u8; 32], inputs: &[u8], entropy: PhysHash) -> Jitter;
}
