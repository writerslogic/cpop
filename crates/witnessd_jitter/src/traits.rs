// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Core traits for entropy sources and jitter engines.
//!
//! This module defines the fundamental abstractions used throughout the crate:
//!
//! - [`EntropySource`]: Collects entropy from hardware or environment
//! - [`JitterEngine`]: Computes jitter delays from secrets and entropy
//!
//! # Implementing Custom Engines
//!
//! You can implement these traits to create custom jitter engines:
//!
//! ```rust
//! use witnessd_jitter::{EntropySource, JitterEngine, PhysHash, Jitter, Error};
//!
//! struct MyCustomEngine;
//!
//! impl JitterEngine for MyCustomEngine {
//!     fn compute_jitter(&self, secret: &[u8; 32], inputs: &[u8], entropy: PhysHash) -> Jitter {
//!         // Custom jitter computation
//!         1000 // Fixed 1ms for example
//!     }
//! }
//! ```

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::{Error, Jitter, PhysHash};

type HmacSha256 = Hmac<Sha256>;

/// Compute jitter via HMAC-SHA256 with domain separation.
///
/// Shared by both `PureJitter` and `PhysJitter`. The `extra` slice
/// lets `PhysJitter` mix in entropy hash bytes.
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
///
/// # Example
///
/// ```rust
/// use witnessd_jitter::{PhysJitter, EntropySource};
///
/// let source = PhysJitter::new(8);
/// match source.sample(b"context data") {
///     Ok(entropy) if source.validate(entropy) => { /* use entropy */ }
///     _ => { /* fallback */ }
/// }
/// ```
pub trait EntropySource {
    /// Collect entropy sample, binding hardware state to `inputs` context.
    fn sample(&self, inputs: &[u8]) -> Result<PhysHash, Error>;

    /// Check that a captured hash meets the minimum entropy threshold.
    fn validate(&self, hash: PhysHash) -> bool;
}

/// Engine that computes jitter delays from entropy.
///
/// Implementations must use constant-time operations where secrets are involved
/// and must not leak secret material in error messages.
///
/// # Example
///
/// ```rust
/// use witnessd_jitter::{PureJitter, JitterEngine};
///
/// let engine = PureJitter::default();
/// let secret = [0u8; 32];
/// let jitter = engine.compute_jitter(&secret, b"keystroke-a", [0u8; 32].into());
/// assert!(jitter >= 500 && jitter < 3000);
/// ```
pub trait JitterEngine {
    /// Compute jitter delay in microseconds. The `secret` must be kept confidential.
    fn compute_jitter(&self, secret: &[u8; 32], inputs: &[u8], entropy: PhysHash) -> Jitter;
}
