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

use crate::{Error, Jitter, PhysHash};

/// Source of physical entropy from hardware or environment.
///
/// This trait abstracts entropy collection, allowing different implementations
/// for various platforms and environments.
///
/// # Implementors
///
/// - [`PhysJitter`](crate::PhysJitter): Hardware entropy using TSC/timing
///
/// # Example
///
/// ```rust
/// use witnessd_jitter::{PhysJitter, EntropySource};
///
/// let source = PhysJitter::new(8); // Require 8 bits minimum entropy
///
/// match source.sample(b"context data") {
///     Ok(entropy) => {
///         if source.validate(entropy) {
///             println!("Valid entropy collected");
///         }
///     }
///     Err(e) => println!("Entropy collection failed: {}", e),
/// }
/// ```
pub trait EntropySource {
    /// Collect entropy sample, mixing with provided inputs.
    ///
    /// The `inputs` parameter allows binding the entropy to specific context
    /// (e.g., keystroke data), making the resulting hash unique to both the
    /// hardware state and the input.
    ///
    /// # Arguments
    ///
    /// * `inputs` - Context data to mix with entropy (typically keystroke bytes)
    ///
    /// # Returns
    ///
    /// A [`PhysHash`] containing the entropy hash and metadata.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InsufficientEntropy`](crate::Error::InsufficientEntropy)
    /// if the collected entropy doesn't meet the minimum threshold.
    fn sample(&self, inputs: &[u8]) -> Result<PhysHash, Error>;

    /// Validate that a captured hash meets statistical requirements.
    ///
    /// This allows verifying that previously captured entropy meets the
    /// current configuration's requirements.
    ///
    /// # Arguments
    ///
    /// * `hash` - The entropy hash to validate
    ///
    /// # Returns
    ///
    /// `true` if the entropy meets requirements, `false` otherwise.
    fn validate(&self, hash: PhysHash) -> bool;
}

/// Engine that computes jitter delays from entropy.
///
/// This trait abstracts the jitter computation algorithm, allowing different
/// security models to be implemented.
///
/// # Implementors
///
/// - [`PureJitter`](crate::PureJitter): HMAC-based, deterministic
/// - [`PhysJitter`](crate::PhysJitter): Uses hardware entropy
///
/// # Security Considerations
///
/// Implementations should:
/// - Use constant-time operations where secrets are involved
/// - Not leak secret material in error messages
/// - Produce values in the expected human typing range (typically 500-3000μs)
///
/// # Example
///
/// ```rust
/// use witnessd_jitter::{PureJitter, JitterEngine};
///
/// let engine = PureJitter::default();
/// let secret = [0u8; 32];
/// let entropy = [0u8; 32].into();
///
/// let jitter = engine.compute_jitter(&secret, b"keystroke-a", entropy);
/// assert!(jitter >= 500 && jitter < 3000);
///
/// // Same inputs always produce same output (deterministic)
/// let jitter2 = engine.compute_jitter(&secret, b"keystroke-a", entropy);
/// assert_eq!(jitter, jitter2);
/// ```
pub trait JitterEngine {
    /// Compute jitter delay from secret, inputs, and entropy.
    ///
    /// # Arguments
    ///
    /// * `secret` - 32-byte session secret (keep confidential!)
    /// * `inputs` - Input data (typically keystroke bytes)
    /// * `entropy` - Entropy hash (from [`EntropySource::sample`] or zeros for pure mode)
    ///
    /// # Returns
    ///
    /// Jitter delay in microseconds. Typical range is 500-3000μs.
    ///
    /// # Security
    ///
    /// The `secret` parameter must be kept confidential. Compromise of the
    /// secret allows an attacker to compute valid jitter values (though they
    /// would still need to match the exact input sequence).
    fn compute_jitter(&self, secret: &[u8; 32], inputs: &[u8], entropy: PhysHash) -> Jitter;
}
