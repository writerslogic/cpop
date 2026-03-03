// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Pure HMAC-based jitter engine (economic security model).
//!
//! Provides deterministic jitter computation using only cryptographic primitives.
//! Security relies on economic cost of retyping content identically.

use crate::{Jitter, JitterEngine, PhysHash};

/// Pure jitter engine using HMAC for deterministic delay computation.
///
/// Security model: Economic - attacker would need to retype content
/// character-by-character to reproduce the jitter sequence.
#[derive(Debug, Clone)]
pub struct PureJitter {
    /// Minimum jitter delay in microseconds.
    pub jmin: u32,
    /// Range for jitter variation in microseconds.
    pub range: u32,
}

impl Default for PureJitter {
    fn default() -> Self {
        Self {
            jmin: 500,   // 500μs minimum
            range: 2500, // Up to 3000μs total
        }
    }
}

impl PureJitter {
    /// Create with custom parameters.
    ///
    /// # Panics
    /// Panics if `range` is 0.
    pub fn new(jmin: u32, range: u32) -> Self {
        assert!(range > 0, "range must be greater than 0");
        Self { jmin, range }
    }

    /// Create with custom parameters, returning None if invalid.
    pub fn try_new(jmin: u32, range: u32) -> Option<Self> {
        if range == 0 {
            None
        } else {
            Some(Self { jmin, range })
        }
    }
}

impl JitterEngine for PureJitter {
    fn compute_jitter(&self, secret: &[u8; 32], inputs: &[u8], _entropy: PhysHash) -> Jitter {
        crate::traits::hmac_jitter(secret, inputs, &[], self.jmin, self.range)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_jitter() {
        let engine = PureJitter::default();
        let secret = [0u8; 32];
        let inputs = b"hello world";
        let entropy = PhysHash::from([0u8; 32]);

        let j1 = engine.compute_jitter(&secret, inputs, entropy);
        let j2 = engine.compute_jitter(&secret, inputs, entropy);

        assert_eq!(j1, j2, "Same inputs should produce same jitter");
    }

    #[test]
    fn test_jitter_range() {
        let engine = PureJitter::new(500, 2500);
        let secret = [42u8; 32];
        let entropy = PhysHash::from([0u8; 32]);

        for i in 0..100 {
            let inputs = format!("test input {}", i);
            let jitter = engine.compute_jitter(&secret, inputs.as_bytes(), entropy);
            assert!(jitter >= 500, "Jitter should be >= jmin");
            assert!(jitter < 3000, "Jitter should be < jmin + range");
        }
    }

    #[test]
    fn test_different_inputs_different_jitter() {
        let engine = PureJitter::default();
        let secret = [1u8; 32];
        let entropy = PhysHash::from([0u8; 32]);

        let j1 = engine.compute_jitter(&secret, b"input a", entropy);
        let j2 = engine.compute_jitter(&secret, b"input b", entropy);

        // Statistically should be different (collision unlikely)
        assert_ne!(j1, j2);
    }

    #[test]
    #[should_panic(expected = "range must be greater than 0")]
    fn test_new_zero_range_panics() {
        PureJitter::new(500, 0);
    }

    #[test]
    fn test_try_new_zero_range() {
        assert!(PureJitter::try_new(500, 0).is_none());
        assert!(PureJitter::try_new(500, 100).is_some());
    }
}
