// SPDX-License-Identifier: Apache-2.0

//! Pure HMAC-based jitter engine (economic security model).

use crate::{Error, Jitter, JitterEngine, PhysHash};

#[derive(Debug, Clone)]
pub struct PureJitter {
    jmin: u32,
    range: u32,
}

impl PureJitter {
    /// Minimum jitter output in microseconds.
    pub fn jmin(&self) -> u32 {
        self.jmin
    }

    /// Range of jitter values above `jmin`.
    pub fn range(&self) -> u32 {
        self.range
    }
}

impl Default for PureJitter {
    fn default() -> Self {
        Self {
            jmin: 500,
            range: 2500,
        }
    }
}

impl PureJitter {
    /// Create a pure jitter engine.
    ///
    /// Returns `Error::InvalidParameter` if `range` is 0.
    pub fn new(jmin: u32, range: u32) -> Result<Self, Error> {
        if range == 0 {
            return Err(Error::InvalidParameter("range must be > 0"));
        }
        Ok(Self { jmin, range })
    }

    /// Create a pure jitter engine, returning `None` if `range` is 0.
    pub fn try_new(jmin: u32, range: u32) -> Option<Self> {
        Self::new(jmin, range).ok()
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
        let engine = PureJitter::new(500, 2500).unwrap();
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
    fn test_new_zero_range_returns_err() {
        assert!(PureJitter::new(500, 0).is_err());
        assert!(PureJitter::new(500, 100).is_ok());
    }

    #[test]
    fn test_try_new_zero_range() {
        assert!(PureJitter::try_new(500, 0).is_none());
        assert!(PureJitter::try_new(500, 100).is_some());
    }
}
