// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! A newtype guaranteeing a value lies in `[0.0, 1.0]`.
//!
//! Use `Probability::clamp(v)` at computation boundaries and store the
//! result in struct fields typed as `Probability` to enforce the invariant
//! at the type level.

use serde::{Deserialize, Serialize};
use std::fmt;

/// A value guaranteed to be in `[0.0, 1.0]`.
///
/// Wraps probability, confidence, ratio, similarity, and score fields that
/// are mathematically bounded to the unit interval. During the transition
/// period, `Deref<Target = f64>` provides transparent read access.
#[derive(Clone, Copy, PartialEq, PartialOrd)]
pub struct Probability(f64);

/// Error returned when a value outside `[0.0, 1.0]` is passed to
/// [`Probability::new`].
#[derive(Debug, Clone)]
pub struct ProbabilityError(f64);

impl fmt::Display for ProbabilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "value {} is not in [0.0, 1.0]", self.0)
    }
}

impl std::error::Error for ProbabilityError {}

impl Probability {
    pub const ZERO: Self = Self(0.0);
    pub const ONE: Self = Self(1.0);

    /// Create a `Probability` from a value that must already lie in
    /// `[0.0, 1.0]`.  Returns `Err` for NaN, infinities, or out-of-range
    /// values.
    pub fn new(value: f64) -> Result<Self, ProbabilityError> {
        if !value.is_finite() || !(0.0..=1.0).contains(&value) {
            return Err(ProbabilityError(value));
        }
        Ok(Self(value))
    }

    /// Clamp an arbitrary `f64` into `[0.0, 1.0]`.
    ///
    /// Non-finite values (NaN, +Inf, -Inf) map to `0.0`.
    pub fn clamp(value: f64) -> Self {
        if !value.is_finite() {
            Self(0.0)
        } else {
            Self(value.clamp(0.0, 1.0))
        }
    }

    /// Return the inner `f64`.
    #[inline]
    pub fn get(self) -> f64 {
        self.0
    }
}

impl Default for Probability {
    fn default() -> Self {
        Self::ZERO
    }
}

impl fmt::Debug for Probability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Probability({:.6})", self.0)
    }
}

impl fmt::Display for Probability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl std::ops::Deref for Probability {
    type Target = f64;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Probability> for f64 {
    fn from(p: Probability) -> Self {
        p.0
    }
}

impl PartialEq<f64> for Probability {
    fn eq(&self, other: &f64) -> bool {
        self.0 == *other
    }
}

impl PartialOrd<f64> for Probability {
    fn partial_cmp(&self, other: &f64) -> Option<std::cmp::Ordering> {
        self.0.partial_cmp(other)
    }
}

impl Serialize for Probability {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Probability {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let v = f64::deserialize(deserializer)?;
        Ok(Self::clamp(v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_accepts_valid_range() {
        assert!(Probability::new(0.0).is_ok());
        assert!(Probability::new(0.5).is_ok());
        assert!(Probability::new(1.0).is_ok());
    }

    #[test]
    fn new_rejects_out_of_range() {
        assert!(Probability::new(-0.1).is_err());
        assert!(Probability::new(1.1).is_err());
        assert!(Probability::new(f64::NAN).is_err());
        assert!(Probability::new(f64::INFINITY).is_err());
        assert!(Probability::new(f64::NEG_INFINITY).is_err());
    }

    #[test]
    fn clamp_normalizes_values() {
        assert_eq!(Probability::clamp(0.5).get(), 0.5);
        assert_eq!(Probability::clamp(-1.0).get(), 0.0);
        assert_eq!(Probability::clamp(2.0).get(), 1.0);
        assert_eq!(Probability::clamp(f64::NAN).get(), 0.0);
        assert_eq!(Probability::clamp(f64::INFINITY).get(), 0.0);
        assert_eq!(Probability::clamp(f64::NEG_INFINITY).get(), 0.0);
    }

    #[test]
    fn constants() {
        assert_eq!(Probability::ZERO.get(), 0.0);
        assert_eq!(Probability::ONE.get(), 1.0);
    }

    #[test]
    fn default_is_zero() {
        assert_eq!(Probability::default(), Probability::ZERO);
    }

    #[test]
    fn deref_to_f64() {
        let p = Probability::new(0.75).unwrap();
        let r: &f64 = &p;
        assert_eq!(*r, 0.75);
    }

    #[test]
    fn comparison_with_f64() {
        let p = Probability::new(0.5).unwrap();
        assert!(p > 0.4);
        assert!(p < 0.6);
        assert!(p == 0.5);
    }

    #[test]
    fn serde_roundtrip() {
        let p = Probability::new(0.42).unwrap();
        let json = serde_json::to_string(&p).unwrap();
        assert_eq!(json, "0.42");
        let back: Probability = serde_json::from_str(&json).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn serde_deserialize_clamps_out_of_range() {
        let back: Probability = serde_json::from_str("1.5").unwrap();
        assert_eq!(back.get(), 1.0);
        let back: Probability = serde_json::from_str("-0.5").unwrap();
        assert_eq!(back.get(), 0.0);
    }

    #[test]
    fn from_into_f64() {
        let p = Probability::new(0.9).unwrap();
        let v: f64 = p.into();
        assert_eq!(v, 0.9);
    }
}
