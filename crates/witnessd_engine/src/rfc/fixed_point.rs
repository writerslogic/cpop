// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Fixed-point integer types for RFC-compliant CBOR encoding.
//!
//! This module implements fixed-point integer representations as specified
//! in draft-condrey-rats-pop-schema-01 Section 3 (Numeric Representation).
//!
//! Fixed-point integers replace IEEE 754 floating-point for security-critical
//! values because:
//! 1. Cross-platform reproducibility: Integer arithmetic is fully specified
//!    by CBOR (RFC 8949) with no implementation latitude.
//! 2. Constant-time operations: Integer comparison executes in constant time,
//!    eliminating timing side-channels.
//! 3. Deterministic encoding: Integers have a single canonical CBOR encoding,
//!    ensuring identical hash inputs across implementations.
//!
//! # Scaling Conventions (Bitcoin-style)
//!
//! | Type       | Scale Factor | Range       | Example              |
//! |------------|--------------|-------------|----------------------|
//! | Millibits  | x1000        | 0-1000      | 0.95 → 950           |
//! | Centibits  | x10000       | 0-10000     | 0.0005 → 5           |
//! | Decibits   | x10          | 0-640       | 3.2 bits → 32        |
//! | DeciWpm    | x10          | 0-5000      | 45.5 WPM → 455       |
//!
//! Signed versions use the same scaling for values like Spearman rho.

use serde::{Deserialize, Serialize};
use std::ops::{Add, Sub};

/// Fixed-point ratio with scale factor x1000.
///
/// Represents values in the range [0.0, 1.0] as integers [0, 1000].
/// Used for: confidence, coverage, activity ratios.
///
/// # Examples
/// ```ignore
/// let confidence = Millibits::from_float(0.95); // 950
/// let as_float: f64 = confidence.into();        // 0.95
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Millibits(pub u16);

impl Millibits {
    /// Maximum value (1.0 = 1000 millibits)
    pub const MAX: Millibits = Millibits(1000);

    /// Minimum value (0.0 = 0 millibits)
    pub const MIN: Millibits = Millibits(0);

    /// Creates a new Millibits value from raw integer.
    #[inline]
    pub const fn new(value: u16) -> Self {
        Millibits(value)
    }

    /// Creates from a floating-point value using banker's rounding.
    pub fn from_float(value: f64) -> Self {
        let scaled = (value * 1000.0).round() as i32;
        let clamped = scaled.clamp(0, 1000) as u16;
        Millibits(clamped)
    }

    /// Returns the raw integer value.
    #[inline]
    pub const fn raw(&self) -> u16 {
        self.0
    }

    /// Converts to floating-point for display (not for verification).
    #[inline]
    pub fn to_float(&self) -> f64 {
        self.0 as f64 / 1000.0
    }
}

impl From<f64> for Millibits {
    fn from(value: f64) -> Self {
        Millibits::from_float(value)
    }
}

impl From<Millibits> for f64 {
    fn from(value: Millibits) -> Self {
        value.to_float()
    }
}

impl Serialize for Millibits {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u16(self.0)
    }
}

impl<'de> Deserialize<'de> for Millibits {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = u16::deserialize(deserializer)?;
        Ok(Millibits(value))
    }
}

/// Signed fixed-point with scale factor x1000.
///
/// Represents values in the range [-1.0, 1.0] as integers [-1000, 1000].
/// Used for: Spearman rho correlation coefficients.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct RhoMillibits(pub i16);

impl RhoMillibits {
    /// Maximum value (+1.0 = +1000)
    pub const MAX: RhoMillibits = RhoMillibits(1000);

    /// Minimum value (-1.0 = -1000)
    pub const MIN: RhoMillibits = RhoMillibits(-1000);

    /// Creates a new RhoMillibits value from raw integer.
    #[inline]
    pub const fn new(value: i16) -> Self {
        RhoMillibits(value)
    }

    /// Creates from a floating-point value using banker's rounding.
    pub fn from_float(value: f64) -> Self {
        let scaled = (value * 1000.0).round() as i32;
        let clamped = scaled.clamp(-1000, 1000) as i16;
        RhoMillibits(clamped)
    }

    /// Returns the raw integer value.
    #[inline]
    pub const fn raw(&self) -> i16 {
        self.0
    }

    /// Converts to floating-point for display.
    #[inline]
    pub fn to_float(&self) -> f64 {
        self.0 as f64 / 1000.0
    }
}

impl From<f64> for RhoMillibits {
    fn from(value: f64) -> Self {
        RhoMillibits::from_float(value)
    }
}

impl From<RhoMillibits> for f64 {
    fn from(value: RhoMillibits) -> Self {
        value.to_float()
    }
}

impl Serialize for RhoMillibits {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_i16(self.0)
    }
}

impl<'de> Deserialize<'de> for RhoMillibits {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = i16::deserialize(deserializer)?;
        Ok(RhoMillibits(value))
    }
}

/// Fixed-point ratio with scale factor x10000.
///
/// Represents fine ratios in the range [0.0, 1.0] as integers [0, 10000].
/// Used for: differential privacy epsilon, p-values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Centibits(pub u16);

impl Centibits {
    /// Maximum value (1.0 = 10000 centibits)
    pub const MAX: Centibits = Centibits(10000);

    /// Minimum value (0.0 = 0 centibits)
    pub const MIN: Centibits = Centibits(0);

    /// Creates a new Centibits value from raw integer.
    #[inline]
    pub const fn new(value: u16) -> Self {
        Centibits(value)
    }

    /// Creates from a floating-point value using banker's rounding.
    pub fn from_float(value: f64) -> Self {
        let scaled = (value * 10000.0).round() as i32;
        let clamped = scaled.clamp(0, 10000) as u16;
        Centibits(clamped)
    }

    /// Returns the raw integer value.
    #[inline]
    pub const fn raw(&self) -> u16 {
        self.0
    }

    /// Converts to floating-point for display.
    #[inline]
    pub fn to_float(&self) -> f64 {
        self.0 as f64 / 10000.0
    }
}

impl From<f64> for Centibits {
    fn from(value: f64) -> Self {
        Centibits::from_float(value)
    }
}

impl From<Centibits> for f64 {
    fn from(value: Centibits) -> Self {
        value.to_float()
    }
}

impl Serialize for Centibits {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u16(self.0)
    }
}

impl<'de> Deserialize<'de> for Centibits {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = u16::deserialize(deserializer)?;
        Ok(Centibits(value))
    }
}

/// Fixed-point entropy with scale factor x10.
///
/// Represents entropy values in the range [0.0, 64.0] bits as integers [0, 640].
/// Used for: Shannon entropy measurements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Decibits(pub u16);

impl Decibits {
    /// Maximum value (64.0 bits = 640 decibits)
    pub const MAX: Decibits = Decibits(640);

    /// Minimum value (0.0 bits = 0 decibits)
    pub const MIN: Decibits = Decibits(0);

    /// Creates a new Decibits value from raw integer.
    #[inline]
    pub const fn new(value: u16) -> Self {
        Decibits(value)
    }

    /// Creates from a floating-point value using banker's rounding.
    pub fn from_float(value: f64) -> Self {
        let scaled = (value * 10.0).round() as i32;
        let clamped = scaled.clamp(0, 640) as u16;
        Decibits(clamped)
    }

    /// Returns the raw integer value.
    #[inline]
    pub const fn raw(&self) -> u16 {
        self.0
    }

    /// Converts to floating-point for display.
    #[inline]
    pub fn to_float(&self) -> f64 {
        self.0 as f64 / 10.0
    }
}

impl From<f64> for Decibits {
    fn from(value: f64) -> Self {
        Decibits::from_float(value)
    }
}

impl From<Decibits> for f64 {
    fn from(value: Decibits) -> Self {
        value.to_float()
    }
}

impl Serialize for Decibits {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u16(self.0)
    }
}

impl<'de> Deserialize<'de> for Decibits {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = u16::deserialize(deserializer)?;
        Ok(Decibits(value))
    }
}

/// Signed fixed-point with scale factor x10 for noise slopes.
///
/// Represents 1/f noise slope in the range [-10.0, +10.0] as integers [-100, 100].
/// Used for: pink noise slope (typically around -1.0).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct SlopeDecibits(pub i8);

impl SlopeDecibits {
    /// Maximum value (+10.0 = +100)
    pub const MAX: SlopeDecibits = SlopeDecibits(100);

    /// Minimum value (-10.0 = -100)
    pub const MIN: SlopeDecibits = SlopeDecibits(-100);

    /// Creates a new SlopeDecibits value from raw integer.
    #[inline]
    pub const fn new(value: i8) -> Self {
        SlopeDecibits(value)
    }

    /// Creates from a floating-point value using banker's rounding.
    pub fn from_float(value: f64) -> Self {
        let scaled = (value * 10.0).round() as i32;
        let clamped = scaled.clamp(-100, 100) as i8;
        SlopeDecibits(clamped)
    }

    /// Returns the raw integer value.
    #[inline]
    pub const fn raw(&self) -> i8 {
        self.0
    }

    /// Converts to floating-point for display.
    #[inline]
    pub fn to_float(&self) -> f64 {
        self.0 as f64 / 10.0
    }
}

impl From<f64> for SlopeDecibits {
    fn from(value: f64) -> Self {
        SlopeDecibits::from_float(value)
    }
}

impl From<SlopeDecibits> for f64 {
    fn from(value: SlopeDecibits) -> Self {
        value.to_float()
    }
}

impl Serialize for SlopeDecibits {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_i8(self.0)
    }
}

impl<'de> Deserialize<'de> for SlopeDecibits {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = i8::deserialize(deserializer)?;
        Ok(SlopeDecibits(value))
    }
}

/// Fixed-point words-per-minute with scale factor x10.
///
/// Represents typing rate in the range [0.0, 500.0] WPM as integers [0, 5000].
/// Used for: effective typing rate measurements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct DeciWpm(pub u16);

impl DeciWpm {
    /// Maximum value (500.0 WPM = 5000 deci-WPM)
    pub const MAX: DeciWpm = DeciWpm(5000);

    /// Minimum value (0.0 WPM = 0 deci-WPM)
    pub const MIN: DeciWpm = DeciWpm(0);

    /// Creates a new DeciWpm value from raw integer.
    #[inline]
    pub const fn new(value: u16) -> Self {
        DeciWpm(value)
    }

    /// Creates from a floating-point value using banker's rounding.
    pub fn from_float(value: f64) -> Self {
        let scaled = (value * 10.0).round() as i32;
        let clamped = scaled.clamp(0, 5000) as u16;
        DeciWpm(clamped)
    }

    /// Returns the raw integer value.
    #[inline]
    pub const fn raw(&self) -> u16 {
        self.0
    }

    /// Converts to floating-point for display.
    #[inline]
    pub fn to_float(&self) -> f64 {
        self.0 as f64 / 10.0
    }
}

impl From<f64> for DeciWpm {
    fn from(value: f64) -> Self {
        DeciWpm::from_float(value)
    }
}

impl From<DeciWpm> for f64 {
    fn from(value: DeciWpm) -> Self {
        value.to_float()
    }
}

impl Serialize for DeciWpm {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u16(self.0)
    }
}

impl<'de> Deserialize<'de> for DeciWpm {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = u16::deserialize(deserializer)?;
        Ok(DeciWpm(value))
    }
}

/// Economic cost in microdollars (USD x 1,000,000).
///
/// Represents monetary values with 6 decimal places of precision.
/// Used for: forgery cost bounds, economic attack analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Microdollars(pub u64);

impl Microdollars {
    /// Creates a new Microdollars value from raw integer.
    #[inline]
    pub const fn new(value: u64) -> Self {
        Microdollars(value)
    }

    /// Creates from a floating-point dollar value.
    pub fn from_dollars(value: f64) -> Self {
        let scaled = (value * 1_000_000.0).round() as i64;
        let clamped = scaled.max(0) as u64;
        Microdollars(clamped)
    }

    /// Returns the raw integer value.
    #[inline]
    pub const fn raw(&self) -> u64 {
        self.0
    }

    /// Converts to floating-point dollars for display.
    #[inline]
    pub fn to_dollars(&self) -> f64 {
        self.0 as f64 / 1_000_000.0
    }
}

impl Serialize for Microdollars {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u64(self.0)
    }
}

impl<'de> Deserialize<'de> for Microdollars {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        Ok(Microdollars(value))
    }
}

impl Add for Millibits {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        Millibits((self.0 + other.0).min(1000))
    }
}

impl Sub for Millibits {
    type Output = Self;
    fn sub(self, other: Self) -> Self {
        Millibits(self.0.saturating_sub(other.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_millibits_roundtrip() {
        let values = [0.0, 0.5, 0.95, 1.0, 0.001, 0.999];
        for v in values {
            let mb = Millibits::from_float(v);
            let back: f64 = mb.into();
            assert!(
                (back - v).abs() < 0.001,
                "value {} roundtripped to {}",
                v,
                back
            );
        }
    }

    #[test]
    fn test_millibits_clamping() {
        assert_eq!(Millibits::from_float(-0.5).raw(), 0);
        assert_eq!(Millibits::from_float(1.5).raw(), 1000);
    }

    #[test]
    fn test_rho_millibits_signed() {
        let rho = RhoMillibits::from_float(-0.75);
        assert_eq!(rho.raw(), -750);
        assert!((rho.to_float() - (-0.75)).abs() < 0.001);
    }

    #[test]
    fn test_centibits_precision() {
        let epsilon = Centibits::from_float(0.0005);
        assert_eq!(epsilon.raw(), 5);
        assert!((epsilon.to_float() - 0.0005).abs() < 0.0001);
    }

    #[test]
    fn test_decibits_entropy() {
        let entropy = Decibits::from_float(3.2);
        assert_eq!(entropy.raw(), 32);
        assert!((entropy.to_float() - 3.2).abs() < 0.1);
    }

    #[test]
    fn test_slope_decibits_negative() {
        let slope = SlopeDecibits::from_float(-1.2);
        assert_eq!(slope.raw(), -12);
        assert!((slope.to_float() - (-1.2)).abs() < 0.1);
    }

    #[test]
    fn test_deci_wpm() {
        let wpm = DeciWpm::from_float(45.5);
        assert_eq!(wpm.raw(), 455);
        assert!((wpm.to_float() - 45.5).abs() < 0.1);
    }

    #[test]
    fn test_microdollars() {
        let cost = Microdollars::from_dollars(0.05);
        assert_eq!(cost.raw(), 50000);
        assert!((cost.to_dollars() - 0.05).abs() < 0.000001);
    }

    #[test]
    fn test_millibits_serde() {
        let mb = Millibits::from_float(0.75);
        let json = serde_json::to_string(&mb).unwrap();
        assert_eq!(json, "750");
        let decoded: Millibits = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, mb);
    }

    #[test]
    fn test_millibits_arithmetic() {
        let a = Millibits::new(300);
        let b = Millibits::new(400);
        assert_eq!((a + b).raw(), 700);
        assert_eq!((b - a).raw(), 100);
        assert_eq!((a - b).raw(), 0); // saturating
    }
}
