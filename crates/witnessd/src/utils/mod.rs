// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Shared engine-wide utility functions.

pub mod mlock;
pub mod stats;
pub mod time;

pub use stats::{
    coefficient_of_variation, mean, mean_and_sample_std_dev, mean_and_sample_variance,
    mean_and_std_dev, mean_and_variance, median, std_dev,
};
pub use time::now_ns;

/// Hash a filesystem path (its UTF-8 string representation) with SHA-256.
pub fn sha256_of_path(path: &std::path::Path) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(path.to_string_lossy().as_bytes()).into()
}

/// Return an error if any value in `vals` is NaN or infinite.
pub fn require_all_finite(vals: &[f64], context: &str) -> crate::error::Result<()> {
    if vals.iter().any(|x| !x.is_finite()) {
        return Err(crate::error::Error::validation(
            format!("{context}: contains NaN or infinity")
        ));
    }
    Ok(())
}

/// Return `fallback` when `v` is NaN or infinite.
pub fn finite_or(v: f64, fallback: f64) -> f64 {
    if v.is_finite() {
        v
    } else {
        fallback
    }
}

/// Return `Ok(x)` when `x` is finite, or a validation error when it is NaN or infinite.
pub fn finite(x: f64) -> crate::error::Result<f64> {
    if x.is_finite() {
        Ok(x)
    } else {
        Err(crate::error::Error::validation(format!("non-finite value: {x}")))
    }
}

/// Return a short hex string from the first 8 bytes (or fewer) of `hash`.
pub fn short_hex_id(hash: &[u8]) -> String {
    hex::encode(&hash[..hash.len().min(8)])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finite_or_returns_value_when_finite() {
        assert_eq!(finite_or(1.5, 0.0), 1.5);
        assert_eq!(finite_or(-3.0, 0.0), -3.0);
        assert_eq!(finite_or(0.0, 99.0), 0.0);
    }

    #[test]
    fn finite_or_returns_fallback_for_nan_and_inf() {
        assert_eq!(finite_or(f64::NAN, 42.0), 42.0);
        assert_eq!(finite_or(f64::INFINITY, -1.0), -1.0);
        assert_eq!(finite_or(f64::NEG_INFINITY, 0.0), 0.0);
    }

    #[test]
    fn finite_ok_for_finite_values() {
        assert_eq!(finite(1.5).unwrap(), 1.5);
        assert_eq!(finite(-3.0).unwrap(), -3.0);
        assert_eq!(finite(0.0).unwrap(), 0.0);
    }

    #[test]
    fn finite_err_for_nan_and_inf() {
        assert!(finite(f64::NAN).is_err());
        assert!(finite(f64::INFINITY).is_err());
        assert!(finite(f64::NEG_INFINITY).is_err());
    }

    #[test]
    fn short_hex_id_truncates_to_8_bytes() {
        let hash = [0xab; 32];
        assert_eq!(short_hex_id(&hash), "abababababababab");
    }

    #[test]
    fn short_hex_id_handles_short_input() {
        let hash = [0xff; 3];
        assert_eq!(short_hex_id(&hash), "ffffff");
    }

    #[test]
    fn short_hex_id_empty_input() {
        let hash: [u8; 0] = [];
        assert_eq!(short_hex_id(&hash), "");
    }
}
