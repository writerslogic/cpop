// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

/// Return `fallback` when `v` is NaN or infinite.
pub fn finite_or(v: f64, fallback: f64) -> f64 {
    if v.is_finite() { v } else { fallback }
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
