// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! IKI compression ratio analysis.
//!
//! Quantizes IKI intervals to milliseconds and measures information density
//! via byte-level entropy estimation. Highly compressible (low entropy) data
//! suggests LLM-like replay; incompressible (high entropy) suggests random noise.

use serde::{Deserialize, Serialize};

/// Compression ratio below this suggests generated/replay data (too structured).
const LOW_RATIO_THRESHOLD: f64 = 0.2;

/// Compression ratio above this suggests random noise (no temporal structure).
const HIGH_RATIO_THRESHOLD: f64 = 0.95;

/// Minimum IKI samples required.
const MIN_SAMPLES: usize = 50;

/// Result of IKI compression ratio analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IkiCompressionAnalysis {
    /// Estimated compression ratio (0.0-1.0). Lower = more compressible.
    pub ratio: f64,
    /// Whether the ratio is flagged as anomalous.
    pub flagged: bool,
}

/// Analyze IKI compression ratio using byte-level Shannon entropy as a proxy
/// for compressibility (avoids external compression library dependency).
///
/// Quantizes IKI intervals to millisecond precision, serializes as a byte
/// stream, and computes normalized Shannon entropy.
pub fn analyze_iki_compression(iki_intervals_ns: &[f64]) -> Option<IkiCompressionAnalysis> {
    if iki_intervals_ns.len() < MIN_SAMPLES {
        return None;
    }
    if iki_intervals_ns.iter().any(|x| !x.is_finite()) {
        return None;
    }

    // Quantize to milliseconds and serialize to bytes (little-endian u16, clamped)
    let mut bytes = Vec::with_capacity(iki_intervals_ns.len() * 2);
    for &iki_ns in iki_intervals_ns {
        let ms = (iki_ns / 1_000_000.0).round() as u64;
        let clamped = ms.min(u16::MAX as u64) as u16;
        bytes.extend_from_slice(&clamped.to_le_bytes());
    }

    // Compute byte-level Shannon entropy
    let mut freq = [0u64; 256];
    for &b in &bytes {
        freq[b as usize] += 1;
    }

    let total = bytes.len() as f64;
    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / total;
            entropy -= p * p.log2();
        }
    }

    // Normalize to [0, 1] where 8 bits = maximum entropy
    let ratio = entropy / 8.0;

    let flagged = !(LOW_RATIO_THRESHOLD..=HIGH_RATIO_THRESHOLD).contains(&ratio);

    Some(IkiCompressionAnalysis { ratio, flagged })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compression_insufficient_data() {
        let data: Vec<f64> = (0..20).map(|i| i as f64 * 1_000_000.0).collect();
        assert!(analyze_iki_compression(&data).is_none());
    }

    #[test]
    fn test_compression_constant_data() {
        // All same IKI → very compressible → low ratio → flagged
        let data = vec![150_000_000.0; 100];
        let result = analyze_iki_compression(&data).unwrap();
        assert!(
            result.ratio < LOW_RATIO_THRESHOLD,
            "Constant data ratio={:.3} should be below {}",
            result.ratio,
            LOW_RATIO_THRESHOLD
        );
        assert!(result.flagged);
    }

    #[test]
    fn test_compression_varied_data() {
        // Human-like varied typing — should have moderate entropy
        let data: Vec<f64> = (0..200)
            .map(|i| {
                let base = 150_000_000.0;
                let variation = ((i as f64 * 0.3).sin() * 80_000_000.0)
                    + ((i as f64 * 1.7).cos() * 40_000_000.0)
                    + (i as f64 * 7.0 % 30.0) * 1_000_000.0;
                base + variation
            })
            .collect();
        let result = analyze_iki_compression(&data).unwrap();
        // Should be in the acceptable range
        assert!(
            result.ratio >= LOW_RATIO_THRESHOLD && result.ratio <= HIGH_RATIO_THRESHOLD,
            "Varied data ratio={:.3} should be in range [{}, {}]",
            result.ratio,
            LOW_RATIO_THRESHOLD,
            HIGH_RATIO_THRESHOLD
        );
    }
}
