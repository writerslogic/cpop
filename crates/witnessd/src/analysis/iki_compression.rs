// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! IKI compression ratio analysis.
//!
//! Quantizes IKI intervals to milliseconds and measures information density
//! via byte-level entropy estimation. Highly compressible (low entropy) data
//! suggests LLM-like replay; incompressible (high entropy) suggests random noise.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Comprehensive error type for IKI Compression analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IkiCompressionError {
    InsufficientSamples { found: usize, required: usize },
    InvalidInputExceedsBounds,
    NonFiniteValues,
    EmptyByteStream,
}

impl fmt::Display for IkiCompressionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientSamples { found, required } => write!(
                f,
                "Insufficient IKI samples: found {}, minimum {} required",
                found, required
            ),
            Self::InvalidInputExceedsBounds => write!(f, "IKI values exceed 10^12 ns (>1000s); likely invalid input"),
            Self::NonFiniteValues => write!(f, "Input contains non-finite values"),
            Self::EmptyByteStream => write!(f, "No valid positive intervals to compress"),
        }
    }
}

impl std::error::Error for IkiCompressionError {}

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
/// Quantizes IKI intervals to millisecond precision and computes normalized 
/// Shannon entropy on the fly with zero heap allocations.
pub fn analyze_iki_compression(iki_intervals_ns: &[f64]) -> Result<IkiCompressionAnalysis, IkiCompressionError> {
    if iki_intervals_ns.iter().any(|&v| v > 1_000_000_000_000.0) {
        return Err(IkiCompressionError::InvalidInputExceedsBounds);
    }
    if iki_intervals_ns.len() < MIN_SAMPLES {
        return Err(IkiCompressionError::InsufficientSamples {
            found: iki_intervals_ns.len(),
            required: MIN_SAMPLES,
        });
    }
    if crate::utils::require_all_finite(iki_intervals_ns, "iki_compression").is_err() {
        return Err(IkiCompressionError::NonFiniteValues);
    }

    // Compute frequencies directly without allocating a Vec<u8> byte stream
    let mut freq = [0u64; 256];
    let mut negative_count = 0usize;
    let mut total_bytes = 0.0;

    for &iki_ns in iki_intervals_ns {
        let ms_f = (iki_ns / 1_000_000.0).round();
        if ms_f < 0.0 {
            negative_count += 1;
            continue;
        }
        let clamped = (ms_f as u64).min(u16::MAX as u64) as u16;
        let bytes = clamped.to_le_bytes();
        
        freq[bytes[0] as usize] += 1;
        freq[bytes[1] as usize] += 1;
        total_bytes += 2.0;
    }

    if negative_count > 0 {
        log::warn!("IKI compression: skipped {negative_count} negative IKI value(s)");
    }

    if total_bytes == 0.0 {
        return Err(IkiCompressionError::EmptyByteStream);
    }

    // Compute byte-level Shannon entropy
    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / total_bytes;
            entropy -= p * p.log2();
        }
    }

    // Normalize to [0, 1] where 8 bits = maximum entropy
    let ratio = entropy / 8.0;
    let flagged = !(LOW_RATIO_THRESHOLD..=HIGH_RATIO_THRESHOLD).contains(&ratio);

    Ok(IkiCompressionAnalysis { ratio, flagged })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compression_insufficient_data() {
        let data: Vec<f64> = (0..20).map(|i| i as f64 * 1_000_000.0).collect();
        assert!(matches!(
            analyze_iki_compression(&data),
            Err(IkiCompressionError::InsufficientSamples { .. })
        ));
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