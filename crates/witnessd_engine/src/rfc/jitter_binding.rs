// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! RFC-compliant jitter-binding structure.
//!
//! Implements the 7-key CDDL structure from draft-condrey-rats-pop-01:
//! - entropy-commitment: Hash commitment to entropy sources
//! - sources: Entropy source descriptors
//! - summary: Statistical summary of jitter data
//! - binding-mac: HMAC binding to document state
//! - raw-intervals: Optional raw interval data (Enhanced/Maximum tiers)
//! - active-probes: Active behavioral probes (Galton Invariant, Reflex Gate)
//! - labyrinth-structure: Topological phase space analysis

use serde::{Deserialize, Serialize};

/// RFC-compliant jitter-binding structure.
///
/// CDDL Definition:
/// ```cddl
/// jitter-binding = {
///   1: entropy-commitment,      ; Hash commitment
///   2: [* source-descriptor],   ; Entropy sources
///   3: jitter-summary,          ; Statistical summary
///   4: binding-mac,             ; HMAC binding
///   ? 5: raw-intervals,         ; Raw data (optional)
///   ? 6: active-probes,         ; Behavioral probes (optional)
///   ? 7: labyrinth-structure    ; Phase space (optional)
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JitterBinding {
    /// Hash commitment to entropy sources (key 1).
    #[serde(rename = "1")]
    pub entropy_commitment: EntropyCommitment,

    /// Entropy source descriptors (key 2).
    #[serde(rename = "2")]
    pub sources: Vec<SourceDescriptor>,

    /// Statistical summary of jitter data (key 3).
    #[serde(rename = "3")]
    pub summary: JitterSummary,

    /// HMAC binding to document state (key 4).
    #[serde(rename = "4")]
    pub binding_mac: BindingMac,

    /// Raw interval data, optional (key 5).
    /// Only included for Enhanced/Maximum tiers.
    #[serde(rename = "5", skip_serializing_if = "Option::is_none")]
    pub raw_intervals: Option<RawIntervals>,

    /// Active behavioral probes, optional (key 6).
    /// Galton Invariant and Reflex Gate tests.
    #[serde(rename = "6", skip_serializing_if = "Option::is_none")]
    pub active_probes: Option<ActiveProbes>,

    /// Topological phase space analysis, optional (key 7).
    /// Takens' theorem delay-coordinate embedding.
    #[serde(rename = "7", skip_serializing_if = "Option::is_none")]
    pub labyrinth_structure: Option<LabyrinthStructure>,
}

/// Entropy commitment - hash of concatenated entropy sources.
///
/// CDDL Definition:
/// ```cddl
/// entropy-commitment = {
///   1: bstr .size 32,           ; SHA-256 hash of sources
///   2: uint,                    ; Timestamp (Unix epoch ms)
///   3: bstr .size 32            ; Previous commitment hash
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyCommitment {
    /// SHA-256 hash of concatenated entropy sources.
    #[serde(rename = "1", with = "hex_bytes")]
    pub hash: [u8; 32],

    /// Timestamp in Unix epoch milliseconds.
    #[serde(rename = "2")]
    pub timestamp_ms: u64,

    /// Previous commitment hash (chain linkage).
    #[serde(rename = "3", with = "hex_bytes")]
    pub previous_hash: [u8; 32],
}

/// Entropy source descriptor.
///
/// CDDL Definition:
/// ```cddl
/// source-descriptor = {
///   1: tstr,                    ; Source type identifier
///   2: uint,                    ; Contribution weight (0-1000)
///   ? 3: tstr,                  ; Device fingerprint (optional)
///   ? 4: transport-calibration  ; Transport calibration (optional)
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceDescriptor {
    /// Source type identifier (e.g., "keyboard.usb", "keyboard.bluetooth", "witnessd_jitter").
    #[serde(rename = "1")]
    pub source_type: String,

    /// Contribution weight (0-1000, where 1000 = 100%).
    #[serde(rename = "2")]
    pub weight: u16,

    /// Device fingerprint (optional).
    #[serde(rename = "3", skip_serializing_if = "Option::is_none")]
    pub device_fingerprint: Option<String>,

    /// Transport calibration data (optional).
    #[serde(rename = "4", skip_serializing_if = "Option::is_none")]
    pub transport_calibration: Option<TransportCalibration>,
}

/// Transport calibration data for per-transport baseline measurements.
///
/// CDDL Definition:
/// ```cddl
/// transport-calibration = {
///   1: tstr,                    ; Transport type (usb, bluetooth, internal, etc.)
///   2: uint,                    ; Baseline latency in microseconds
///   3: uint,                    ; Latency variance in microseconds
///   4: uint                     ; Calibration timestamp (Unix epoch ms)
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportCalibration {
    /// Transport type identifier.
    #[serde(rename = "1")]
    pub transport: String,

    /// Baseline latency in microseconds (minimum observed interval).
    #[serde(rename = "2")]
    pub baseline_latency_us: u64,

    /// Latency variance in microseconds.
    #[serde(rename = "3")]
    pub latency_variance_us: u64,

    /// Calibration timestamp in Unix epoch milliseconds.
    #[serde(rename = "4")]
    pub calibrated_at_ms: u64,
}

/// Jitter summary statistics.
///
/// CDDL Definition:
/// ```cddl
/// jitter-summary = {
///   1: uint,                    ; Sample count
///   2: float64,                 ; Mean interval (microseconds)
///   3: float64,                 ; Standard deviation
///   4: float64,                 ; Coefficient of variation
///   5: [5*float64],             ; Percentiles (10th, 25th, 50th, 75th, 90th)
///   6: float64,                 ; Entropy bits
///   ? 7: float64                ; Hurst exponent (optional)
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JitterSummary {
    /// Total number of samples.
    #[serde(rename = "1")]
    pub sample_count: u64,

    /// Mean interval in microseconds.
    #[serde(rename = "2")]
    pub mean_interval_us: f64,

    /// Standard deviation of intervals.
    #[serde(rename = "3")]
    pub std_dev: f64,

    /// Coefficient of variation (std_dev / mean).
    #[serde(rename = "4")]
    pub coefficient_of_variation: f64,

    /// Percentile distribution [10th, 25th, 50th, 75th, 90th].
    #[serde(rename = "5")]
    pub percentiles: [f64; 5],

    /// Shannon entropy in bits.
    #[serde(rename = "6")]
    pub entropy_bits: f64,

    /// Hurst exponent for long-range dependence (optional).
    /// H_e ≈ 0.7 for human input; reject 0.5 (white noise) or 1.0 (predictable).
    #[serde(rename = "7", skip_serializing_if = "Option::is_none")]
    pub hurst_exponent: Option<f64>,
}

/// Binding MAC for document state attestation.
///
/// CDDL Definition:
/// ```cddl
/// binding-mac = {
///   1: bstr .size 32,           ; HMAC-SHA256 value
///   2: bstr .size 32,           ; Document hash at binding
///   3: uint,                    ; Keystroke count at binding
///   4: uint                     ; Timestamp (Unix epoch ms)
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BindingMac {
    /// HMAC-SHA256 binding the jitter data to document state.
    #[serde(rename = "1", with = "hex_bytes")]
    pub mac: [u8; 32],

    /// Document content hash at time of binding.
    #[serde(rename = "2", with = "hex_bytes")]
    pub document_hash: [u8; 32],

    /// Cumulative keystroke count at binding.
    #[serde(rename = "3")]
    pub keystroke_count: u64,

    /// Timestamp in Unix epoch milliseconds.
    #[serde(rename = "4")]
    pub timestamp_ms: u64,
}

/// Raw interval data for forensic analysis.
///
/// Only included for Enhanced/Maximum evidence tiers.
///
/// CDDL Definition:
/// ```cddl
/// raw-intervals = {
///   1: [* uint],                ; Interval values (microseconds)
///   2: uint,                    ; Compression method (0=none, 1=delta, 2=zstd)
///   ? 3: bstr                   ; Compressed data (if method != 0)
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawIntervals {
    /// Raw interval values in microseconds.
    #[serde(rename = "1")]
    pub intervals: Vec<u32>,

    /// Compression method: 0=none, 1=delta encoding, 2=zstd.
    #[serde(rename = "2")]
    pub compression_method: u8,

    /// Compressed data blob (if compression_method != 0).
    #[serde(rename = "3", skip_serializing_if = "Option::is_none")]
    pub compressed_data: Option<Vec<u8>>,
}

/// Active behavioral probes.
///
/// CDDL Definition:
/// ```cddl
/// active-probes = {
///   ? 1: galton-invariant,
///   ? 2: reflex-gate
/// }
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ActiveProbes {
    /// Galton Invariant (binomial absorption test).
    #[serde(rename = "1", skip_serializing_if = "Option::is_none")]
    pub galton_invariant: Option<GaltonInvariant>,

    /// Reflex Gate (reflexive return latency test).
    #[serde(rename = "2", skip_serializing_if = "Option::is_none")]
    pub reflex_gate: Option<ReflexGate>,
}

/// Galton Invariant - absorption coefficient from binomial stimulus.
///
/// Based on the Galton Board: measures natural variation in reaction
/// to pseudo-random stimuli. Human responses show characteristic
/// absorption coefficients distinct from automated input.
///
/// CDDL Definition:
/// ```cddl
/// galton-invariant = {
///   1: float64,                 ; Absorption coefficient (0.0-1.0)
///   2: uint,                    ; Stimulus count
///   3: float64,                 ; Expected absorption (baseline)
///   4: float64,                 ; Z-score deviation
///   5: bool                     ; Pass/fail (within 2σ of expected)
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GaltonInvariant {
    /// Measured absorption coefficient (0.0-1.0).
    #[serde(rename = "1")]
    pub absorption_coefficient: f64,

    /// Number of stimuli presented.
    #[serde(rename = "2")]
    pub stimulus_count: u32,

    /// Expected absorption coefficient (calibrated baseline).
    #[serde(rename = "3")]
    pub expected_absorption: f64,

    /// Z-score deviation from expected.
    #[serde(rename = "4")]
    pub z_score: f64,

    /// Whether the test passed (within 2σ of expected).
    #[serde(rename = "5")]
    pub passed: bool,
}

/// Reflex Gate - reflexive return latency measurement.
///
/// Measures the latency of reflexive corrections (e.g., backspace
/// after typo). Human reflexive responses have characteristic
/// latency distributions that are difficult to simulate.
///
/// CDDL Definition:
/// ```cddl
/// reflex-gate = {
///   1: float64,                 ; Mean reflex latency (ms)
///   2: float64,                 ; Standard deviation (ms)
///   3: uint,                    ; Reflex event count
///   4: [5*float64],             ; Percentiles (10, 25, 50, 75, 90)
///   5: bool                     ; Pass/fail (within human range)
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReflexGate {
    /// Mean reflexive correction latency in milliseconds.
    #[serde(rename = "1")]
    pub mean_latency_ms: f64,

    /// Standard deviation of latency.
    #[serde(rename = "2")]
    pub std_dev_ms: f64,

    /// Number of reflexive events measured.
    #[serde(rename = "3")]
    pub event_count: u32,

    /// Percentile distribution [10th, 25th, 50th, 75th, 90th].
    #[serde(rename = "4")]
    pub percentiles: [f64; 5],

    /// Whether the test passed (within human range: 150-400ms typical).
    #[serde(rename = "5")]
    pub passed: bool,
}

/// Labyrinth Structure - topological phase space analysis.
///
/// Uses Takens' theorem for delay-coordinate embedding to detect
/// characteristic attractors in human typing patterns.
///
/// CDDL Definition:
/// ```cddl
/// labyrinth-structure = {
///   1: uint,                    ; Embedding dimension (typically 3-5)
///   2: uint,                    ; Time delay (samples)
///   3: [[* float64]],           ; Attractor points (sampled)
///   4: [* uint],                ; Betti numbers [β₀, β₁, β₂, ...]
///   5: float64,                 ; Lyapunov exponent estimate
///   6: float64                  ; Correlation dimension
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabyrinthStructure {
    /// Embedding dimension (typically 3-5 for typing patterns).
    #[serde(rename = "1")]
    pub embedding_dimension: u8,

    /// Time delay in samples for embedding.
    #[serde(rename = "2")]
    pub time_delay: u16,

    /// Sampled attractor points in phase space.
    /// Each inner vector has length = embedding_dimension.
    #[serde(rename = "3")]
    pub attractor_points: Vec<Vec<f64>>,

    /// Betti numbers describing topology [β₀, β₁, β₂, ...].
    /// β₀ = connected components, β₁ = loops, β₂ = voids.
    #[serde(rename = "4")]
    pub betti_numbers: Vec<u32>,

    /// Estimated Lyapunov exponent (chaos measure).
    /// Positive = chaotic (human-like), zero/negative = periodic.
    #[serde(rename = "5")]
    pub lyapunov_exponent: f64,

    /// Correlation dimension estimate.
    /// Non-integer values suggest fractal attractor (human-like).
    #[serde(rename = "6")]
    pub correlation_dimension: f64,
}

impl JitterBinding {
    /// Create a new JitterBinding with required fields.
    pub fn new(
        entropy_commitment: EntropyCommitment,
        sources: Vec<SourceDescriptor>,
        summary: JitterSummary,
        binding_mac: BindingMac,
    ) -> Self {
        Self {
            entropy_commitment,
            sources,
            summary,
            binding_mac,
            raw_intervals: None,
            active_probes: None,
            labyrinth_structure: None,
        }
    }

    /// Add raw intervals (for Enhanced/Maximum tiers).
    pub fn with_raw_intervals(mut self, intervals: RawIntervals) -> Self {
        self.raw_intervals = Some(intervals);
        self
    }

    /// Add active probes.
    pub fn with_active_probes(mut self, probes: ActiveProbes) -> Self {
        self.active_probes = Some(probes);
        self
    }

    /// Add labyrinth structure.
    pub fn with_labyrinth(mut self, labyrinth: LabyrinthStructure) -> Self {
        self.labyrinth_structure = Some(labyrinth);
        self
    }

    /// Verify the binding MAC against provided seed.
    pub fn verify_binding(&self, seed: &[u8]) -> bool {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        let mut mac = match HmacSha256::new_from_slice(seed) {
            Ok(m) => m,
            Err(_) => return false,
        };

        mac.update(&self.binding_mac.document_hash);
        mac.update(&self.binding_mac.keystroke_count.to_be_bytes());
        mac.update(&self.binding_mac.timestamp_ms.to_be_bytes());
        mac.update(&self.entropy_commitment.hash);

        mac.verify_slice(&self.binding_mac.mac).is_ok()
    }

    /// Check if Hurst exponent is within human range.
    /// Human typing typically has H_e ≈ 0.7 (long-range dependence).
    pub fn is_hurst_valid(&self) -> bool {
        if let Some(h) = self.summary.hurst_exponent {
            // Reject white noise (0.5) and perfectly predictable (1.0)
            // Accept range: 0.55 to 0.85 as human-like
            h > 0.55 && h < 0.85
        } else {
            true // No Hurst exponent = not evaluated
        }
    }

    /// Check if all active probes passed.
    pub fn probes_passed(&self) -> bool {
        if let Some(probes) = &self.active_probes {
            let galton_ok = probes
                .galton_invariant
                .as_ref()
                .map(|g| g.passed)
                .unwrap_or(true);
            let reflex_ok = probes
                .reflex_gate
                .as_ref()
                .map(|r| r.passed)
                .unwrap_or(true);
            galton_ok && reflex_ok
        } else {
            true // No probes = not evaluated
        }
    }

    /// Comprehensive validation of the JitterBinding structure.
    ///
    /// Returns a list of validation errors, or empty if valid.
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        // Validate entropy commitment
        if self.entropy_commitment.hash == [0u8; 32] {
            errors.push("entropy commitment hash is zero".into());
        }
        if self.entropy_commitment.timestamp_ms == 0 {
            errors.push("entropy commitment timestamp is zero".into());
        }

        // Validate sources
        if self.sources.is_empty() {
            errors.push("no entropy sources declared".into());
        }
        let total_weight: u32 = self.sources.iter().map(|s| s.weight as u32).sum();
        if total_weight == 0 {
            errors.push("total source weight is zero".into());
        }
        if total_weight > 1000 {
            errors.push(format!("total source weight {} exceeds 1000", total_weight));
        }
        for source in &self.sources {
            if source.source_type.is_empty() {
                errors.push("empty source type".into());
            }
        }

        // Validate summary statistics
        if self.summary.sample_count == 0 {
            errors.push("sample count is zero".into());
        }
        if self.summary.mean_interval_us <= 0.0 {
            errors.push("mean interval is non-positive".into());
        }
        if self.summary.std_dev < 0.0 {
            errors.push("standard deviation is negative".into());
        }
        if self.summary.coefficient_of_variation < 0.0 {
            errors.push("coefficient of variation is negative".into());
        }
        if self.summary.entropy_bits < 0.0 {
            errors.push("entropy bits is negative".into());
        }

        // Validate percentiles are monotonically increasing
        // Percentiles are at indices [0,1,2,3,4] = [10th, 25th, 50th, 75th, 90th]
        for i in 1..5 {
            if self.summary.percentiles[i] < self.summary.percentiles[i - 1] {
                errors.push(format!(
                    "percentiles not monotonic: index {} ({}) < index {} ({})",
                    i,
                    self.summary.percentiles[i],
                    i - 1,
                    self.summary.percentiles[i - 1]
                ));
                break;
            }
        }

        // Validate Hurst exponent range if present
        if let Some(h) = self.summary.hurst_exponent {
            if !(0.0..=1.0).contains(&h) {
                errors.push(format!("Hurst exponent {} out of range [0, 1]", h));
            }
        }

        // Validate binding MAC
        if self.binding_mac.mac == [0u8; 32] {
            errors.push("binding MAC is zero".into());
        }
        if self.binding_mac.document_hash == [0u8; 32] {
            errors.push("document hash is zero".into());
        }
        if self.binding_mac.timestamp_ms == 0 {
            errors.push("binding MAC timestamp is zero".into());
        }

        // Validate active probes if present
        if let Some(probes) = &self.active_probes {
            if let Some(galton) = &probes.galton_invariant {
                if galton.absorption_coefficient < 0.0 || galton.absorption_coefficient > 1.0 {
                    errors.push(format!(
                        "Galton absorption coefficient {} out of range [0, 1]",
                        galton.absorption_coefficient
                    ));
                }
                if galton.stimulus_count == 0 {
                    errors.push("Galton stimulus count is zero".into());
                }
            }
            if let Some(reflex) = &probes.reflex_gate {
                if reflex.mean_latency_ms < 0.0 {
                    errors.push("reflex gate mean latency is negative".into());
                }
                if reflex.std_dev_ms < 0.0 {
                    errors.push("reflex gate std dev is negative".into());
                }
            }
        }

        // Validate labyrinth structure if present
        if let Some(labyrinth) = &self.labyrinth_structure {
            if labyrinth.embedding_dimension < 2 {
                errors.push("labyrinth embedding dimension < 2".into());
            }
            if labyrinth.time_delay == 0 {
                errors.push("labyrinth time delay is zero".into());
            }
            if labyrinth.betti_numbers.is_empty() {
                errors.push("labyrinth betti numbers empty".into());
            }
            if labyrinth.correlation_dimension < 0.0 {
                errors.push("correlation dimension is negative".into());
            }
        }

        errors
    }

    /// Check if the binding is valid (no validation errors).
    pub fn is_valid(&self) -> bool {
        self.validate().is_empty()
    }
}

/// Serde helper for hex-encoded fixed-size byte arrays.
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S, const N: usize>(bytes: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != N {
            return Err(serde::de::Error::custom(format!(
                "expected {} bytes, got {}",
                N,
                bytes.len()
            )));
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

// ============================================
// Conversion from analysis module types
// ============================================

impl From<&crate::analysis::active_probes::GaltonInvariantResult> for GaltonInvariant {
    fn from(result: &crate::analysis::active_probes::GaltonInvariantResult) -> Self {
        Self {
            absorption_coefficient: result.absorption_coefficient,
            stimulus_count: result.perturbation_count as u32,
            expected_absorption: 0.55, // RFC default baseline
            z_score: (result.absorption_coefficient - 0.55) / result.std_error.max(0.001),
            passed: result.is_valid,
        }
    }
}

impl From<&crate::analysis::active_probes::ReflexGateResult> for ReflexGate {
    fn from(result: &crate::analysis::active_probes::ReflexGateResult) -> Self {
        Self {
            mean_latency_ms: result.mean_latency_ms,
            std_dev_ms: result.std_latency_ms,
            event_count: result.response_count as u32,
            // Estimate percentiles from mean and std (assuming normal distribution)
            percentiles: estimate_percentiles(result.mean_latency_ms, result.std_latency_ms),
            passed: result.is_valid,
        }
    }
}

impl From<&crate::analysis::active_probes::ActiveProbeResults> for ActiveProbes {
    fn from(results: &crate::analysis::active_probes::ActiveProbeResults) -> Self {
        Self {
            galton_invariant: results.galton.as_ref().map(|g| g.into()),
            reflex_gate: results.reflex.as_ref().map(|r| r.into()),
        }
    }
}

impl From<&crate::analysis::labyrinth::LabyrinthAnalysis> for LabyrinthStructure {
    fn from(analysis: &crate::analysis::labyrinth::LabyrinthAnalysis) -> Self {
        // Sample attractor points (simplified - in production would capture actual points)
        let attractor_points: Vec<Vec<f64>> = Vec::new();

        Self {
            embedding_dimension: analysis.embedding_dimension as u8,
            time_delay: analysis.optimal_delay as u16,
            attractor_points,
            betti_numbers: vec![
                analysis.betti_numbers[0] as u32,
                analysis.betti_numbers[1] as u32,
                analysis.betti_numbers[2] as u32,
            ],
            lyapunov_exponent: 0.0, // Would need separate calculation
            correlation_dimension: analysis.correlation_dimension,
        }
    }
}

/// Estimate percentiles from mean and std assuming approximate normality.
fn estimate_percentiles(mean: f64, std: f64) -> [f64; 5] {
    // z-scores for 10th, 25th, 50th, 75th, 90th percentiles
    let z_scores = [-1.28, -0.67, 0.0, 0.67, 1.28];
    [
        (mean + z_scores[0] * std).max(0.0),
        (mean + z_scores[1] * std).max(0.0),
        mean,
        mean + z_scores[3] * std,
        mean + z_scores[4] * std,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_binding() -> JitterBinding {
        let commitment = EntropyCommitment {
            hash: [1u8; 32],
            timestamp_ms: 1700000000000,
            previous_hash: [0u8; 32],
        };

        let sources = vec![
            SourceDescriptor {
                source_type: "keyboard".to_string(),
                weight: 700,
                device_fingerprint: Some("usb:1234:5678".to_string()),
                transport_calibration: None,
            },
            SourceDescriptor {
                source_type: "mouse".to_string(),
                weight: 300,
                device_fingerprint: None,
                transport_calibration: None,
            },
        ];

        let summary = JitterSummary {
            sample_count: 1000,
            mean_interval_us: 150000.0,
            std_dev: 50000.0,
            coefficient_of_variation: 0.33,
            percentiles: [50000.0, 80000.0, 140000.0, 200000.0, 300000.0],
            entropy_bits: 8.5,
            hurst_exponent: Some(0.72),
        };

        let binding_mac = BindingMac {
            mac: [2u8; 32],
            document_hash: [3u8; 32],
            keystroke_count: 5000,
            timestamp_ms: 1700000000000,
        };

        JitterBinding::new(commitment, sources, summary, binding_mac)
    }

    #[test]
    fn test_jitter_binding_serialization() {
        let binding = create_test_binding();

        // Test JSON roundtrip
        let json = serde_json::to_string_pretty(&binding).unwrap();
        let decoded: JitterBinding = serde_json::from_str(&json).unwrap();

        assert_eq!(binding.summary.sample_count, decoded.summary.sample_count);
        assert_eq!(binding.sources.len(), decoded.sources.len());
    }

    #[test]
    fn test_hurst_validation() {
        let mut binding = create_test_binding();

        // Valid Hurst exponent
        binding.summary.hurst_exponent = Some(0.72);
        assert!(binding.is_hurst_valid());

        // White noise (invalid)
        binding.summary.hurst_exponent = Some(0.5);
        assert!(!binding.is_hurst_valid());

        // Perfectly predictable (invalid)
        binding.summary.hurst_exponent = Some(1.0);
        assert!(!binding.is_hurst_valid());

        // No Hurst (not evaluated)
        binding.summary.hurst_exponent = None;
        assert!(binding.is_hurst_valid());
    }

    #[test]
    fn test_active_probes() {
        let mut binding = create_test_binding();

        let probes = ActiveProbes {
            galton_invariant: Some(GaltonInvariant {
                absorption_coefficient: 0.65,
                stimulus_count: 100,
                expected_absorption: 0.63,
                z_score: 0.5,
                passed: true,
            }),
            reflex_gate: Some(ReflexGate {
                mean_latency_ms: 250.0,
                std_dev_ms: 50.0,
                event_count: 50,
                percentiles: [180.0, 210.0, 245.0, 285.0, 340.0],
                passed: true,
            }),
        };

        binding.active_probes = Some(probes);
        assert!(binding.probes_passed());

        // Test failing probe
        binding
            .active_probes
            .as_mut()
            .unwrap()
            .galton_invariant
            .as_mut()
            .unwrap()
            .passed = false;
        assert!(!binding.probes_passed());
    }

    #[test]
    fn test_jitter_binding_validation_valid() {
        let binding = create_test_binding();
        let errors = binding.validate();
        assert!(errors.is_empty(), "expected no errors, got: {:?}", errors);
        assert!(binding.is_valid());
    }

    #[test]
    fn test_jitter_binding_validation_zero_hash() {
        let mut binding = create_test_binding();
        binding.entropy_commitment.hash = [0u8; 32];
        let errors = binding.validate();
        assert!(errors
            .iter()
            .any(|e| e.contains("entropy commitment hash is zero")));
        assert!(!binding.is_valid());
    }

    #[test]
    fn test_jitter_binding_validation_empty_sources() {
        let mut binding = create_test_binding();
        binding.sources.clear();
        let errors = binding.validate();
        assert!(errors.iter().any(|e| e.contains("no entropy sources")));
    }

    #[test]
    fn test_jitter_binding_validation_excessive_weight() {
        let mut binding = create_test_binding();
        binding.sources[0].weight = 800;
        binding.sources[1].weight = 500;
        let errors = binding.validate();
        assert!(errors.iter().any(|e| e.contains("exceeds 1000")));
    }

    #[test]
    fn test_jitter_binding_validation_invalid_hurst() {
        let mut binding = create_test_binding();
        binding.summary.hurst_exponent = Some(1.5);
        let errors = binding.validate();
        assert!(errors.iter().any(|e| e.contains("Hurst exponent")));
    }

    #[test]
    fn test_jitter_binding_validation_non_monotonic_percentiles() {
        let mut binding = create_test_binding();
        binding.summary.percentiles = [100.0, 50.0, 75.0, 80.0, 90.0]; // Non-monotonic
        let errors = binding.validate();
        assert!(errors.iter().any(|e| e.contains("not monotonic")));
    }
}
