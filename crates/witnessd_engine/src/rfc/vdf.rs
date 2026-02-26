// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! RFC-compliant VDF proof structures.
//!
//! Implements the CDDL-defined VDF structures from draft-condrey-rats-pop-01.
//! These structures ensure minimum elapsed time verification through
//! verifiable delay functions.

use serde::{Deserialize, Serialize};

/// Serde helper for hex-encoded 32-byte arrays.
mod hex_bytes_32 {
    use serde::{de, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| de::Error::custom("expected 32 bytes"))
    }
}

/// Serde helper for hex-encoded 64-byte arrays.
mod hex_bytes_64 {
    use serde::{de, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| de::Error::custom("expected 64 bytes"))
    }
}

/// Serde helper for variable-length hex-encoded bytes.
mod hex_bytes_vec {
    use serde::{de, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s).map_err(de::Error::custom)
    }
}

/// RFC-compliant VDF proof structure.
///
/// CDDL definition:
/// ```cddl
/// vdf-proof = {
///   1: bstr .size 32,          ; challenge (input)
///   2: bstr .size 64,          ; output (proof result)
///   3: uint,                   ; iterations (T parameter)
///   4: uint,                   ; duration-ms (measured wall time)
///   5: calibration-attestation ; calibration reference
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VdfProofRfc {
    /// Challenge input (32 bytes).
    /// Key 1 in CDDL.
    #[serde(rename = "1", with = "hex_bytes_32")]
    pub challenge: [u8; 32],

    /// VDF output/proof result (64 bytes for Wesolowski proof).
    /// Key 2 in CDDL.
    #[serde(rename = "2", with = "hex_bytes_64")]
    pub output: [u8; 64],

    /// Number of sequential iterations (T parameter).
    /// Key 3 in CDDL.
    #[serde(rename = "3")]
    pub iterations: u64,

    /// Measured wall clock duration in milliseconds.
    /// Key 4 in CDDL.
    #[serde(rename = "4")]
    pub duration_ms: u64,

    /// Calibration attestation for this proof.
    /// Key 5 in CDDL.
    #[serde(rename = "5")]
    pub calibration: CalibrationAttestation,
}

impl VdfProofRfc {
    /// Creates a new VDF proof.
    pub fn new(
        challenge: [u8; 32],
        output: [u8; 64],
        iterations: u64,
        duration_ms: u64,
        calibration: CalibrationAttestation,
    ) -> Self {
        Self {
            challenge,
            output,
            iterations,
            duration_ms,
            calibration,
        }
    }

    /// Returns the minimum elapsed time in milliseconds based on calibration.
    ///
    /// This represents the theoretical minimum time required to compute
    /// the VDF, regardless of hardware improvements.
    pub fn minimum_elapsed_ms(&self) -> u64 {
        // Calculate based on iterations and calibration rate
        if self.calibration.iterations_per_second > 0 {
            (self.iterations as f64 / self.calibration.iterations_per_second as f64 * 1000.0) as u64
        } else {
            self.duration_ms
        }
    }

    /// Validates that the measured duration is consistent with expected minimum.
    ///
    /// Returns true if duration_ms >= minimum_elapsed_ms with a small tolerance
    /// for timing jitter.
    pub fn is_duration_consistent(&self) -> bool {
        let minimum = self.minimum_elapsed_ms();
        // Allow 5% tolerance for timing variance
        let threshold = minimum.saturating_sub(minimum / 20);
        self.duration_ms >= threshold
    }

    /// Returns the iterations-to-time ratio for this proof.
    ///
    /// Higher values indicate faster hardware (potential gaming).
    pub fn iterations_per_ms(&self) -> f64 {
        if self.duration_ms > 0 {
            self.iterations as f64 / self.duration_ms as f64
        } else {
            0.0
        }
    }

    /// Validate the VdfProofRfc structure and return a list of validation errors.
    ///
    /// Checks:
    /// - Challenge is non-zero
    /// - Output is non-zero
    /// - Iterations is non-zero
    /// - Duration_ms is non-zero
    /// - Calibration is valid (iterations_per_second non-zero, hardware_class non-empty)
    /// - Duration is consistent with calibration (not impossibly fast)
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        // Validate challenge is non-zero
        if self.challenge == [0u8; 32] {
            errors.push("challenge must be non-zero".to_string());
        }

        // Validate output is non-zero
        if self.output == [0u8; 64] {
            errors.push("output must be non-zero".to_string());
        }

        // Validate iterations is non-zero
        if self.iterations == 0 {
            errors.push("iterations must be non-zero".to_string());
        }

        // Validate duration_ms is non-zero
        if self.duration_ms == 0 {
            errors.push("duration_ms must be non-zero".to_string());
        }

        // Validate calibration
        errors.extend(self.calibration.validate());

        // Check duration consistency only if we have valid calibration and iterations
        if self.calibration.iterations_per_second > 0
            && self.iterations > 0
            && self.duration_ms > 0
            && !self.is_duration_consistent()
        {
            errors.push(format!(
                "duration_ms ({}) is inconsistent with expected minimum ({} ms) based on calibration",
                self.duration_ms,
                self.minimum_elapsed_ms()
            ));
        }

        errors
    }

    /// Returns true if the VdfProofRfc is valid (no validation errors).
    pub fn is_valid(&self) -> bool {
        self.validate().is_empty()
    }
}

/// Calibration attestation for VDF proof verification.
///
/// Provides a reference point for evaluating VDF computation times
/// across different hardware configurations.
///
/// CDDL definition:
/// ```cddl
/// calibration-attestation = {
///   1: uint,                   ; iterations-per-second (baseline rate)
///   2: tstr,                   ; hardware-class (device classification)
///   3: bstr,                   ; calibration-signature (signed attestation)
///   4: uint,                   ; timestamp (calibration time)
///   ? 5: tstr                  ; calibration-authority (optional issuer)
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CalibrationAttestation {
    /// Baseline iterations per second for this hardware class.
    /// Key 1 in CDDL.
    #[serde(rename = "1")]
    pub iterations_per_second: u64,

    /// Hardware classification string.
    /// Examples: "mobile-arm64", "desktop-x86_64", "server-xeon"
    /// Key 2 in CDDL.
    #[serde(rename = "2")]
    pub hardware_class: String,

    /// Signed calibration attestation.
    /// Key 3 in CDDL.
    #[serde(rename = "3", with = "hex_bytes_vec")]
    pub calibration_signature: Vec<u8>,

    /// Unix timestamp when calibration was performed.
    /// Key 4 in CDDL.
    #[serde(rename = "4")]
    pub timestamp: u64,

    /// Optional calibration authority identifier.
    /// Key 5 in CDDL.
    #[serde(rename = "5", skip_serializing_if = "Option::is_none")]
    pub calibration_authority: Option<String>,
}

impl CalibrationAttestation {
    /// Creates a new calibration attestation.
    pub fn new(
        iterations_per_second: u64,
        hardware_class: String,
        calibration_signature: Vec<u8>,
        timestamp: u64,
    ) -> Self {
        Self {
            iterations_per_second,
            hardware_class,
            calibration_signature,
            timestamp,
            calibration_authority: None,
        }
    }

    /// Creates a calibration attestation with an authority.
    pub fn with_authority(
        iterations_per_second: u64,
        hardware_class: String,
        calibration_signature: Vec<u8>,
        timestamp: u64,
        authority: String,
    ) -> Self {
        Self {
            iterations_per_second,
            hardware_class,
            calibration_signature,
            timestamp,
            calibration_authority: Some(authority),
        }
    }

    /// Returns the age of this calibration in seconds.
    pub fn age_seconds(&self, current_time: u64) -> u64 {
        current_time.saturating_sub(self.timestamp)
    }

    /// Checks if the calibration is considered fresh (less than 24 hours old).
    pub fn is_fresh(&self, current_time: u64) -> bool {
        self.age_seconds(current_time) < 86400
    }

    /// Validate the CalibrationAttestation structure and return a list of validation errors.
    ///
    /// Checks:
    /// - iterations_per_second is non-zero
    /// - hardware_class is non-empty
    /// - calibration_signature is non-empty
    /// - timestamp is non-zero
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        if self.iterations_per_second == 0 {
            errors.push("calibration.iterations_per_second must be non-zero".to_string());
        }

        if self.hardware_class.is_empty() {
            errors.push("calibration.hardware_class must be non-empty".to_string());
        }

        if self.calibration_signature.is_empty() {
            errors.push("calibration.calibration_signature must be non-empty".to_string());
        }

        if self.timestamp == 0 {
            errors.push("calibration.timestamp must be non-zero".to_string());
        }

        errors
    }

    /// Returns true if the CalibrationAttestation is valid (no validation errors).
    pub fn is_valid(&self) -> bool {
        self.validate().is_empty()
    }
}

/// VDF algorithm identifier for proof verification.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum VdfAlgorithm {
    /// Wesolowski's VDF construction.
    #[default]
    Wesolowski,
    /// Pietrzak's VDF construction.
    Pietrzak,
    /// RSA-based VDF.
    Rsa2048,
}

/// Extended VDF proof with algorithm metadata.
///
/// Used when multiple VDF algorithms may be in use.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VdfProofExtended {
    /// The core VDF proof.
    pub proof: VdfProofRfc,

    /// Algorithm used for this proof.
    pub algorithm: VdfAlgorithm,

    /// Optional intermediate checkpoints for long VDFs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoints: Option<Vec<VdfCheckpoint>>,
}

/// Intermediate checkpoint in a long VDF computation.
///
/// Used for proofs that span extended time periods, allowing
/// partial verification without recomputing the entire chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VdfCheckpoint {
    /// Iteration count at this checkpoint.
    pub iteration: u64,

    /// Output value at this checkpoint.
    #[serde(with = "hex_bytes_64")]
    pub value: [u8; 64],

    /// Wall clock time elapsed to this point (ms).
    pub elapsed_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vdf_proof_creation() {
        let calibration = CalibrationAttestation::new(
            1_000_000,
            "desktop-x86_64".to_string(),
            vec![0u8; 64],
            1700000000,
        );

        let proof = VdfProofRfc::new(
            [1u8; 32],
            [2u8; 64],
            1_000_000,
            1000, // 1 second
            calibration,
        );

        assert_eq!(proof.iterations, 1_000_000);
        assert_eq!(proof.duration_ms, 1000);
    }

    #[test]
    fn test_minimum_elapsed_calculation() {
        let calibration = CalibrationAttestation::new(
            1_000_000, // 1M iterations per second
            "test".to_string(),
            vec![],
            0,
        );

        let proof = VdfProofRfc::new(
            [0u8; 32],
            [0u8; 64],
            2_000_000, // 2M iterations
            2500,      // 2.5 seconds (some overhead)
            calibration,
        );

        // Should be ~2000ms minimum
        assert_eq!(proof.minimum_elapsed_ms(), 2000);
        assert!(proof.is_duration_consistent());
    }

    #[test]
    fn test_duration_inconsistent_when_too_fast() {
        let calibration = CalibrationAttestation::new(
            1_000_000, // 1M iterations per second
            "test".to_string(),
            vec![],
            0,
        );

        let proof = VdfProofRfc::new(
            [0u8; 32],
            [0u8; 64],
            2_000_000, // 2M iterations
            500,       // Only 0.5 seconds - impossibly fast!
            calibration,
        );

        assert!(!proof.is_duration_consistent());
    }

    #[test]
    fn test_calibration_freshness() {
        let calibration = CalibrationAttestation::new(
            1_000_000,
            "test".to_string(),
            vec![],
            1700000000, // Some past timestamp
        );

        // Fresh if current time is within 24 hours
        assert!(calibration.is_fresh(1700000000 + 3600)); // 1 hour later
        assert!(calibration.is_fresh(1700000000 + 86000)); // ~23.9 hours later

        // Stale if more than 24 hours
        assert!(!calibration.is_fresh(1700000000 + 90000)); // 25 hours later
    }

    #[test]
    fn test_vdf_proof_serialization() {
        let calibration = CalibrationAttestation::with_authority(
            500_000,
            "mobile-arm64".to_string(),
            vec![0xAB; 32],
            1700000000,
            "witnessd.io".to_string(),
        );

        let proof = VdfProofRfc::new([0xDE; 32], [0xAD; 64], 500_000, 1000, calibration);

        // Serialize to JSON
        let json = serde_json::to_string(&proof).expect("JSON serialization failed");
        assert!(json.contains("\"1\""));
        assert!(json.contains("\"2\""));

        // Deserialize back
        let decoded: VdfProofRfc =
            serde_json::from_str(&json).expect("JSON deserialization failed");
        assert_eq!(decoded, proof);
    }

    #[test]
    fn test_iterations_per_ms() {
        let calibration = CalibrationAttestation::new(1_000_000, "test".to_string(), vec![1u8], 1);

        let proof = VdfProofRfc::new([1u8; 32], [1u8; 64], 1_000_000, 1000, calibration);

        // 1M iterations in 1000ms = 1000 iterations/ms
        assert!((proof.iterations_per_ms() - 1000.0).abs() < 0.001);
    }

    #[test]
    fn test_vdf_proof_validate_valid() {
        let calibration = CalibrationAttestation::new(
            1_000_000,
            "desktop-x86_64".to_string(),
            vec![0xAB; 64],
            1700000000,
        );

        let proof = VdfProofRfc::new(
            [1u8; 32],
            [2u8; 64],
            1_000_000,
            1000, // 1 second - consistent with calibration
            calibration,
        );

        assert!(proof.is_valid());
        assert!(proof.validate().is_empty());
    }

    #[test]
    fn test_vdf_proof_validate_zero_challenge() {
        let calibration =
            CalibrationAttestation::new(1_000_000, "test".to_string(), vec![1u8], 1700000000);

        let proof = VdfProofRfc::new(
            [0u8; 32], // Zero challenge - invalid
            [2u8; 64],
            1_000_000,
            1000,
            calibration,
        );

        let errors = proof.validate();
        assert!(errors
            .iter()
            .any(|e| e.contains("challenge must be non-zero")));
        assert!(!proof.is_valid());
    }

    #[test]
    fn test_vdf_proof_validate_zero_output() {
        let calibration =
            CalibrationAttestation::new(1_000_000, "test".to_string(), vec![1u8], 1700000000);

        let proof = VdfProofRfc::new(
            [1u8; 32],
            [0u8; 64], // Zero output - invalid
            1_000_000,
            1000,
            calibration,
        );

        let errors = proof.validate();
        assert!(errors.iter().any(|e| e.contains("output must be non-zero")));
        assert!(!proof.is_valid());
    }

    #[test]
    fn test_vdf_proof_validate_zero_iterations() {
        let calibration =
            CalibrationAttestation::new(1_000_000, "test".to_string(), vec![1u8], 1700000000);

        let proof = VdfProofRfc::new(
            [1u8; 32],
            [2u8; 64],
            0, // Zero iterations - invalid
            1000,
            calibration,
        );

        let errors = proof.validate();
        assert!(errors
            .iter()
            .any(|e| e.contains("iterations must be non-zero")));
        assert!(!proof.is_valid());
    }

    #[test]
    fn test_vdf_proof_validate_zero_duration() {
        let calibration =
            CalibrationAttestation::new(1_000_000, "test".to_string(), vec![1u8], 1700000000);

        let proof = VdfProofRfc::new(
            [1u8; 32],
            [2u8; 64],
            1_000_000,
            0, // Zero duration - invalid
            calibration,
        );

        let errors = proof.validate();
        assert!(errors
            .iter()
            .any(|e| e.contains("duration_ms must be non-zero")));
        assert!(!proof.is_valid());
    }

    #[test]
    fn test_vdf_proof_validate_inconsistent_duration() {
        let calibration = CalibrationAttestation::new(
            1_000_000, // 1M iterations per second
            "test".to_string(),
            vec![1u8],
            1700000000,
        );

        let proof = VdfProofRfc::new(
            [1u8; 32],
            [2u8; 64],
            2_000_000, // 2M iterations
            500,       // Only 0.5 seconds - impossibly fast!
            calibration,
        );

        let errors = proof.validate();
        assert!(errors
            .iter()
            .any(|e| e.contains("duration_ms") && e.contains("inconsistent")));
        assert!(!proof.is_valid());
    }

    #[test]
    fn test_calibration_validate_valid() {
        let calibration = CalibrationAttestation::new(
            1_000_000,
            "desktop-x86_64".to_string(),
            vec![0xAB; 64],
            1700000000,
        );

        assert!(calibration.is_valid());
        assert!(calibration.validate().is_empty());
    }

    #[test]
    fn test_calibration_validate_zero_iterations_per_second() {
        let calibration = CalibrationAttestation::new(
            0, // Zero - invalid
            "test".to_string(),
            vec![1u8],
            1700000000,
        );

        let errors = calibration.validate();
        assert!(errors
            .iter()
            .any(|e| e.contains("iterations_per_second must be non-zero")));
        assert!(!calibration.is_valid());
    }

    #[test]
    fn test_calibration_validate_empty_hardware_class() {
        let calibration = CalibrationAttestation::new(
            1_000_000,
            "".to_string(), // Empty - invalid
            vec![1u8],
            1700000000,
        );

        let errors = calibration.validate();
        assert!(errors
            .iter()
            .any(|e| e.contains("hardware_class must be non-empty")));
        assert!(!calibration.is_valid());
    }

    #[test]
    fn test_calibration_validate_empty_signature() {
        let calibration = CalibrationAttestation::new(
            1_000_000,
            "test".to_string(),
            vec![], // Empty - invalid
            1700000000,
        );

        let errors = calibration.validate();
        assert!(errors
            .iter()
            .any(|e| e.contains("calibration_signature must be non-empty")));
        assert!(!calibration.is_valid());
    }

    #[test]
    fn test_calibration_validate_zero_timestamp() {
        let calibration = CalibrationAttestation::new(
            1_000_000,
            "test".to_string(),
            vec![1u8],
            0, // Zero - invalid
        );

        let errors = calibration.validate();
        assert!(errors
            .iter()
            .any(|e| e.contains("timestamp must be non-zero")));
        assert!(!calibration.is_valid());
    }

    #[test]
    fn test_vdf_proof_validate_multiple_errors() {
        let calibration = CalibrationAttestation::new(
            0,              // Zero - invalid
            "".to_string(), // Empty - invalid
            vec![],         // Empty - invalid
            0,              // Zero - invalid
        );

        let proof = VdfProofRfc::new(
            [0u8; 32], // Zero - invalid
            [0u8; 64], // Zero - invalid
            0,         // Zero - invalid
            0,         // Zero - invalid
            calibration,
        );

        let errors = proof.validate();
        // Should have multiple errors from both proof and calibration
        assert!(errors.len() >= 8);
        assert!(!proof.is_valid());
    }
}
