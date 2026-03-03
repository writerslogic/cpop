// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! RFC-compliant VDF proof structures.
//!
//! Implements the CDDL-defined VDF structures from draft-condrey-rats-pop-01.
//! These structures ensure minimum elapsed time verification through
//! verifiable delay functions.

use serde::{Deserialize, Serialize};

use super::serde_helpers::{hex_bytes, hex_bytes_vec};
use super::wire_types::components::{SWF_MAX_DURATION_FACTOR, SWF_MIN_DURATION_FACTOR};

/// RFC-compliant VDF proof structure.
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
    /// Challenge input.
    #[serde(rename = "1", with = "hex_bytes")]
    pub challenge: [u8; 32],

    /// VDF output (64 bytes, Wesolowski proof).
    #[serde(rename = "2", with = "hex_bytes")]
    pub output: [u8; 64],

    /// Sequential iterations (T parameter).
    #[serde(rename = "3")]
    pub iterations: u64,

    /// Measured wall clock duration (ms).
    #[serde(rename = "4")]
    pub duration_ms: u64,

    /// Calibration reference for this proof.
    #[serde(rename = "5")]
    pub calibration: CalibrationAttestation,
}

impl VdfProofRfc {
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

    /// Theoretical minimum elapsed time (ms) based on calibration.
    pub fn minimum_elapsed_ms(&self) -> u64 {
        // Integer arithmetic avoids f64 precision / NaN edge cases
        if self.calibration.iterations_per_second > 0 {
            self.iterations
                .saturating_mul(1000)
                .checked_div(self.calibration.iterations_per_second)
                .unwrap_or(self.duration_ms)
        } else {
            self.duration_ms
        }
    }

    /// Returns `true` if `duration_ms` >= `minimum_elapsed_ms` (5% tolerance).
    pub fn is_duration_consistent(&self) -> bool {
        let minimum = self.minimum_elapsed_ms();
        // 5% tolerance for timing variance
        let threshold = minimum.saturating_sub(minimum / 20);
        self.duration_ms >= threshold
    }

    /// Returns `true` if `duration_ms` falls within the IETF-mandated
    /// `[SWF_MIN_DURATION_FACTOR, SWF_MAX_DURATION_FACTOR]` range relative
    /// to the calibration-derived expected duration.
    pub fn is_duration_within_spec_bounds(&self) -> bool {
        let expected = self.minimum_elapsed_ms();
        if expected == 0 || self.duration_ms == 0 {
            return false;
        }
        let ratio = self.duration_ms as f64 / expected as f64;
        (SWF_MIN_DURATION_FACTOR..=SWF_MAX_DURATION_FACTOR).contains(&ratio)
    }

    /// Iterations-to-time ratio. Higher = faster hardware (potential gaming).
    pub fn iterations_per_ms(&self) -> f64 {
        if self.duration_ms > 0 {
            self.iterations as f64 / self.duration_ms as f64
        } else {
            0.0
        }
    }

    /// Validate all fields; returns a list of errors.
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        if self.challenge == [0u8; 32] {
            errors.push("challenge must be non-zero".to_string());
        }

        if self.output == [0u8; 64] {
            errors.push("output must be non-zero".to_string());
        }

        if self.iterations == 0 {
            errors.push("iterations must be non-zero".to_string());
        }

        if self.duration_ms == 0 {
            errors.push("duration_ms must be non-zero".to_string());
        }

        errors.extend(self.calibration.validate_structure());

        if self.calibration.iterations_per_second > 0 && self.iterations > 0 && self.duration_ms > 0
        {
            if !self.is_duration_consistent() {
                errors.push(format!(
                    "duration_ms ({}) is inconsistent with expected minimum ({} ms) based on calibration",
                    self.duration_ms,
                    self.minimum_elapsed_ms()
                ));
            }
            if !self.is_duration_within_spec_bounds() {
                let expected = self.minimum_elapsed_ms();
                let ratio = self.duration_ms as f64 / expected as f64;
                errors.push(format!(
                    "duration ratio {ratio:.2}x outside spec bounds [{SWF_MIN_DURATION_FACTOR}x, {SWF_MAX_DURATION_FACTOR}x]",
                ));
            }
        }

        errors
    }

    pub fn is_valid(&self) -> bool {
        self.validate().is_empty()
    }
}

/// Calibration reference for evaluating VDF computation times
/// across hardware configurations.
///
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
    #[serde(rename = "1")]
    pub iterations_per_second: u64,

    /// Hardware classification string.
    /// Examples: "mobile-arm64", "desktop-x86_64", "server-xeon"
    #[serde(rename = "2")]
    pub hardware_class: String,

    /// Signed calibration attestation.
    #[serde(rename = "3", with = "hex_bytes_vec")]
    pub calibration_signature: Vec<u8>,

    /// Unix timestamp when calibration was performed.
    #[serde(rename = "4")]
    pub timestamp: u64,

    /// Optional calibration authority identifier.
    #[serde(rename = "5", skip_serializing_if = "Option::is_none")]
    pub calibration_authority: Option<String>,
}

impl CalibrationAttestation {
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

    pub fn age_seconds(&self, current_time: u64) -> u64 {
        current_time.saturating_sub(self.timestamp)
    }

    /// Returns `true` if calibration is less than 24 hours old.
    pub fn is_fresh(&self, current_time: u64) -> bool {
        self.age_seconds(current_time) < 86400
    }

    /// Structural validation only — does NOT verify the signature.
    pub fn validate_structure(&self) -> Vec<String> {
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

    pub fn is_valid(&self) -> bool {
        self.validate_structure().is_empty()
    }
}

/// VDF algorithm identifier.
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

/// Extended VDF proof with algorithm metadata for multi-algorithm scenarios.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VdfProofExtended {
    /// Core VDF proof
    pub proof: VdfProofRfc,

    /// Algorithm used
    pub algorithm: VdfAlgorithm,

    /// Intermediate checkpoints for long VDFs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoints: Option<Vec<VdfCheckpoint>>,
}

/// Intermediate VDF checkpoint for partial verification of long proofs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VdfCheckpoint {
    /// Iteration count at this point
    pub iteration: u64,

    /// Output value at this point
    #[serde(with = "hex_bytes")]
    pub value: [u8; 64],

    /// Wall clock elapsed to this point (ms)
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

        let proof = VdfProofRfc::new([1u8; 32], [2u8; 64], 1_000_000, 1000, calibration);

        assert_eq!(proof.iterations, 1_000_000);
        assert_eq!(proof.duration_ms, 1000);
    }

    #[test]
    fn test_minimum_elapsed_calculation() {
        let calibration = CalibrationAttestation::new(1_000_000, "test".to_string(), vec![], 0);

        let proof = VdfProofRfc::new([0u8; 32], [0u8; 64], 2_000_000, 2500, calibration);

        assert_eq!(proof.minimum_elapsed_ms(), 2000);
        assert!(proof.is_duration_consistent());
    }

    #[test]
    fn test_duration_inconsistent_when_too_fast() {
        let calibration = CalibrationAttestation::new(1_000_000, "test".to_string(), vec![], 0);

        let proof = VdfProofRfc::new(
            [0u8; 32],
            [0u8; 64],
            2_000_000,
            500, // Impossibly fast
            calibration,
        );

        assert!(!proof.is_duration_consistent());
    }

    #[test]
    fn test_calibration_freshness() {
        let calibration =
            CalibrationAttestation::new(1_000_000, "test".to_string(), vec![], 1700000000);

        assert!(calibration.is_fresh(1700000000 + 3600));
        assert!(calibration.is_fresh(1700000000 + 86000));
        assert!(!calibration.is_fresh(1700000000 + 90000));
    }

    #[test]
    fn test_vdf_proof_serialization() {
        let calibration = CalibrationAttestation::with_authority(
            500_000,
            "mobile-arm64".to_string(),
            vec![0xAB; 32],
            1700000000,
            "writerslogic.com".to_string(),
        );

        let proof = VdfProofRfc::new([0xDE; 32], [0xAD; 64], 500_000, 1000, calibration);

        let json = serde_json::to_string(&proof).expect("JSON serialization failed");
        assert!(json.contains("\"1\""));
        assert!(json.contains("\"2\""));

        let decoded: VdfProofRfc =
            serde_json::from_str(&json).expect("JSON deserialization failed");
        assert_eq!(decoded, proof);
    }

    #[test]
    fn test_iterations_per_ms() {
        let calibration = CalibrationAttestation::new(1_000_000, "test".to_string(), vec![1u8], 1);

        let proof = VdfProofRfc::new([1u8; 32], [1u8; 64], 1_000_000, 1000, calibration);

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

        let proof = VdfProofRfc::new([1u8; 32], [2u8; 64], 1_000_000, 1000, calibration);

        assert!(proof.is_valid());
        assert!(proof.validate().is_empty());
    }

    #[test]
    fn test_vdf_proof_validate_zero_challenge() {
        let calibration =
            CalibrationAttestation::new(1_000_000, "test".to_string(), vec![1u8], 1700000000);

        let proof = VdfProofRfc::new([0u8; 32], [2u8; 64], 1_000_000, 1000, calibration);

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

        let proof = VdfProofRfc::new([1u8; 32], [0u8; 64], 1_000_000, 1000, calibration);

        let errors = proof.validate();
        assert!(errors.iter().any(|e| e.contains("output must be non-zero")));
        assert!(!proof.is_valid());
    }

    #[test]
    fn test_vdf_proof_validate_zero_iterations() {
        let calibration =
            CalibrationAttestation::new(1_000_000, "test".to_string(), vec![1u8], 1700000000);

        let proof = VdfProofRfc::new([1u8; 32], [2u8; 64], 0, 1000, calibration);

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

        let proof = VdfProofRfc::new([1u8; 32], [2u8; 64], 1_000_000, 0, calibration);

        let errors = proof.validate();
        assert!(errors
            .iter()
            .any(|e| e.contains("duration_ms must be non-zero")));
        assert!(!proof.is_valid());
    }

    #[test]
    fn test_vdf_proof_validate_inconsistent_duration() {
        let calibration =
            CalibrationAttestation::new(1_000_000, "test".to_string(), vec![1u8], 1700000000);

        let proof = VdfProofRfc::new(
            [1u8; 32],
            [2u8; 64],
            2_000_000,
            500, // Impossibly fast
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
        assert!(calibration.validate_structure().is_empty());
    }

    #[test]
    fn test_calibration_validate_zero_iterations_per_second() {
        let calibration = CalibrationAttestation::new(0, "test".to_string(), vec![1u8], 1700000000);

        let errors = calibration.validate_structure();
        assert!(errors
            .iter()
            .any(|e| e.contains("iterations_per_second must be non-zero")));
        assert!(!calibration.is_valid());
    }

    #[test]
    fn test_calibration_validate_empty_hardware_class() {
        let calibration =
            CalibrationAttestation::new(1_000_000, "".to_string(), vec![1u8], 1700000000);

        let errors = calibration.validate_structure();
        assert!(errors
            .iter()
            .any(|e| e.contains("hardware_class must be non-empty")));
        assert!(!calibration.is_valid());
    }

    #[test]
    fn test_calibration_validate_empty_signature() {
        let calibration =
            CalibrationAttestation::new(1_000_000, "test".to_string(), vec![], 1700000000);

        let errors = calibration.validate_structure();
        assert!(errors
            .iter()
            .any(|e| e.contains("calibration_signature must be non-empty")));
        assert!(!calibration.is_valid());
    }

    #[test]
    fn test_calibration_validate_zero_timestamp() {
        let calibration = CalibrationAttestation::new(1_000_000, "test".to_string(), vec![1u8], 0);

        let errors = calibration.validate_structure();
        assert!(errors
            .iter()
            .any(|e| e.contains("timestamp must be non-zero")));
        assert!(!calibration.is_valid());
    }

    #[test]
    fn test_vdf_proof_validate_multiple_errors() {
        let calibration = CalibrationAttestation::new(0, "".to_string(), vec![], 0);

        let proof = VdfProofRfc::new([0u8; 32], [0u8; 64], 0, 0, calibration);

        let errors = proof.validate();
        assert!(errors.len() >= 8);
        assert!(!proof.is_valid());
    }
}
