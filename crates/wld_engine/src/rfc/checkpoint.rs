// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! RFC-compliant checkpoint structure for CBOR encoding.
//!
//! Implements the checkpoint CDDL structure from draft-condrey-rats-pop-schema-01:
//!
//! ```cddl
//! checkpoint = {
//!     1 => uint,           ; sequence
//!     2 => uuid,           ; checkpoint-id
//!     3 => pop-timestamp,  ; timestamp
//!     4 => bstr .size 32,  ; content-hash
//!     5 => bstr .size 32,  ; prev-hash
//!     6 => bstr .size 32,  ; checkpoint-hash
//!     7 => vdf-proof,      ; silicon-anchored VDF
//!     8 => jitter-binding, ; behavioral binding
//!     9 => bstr .size 32,  ; chain-mac (PUF-bound)
//! }
//! ```

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::fixed_point::{Millibits, RhoMillibits};
use super::jitter_binding::JitterBinding;
use super::serde_helpers::{hex_bytes, hex_bytes_32_opt, hex_bytes_vec};
use super::vdf::VdfProofRfc;

/// RFC-compliant checkpoint for CBOR wire format.
///
/// Separate from internal `Checkpoint` to allow different serialization
/// strategies (JSON for human-readable, CBOR for wire).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointRfc {
    /// Sequence number (ordinal) of this checkpoint in the chain.
    #[serde(rename = "1")]
    pub sequence: u64,

    /// Checkpoint UUID (v4)
    #[serde(rename = "2")]
    pub checkpoint_id: Uuid,

    /// Unix timestamp (epoch seconds)
    #[serde(rename = "3")]
    pub timestamp: u64,

    /// SHA-256 of document content at checkpoint time
    #[serde(rename = "4", with = "hex_bytes")]
    pub content_hash: [u8; 32],

    /// SHA-256 of previous checkpoint (zeros for first)
    #[serde(rename = "5", with = "hex_bytes")]
    pub prev_hash: [u8; 32],

    /// SHA-256 of this checkpoint structure
    #[serde(rename = "6", with = "hex_bytes")]
    pub checkpoint_hash: [u8; 32],

    /// Silicon-anchored VDF proof (optional for first checkpoint)
    #[serde(rename = "7", skip_serializing_if = "Option::is_none")]
    pub vdf_proof: Option<VdfProofRfc>,

    /// Behavioral jitter binding
    #[serde(rename = "8", skip_serializing_if = "Option::is_none")]
    pub jitter_binding: Option<JitterBinding>,

    /// PUF-bound chain MAC
    #[serde(
        rename = "9",
        skip_serializing_if = "Option::is_none",
        with = "hex_bytes_32_opt"
    )]
    pub chain_mac: Option<[u8; 32]>,
}

impl CheckpointRfc {
    /// Create a checkpoint with core fields; optional fields default to `None`.
    pub fn new(sequence: u64, timestamp: u64, content_hash: [u8; 32], prev_hash: [u8; 32]) -> Self {
        Self {
            sequence,
            checkpoint_id: Uuid::new_v4(),
            timestamp,
            content_hash,
            prev_hash,
            checkpoint_hash: [0u8; 32], // Computed later
            vdf_proof: None,
            jitter_binding: None,
            chain_mac: None,
        }
    }

    /// Attach VDF proof.
    pub fn with_vdf(mut self, proof: VdfProofRfc) -> Self {
        self.vdf_proof = Some(proof);
        self
    }

    /// Attach jitter binding.
    pub fn with_jitter(mut self, binding: JitterBinding) -> Self {
        self.jitter_binding = Some(binding);
        self
    }

    /// Attach PUF-bound chain MAC.
    pub fn with_chain_mac(mut self, mac: [u8; 32]) -> Self {
        self.chain_mac = Some(mac);
        self
    }

    /// Compute and set `checkpoint_hash` (SHA-256 over all fields except itself).
    pub fn compute_hash(&mut self) {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();

        // Domain separation
        hasher.update(b"witnessd-checkpoint-v3");

        // Hash core fields
        hasher.update(self.sequence.to_be_bytes());
        hasher.update(self.checkpoint_id.as_bytes());
        hasher.update(self.timestamp.to_be_bytes());
        hasher.update(self.content_hash);
        hasher.update(self.prev_hash);

        // Hash optional VDF proof
        if let Some(vdf) = &self.vdf_proof {
            hasher.update(b"\x01"); // present marker
            hasher.update(vdf.challenge);
            hasher.update(vdf.output);
            hasher.update(vdf.iterations.to_be_bytes());
            hasher.update(vdf.duration_ms.to_be_bytes());
        } else {
            hasher.update(b"\x00"); // absent marker
        }

        // Hash optional jitter binding
        if let Some(jitter) = &self.jitter_binding {
            hasher.update(b"\x01");
            hasher.update(jitter.entropy_commitment.hash);
        } else {
            hasher.update(b"\x00");
        }

        // Hash optional chain MAC
        if let Some(mac) = &self.chain_mac {
            hasher.update(b"\x01");
            hasher.update(mac);
        } else {
            hasher.update(b"\x00");
        }

        self.checkpoint_hash = hasher.finalize().into();
    }

    /// Validate all fields. Returns a list of errors (empty if valid).
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        // Content hash must be non-zero
        if self.content_hash == [0u8; 32] {
            errors.push("content_hash is zero".into());
        }

        // Checkpoint hash must be non-zero (except during construction)
        if self.checkpoint_hash == [0u8; 32] {
            errors.push("checkpoint_hash is zero (call compute_hash first)".into());
        }

        // Validate VDF if present
        if let Some(vdf) = &self.vdf_proof {
            errors.extend(vdf.validate());
        }

        // Validate jitter binding if present
        if let Some(jitter) = &self.jitter_binding {
            errors.extend(jitter.validate());
        }

        errors
    }

    /// Returns `true` if no validation errors.
    pub fn is_valid(&self) -> bool {
        self.validate().is_empty()
    }
}

/// Silicon-bound VDF proof with bio-binding.
///
/// ```cddl
/// sa-vdf-proof = {
///     1 => uint,   ; algorithm (20=hmac-sha256-puf)
///     2 => uint,   ; iterations
///     3 => uint,   ; cycle-count (RDTSC)
///     4 => bstr,   ; output
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaVdfProof {
    /// Algorithm identifier (20 = HMAC-SHA256-PUF)
    #[serde(rename = "1")]
    pub algorithm: u32,

    /// Iteration count
    #[serde(rename = "2")]
    pub iterations: u64,

    /// CPU cycle count (RDTSC)
    #[serde(rename = "3")]
    pub cycle_count: u64,

    /// VDF output
    #[serde(rename = "4", with = "hex_bytes_vec")]
    pub output: Vec<u8>,
}

/// Biometric binding for checkpoint.
///
/// ```cddl
/// bio-binding = {
///     1 => uint,   ; rho_millibits (Spearman * 1000)
///     2 => uint,   ; hurst_millibits (H * 1000)
///     3 => uint,   ; recognition_gap_ms
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BioBinding {
    /// Spearman rho (x1000)
    #[serde(rename = "1")]
    pub rho_millibits: RhoMillibits,

    /// Hurst exponent (x1000)
    #[serde(rename = "2")]
    pub hurst_millibits: Millibits,

    /// Recognition gap (ms)
    #[serde(rename = "3")]
    pub recognition_gap_ms: u32,
}

impl BioBinding {
    /// Create from floating-point values.
    pub fn new(rho: f64, hurst: f64, gap_ms: u32) -> Self {
        Self {
            rho_millibits: RhoMillibits::from_float(rho),
            hurst_millibits: Millibits::from_float(hurst),
            recognition_gap_ms: gap_ms,
        }
    }

    /// Returns `true` if Hurst exponent is in the human typing range (0.55..0.85).
    pub fn is_hurst_human_like(&self) -> bool {
        let h = self.hurst_millibits.raw();
        h > 550 && h < 850 // 0.55 < H < 0.85
    }

    /// Returns `true` if rho is in the acceptable range (0.5..=0.95).
    pub fn is_correlation_valid(&self) -> bool {
        let rho = self.rho_millibits.raw();
        (500..=950).contains(&rho) // 0.5 <= rho <= 0.95
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checkpoint_creation() {
        let cp = CheckpointRfc::new(0, 1700000000, [1u8; 32], [0u8; 32]);

        assert_eq!(cp.sequence, 0);
        assert_eq!(cp.content_hash, [1u8; 32]);
        assert_eq!(cp.prev_hash, [0u8; 32]);
    }

    #[test]
    fn test_checkpoint_hash_computation() {
        let mut cp = CheckpointRfc::new(1, 1700000000, [1u8; 32], [2u8; 32]);

        assert_eq!(cp.checkpoint_hash, [0u8; 32]);
        cp.compute_hash();
        assert_ne!(cp.checkpoint_hash, [0u8; 32]);
    }

    #[test]
    fn test_bio_binding_hurst() {
        let binding = BioBinding::new(0.75, 0.72, 250);
        assert!(binding.is_hurst_human_like());
        assert!(binding.is_correlation_valid());

        // White noise (H=0.5)
        let white_noise = BioBinding::new(0.75, 0.5, 250);
        assert!(!white_noise.is_hurst_human_like());
    }

    #[test]
    fn test_checkpoint_serialization() {
        let cp = CheckpointRfc::new(0, 1700000000, [1u8; 32], [0u8; 32]);

        let json = serde_json::to_string(&cp).unwrap();
        assert!(json.contains("\"1\":0")); // sequence
        assert!(json.contains("\"3\":1700000000")); // timestamp
    }
}
