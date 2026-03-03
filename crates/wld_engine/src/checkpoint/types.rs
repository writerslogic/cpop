// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration;

use crate::error::{Error, Result};
use crate::rfc::{self, TimeEvidence, VdfProofRfc};
use crate::vdf::VdfProof;
use crate::DateTimeNanosExt;

/// Entanglement mode for checkpoint chain computation.
///
/// WAR/1.0 (Legacy): VDF input = hash(content_hash ‖ previous_checkpoint_hash ‖ ordinal)
/// WAR/1.1 (Entangled): VDF input = hash(previous_vdf_output ‖ jitter_hash ‖ content_hash ‖ ordinal)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum EntanglementMode {
    /// Legacy mode (WAR/1.0): parallel computation possible
    #[default]
    Legacy,
    /// Entangled mode (WAR/1.1): each VDF depends on previous VDF output + jitter
    Entangled,
}

/// Signature policy for checkpoint chains.
///
/// Controls whether checkpoints must be signed with ratchet keys.
/// Legacy chains deserialize as `Optional`; new chains should use `Required`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum SignaturePolicy {
    /// Legacy chains: warn on unsigned checkpoints but allow verification to pass
    #[default]
    Optional,
    /// New chains: reject any checkpoint without a valid signature
    Required,
}

/// Granular verification results for a checkpoint chain (beyond pass/fail).
#[derive(Debug, Clone)]
pub struct VerificationReport {
    pub valid: bool,
    pub unsigned_checkpoints: Vec<u64>,
    pub signature_failures: Vec<u64>,
    /// (expected, actual) ordinal pairs
    pub ordinal_gaps: Vec<(u64, u64)>,
    pub metadata_valid: bool,
    /// Non-fatal issues (e.g., unsigned under `Optional` policy)
    pub warnings: Vec<String>,
    pub error: Option<String>,
}

impl VerificationReport {
    pub(super) fn new() -> Self {
        Self {
            valid: true,
            unsigned_checkpoints: Vec::new(),
            signature_failures: Vec::new(),
            ordinal_gaps: Vec::new(),
            metadata_valid: true,
            warnings: Vec::new(),
            error: None,
        }
    }

    pub(super) fn fail(&mut self, msg: String) {
        self.valid = false;
        self.error = Some(msg);
    }
}

/// Cryptographic link between behavioral timing jitter and the checkpoint chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JitterBinding {
    pub jitter_hash: [u8; 32],
    pub session_id: String,
    pub keystroke_count: u64,
    /// Physics-bound seed mixed into the VDF input for stronger non-repudiation.
    /// Present when a `PhysicalContext` was available at checkpoint creation time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub physics_seed: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub ordinal: u64,
    pub previous_hash: [u8; 32],
    pub hash: [u8; 32],
    pub content_hash: [u8; 32],
    pub content_size: u64,
    /// Deprecated: redundant with `Chain::document_path`. Retained for backward-compatible
    /// deserialization of older chains; new checkpoints leave this empty.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub file_path: String,
    pub timestamp: DateTime<Utc>,
    pub message: Option<String>,
    pub vdf: Option<VdfProof>,
    pub tpm_binding: Option<TpmBinding>,
    pub signature: Option<Vec<u8>>,
    /// Jitter binding for entangled mode (WAR/1.1)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jitter_binding: Option<JitterBinding>,

    /// RFC-compliant VDF proof (CDDL `vdf-proof`)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rfc_vdf: Option<VdfProofRfc>,

    /// RFC-compliant jitter binding (entropy commitment + stats)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rfc_jitter: Option<rfc::JitterBinding>,

    /// External time evidence (roughtime, TSA, blockchain anchors)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_evidence: Option<TimeEvidence>,

    /// Serialized `InclusionProof` for anti-deletion verification
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mmr_inclusion_proof: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmBinding {
    pub monotonic_counter: u64,
    pub clock_info: Vec<u8>,
    pub attestation: Vec<u8>,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
}

/// Signed chain state snapshot for anti-deletion verification.
///
/// Signed with the current ratchet key; deleting checkpoints invalidates the signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainMetadata {
    pub checkpoint_count: u64,
    pub mmr_root: [u8; 32],
    /// Should equal `checkpoint_count`
    pub mmr_leaf_count: u64,
    /// Ed25519 over `(checkpoint_count || mmr_root || mmr_leaf_count)`
    pub metadata_signature: Option<Vec<u8>>,
    pub metadata_version: u32,
}

impl Checkpoint {
    /// Base constructor with common fields initialized and variant-specific fields defaulted.
    pub(super) fn new_base(
        ordinal: u64,
        previous_hash: [u8; 32],
        content_hash: [u8; 32],
        content_size: u64,
        message: Option<String>,
    ) -> Self {
        Self {
            ordinal,
            previous_hash,
            hash: [0u8; 32],
            content_hash,
            content_size,
            file_path: String::new(),
            timestamp: Utc::now(),
            message,
            vdf: None,
            tpm_binding: None,
            signature: None,
            jitter_binding: None,
            rfc_vdf: None,
            rfc_jitter: None,
            time_evidence: None,
            mmr_inclusion_proof: None,
        }
    }

    /// Reject timestamps that overflow i64 nanos (~2262+) or precede the Unix epoch,
    /// either of which would silently degrade hash uniqueness.
    pub(super) fn validate_timestamp(&self) -> Result<()> {
        let nanos = self.timestamp.timestamp_nanos_opt();
        if nanos.is_none() {
            return Err(Error::checkpoint(format!(
                "checkpoint timestamp {} overflows nanosecond representation",
                self.timestamp
            )));
        }
        // Pre-epoch: `as u64` would wrap negative values
        if nanos.unwrap() < 0 {
            return Err(Error::checkpoint(format!(
                "checkpoint timestamp {} is before the Unix epoch",
                self.timestamp
            )));
        }
        Ok(())
    }

    pub(super) fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        // Domain separator: v3 (RFC fields), v2 (jitter), v1 (legacy)
        if self.rfc_vdf.is_some() || self.rfc_jitter.is_some() || self.time_evidence.is_some() {
            hasher.update(b"witnessd-checkpoint-v3");
        } else if self.jitter_binding.is_some() {
            hasher.update(b"witnessd-checkpoint-v2");
        } else {
            hasher.update(b"witnessd-checkpoint-v1");
        }
        hasher.update(self.ordinal.to_be_bytes());
        hasher.update(self.previous_hash);
        hasher.update(self.content_hash);
        hasher.update(self.content_size.to_be_bytes());

        let timestamp_nanos = self.timestamp.timestamp_nanos_safe() as u64;
        hasher.update(timestamp_nanos.to_be_bytes());

        if let Some(vdf) = &self.vdf {
            hasher.update(vdf.encode());
        }

        if let Some(jitter) = &self.jitter_binding {
            hasher.update(jitter.jitter_hash);
            hasher.update(jitter.session_id.as_bytes());
            hasher.update(jitter.keystroke_count.to_be_bytes());
            if let Some(physics_seed) = &jitter.physics_seed {
                hasher.update(physics_seed);
            }
        }

        if let Some(rfc_vdf) = &self.rfc_vdf {
            hasher.update(rfc_vdf.challenge);
            hasher.update(rfc_vdf.output);
            hasher.update(rfc_vdf.iterations.to_be_bytes());
            hasher.update(rfc_vdf.duration_ms.to_be_bytes());
            hasher.update(rfc_vdf.calibration.iterations_per_second.to_be_bytes());
            hasher.update(rfc_vdf.calibration.hardware_class.as_bytes());
        }

        if let Some(rfc_jitter) = &self.rfc_jitter {
            hasher.update(rfc_jitter.entropy_commitment.hash);
            hasher.update(rfc_jitter.summary.sample_count.to_be_bytes());
            if let Some(hurst) = rfc_jitter.summary.hurst_exponent {
                hasher.update(hurst.to_be_bytes());
            }
        }

        if let Some(time_ev) = &self.time_evidence {
            hasher.update([time_ev.tier as u8]);
            hasher.update(time_ev.timestamp_ms.to_be_bytes());
        }

        hasher.finalize().into()
    }

    pub fn with_rfc_vdf(mut self, vdf_proof: VdfProofRfc) -> Self {
        self.rfc_vdf = Some(vdf_proof);
        self
    }

    pub fn with_rfc_jitter(mut self, jitter: rfc::JitterBinding) -> Self {
        self.rfc_jitter = Some(jitter);
        self
    }

    pub fn with_time_evidence(mut self, evidence: TimeEvidence) -> Self {
        self.time_evidence = Some(evidence);
        self
    }

    /// Convert internal `VdfProof` to RFC-compliant `VdfProofRfc`.
    pub fn to_rfc_vdf(&self, calibration: rfc::CalibrationAttestation) -> Option<VdfProofRfc> {
        self.vdf.as_ref().map(|vdf| {
            // Expand to 64-byte Wesolowski-style: output || input for integrity
            let mut output = [0u8; 64];
            output[..32].copy_from_slice(&vdf.output);
            output[32..].copy_from_slice(&vdf.input);

            VdfProofRfc::new(
                vdf.input,
                output,
                vdf.iterations,
                vdf.duration.as_millis().min(u64::MAX as u128) as u64,
                calibration,
            )
        })
    }

    /// Recompute the hash after modifying checkpoint fields.
    pub fn recompute_hash(&mut self) {
        self.hash = self.compute_hash();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainSummary {
    pub document_path: String,
    pub checkpoint_count: usize,
    pub first_commit: Option<DateTime<Utc>>,
    pub last_commit: Option<DateTime<Utc>>,
    pub total_elapsed_time: Duration,
    pub final_content_hash: Option<String>,
    /// `None` when not yet verified; call `Chain::verify_hash_chain()` explicitly.
    pub chain_valid: Option<bool>,
}
