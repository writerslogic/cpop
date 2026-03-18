// SPDX-License-Identifier: Apache-2.0

//! Wire-format checkpoint type per CDDL `checkpoint`.

use serde::{Deserialize, Serialize};

use super::components::{
    ActiveProbe, BeaconAnchor, EditDelta, HatProof, JitterBindingWire, PhysicalState, ProcessProof,
    Receipt,
};
use super::hash::HashValue;
use super::serde_helpers::{fixed_bytes_16, fixed_bytes_32_opt, serde_bytes_opt};

/// Wire-format checkpoint per draft-condrey-rats-pop CDDL `checkpoint`.
///
/// ```cddl
/// checkpoint = {
///     1 => uint,               ; sequence
///     2 => uuid,               ; checkpoint-id
///     3 => pop-timestamp,      ; timestamp
///     4 => hash-value,         ; content-hash
///     5 => uint,               ; char-count
///     6 => edit-delta,         ; delta
///     7 => hash-value,         ; prev-hash
///     8 => hash-value,         ; checkpoint-hash
///     9 => process-proof,      ; SWF proof
///     ? 10 => jitter-binding,
///     ? 11 => physical-state,
///     ? 12 => hash-digest,     ; entangled-mac
///     ? 13 => [+ receipt],
///     ? 14 => [+ active-probe],
///     ? 15 => hat-proof,
///     ? 16 => beacon-anchor,
///     ? 17 => bstr .size 32, ; verifier-nonce
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointWire {
    #[serde(rename = "1")]
    pub sequence: u64,

    #[serde(rename = "2", with = "fixed_bytes_16")]
    pub checkpoint_id: [u8; 16],

    #[serde(rename = "3")]
    pub timestamp: u64,

    #[serde(rename = "4")]
    pub content_hash: HashValue,

    #[serde(rename = "5")]
    pub char_count: u64,

    #[serde(rename = "6")]
    pub delta: EditDelta,

    #[serde(rename = "7")]
    pub prev_hash: HashValue,

    #[serde(rename = "8")]
    pub checkpoint_hash: HashValue,

    #[serde(rename = "9")]
    pub process_proof: ProcessProof,

    #[serde(rename = "10", default, skip_serializing_if = "Option::is_none")]
    pub jitter_binding: Option<JitterBindingWire>,

    #[serde(rename = "11", default, skip_serializing_if = "Option::is_none")]
    pub physical_state: Option<PhysicalState>,

    #[serde(
        rename = "12",
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_bytes_opt"
    )]
    pub entangled_mac: Option<Vec<u8>>,

    #[serde(rename = "13", default, skip_serializing_if = "Option::is_none")]
    pub receipts: Option<Vec<Receipt>>,

    #[serde(rename = "14", default, skip_serializing_if = "Option::is_none")]
    pub active_probes: Option<Vec<ActiveProbe>>,

    /// HAT temporal proof (T3/T4)
    #[serde(rename = "15", default, skip_serializing_if = "Option::is_none")]
    pub hat_proof: Option<HatProof>,

    /// Public randomness beacon anchor
    #[serde(rename = "16", default, skip_serializing_if = "Option::is_none")]
    pub beacon_anchor: Option<BeaconAnchor>,

    /// Verifier nonce for interactive mode (32 bytes)
    #[serde(
        rename = "17",
        default,
        skip_serializing_if = "Option::is_none",
        with = "fixed_bytes_32_opt"
    )]
    pub verifier_nonce: Option<[u8; 32]>,
}

const MAX_SELF_RECEIPTS: usize = 100;
const MAX_ACTIVE_PROBES: usize = 100;

impl CheckpointWire {
    /// Compute the spec-conformant checkpoint hash per draft-condrey-rats-pop S6.6.
    ///
    /// ```text
    /// checkpoint-hash = H(
    ///     "PoP-Checkpoint-v1" ||
    ///     prev-hash.digest ||
    ///     content-hash.digest ||
    ///     CBOR-encode(edit-delta) ||
    ///     CBOR-encode(jitter-binding) ||   ; if present
    ///     CBOR-encode(physical-state) ||   ; if present
    ///     process-proof.merkle-root
    /// )
    /// ```
    pub fn compute_hash(&self) -> HashValue {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();

        hasher.update(b"PoP-Checkpoint-v1");
        hasher.update(&self.prev_hash.digest);
        hasher.update(&self.content_hash.digest);

        let delta_cbor = crate::codec::cbor::encode(&self.delta).expect("CBOR encode edit-delta");
        hasher.update(&delta_cbor);

        if let Some(ref jitter) = self.jitter_binding {
            let jitter_cbor =
                crate::codec::cbor::encode(jitter).expect("CBOR encode jitter-binding");
            hasher.update(&jitter_cbor);
        }

        if let Some(ref phys) = self.physical_state {
            let phys_cbor = crate::codec::cbor::encode(phys).expect("CBOR encode physical-state");
            hasher.update(&phys_cbor);
        }

        hasher.update(&self.process_proof.merkle_root);

        let digest: [u8; 32] = hasher.finalize().into();
        HashValue::sha256(digest.to_vec())
    }

    /// Validate digest lengths, size limits, and nested structure.
    pub fn validate(&self) -> Result<(), String> {
        self.content_hash.validate_digest_length()?;
        self.prev_hash.validate_digest_length()?;
        self.checkpoint_hash.validate_digest_length()?;

        if let Some(ref mac) = self.entangled_mac {
            if !matches!(mac.len(), 32 | 48 | 64) {
                return Err(format!(
                    "entangled_mac length {} invalid (must be 32, 48, or 64 bytes)",
                    mac.len()
                ));
            }
        }
        if let Some(ref receipts) = self.receipts {
            if receipts.len() > MAX_SELF_RECEIPTS {
                return Err(format!(
                    "too many receipts: {} (max {})",
                    receipts.len(),
                    MAX_SELF_RECEIPTS
                ));
            }
        }
        if let Some(ref probes) = self.active_probes {
            if probes.len() > MAX_ACTIVE_PROBES {
                return Err(format!(
                    "too many active_probes: {} (max {})",
                    probes.len(),
                    MAX_ACTIVE_PROBES
                ));
            }
        }

        self.delta.validate()?;
        self.process_proof.validate()?;

        if let Some(ref jb) = self.jitter_binding {
            jb.validate()?;
        }

        Ok(())
    }
}
