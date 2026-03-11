// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Wire-format checkpoint type per CDDL `checkpoint`.

use serde::{Deserialize, Serialize};

use super::components::{
    ActiveProbe, EditDelta, JitterBindingWire, PhysicalState, ProcessProof, Receipt,
};
use super::hash::HashValue;
use super::serde_helpers::{fixed_bytes_16, serde_bytes_opt};

/// Wire-format checkpoint per CDDL `checkpoint`.
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
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointWire {
    #[serde(rename = "1")]
    pub sequence: u64,

    #[serde(rename = "2", with = "fixed_bytes_16")]
    pub checkpoint_id: [u8; 16],

    /// Epoch ms
    #[serde(rename = "3")]
    pub timestamp: u64,

    #[serde(rename = "4")]
    pub content_hash: HashValue,

    #[serde(rename = "5")]
    pub char_count: u64,

    #[serde(rename = "6")]
    pub delta: EditDelta,

    /// Zeros for the first checkpoint in a chain
    #[serde(rename = "7")]
    pub prev_hash: HashValue,

    #[serde(rename = "8")]
    pub checkpoint_hash: HashValue,

    #[serde(rename = "9")]
    pub process_proof: ProcessProof,

    /// ENHANCED+ tier only
    #[serde(rename = "10", default, skip_serializing_if = "Option::is_none")]
    pub jitter_binding: Option<JitterBindingWire>,

    /// ENHANCED+ tier only
    #[serde(rename = "11", default, skip_serializing_if = "Option::is_none")]
    pub physical_state: Option<PhysicalState>,

    /// ENHANCED+ tier only
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
}

/// Max self-receipts per checkpoint.
const MAX_SELF_RECEIPTS: usize = 100;
/// Max active probes per checkpoint.
const MAX_ACTIVE_PROBES: usize = 100;
/// Max entangled MAC length (HMAC-SHA256 = 32 bytes).
const MAX_ENTANGLED_MAC_LEN: usize = 64;

/// Subset of CheckpointWire fields for hash computation (excludes `checkpoint_hash`).
///
/// Per draft-condrey-rats-pop: `checkpoint-hash = SHA-256(CBOR(checkpoint \ {8}))`.
#[derive(Serialize)]
struct CheckpointHashInput<'a> {
    #[serde(rename = "1")]
    sequence: u64,
    #[serde(rename = "2", with = "fixed_bytes_16")]
    checkpoint_id: [u8; 16],
    #[serde(rename = "3")]
    timestamp: u64,
    #[serde(rename = "4")]
    content_hash: &'a HashValue,
    #[serde(rename = "5")]
    char_count: u64,
    #[serde(rename = "6")]
    delta: &'a EditDelta,
    #[serde(rename = "7")]
    prev_hash: &'a HashValue,
    #[serde(rename = "9")]
    process_proof: &'a ProcessProof,
    #[serde(rename = "10", skip_serializing_if = "Option::is_none")]
    jitter_binding: Option<&'a JitterBindingWire>,
    #[serde(rename = "11", skip_serializing_if = "Option::is_none")]
    physical_state: Option<&'a PhysicalState>,
    #[serde(
        rename = "12",
        skip_serializing_if = "Option::is_none",
        with = "serde_bytes_opt"
    )]
    entangled_mac: Option<Vec<u8>>,
}

impl CheckpointWire {
    /// Compute the spec-conformant checkpoint hash.
    ///
    /// Per draft-condrey-rats-pop:
    /// `checkpoint-hash = SHA-256("PoP-Checkpoint-v1" || CBOR-encode(checkpoint \ {8}))`,
    /// i.e. prepend the DST, then CBOR-encode all fields except `checkpoint_hash`, then SHA-256.
    pub fn compute_hash(&self) -> HashValue {
        use sha2::{Digest, Sha256};

        let input = CheckpointHashInput {
            sequence: self.sequence,
            checkpoint_id: self.checkpoint_id,
            timestamp: self.timestamp,
            content_hash: &self.content_hash,
            char_count: self.char_count,
            delta: &self.delta,
            prev_hash: &self.prev_hash,
            process_proof: &self.process_proof,
            jitter_binding: self.jitter_binding.as_ref(),
            physical_state: self.physical_state.as_ref(),
            entangled_mac: self.entangled_mac.clone(),
        };

        let cbor_bytes =
            crate::codec::cbor::encode(&input).expect("CBOR encode checkpoint hash input");
        let mut hasher = Sha256::new();
        hasher.update(b"PoP-Checkpoint-v1");
        hasher.update(&cbor_bytes);
        let digest: [u8; 32] = hasher.finalize().into();
        HashValue::sha256(digest.to_vec())
    }

    /// Validate size limits and hash digests.
    pub fn validate(&self) -> Result<(), String> {
        self.content_hash.validate_digest_length()?;
        self.prev_hash.validate_digest_length()?;
        self.checkpoint_hash.validate_digest_length()?;

        if let Some(ref mac) = self.entangled_mac {
            if mac.len() > MAX_ENTANGLED_MAC_LEN {
                return Err(format!(
                    "entangled_mac too long: {} (max {})",
                    mac.len(),
                    MAX_ENTANGLED_MAC_LEN
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

        self.process_proof.validate()?;

        if let Some(ref jb) = self.jitter_binding {
            jb.validate()?;
        }

        Ok(())
    }
}
