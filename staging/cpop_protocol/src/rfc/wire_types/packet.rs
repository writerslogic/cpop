// SPDX-License-Identifier: Apache-2.0

//! Wire-format evidence packet type per CDDL `evidence-packet`.

use serde::{Deserialize, Serialize};

use super::checkpoint::CheckpointWire;
use super::components::{
    BaselineVerification, ChannelBinding, DocumentRef, PhysicalLiveness, PresenceChallenge,
    ProfileDeclarationWire,
};
use super::enums::{AttestationTier, ContentTier};
use super::hash::HashValue;
use super::serde_helpers::fixed_bytes_16;
use super::CBOR_TAG_EVIDENCE_PACKET;
use crate::codec::{self, CodecError};

/// Wire-format evidence packet per CDDL `evidence-packet`.
///
/// Wrapped with CBOR tag 1129336656 (CPOP) for transmission.
///
/// ```cddl
/// evidence-packet = {
///     1 => uint,                    ; version
///     2 => tstr,                    ; profile-uri
///     3 => uuid,                    ; packet-id
///     4 => pop-timestamp,           ; created
///     5 => document-ref,            ; document
///     6 => [3* checkpoint],         ; checkpoints (min 3)
///     ? 7 => attestation-tier,
///     ? 8 => [* tstr],              ; limitations
///     ? 9 => profile-declaration,
///     ? 10 => [+ presence-challenge],
///     ? 11 => channel-binding,
///     ? 13 => content-tier,
///     ? 14 => hash-value,           ; previous-packet-ref
///     ? 15 => uint,                 ; packet-sequence
///     ? 18 => physical-liveness,
///     ? 19 => baseline-verification,
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidencePacketWire {
    /// Must be 1
    #[serde(rename = "1")]
    pub version: u64,

    #[serde(rename = "2")]
    pub profile_uri: String,

    #[serde(rename = "3", with = "fixed_bytes_16")]
    pub packet_id: [u8; 16],

    /// Epoch ms
    #[serde(rename = "4")]
    pub created: u64,

    #[serde(rename = "5")]
    pub document: DocumentRef,

    /// Minimum 3 checkpoints required
    #[serde(rename = "6")]
    pub checkpoints: Vec<CheckpointWire>,

    #[serde(rename = "7", default, skip_serializing_if = "Option::is_none")]
    pub attestation_tier: Option<AttestationTier>,

    #[serde(rename = "8", default, skip_serializing_if = "Option::is_none")]
    pub limitations: Option<Vec<String>>,

    #[serde(rename = "9", default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<ProfileDeclarationWire>,

    #[serde(rename = "10", default, skip_serializing_if = "Option::is_none")]
    pub presence_challenges: Option<Vec<PresenceChallenge>>,

    #[serde(rename = "11", default, skip_serializing_if = "Option::is_none")]
    pub channel_binding: Option<ChannelBinding>,

    #[serde(rename = "13", default, skip_serializing_if = "Option::is_none")]
    pub content_tier: Option<ContentTier>,

    #[serde(rename = "14", default, skip_serializing_if = "Option::is_none")]
    pub previous_packet_ref: Option<HashValue>,

    /// 1-based
    #[serde(rename = "15", default, skip_serializing_if = "Option::is_none")]
    pub packet_sequence: Option<u64>,

    #[serde(rename = "18", default, skip_serializing_if = "Option::is_none")]
    pub physical_liveness: Option<PhysicalLiveness>,

    #[serde(rename = "19", default, skip_serializing_if = "Option::is_none")]
    pub baseline_verification: Option<BaselineVerification>,
}

/// Minimum number of checkpoints per CDDL: `6 => [3* checkpoint]`.
const MIN_CHECKPOINTS: usize = 3;
/// Maximum checkpoints before rejecting as DoS payload.
const MAX_CHECKPOINTS: usize = 10_000;
/// Maximum number of limitation strings.
const MAX_LIMITATIONS: usize = 100;
/// Maximum number of presence challenges.
const MAX_PRESENCE_CHALLENGES: usize = 100;
use super::MAX_STRING_LEN;

impl EvidencePacketWire {
    /// Encode to CBOR with the CPOP semantic tag.
    pub fn encode_cbor(&self) -> Result<Vec<u8>, CodecError> {
        codec::cbor::encode_tagged(self, CBOR_TAG_EVIDENCE_PACKET)
    }

    /// Decode from tagged CBOR bytes with validation.
    pub fn decode_cbor(data: &[u8]) -> Result<Self, CodecError> {
        let packet: Self = codec::cbor::decode_tagged(data, CBOR_TAG_EVIDENCE_PACKET)?;
        packet.validate()?;
        Ok(packet)
    }

    /// Encode to CBOR without the semantic tag.
    pub fn encode_cbor_untagged(&self) -> Result<Vec<u8>, CodecError> {
        codec::cbor::encode(self)
    }

    /// Decode from untagged CBOR bytes with validation.
    pub fn decode_cbor_untagged(data: &[u8]) -> Result<Self, CodecError> {
        let packet: Self = codec::cbor::decode(data)?;
        packet.validate()?;
        Ok(packet)
    }

    /// Check CDDL-mandated invariants and size limits after deserialization.
    pub fn validate(&self) -> Result<(), CodecError> {
        if self.version != 1 {
            return Err(CodecError::Validation(format!(
                "unsupported version {}, expected 1",
                self.version
            )));
        }

        if self.profile_uri.is_empty() || self.profile_uri.len() > MAX_STRING_LEN {
            return Err(CodecError::Validation(format!(
                "profile_uri length {} out of range [1, {}]",
                self.profile_uri.len(),
                MAX_STRING_LEN
            )));
        }

        if self.packet_id == [0u8; 16] {
            return Err(CodecError::Validation(
                "packet_id must not be all zeros".into(),
            ));
        }

        if self.created == 0 {
            return Err(CodecError::Validation(
                "created timestamp must not be zero".into(),
            ));
        }

        if self.checkpoints.len() < MIN_CHECKPOINTS {
            return Err(CodecError::Validation(format!(
                "need at least {} checkpoints, got {}",
                MIN_CHECKPOINTS,
                self.checkpoints.len()
            )));
        }
        if self.checkpoints.len() > MAX_CHECKPOINTS {
            return Err(CodecError::Validation(format!(
                "too many checkpoints: {} (max {})",
                self.checkpoints.len(),
                MAX_CHECKPOINTS
            )));
        }

        if let Some(ref lims) = self.limitations {
            if lims.len() > MAX_LIMITATIONS {
                return Err(CodecError::Validation(format!(
                    "too many limitations: {} (max {})",
                    lims.len(),
                    MAX_LIMITATIONS
                )));
            }
            for (i, s) in lims.iter().enumerate() {
                if s.len() > MAX_STRING_LEN {
                    return Err(CodecError::Validation(format!(
                        "limitation[{}] too long: {} (max {})",
                        i,
                        s.len(),
                        MAX_STRING_LEN
                    )));
                }
            }
        }
        if let Some(ref pcs) = self.presence_challenges {
            if pcs.len() > MAX_PRESENCE_CHALLENGES {
                return Err(CodecError::Validation(format!(
                    "too many presence_challenges: {} (max {})",
                    pcs.len(),
                    MAX_PRESENCE_CHALLENGES
                )));
            }
        }

        self.document
            .content_hash
            .validate_digest_length()
            .map_err(CodecError::Validation)?;
        if let Some(ref name) = self.document.filename {
            if name.len() > MAX_STRING_LEN {
                return Err(CodecError::Validation(format!(
                    "document filename too long: {} (max {})",
                    name.len(),
                    MAX_STRING_LEN
                )));
            }
        }

        for (i, cp) in self.checkpoints.iter().enumerate() {
            cp.validate()
                .map_err(|e| CodecError::Validation(format!("checkpoint[{}]: {}", i, e)))?;
        }

        if let Some(seq) = self.packet_sequence {
            if seq == 0 {
                return Err(CodecError::Validation(
                    "packet_sequence is 1-based, got 0".into(),
                ));
            }
        }

        Ok(())
    }
}
