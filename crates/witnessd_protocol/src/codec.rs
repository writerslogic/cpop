// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::rfc::{EvidencePacket, AttestationResult, CBOR_TAG_EVIDENCE_PACKET, CBOR_TAG_ATTESTATION_RESULT};
use crate::error::{Error, Result};
use ciborium::tag::Required;

/// Encodes an Evidence Packet to CBOR bytes with the protocol tag.
pub fn encode_evidence(packet: &EvidencePacket) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&Required::<&EvidencePacket, CBOR_TAG_EVIDENCE_PACKET>(packet), &mut bytes)
        .map_err(|e| Error::Serialization(e.to_string()))?;
    Ok(bytes)
}

/// Decodes an Evidence Packet from CBOR bytes, validating the protocol tag.
pub fn decode_evidence(bytes: &[u8]) -> Result<EvidencePacket> {
    let tag_packet: Required<EvidencePacket, CBOR_TAG_EVIDENCE_PACKET> = ciborium::de::from_reader(bytes)
        .map_err(|e| Error::Serialization(e.to_string()))?;
    
    Ok(tag_packet.0)
}

/// Encodes an Attestation Result to CBOR bytes with the protocol tag.
pub fn encode_attestation(result: &AttestationResult) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&Required::<&AttestationResult, CBOR_TAG_ATTESTATION_RESULT>(result), &mut bytes)
        .map_err(|e| Error::Serialization(e.to_string()))?;
    Ok(bytes)
}

/// Decodes an Attestation Result from CBOR bytes, validating the protocol tag.
pub fn decode_attestation(bytes: &[u8]) -> Result<AttestationResult> {
    let tag_result: Required<AttestationResult, CBOR_TAG_ATTESTATION_RESULT> = ciborium::de::from_reader(bytes)
        .map_err(|e| Error::Serialization(e.to_string()))?;
    
    Ok(tag_result.0)
}
