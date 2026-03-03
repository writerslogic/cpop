// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::error::{Error, Result};
use crate::rfc::{
    AttestationResult, EvidencePacket, CBOR_TAG_ATTESTATION_RESULT, CBOR_TAG_EVIDENCE_PACKET,
};
use ciborium::tag::Required;

pub fn encode_evidence(packet: &EvidencePacket) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(
        &Required::<&EvidencePacket, CBOR_TAG_EVIDENCE_PACKET>(packet),
        &mut bytes,
    )
    .map_err(|e| Error::Serialization(e.to_string()))?;
    Ok(bytes)
}

pub fn decode_evidence(bytes: &[u8]) -> Result<EvidencePacket> {
    let tag_packet: Required<EvidencePacket, CBOR_TAG_EVIDENCE_PACKET> =
        ciborium::de::from_reader(bytes).map_err(|e| Error::Serialization(e.to_string()))?;

    Ok(tag_packet.0)
}

pub fn encode_attestation(result: &AttestationResult) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(
        &Required::<&AttestationResult, CBOR_TAG_ATTESTATION_RESULT>(result),
        &mut bytes,
    )
    .map_err(|e| Error::Serialization(e.to_string()))?;
    Ok(bytes)
}

pub fn decode_attestation(bytes: &[u8]) -> Result<AttestationResult> {
    let tag_result: Required<AttestationResult, CBOR_TAG_ATTESTATION_RESULT> =
        ciborium::de::from_reader(bytes).map_err(|e| Error::Serialization(e.to_string()))?;

    Ok(tag_result.0)
}
