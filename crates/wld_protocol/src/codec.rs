// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::error::{Error, Result};
use crate::rfc::{
    AttestationResult, EvidencePacket, CBOR_TAG_ATTESTATION_RESULT, CBOR_TAG_EVIDENCE_PACKET,
};
use ciborium::tag::Required;

fn encode_tagged<T: serde::Serialize, const TAG: u64>(value: &T) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&Required::<&T, TAG>(value), &mut bytes)
        .map_err(|e| Error::Serialization(e.to_string()))?;
    Ok(bytes)
}

fn decode_tagged<T: serde::de::DeserializeOwned, const TAG: u64>(bytes: &[u8]) -> Result<T> {
    let tagged: Required<T, TAG> =
        ciborium::de::from_reader(bytes).map_err(|e| Error::Serialization(e.to_string()))?;
    Ok(tagged.0)
}

/// Serialize an `EvidencePacket` to CBOR with the registered CBOR tag.
pub fn encode_evidence(packet: &EvidencePacket) -> Result<Vec<u8>> {
    encode_tagged::<_, CBOR_TAG_EVIDENCE_PACKET>(packet)
}

/// Deserialize CBOR-tagged bytes into an `EvidencePacket`.
pub fn decode_evidence(bytes: &[u8]) -> Result<EvidencePacket> {
    decode_tagged::<_, CBOR_TAG_EVIDENCE_PACKET>(bytes)
}

/// Serialize an `AttestationResult` to CBOR with the registered CBOR tag.
pub fn encode_attestation(result: &AttestationResult) -> Result<Vec<u8>> {
    encode_tagged::<_, CBOR_TAG_ATTESTATION_RESULT>(result)
}

/// Deserialize CBOR-tagged bytes into an `AttestationResult`.
pub fn decode_attestation(bytes: &[u8]) -> Result<AttestationResult> {
    decode_tagged::<_, CBOR_TAG_ATTESTATION_RESULT>(bytes)
}
