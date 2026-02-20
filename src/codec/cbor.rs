//! CBOR encoding/decoding for RFC 8949 compliance.
//!
//! Uses deterministic encoding (RFC 8949 Section 4.2) for reproducible serialization.

use ciborium::value::Value;
use serde::{de::DeserializeOwned, Serialize};
use std::io::{Read, Write};

use super::{CodecError, Result, CBOR_TAG_COMPACT_REF, CBOR_TAG_PPP, CBOR_TAG_WAR};

/// Encode a value to CBOR bytes.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    ciborium::into_writer(value, &mut buffer).map_err(|e| CodecError::CborEncode(e.to_string()))?;
    Ok(buffer)
}

/// Decode a value from CBOR bytes.
pub fn decode<T: DeserializeOwned>(data: &[u8]) -> Result<T> {
    ciborium::from_reader(data).map_err(|e| CodecError::CborDecode(e.to_string()))
}

/// Encode a value to a CBOR writer.
pub fn encode_to<T: Serialize, W: Write>(value: &T, writer: W) -> Result<()> {
    ciborium::into_writer(value, writer).map_err(|e| CodecError::CborEncode(e.to_string()))
}

/// Decode a value from a CBOR reader.
pub fn decode_from<T: DeserializeOwned, R: Read>(reader: R) -> Result<T> {
    ciborium::from_reader(reader).map_err(|e| CodecError::CborDecode(e.to_string()))
}

/// Encode a Proof-of-Process Packet with semantic tag.
pub fn encode_ppp<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    encode_tagged(value, CBOR_TAG_PPP)
}

/// Encode a Writers Authenticity Report with semantic tag.
pub fn encode_war<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    encode_tagged(value, CBOR_TAG_WAR)
}

/// Encode a Compact Evidence Reference with semantic tag.
pub fn encode_compact_ref<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    encode_tagged(value, CBOR_TAG_COMPACT_REF)
}

/// Encode a value with a semantic tag.
pub fn encode_tagged<T: Serialize>(value: &T, tag: u64) -> Result<Vec<u8>> {
    // First encode the value to get the CBOR representation
    let inner = encode(value)?;
    let inner_value: Value =
        ciborium::from_reader(&inner[..]).map_err(|e| CodecError::CborDecode(e.to_string()))?;

    // Wrap in semantic tag
    let tagged = Value::Tag(tag, Box::new(inner_value));

    // Encode the tagged value
    let mut buffer = Vec::new();
    ciborium::into_writer(&tagged, &mut buffer)
        .map_err(|e| CodecError::CborEncode(e.to_string()))?;

    Ok(buffer)
}

/// Decode a value with semantic tag, verifying the expected tag.
pub fn decode_tagged<T: DeserializeOwned>(data: &[u8], expected_tag: u64) -> Result<T> {
    let value: Value =
        ciborium::from_reader(data).map_err(|e| CodecError::CborDecode(e.to_string()))?;

    match value {
        Value::Tag(actual_tag, inner) => {
            if actual_tag != expected_tag {
                return Err(CodecError::InvalidTag {
                    expected: expected_tag,
                    actual: actual_tag,
                });
            }

            // Re-encode inner value and decode as T
            let mut inner_bytes = Vec::new();
            ciborium::into_writer(&*inner, &mut inner_bytes)
                .map_err(|e| CodecError::CborEncode(e.to_string()))?;

            ciborium::from_reader(&inner_bytes[..])
                .map_err(|e| CodecError::CborDecode(e.to_string()))
        }
        _ => Err(CodecError::MissingTag),
    }
}

/// Decode a PPP packet, verifying the semantic tag.
pub fn decode_ppp<T: DeserializeOwned>(data: &[u8]) -> Result<T> {
    decode_tagged(data, CBOR_TAG_PPP)
}

/// Decode a WAR packet, verifying the semantic tag.
pub fn decode_war<T: DeserializeOwned>(data: &[u8]) -> Result<T> {
    decode_tagged(data, CBOR_TAG_WAR)
}

/// Decode a Compact Evidence Reference, verifying the semantic tag.
pub fn decode_compact_ref<T: DeserializeOwned>(data: &[u8]) -> Result<T> {
    decode_tagged(data, CBOR_TAG_COMPACT_REF)
}

/// Check if data has a specific CBOR semantic tag.
pub fn has_tag(data: &[u8], expected_tag: u64) -> bool {
    if let Ok(value) = ciborium::from_reader::<Value, _>(data) {
        matches!(value, Value::Tag(tag, _) if tag == expected_tag)
    } else {
        false
    }
}

/// Extract the semantic tag from CBOR data, if present.
pub fn extract_tag(data: &[u8]) -> Option<u64> {
    if let Ok(value) = ciborium::from_reader::<Value, _>(data) {
        match value {
            Value::Tag(tag, _) => Some(tag),
            _ => None,
        }
    } else {
        None
    }
}

/// CDDL key mapping for RFC-compliant integer keys.
///
/// Using integer keys instead of string keys reduces CBOR size
/// and aligns with RFC CDDL definitions.
pub mod keys {
    // Packet-level keys (1-20)
    pub const VERSION: i64 = 1;
    pub const EXPORTED_AT: i64 = 2;
    pub const STRENGTH: i64 = 3;
    pub const PROVENANCE: i64 = 4;
    pub const DOCUMENT: i64 = 5;
    pub const CHECKPOINTS: i64 = 6;
    pub const VDF_PARAMS: i64 = 7;
    pub const CHAIN_HASH: i64 = 8;
    pub const DECLARATION: i64 = 9;
    pub const PRESENCE: i64 = 10;
    pub const HARDWARE: i64 = 11;
    pub const KEYSTROKE: i64 = 12;
    pub const BEHAVIORAL: i64 = 13;
    pub const CONTEXTS: i64 = 14;
    pub const EXTERNAL: i64 = 15;
    pub const KEY_HIERARCHY: i64 = 16;
    pub const JITTER_BINDING: i64 = 17;
    pub const TIME_EVIDENCE: i64 = 18;
    pub const BIOLOGY_CLAIM: i64 = 19;
    pub const CLAIMS: i64 = 20;

    // Jitter-binding keys (21-30)
    pub const ENTROPY_COMMITMENT: i64 = 21;
    pub const SOURCES: i64 = 22;
    pub const SUMMARY: i64 = 23;
    pub const BINDING_MAC: i64 = 24;
    pub const RAW_INTERVALS: i64 = 25;
    pub const ACTIVE_PROBES: i64 = 26;
    pub const LABYRINTH_STRUCTURE: i64 = 27;

    // Biology-invariant-claim keys (31-40)
    pub const VALIDATION_STATUS: i64 = 31;
    pub const MILLIBITS: i64 = 32;
    pub const PARAMETER_VERSION: i64 = 33;
    pub const THRESHOLDS: i64 = 34;

    // Time-evidence keys (41-50)
    pub const BINDING_TIER: i64 = 41;
    pub const TSA_RESPONSES: i64 = 42;
    pub const BLOCKCHAIN_ANCHORS: i64 = 43;
    pub const ROUGHTIME_SAMPLES: i64 = 44;

    // VDF proof keys (51-60)
    pub const INPUT: i64 = 51;
    pub const OUTPUT: i64 = 52;
    pub const ITERATIONS: i64 = 53;
    pub const PROOF: i64 = 54;
    pub const CALIBRATION: i64 = 55;

    // Active probes keys (61-70)
    pub const GALTON_INVARIANT: i64 = 61;
    pub const REFLEX_GATE: i64 = 62;

    // Labyrinth structure keys (71-80)
    pub const EMBEDDING_DIMENSION: i64 = 71;
    pub const TIME_DELAY: i64 = 72;
    pub const ATTRACTOR_POINTS: i64 = 73;
    pub const BETTI_NUMBERS: i64 = 74;
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct TestPacket {
        version: i32,
        data: Vec<u8>,
    }

    #[test]
    fn test_tagged_roundtrip() {
        let original = TestPacket {
            version: 1,
            data: vec![1, 2, 3, 4, 5],
        };

        let encoded = encode_ppp(&original).unwrap();
        let decoded: TestPacket = decode_ppp(&encoded).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_tag_detection() {
        let packet = TestPacket {
            version: 1,
            data: vec![],
        };

        let ppp_encoded = encode_ppp(&packet).unwrap();
        let war_encoded = encode_war(&packet).unwrap();

        assert!(has_tag(&ppp_encoded, CBOR_TAG_PPP));
        assert!(!has_tag(&ppp_encoded, CBOR_TAG_WAR));

        assert!(has_tag(&war_encoded, CBOR_TAG_WAR));
        assert!(!has_tag(&war_encoded, CBOR_TAG_PPP));
    }

    #[test]
    fn test_tag_extraction() {
        let packet = TestPacket {
            version: 1,
            data: vec![],
        };

        let encoded = encode_ppp(&packet).unwrap();
        assert_eq!(extract_tag(&encoded), Some(CBOR_TAG_PPP));

        // Untagged value
        let untagged = encode(&packet).unwrap();
        assert_eq!(extract_tag(&untagged), None);
    }

    #[test]
    fn test_wrong_tag_error() {
        let packet = TestPacket {
            version: 1,
            data: vec![],
        };

        let encoded = encode_ppp(&packet).unwrap();
        let result: Result<TestPacket> = decode_war(&encoded);

        assert!(matches!(
            result,
            Err(CodecError::InvalidTag {
                expected: CBOR_TAG_WAR,
                actual: CBOR_TAG_PPP
            })
        ));
    }
}
