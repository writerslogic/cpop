// SPDX-License-Identifier: Apache-2.0

//! CBOR encoding/decoding for RFC 8949 compliance.
//!
//! Uses deterministic encoding (RFC 8949 Section 4.2) for reproducible serialization.

use ciborium::value::Value;
use serde::{de::DeserializeOwned, Serialize};
use std::io::{Read, Write};

use super::{CodecError, Result, CBOR_TAG_COMPACT_REF, CBOR_TAG_CPOP, CBOR_TAG_CWAR};

/// Serialize a value to deterministic CBOR bytes.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    ciborium::into_writer(value, &mut buffer).map_err(|e| CodecError::CborEncode(e.to_string()))?;
    Ok(buffer)
}

/// Deserialize a value from CBOR bytes.
pub fn decode<T: DeserializeOwned>(data: &[u8]) -> Result<T> {
    ciborium::from_reader(data).map_err(|e| CodecError::CborDecode(e.to_string()))
}

/// Serialize a value as CBOR into a writer.
pub fn encode_to<T: Serialize, W: Write>(value: &T, writer: W) -> Result<()> {
    ciborium::into_writer(value, writer).map_err(|e| CodecError::CborEncode(e.to_string()))
}

/// Deserialize a value from a CBOR reader.
pub fn decode_from<T: DeserializeOwned, R: Read>(reader: R) -> Result<T> {
    ciborium::from_reader(reader).map_err(|e| CodecError::CborDecode(e.to_string()))
}

/// Encode with CPOP semantic tag (evidence packet).
pub fn encode_cpop<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    encode_tagged(value, CBOR_TAG_CPOP)
}

/// Encode with CWAR semantic tag (attestation result).
pub fn encode_cwar<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    encode_tagged(value, CBOR_TAG_CWAR)
}

/// Encode with compact evidence reference semantic tag.
pub fn encode_compact_ref<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    encode_tagged(value, CBOR_TAG_COMPACT_REF)
}

/// Wrap a serialized value in a CBOR semantic tag.
pub fn encode_tagged<T: Serialize>(value: &T, tag: u64) -> Result<Vec<u8>> {
    let inner = encode(value)?;
    let inner_value: Value =
        ciborium::from_reader(&inner[..]).map_err(|e| CodecError::CborDecode(e.to_string()))?;

    let tagged = Value::Tag(tag, Box::new(inner_value));

    let mut buffer = Vec::new();
    ciborium::into_writer(&tagged, &mut buffer)
        .map_err(|e| CodecError::CborEncode(e.to_string()))?;

    Ok(buffer)
}

/// Decode CBOR data, verifying the expected semantic tag.
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

            let mut inner_bytes = Vec::new();
            ciborium::into_writer(&*inner, &mut inner_bytes)
                .map_err(|e| CodecError::CborEncode(e.to_string()))?;

            ciborium::from_reader(&inner_bytes[..])
                .map_err(|e| CodecError::CborDecode(e.to_string()))
        }
        _ => Err(CodecError::MissingTag),
    }
}

/// Decode a CPOP-tagged evidence packet.
pub fn decode_cpop<T: DeserializeOwned>(data: &[u8]) -> Result<T> {
    decode_tagged(data, CBOR_TAG_CPOP)
}

/// Decode a CWAR-tagged attestation result.
pub fn decode_cwar<T: DeserializeOwned>(data: &[u8]) -> Result<T> {
    decode_tagged(data, CBOR_TAG_CWAR)
}

/// Decode a compact evidence reference.
pub fn decode_compact_ref<T: DeserializeOwned>(data: &[u8]) -> Result<T> {
    decode_tagged(data, CBOR_TAG_COMPACT_REF)
}

/// Check whether CBOR data carries the expected semantic tag.
pub fn has_tag(data: &[u8], expected_tag: u64) -> bool {
    if let Ok(value) = ciborium::from_reader::<Value, _>(data) {
        matches!(value, Value::Tag(tag, _) if tag == expected_tag)
    } else {
        false
    }
}

/// Extract the outermost CBOR semantic tag, if present.
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

/// Integer keys per RFC CDDL definitions (smaller than string keys on the wire).
pub mod keys {
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

    pub const ENTROPY_COMMITMENT: i64 = 21;
    pub const SOURCES: i64 = 22;
    pub const SUMMARY: i64 = 23;
    pub const BINDING_MAC: i64 = 24;
    pub const RAW_INTERVALS: i64 = 25;
    pub const ACTIVE_PROBES: i64 = 26;
    pub const LABYRINTH_STRUCTURE: i64 = 27;

    pub const VALIDATION_STATUS: i64 = 31;
    pub const MILLIBITS: i64 = 32;
    pub const PARAMETER_VERSION: i64 = 33;
    pub const THRESHOLDS: i64 = 34;

    pub const BINDING_TIER: i64 = 41;
    pub const TSA_RESPONSES: i64 = 42;
    pub const BLOCKCHAIN_ANCHORS: i64 = 43;
    pub const ROUGHTIME_SAMPLES: i64 = 44;

    pub const INPUT: i64 = 51;
    pub const OUTPUT: i64 = 52;
    pub const ITERATIONS: i64 = 53;
    pub const PROOF: i64 = 54;
    pub const CALIBRATION: i64 = 55;

    pub const GALTON_INVARIANT: i64 = 61;
    pub const REFLEX_GATE: i64 = 62;

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

        let encoded = encode_cpop(&original).unwrap();
        let decoded: TestPacket = decode_cpop(&encoded).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_tag_detection() {
        let packet = TestPacket {
            version: 1,
            data: vec![],
        };

        let cpop_encoded = encode_cpop(&packet).unwrap();
        let cwar_encoded = encode_cwar(&packet).unwrap();

        assert!(has_tag(&cpop_encoded, CBOR_TAG_CPOP));
        assert!(!has_tag(&cpop_encoded, CBOR_TAG_CWAR));

        assert!(has_tag(&cwar_encoded, CBOR_TAG_CWAR));
        assert!(!has_tag(&cwar_encoded, CBOR_TAG_CPOP));
    }

    #[test]
    fn test_tag_extraction() {
        let packet = TestPacket {
            version: 1,
            data: vec![],
        };

        let encoded = encode_cpop(&packet).unwrap();
        assert_eq!(extract_tag(&encoded), Some(CBOR_TAG_CPOP));

        let untagged = encode(&packet).unwrap();
        assert_eq!(extract_tag(&untagged), None);
    }

    #[test]
    fn test_wrong_tag_error() {
        let packet = TestPacket {
            version: 1,
            data: vec![],
        };

        let encoded = encode_cpop(&packet).unwrap();
        let result: Result<TestPacket> = decode_cwar(&encoded);

        assert!(matches!(
            result,
            Err(CodecError::InvalidTag {
                expected: CBOR_TAG_CWAR,
                actual: CBOR_TAG_CPOP
            })
        ));
    }

    #[test]
    fn test_has_tag_on_untagged_data() {
        let packet = TestPacket {
            version: 1,
            data: vec![10, 20],
        };
        let encoded = encode(&packet).unwrap();
        assert!(!has_tag(&encoded, CBOR_TAG_CPOP));
        assert!(!has_tag(&encoded, CBOR_TAG_CWAR));
    }

    #[test]
    fn test_has_tag_on_invalid_cbor() {
        // Garbage bytes that aren't valid CBOR
        assert!(!has_tag(&[0xFF, 0xFE, 0xFD], CBOR_TAG_CPOP));
        assert!(!has_tag(&[], CBOR_TAG_CPOP));
    }

    #[test]
    fn test_extract_tag_on_invalid_cbor() {
        assert_eq!(extract_tag(&[0xFF, 0xFE, 0xFD]), None);
        assert_eq!(extract_tag(&[]), None);
    }

    #[test]
    fn test_decode_tagged_on_untagged_data_returns_missing_tag() {
        let packet = TestPacket {
            version: 1,
            data: vec![],
        };
        let encoded = encode(&packet).unwrap();
        let result: Result<TestPacket> = decode_tagged(&encoded, CBOR_TAG_CPOP);
        assert!(matches!(result, Err(CodecError::MissingTag)));
    }

    #[test]
    fn test_decode_invalid_cbor_returns_error() {
        let garbage = &[0xFF, 0xFE, 0xFD, 0xFC];
        let result: Result<TestPacket> = decode(garbage);
        assert!(matches!(result, Err(CodecError::CborDecode(_))));
    }

    #[test]
    fn test_compact_ref_roundtrip() {
        let packet = TestPacket {
            version: 3,
            data: vec![99, 100],
        };

        let encoded = encode_compact_ref(&packet).unwrap();
        assert!(has_tag(&encoded, CBOR_TAG_COMPACT_REF));
        assert_eq!(extract_tag(&encoded), Some(CBOR_TAG_COMPACT_REF));

        let decoded: TestPacket = decode_compact_ref(&encoded).unwrap();
        assert_eq!(packet, decoded);
    }

    #[test]
    fn test_cwar_roundtrip() {
        let packet = TestPacket {
            version: 2,
            data: vec![7, 8, 9],
        };

        let encoded = encode_cwar(&packet).unwrap();
        assert!(has_tag(&encoded, CBOR_TAG_CWAR));

        let decoded: TestPacket = decode_cwar(&encoded).unwrap();
        assert_eq!(packet, decoded);
    }

    #[test]
    fn test_encode_to_decode_from_cbor() {
        let packet = TestPacket {
            version: 5,
            data: vec![1, 2, 3],
        };

        let mut buf = Vec::new();
        encode_to(&packet, &mut buf).unwrap();
        let decoded: TestPacket = decode_from(&buf[..]).unwrap();
        assert_eq!(packet, decoded);
    }
}
