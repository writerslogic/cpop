// SPDX-License-Identifier: Apache-2.0

//! JSON encoding/decoding for backwards compatibility.
//!
//! Provides human-readable serialization format for debugging and legacy support.

use serde::{de::DeserializeOwned, Serialize};
use std::io::{Read, Write};

use super::{CodecError, Result};

/// Serialize to pretty-printed JSON bytes.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec_pretty(value).map_err(|e| CodecError::JsonEncode(e.to_string()))
}

/// Serialize to compact (no whitespace) JSON bytes.
pub fn encode_compact<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|e| CodecError::JsonEncode(e.to_string()))
}

/// Deserialize from JSON bytes.
pub fn decode<T: DeserializeOwned>(data: &[u8]) -> Result<T> {
    serde_json::from_slice(data).map_err(|e| CodecError::JsonDecode(e.to_string()))
}

/// Serialize pretty-printed JSON into a writer.
pub fn encode_to<T: Serialize, W: Write>(value: &T, mut writer: W) -> Result<()> {
    let bytes = encode(value)?;
    writer.write_all(&bytes)?;
    Ok(())
}

/// Serialize compact JSON into a writer.
pub fn encode_to_compact<T: Serialize, W: Write>(value: &T, mut writer: W) -> Result<()> {
    let bytes = encode_compact(value)?;
    writer.write_all(&bytes)?;
    Ok(())
}

/// Deserialize from a JSON reader.
pub fn decode_from<T: DeserializeOwned, R: Read>(reader: R) -> Result<T> {
    serde_json::from_reader(reader).map_err(|e| CodecError::JsonDecode(e.to_string()))
}

/// Serialize to a pretty-printed JSON `String`.
pub fn to_string<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string_pretty(value).map_err(|e| CodecError::JsonEncode(e.to_string()))
}

/// Serialize to a compact JSON `String`.
pub fn to_string_compact<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).map_err(|e| CodecError::JsonEncode(e.to_string()))
}

/// Deserialize from a JSON `&str`.
pub fn from_string<T: DeserializeOwned>(s: &str) -> Result<T> {
    serde_json::from_str(s).map_err(|e| CodecError::JsonDecode(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct TestData {
        name: String,
        count: u32,
        items: Vec<String>,
    }

    #[test]
    fn test_json_roundtrip() {
        let original = TestData {
            name: "test".to_string(),
            count: 42,
            items: vec!["a".to_string(), "b".to_string()],
        };

        let encoded = encode(&original).unwrap();
        let decoded: TestData = decode(&encoded).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_json_string_roundtrip() {
        let original = TestData {
            name: "string_test".to_string(),
            count: 100,
            items: vec!["x".to_string()],
        };

        let json_string = to_string(&original).unwrap();
        let decoded: TestData = from_string(&json_string).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_compact_vs_pretty() {
        let data = TestData {
            name: "compact".to_string(),
            count: 1,
            items: vec![],
        };

        let pretty = encode(&data).unwrap();
        let compact = encode_compact(&data).unwrap();

        assert!(compact.len() < pretty.len());

        let decoded_pretty: TestData = decode(&pretty).unwrap();
        let decoded_compact: TestData = decode(&compact).unwrap();

        assert_eq!(decoded_pretty, decoded_compact);
    }

    #[test]
    fn test_decode_invalid_json() {
        let garbage = b"not valid json {{{";
        let result: Result<TestData> = decode(garbage);
        assert!(matches!(result, Err(CodecError::JsonDecode(_))));
    }

    #[test]
    fn test_encode_to_decode_from_json() {
        let original = TestData {
            name: "stream".to_string(),
            count: 55,
            items: vec!["one".to_string(), "two".to_string()],
        };

        let mut buf = Vec::new();
        encode_to(&original, &mut buf).unwrap();
        let decoded: TestData = decode_from(&buf[..]).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_encode_to_compact_writer() {
        let data = TestData {
            name: "cw".to_string(),
            count: 0,
            items: vec![],
        };

        let mut pretty_buf = Vec::new();
        encode_to(&data, &mut pretty_buf).unwrap();

        let mut compact_buf = Vec::new();
        encode_to_compact(&data, &mut compact_buf).unwrap();

        assert!(compact_buf.len() < pretty_buf.len());

        let decoded: TestData = decode(&compact_buf).unwrap();
        assert_eq!(data, decoded);
    }

    #[test]
    fn test_from_string_invalid() {
        let result: Result<TestData> = from_string("}{bad");
        assert!(matches!(result, Err(CodecError::JsonDecode(_))));
    }

    #[test]
    fn test_to_string_compact_roundtrip() {
        let data = TestData {
            name: "compact_str".to_string(),
            count: 999,
            items: vec!["z".to_string()],
        };

        let compact = to_string_compact(&data).unwrap();
        assert!(!compact.contains('\n'));

        let decoded: TestData = from_string(&compact).unwrap();
        assert_eq!(data, decoded);
    }
}
