// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Codec module for RFC-compliant serialization.
//!
//! Supports both CBOR (primary, RFC 8949) and JSON (legacy) encoding
//! for Proof-of-Process evidence packets.

pub mod cbor;
pub mod json;

use serde::{de::DeserializeOwned, Serialize};
use std::io::{Read, Write};

/// CBOR semantic tag for Proof-of-Process Packet (PPP).
/// Tag value: 1347571280 (0x50505050 = "PPPP" in ASCII)
/// Per draft-condrey-rats-pop CDDL and IANA CBOR tag registry.
pub const CBOR_TAG_PPP: u64 = 1347571280;

/// CBOR semantic tag for Writers Authenticity Report (WAR).
/// Tag value: 1463894560 (0x57415220 = "WAR " in ASCII)
/// Per draft-condrey-rats-pop CDDL and IANA CBOR tag registry.
pub const CBOR_TAG_WAR: u64 = 1463894560;

/// CBOR semantic tag for Compact Evidence Reference.
/// Tag value: 1347571281 (0x50505021)
pub const CBOR_TAG_COMPACT_REF: u64 = 1347571281;

/// IANA Private Enterprise Number for WritersLogic Inc.
pub const IANA_PEN: u32 = 65074;

/// Evidence format for serialization/deserialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Format {
    /// CBOR encoding (RFC 8949 deterministic)
    #[default]
    Cbor,
    /// JSON encoding (legacy, for human readability)
    Json,
}

impl Format {
    /// Returns the MIME type for this format.
    pub fn mime_type(&self) -> &'static str {
        match self {
            Format::Cbor => "application/vnd.writerslogic-pop+cbor",
            Format::Json => "application/json",
        }
    }

    /// Returns the file extension for this format.
    pub fn extension(&self) -> &'static str {
        match self {
            Format::Cbor => "pop",
            Format::Json => "json",
        }
    }

    /// Detect format from magic bytes.
    pub fn detect(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }
        // CBOR map starts with 0xA (major type 5) or tagged value 0xD9/0xDA/0xDB
        // JSON starts with '{' (0x7B) or '[' (0x5B)
        match data[0] {
            0x7B | 0x5B => Some(Format::Json),
            0xA0..=0xBF | 0xD9 | 0xDA | 0xDB => Some(Format::Cbor),
            _ => None,
        }
    }
}

/// Codec error types.
#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("CBOR encoding error: {0}")]
    CborEncode(String),
    #[error("CBOR decoding error: {0}")]
    CborDecode(String),
    #[error("JSON encoding error: {0}")]
    JsonEncode(String),
    #[error("JSON decoding error: {0}")]
    JsonDecode(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid format: {0}")]
    InvalidFormat(String),
    #[error("Missing semantic tag")]
    MissingTag,
    #[error("Invalid semantic tag: expected {expected}, got {actual}")]
    InvalidTag { expected: u64, actual: u64 },
    #[error("Validation error: {0}")]
    Validation(String),
}

/// Result type for codec operations.
pub type Result<T> = std::result::Result<T, CodecError>;

/// Encode a value to bytes using the specified format.
pub fn encode<T: Serialize>(value: &T, format: Format) -> Result<Vec<u8>> {
    match format {
        Format::Cbor => cbor::encode(value),
        Format::Json => json::encode(value),
    }
}

/// Decode a value from bytes using the specified format.
pub fn decode<T: DeserializeOwned>(data: &[u8], format: Format) -> Result<T> {
    match format {
        Format::Cbor => cbor::decode(data),
        Format::Json => json::decode(data),
    }
}

/// Decode a value from bytes, auto-detecting the format.
pub fn decode_auto<T: DeserializeOwned>(data: &[u8]) -> Result<T> {
    let format = Format::detect(data)
        .ok_or_else(|| CodecError::InvalidFormat("unable to detect format".to_string()))?;
    decode(data, format)
}

/// Encode a value to a writer using the specified format.
pub fn encode_to<T: Serialize, W: Write>(value: &T, writer: W, format: Format) -> Result<()> {
    match format {
        Format::Cbor => cbor::encode_to(value, writer),
        Format::Json => json::encode_to(value, writer),
    }
}

/// Decode a value from a reader using the specified format.
pub fn decode_from<T: DeserializeOwned, R: Read>(reader: R, format: Format) -> Result<T> {
    match format {
        Format::Cbor => cbor::decode_from(reader),
        Format::Json => json::decode_from(reader),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct TestStruct {
        name: String,
        value: i32,
        data: Vec<u8>,
    }

    #[test]
    fn test_format_detection() {
        // JSON object
        assert_eq!(Format::detect(b"{\"key\":\"value\"}"), Some(Format::Json));
        // JSON array
        assert_eq!(Format::detect(b"[1,2,3]"), Some(Format::Json));
        // CBOR map (small, 0xA0-0xB7)
        assert_eq!(Format::detect(&[0xA1, 0x01, 0x02]), Some(Format::Cbor));
        // Empty
        assert_eq!(Format::detect(&[]), None);
    }

    #[test]
    fn test_roundtrip_cbor() {
        let original = TestStruct {
            name: "test".to_string(),
            value: 42,
            data: vec![1, 2, 3, 4],
        };

        let encoded = encode(&original, Format::Cbor).unwrap();
        let decoded: TestStruct = decode(&encoded, Format::Cbor).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_roundtrip_json() {
        let original = TestStruct {
            name: "test".to_string(),
            value: 42,
            data: vec![1, 2, 3, 4],
        };

        let encoded = encode(&original, Format::Json).unwrap();
        let decoded: TestStruct = decode(&encoded, Format::Json).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_auto_detect_decode() {
        let original = TestStruct {
            name: "auto".to_string(),
            value: 100,
            data: vec![5, 6, 7],
        };

        let cbor_encoded = encode(&original, Format::Cbor).unwrap();
        let cbor_decoded: TestStruct = decode_auto(&cbor_encoded).unwrap();
        assert_eq!(original, cbor_decoded);

        let json_encoded = encode(&original, Format::Json).unwrap();
        let json_decoded: TestStruct = decode_auto(&json_encoded).unwrap();
        assert_eq!(original, json_decoded);
    }
}
