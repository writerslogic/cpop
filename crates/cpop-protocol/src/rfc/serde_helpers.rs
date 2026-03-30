// SPDX-License-Identifier: Apache-2.0

//! Shared serde helpers for hex-encoded byte fields in RFC structures.
//!
//! Consolidates the duplicated `mod hex_bytes` / `mod hex_bytes_vec` helpers
//! that were previously copy-pasted across multiple rfc submodules.

/// Hex serde for fixed-size byte arrays (const-generic).
///
/// Usage: `#[serde(with = "crate::rfc::serde_helpers::hex_bytes")]`
pub(crate) mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S, const N: usize>(bytes: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != N {
            return Err(serde::de::Error::custom(format!(
                "expected {} bytes, got {}",
                N,
                bytes.len()
            )));
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

/// Hex serde for variable-length byte vectors.
///
/// Usage: `#[serde(with = "crate::rfc::serde_helpers::hex_bytes_vec")]`
pub(crate) mod hex_bytes_vec {
    use serde::{de, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    /// Maximum decoded byte length for variable-length hex fields (1 MiB).
    pub const MAX_HEX_BYTES: usize = 1_048_576;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(de::Error::custom)?;
        if bytes.len() > MAX_HEX_BYTES {
            return Err(de::Error::custom(format!(
                "hex_bytes_vec length {} exceeds maximum {}",
                bytes.len(),
                MAX_HEX_BYTES
            )));
        }
        Ok(bytes)
    }
}

/// Hex serde for optional fixed-size 32-byte arrays.
///
/// Usage: `#[serde(with = "crate::rfc::serde_helpers::hex_bytes_32_opt")]`
pub(crate) mod hex_bytes_32_opt {
    use serde::{de, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Option<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(bytes) => serializer.serialize_str(&hex::encode(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) => {
                let bytes = hex::decode(&s).map_err(de::Error::custom)?;
                if bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    Ok(Some(arr))
                } else {
                    Err(de::Error::custom(format!(
                        "expected 32 bytes, got {}",
                        bytes.len()
                    )))
                }
            }
            None => Ok(None),
        }
    }
}

/// Hex serde for optional variable-length byte vectors.
///
/// Usage: `#[serde(with = "crate::rfc::serde_helpers::hex_bytes_vec_opt")]`
pub(crate) mod hex_bytes_vec_opt {
    use serde::{de, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(bytes) => serializer.serialize_str(&hex::encode(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) => Ok(Some(hex::decode(&s).map_err(de::Error::custom)?)),
            None => Ok(None),
        }
    }
}
