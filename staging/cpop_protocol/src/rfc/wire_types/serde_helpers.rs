// SPDX-License-Identifier: Apache-2.0

//! Serde helper modules for fixed-size byte arrays and optional byte vectors.
//!
//! These modules are used with `#[serde(with = "...")]` attributes on wire-format
//! struct fields that need special CBOR byte string handling.

/// Serde helper for optional byte vectors with serde_bytes.
pub(super) mod serde_bytes_opt {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(bytes) => serde_bytes::serialize(bytes, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<serde_bytes::ByteBuf> = Option::deserialize(deserializer)?;
        Ok(opt.map(|b| b.into_vec()))
    }
}

/// Serde helper for 32-byte fixed arrays.
pub(super) mod fixed_bytes_32 {
    use serde::{de, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_bytes::serialize(bytes.as_slice(), serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let buf: serde_bytes::ByteBuf = Deserialize::deserialize(deserializer)?;
        buf.as_ref()
            .try_into()
            .map_err(|_| de::Error::custom(format!("expected 32 bytes, got {}", buf.len())))
    }
}

/// Serde helper for optional 32-byte fixed arrays.
pub(super) mod fixed_bytes_32_opt {
    use serde::{de, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Option<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(bytes) => serde_bytes::serialize(bytes.as_slice(), serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<serde_bytes::ByteBuf> = Option::deserialize(deserializer)?;
        match opt {
            Some(buf) => {
                let arr: [u8; 32] = buf.as_ref().try_into().map_err(|_| {
                    de::Error::custom(format!("expected 32 bytes, got {}", buf.len()))
                })?;
                Ok(Some(arr))
            }
            None => Ok(None),
        }
    }
}

/// Serde helper for 16-byte fixed arrays (UUIDs).
pub(super) mod fixed_bytes_16 {
    use serde::{de, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 16], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_bytes::serialize(bytes.as_slice(), serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 16], D::Error>
    where
        D: Deserializer<'de>,
    {
        let buf: serde_bytes::ByteBuf = Deserialize::deserialize(deserializer)?;
        buf.as_ref()
            .try_into()
            .map_err(|_| de::Error::custom(format!("expected 16 bytes, got {}", buf.len())))
    }
}
