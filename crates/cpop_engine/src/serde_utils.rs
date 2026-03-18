// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Consolidated serde helpers for hex, base64, and raw byte array serialization.
//!
//! Use these modules with `#[serde(with = "...")]` on struct fields, or import
//! the `optional_hex_*` functions directly for `serialize_with`/`deserialize_with`.

use serde::{Deserialize, Deserializer, Serializer};

// ---------------------------------------------------------------------------
// Hex encoding for fixed-size byte arrays
// ---------------------------------------------------------------------------

/// Hex serde for `[u8; 32]` fields: `#[serde(with = "crate::serde_utils::hex_bytes_32")]`
pub mod hex_bytes_32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

/// Hex serde for `[u8; 64]` fields: `#[serde(with = "crate::serde_utils::hex_bytes_64")]`
pub mod hex_bytes_64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom(format!(
                "expected 64 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

/// Generic hex serde for any `[u8; N]` via const generics:
/// `#[serde(with = "crate::serde_utils::hex_serde")]`
pub mod hex_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S, T>(data: T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: AsRef<[u8]>,
    {
        serializer.serialize_str(&hex::encode(data.as_ref()))
    }

    pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("wrong length"))
    }
}

/// Hex serde for `Vec<u8>` fields: `#[serde(with = "crate::serde_utils::hex_vec_serde")]`
pub mod hex_vec_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(data: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(data))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Base64 encoding for byte vectors
// ---------------------------------------------------------------------------

/// Base64 serde for `Vec<u8>` fields: `#[serde(with = "crate::serde_utils::base64_serde")]`
pub mod base64_serde {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(data: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(data))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Raw byte array serde (not hex-encoded)
// ---------------------------------------------------------------------------

/// Raw-bytes serde for `[u8; 64]` fields (serializes as byte sequence, not hex):
/// `#[serde(with = "crate::serde_utils::serde_array_64")]`
pub mod serde_array_64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(value: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value.as_slice().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let values = Vec::<u8>::deserialize(deserializer)?;
        if values.len() != 64 {
            return Err(serde::de::Error::custom(format!(
                "expected 64-byte array, got {} bytes",
                values.len()
            )));
        }
        let mut out = [0u8; 64];
        out.copy_from_slice(&values);
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Optional hex serde (for serialize_with / deserialize_with on Option fields)
// ---------------------------------------------------------------------------

macro_rules! optional_hex_serde {
    ($ser:ident, $de:ident, $size:expr, $label:expr) => {
        pub fn $ser<S>(bytes: &Option<[u8; $size]>, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            match bytes {
                Some(b) => serializer.serialize_some(&hex::encode(b)),
                None => serializer.serialize_none(),
            }
        }

        pub fn $de<'de, D>(deserializer: D) -> Result<Option<[u8; $size]>, D::Error>
        where
            D: Deserializer<'de>,
        {
            let opt: Option<String> = Option::deserialize(deserializer)?;
            match opt {
                Some(hex_str) => {
                    let bytes = hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
                    if bytes.len() != $size {
                        return Err(serde::de::Error::custom(concat!(
                            $label,
                            " must be ",
                            stringify!($size),
                            " bytes"
                        )));
                    }
                    let mut arr = [0u8; $size];
                    arr.copy_from_slice(&bytes);
                    Ok(Some(arr))
                }
                None => Ok(None),
            }
        }
    };
}

optional_hex_serde!(
    serialize_optional_nonce,
    deserialize_optional_nonce,
    32,
    "nonce"
);
optional_hex_serde!(
    serialize_optional_signature,
    deserialize_optional_signature,
    64,
    "signature"
);
optional_hex_serde!(
    serialize_optional_pubkey,
    deserialize_optional_pubkey,
    32,
    "public key"
);
