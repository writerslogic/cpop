// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Consolidated serde helpers for hex, base64, and raw byte array serialization.
//!
//! Use these modules with `#[serde(with = "...")]` on struct fields, or import
//! the `optional_hex_*` functions directly for `serialize_with`/`deserialize_with`.

use serde::{de, Deserialize, Deserializer, Serializer};
use std::fmt;

// ---------------------------------------------------------------------------
// 1. Fixed-Size Arrays [u8; N] (Hex Encoding, format-aware)
// ---------------------------------------------------------------------------

pub mod hex_array {
    use super::*;

    pub fn serialize<S, const N: usize>(bytes: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.collect_str(&format_args!("{}", hex::encode(bytes)))
        } else {
            serializer.serialize_bytes(bytes)
        }
    }

    pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            struct HexVisitor<const N: usize>;
            impl<'de, const N: usize> de::Visitor<'de> for HexVisitor<N> {
                type Value = [u8; N];
                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    write!(f, "a hex string of length {}", N * 2)
                }
                fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                    let mut arr = [0u8; N];
                    if v.len() != N * 2 {
                        return Err(E::custom(format!("expected {} hex chars, got {}", N * 2, v.len())));
                    }
                    hex::decode_to_slice(v, &mut arr).map_err(E::custom)?;
                    Ok(arr)
                }
            }
            deserializer.deserialize_str(HexVisitor::<N>)
        } else {
            struct BytesVisitor<const N: usize>;
            impl<'de, const N: usize> de::Visitor<'de> for BytesVisitor<N> {
                type Value = [u8; N];
                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    write!(f, "{} bytes", N)
                }
                fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                    v.try_into().map_err(|_| E::custom(format!("expected {} bytes, got {}", N, v.len())))
                }
                fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                    let mut arr = [0u8; N];
                    for (i, byte) in arr.iter_mut().enumerate() {
                        *byte = seq.next_element()?.ok_or_else(|| de::Error::invalid_length(i, &self))?;
                    }
                    Ok(arr)
                }
            }
            deserializer.deserialize_any(BytesVisitor::<N>)
        }
    }
}

// ---------------------------------------------------------------------------
// 2. Optional Fixed-Size Arrays Option<[u8; N]> (Hex Encoding, format-aware)
// ---------------------------------------------------------------------------

pub mod hex_array_opt {
    use super::*;

    pub fn serialize<S, const N: usize>(opt: &Option<[u8; N]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match opt {
            Some(bytes) => super::hex_array::serialize(bytes, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<Option<[u8; N]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            Option::<String>::deserialize(deserializer)?
                .map(|s| {
                    let mut arr = [0u8; N];
                    if s.len() != N * 2 {
                        return Err(de::Error::custom(format!("expected {} hex chars", N * 2)));
                    }
                    hex::decode_to_slice(&s, &mut arr).map_err(de::Error::custom)?;
                    Ok(arr)
                })
                .transpose()
        } else {
            Option::<Vec<u8>>::deserialize(deserializer)?
                .map(|v| {
                    v.try_into()
                        .map_err(|_| de::Error::custom(format!("expected {} bytes", N)))
                })
                .transpose()
        }
    }
}

// ---------------------------------------------------------------------------
// 3. Byte Vectors Vec<u8> (Hex & Base64, format-aware)
// ---------------------------------------------------------------------------

pub mod hex_vec {
    use super::*;
    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(bytes))
        } else {
            serializer.serialize_bytes(bytes)
        }
    }
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error> where D: Deserializer<'de> {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            hex::decode(s).map_err(de::Error::custom)
        } else {
            Vec::<u8>::deserialize(deserializer)
        }
    }
}

pub mod base64_vec {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use super::*;

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        if serializer.is_human_readable() {
            serializer.serialize_str(&STANDARD.encode(bytes))
        } else {
            serializer.serialize_bytes(bytes)
        }
    }
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error> where D: Deserializer<'de> {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            STANDARD.decode(s).map_err(de::Error::custom)
        } else {
            Vec::<u8>::deserialize(deserializer)
        }
    }
}

// ---------------------------------------------------------------------------
// 4. Raw Bytes (No Encoding)
// ---------------------------------------------------------------------------

pub mod raw_array {
    use super::*;
    pub fn serialize<S, const N: usize>(bytes: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        serializer.serialize_bytes(bytes)
    }
    pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
    where D: Deserializer<'de> {
        struct BytesVisitor<const N: usize>;
        impl<'de, const N: usize> de::Visitor<'de> for BytesVisitor<N> {
            type Value = [u8; N];
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "{} bytes", N)
            }
            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                v.try_into().map_err(|_| E::custom(format!("expected {} bytes, got {}", N, v.len())))
            }
            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut arr = [0u8; N];
                for (i, byte) in arr.iter_mut().enumerate() {
                    *byte = seq.next_element()?.ok_or_else(|| de::Error::invalid_length(i, &self))?;
                }
                Ok(arr)
            }
        }
        deserializer.deserialize_any(BytesVisitor::<N>)
    }
}

// ---------------------------------------------------------------------------
// 5. Backward-compatible aliases
// ---------------------------------------------------------------------------

/// Hex serde for `[u8; 32]` fields.
pub mod hex_bytes_32 {
    use serde::{Deserializer, Serializer};
    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        super::hex_array::serialize(bytes, s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        super::hex_array::deserialize(d)
    }
}

/// Hex serde for `[u8; 64]` fields.
pub mod hex_bytes_64 {
    use serde::{Deserializer, Serializer};
    pub fn serialize<S: Serializer>(bytes: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        super::hex_array::serialize(bytes, s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        super::hex_array::deserialize(d)
    }
}

/// Generic hex serde for any `[u8; N]`.
pub mod hex_serde {
    use serde::{Deserializer, Serializer};
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
        super::hex_array::deserialize(deserializer)
    }
}

/// Hex serde for `Vec<u8>` fields.
pub mod hex_vec_serde {
    use serde::{Deserializer, Serializer};
    pub fn serialize<S: Serializer>(data: &[u8], s: S) -> Result<S::Ok, S::Error> {
        super::hex_vec::serialize(data, s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        super::hex_vec::deserialize(d)
    }
}

/// Base64 serde for `Vec<u8>` fields.
pub mod base64_serde {
    use serde::{Deserializer, Serializer};
    pub fn serialize<S: Serializer>(data: &[u8], s: S) -> Result<S::Ok, S::Error> {
        super::base64_vec::serialize(data, s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        super::base64_vec::deserialize(d)
    }
}

/// Raw-bytes serde for `[u8; 64]` fields.
pub mod serde_array_64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(value: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error> {
        value.as_slice().serialize(serializer)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 64], D::Error> {
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
// 6. Optional hex serde (for serialize_with / deserialize_with on Option fields)
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
