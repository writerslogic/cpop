// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Hex-encoded optional fixed-size byte array serde helpers.

use serde::{Deserialize, Deserializer, Serializer};

macro_rules! optional_hex_serde {
    ($ser:ident, $de:ident, $size:expr, $label:expr) => {
        pub(crate) fn $ser<S>(bytes: &Option<[u8; $size]>, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            match bytes {
                Some(b) => serializer.serialize_some(&hex::encode(b)),
                None => serializer.serialize_none(),
            }
        }

        pub(crate) fn $de<'de, D>(deserializer: D) -> Result<Option<[u8; $size]>, D::Error>
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
