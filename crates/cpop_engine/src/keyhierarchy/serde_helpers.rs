// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

pub(crate) mod serde_array_64 {
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
