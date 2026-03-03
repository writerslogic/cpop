// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use rand::RngCore;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// In-memory XOR-obfuscated string (defense-in-depth against memory scraping).
/// NOT encryption — does not resist an attacker who can read the nonce.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ObfuscatedString {
    nonce: [u8; 8],
    data: Vec<u8>,
}

impl ObfuscatedString {
    pub fn new(s: &str) -> Self {
        let mut nonce = [0u8; 8];
        rand::rng().fill_bytes(&mut nonce);

        let mut data = s.as_bytes().to_vec();
        Self::xor(&mut data, &nonce);

        Self { nonce, data }
    }

    pub fn reveal(&self) -> String {
        let mut data = self.data.clone();
        Self::xor(&mut data, &self.nonce);
        String::from_utf8_lossy(&data).to_string()
    }

    fn xor(data: &mut [u8], nonce: &[u8]) {
        for (i, b) in data.iter_mut().enumerate() {
            *b ^= nonce[i % nonce.len()];
        }
    }
}

impl fmt::Debug for ObfuscatedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "***OBFUSCATED***")
    }
}

impl Default for ObfuscatedString {
    fn default() -> Self {
        Self::new("")
    }
}

// Serialize as plaintext for disk/IPC format compatibility.
impl Serialize for ObfuscatedString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.reveal().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ObfuscatedString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(Self::new(&s))
    }
}

impl PartialEq for ObfuscatedString {
    fn eq(&self, other: &Self) -> bool {
        // Optimization: if nonces are same, compare data directly
        if self.nonce == other.nonce {
            return self.data == other.data;
        }
        self.reveal() == other.reveal()
    }
}

impl Eq for ObfuscatedString {}
