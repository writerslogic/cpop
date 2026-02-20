use rand::RngCore;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A string that is stored in memory in an obfuscated form (XORed with a random nonce).
/// This provides defense-in-depth against memory scraping attacks that look for
/// plaintext window titles or file paths.
///
/// Note: This is NOT encryption. It does not provide cryptographic confidentiality
/// against an attacker who can read the nonce. It is strictly for obfuscation.
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

// Custom serialization to allow transparent usage with Serde (optional)
// We serialize as the plaintext string to maintain compatibility with disk/IPC formats
// that expect standard JSON strings, unless we want to obfuscate on disk too.
// For now, let's serialize as plaintext to not break existing file formats.
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

// PartialEq for comparison (decrypts to compare)
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
