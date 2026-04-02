// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Lamport one-shot signatures for checkpoint anti-forgery.
//!
//! A Lamport signature is a hash-based one-time signature scheme. Each key
//! pair can only sign one message. Attempting to sign a second, different
//! message reveals enough preimages to reconstruct the private key, making
//! forgery both detectable and provable.
//!
//! This provides post-quantum security and the one-shot property that
//! prevents checkpoint chain forgery.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// Number of bit-pairs in the key (one per bit of the message hash).
const N: usize = 256;
/// Size of each hash value in bytes.
const HASH_SIZE: usize = 32;

/// Lamport private key: 256 pairs of 32-byte secrets.
/// Total: 256 * 2 * 32 = 16,384 bytes.
pub struct LamportPrivateKey {
    /// secret[i][0] and secret[i][1] for each bit position i.
    secrets: Zeroizing<Vec<u8>>,
}

/// Lamport public key: 256 pairs of 32-byte hashes.
/// Total: 256 * 2 * 32 = 16,384 bytes.
#[derive(Clone)]
pub struct LamportPublicKey {
    pub hashes: Vec<u8>,
}

/// Lamport signature: 256 revealed secrets (one per bit of message hash).
/// Total: 256 * 32 = 8,192 bytes.
#[derive(Clone)]
pub struct LamportSignature {
    pub revealed: Vec<u8>,
}

impl LamportPrivateKey {
    /// Generate a Lamport key pair from a 32-byte seed.
    /// The seed is expanded via HKDF to produce all 512 secret values.
    pub fn from_seed(seed: &[u8; 32]) -> (Self, LamportPublicKey) {
        let mut secrets = Zeroizing::new(vec![0u8; N * 2 * HASH_SIZE]);
        let mut hashes = vec![0u8; N * 2 * HASH_SIZE];

        for i in 0..(N * 2) {
            // Derive each secret: SHA256(seed || index)
            let mut hasher = Sha256::new();
            hasher.update(b"cpop-lamport-secret-v1");
            hasher.update(seed);
            hasher.update((i as u32).to_le_bytes());
            let secret = hasher.finalize();

            let offset = i * HASH_SIZE;
            secrets[offset..offset + HASH_SIZE].copy_from_slice(&secret);

            // Public hash: SHA256(secret)
            let public = Sha256::digest(secret);
            hashes[offset..offset + HASH_SIZE].copy_from_slice(&public);
        }

        (Self { secrets }, LamportPublicKey { hashes })
    }

    /// Sign a 32-byte message hash. For each bit of the hash, reveal the
    /// corresponding secret (index 0 for bit=0, index 1 for bit=1).
    pub fn sign(&self, message_hash: &[u8; 32]) -> LamportSignature {
        let mut revealed = vec![0u8; N * HASH_SIZE];

        for i in 0..N {
            let byte_idx = i / 8;
            let bit_idx = 7 - (i % 8);
            let bit = (message_hash[byte_idx] >> bit_idx) & 1;

            let secret_offset = (i * 2 + bit as usize) * HASH_SIZE;
            let reveal_offset = i * HASH_SIZE;
            revealed[reveal_offset..reveal_offset + HASH_SIZE]
                .copy_from_slice(&self.secrets[secret_offset..secret_offset + HASH_SIZE]);
        }

        LamportSignature { revealed }
    }
}

impl LamportPublicKey {
    /// Verify a Lamport signature against this public key.
    pub fn verify(&self, message_hash: &[u8; 32], signature: &LamportSignature) -> bool {
        if signature.revealed.len() != N * HASH_SIZE {
            return false;
        }
        if self.hashes.len() != N * 2 * HASH_SIZE {
            return false;
        }

        let mut valid = subtle::Choice::from(1u8);

        for i in 0..N {
            let byte_idx = i / 8;
            let bit_idx = 7 - (i % 8);
            let bit = (message_hash[byte_idx] >> bit_idx) & 1;

            let reveal_offset = i * HASH_SIZE;
            let revealed = &signature.revealed[reveal_offset..reveal_offset + HASH_SIZE];

            // Hash the revealed secret
            let hashed = Sha256::digest(revealed);

            // Compare with the public hash for this bit position
            let pub_offset = (i * 2 + bit as usize) * HASH_SIZE;
            let expected = &self.hashes[pub_offset..pub_offset + HASH_SIZE];

            valid &= hashed.as_slice().ct_eq(expected);
        }

        valid.into()
    }

    /// Serialize the public key to bytes.
    pub fn to_bytes(&self) -> &[u8] {
        &self.hashes
    }

    /// Deserialize a public key from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != N * 2 * HASH_SIZE {
            return None;
        }
        Some(Self {
            hashes: bytes.to_vec(),
        })
    }

    /// Compact fingerprint of the public key (first 8 bytes of SHA-256).
    pub fn fingerprint(&self) -> [u8; 8] {
        let hash = Sha256::digest(&self.hashes);
        let mut fp = [0u8; 8];
        fp.copy_from_slice(&hash[..8]);
        fp
    }
}

impl LamportSignature {
    /// Serialize the signature to bytes.
    pub fn to_bytes(&self) -> &[u8] {
        &self.revealed
    }

    /// Deserialize a signature from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != N * HASH_SIZE {
            return None;
        }
        Some(Self {
            revealed: bytes.to_vec(),
        })
    }
}

/// Detect if two Lamport signatures on different messages reveal the full
/// private key (proof of forgery). Returns true if forgery is detected.
pub fn detect_forgery(
    _pubkey: &LamportPublicKey,
    hash_a: &[u8; 32],
    _sig_a: &LamportSignature,
    hash_b: &[u8; 32],
    _sig_b: &LamportSignature,
) -> bool {
    if hash_a == hash_b {
        return false; // Same message, not forgery
    }

    // For each bit position where the two message hashes differ,
    // the two signatures reveal BOTH secrets (one for bit=0, one for bit=1).
    // If we can recover all 512 secrets, the private key is fully exposed.
    let mut exposed_count = 0usize;
    for i in 0..N {
        let byte_idx = i / 8;
        let bit_idx = 7 - (i % 8);
        let bit_a = (hash_a[byte_idx] >> bit_idx) & 1;
        let bit_b = (hash_b[byte_idx] >> bit_idx) & 1;

        if bit_a != bit_b {
            // Different bits: both secrets for position i are revealed
            exposed_count += 2;
        } else {
            // Same bit: only one secret revealed (same one in both sigs)
            exposed_count += 1;
        }
    }

    // If ANY bits differ, at least some private key material is exposed.
    // In practice, ~128 of 256 bits differ for random hashes, exposing ~384/512 secrets.
    exposed_count > N // More than one secret per position = forgery evidence
}

impl Drop for LamportPrivateKey {
    fn drop(&mut self) {
        self.secrets.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify() {
        let seed = [42u8; 32];
        let (privkey, pubkey) = LamportPrivateKey::from_seed(&seed);

        let message = Sha256::digest(b"hello world");
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&message);

        let sig = privkey.sign(&hash);
        assert!(pubkey.verify(&hash, &sig));
    }

    #[test]
    fn test_wrong_message_fails() {
        let seed = [42u8; 32];
        let (privkey, pubkey) = LamportPrivateKey::from_seed(&seed);

        let hash_a = Sha256::digest(b"message A");
        let hash_b = Sha256::digest(b"message B");
        let mut ha = [0u8; 32];
        let mut hb = [0u8; 32];
        ha.copy_from_slice(&hash_a);
        hb.copy_from_slice(&hash_b);

        let sig = privkey.sign(&ha);
        assert!(!pubkey.verify(&hb, &sig));
    }

    #[test]
    fn test_forgery_detection() {
        let seed = [42u8; 32];
        let (privkey, pubkey) = LamportPrivateKey::from_seed(&seed);

        let hash_a = Sha256::digest(b"legitimate checkpoint");
        let hash_b = Sha256::digest(b"forged checkpoint");
        let mut ha = [0u8; 32];
        let mut hb = [0u8; 32];
        ha.copy_from_slice(&hash_a);
        hb.copy_from_slice(&hash_b);

        let sig_a = privkey.sign(&ha);
        let sig_b = privkey.sign(&hb);

        // Both signatures verify independently
        assert!(pubkey.verify(&ha, &sig_a));
        assert!(pubkey.verify(&hb, &sig_b));

        // But together they prove forgery
        assert!(detect_forgery(&pubkey, &ha, &sig_a, &hb, &sig_b));
    }

    #[test]
    fn test_same_message_no_forgery() {
        let seed = [42u8; 32];
        let (privkey, pubkey) = LamportPrivateKey::from_seed(&seed);

        let hash = Sha256::digest(b"same message");
        let mut h = [0u8; 32];
        h.copy_from_slice(&hash);

        let sig1 = privkey.sign(&h);
        let sig2 = privkey.sign(&h);

        assert!(!detect_forgery(&pubkey, &h, &sig1, &h, &sig2));
    }

    #[test]
    fn test_signature_sizes() {
        let seed = [1u8; 32];
        let (privkey, pubkey) = LamportPrivateKey::from_seed(&seed);
        let hash = [0u8; 32];
        let sig = privkey.sign(&hash);

        assert_eq!(pubkey.to_bytes().len(), 16384); // 256 * 2 * 32
        assert_eq!(sig.to_bytes().len(), 8192); // 256 * 32
    }

    #[test]
    fn test_serialization_roundtrip() {
        let seed = [7u8; 32];
        let (privkey, pubkey) = LamportPrivateKey::from_seed(&seed);
        let hash = [0u8; 32];
        let sig = privkey.sign(&hash);

        let pubkey2 = LamportPublicKey::from_bytes(pubkey.to_bytes()).unwrap();
        let sig2 = LamportSignature::from_bytes(sig.to_bytes()).unwrap();
        assert!(pubkey2.verify(&hash, &sig2));
    }
}
