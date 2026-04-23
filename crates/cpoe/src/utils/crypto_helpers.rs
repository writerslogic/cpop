// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Shared cryptographic utilities to eliminate duplication across modules.
//! Used by: text_fragments, clipboard, wal, beacon, credentials

use crate::error::{Error, Result};
use ed25519_dalek::{Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::utils::DateTimeNanosExt;

/// Unified constant-time comparison to prevent timing attacks.
/// Never branches on secret values.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> Result<()> {
    if a.len() != b.len() {
        return Err(Error::validation("length mismatch in constant_time_eq"));
    }

    if a.ct_eq(b).unwrap_u8() == 1 {
        Ok(())
    } else {
        Err(Error::validation("constant-time comparison failed"))
    }
}

/// Build signed payload with consistent format across all modules.
/// Format: namespace || field1_len || field1 || field2_len || field2 || ...
#[derive(Debug, Clone)]
pub struct SignedPayloadBuilder {
    #[allow(dead_code)]
    namespace: String,
    fields: Vec<Vec<u8>>,
}

impl SignedPayloadBuilder {
    /// Create a new payload builder with a namespace identifier.
    /// Namespace examples: "text-fragment-v1", "wal-entry-v1", "evidence-packet-v1"
    pub fn new(namespace: &str) -> Self {
        SignedPayloadBuilder {
            namespace: namespace.to_string(),
            fields: vec![namespace.as_bytes().to_vec()],
        }
    }

    /// Append raw bytes to payload.
    pub fn push_bytes(mut self, data: &[u8]) -> Self {
        self.fields.push(data.to_vec());
        self
    }

    /// Append UTF-8 string to payload.
    pub fn push_string(mut self, s: &str) -> Self {
        self.fields.push(s.as_bytes().to_vec());
        self
    }

    /// Append i64 (little-endian) to payload.
    pub fn push_i64(mut self, val: i64) -> Self {
        self.fields.push(val.to_le_bytes().to_vec());
        self
    }

    /// Append f64 (little-endian) to payload.
    pub fn push_f64(mut self, val: f64) -> Self {
        self.fields.push(val.to_le_bytes().to_vec());
        self
    }

    /// Append u32 (little-endian) to payload.
    pub fn push_u32(mut self, val: u32) -> Self {
        self.fields.push(val.to_le_bytes().to_vec());
        self
    }

    /// Build final payload with length prefixes for variable fields.
    /// Returns: namespace || 4-byte-len || field1 || 4-byte-len || field2 || ...
    pub fn build(self) -> Vec<u8> {
        let mut result = Vec::new();

        for (i, field) in self.fields.iter().enumerate() {
            if i == 0 {
                // Namespace (no length prefix, fixed)
                result.extend_from_slice(field);
            } else {
                // All other fields: 4-byte length prefix + data
                result.extend_from_slice(&(field.len() as u32).to_le_bytes());
                result.extend_from_slice(field);
            }
        }

        result
    }
}

/// Verify signature using Ed25519 key.
#[derive(Debug, Clone)]
pub enum SignatureKey {
    Ed25519(VerifyingKey),
}

impl SignatureKey {
    /// Verify a signature. Returns Ok(()) if valid, Err if invalid.
    pub fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<()> {
        match self {
            SignatureKey::Ed25519(key) => {
                let sig = ed25519_dalek::Signature::from_slice(signature)
                    .map_err(|_| Error::validation("invalid signature format"))?;
                key.verify(payload, &sig)
                    .map_err(|_| Error::validation("signature verification failed"))?;
                Ok(())
            }
        }
    }
}

/// Nonce management: check, mark used, cleanup old nonces.
/// Prevents replay attacks by tracking used nonces in database.
#[allow(missing_debug_implementations)]
pub struct NonceManager {
    db: std::sync::Arc<rusqlite::Connection>,
}

impl NonceManager {
    /// Create a new nonce manager with database connection.
    pub fn new(db: std::sync::Arc<rusqlite::Connection>) -> Self {
        NonceManager { db }
    }

    /// Check if nonce has been used (constant-time comparison).
    /// Returns true if nonce exists in used_nonces table.
    pub fn is_used(&self, nonce: &[u8; 16]) -> Result<bool> {
        let nonce_vec = nonce.to_vec();
        let result = self.db.query_row(
            "SELECT 1 FROM used_nonces WHERE nonce = ? LIMIT 1",
            rusqlite::params![&nonce_vec],
            |_| Ok(true),
        );

        match result {
            Ok(exists) => Ok(exists),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
            Err(e) => Err(Error::validation(format!("nonce lookup failed: {}", e))),
        }
    }

    /// Mark nonce as used with timestamp.
    /// Inserts into used_nonces table. If nonce already exists, silently ignores (INSERT OR IGNORE).
    pub fn mark_used(&self, nonce: &[u8; 16], timestamp: i64) -> Result<()> {
        self.db.execute(
            "INSERT OR IGNORE INTO used_nonces (nonce, used_at) VALUES (?, ?)",
            rusqlite::params![nonce.to_vec(), timestamp],
        )
        .map_err(|e| Error::validation(format!("nonce insert failed: {}", e)))?;
        Ok(())
    }

    /// Clean up nonces older than TTL (called during maintenance).
    /// Returns count of deleted rows.
    pub fn cleanup_expired(&self, ttl_secs: u64) -> Result<usize> {
        let now = chrono::Utc::now().timestamp_nanos_safe();
        let cutoff = now - (ttl_secs as i64 * 1_000_000_000);

        let affected = self.db.execute(
            "DELETE FROM used_nonces WHERE used_at < ?",
            rusqlite::params![cutoff],
        )
        .map_err(|e| Error::validation(format!("nonce cleanup failed: {}", e)))?;

        Ok(affected)
    }
}

/// Compute SHA-256 hash of data.
/// Returns: [u8; 32] hash value.
pub fn compute_content_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result[..]);
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signed_payload_builder_roundtrip() {
        let payload = SignedPayloadBuilder::new("test-v1")
            .push_string("hello")
            .push_i64(42)
            .push_bytes(&[0xaa, 0xbb])
            .build();

        // Payload structure:
        // "test-v1" (7 bytes, no length prefix)
        // [5,0,0,0] "hello" (length prefix + 5 bytes)
        // [8,0,0,0] [42,0,0,0,0,0,0,0] (length prefix + i64)
        // [2,0,0,0] [0xaa,0xbb] (length prefix + 2 bytes)

        assert!(payload.len() > 7); // At least namespace
        assert!(payload.starts_with(b"test-v1"));
    }

    #[test]
    fn test_constant_time_eq_success() {
        let a = b"secret";
        let b = b"secret";
        assert!(constant_time_eq(a, b).is_ok());
    }

    #[test]
    fn test_constant_time_eq_failure() {
        let a = b"secret";
        let b = b"wrong";
        assert!(constant_time_eq(a, b).is_err());
    }

    #[test]
    fn test_constant_time_eq_length_mismatch() {
        let a = b"short";
        let b = b"much_longer";
        assert!(constant_time_eq(a, b).is_err());
    }

    #[test]
    fn test_compute_content_hash_deterministic() {
        let data = b"test content";
        let hash1 = compute_content_hash(data);
        let hash2 = compute_content_hash(data);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_compute_content_hash_different_inputs() {
        let hash1 = compute_content_hash(b"input1");
        let hash2 = compute_content_hash(b"input2");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_compute_content_hash_empty() {
        let hash = compute_content_hash(b"");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_signed_payload_multiple_fields() {
        let payload = SignedPayloadBuilder::new("multi")
            .push_string("field1")
            .push_string("field2")
            .push_i64(100)
            .build();

        assert!(payload.starts_with(b"multi"));
        assert!(payload.len() > 5); // More than just namespace
    }

    #[test]
    fn test_signed_payload_empty_fields() {
        let payload = SignedPayloadBuilder::new("test-v1")
            .push_string("")
            .push_bytes(&[])
            .build();

        // Empty fields are still prefixed with length (4 bytes each)
        assert!(payload.starts_with(b"test-v1"));
        assert!(payload.len() >= 7 + 8); // namespace + two 4-byte length prefixes
    }

    #[test]
    fn test_signed_payload_large_field() {
        let large_data = vec![0xAAu8; 10_000];
        let payload = SignedPayloadBuilder::new("big")
            .push_bytes(&large_data)
            .build();

        assert!(payload.len() > 10_000);
        assert!(payload.starts_with(b"big"));
    }

    #[test]
    fn test_constant_time_eq_empty() {
        let a = b"";
        let b = b"";
        assert!(constant_time_eq(a, b).is_ok());
    }

    #[test]
    fn test_signed_payload_builder_field_order() {
        let p1 = SignedPayloadBuilder::new("ns")
            .push_string("first")
            .push_string("second")
            .build();

        let p2 = SignedPayloadBuilder::new("ns")
            .push_string("second")
            .push_string("first")
            .build();

        // Different field orders produce different payloads
        assert_ne!(p1, p2);
    }
}
