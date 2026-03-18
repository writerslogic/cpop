// SPDX-License-Identifier: Apache-2.0

//! Base hash and reference types for wire-format structures.
//!
//! Implements `hash-value`, `compact-ref`, and `time-window` from the CDDL schema.

use serde::{Deserialize, Serialize};

use super::enums::HashAlgorithm;

/// Cryptographic hash value per CDDL `hash-value`.
///
/// ```cddl
/// hash-value = {
///     1 => hash-algorithm,
///     2 => bstr,
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashValue {
    #[serde(rename = "1")]
    pub algorithm: HashAlgorithm,

    #[serde(rename = "2", with = "serde_bytes")]
    pub digest: Vec<u8>,
}

impl HashValue {
    /// Create a SHA-256 hash value from a 32-byte digest.
    ///
    /// # Panics
    /// If `digest` is not 32 bytes. Use `try_sha256` for fallible construction.
    pub fn sha256(digest: Vec<u8>) -> Self {
        assert!(
            digest.len() == 32,
            "SHA-256 digest must be 32 bytes, got {}",
            digest.len()
        );
        Self {
            algorithm: HashAlgorithm::Sha256,
            digest,
        }
    }

    /// Create a SHA-256 hash value, returning an error if length is wrong.
    pub fn try_sha256(digest: Vec<u8>) -> Result<Self, String> {
        if digest.len() != 32 {
            return Err(format!(
                "SHA-256 digest must be 32 bytes, got {}",
                digest.len()
            ));
        }
        Ok(Self {
            algorithm: HashAlgorithm::Sha256,
            digest,
        })
    }

    /// Create a SHA-384 hash value from a 48-byte digest.
    ///
    /// # Panics
    /// If `digest` is not 48 bytes. Use `try_sha384` for fallible construction.
    pub fn sha384(digest: Vec<u8>) -> Self {
        assert!(
            digest.len() == 48,
            "SHA-384 digest must be 48 bytes, got {}",
            digest.len()
        );
        Self {
            algorithm: HashAlgorithm::Sha384,
            digest,
        }
    }

    /// Create a SHA-384 hash value, returning an error if length is wrong.
    pub fn try_sha384(digest: Vec<u8>) -> Result<Self, String> {
        if digest.len() != 48 {
            return Err(format!(
                "SHA-384 digest must be 48 bytes, got {}",
                digest.len()
            ));
        }
        Ok(Self {
            algorithm: HashAlgorithm::Sha384,
            digest,
        })
    }

    /// Create a SHA-512 hash value from a 64-byte digest.
    ///
    /// # Panics
    /// If `digest` is not 64 bytes. Use `try_sha512` for fallible construction.
    pub fn sha512(digest: Vec<u8>) -> Self {
        assert!(
            digest.len() == 64,
            "SHA-512 digest must be 64 bytes, got {}",
            digest.len()
        );
        Self {
            algorithm: HashAlgorithm::Sha512,
            digest,
        }
    }

    /// Create a SHA-512 hash value, returning an error if length is wrong.
    pub fn try_sha512(digest: Vec<u8>) -> Result<Self, String> {
        if digest.len() != 64 {
            return Err(format!(
                "SHA-512 digest must be 64 bytes, got {}",
                digest.len()
            ));
        }
        Ok(Self {
            algorithm: HashAlgorithm::Sha512,
            digest,
        })
    }

    /// For `prev_hash` of the first checkpoint in a chain.
    pub fn zero_sha256() -> Self {
        Self {
            algorithm: HashAlgorithm::Sha256,
            digest: vec![0u8; 32],
        }
    }

    /// Validate that the digest length matches the declared algorithm.
    pub fn validate_digest_length(&self) -> Result<(), String> {
        let expected = match self.algorithm {
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
            HashAlgorithm::Sha512 => 64,
        };
        if self.digest.len() != expected {
            return Err(format!(
                "{:?} digest must be {} bytes, got {}",
                self.algorithm,
                expected,
                self.digest.len()
            ));
        }
        Ok(())
    }
}

/// Compact evidence reference per CDDL `compact-ref`.
///
/// ```cddl
/// compact-ref = {
///     1 => hash-algorithm,
///     2 => bstr .size (8..32),
///     3 => uint,
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactRef {
    #[serde(rename = "1")]
    pub algorithm: HashAlgorithm,

    /// 8-32 bytes
    #[serde(rename = "2", with = "serde_bytes")]
    pub truncated_digest: Vec<u8>,

    /// Bytes retained from full digest
    #[serde(rename = "3")]
    pub prefix_length: u64,
}

/// Time window per CDDL `time-window`.
///
/// ```cddl
/// time-window = {
///     1 => pop-timestamp,
///     2 => pop-timestamp,
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeWindow {
    /// Epoch ms
    #[serde(rename = "1")]
    pub start: u64,

    /// Epoch ms
    #[serde(rename = "2")]
    pub end: u64,
}
