// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors from anchor submission, verification, and provider operations.
#[derive(Debug, Error)]
pub enum AnchorError {
    /// Anchor provider is not configured or reachable.
    #[error("provider unavailable: {0}")]
    Unavailable(String),
    /// Provider configuration is invalid (e.g., bad key, missing endpoint).
    #[error("configuration error: {0}")]
    Configuration(String),
    /// Hash submission to the anchor backend failed.
    #[error("submission failed: {0}")]
    Submission(String),
    /// Transaction or proof signing failed.
    #[error("signing error: {0}")]
    Signing(String),
    /// Cryptographic verification of a proof failed.
    #[error("verification failed: {0}")]
    Verification(String),
    /// Proof exists but is not yet confirmed by the backend.
    #[error("proof not ready")]
    NotReady,
    /// Proof has expired and is no longer valid.
    #[error("proof expired")]
    Expired,
    /// Network communication with the anchor backend failed.
    #[error("network error: {0}")]
    Network(String),
    /// Proof data does not conform to the expected format.
    #[error("invalid proof format: {0}")]
    InvalidFormat(String),
    /// Anchored hash does not match the expected content hash.
    #[error("hash mismatch")]
    HashMismatch,
}

/// Supported anchor provider backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderType {
    /// OpenTimestamps calendar servers with Bitcoin attestation.
    #[serde(rename = "ots")]
    OpenTimestamps,
    /// RFC 3161 Time-Stamp Authority.
    #[serde(rename = "rfc3161")]
    Rfc3161,
    /// Bitcoin OP_RETURN transaction.
    Bitcoin,
    /// Ethereum smart contract anchor.
    Ethereum,
    /// Third-party notary service.
    Notary,
}

/// Lifecycle state of an anchor proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProofStatus {
    /// Submitted but not yet confirmed by the backend.
    Pending,
    /// Confirmed and independently verifiable.
    Confirmed,
    /// Submission or confirmation permanently failed.
    Failed,
    /// Proof was valid but has since expired.
    Expired,
}

/// Cryptographic proof that a hash was anchored to an external system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    /// Provider-assigned identifier (txid, serial number, etc.).
    pub id: String,
    /// Backend that produced this proof.
    pub provider: ProviderType,
    /// Current lifecycle state.
    pub status: ProofStatus,
    /// The content hash that was anchored.
    #[serde(with = "hex_serde")]
    pub anchored_hash: [u8; 32],
    /// When the proof was submitted.
    pub submitted_at: DateTime<Utc>,
    /// When the proof was confirmed, if applicable.
    pub confirmed_at: Option<DateTime<Utc>>,
    /// Raw proof bytes (OTS file, RFC 3161 token, etc.).
    #[serde(with = "base64_serde")]
    pub proof_data: Vec<u8>,
    /// Human-readable location (URL, txid, block explorer link).
    pub location: Option<String>,
    /// Parsed attestation path for step-by-step verification.
    pub attestation_path: Option<Vec<AttestationStep>>,
    /// Provider-specific metadata.
    #[serde(default)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

/// Single step in an attestation proof chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationStep {
    /// Hash or data operation to apply.
    pub operation: AttestationOp,
    /// Operand bytes (empty for hash operations, content for append/prepend).
    #[serde(with = "hex_vec_serde")]
    pub data: Vec<u8>,
}

/// Operation within an attestation proof path.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AttestationOp {
    /// Apply SHA-256 to the current state.
    Sha256,
    /// Apply RIPEMD-160 to the current state.
    Ripemd160,
    /// Append operand bytes after the current state.
    Append,
    /// Prepend operand bytes before the current state.
    Prepend,
    /// Terminal verification step (e.g., Bitcoin block header match).
    Verify,
}

/// Configuration for a single anchor provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    /// Which provider backend this config applies to.
    pub provider_type: ProviderType,
    /// Whether this provider is active.
    pub enabled: bool,
    /// Provider endpoint URL, if applicable.
    pub endpoint: Option<String>,
    /// API key or authentication token.
    pub api_key: Option<String>,
    /// Request timeout in seconds.
    pub timeout_seconds: u64,
    /// Additional provider-specific key-value options.
    #[serde(default)]
    pub options: std::collections::HashMap<String, String>,
}

/// Collection of proofs anchoring a single content hash across providers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anchor {
    /// Anchor format version.
    pub version: u32,
    /// Content hash being anchored.
    #[serde(with = "hex_serde")]
    pub hash: [u8; 32],
    /// Optional document identifier for correlation.
    pub document_id: Option<String>,
    /// When this anchor was created.
    pub created_at: DateTime<Utc>,
    /// Individual proofs from different providers.
    pub proofs: Vec<Proof>,
    /// Aggregate status (confirmed if any proof is confirmed).
    pub status: ProofStatus,
}

impl Anchor {
    /// Create a new pending anchor for the given content hash.
    pub fn new(hash: [u8; 32]) -> Self {
        Self {
            version: 1,
            hash,
            document_id: None,
            created_at: Utc::now(),
            proofs: Vec::new(),
            status: ProofStatus::Pending,
        }
    }

    /// Append a proof, promoting anchor status to confirmed if the proof is.
    pub fn add_proof(&mut self, proof: Proof) {
        if proof.status == ProofStatus::Confirmed {
            self.status = ProofStatus::Confirmed;
        }
        self.proofs.push(proof);
    }

    /// Return the highest-priority confirmed proof, preferring blockchain anchors.
    pub fn best_proof(&self) -> Option<&Proof> {
        self.proofs
            .iter()
            .filter(|p| p.status == ProofStatus::Confirmed)
            .min_by_key(|p| match p.provider {
                ProviderType::Bitcoin => 0,
                ProviderType::Ethereum => 1,
                ProviderType::OpenTimestamps => 2,
                ProviderType::Rfc3161 => 3,
                ProviderType::Notary => 4,
            })
            .or_else(|| self.proofs.first())
    }

    /// Return true if at least one proof is confirmed.
    pub fn is_confirmed(&self) -> bool {
        self.proofs
            .iter()
            .any(|p| p.status == ProofStatus::Confirmed)
    }
}

mod hex_serde {
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

mod base64_serde {
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

mod hex_vec_serde {
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
