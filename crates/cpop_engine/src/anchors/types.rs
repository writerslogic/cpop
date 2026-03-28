// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::serde_utils::{base64_serde, hex_serde, hex_vec_serde};

/// Errors from anchor submission, verification, and provider operations.
#[derive(Debug, Error)]
pub enum AnchorError {
    #[error("provider unavailable: {0}")]
    Unavailable(String),
    #[error("configuration error: {0}")]
    Configuration(String),
    #[error("submission failed: {0}")]
    Submission(String),
    #[error("signing error: {0}")]
    Signing(String),
    #[error("verification failed: {0}")]
    Verification(String),
    #[error("proof not ready")]
    NotReady,
    #[error("proof expired")]
    Expired,
    #[error("network error: {0}")]
    Network(String),
    #[error("invalid proof format: {0}")]
    InvalidFormat(String),
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
    /// OP_RETURN transaction.
    Bitcoin,
    Ethereum,
    Notary,
}

/// Lifecycle state of an anchor proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProofStatus {
    Pending,
    Confirmed,
    Failed,
    Expired,
}

/// Cryptographic proof that a hash was anchored to an external system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    /// Provider-assigned identifier (txid, serial number, etc.).
    pub id: String,
    pub provider: ProviderType,
    pub status: ProofStatus,
    #[serde(with = "hex_serde")]
    pub anchored_hash: [u8; 32],
    pub submitted_at: DateTime<Utc>,
    pub confirmed_at: Option<DateTime<Utc>>,
    /// Raw proof bytes (OTS file, RFC 3161 token, etc.).
    #[serde(with = "base64_serde")]
    pub proof_data: Vec<u8>,
    /// Human-readable location (URL, txid, block explorer link).
    pub location: Option<String>,
    pub attestation_path: Option<Vec<AttestationStep>>,
    #[serde(default)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

/// Single step in an attestation proof chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationStep {
    pub operation: AttestationOp,
    /// Operand bytes (empty for hash operations, content for append/prepend).
    #[serde(with = "hex_vec_serde")]
    pub data: Vec<u8>,
}

/// Operation within an attestation proof path.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AttestationOp {
    Sha256,
    Ripemd160,
    Append,
    Prepend,
    /// Terminal step (e.g., Bitcoin block header match).
    Verify,
}

/// Configuration for a single anchor provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    pub provider_type: ProviderType,
    pub enabled: bool,
    pub endpoint: Option<String>,
    pub api_key: Option<String>,
    /// Timeout in seconds.
    pub timeout_seconds: u64,
    #[serde(default)]
    pub options: std::collections::HashMap<String, String>,
}

/// Collection of proofs anchoring a single content hash across providers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anchor {
    pub version: u32,
    #[serde(with = "hex_serde")]
    pub hash: [u8; 32],
    pub document_id: Option<String>,
    pub created_at: DateTime<Utc>,
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

    /// Append a proof, updating anchor status based on the best proof state.
    ///
    /// Promotes to `Confirmed` when any proof is confirmed; demotes back to
    /// `Pending` or `Failed` if the last confirmed proof is removed or replaced.
    pub fn add_proof(&mut self, proof: Proof) {
        self.proofs.push(proof);
        self.recompute_status();
    }

    /// Recompute aggregate status from the current set of proofs.
    fn recompute_status(&mut self) {
        if self
            .proofs
            .iter()
            .any(|p| p.status == ProofStatus::Confirmed)
        {
            self.status = ProofStatus::Confirmed;
        } else if self.proofs.iter().all(|p| p.status == ProofStatus::Failed)
            && !self.proofs.is_empty()
        {
            self.status = ProofStatus::Failed;
        } else {
            self.status = ProofStatus::Pending;
        }
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
        // Only return confirmed proofs; callers should handle None explicitly.
    }

    /// Return true if at least one proof is confirmed.
    pub fn is_confirmed(&self) -> bool {
        self.proofs
            .iter()
            .any(|p| p.status == ProofStatus::Confirmed)
    }
}
