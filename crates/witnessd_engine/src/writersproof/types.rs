// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Request/response types for the WritersProof attestation API.

use serde::{Deserialize, Serialize};

/// Nonce response from `POST /v1/nonce`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceResponse {
    /// 32-byte random nonce (hex-encoded).
    pub nonce: String,
    /// ISO 8601 timestamp when the nonce expires.
    pub expires_at: String,
    /// Unique identifier for the nonce session.
    pub nonce_id: String,
}

/// Enrollment request for `POST /v1/enroll`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollRequest {
    /// Hex-encoded master public key.
    pub public_key: String,
    /// Device identifier (SHA-256 of public key).
    pub device_id: String,
    /// Operating system platform.
    pub platform: String,
    /// Hardware attestation type (secure_enclave, tpm, software).
    pub attestation_type: String,
    /// Optional hardware attestation certificate (hex or base64).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_certificate: Option<String>,
}

/// Enrollment response from `POST /v1/enroll`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollResponse {
    /// Assigned hardware key ID.
    pub hardware_key_id: String,
    /// Trust tier assigned (T1, T2, T3).
    pub assurance_tier: String,
    /// Whether enrollment was successful.
    pub enrolled: bool,
}

/// Attestation response from `POST /v1/attest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestResponse {
    /// Attestation record identifier.
    pub attestation_id: String,
    /// Submission status (e.g., "accepted").
    pub status: String,
    /// Verification status (pending, verified, failed).
    pub verification_status: String,
    /// Position in the hardware key's evidence chain.
    pub chain_position: u64,
}

/// Queued attestation for offline submission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueuedAttestation {
    /// Unique queue entry ID.
    pub id: String,
    /// CBOR evidence packet (base64-encoded).
    pub evidence_b64: String,
    /// Hex-encoded nonce (if pre-fetched).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Hardware key ID.
    pub hardware_key_id: String,
    /// Hex-encoded signature over evidence.
    pub signature: String,
    /// Number of retry attempts.
    pub retry_count: u32,
    /// Last error message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// When this entry was created.
    pub created_at: String,
}
