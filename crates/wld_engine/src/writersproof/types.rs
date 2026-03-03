// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Request/response types for the WritersProof attestation API.

use serde::{Deserialize, Serialize};

/// Response from `POST /v1/nonce`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceResponse {
    /// 32-byte hex-encoded random nonce
    pub nonce: String,
    /// ISO 8601 expiration timestamp
    pub expires_at: String,
    pub nonce_id: String,
}

/// Request body for `POST /v1/enroll`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollRequest {
    /// Hex-encoded master public key
    pub public_key: String,
    /// SHA-256 of `public_key`
    pub device_id: String,
    pub platform: String,
    /// One of: `secure_enclave`, `tpm`, `software`
    pub attestation_type: String,
    /// Hardware attestation certificate (hex or base64)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_certificate: Option<String>,
}

/// Response from `POST /v1/enroll`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollResponse {
    pub hardware_key_id: String,
    /// Trust tier: T1, T2, or T3
    pub assurance_tier: String,
    pub enrolled: bool,
}

/// Response from `POST /v1/attest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestResponse {
    pub attestation_id: String,
    /// e.g. "accepted"
    pub status: String,
    /// One of: `pending`, `verified`, `failed`
    pub verification_status: String,
    /// Position in the hardware key's evidence chain
    pub chain_position: u64,
}

/// Queued attestation for offline submission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueuedAttestation {
    pub id: String,
    /// Base64-encoded CBOR evidence packet
    pub evidence_b64: String,
    /// Hex-encoded pre-fetched nonce, if available
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    pub hardware_key_id: String,
    /// Hex-encoded Ed25519 signature over evidence
    pub signature: String,
    pub retry_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    pub created_at: String,
}
