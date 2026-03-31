// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Request/response types for the WritersProof attestation API.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NonceResponse {
    /// 32-byte hex-encoded random nonce
    pub nonce: String,
    /// ISO 8601 expiration timestamp
    pub expires_at: String,
    pub nonce_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollResponse {
    pub hardware_key_id: String,
    /// Trust tier: T1, T2, or T3
    pub assurance_tier: String,
    pub enrolled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestResponse {
    pub attestation_id: String,
    /// e.g. "accepted"
    pub status: String,
    /// One of: `pending`, `verified`, `failed`
    pub verification_status: String,
    /// Position in the hardware key's evidence chain
    pub chain_position: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnchorRequest {
    /// SHA-256 hash of the evidence packet (hex-encoded).
    pub evidence_hash: String,
    /// Author DID (e.g. `did:cpop:...`).
    pub author_did: String,
    /// Ed25519 signature over the evidence hash (hex-encoded).
    pub signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<AnchorMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnchorMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnchorResponse {
    pub anchor_id: String,
    pub timestamp: String,
    pub log_index: u64,
    pub inclusion_proof: Vec<String>,
    pub signed_tree_head: SignedTreeHead,
}

/// Signed Tree Head from the transparency log.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedTreeHead {
    pub tree_size: u64,
    pub root_hash: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyResponse {
    pub verdict: String,
    pub confidence: f64,
    pub tier: String,
    pub anchored: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchor_timestamp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transparency_log: Option<TransparencyLogInfo>,
    pub evidence_summary: EvidenceSummary,
    /// Base64-encoded WAR (CBOR EAT Attestation Result).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub war: Option<String>,
}

impl VerifyResponse {
    /// Clamp fields to their valid ranges after deserialization.
    /// `confidence` must be in [0.0, 1.0]; values outside this range indicate
    /// a malformed or tampered server response.
    pub fn sanitize(&mut self) {
        self.confidence = self.confidence.clamp(0.0, 1.0);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransparencyLogInfo {
    pub log_index: u64,
    pub inclusion_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceSummary {
    pub duration: String,
    pub keystrokes: u64,
    pub sessions: u64,
    pub behavioral_plausibility: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cross_modal_consistency: Option<String>,
}

/// Request body for `/v1/beacon` -- fetch temporal beacon attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BeaconRequest {
    /// SHA-256 hash of the checkpoint being attested (hex-encoded).
    pub checkpoint_hash: String,
}

/// Response from `/v1/beacon` — WritersProof-attested temporal beacon bundle.
///
/// WritersProof fetches the latest drand round and NIST pulse server-side,
/// then counter-signs the bundle. The `wp_signature` is an Ed25519 signature
/// over `(checkpoint_hash || drand_round || drand_randomness || nist_pulse_index
/// || nist_output_value || fetched_at)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BeaconResponse {
    /// drand League of Entropy round number.
    pub drand_round: u64,
    /// drand randomness output (hex-encoded, 32 bytes).
    pub drand_randomness: String,
    /// NIST Randomness Beacon pulse index.
    pub nist_pulse_index: u64,
    /// NIST beacon output value (hex-encoded, 64 bytes).
    pub nist_output_value: String,
    /// NIST pulse timestamp.
    pub nist_timestamp: String,
    /// When WritersProof fetched the beacon values.
    pub fetched_at: String,
    /// WritersProof Ed25519 counter-signature over the bundle (hex-encoded, 64 bytes).
    pub wp_signature: String,
}

/// Queued attestation for offline submission.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QueuedAttestation {
    pub id: String,
    /// Base64-encoded CBOR evidence packet
    pub evidence_b64: String,
    /// Hex-encoded pre-fetched nonce, if available
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    pub hardware_key_id: String,
    /// Hex-encoded Ed25519 signature over DST + queue_nonce + evidence
    pub signature: String,
    /// Hex-encoded random nonce included in signature to prevent replay (EH-015)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue_nonce: Option<String>,
    pub retry_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    pub created_at: String,
}
