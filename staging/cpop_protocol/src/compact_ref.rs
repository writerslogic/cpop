// SPDX-License-Identifier: Apache-2.0

//! Compact evidence references (~200B CBOR / ~300 chars base64).
//!
//! Cryptographic link to a full Evidence packet for embedding in
//! document metadata (PDF, EXIF, Office), QR codes, git commit messages,
//! or protocol headers with size constraints.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Summary statistics for compact representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactSummary {
    pub checkpoint_count: u32,
    pub total_chars: u64,
    pub total_vdf_time_seconds: f64,
    /// 1=Basic, 2=Standard, 3=Enhanced, 4=Maximum
    pub evidence_tier: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence_score: Option<f32>,
}

/// Optional metadata for compact references.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<DateTime<Utc>>,
}

/// Cryptographically-bound reference to a full Evidence packet,
/// embeddable in space-constrained contexts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactEvidenceRef {
    pub packet_id: Uuid,
    /// Final checkpoint hash
    pub chain_hash: String,
    pub document_hash: String,
    pub summary: CompactSummary,
    /// Where the full Evidence can be retrieved
    pub evidence_uri: String,
    /// Ed25519 over the reference fields
    pub signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<CompactMetadata>,
}

impl CompactEvidenceRef {
    /// Create a compact reference with required fields.
    pub fn new(
        packet_id: Uuid,
        chain_hash: String,
        document_hash: String,
        summary: CompactSummary,
        evidence_uri: String,
        signature: String,
    ) -> Self {
        Self {
            packet_id,
            chain_hash,
            document_hash,
            summary,
            evidence_uri,
            signature,
            metadata: None,
        }
    }

    /// Attach optional metadata (author, verifier, timestamps).
    pub fn with_metadata(mut self, metadata: CompactMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Canonical payload to sign for the `signature` field.
    pub fn signable_payload(&self) -> Vec<u8> {
        let payload = serde_json::json!({
            "packet_id": self.packet_id.to_string(),
            "chain_hash": self.chain_hash,
            "document_hash": self.document_hash,
            "summary": {
                "checkpoint_count": self.summary.checkpoint_count,
                "total_chars": self.summary.total_chars,
                "total_vdf_time_seconds": self.summary.total_vdf_time_seconds,
                "evidence_tier": self.summary.evidence_tier,
            },
            "evidence_uri": self.evidence_uri,
        });

        payload.to_string().into_bytes()
    }

    /// Encode as `pop-ref:<base64url>` URI.
    pub fn to_base64_uri(&self) -> Result<String, serde_json::Error> {
        let json = serde_json::to_vec(self)?;
        let encoded =
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &json);
        Ok(format!("pop-ref:{}", encoded))
    }

    /// Decode from `pop-ref:<base64url>` URI.
    pub fn from_base64_uri(uri: &str) -> Result<Self, CompactRefError> {
        let encoded = uri
            .strip_prefix("pop-ref:")
            .ok_or(CompactRefError::InvalidPrefix)?;

        let json =
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, encoded)
                .map_err(|_| CompactRefError::InvalidBase64)?;

        serde_json::from_slice(&json).map_err(|_| CompactRefError::InvalidJson)
    }

    /// `pop://verify?...` URI for the verification service.
    pub fn verification_uri(&self) -> String {
        let encoded_evidence = urlencoding::encode(&self.evidence_uri);
        format!(
            "pop://verify?packet={}&uri={}",
            self.packet_id, encoded_evidence
        )
    }

    /// Rough estimate of encoded size in bytes.
    pub fn estimated_size(&self) -> usize {
        // Fixed overhead: UUID(16) + hashes(128) + summary(50) + sig(88) + JSON(~200)
        let base = 16 + 64 + 64 + 50 + 100 + 88 + 100;
        let uri_len = self.evidence_uri.len();
        let metadata_len = self
            .metadata
            .as_ref()
            .map(|m| {
                m.author_name.as_ref().map(|s| s.len()).unwrap_or(0)
                    + m.verifier_name.as_ref().map(|s| s.len()).unwrap_or(0)
                    + 40 // timestamps
            })
            .unwrap_or(0);

        base + uri_len + metadata_len
    }
}

/// Compact reference decoding/verification errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompactRefError {
    /// URI does not start with `pop-ref:`.
    InvalidPrefix,
    /// Base64 decoding failed.
    InvalidBase64,
    /// JSON structure is malformed.
    InvalidJson,
    /// Ed25519 signature verification failed.
    InvalidSignature,
    /// Document hash does not match the referenced evidence.
    HashMismatch,
}

impl std::fmt::Display for CompactRefError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPrefix => write!(f, "URI must start with 'pop-ref:'"),
            Self::InvalidBase64 => write!(f, "Invalid base64 encoding"),
            Self::InvalidJson => write!(f, "Invalid JSON structure"),
            Self::InvalidSignature => write!(f, "Signature verification failed"),
            Self::HashMismatch => write!(f, "Hash does not match Evidence"),
        }
    }
}

impl std::error::Error for CompactRefError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ref() -> CompactEvidenceRef {
        CompactEvidenceRef::new(
            Uuid::nil(),
            "abcd1234".to_string(),
            "efgh5678".to_string(),
            CompactSummary {
                checkpoint_count: 47,
                total_chars: 12500,
                total_vdf_time_seconds: 5400.0,
                evidence_tier: 2,
                verdict: Some("likely-human".to_string()),
                confidence_score: Some(0.87),
            },
            "https://evidence.example.com/packets/abc.pop".to_string(),
            "test_signature".to_string(),
        )
    }

    #[test]
    fn test_create_compact_ref() {
        let compact = sample_ref();
        assert_eq!(compact.summary.checkpoint_count, 47);
        assert_eq!(compact.summary.evidence_tier, 2);
    }

    #[test]
    fn test_base64_roundtrip() {
        let original = sample_ref();
        let encoded = original.to_base64_uri().unwrap();
        assert!(encoded.starts_with("pop-ref:"));

        let decoded = CompactEvidenceRef::from_base64_uri(&encoded).unwrap();
        assert_eq!(decoded.packet_id, original.packet_id);
        assert_eq!(decoded.chain_hash, original.chain_hash);
    }

    #[test]
    fn test_invalid_prefix() {
        let result = CompactEvidenceRef::from_base64_uri("invalid:data");
        assert_eq!(result.unwrap_err(), CompactRefError::InvalidPrefix);
    }

    #[test]
    fn test_new_constructor() {
        let compact = CompactEvidenceRef::new(
            Uuid::new_v4(),
            "hash1".to_string(),
            "hash2".to_string(),
            CompactSummary {
                checkpoint_count: 10,
                total_chars: 1000,
                total_vdf_time_seconds: 600.0,
                evidence_tier: 1,
                verdict: None,
                confidence_score: None,
            },
            "https://example.com/evidence.pop".to_string(),
            "signature".to_string(),
        );

        assert_eq!(compact.summary.checkpoint_count, 10);
    }

    #[test]
    fn test_verification_uri() {
        let compact = sample_ref();
        let uri = compact.verification_uri();
        assert!(uri.starts_with("pop://verify?"));
        assert!(uri.contains("packet="));
    }

    #[test]
    fn test_estimated_size() {
        let compact = sample_ref();
        let size = compact.estimated_size();
        assert!(size < 1000);
    }

    #[test]
    fn test_serialization() {
        let original = sample_ref();
        let json = serde_json::to_string(&original).unwrap();
        let parsed: CompactEvidenceRef = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.packet_id, original.packet_id);
    }
}
