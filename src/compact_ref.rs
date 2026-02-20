//! Compact Evidence References
//!
//! This module implements compact evidence references as defined in the witnessd
//! RFC. Compact references provide a cryptographic link to full Evidence packets
//! without requiring the full packet to be transmitted.
//!
//! # Use Cases
//!
//! - Embedding in document metadata (PDF, EXIF, Office)
//! - QR codes for physical verification
//! - Git commit messages
//! - Protocol headers with size constraints
//!
//! # Size Target
//!
//! Compact references are designed to be ~200 bytes (CBOR) or ~300 characters
//! (base64), fitting comfortably in most metadata fields and QR codes.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Summary of evidence for compact representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactSummary {
    /// Number of checkpoints in the Evidence
    pub checkpoint_count: u32,

    /// Total characters in the document
    pub total_chars: u64,

    /// Total VDF time in seconds
    pub total_vdf_time_seconds: f64,

    /// Evidence tier (1=Basic, 2=Standard, 3=Enhanced, 4=Maximum)
    pub evidence_tier: u8,

    /// Verdict (if available from Attestation Result)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict: Option<String>,

    /// Confidence score (if available)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence_score: Option<f32>,
}

/// Metadata for compact reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactMetadata {
    /// Author name (if disclosed)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author_name: Option<String>,

    /// When Evidence was created
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<DateTime<Utc>>,

    /// Name of verifier (if verified)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier_name: Option<String>,

    /// When verification occurred
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<DateTime<Utc>>,
}

/// Compact Evidence Reference
///
/// Provides a cryptographically-bound reference to a full Evidence packet
/// that can be embedded in space-constrained contexts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactEvidenceRef {
    /// UUID of the full Evidence packet
    pub packet_id: Uuid,

    /// Hash of the final checkpoint (for verification)
    pub chain_hash: String,

    /// Hash of the document content
    pub document_hash: String,

    /// Summary statistics
    pub summary: CompactSummary,

    /// URI where full Evidence can be retrieved
    pub evidence_uri: String,

    /// Signature over the reference fields
    pub signature: String,

    /// Optional metadata
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<CompactMetadata>,
}

impl CompactEvidenceRef {
    /// Create a new compact reference
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

    /// Set metadata
    pub fn with_metadata(mut self, metadata: CompactMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Generate the signable payload for this reference
    ///
    /// The payload is what should be signed to produce the signature field.
    pub fn signable_payload(&self) -> Vec<u8> {
        // Create a deterministic JSON representation of fields to sign
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

    /// Encode to base64 URI format
    ///
    /// Returns a string like: pop-ref:base64urldata...
    pub fn to_base64_uri(&self) -> Result<String, serde_json::Error> {
        let json = serde_json::to_vec(self)?;
        let encoded =
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &json);
        Ok(format!("pop-ref:{}", encoded))
    }

    /// Decode from base64 URI format
    pub fn from_base64_uri(uri: &str) -> Result<Self, CompactRefError> {
        let encoded = uri
            .strip_prefix("pop-ref:")
            .ok_or(CompactRefError::InvalidPrefix)?;

        let json =
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, encoded)
                .map_err(|_| CompactRefError::InvalidBase64)?;

        serde_json::from_slice(&json).map_err(|_| CompactRefError::InvalidJson)
    }

    /// Generate a verification URI
    ///
    /// Returns a clickable URI that opens the verification service
    pub fn verification_uri(&self) -> String {
        // URL-encode the evidence URI
        let encoded_evidence = urlencoding::encode(&self.evidence_uri);
        format!(
            "pop://verify?packet={}&uri={}",
            self.packet_id, encoded_evidence
        )
    }

    /// Estimate the encoded size in bytes
    pub fn estimated_size(&self) -> usize {
        // UUID: 16 bytes
        // chain_hash: ~64 bytes (hex SHA-256)
        // document_hash: ~64 bytes
        // summary: ~50 bytes
        // evidence_uri: variable (assume ~100)
        // signature: ~88 bytes (Ed25519 base64)
        // metadata: variable
        // JSON overhead: ~100 bytes

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

/// Errors that can occur when working with compact references
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompactRefError {
    /// URI doesn't start with "pop-ref:"
    InvalidPrefix,
    /// Base64 decoding failed
    InvalidBase64,
    /// JSON parsing failed
    InvalidJson,
    /// Signature verification failed
    InvalidSignature,
    /// Hash mismatch during verification
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

/// Builder for creating compact references from Evidence packets
pub struct CompactRefBuilder {
    packet_id: Option<Uuid>,
    chain_hash: Option<String>,
    document_hash: Option<String>,
    summary: Option<CompactSummary>,
    evidence_uri: Option<String>,
    metadata: Option<CompactMetadata>,
}

impl CompactRefBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            packet_id: None,
            chain_hash: None,
            document_hash: None,
            summary: None,
            evidence_uri: None,
            metadata: None,
        }
    }

    /// Set packet ID
    pub fn packet_id(mut self, id: Uuid) -> Self {
        self.packet_id = Some(id);
        self
    }

    /// Set chain hash
    pub fn chain_hash(mut self, hash: impl Into<String>) -> Self {
        self.chain_hash = Some(hash.into());
        self
    }

    /// Set document hash
    pub fn document_hash(mut self, hash: impl Into<String>) -> Self {
        self.document_hash = Some(hash.into());
        self
    }

    /// Set summary
    pub fn summary(mut self, summary: CompactSummary) -> Self {
        self.summary = Some(summary);
        self
    }

    /// Set evidence URI
    pub fn evidence_uri(mut self, uri: impl Into<String>) -> Self {
        self.evidence_uri = Some(uri.into());
        self
    }

    /// Set metadata
    pub fn metadata(mut self, metadata: CompactMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Build the compact reference (signature must be provided separately)
    pub fn build(self, signature: String) -> Result<CompactEvidenceRef, &'static str> {
        Ok(CompactEvidenceRef {
            packet_id: self.packet_id.ok_or("packet_id required")?,
            chain_hash: self.chain_hash.ok_or("chain_hash required")?,
            document_hash: self.document_hash.ok_or("document_hash required")?,
            summary: self.summary.ok_or("summary required")?,
            evidence_uri: self.evidence_uri.ok_or("evidence_uri required")?,
            signature,
            metadata: self.metadata,
        })
    }
}

impl Default for CompactRefBuilder {
    fn default() -> Self {
        Self::new()
    }
}

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
    fn test_builder() {
        let compact = CompactRefBuilder::new()
            .packet_id(Uuid::new_v4())
            .chain_hash("hash1")
            .document_hash("hash2")
            .summary(CompactSummary {
                checkpoint_count: 10,
                total_chars: 1000,
                total_vdf_time_seconds: 600.0,
                evidence_tier: 1,
                verdict: None,
                confidence_score: None,
            })
            .evidence_uri("https://example.com/evidence.pop")
            .build("signature".to_string())
            .unwrap();

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
        // Should be reasonable for embedding
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
