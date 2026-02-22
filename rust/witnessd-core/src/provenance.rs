//! Cross-Document Provenance Links
//!
//! This module implements the provenance linking mechanism defined in the
//! witnessd RFC. Provenance links establish cryptographic relationships
//! between Evidence packets, enabling authors to prove that one document
//! evolved from, merged with, or was derived from other documented works.
//!
//! # Security Model
//!
//! Provenance links are verified by:
//! 1. Validating that parent-chain-hash matches the final checkpoint hash
//!    of the parent Evidence packet (if available)
//! 2. Verifying that cross-packet attestation signatures are valid
//! 3. Checking temporal consistency (derivation cannot precede parent creation)
//!
//! # Privacy Considerations
//!
//! Provenance links may reveal:
//! - Document lineage and creative history
//! - Collaboration patterns and research relationships
//! - Timing of derivative work

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Type of derivation relationship between documents
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivationType {
    /// Same work, new Evidence packet (e.g., monthly export of ongoing project)
    Continuation,
    /// Combined from multiple sources
    Merge,
    /// Extracted from larger work
    Split,
    /// Substantial revision
    Rewrite,
    /// Language translation
    Translation,
    /// Independent development branch
    Fork,
    /// References but not derived from (citation only)
    CitationOnly,
}

/// Aspect of the work that was derived
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivationAspect {
    /// Document organization
    Structure,
    /// Textual content
    Content,
    /// Conceptual elements
    Ideas,
    /// Data or results
    Data,
    /// Methods or approach
    Methodology,
    /// Source code
    Code,
}

/// Extent of derivation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivationExtent {
    /// Not derived
    None,
    /// Less than 10%
    Minimal,
    /// 10-50%
    Partial,
    /// 50-90%
    Substantial,
    /// More than 90%
    Complete,
}

/// Link to a parent Evidence packet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceLink {
    /// UUID of the parent Evidence packet
    pub parent_packet_id: Uuid,

    /// Hash of the final checkpoint in the parent packet
    /// Used for verification when parent is available
    pub parent_chain_hash: String,

    /// Type of derivation relationship
    pub derivation_type: DerivationType,

    /// When this derivation occurred
    pub derivation_timestamp: DateTime<Utc>,

    /// Human-readable description of the relationship
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relationship_description: Option<String>,

    /// Indices of checkpoints inherited from parent
    /// (for continuation/split operations)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inherited_checkpoints: Option<Vec<u32>>,

    /// Cross-packet attestation signature
    /// Proves author had access to parent at derivation time
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cross_attestation: Option<String>,
}

/// Claim about what was derived and how
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerivationClaim {
    /// What aspect was derived
    pub aspect: DerivationAspect,

    /// Extent of derivation
    pub extent: DerivationExtent,

    /// Description of derivation
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Estimated percentage (0.0-1.0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub estimated_percentage: Option<f32>,
}

/// Metadata about provenance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceMetadata {
    /// Human-readable provenance statement
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement: Option<String>,

    /// Whether all parent packets are available for verification
    #[serde(default)]
    pub all_parents_available: bool,

    /// Reasons why some parents are missing
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_parent_reasons: Vec<String>,
}

/// Complete provenance section for an Evidence packet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceSection {
    /// Links to parent Evidence packets
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parent_links: Vec<ProvenanceLink>,

    /// Claims about derivation
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub derivation_claims: Vec<DerivationClaim>,

    /// Metadata about provenance
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ProvenanceMetadata>,
}

impl ProvenanceSection {
    /// Create a new empty provenance section
    pub fn new() -> Self {
        Self {
            parent_links: Vec::new(),
            derivation_claims: Vec::new(),
            metadata: None,
        }
    }

    /// Add a parent link
    pub fn add_link(mut self, link: ProvenanceLink) -> Self {
        self.parent_links.push(link);
        self
    }

    /// Add a derivation claim
    pub fn add_claim(mut self, claim: DerivationClaim) -> Self {
        self.derivation_claims.push(claim);
        self
    }

    /// Set metadata
    pub fn with_metadata(mut self, metadata: ProvenanceMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Check if this section is empty (no meaningful content)
    pub fn is_empty(&self) -> bool {
        self.parent_links.is_empty() && self.derivation_claims.is_empty()
    }
}

impl Default for ProvenanceSection {
    fn default() -> Self {
        Self::new()
    }
}

impl ProvenanceLink {
    /// Create a new provenance link
    pub fn new(
        parent_packet_id: Uuid,
        parent_chain_hash: String,
        derivation_type: DerivationType,
    ) -> Self {
        Self {
            parent_packet_id,
            parent_chain_hash,
            derivation_type,
            derivation_timestamp: Utc::now(),
            relationship_description: None,
            inherited_checkpoints: None,
            cross_attestation: None,
        }
    }

    /// Set relationship description
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.relationship_description = Some(description.into());
        self
    }

    /// Set inherited checkpoint indices
    pub fn with_inherited_checkpoints(mut self, checkpoints: Vec<u32>) -> Self {
        self.inherited_checkpoints = Some(checkpoints);
        self
    }

    /// Set cross-attestation signature
    pub fn with_attestation(mut self, signature: String) -> Self {
        self.cross_attestation = Some(signature);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provenance_link_creation() {
        let link = ProvenanceLink::new(
            Uuid::new_v4(),
            "abc123".to_string(),
            DerivationType::Continuation,
        )
        .with_description("Continued from January export");

        assert_eq!(link.derivation_type, DerivationType::Continuation);
        assert!(link.relationship_description.is_some());
    }

    #[test]
    fn test_provenance_section_builder() {
        let section = ProvenanceSection::new()
            .add_link(ProvenanceLink::new(
                Uuid::new_v4(),
                "hash1".to_string(),
                DerivationType::Merge,
            ))
            .add_claim(DerivationClaim {
                aspect: DerivationAspect::Content,
                extent: DerivationExtent::Substantial,
                description: Some("Main text from parent".to_string()),
                estimated_percentage: Some(0.6),
            });

        assert_eq!(section.parent_links.len(), 1);
        assert_eq!(section.derivation_claims.len(), 1);
        assert!(!section.is_empty());
    }

    #[test]
    fn test_serialization() {
        let section = ProvenanceSection::new().add_link(ProvenanceLink::new(
            Uuid::nil(),
            "test_hash".to_string(),
            DerivationType::Fork,
        ));

        let json = serde_json::to_string(&section).unwrap();
        let parsed: ProvenanceSection = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.parent_links[0].derivation_type, DerivationType::Fork);
    }
}
