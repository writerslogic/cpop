// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Cross-document provenance links between Evidence packets.
//!
//! Establishes cryptographic relationships (continuation, merge, fork, etc.)
//! between packets so authors can prove derivation history. Verified via
//! parent chain-hash matching, cross-packet attestation signatures, and
//! temporal consistency checks.
//!
//! # Privacy
//!
//! Links may reveal document lineage, collaboration patterns, and derivation timing.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Derivation relationship between documents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivationType {
    /// Document continues from a previous session.
    Continuation,
    /// Two or more documents merged into one.
    Merge,
    /// Document split into multiple parts.
    Split,
    /// Substantial rewrite of parent content.
    Rewrite,
    /// Translation of parent into another language.
    Translation,
    /// Independent fork diverging from parent.
    Fork,
    /// Reference-only link with no content derivation.
    CitationOnly,
}

/// Aspect of the work that was derived.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivationAspect {
    /// Document structure or outline.
    Structure,
    /// Written text or media content.
    Content,
    /// Conceptual ideas or arguments.
    Ideas,
    /// Datasets or factual references.
    Data,
    /// Research methodology or process.
    Methodology,
    /// Source code or algorithms.
    Code,
}

/// Extent of derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivationExtent {
    /// No derivation from this aspect.
    None,
    /// Less than 10% derived.
    Minimal,
    /// 10--50% derived.
    Partial,
    /// 50--90% derived.
    Substantial,
    /// More than 90% derived.
    Complete,
}

/// Cryptographic link to a parent Evidence packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceLink {
    /// UUID of the parent Evidence packet.
    pub parent_packet_id: Uuid,
    /// Final checkpoint hash; used for verification when parent is available.
    pub parent_chain_hash: String,
    /// Type of derivation relationship to the parent.
    pub derivation_type: DerivationType,
    /// When the derivation occurred.
    pub derivation_timestamp: DateTime<Utc>,
    /// Optional human-readable description of the relationship.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relationship_description: Option<String>,
    /// Checkpoint indices inherited from parent (continuation/split).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inherited_checkpoints: Option<Vec<u32>>,
    /// Proves author had access to parent at derivation time
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cross_attestation: Option<String>,
}

/// Claim about what was derived and to what extent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerivationClaim {
    /// Which aspect of the work was derived.
    pub aspect: DerivationAspect,
    /// How much of that aspect was derived.
    pub extent: DerivationExtent,
    /// Optional human-readable description of the derivation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Estimated percentage of content derived (0.0--1.0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub estimated_percentage: Option<f32>,
}

/// Provenance metadata and parent availability status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceMetadata {
    /// Human-readable provenance statement
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement: Option<String>,
    /// Whether all referenced parent packets are available for verification.
    #[serde(default)]
    pub all_parents_available: bool,
    /// Reasons why specific parent packets are unavailable.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_parent_reasons: Vec<String>,
}

/// Provenance section embedded in an Evidence packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceSection {
    /// Links to parent Evidence packets.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parent_links: Vec<ProvenanceLink>,
    /// Claims about what was derived and to what extent.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub derivation_claims: Vec<DerivationClaim>,
    /// Optional provenance metadata and parent availability status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ProvenanceMetadata>,
}

impl ProvenanceSection {
    /// Create an empty provenance section.
    pub fn new() -> Self {
        Self {
            parent_links: Vec::new(),
            derivation_claims: Vec::new(),
            metadata: None,
        }
    }

    /// Append a parent link (builder pattern).
    pub fn add_link(mut self, link: ProvenanceLink) -> Self {
        self.parent_links.push(link);
        self
    }

    /// Append a derivation claim (builder pattern).
    pub fn add_claim(mut self, claim: DerivationClaim) -> Self {
        self.derivation_claims.push(claim);
        self
    }

    /// Set provenance metadata (builder pattern).
    pub fn with_metadata(mut self, metadata: ProvenanceMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Return true if there are no parent links or derivation claims.
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
    /// Create a link to a parent packet with the given derivation type.
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

    /// Set a human-readable relationship description (builder pattern).
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.relationship_description = Some(description.into());
        self
    }

    /// Set checkpoint indices inherited from the parent (builder pattern).
    pub fn with_inherited_checkpoints(mut self, checkpoints: Vec<u32>) -> Self {
        self.inherited_checkpoints = Some(checkpoints);
        self
    }

    /// Set a cross-attestation signature proving access to the parent (builder pattern).
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
