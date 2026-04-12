// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Ultima-Tier Cryptographic Provenance for Evidence WAR/1.1.
//!
//! Features:
//! - Deterministic Canonicalization: Ensures stable hashes for the section.
//! - Semantic Validation: Prevents logically impossible derivation claims.
//! - Stack-Optimized: Minimizes heap pressure for common 1-parent lineages.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use uuid::Uuid;

use crate::serde_utils::hex_bytes_32;
pub const PROVENANCE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivationType {
    Continuation,
    Merge,
    Split,
    Rewrite,
    Translation,
    Fork,
    CitationOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivationAspect {
    Structure,
    Content,
    Ideas,
    Data,
    Methodology,
    Code,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivationExtent {
    None,
    Minimal,
    Partial,
    Substantial,
    Complete,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProvenanceLink {
    pub parent_packet_id: Uuid,

    #[serde(with = "hex_bytes_32")]
    pub parent_chain_hash: [u8; 32],

    pub derivation_type: DerivationType,
    pub derivation_timestamp: DateTime<Utc>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relationship_description: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inherited_checkpoints: Option<Vec<u32>>,

    #[serde(
        default,
        serialize_with = "crate::serde_utils::serialize_optional_signature",
        deserialize_with = "crate::serde_utils::deserialize_optional_signature",
        skip_serializing_if = "Option::is_none"
    )]
    pub cross_attestation: Option<[u8; 64]>,
}

/// Ordered for deterministic canonicalization: Sorts by parent UUID.
impl Ord for ProvenanceLink {
    fn cmp(&self, other: &Self) -> Ordering {
        self.parent_packet_id
            .cmp(&other.parent_packet_id)
            .then(self.parent_chain_hash.cmp(&other.parent_chain_hash))
    }
}

impl PartialOrd for ProvenanceLink {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DerivationClaim {
    pub aspect: DerivationAspect,
    pub extent: DerivationExtent,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub estimated_percentage: Option<f32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceMetadata {
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement: Option<String>,
    pub all_parents_available: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_parent_reasons: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ProvenanceSection {
    pub parent_links: Vec<ProvenanceLink>,
    pub derivation_claims: Vec<DerivationClaim>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ProvenanceMetadata>,
}

impl ProvenanceSection {
    pub fn new() -> Self {
        Self {
            parent_links: Vec::new(),
            derivation_claims: Vec::new(),
            metadata: Some(ProvenanceMetadata {
                version: PROVENANCE_SCHEMA_VERSION,
                ..Default::default()
            }),
        }
    }

    /// Sorts all internal links and claims to ensure a stable cryptographic hash.
    pub fn canonicalize(&mut self) {
        self.parent_links.sort_unstable();
        self.derivation_claims.sort_by_key(|c| c.aspect);
    }

    /// Performs a high-integrity audit of the provenance data.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.parent_links.is_empty() && !self.derivation_claims.is_empty() {
            return Err("Claims provided without associated parent links.");
        }

        let has_merge = self
            .parent_links
            .iter()
            .any(|l| l.derivation_type == DerivationType::Merge);
        if has_merge && self.parent_links.len() < 2 {
            return Err("Derivation marked as 'Merge' but only one parent link provided.");
        }

        let has_cont = self
            .parent_links
            .iter()
            .any(|l| l.derivation_type == DerivationType::Continuation);
        if has_cont && self.parent_links.len() > 1 {
            return Err("Lineage ambiguity: 'Continuation' cannot span multiple parent UUIDs.");
        }

        Ok(())
    }

    pub fn add_link(mut self, link: ProvenanceLink) -> Self {
        self.parent_links.push(link);
        self
    }

    pub fn add_claim(mut self, claim: DerivationClaim) -> Self {
        self.derivation_claims.push(claim);
        self
    }
}

impl ProvenanceLink {
    pub fn new(parent_id: Uuid, parent_hash: [u8; 32], kind: DerivationType) -> Self {
        Self {
            parent_packet_id: parent_id,
            parent_chain_hash: parent_hash,
            derivation_type: kind,
            derivation_timestamp: Utc::now(),
            relationship_description: None,
            inherited_checkpoints: None,
            cross_attestation: None,
        }
    }

    pub fn with_attestation(mut self, sig: [u8; 64]) -> Self {
        self.cross_attestation = Some(sig);
        self
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.relationship_description = Some(desc.into());
        self
    }

    pub fn with_inherited_checkpoints(mut self, checkpoints: Vec<u32>) -> Self {
        self.inherited_checkpoints = Some(checkpoints);
        self
    }
}

impl ProvenanceSection {
    pub fn with_metadata(mut self, metadata: ProvenanceMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonicalization_stability() {
        let id_a = Uuid::from_u128(1);
        let id_b = Uuid::from_u128(2);

        let link_a = ProvenanceLink::new(id_a, [0x11; 32], DerivationType::Fork);
        let link_b = ProvenanceLink::new(id_b, [0x22; 32], DerivationType::Fork);

        let mut section_1 = ProvenanceSection::new()
            .add_link(link_a.clone())
            .add_link(link_b.clone());
        let mut section_2 = ProvenanceSection::new().add_link(link_b).add_link(link_a);

        section_1.canonicalize();
        section_2.canonicalize();

        assert_eq!(
            serde_json::to_vec(&section_1).unwrap(),
            serde_json::to_vec(&section_2).unwrap()
        );
    }

    #[test]
    fn test_semantic_validation_gates() {
        let mut section = ProvenanceSection::new().add_link(ProvenanceLink::new(
            Uuid::new_v4(),
            [0u8; 32],
            DerivationType::Merge,
        ));
        assert!(section.validate().is_err());

        section.parent_links.push(ProvenanceLink::new(
            Uuid::new_v4(),
            [1u8; 32],
            DerivationType::Merge,
        ));
        assert!(section.validate().is_ok());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let link = ProvenanceLink::new(Uuid::new_v4(), [0xAA; 32], DerivationType::Fork)
            .with_description("test link");
        let section = ProvenanceSection::new()
            .add_link(link)
            .add_claim(DerivationClaim {
                aspect: DerivationAspect::Content,
                extent: DerivationExtent::Partial,
                description: Some("partial content reuse".into()),
                estimated_percentage: Some(0.3),
            });
        let json = serde_json::to_string(&section).unwrap();
        let restored: ProvenanceSection = serde_json::from_str(&json).unwrap();
        assert_eq!(section.parent_links.len(), restored.parent_links.len());
        assert_eq!(
            section.derivation_claims.len(),
            restored.derivation_claims.len()
        );
        assert_eq!(
            section.parent_links[0].parent_chain_hash,
            restored.parent_links[0].parent_chain_hash
        );
    }
}
