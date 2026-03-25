// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! ToIP (Trust over IP) Ecosystem Governance Framework metadata and
//! Trust Registry Query Protocol (TRQP) v2.0 types for WritersProof.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Ecosystem Governance Framework
// ---------------------------------------------------------------------------

/// ToIP Ecosystem Governance Framework metadata for WritersProof.
/// Defines the trust rules for the WritersProof attestation ecosystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcosystemGovernanceFramework {
    /// EGF identifier URI.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Version.
    pub version: String,
    /// Governing authority.
    pub authority: String,
    /// Technical specification reference (draft-condrey-rats-pop).
    pub technical_spec: String,
    /// Authorized roles.
    pub roles: Vec<EgfRole>,
    /// Trust assurance levels.
    pub assurance_levels: Vec<AssuranceLevel>,
}

/// A role authorized within an EGF.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgfRole {
    /// Role name (e.g. "attester", "verifier", "relying_party").
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Requirements that an entity must meet to hold this role.
    pub requirements: Vec<String>,
}

/// A trust assurance level defined by an EGF.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssuranceLevel {
    /// Level name (e.g. "software_only", "hardware_assisted", "hardware_bound").
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Minimum requirements for this level.
    pub minimum_requirements: Vec<String>,
}

/// Return the default WritersProof Ecosystem Governance Framework
/// with the three attestation tiers (software-only, hardware-assisted,
/// hardware-bound) and the standard RATS roles.
pub fn writersproof_egf() -> EcosystemGovernanceFramework {
    EcosystemGovernanceFramework {
        id: "urn:writersproof:egf:v1".to_string(),
        name: "WritersProof Authorship Attestation EGF".to_string(),
        version: "1.0".to_string(),
        authority: "WritersLogic LLC".to_string(),
        technical_spec: "draft-condrey-rats-pop".to_string(),
        roles: vec![
            EgfRole {
                name: "attester".to_string(),
                description: "Captures behavioral evidence during document creation".to_string(),
                requirements: vec![
                    "Run CPOP sentinel with keystroke capture enabled".to_string(),
                    "Maintain checkpoint chain integrity".to_string(),
                ],
            },
            EgfRole {
                name: "verifier".to_string(),
                description: "Appraises evidence and produces attestation results".to_string(),
                requirements: vec![
                    "Implement draft-condrey-rats-pop verification pipeline".to_string(),
                    "Produce EAR tokens per draft-ietf-rats-ear".to_string(),
                ],
            },
            EgfRole {
                name: "relying_party".to_string(),
                description: "Consumes attestation results for trust decisions".to_string(),
                requirements: vec![
                    "Validate EAR signature and profile".to_string(),
                    "Respect assurance level thresholds".to_string(),
                ],
            },
        ],
        assurance_levels: vec![
            AssuranceLevel {
                name: "software_only".to_string(),
                description: "Evidence captured and signed entirely in software".to_string(),
                minimum_requirements: vec![
                    "Ed25519 identity key".to_string(),
                    "Checkpoint chain with VDF proofs".to_string(),
                    "Behavioral entropy above 1.5 bits".to_string(),
                ],
            },
            AssuranceLevel {
                name: "hardware_assisted".to_string(),
                description: "Software evidence with hardware-backed key storage".to_string(),
                minimum_requirements: vec![
                    "TPM or Secure Enclave key attestation".to_string(),
                    "PUF binding for session keys".to_string(),
                    "All software_only requirements".to_string(),
                ],
            },
            AssuranceLevel {
                name: "hardware_bound".to_string(),
                description: "Evidence signing performed within hardware security module"
                    .to_string(),
                minimum_requirements: vec![
                    "All hardware_assisted requirements".to_string(),
                    "Non-exportable signing key in HSM".to_string(),
                    "Hardware event counter attestation".to_string(),
                ],
            },
        ],
    }
}

// ---------------------------------------------------------------------------
// Trust Registry Query Protocol (TRQP) v2.0
// ---------------------------------------------------------------------------

/// A query to a ToIP Trust Registry per TRQP v2.0.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrqpQuery {
    /// URI of the trust registry to query.
    pub registry_uri: String,
    /// DID of the entity being queried.
    pub entity_did: String,
    /// Authorization being checked (e.g. "issue_attestation").
    pub authorization: String,
    /// EGF URI that defines the governance context.
    pub egf_uri: String,
}

/// Response from a ToIP Trust Registry per TRQP v2.0.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrqpResponse {
    /// Whether the entity is authorized.
    pub authorized: bool,
    /// DID of the queried entity.
    pub entity_did: String,
    /// The authorization that was checked.
    pub authorization: String,
    /// EGF URI for the governance context.
    pub egf_uri: String,
    /// Start of the authorization period (RFC 3339), if bounded.
    pub effective_from: Option<String>,
    /// End of the authorization period (RFC 3339), if bounded.
    pub effective_until: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_writersproof_egf_has_three_roles() {
        let egf = writersproof_egf();
        assert_eq!(egf.roles.len(), 3);
        let names: Vec<&str> = egf.roles.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"attester"));
        assert!(names.contains(&"verifier"));
        assert!(names.contains(&"relying_party"));
    }

    #[test]
    fn test_writersproof_egf_has_three_assurance_levels() {
        let egf = writersproof_egf();
        assert_eq!(egf.assurance_levels.len(), 3);
        let names: Vec<&str> = egf
            .assurance_levels
            .iter()
            .map(|l| l.name.as_str())
            .collect();
        assert_eq!(
            names,
            vec!["software_only", "hardware_assisted", "hardware_bound"]
        );
    }

    #[test]
    fn test_egf_metadata_fields() {
        let egf = writersproof_egf();
        assert_eq!(egf.id, "urn:writersproof:egf:v1");
        assert_eq!(egf.version, "1.0");
        assert_eq!(egf.authority, "WritersLogic LLC");
        assert_eq!(egf.technical_spec, "draft-condrey-rats-pop");
    }

    #[test]
    fn test_egf_serde_roundtrip() {
        let egf = writersproof_egf();
        let json = serde_json::to_string(&egf).expect("serialize");
        let decoded: EcosystemGovernanceFramework =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(egf, decoded);
    }

    #[test]
    fn test_trqp_query_serde_roundtrip() {
        let query = TrqpQuery {
            registry_uri: "https://trust.writersproof.com/v2".to_string(),
            entity_did: "did:web:example.com".to_string(),
            authorization: "issue_attestation".to_string(),
            egf_uri: "urn:writersproof:egf:v1".to_string(),
        };
        let json = serde_json::to_string(&query).expect("serialize");
        let decoded: TrqpQuery = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(query, decoded);
    }

    #[test]
    fn test_trqp_response_authorized() {
        let resp = TrqpResponse {
            authorized: true,
            entity_did: "did:web:example.com".to_string(),
            authorization: "issue_attestation".to_string(),
            egf_uri: "urn:writersproof:egf:v1".to_string(),
            effective_from: Some("2026-01-01T00:00:00Z".to_string()),
            effective_until: None,
        };
        assert!(resp.authorized);
        assert!(resp.effective_until.is_none());
    }

    #[test]
    fn test_trqp_response_unauthorized() {
        let resp = TrqpResponse {
            authorized: false,
            entity_did: "did:web:revoked.com".to_string(),
            authorization: "issue_attestation".to_string(),
            egf_uri: "urn:writersproof:egf:v1".to_string(),
            effective_from: None,
            effective_until: Some("2025-12-31T23:59:59Z".to_string()),
        };
        assert!(!resp.authorized);
        assert!(resp.effective_from.is_none());
        assert!(resp.effective_until.is_some());
    }

    #[test]
    fn test_trqp_response_serde_roundtrip() {
        let resp = TrqpResponse {
            authorized: true,
            entity_did: "did:web:example.com".to_string(),
            authorization: "verify_attestation".to_string(),
            egf_uri: "urn:writersproof:egf:v1".to_string(),
            effective_from: Some("2026-01-01T00:00:00Z".to_string()),
            effective_until: Some("2027-01-01T00:00:00Z".to_string()),
        };
        let json = serde_json::to_string(&resp).expect("serialize");
        let decoded: TrqpResponse = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(resp, decoded);
    }

    #[test]
    fn test_assurance_level_requirements_non_empty() {
        let egf = writersproof_egf();
        for level in &egf.assurance_levels {
            assert!(
                !level.minimum_requirements.is_empty(),
                "assurance level '{}' should have requirements",
                level.name
            );
        }
    }

    #[test]
    fn test_role_requirements_non_empty() {
        let egf = writersproof_egf();
        for role in &egf.roles {
            assert!(
                !role.requirements.is_empty(),
                "role '{}' should have requirements",
                role.name
            );
        }
    }
}
