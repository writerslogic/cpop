// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use chrono::Utc;
use serde::Serialize;

/// DIF Well Known DID Configuration context URI.
const DID_CONFIGURATION_CONTEXT: &str =
    "https://identity.foundation/.well-known/did-configuration/v1";

/// W3C Verifiable Credentials context URI.
const VC_CONTEXT: &str = "https://www.w3.org/2018/credentials/v1";

/// DIF Well Known DID Configuration.
///
/// Generates `/.well-known/did-configuration.json` linking a domain to a DID
/// per the DIF specification.
#[derive(Debug, Clone, Serialize)]
pub struct DidConfiguration {
    #[serde(rename = "@context")]
    pub context: String,
    pub linked_dids: Vec<DomainLinkageCredential>,
}

/// A Domain Linkage Credential binding a DID to an origin.
#[derive(Debug, Clone, Serialize)]
pub struct DomainLinkageCredential {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    #[serde(rename = "type")]
    pub vc_type: Vec<String>,
    pub issuer: String,
    #[serde(rename = "issuanceDate")]
    pub issuance_date: String,
    #[serde(rename = "credentialSubject")]
    pub credential_subject: DomainLinkageSubject,
}

/// Subject of a Domain Linkage Credential.
#[derive(Debug, Clone, Serialize)]
pub struct DomainLinkageSubject {
    pub id: String,
    pub origin: String,
}

/// Generate a DIF Well Known DID Configuration linking a domain to a DID.
///
/// The returned structure can be serialized to JSON and served at
/// `/.well-known/did-configuration.json` on the given domain.
pub fn generate_did_configuration(did: &str, domain: &str) -> DidConfiguration {
    let credential = DomainLinkageCredential {
        context: vec![
            VC_CONTEXT.to_string(),
            DID_CONFIGURATION_CONTEXT.to_string(),
        ],
        vc_type: vec![
            "VerifiableCredential".to_string(),
            "DomainLinkageCredential".to_string(),
        ],
        issuer: did.to_string(),
        issuance_date: Utc::now().to_rfc3339(),
        credential_subject: DomainLinkageSubject {
            id: did.to_string(),
            origin: domain.to_string(),
        },
    };

    DidConfiguration {
        context: DID_CONFIGURATION_CONTEXT.to_string(),
        linked_dids: vec![credential],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_did_configuration_structure() {
        let did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        let domain = "https://writerslogic.com";

        let config = generate_did_configuration(did, domain);

        assert_eq!(config.context, DID_CONFIGURATION_CONTEXT);
        assert_eq!(config.linked_dids.len(), 1);

        let cred = &config.linked_dids[0];
        assert_eq!(cred.context.len(), 2);
        assert_eq!(cred.context[0], VC_CONTEXT);
        assert_eq!(cred.context[1], DID_CONFIGURATION_CONTEXT);
        assert_eq!(cred.vc_type[0], "VerifiableCredential");
        assert_eq!(cred.vc_type[1], "DomainLinkageCredential");
        assert_eq!(cred.issuer, did);
        assert!(!cred.issuance_date.is_empty());
        assert_eq!(cred.credential_subject.id, did);
        assert_eq!(cred.credential_subject.origin, domain);

        // Verify JSON serialization round-trips key fields.
        let json = serde_json::to_value(&config).expect("serializes");
        assert_eq!(json["@context"], DID_CONFIGURATION_CONTEXT);
        assert_eq!(json["linked_dids"][0]["issuer"], did);
    }
}
