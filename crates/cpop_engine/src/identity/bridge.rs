// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::orcid::OrcidIdentity;
use serde::Serialize;

/// How the CPOP identity bridges to C2PA/CAWG ecosystems.
///
/// C2PA requires X.509 certs. CAWG v1.2 supports X.509 and Identity Claims
/// Aggregators (ICA). CPOP uses `did:key` (self-sovereign Ed25519). These do
/// not directly interoperate, so the bridge resolves the gap.
///
/// - `IdentityClaimsAggregator`: WritersProof acts as an ICA per CAWG spec.
///   The author authenticates with `did:key`, WritersProof issues an ICA
///   credential wrapping the DID, usable in CAWG identity assertions.
/// - `DidWebWithX509`: `did:web` with an X.509 certificate binding for users
///   who need C2PA conformance without an ICA (self-hosted).
/// - `SelfSovereign`: Direct `did:key` with no CAWG compatibility; uses a
///   custom assertion type only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum IdentityBridgeMode {
    /// WritersProof ICA wraps did:key for CAWG.
    IdentityClaimsAggregator,
    /// did:web with X.509 certificate binding (self-hosted).
    DidWebWithX509,
    /// Direct did:key, no CAWG compatibility (custom assertion only).
    SelfSovereign,
}

/// An identity bridged across DID, C2PA/CAWG, and optionally ORCID.
#[derive(Debug, Clone, Serialize)]
pub struct BridgedIdentity {
    pub mode: IdentityBridgeMode,
    /// The author's DID (e.g. `did:key:z6Mk...`).
    pub author_did: String,
    /// For ICA mode: the ICA credential issued by WritersProof.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ica_credential: Option<serde_json::Value>,
    /// For did:web mode: the X.509 certificate in PEM format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x509_pem: Option<String>,
    /// Linked ORCID identity, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub orcid: Option<OrcidIdentity>,
}

impl BridgedIdentity {
    /// Create a self-sovereign identity (did:key only, no CAWG bridge).
    pub fn self_sovereign(did: &str) -> Self {
        Self {
            mode: IdentityBridgeMode::SelfSovereign,
            author_did: did.to_string(),
            ica_credential: None,
            x509_pem: None,
            orcid: None,
        }
    }

    /// Create an ICA-bridged identity.
    pub fn with_ica(did: &str, ica_credential: serde_json::Value) -> Self {
        Self {
            mode: IdentityBridgeMode::IdentityClaimsAggregator,
            author_did: did.to_string(),
            ica_credential: Some(ica_credential),
            x509_pem: None,
            orcid: None,
        }
    }

    /// Create a did:web identity with X.509 binding.
    pub fn with_x509(did: &str, x509_pem: String) -> Self {
        Self {
            mode: IdentityBridgeMode::DidWebWithX509,
            author_did: did.to_string(),
            ica_credential: None,
            x509_pem: Some(x509_pem),
            orcid: None,
        }
    }

    /// Attach an ORCID identity.
    pub fn with_orcid(mut self, orcid: OrcidIdentity) -> Self {
        self.orcid = Some(orcid);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_bridge_modes() {
        let did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

        // Self-sovereign mode.
        let ss = BridgedIdentity::self_sovereign(did);
        assert_eq!(ss.mode, IdentityBridgeMode::SelfSovereign);
        assert_eq!(ss.author_did, did);
        assert!(ss.ica_credential.is_none());
        assert!(ss.x509_pem.is_none());
        assert!(ss.orcid.is_none());

        // ICA mode.
        let cred = serde_json::json!({"type": "IdentityClaimsAggregation", "holder": did});
        let ica = BridgedIdentity::with_ica(did, cred.clone());
        assert_eq!(ica.mode, IdentityBridgeMode::IdentityClaimsAggregator);
        assert_eq!(ica.ica_credential.as_ref().unwrap()["holder"], did);

        // did:web + X.509 mode.
        let x509 = BridgedIdentity::with_x509(
            "did:web:writerslogic.com",
            "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----".to_string(),
        );
        assert_eq!(x509.mode, IdentityBridgeMode::DidWebWithX509);
        assert!(x509.x509_pem.is_some());

        // ORCID attachment.
        let orcid = OrcidIdentity {
            orcid_id: "0000-0002-1694-233X".to_string(),
            display_name: Some("Jane Doe".to_string()),
            verified: true,
        };
        let with_orcid = BridgedIdentity::self_sovereign(did).with_orcid(orcid);
        assert!(with_orcid.orcid.is_some());
        assert_eq!(
            with_orcid.orcid.as_ref().unwrap().orcid_id,
            "0000-0002-1694-233X"
        );
    }
}
