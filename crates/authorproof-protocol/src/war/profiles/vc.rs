// SPDX-License-Identifier: Apache-2.0

//! W3C Verifiable Credential profile — projects an EAR token into a VC 2.0.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

type Result<T> = std::result::Result<T, String>;
use crate::war::ear::{Ar4siStatus, EarToken, TrustVectorProjection};

/// W3C Verifiable Credential 2.0 structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiableCredential {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    #[serde(rename = "type")]
    pub vc_type: Vec<String>,
    pub issuer: String,
    #[serde(rename = "validFrom")]
    pub valid_from: String,
    #[serde(rename = "credentialSubject")]
    pub credential_subject: CredentialSubject,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Vec<VcEvidence>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<VcProof>,
}

/// The credential subject — the author and their attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSubject {
    pub id: String,
    #[serde(rename = "type")]
    pub subject_type: String,
    #[serde(rename = "processAttestation")]
    pub process_attestation: ProcessAttestation,
}

/// Process attestation claims embedded in the credential subject.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessAttestation {
    pub status: String,
    #[serde(rename = "trustVector", skip_serializing_if = "Option::is_none")]
    pub trust_vector: Option<TrustVectorProjection>,
    #[serde(rename = "documentRef", skip_serializing_if = "Option::is_none")]
    pub document_ref: Option<String>,
    #[serde(rename = "chainDuration", skip_serializing_if = "Option::is_none")]
    pub chain_duration: Option<String>,
    #[serde(rename = "attestationTier", skip_serializing_if = "Option::is_none")]
    pub attestation_tier: Option<String>,
}

/// Evidence entry in the VC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VcEvidence {
    #[serde(rename = "type")]
    pub evidence_type: String,
    pub verifier: String,
    #[serde(rename = "sealHash", skip_serializing_if = "Option::is_none")]
    pub seal_hash: Option<String>,
}

/// Data integrity proof on the VC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VcProof {
    #[serde(rename = "type")]
    pub proof_type: String,
    pub cryptosuite: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,
    #[serde(rename = "proofValue")]
    pub proof_value: String,
}

/// Default issuer DID used when none is provided.
pub const DEFAULT_ISSUER: &str = "did:web:writerslogic.com";

/// Produce a W3C Verifiable Credential 2.0 from an EAR token.
///
/// `issuer` overrides the credential issuer DID; defaults to [`DEFAULT_ISSUER`].
pub fn to_verifiable_credential(
    ear: &EarToken,
    author_did: &str,
    issuer: Option<&str>,
) -> Result<VerifiableCredential> {
    let appr = ear
        .pop_appraisal()
        .ok_or_else(|| String::from("EAR token missing 'pop' submodule"))?;

    let tv_vc = appr
        .ear_trustworthiness_vector
        .as_ref()
        .map(TrustVectorProjection::from);

    let document_ref = appr.pop_evidence_ref.as_ref().map(hex::encode);

    let chain_duration = appr.pop_chain_duration.map(|secs| {
        let hours = secs / 3600;
        let minutes = (secs % 3600) / 60;
        let remaining_secs = secs % 60;
        if hours > 0 {
            format!("PT{}H{}M{}S", hours, minutes, remaining_secs)
        } else if minutes > 0 {
            format!("PT{}M{}S", minutes, remaining_secs)
        } else {
            format!("PT{}S", remaining_secs)
        }
    });

    let tier_str = appr
        .ear_trustworthiness_vector
        .as_ref()
        .map(|tv| {
            // Normalize through from_i8 so non-standard values (3-31)
            // are treated as Contraindicated, not Affirming.
            match Ar4siStatus::from_i8(tv.hardware) {
                Ar4siStatus::Affirming => "hardware_bound",
                Ar4siStatus::Warning => "attested_software",
                _ => "software_only",
            }
        })
        .map(String::from);

    let valid_from: DateTime<Utc> = DateTime::from_timestamp(ear.iat, 0)
        .ok_or_else(|| format!("invalid EAR issued-at timestamp: {}", ear.iat))?;
    let now = Utc::now();
    if valid_from > now + chrono::Duration::hours(24) {
        return Err(format!("EAR issued-at is >24h in the future: {}", ear.iat));
    }

    let seal_hash = appr.pop_seal.as_ref().map(|s| hex::encode(s.h3));

    let evidence = vec![VcEvidence {
        evidence_type: "ProofOfProcessEvidence".to_string(),
        verifier: ear.ear_verifier_id.build.clone(),
        seal_hash,
    }];

    // Proof is None until the signing layer adds it. Emitting an empty
    // proofValue would be invalid per the W3C Data Integrity spec.

    Ok(VerifiableCredential {
        context: vec![
            "https://www.w3.org/ns/credentials/v2".to_string(),
            "https://writerslogic.com/ns/pop/v1".to_string(),
        ],
        vc_type: vec![
            "VerifiableCredential".to_string(),
            "ProcessAttestationCredential".to_string(),
        ],
        issuer: issuer.unwrap_or(DEFAULT_ISSUER).to_string(),
        valid_from: valid_from.to_rfc3339(),
        credential_subject: CredentialSubject {
            id: author_did.to_string(),
            subject_type: "Author".to_string(),
            process_attestation: ProcessAttestation {
                status: appr.ear_status.as_str().to_owned(),
                trust_vector: tv_vc,
                document_ref,
                chain_duration,
                attestation_tier: tier_str,
            },
        },
        evidence: Some(evidence),
        proof: None,
    })
}
