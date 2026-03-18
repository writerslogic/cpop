// SPDX-License-Identifier: Apache-2.0

//! W3C Verifiable Credential profile — projects an EAR token into a VC 2.0.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::war::ear::{Ar4siStatus, EarToken};

type Result<T> = std::result::Result<T, String>;

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
    pub trust_vector: Option<TrustVectorVc>,
    #[serde(rename = "documentRef", skip_serializing_if = "Option::is_none")]
    pub document_ref: Option<String>,
    #[serde(rename = "chainDuration", skip_serializing_if = "Option::is_none")]
    pub chain_duration: Option<String>,
    #[serde(rename = "attestationTier", skip_serializing_if = "Option::is_none")]
    pub attestation_tier: Option<String>,
}

/// Trust vector in VC JSON-LD format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustVectorVc {
    pub instance_identity: i8,
    pub configuration: i8,
    pub executables: i8,
    pub file_system: i8,
    pub hardware: i8,
    pub runtime_opaque: i8,
    pub storage_opaque: i8,
    pub sourced_data: i8,
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

/// Produce a W3C Verifiable Credential 2.0 from an EAR token.
pub fn to_verifiable_credential(ear: &EarToken, author_did: &str) -> Result<VerifiableCredential> {
    let appr = ear
        .pop_appraisal()
        .ok_or_else(|| "EAR token missing 'pop' submodule".to_string())?;

    let tv_vc = appr
        .ear_trustworthiness_vector
        .as_ref()
        .map(|tv| TrustVectorVc {
            instance_identity: tv.instance_identity,
            configuration: tv.configuration,
            executables: tv.executables,
            file_system: tv.file_system,
            hardware: tv.hardware,
            runtime_opaque: tv.runtime_opaque,
            storage_opaque: tv.storage_opaque,
            sourced_data: tv.sourced_data,
        });

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
            if tv.hardware >= Ar4siStatus::Affirming as i8 {
                "hardware_bound"
            } else if tv.hardware >= Ar4siStatus::Warning as i8 {
                "attested_software"
            } else {
                "software_only"
            }
        })
        .map(String::from);

    let valid_from: DateTime<Utc> = DateTime::from_timestamp(ear.iat, 0).unwrap_or_else(Utc::now);

    let seal_hash = appr.pop_seal.as_ref().map(|s| hex::encode(s.h3));

    let evidence = vec![VcEvidence {
        evidence_type: "ProofOfProcessEvidence".to_string(),
        verifier: ear.ear_verifier_id.build.clone(),
        seal_hash,
    }];

    // Proof placeholder — actual signing happens at a higher layer
    let proof = VcProof {
        proof_type: "DataIntegrityProof".to_string(),
        cryptosuite: "eddsa-rdfc-2022".to_string(),
        verification_method: format!("{}#key-1", author_did),
        proof_purpose: "assertionMethod".to_string(),
        proof_value: String::new(),
    };

    Ok(VerifiableCredential {
        context: vec![
            "https://www.w3.org/ns/credentials/v2".to_string(),
            "https://writerslogic.com/ns/pop/v1".to_string(),
        ],
        vc_type: vec![
            "VerifiableCredential".to_string(),
            "ProcessAttestationCredential".to_string(),
        ],
        issuer: "did:web:writerslogic.com".to_string(),
        valid_from: valid_from.to_rfc3339(),
        credential_subject: CredentialSubject {
            id: author_did.to_string(),
            subject_type: "Author".to_string(),
            process_attestation: ProcessAttestation {
                status: appr.ear_status.as_str().to_string(),
                trust_vector: tv_vc,
                document_ref,
                chain_duration,
                attestation_tier: tier_str,
            },
        },
        evidence: Some(evidence),
        proof: Some(proof),
    })
}
