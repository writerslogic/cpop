// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::error::{Error, Result};
use ed25519_dalek::{SigningKey, VerifyingKey, Signer};
use x509_cert::builder::{Builder, RequestBuilder};
use x509_cert::name::Name;
use x509_cert::ext::pkix::SubjectKeyIdentifier;
use x509_cert::der::asn1::{OctetString, BitString};
use x509_cert::der::{Encode, Tag, FixedTag};
use spki::{AlgorithmIdentifierOwned, ObjectIdentifier, SubjectPublicKeyInfoOwned, EncodePublicKey, SignatureBitStringEncoding, DynSignatureAlgorithmIdentifier};
use const_oid::AssociatedOid;
use signature::Keypair;
use x509_cert::ext::{AsExtension, Extension};
use std::str::FromStr;
use rand::RngCore;
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};

/// Wrapper for VerifyingKey to implement required traits for x509-cert builder.
#[derive(Clone, Debug)]
pub struct PoPVerifyingKey(pub VerifyingKey);

impl EncodePublicKey for PoPVerifyingKey {
    fn to_public_key_der(&self) -> spki::Result<spki::der::Document> {
        let spki = SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: ObjectIdentifier::new_unwrap("1.3.101.112"), // Ed25519
                parameters: None,
            },
            subject_public_key: BitString::from_bytes(self.0.as_bytes())?,
        };
        let der = spki.to_der().map_err(|_| spki::Error::KeyMalformed)?;
        spki::der::Document::try_from(der.as_slice())
            .map_err(|_| spki::Error::KeyMalformed)
    }
}

/// Wrapper for SigningKey to implement required traits for x509-cert builder.
pub struct PoPSigner(pub SigningKey);

impl Keypair for PoPSigner {
    type VerifyingKey = PoPVerifyingKey;
    fn verifying_key(&self) -> Self::VerifyingKey {
        PoPVerifyingKey(self.0.verifying_key())
    }
}

impl DynSignatureAlgorithmIdentifier for PoPSigner {
    fn signature_algorithm_identifier(&self) -> spki::Result<AlgorithmIdentifierOwned> {
        Ok(AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("1.3.101.112"), // Ed25519
            parameters: None,
        })
    }
}

/// We need a local signature type to implement SignatureBitStringEncoding due to orphan rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoPSignature(pub ed25519_dalek::Signature);

impl signature::SignatureEncoding for PoPSignature {
    type Repr = [u8; 64];
    fn to_bytes(&self) -> Self::Repr {
        self.0.to_bytes()
    }
}

impl TryFrom<&[u8]> for PoPSignature {
    type Error = signature::Error;
    fn try_from(bytes: &[u8]) -> std::result::Result<Self, Self::Error> {
        ed25519_dalek::Signature::from_slice(bytes)
            .map(PoPSignature)
            .map_err(|_| signature::Error::new())
    }
}

impl From<PoPSignature> for [u8; 64] {
    fn from(sig: PoPSignature) -> Self {
        sig.0.to_bytes()
    }
}

impl Signer<PoPSignature> for PoPSigner {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<PoPSignature, signature::Error> {
        Ok(PoPSignature(self.0.sign(msg)))
    }
}

impl SignatureBitStringEncoding for PoPSignature {
    fn to_bitstring(&self) -> std::result::Result<BitString, x509_cert::der::Error> {
        BitString::from_bytes(&self.0.to_bytes())
    }
}

/// Custom extension for PoP Capability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoPCapability(pub OctetString);

impl AssociatedOid for PoPCapability {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.54066.1.1");
}

impl Encode for PoPCapability {
    fn encoded_len(&self) -> x509_cert::der::Result<x509_cert::der::Length> {
        self.0.encoded_len()
    }
    fn encode(&self, encoder: &mut impl x509_cert::der::Writer) -> x509_cert::der::Result<()> {
        self.0.encode(encoder)
    }
}

impl FixedTag for PoPCapability {
    const TAG: Tag = Tag::OctetString;
}

impl AsExtension for PoPCapability {
    fn critical(&self, _: &x509_cert::name::RdnSequence, _: &[Extension]) -> bool {
        false
    }
}

/// Enrollment Request for the WritersLogic platform.
#[derive(Debug, Serialize, Deserialize)]
pub struct EnrollmentRequest {
    pub user_id: String,
    pub public_key_cose: Vec<u8>,
    pub hardware_attestation: Vec<u8>,
}

/// Manager for PoP Identities and cryptographic keys.
pub struct IdentityManager {
    signer: PoPSigner,
}

impl IdentityManager {
    /// Generates a new identity with a random Ed25519 key pair.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self {
            signer: PoPSigner(SigningKey::from_bytes(&bytes)),
        }
    }

    /// Loads an identity from a secret key.
    pub fn from_secret_key(bytes: &[u8; 32]) -> Self {
        Self {
            signer: PoPSigner(SigningKey::from_bytes(bytes)),
        }
    }

    /// Returns the signing key for this identity.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signer.0
    }

    /// Generates a Certificate Signing Request (CSR) for this identity.
    pub fn generate_csr(&self, subject_dn: &str) -> Result<Vec<u8>> {
        let subject = Name::from_str(subject_dn)
            .map_err(|e| Error::Validation(format!("Invalid Subject DN: {}", e)))?;

        let mut builder = RequestBuilder::new(subject, &self.signer)
            .map_err(|e| Error::Crypto(format!("CSR builder error: {}", e)))?;

        // Add Subject Key Identifier extension
        let public_key_bytes = self.signer.0.verifying_key().to_bytes();
        let hash = Sha256::digest(&public_key_bytes);
        let ski = SubjectKeyIdentifier(
            OctetString::new(hash.to_vec())
                .map_err(|e| Error::Crypto(format!("Failed to create OctetString: {}", e)))?
        );
        builder.add_extension(&ski)
            .map_err(|e| Error::Crypto(format!("Failed to add SKI extension: {}", e)))?;

        // PoP Capability Extension
        let pop_cap = PoPCapability(
            OctetString::new(vec![0x01])
                .map_err(|e| Error::Crypto(e.to_string()))?
        );
        builder.add_extension(&pop_cap)
            .map_err(|e| Error::Crypto(format!("Failed to add PoP extension: {}", e)))?;

        let csr = builder.build::<PoPSignature>().map_err(|e| Error::Crypto(format!("CSR signing error: {}", e)))?;

        csr.to_der().map_err(|e| Error::Crypto(format!("DER encoding error: {}", e)))
    }

    /// Constructs an EnrollmentRequest for the WritersLogic platform.
    pub fn create_enrollment_request(&self, user_id: &str) -> Result<EnrollmentRequest> {
        // In a real implementation, public_key_cose would be a COSE_Key structure.
        let public_key_cose = self.signer.0.verifying_key().to_bytes().to_vec();
        
        // hardware_attestation would be a blob from TPM or Apple Secure Enclave.
        let hardware_attestation = b"STUB_HARDWARE_ATTESTATION".to_vec();

        Ok(EnrollmentRequest {
            user_id: user_id.to_string(),
            public_key_cose,
            hardware_attestation,
        })
    }
}
