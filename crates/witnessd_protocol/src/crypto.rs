// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use crate::rfc::{HashValue, HashAlgorithm};
use crate::error::{Error, Result};
use coset::{CoseSign1Builder, HeaderBuilder, CborSerializable};

type HmacSha256 = Hmac<Sha256>;

/// Computes the SHA-256 hash of the given data.
pub fn hash_sha256(data: &[u8]) -> HashValue {
    let mut hasher = Sha256::new();
    hasher.update(data);
    HashValue {
        algorithm: HashAlgorithm::Sha256,
        digest: hasher.finalize().to_vec(),
    }
}

/// Computes the HMAC-SHA256 for the causality lock.
pub fn compute_causality_lock(key: &[u8], prev_hash: &[u8], current_hash: &[u8]) -> Result<HashValue> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|e| Error::Crypto(format!("HMAC key error: {}", e)))?;
    
    mac.update(prev_hash);
    mac.update(current_hash);
    
    Ok(HashValue {
        algorithm: HashAlgorithm::Sha256,
        digest: mac.finalize().into_bytes().to_vec(),
    })
}

/// Advanced causality lock that binds physical entropy (jitter) to the content chain.
pub fn compute_causality_lock_v2(
    key: &[u8], 
    prev_hash: &[u8], 
    current_hash: &[u8],
    phys_entropy: &[u8]
) -> Result<HashValue> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|e| Error::Crypto(format!("HMAC key error: {}", e)))?;
    
    mac.update(prev_hash);
    mac.update(current_hash);
    mac.update(phys_entropy);
    
    Ok(HashValue {
        algorithm: HashAlgorithm::Sha256,
        digest: mac.finalize().into_bytes().to_vec(),
    })
}

/// Abstract signer trait to support both software keys and hardware tokens (TPM/Secure Enclave).
pub trait PoPSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>>;
    fn algorithm(&self) -> coset::iana::Algorithm;
    fn public_key(&self) -> Vec<u8>;
}

impl PoPSigner for SigningKey {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(ed25519_dalek::Signer::sign(self, data).to_bytes().to_vec())
    }

    fn algorithm(&self) -> coset::iana::Algorithm {
        coset::iana::Algorithm::EdDSA
    }

    fn public_key(&self) -> Vec<u8> {
        self.verifying_key().to_bytes().to_vec()
    }
}

/// Signs a CBOR-encoded Evidence Packet using COSE_Sign1.
/// 
/// This is a stub for hardware-backed signing (TPM/Secure Enclave).
pub fn sign_evidence_cose(payload: &[u8], signer: &dyn PoPSigner) -> Result<Vec<u8>> {
    // Construct the protected header
    let protected = HeaderBuilder::new()
        .algorithm(signer.algorithm())
        .build();

    // Construct the COSE_Sign1 structure
    let sign1 = CoseSign1Builder::new()
        .protected(protected)
        .payload(payload.to_vec())
        .create_signature(&[], |sig_data| {
            signer.sign(sig_data).unwrap_or_default()
        })
        .build();

    sign1.to_vec()
        .map_err(|e| Error::Crypto(format!("COSE encoding error: {}", e)))
}

/// Verifies a COSE_Sign1 Evidence Packet.
pub fn verify_evidence_cose(cose_data: &[u8], verifying_key: &VerifyingKey) -> Result<Vec<u8>> {
    let sign1 = coset::CoseSign1::from_slice(cose_data)
        .map_err(|e| Error::Crypto(format!("COSE decoding error: {}", e)))?;

    sign1.verify_signature(&[], |sig, sig_data| {
        let signature = Signature::from_slice(sig)
            .map_err(|e| Error::Crypto(format!("Invalid signature format: {}", e)))?;
        verifying_key.verify(sig_data, &signature)
            .map_err(|e| Error::Crypto(format!("Signature verification failed: {}", e)))
    })?;

    sign1.payload.ok_or_else(|| Error::Crypto("Missing payload in COSE_Sign1".to_string()))
}
