// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::error::{Error, Result};
use crate::rfc::{HashAlgorithm, HashValue};
use coset::{CborSerializable, CoseSign1Builder, HeaderBuilder};
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

pub fn hash_sha256(data: &[u8]) -> HashValue {
    let mut hasher = Sha256::new();
    hasher.update(data);
    HashValue {
        algorithm: HashAlgorithm::Sha256,
        digest: hasher.finalize().to_vec(),
    }
}

/// Length-prefixes fields to prevent concatenation ambiguity.
fn hmac_update_field(mac: &mut HmacSha256, data: &[u8]) {
    mac.update(&(data.len() as u32).to_be_bytes());
    mac.update(data);
}

/// Inputs are length-prefixed and domain-separated to prevent concatenation ambiguity.
pub fn compute_causality_lock(
    key: &[u8],
    prev_hash: &[u8],
    current_hash: &[u8],
) -> Result<HashValue> {
    compute_causality_lock_inner(key, b"causality_v1", prev_hash, current_hash, &[])
}

/// Binds physical entropy (jitter) to the content chain.
/// Inputs are length-prefixed and domain-separated.
pub fn compute_causality_lock_v2(
    key: &[u8],
    prev_hash: &[u8],
    current_hash: &[u8],
    phys_entropy: &[u8],
) -> Result<HashValue> {
    compute_causality_lock_inner(key, b"causality_v2", prev_hash, current_hash, phys_entropy)
}

fn compute_causality_lock_inner(
    key: &[u8],
    dst: &[u8],
    prev_hash: &[u8],
    current_hash: &[u8],
    phys_entropy: &[u8],
) -> Result<HashValue> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|e| Error::Crypto(format!("HMAC key error: {}", e)))?;

    mac.update(dst);
    hmac_update_field(&mut mac, prev_hash);
    hmac_update_field(&mut mac, current_hash);
    if !phys_entropy.is_empty() {
        hmac_update_field(&mut mac, phys_entropy);
    }

    Ok(HashValue {
        algorithm: HashAlgorithm::Sha256,
        digest: mac.finalize().into_bytes().to_vec(),
    })
}

/// Abstraction over signing backends (Ed25519 software key, TPM).
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

pub fn sign_evidence_cose(payload: &[u8], signer: &dyn PoPSigner) -> Result<Vec<u8>> {
    let protected = HeaderBuilder::new().algorithm(signer.algorithm()).build();

    let mut sign_error: Option<Error> = None;
    let sign1 = CoseSign1Builder::new()
        .protected(protected)
        .payload(payload.to_vec())
        .create_signature(&[], |sig_data| match signer.sign(sig_data) {
            Ok(sig) => sig,
            Err(e) => {
                sign_error = Some(e);
                Vec::new()
            }
        })
        .build();

    if let Some(e) = sign_error {
        return Err(e);
    }

    // Empty signature indicates a signing failure not captured by the error path
    if sign1.signature.is_empty() {
        return Err(Error::Crypto(
            "COSE signing produced empty signature".to_string(),
        ));
    }

    sign1
        .to_vec()
        .map_err(|e| Error::Crypto(format!("COSE encoding error: {}", e)))
}

pub fn verify_evidence_cose(cose_data: &[u8], verifying_key: &VerifyingKey) -> Result<Vec<u8>> {
    let sign1 = coset::CoseSign1::from_slice(cose_data)
        .map_err(|e| Error::Crypto(format!("COSE decoding error: {}", e)))?;

    sign1.verify_signature(&[], |sig, sig_data| {
        let signature = Signature::from_slice(sig)
            .map_err(|e| Error::Crypto(format!("Invalid signature format: {}", e)))?;
        verifying_key
            .verify(sig_data, &signature)
            .map_err(|e| Error::Crypto(format!("Signature verification failed: {}", e)))
    })?;

    sign1
        .payload
        .ok_or_else(|| Error::Crypto("Missing payload in COSE_Sign1".to_string()))
}
