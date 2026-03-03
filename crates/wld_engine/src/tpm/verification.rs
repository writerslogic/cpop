// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::{Binding, Quote, TPMError};
use ed25519_dalek::Verifier as _;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs8::DecodePublicKey;

pub fn verify_binding_chain(
    bindings: &[Binding],
    trusted_keys: &[Vec<u8>],
) -> Result<(), TPMError> {
    if bindings.is_empty() {
        return Ok(());
    }

    let mut last_counter: Option<u64> = None;
    for (idx, binding) in bindings.iter().enumerate() {
        if let Some(prev) = last_counter {
            if let Some(counter) = binding.monotonic_counter {
                if counter <= prev {
                    return Err(TPMError::CounterRollback);
                }
            }
        }

        verify_binding_with_trusted(binding, trusted_keys)
            .map_err(|_| TPMError::Verification(format!("binding {} failed", idx)))?;

        last_counter = binding.monotonic_counter;
    }

    Ok(())
}

pub fn verify_binding(binding: &Binding) -> Result<(), TPMError> {
    verify_binding_with_trusted(binding, &[])
}

fn verify_binding_with_trusted(
    binding: &Binding,
    trusted_keys: &[Vec<u8>],
) -> Result<(), TPMError> {
    if binding.attested_hash.len() != 32 {
        return Err(TPMError::InvalidBinding);
    }

    if binding.safe_clock == Some(false) {
        return Err(TPMError::ClockNotSafe);
    }

    let payload = binding_payload(binding);

    if binding.provider_type == "software" {
        return verify_signature(&binding.public_key, &payload, &binding.signature);
    }

    if !binding.public_key.is_empty() {
        return verify_signature(&binding.public_key, &payload, &binding.signature);
    }

    if !trusted_keys.is_empty() {
        for key in trusted_keys {
            if verify_signature(key, &payload, &binding.signature).is_ok() {
                return Ok(());
            }
        }
        return Err(TPMError::Verification(
            "signature did not match trusted keys".into(),
        ));
    }

    Err(TPMError::InvalidSignature)
}

fn binding_payload(binding: &Binding) -> Vec<u8> {
    super::build_binding_payload(
        &binding.attested_hash,
        &binding.timestamp,
        &binding.device_id,
    )
}

pub fn verify_quote(quote: &Quote) -> Result<(), TPMError> {
    if quote.attested_data.is_empty() {
        return Err(TPMError::Quote("empty quote payload".into()));
    }
    if quote.signature.is_empty() {
        return Err(TPMError::InvalidSignature);
    }

    if quote.provider_type == "software" {
        return verify_signature(&quote.public_key, &quote.attested_data, &quote.signature);
    }

    if quote.public_key.is_empty() {
        return Err(TPMError::InvalidSignature);
    }

    verify_signature(&quote.public_key, &quote.attested_data, &quote.signature)
}

fn verify_signature(public_key: &[u8], payload: &[u8], signature: &[u8]) -> Result<(), TPMError> {
    // Try Ed25519 (32-byte raw public key)
    if public_key.len() == 32 && signature.len() == 64 {
        if let Ok(key_bytes) = <[u8; 32]>::try_from(public_key) {
            if let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes) {
                if let Ok(sig_bytes) = <[u8; 64]>::try_from(signature) {
                    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
                    return vk
                        .verify(payload, &sig)
                        .map_err(|_| TPMError::InvalidSignature);
                }
            }
        }
    }

    // Try RSA (DER-encoded public key)
    if let Ok(key) = rsa::RsaPublicKey::from_pkcs1_der(public_key)
        .or_else(|_| rsa::RsaPublicKey::from_public_key_der(public_key))
    {
        let verifying_key = rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new_unprefixed(key);
        let sig = rsa::pkcs1v15::Signature::try_from(signature)
            .map_err(|_| TPMError::InvalidSignature)?;
        return verifying_key
            .verify(payload, &sig)
            .map_err(|_| TPMError::InvalidSignature);
    }

    Err(TPMError::UnsupportedPublicKey)
}
