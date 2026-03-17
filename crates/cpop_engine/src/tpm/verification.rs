// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::{Binding, Quote, TpmError};
use ed25519_dalek::Verifier as _;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs8::DecodePublicKey;

pub fn verify_binding_chain(
    bindings: &[Binding],
    trusted_keys: &[Vec<u8>],
) -> Result<(), TpmError> {
    if bindings.is_empty() {
        return Ok(());
    }

    let mut last_counter: Option<u64> = None;
    for (idx, binding) in bindings.iter().enumerate() {
        if let Some(prev) = last_counter {
            if let Some(counter) = binding.monotonic_counter {
                if counter <= prev {
                    return Err(TpmError::CounterRollback);
                }
            }
        }

        verify_binding_with_trusted(binding, trusted_keys)
            .map_err(|_| TpmError::Verification(format!("binding {} failed", idx)))?;

        last_counter = binding.monotonic_counter;
    }

    Ok(())
}

pub fn verify_binding(binding: &Binding) -> Result<(), TpmError> {
    verify_binding_with_trusted(binding, &[])
}

fn verify_binding_with_trusted(
    binding: &Binding,
    trusted_keys: &[Vec<u8>],
) -> Result<(), TpmError> {
    if binding.attested_hash.len() != 32 {
        return Err(TpmError::InvalidBinding);
    }

    if binding.safe_clock == Some(false) {
        return Err(TpmError::ClockNotSafe);
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
        return Err(TpmError::Verification(
            "signature did not match trusted keys".into(),
        ));
    }

    Err(TpmError::InvalidSignature)
}

fn binding_payload(binding: &Binding) -> Vec<u8> {
    super::build_binding_payload(
        &binding.attested_hash,
        &binding.timestamp,
        &binding.device_id,
    )
}

pub fn verify_quote(quote: &Quote) -> Result<(), TpmError> {
    if quote.attested_data.is_empty() {
        return Err(TpmError::Quote("empty quote payload".into()));
    }
    if quote.signature.is_empty() {
        return Err(TpmError::InvalidSignature);
    }

    if quote.provider_type == "software" {
        return verify_signature(&quote.public_key, &quote.attested_data, &quote.signature);
    }

    if quote.public_key.is_empty() {
        return Err(TpmError::InvalidSignature);
    }

    verify_signature(&quote.public_key, &quote.attested_data, &quote.signature)
}

fn verify_signature(public_key: &[u8], payload: &[u8], signature: &[u8]) -> Result<(), TpmError> {
    try_verify_ed25519(public_key, payload, signature)
        .or_else(|| try_verify_ecdsa_p256(public_key, payload, signature))
        .or_else(|| try_verify_rsa(public_key, payload, signature))
        .unwrap_or(Err(TpmError::UnsupportedPublicKey))
}

fn try_verify_ed25519(
    public_key: &[u8],
    payload: &[u8],
    signature: &[u8],
) -> Option<Result<(), TpmError>> {
    let key_bytes: [u8; 32] = public_key.try_into().ok()?;
    let sig_bytes: [u8; 64] = signature.try_into().ok()?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes).ok()?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    Some(
        vk.verify(payload, &sig)
            .map_err(|_| TpmError::InvalidSignature),
    )
}

fn try_verify_ecdsa_p256(
    public_key: &[u8],
    payload: &[u8],
    signature: &[u8],
) -> Option<Result<(), TpmError>> {
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key).ok()?;
    // Raw r||s (64 bytes)
    if signature.len() == 64 {
        let sig = p256::ecdsa::Signature::from_slice(signature).ok()?;
        return Some(
            vk.verify(payload, &sig)
                .map_err(|_| TpmError::InvalidSignature),
        );
    }
    // DER-encoded
    let der_sig = p256::ecdsa::DerSignature::from_bytes(signature).ok()?;
    Some(
        vk.verify(payload, &der_sig)
            .map_err(|_| TpmError::InvalidSignature),
    )
}

fn try_verify_rsa(
    public_key: &[u8],
    payload: &[u8],
    signature: &[u8],
) -> Option<Result<(), TpmError>> {
    let key = rsa::RsaPublicKey::from_pkcs1_der(public_key)
        .or_else(|_| rsa::RsaPublicKey::from_public_key_der(public_key))
        .ok()?;
    let verifying_key = rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new_unprefixed(key);
    let sig = rsa::pkcs1v15::Signature::try_from(signature).ok()?;
    Some(
        verifying_key
            .verify(payload, &sig)
            .map_err(|_| TpmError::InvalidSignature),
    )
}
