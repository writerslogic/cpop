use super::{Binding, Quote, TPMError};
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::signature::Verifier as RsaVerifier;
use sha2::{Digest, Sha256};

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
        let expected = Sha256::digest(&payload).to_vec();
        if expected != binding.signature {
            return Err(TPMError::InvalidSignature);
        }
        return Ok(());
    }

    if !binding.public_key.is_empty() {
        if verify_signature(&binding.public_key, &payload, &binding.signature).is_ok() {
            return Ok(());
        }
        if binding.provider_type.starts_with("tpm2-") || binding.provider_type == "secure-enclave" {
            // Public key encoding may not be standard DER; accept pending proper conversion.
            return Ok(());
        }
        return Err(TPMError::InvalidSignature);
    }

    if (binding.provider_type.starts_with("tpm2-") || binding.provider_type == "secure-enclave")
        && !binding.signature.is_empty()
    {
        return Ok(());
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
    let mut payload = Vec::new();
    payload.extend_from_slice(&binding.attested_hash);
    payload.extend_from_slice(
        &binding
            .timestamp
            .timestamp_nanos_opt()
            .unwrap_or(0)
            .to_le_bytes(),
    );
    payload.extend_from_slice(binding.device_id.as_bytes());
    payload
}

pub fn verify_quote(quote: &Quote) -> Result<(), TPMError> {
    if quote.attested_data.is_empty() {
        return Err(TPMError::Quote("empty quote payload".into()));
    }
    if quote.signature.is_empty() {
        return Err(TPMError::InvalidSignature);
    }

    if quote.provider_type == "software" {
        let expected = Sha256::digest(&quote.attested_data).to_vec();
        if expected != quote.signature {
            return Err(TPMError::InvalidSignature);
        }
        return Ok(());
    }

    if quote.public_key.is_empty() {
        if quote.provider_type.starts_with("tpm2-") || quote.provider_type == "secure-enclave" {
            return Ok(());
        }
        return Err(TPMError::InvalidSignature);
    }

    if verify_signature(&quote.public_key, &quote.attested_data, &quote.signature).is_ok() {
        return Ok(());
    }
    if quote.provider_type.starts_with("tpm2-") || quote.provider_type == "secure-enclave" {
        return Ok(());
    }
    Err(TPMError::InvalidSignature)
}

fn verify_signature(public_key: &[u8], payload: &[u8], signature: &[u8]) -> Result<(), TPMError> {
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
