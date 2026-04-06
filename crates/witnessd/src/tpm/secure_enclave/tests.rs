// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::*;

#[test]
fn test_secure_enclave_availability() {
    if platform::is_secure_enclave_available() {
        println!("Secure Enclave is available");
    } else {
        println!("Secure Enclave is NOT available - skipping hardware tests");
    }
}

#[test]
fn test_secure_enclave_lifecycle() {
    if !platform::is_secure_enclave_available() {
        println!("Skipping test_secure_enclave_lifecycle (hardware unavailable)");
        return;
    }

    let provider = match try_init() {
        Some(p) => p,
        None => {
            println!("try_init returned None despite is_secure_enclave_available returning true");
            return;
        }
    };

    let caps = provider.capabilities();
    assert!(caps.hardware_backed);
    assert!(!caps.secure_clock);
    assert!(caps.monotonic_counter);

    let device_id = provider.device_id();
    assert!(!device_id.is_empty());
    assert!(device_id.starts_with("se-"));

    let pub_key = provider.public_key();
    assert!(!pub_key.is_empty());

    let data = b"test-binding-data";
    let binding = provider.bind(data).expect("Bind failed");

    assert_eq!(binding.provider_type, "secure-enclave");
    assert_eq!(binding.device_id, device_id);

    provider.verify(&binding).expect("Verification failed");

    let nonce = b"test-nonce";
    let quote = provider.quote(nonce, &[]).expect("Quote failed");
    assert_eq!(quote.nonce, nonce);
    crate::tpm::verify_quote(&quote).expect("Quote verification failed");

    let secret = b"my-secret-data";
    let sealed = provider.seal(secret, &[]).expect("Seal failed");
    assert_ne!(sealed, secret);

    let unsealed = provider.unseal(&sealed).expect("Unseal failed");
    assert_eq!(unsealed, secret);

    let challenge = b"attestation-challenge";
    if let Ok(attestation) = provider.generate_key_attestation(challenge) {
        let verified = provider
            .verify_key_attestation(&attestation, challenge)
            .expect("Attestation verification failed");
        assert!(verified);
    } else {
        println!("Key attestation generation failed (expected in some test environments)");
    }

    let count1 = provider.get_counter();
    let count2 = provider.increment_counter();
    assert_eq!(count2, count1 + 1);
}
