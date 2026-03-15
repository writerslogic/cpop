use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand::RngCore;
use wld_protocol::crypto::hash_sha256;
use wld_protocol::evidence::{PoPBuilder, PoPVerifier};
use wld_protocol::rfc::DocumentRef;

#[test]
fn test_pop_full_roundtrip() {
    let mut csprng = OsRng;
    let mut key_bytes = [0u8; 32];
    csprng.fill_bytes(&mut key_bytes);
    let signing_key = SigningKey::from_bytes(&key_bytes);
    let verifying_key = signing_key.verifying_key();

    let doc_content = b"Integration test document";
    let document = DocumentRef {
        content_hash: hash_sha256(doc_content),
        filename: Some("test.txt".to_string()),
        byte_length: doc_content.len() as u64,
        char_count: doc_content.len() as u64,
    };

    let mut builder = PoPBuilder::new(document, Box::new(signing_key)).unwrap();
    builder
        .add_checkpoint(b"Checkpoint 1", 12)
        .expect("Add checkpoint failed");
    builder
        .add_checkpoint(b"Checkpoint 2", 12)
        .expect("Add checkpoint failed");

    let signed_evidence = builder.finalize().expect("Finalize failed");

    let verifier = PoPVerifier::new(verifying_key);
    let result = verifier
        .verify(&signed_evidence)
        .expect("Verification failed");

    assert_eq!(result.checkpoints.len(), 2);
    assert_eq!(result.checkpoints[0].sequence, 0);
    assert_eq!(result.checkpoints[1].sequence, 1);
}

#[test]
fn test_pop_tamper_detection() {
    let mut csprng = OsRng;
    let mut key_bytes = [0u8; 32];
    csprng.fill_bytes(&mut key_bytes);
    let signing_key = SigningKey::from_bytes(&key_bytes);
    let verifying_key = signing_key.verifying_key();

    let doc_content = b"Tamper test document";
    let document = DocumentRef {
        content_hash: hash_sha256(doc_content),
        filename: Some("test.txt".to_string()),
        byte_length: doc_content.len() as u64,
        char_count: doc_content.len() as u64,
    };

    let mut builder = PoPBuilder::new(document, Box::new(signing_key)).unwrap();
    builder.add_checkpoint(b"Safe checkpoint", 15).unwrap();
    let signed_evidence = builder.finalize().unwrap();

    // Tamper with the data (it's COSE signed, so any change should fail verification)
    let mut tampered_evidence = signed_evidence.clone();
    if let Some(byte) = tampered_evidence.last_mut() {
        *byte ^= 0xFF;
    }

    let verifier = PoPVerifier::new(verifying_key);
    assert!(verifier.verify(&tampered_evidence).is_err());
}

#[test]
fn test_pop_playback_attack_detection() {
    use wld_protocol::codec::encode_evidence;
    use wld_protocol::crypto::sign_evidence_cose;
    use wld_protocol::rfc::{AttestationTier, Checkpoint, EvidencePacket};
    extern crate ciborium;

    let mut csprng = OsRng;
    let mut key_bytes = [0u8; 32];
    csprng.fill_bytes(&mut key_bytes);
    let signing_key = SigningKey::from_bytes(&key_bytes);
    let verifying_key = signing_key.verifying_key();

    let doc_content = b"Playback attack document";
    let doc_hash = hash_sha256(doc_content);
    let packet_id = vec![1u8; 16];
    let created = 1000u64;

    let document = DocumentRef {
        content_hash: doc_hash,
        filename: Some("attack.txt".to_string()),
        byte_length: doc_content.len() as u64,
        char_count: doc_content.len() as u64,
    };

    let mut doc_cbor = Vec::new();
    ciborium::into_writer(&document, &mut doc_cbor).expect("CBOR encode document-ref");
    let mut last_hash = hash_sha256(&doc_cbor);

    let mut checkpoints = Vec::new();
    for i in 0..4u64 {
        let content_hash = hash_sha256(format!("Checkpoint {}", i).as_bytes());
        let checkpoint_hash = wld_protocol::crypto::compute_causality_lock(
            &packet_id,
            &last_hash.digest,
            &content_hash.digest,
        )
        .expect("compute causality lock");

        checkpoints.push(Checkpoint {
            sequence: i,
            checkpoint_id: vec![i as u8; 16],
            timestamp: created + (i + 1) * 1000,
            content_hash,
            char_count: 10,
            prev_hash: last_hash.clone(),
            checkpoint_hash: checkpoint_hash.clone(),
            jitter_hash: None,
        });
        last_hash = checkpoint_hash;
    }

    let packet = EvidencePacket {
        version: 1,
        profile_uri: "urn:ietf:params:pop:profile:1.0".to_string(),
        packet_id,
        created,
        document,
        checkpoints,
        attestation_tier: Some(AttestationTier::HardwareBound),
        baseline_verification: None,
    };

    let encoded = encode_evidence(&packet).unwrap();
    let signer: Box<dyn wld_protocol::crypto::PoPSigner> = Box::new(signing_key);
    let signed = sign_evidence_cose(&encoded, signer.as_ref()).unwrap();

    let verifier = PoPVerifier::new(verifying_key);
    let result = verifier.verify(&signed);

    assert!(
        result.is_err(),
        "Verifier should catch uniform timing (Adversarial Collapse)"
    );
    if let Err(wld_protocol::error::Error::Validation(msg)) = result {
        assert!(msg.contains("Adversarial collapse"));
    } else {
        panic!(
            "Expected Validation Error with 'Adversarial collapse', got {:?}",
            result
        );
    }
}

#[test]
fn test_identity_csr_generation() {
    use wld_protocol::identity::IdentityManager;

    let id_manager = IdentityManager::generate();
    let csr_der = id_manager
        .generate_csr("CN=PopDevice,O=WritersLogic,C=US")
        .expect("CSR generation failed");

    assert!(!csr_der.is_empty());

    // Basic DER check: starts with a sequence tag (0x30)
    assert_eq!(csr_der[0], 0x30);
}
