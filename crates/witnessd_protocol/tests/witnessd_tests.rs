use ed25519_dalek::SigningKey;
use rand::RngCore;
use witnessd_protocol::crypto::hash_sha256;
use witnessd_protocol::evidence::{PoPBuilder, PoPVerifier};
use witnessd_protocol::rfc::DocumentRef;

#[test]
fn test_pop_full_roundtrip() {
    let mut key_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key_bytes);
    let signing_key = SigningKey::from_bytes(&key_bytes);
    let verifying_key = signing_key.verifying_key();

    let doc_content = b"Integration test document";
    let document = DocumentRef {
        content_hash: hash_sha256(doc_content),
        filename: Some("test.txt".to_string()),
        byte_length: doc_content.len() as u64,
        char_count: doc_content.len() as u64,
    };

    let mut builder = PoPBuilder::new(document, Box::new(signing_key));
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
    let mut key_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key_bytes);
    let signing_key = SigningKey::from_bytes(&key_bytes);
    let verifying_key = signing_key.verifying_key();

    let doc_content = b"Tamper test document";
    let document = DocumentRef {
        content_hash: hash_sha256(doc_content),
        filename: Some("test.txt".to_string()),
        byte_length: doc_content.len() as u64,
        char_count: doc_content.len() as u64,
    };

    let mut builder = PoPBuilder::new(document, Box::new(signing_key));
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
    use witnessd_protocol::codec::encode_evidence;
    use witnessd_protocol::crypto::sign_evidence_cose;
    use witnessd_protocol::rfc::{AttestationTier, Checkpoint, EvidencePacket};

    let mut key_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key_bytes);
    let signing_key = SigningKey::from_bytes(&key_bytes);
    let verifying_key = signing_key.verifying_key();

    // Create a "Malicious" packet with perfectly uniform 1-second intervals (Scripted/Playback)
    let doc_content = b"Playback attack document";
    let doc_hash = hash_sha256(doc_content);
    let packet_id = vec![1u8; 16];
    let created = 1000;

    let mut checkpoints = Vec::new();
    let mut last_hash = hash_sha256(&doc_hash.digest);

    for i in 0..4u64 {
        let content_hash = hash_sha256(format!("Checkpoint {}", i).as_bytes());
        let checkpoint_hash = witnessd_protocol::crypto::compute_causality_lock(
            &packet_id,
            &last_hash.digest,
            &content_hash.digest,
        )
        .unwrap();

        checkpoints.push(Checkpoint {
            sequence: i,
            checkpoint_id: vec![i as u8; 16],
            timestamp: created + (i + 1), // Exactly 1 second apart
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
        profile_uri: "https://pop.ietf.org/profiles/default".to_string(),
        packet_id,
        created,
        document: DocumentRef {
            content_hash: doc_hash,
            filename: Some("attack.txt".to_string()),
            byte_length: doc_content.len() as u64,
            char_count: doc_content.len() as u64,
        },
        checkpoints,
        attestation_tier: Some(AttestationTier::HardwareBound),
        baseline_verification: None,
    };

    let encoded = encode_evidence(&packet).unwrap();
    let signer: Box<dyn witnessd_protocol::crypto::PoPSigner> = Box::new(signing_key);
    let signed = sign_evidence_cose(&encoded, signer.as_ref()).unwrap();

    let verifier = PoPVerifier::new(verifying_key);
    let result = verifier.verify(&signed);

    assert!(
        result.is_err(),
        "Verifier should catch uniform timing (Adversarial Collapse)"
    );
    if let Err(witnessd_protocol::error::Error::Validation(msg)) = result {
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
    use witnessd_protocol::identity::IdentityManager;

    let id_manager = IdentityManager::generate();
    let csr_der = id_manager
        .generate_csr("CN=PopDevice,O=WritersLogic,C=US")
        .expect("CSR generation failed");

    assert!(!csr_der.is_empty());

    // Basic DER check: starts with a sequence tag (0x30)
    assert_eq!(csr_der[0], 0x30);
}
