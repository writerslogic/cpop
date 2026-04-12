// SPDX-License-Identifier: Apache-2.0

//! End-to-end and edge case tests for cpoe-protocol.

use authorproof_protocol::c2pa::{
    encode_jumbf, validate_manifest, verify_jumbf_structure, C2paManifestBuilder,
};
use authorproof_protocol::codec::cbor::{
    decode_cpoe, decode_cwar, encode_compact_ref, encode_cpoe, encode_cwar, extract_tag, has_tag,
};
use authorproof_protocol::codec::{
    decode_evidence, encode_evidence, CBOR_TAG_CPOE, CBOR_TAG_CPOR, CBOR_TAG_CWAR,
};
use authorproof_protocol::compact_ref::{CompactEvidenceRef, CompactRefError, CompactSummary};
use authorproof_protocol::crypto::hash_sha256;
use authorproof_protocol::evidence::{Builder, Verifier};
use authorproof_protocol::rfc::{
    Checkpoint, DocumentRef, EvidencePacket, HashAlgorithm, HashValue,
};
use authorproof_protocol::war::types::{Block, Seal, Version};
use ed25519_dalek::SigningKey;
use rand::RngCore;
use uuid::Uuid;

fn random_signing_key() -> SigningKey {
    let mut key_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key_bytes);
    SigningKey::from_bytes(&key_bytes)
}

// ---------------------------------------------------------------------------
// 1. Full evidence lifecycle
// ---------------------------------------------------------------------------

#[test]
fn test_full_evidence_lifecycle() {
    let signing_key = random_signing_key();
    let verifying_key = signing_key.verifying_key();

    let doc_content = b"This is a document for lifecycle testing.";
    let document = DocumentRef {
        content_hash: hash_sha256(doc_content),
        filename: Some("lifecycle.txt".to_string()),
        byte_length: doc_content.len() as u64,
        char_count: doc_content.len() as u64,
    };

    // Build evidence with multiple checkpoints, adding small delays
    // to avoid triggering adversarial collapse (uniform timing) detection.
    let mut builder = Builder::new(document, Box::new(signing_key)).unwrap();
    for i in 0..5 {
        let content = format!("Checkpoint content {}", i);
        // Varying sleep to produce non-uniform timestamps
        std::thread::sleep(std::time::Duration::from_millis(1 + (i as u64 % 3) * 2));
        builder
            .add_checkpoint(content.as_bytes(), (i + 1) * 10)
            .expect("add_checkpoint should succeed");
    }
    let signed_evidence = builder.finalize().expect("finalize should succeed");

    // Verify the COSE envelope and causality chain
    let verifier = Verifier::new(verifying_key);
    let packet = verifier
        .verify(&signed_evidence)
        .expect("verification should succeed");

    assert_eq!(packet.checkpoints.len(), 5);
    assert_eq!(packet.version, 1);
    assert_eq!(packet.profile_uri, "urn:ietf:params:pop:profile:1.0");

    // Verify causality chain ordering
    for (i, cp) in packet.checkpoints.iter().enumerate() {
        assert_eq!(cp.sequence, i as u64);
    }

    // CBOR roundtrip of the decoded packet
    let re_encoded = encode_evidence(&packet).expect("re-encode");
    let re_decoded = decode_evidence(&re_encoded).expect("re-decode");
    assert_eq!(re_decoded.checkpoints.len(), packet.checkpoints.len());
    assert_eq!(re_decoded.packet_id, packet.packet_id);
}

// ---------------------------------------------------------------------------
// 2. C2PA manifest roundtrip
// ---------------------------------------------------------------------------

fn test_evidence_packet() -> EvidencePacket {
    EvidencePacket {
        version: 1,
        profile_uri: "urn:ietf:params:pop:profile:1.0".to_string(),
        packet_id: vec![0xAA; 16],
        created: 1710000000000,
        document: DocumentRef {
            content_hash: HashValue {
                algorithm: HashAlgorithm::Sha256,
                digest: vec![0xAB; 32],
            },
            filename: Some("test.txt".to_string()),
            byte_length: 1024,
            char_count: 512,
        },
        checkpoints: vec![
            make_checkpoint(0, 1710000001000, vec![0u8; 32]),
            make_checkpoint(1, 1710000002000, vec![0x10; 32]),
        ],
        attestation_tier: None,
        baseline_verification: None,
    }
}

fn make_checkpoint(seq: u64, ts: u64, prev_digest: Vec<u8>) -> Checkpoint {
    Checkpoint {
        sequence: seq,
        checkpoint_id: vec![0u8; 16],
        timestamp: ts,
        content_hash: HashValue {
            algorithm: HashAlgorithm::Sha256,
            digest: vec![seq as u8; 32],
        },
        char_count: 100 + seq * 50,
        prev_hash: HashValue {
            algorithm: HashAlgorithm::Sha256,
            digest: prev_digest,
        },
        checkpoint_hash: HashValue {
            algorithm: HashAlgorithm::Sha256,
            digest: vec![seq as u8 + 0x10; 32],
        },
        jitter_hash: None,
    }
}

#[test]
fn test_c2pa_manifest_roundtrip() {
    let packet = test_evidence_packet();
    let evidence_bytes = b"fake evidence cbor".to_vec();
    let doc_hash = [0xABu8; 32];
    let key = SigningKey::from_bytes(&[1u8; 32]);

    let manifest = C2paManifestBuilder::new(packet, evidence_bytes, doc_hash)
        .document_filename("test.txt")
        .title("Roundtrip Test")
        .build_manifest(&key)
        .unwrap();

    // Validate structural correctness
    let validation = validate_manifest(&manifest);
    assert!(validation.is_valid(), "Errors: {:?}", validation.errors);

    // Encode to JUMBF and verify structure
    let jumbf = encode_jumbf(&manifest).unwrap();
    let info = verify_jumbf_structure(&jumbf).unwrap();
    assert_eq!(info.total_size, jumbf.len());
    assert!(info.child_boxes >= 2);
}

// ---------------------------------------------------------------------------
// 3. C2PA manifest with all MIME formats
// ---------------------------------------------------------------------------

#[test]
fn test_c2pa_manifest_with_all_formats() {
    let formats = [
        ("image/jpeg", "photo.jpg"),
        ("video/mp4", "clip.mp4"),
        ("application/pdf", "report.pdf"),
    ];
    let key = SigningKey::from_bytes(&[1u8; 32]);

    for (mime, filename) in &formats {
        let packet = test_evidence_packet();
        let manifest = C2paManifestBuilder::new(packet, b"ev".to_vec(), [0xAB; 32])
            .document_filename(*filename)
            .format(mime)
            .title("Format Test")
            .build_manifest(&key)
            .unwrap();

        // Format is in c2pa.metadata assertion, not the claim (C2PA 2.4).
        let has_metadata = manifest
            .claim
            .created_assertions
            .iter()
            .any(|a| a.url.contains("c2pa.metadata"));
        assert!(
            has_metadata,
            "Metadata assertion should be present for {mime}"
        );
        let validation = validate_manifest(&manifest);
        assert!(
            validation.is_valid(),
            "Manifest invalid for {}: {:?}",
            mime,
            validation.errors
        );

        let jumbf = encode_jumbf(&manifest).unwrap();
        assert!(verify_jumbf_structure(&jumbf).is_ok());
    }
}

// ---------------------------------------------------------------------------
// 4. WAR block encode/decode
// ---------------------------------------------------------------------------

#[test]
fn test_war_block_encode_decode() {
    let seal = Seal {
        h1: [0x11; 32],
        h2: [0x22; 32],
        h3: [0x33; 32],
        signature: [0x44; 64],
        public_key: [0x55; 32],
    };

    let block = Block {
        version: Version::V1_1,
        author: "Test Author".to_string(),
        document_id: [0xAA; 32],
        timestamp: chrono::Utc::now(),
        statement: "I authored this document using CPoE witnessing.".to_string(),
        seal,
        signed: true,
        verifier_nonce: Some([0xBB; 32]),
        ear: None,
    };

    let ascii = block.encode_ascii();
    assert!(ascii.contains("BEGIN CPoE WAR"));
    assert!(ascii.contains("END CPoE WAR"));
    assert!(ascii.contains("WAR/1.1"));
    assert!(ascii.contains("Test Author"));

    let decoded = Block::decode_ascii(&ascii).expect("decode should succeed");
    assert_eq!(decoded.version, Version::V1_1);
    assert_eq!(decoded.author, "Test Author");
    assert_eq!(decoded.document_id, [0xAA; 32]);
    assert!(decoded.signed);
    assert_eq!(decoded.verifier_nonce, Some([0xBB; 32]));
    assert_eq!(decoded.seal.h1, [0x11; 32]);
    assert_eq!(decoded.seal.h2, [0x22; 32]);
    assert_eq!(decoded.seal.h3, [0x33; 32]);
    assert_eq!(decoded.seal.signature, [0x44; 64]);
    assert_eq!(decoded.seal.public_key, [0x55; 32]);
}

// ---------------------------------------------------------------------------
// 4b. WAR encoding edge cases
// ---------------------------------------------------------------------------

#[test]
fn test_war_block_author_newline_sanitization() {
    let block = Block {
        version: Version::V1_0,
        author: "Evil\nInjected-Header: bad".to_string(),
        document_id: [0xAA; 32],
        timestamp: chrono::Utc::now(),
        statement: "Test statement".to_string(),
        seal: Seal {
            h1: [0x11; 32],
            h2: [0x22; 32],
            h3: [0x33; 32],
            signature: [0x44; 64],
            public_key: [0x55; 32],
        },
        signed: true,
        verifier_nonce: None,
        ear: None,
    };
    let encoded = block.encode_ascii();
    // Newlines in author should be stripped, so the injected content
    // becomes part of the author value, not a separate header line.
    // Verify no line starts with "Injected-Header:"
    assert!(
        !encoded.lines().any(|l| l.starts_with("Injected-Header:")),
        "Header injection: found injected header line in encoded output"
    );
    // Decode should recover a sanitized author (no control chars)
    let decoded = Block::decode_ascii(&encoded).expect("decode should succeed");
    assert!(!decoded.author.contains('\n'));
}

#[test]
fn test_war_block_decode_missing_required_header() {
    let malformed = "-----BEGIN CPoE WAR-----\nVersion: 1.0\n\nStatement body\n\n-----BEGIN SEAL-----\n-----END SEAL-----\n-----END CPoE WAR-----\n";
    let result = Block::decode_ascii(malformed);
    assert!(
        result.is_err(),
        "Should reject input missing Author, Document-ID, Timestamp headers"
    );
}

// ---------------------------------------------------------------------------
// 5. Compact reference generation and format
// ---------------------------------------------------------------------------

#[test]
fn test_compact_ref_generation() {
    let compact = CompactEvidenceRef::new(
        Uuid::new_v4(),
        "abcdef1234567890".to_string(),
        "fedcba0987654321".to_string(),
        CompactSummary {
            checkpoint_count: 25,
            total_chars: 5000,
            total_vdf_time_seconds: 3600.0,
            evidence_tier: 3,
            verdict: Some("likely-human".to_string()),
            confidence_score: Some(0.92),
        },
        "https://api.writersproof.com/evidence/abc123".to_string(),
        "ed25519_signature_placeholder".to_string(),
    );

    // Test base64 URI format
    let uri = compact.to_base64_uri().unwrap();
    assert!(uri.starts_with("cpoe-ref:"));

    // Roundtrip
    let decoded = CompactEvidenceRef::from_base64_uri(&uri).unwrap();
    assert_eq!(decoded.packet_id, compact.packet_id);
    assert_eq!(decoded.chain_hash, compact.chain_hash);
    assert_eq!(decoded.document_hash, compact.document_hash);
    assert_eq!(decoded.summary.checkpoint_count, 25);
    assert_eq!(decoded.summary.evidence_tier, 3);

    // Verification URI
    let verify_uri = compact.verification_uri();
    assert!(verify_uri.starts_with("pop://verify?"));
    assert!(verify_uri.contains(&compact.packet_id.to_string()));

    // Size estimate
    let size = compact.estimated_size();
    assert!(size > 100);
    assert!(size < 2000);

    // Signable payload is deterministic
    let payload1 = compact.signable_payload().unwrap();
    let payload2 = compact.signable_payload().unwrap();
    assert_eq!(payload1, payload2);
}

// ---------------------------------------------------------------------------
// 6. CBOR tag preservation across encode/decode
// ---------------------------------------------------------------------------

#[test]
fn test_codec_cbor_tag_preservation() {
    let packet = test_evidence_packet();

    // CPoE tag
    let cpoe_encoded = encode_cpoe(&packet).unwrap();
    assert!(has_tag(&cpoe_encoded, CBOR_TAG_CPOE));
    assert!(!has_tag(&cpoe_encoded, CBOR_TAG_CWAR));
    assert_eq!(extract_tag(&cpoe_encoded), Some(CBOR_TAG_CPOE));
    let cpoe_decoded: EvidencePacket = decode_cpoe(&cpoe_encoded).unwrap();
    assert_eq!(cpoe_decoded.version, 1);
    assert_eq!(cpoe_decoded.checkpoints.len(), 2);

    // CWAR tag
    let cwar_encoded = encode_cwar(&packet).unwrap();
    assert!(has_tag(&cwar_encoded, CBOR_TAG_CWAR));
    assert!(!has_tag(&cwar_encoded, CBOR_TAG_CPOE));
    assert_eq!(extract_tag(&cwar_encoded), Some(CBOR_TAG_CWAR));
    let cwar_decoded: EvidencePacket = decode_cwar(&cwar_encoded).unwrap();
    assert_eq!(cwar_decoded.version, packet.version);

    // Compact ref tag
    let compact_encoded = encode_compact_ref(&packet).unwrap();
    assert!(has_tag(&compact_encoded, CBOR_TAG_CPOR));
    assert_eq!(extract_tag(&compact_encoded), Some(CBOR_TAG_CPOR));

    // Cross-tag decode should fail
    let wrong_tag_result: std::result::Result<EvidencePacket, _> = decode_cwar(&cpoe_encoded);
    assert!(wrong_tag_result.is_err());
}

// ---------------------------------------------------------------------------
// Edge case: empty evidence in C2PA manifest
// ---------------------------------------------------------------------------

#[test]
fn test_manifest_empty_evidence() {
    let mut packet = test_evidence_packet();
    packet.checkpoints.clear();
    let key = SigningKey::from_bytes(&[1u8; 32]);

    let manifest = C2paManifestBuilder::new(packet, b"ev".to_vec(), [0xAB; 32])
        .build_manifest(&key)
        .unwrap();

    // Should still produce a valid manifest structurally
    let validation = validate_manifest(&manifest);
    assert!(validation.is_valid(), "Errors: {:?}", validation.errors);
}

// ---------------------------------------------------------------------------
// Edge case: large evidence packet in C2PA manifest
// ---------------------------------------------------------------------------

#[test]
fn test_manifest_max_size_evidence() {
    let mut packet = test_evidence_packet();
    // Add 100 checkpoints (not huge, but meaningful)
    packet.checkpoints = (0..100)
        .map(|i| {
            let prev = if i == 0 {
                vec![0u8; 32]
            } else {
                vec![(i - 1) as u8 + 0x10; 32]
            };
            make_checkpoint(i, 1710000000000 + i * 1000, prev)
        })
        .collect();
    let key = SigningKey::from_bytes(&[1u8; 32]);

    let large_evidence = vec![0xFFu8; 64 * 1024]; // 64KB evidence
    let manifest = C2paManifestBuilder::new(packet, large_evidence, [0xAB; 32])
        .build_manifest(&key)
        .unwrap();

    let validation = validate_manifest(&manifest);
    assert!(validation.is_valid(), "Errors: {:?}", validation.errors);

    let jumbf = encode_jumbf(&manifest).unwrap();
    assert!(verify_jumbf_structure(&jumbf).is_ok());
}

// ---------------------------------------------------------------------------
// Edge case: malformed JUMBF
// ---------------------------------------------------------------------------

#[test]
fn test_jumbf_parse_malformed() {
    // Empty
    assert!(verify_jumbf_structure(&[]).is_err());

    // Too short
    assert!(verify_jumbf_structure(&[0, 0, 0, 4]).is_err());

    // Wrong box type
    let mut bad = vec![0, 0, 0, 16];
    bad.extend_from_slice(b"xxxx");
    bad.extend_from_slice(&[0; 8]);
    assert!(verify_jumbf_structure(&bad).is_err());

    // Length exceeds data
    let mut truncated = vec![0, 0, 1, 0]; // claims 256 bytes
    truncated.extend_from_slice(b"jumb");
    truncated.extend_from_slice(&[0; 8]); // only 16 bytes total
    assert!(verify_jumbf_structure(&truncated).is_err());
}

// ---------------------------------------------------------------------------
// Edge case: COSE sign -> verify roundtrip
// ---------------------------------------------------------------------------

#[test]
fn test_cose_sign_verify_roundtrip() {
    use authorproof_protocol::crypto::{sign_evidence_cose, verify_evidence_cose};

    let signing_key = random_signing_key();
    let verifying_key = signing_key.verifying_key();

    let payload = b"test payload for COSE signing";
    let signer: Box<dyn authorproof_protocol::crypto::EvidenceSigner> = Box::new(signing_key);
    let signed = sign_evidence_cose(payload, signer.as_ref()).unwrap();

    // Verify with correct key
    let recovered = verify_evidence_cose(&signed, &verifying_key).unwrap();
    assert_eq!(recovered, payload);

    // Verify with wrong key should fail
    let wrong_key = random_signing_key().verifying_key();
    assert!(verify_evidence_cose(&signed, &wrong_key).is_err());

    // Tampered data should fail
    let mut tampered = signed.clone();
    if let Some(byte) = tampered.last_mut() {
        *byte ^= 0xFF;
    }
    assert!(verify_evidence_cose(&tampered, &verifying_key).is_err());
}

// ---------------------------------------------------------------------------
// Edge case: compact ref error paths
// ---------------------------------------------------------------------------

#[test]
fn test_compact_ref_invalid_prefix() {
    assert_eq!(
        CompactEvidenceRef::from_base64_uri("https://example.com").unwrap_err(),
        CompactRefError::InvalidPrefix
    );
}

#[test]
fn test_compact_ref_invalid_base64() {
    assert_eq!(
        CompactEvidenceRef::from_base64_uri("cpoe-ref:!!!invalid!!!").unwrap_err(),
        CompactRefError::InvalidBase64
    );
}

#[test]
fn test_compact_ref_invalid_json() {
    // Valid base64 but not valid JSON
    let encoded = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        b"not json",
    );
    assert_eq!(
        CompactEvidenceRef::from_base64_uri(&format!("cpoe-ref:{}", encoded)).unwrap_err(),
        CompactRefError::InvalidJson
    );
}
