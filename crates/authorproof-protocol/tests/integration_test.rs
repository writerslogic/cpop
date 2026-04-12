// SPDX-License-Identifier: Apache-2.0
use authorproof_protocol::codec::{decode_evidence, encode_evidence};
use authorproof_protocol::rfc::{DocumentRef, EvidencePacket, HashAlgorithm, HashValue};

#[test]
fn test_evidence_packet_roundtrip() {
    let packet = EvidencePacket {
        version: 1,
        profile_uri: "urn:ietf:params:pop:profile:1.0".to_string(),
        packet_id: vec![0u8; 16],
        created: 123456789,
        document: DocumentRef {
            content_hash: HashValue {
                algorithm: HashAlgorithm::Sha256,
                digest: vec![0u8; 32],
            },
            filename: Some("test.txt".to_string()),
            byte_length: 100,
            char_count: 50,
        },
        checkpoints: vec![],
        attestation_tier: None,
        baseline_verification: None,
    };

    let encoded = encode_evidence(&packet).expect("Encoding failed");
    let decoded = decode_evidence(&encoded).expect("Decoding failed");

    assert_eq!(decoded.version, packet.version);
    assert_eq!(decoded.profile_uri, packet.profile_uri);
    assert_eq!(decoded.packet_id, packet.packet_id);
}

fn make_test_checkpoint(seq: u64, ts: u64, prev_digest: Vec<u8>) -> authorproof_protocol::rfc::Checkpoint {
    authorproof_protocol::rfc::Checkpoint {
        sequence: seq,
        checkpoint_id: vec![seq as u8; 16],
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
fn test_evidence_packet_roundtrip_with_checkpoints() {
    let packet = EvidencePacket {
        version: 1,
        profile_uri: "urn:ietf:params:pop:profile:1.0".to_string(),
        packet_id: vec![0xFFu8; 16],
        created: 1700000000000,
        document: DocumentRef {
            content_hash: HashValue {
                algorithm: HashAlgorithm::Sha256,
                digest: vec![0xAA; 32],
            },
            filename: Some("test.txt".to_string()),
            byte_length: 5000,
            char_count: 2500,
        },
        checkpoints: vec![
            make_test_checkpoint(0, 1700000001000, vec![0u8; 32]),
            make_test_checkpoint(1, 1700000002000, vec![0x10; 32]),
            make_test_checkpoint(2, 1700000003000, vec![0x11; 32]),
            make_test_checkpoint(3, 1700000004000, vec![0x12; 32]),
        ],
        attestation_tier: None,
        baseline_verification: None,
    };

    let encoded = encode_evidence(&packet).expect("Encoding failed");
    let decoded = decode_evidence(&encoded).expect("Decoding failed");

    assert_eq!(decoded.version, packet.version);
    assert_eq!(decoded.checkpoints.len(), 4);
    for (i, cp) in decoded.checkpoints.iter().enumerate() {
        assert_eq!(cp.sequence, i as u64);
        assert_eq!(cp.char_count, 100 + i as u64 * 50);
    }
    // Verify prev_hash chain
    assert_eq!(decoded.checkpoints[1].prev_hash.digest, vec![0x10; 32]);
    assert_eq!(decoded.checkpoints[2].prev_hash.digest, vec![0x11; 32]);
}
