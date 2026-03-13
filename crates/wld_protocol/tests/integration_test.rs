use wld_protocol::codec::{decode_evidence, encode_evidence};
use wld_protocol::rfc::{DocumentRef, EvidencePacket, HashAlgorithm, HashValue};

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
