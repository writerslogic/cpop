use witnessd_protocol::rfc::{EvidencePacket, DocumentRef, HashValue, HashAlgorithm};
use witnessd_protocol::codec::{encode_evidence, decode_evidence};

#[test]
fn test_evidence_packet_roundtrip() {
    let packet = EvidencePacket {
        version: 1,
        profile_uri: "https://pop.ietf.org/profiles/default".to_string(),
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
    };

    let encoded = encode_evidence(&packet).expect("Encoding failed");
    let decoded = decode_evidence(&encoded).expect("Decoding failed");

    assert_eq!(decoded.version, packet.version);
    assert_eq!(decoded.profile_uri, packet.profile_uri);
    assert_eq!(decoded.packet_id, packet.packet_id);
}
