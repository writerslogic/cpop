// SPDX-License-Identifier: Apache-2.0

//! Tests for wire-format types.

use crate::codec;
use crate::rfc::wire_types::*;

#[test]
fn test_checkpoint_wire_cbor_roundtrip() {
    let content_hash = HashValue::sha256(vec![0xAA; 32]);
    let prev_hash = HashValue::zero_sha256();
    let checkpoint_hash = HashValue::sha256(vec![0xCC; 32]);

    let checkpoint = CheckpointWire {
        sequence: 0,
        checkpoint_id: [1u8; 16],
        timestamp: 1700000000000,
        content_hash,
        char_count: 5000,
        delta: EditDelta {
            chars_added: 5000,
            chars_deleted: 0,
            op_count: 150,
            positions: None,
            edit_graph_hash: None,
            cursor_trajectory_histogram: None,
            revision_depth_histogram: None,
            pause_duration_histogram: None,
        },
        prev_hash,
        checkpoint_hash,
        process_proof: ProcessProof {
            algorithm: ProofAlgorithm::SwfArgon2id,
            params: ProofParams {
                time_cost: 3,
                memory_cost: 65536,
                parallelism: 1,
                steps: 1000,
                waypoint_interval: None,
                waypoint_memory: None,
            },
            input: vec![0x11; 32],
            merkle_root: vec![0x22; 32],
            sampled_proofs: vec![MerkleProof {
                leaf_index: 0,
                sibling_path: vec![serde_bytes::ByteBuf::from(vec![0x33; 32])],
                leaf_value: vec![0x44; 32],
            }],
            claimed_duration: 30000,
        },
        jitter_binding: None,
        physical_state: None,
        entangled_mac: None,
        receipts: None,
        active_probes: None,
        hat_proof: None,
        beacon_anchor: None,
        verifier_nonce: None,
    };

    let encoded = codec::cbor::encode(&checkpoint).expect("encode checkpoint");
    let decoded: CheckpointWire = codec::cbor::decode(&encoded).expect("decode checkpoint");
    assert_eq!(decoded.sequence, 0);
    assert_eq!(decoded.char_count, 5000);
    assert_eq!(decoded.delta.chars_added, 5000);
}

/// Create a minimal test evidence packet.
fn create_test_evidence_packet() -> EvidencePacketWire {
    let content_hash = HashValue::sha256(vec![0xAA; 32]);
    let prev_hash = HashValue::zero_sha256();
    let checkpoint_hash = HashValue::sha256(vec![0xCC; 32]);

    let checkpoint = CheckpointWire {
        sequence: 0,
        checkpoint_id: [1u8; 16],
        timestamp: 1700000000000,
        content_hash: content_hash.clone(),
        char_count: 5000,
        delta: EditDelta {
            chars_added: 5000,
            chars_deleted: 0,
            op_count: 150,
            positions: None,
            edit_graph_hash: None,
            cursor_trajectory_histogram: None,
            revision_depth_histogram: None,
            pause_duration_histogram: None,
        },
        prev_hash: prev_hash.clone(),
        checkpoint_hash: checkpoint_hash.clone(),
        process_proof: ProcessProof {
            algorithm: ProofAlgorithm::SwfArgon2id,
            params: ProofParams {
                time_cost: 3,
                memory_cost: 65536,
                parallelism: 1,
                steps: 1000,
                waypoint_interval: None,
                waypoint_memory: None,
            },
            input: vec![0x11; 32],
            merkle_root: vec![0x22; 32],
            sampled_proofs: vec![MerkleProof {
                leaf_index: 0,
                sibling_path: vec![serde_bytes::ByteBuf::from(vec![0x33; 32])],
                leaf_value: vec![0x44; 32],
            }],
            claimed_duration: 30000,
        },
        jitter_binding: None,
        physical_state: None,
        entangled_mac: None,
        receipts: None,
        active_probes: None,
        hat_proof: None,
        beacon_anchor: None,
        verifier_nonce: None,
    };

    let mut checkpoints = vec![checkpoint.clone()];
    for i in 1..3 {
        let mut cp = checkpoint.clone();
        cp.sequence = i;
        cp.checkpoint_id = [(i + 1) as u8; 16];
        cp.prev_hash = checkpoint_hash.clone();
        checkpoints.push(cp);
    }

    EvidencePacketWire {
        version: 1,
        profile_uri: "urn:ietf:params:pop:profile:1.0".to_string(),
        packet_id: [0xFF; 16],
        created: 1700000000000,
        document: DocumentRef {
            content_hash: content_hash.clone(),
            filename: Some("test_document.txt".to_string()),
            byte_length: 12500,
            char_count: 5000,
            salt_mode: None,
            salt_commitment: None,
        },
        checkpoints,
        attestation_tier: Some(AttestationTier::SoftwareOnly),
        limitations: None,
        profile: None,
        presence_challenges: None,
        channel_binding: None,
        content_tier: Some(ContentTier::Core),
        previous_packet_ref: None,
        packet_sequence: None,
        physical_liveness: None,
        baseline_verification: None,
    }
}

/// Create a minimal test attestation result.
fn create_test_attestation_result() -> AttestationResultWire {
    AttestationResultWire {
        version: 1,
        evidence_ref: HashValue::sha256(vec![0xBB; 32]),
        verdict: Verdict::Authentic,
        assessed_tier: AttestationTier::SoftwareOnly,
        chain_length: 10,
        chain_duration: 3600,
        entropy_report: Some(EntropyReport {
            timing_entropy: 3.5,
            revision_entropy: 2.8,
            pause_entropy: 4.1,
            meets_threshold: true,
        }),
        forgery_cost: Some(ForgeryCostEstimate {
            c_swf: 150.0,
            c_entropy: 50.0,
            c_hardware: 0.0,
            c_total: 200.0,
            currency: CostUnit::Usd,
        }),
        absence_claims: None,
        warnings: None,
        verifier_signature: vec![0xDD; 64],
        created: 1700000000000,
        forensic_summary: Some(ForensicSummary {
            flags_triggered: 0,
            flags_evaluated: 5,
            affected_checkpoints: 0,
            total_checkpoints: 10,
            flags: Some(vec![ForensicFlag {
                mechanism: "SNR".to_string(),
                triggered: false,
                affected_windows: 0,
                total_windows: 9,
            }]),
        }),
        effort_attribution: None,
        confidence_tier: None,
    }
}

#[test]
fn test_evidence_packet_cbor_roundtrip() {
    let packet = create_test_evidence_packet();

    let encoded = packet.encode_cbor().expect("encode should succeed");

    assert!(
        codec::cbor::has_tag(&encoded, CBOR_TAG_EVIDENCE_PACKET),
        "encoded packet should have CPOP tag"
    );

    let decoded = EvidencePacketWire::decode_cbor(&encoded).expect("decode should succeed");

    assert_eq!(decoded.version, 1);
    assert_eq!(decoded.profile_uri, packet.profile_uri);
    assert_eq!(decoded.packet_id, packet.packet_id);
    assert_eq!(decoded.created, packet.created);
    assert_eq!(decoded.checkpoints.len(), 3);
    assert_eq!(
        decoded.document.content_hash.algorithm,
        HashAlgorithm::Sha256
    );
    assert_eq!(decoded.document.byte_length, 12500);
    assert_eq!(decoded.document.char_count, 5000);
    assert_eq!(
        decoded.attestation_tier,
        Some(AttestationTier::SoftwareOnly)
    );
    assert_eq!(decoded.content_tier, Some(ContentTier::Core));
}

#[test]
fn test_attestation_result_cbor_roundtrip() {
    let result = create_test_attestation_result();

    let encoded = result.encode_cbor().expect("encode should succeed");

    assert!(
        codec::cbor::has_tag(&encoded, CBOR_TAG_ATTESTATION_RESULT),
        "encoded result should have CWAR tag"
    );

    let decoded = AttestationResultWire::decode_cbor(&encoded).expect("decode should succeed");

    assert_eq!(decoded.version, 1);
    assert_eq!(decoded.verdict, Verdict::Authentic);
    assert_eq!(decoded.assessed_tier, AttestationTier::SoftwareOnly);
    assert_eq!(decoded.chain_length, 10);
    assert_eq!(decoded.chain_duration, 3600);
    assert_eq!(decoded.verifier_signature.len(), 64);
    assert!(decoded.entropy_report.is_some());
    assert!(decoded.forgery_cost.is_some());
    assert!(decoded.forensic_summary.is_some());
}

#[test]
fn test_correct_cbor_tag_values() {
    assert_eq!(
        CBOR_TAG_EVIDENCE_PACKET, 1129336656,
        "Evidence packet tag should be 1129336656 (IANA CPOP)"
    );
    assert_eq!(
        CBOR_TAG_ATTESTATION_RESULT, 1129791826,
        "Attestation result tag should be 1129791826 (IANA CWAR)"
    );
}

#[test]
fn test_wrong_tag_rejected() {
    let packet = create_test_evidence_packet();
    let encoded = packet.encode_cbor().expect("encode");

    let result = AttestationResultWire::decode_cbor(&encoded);
    assert!(result.is_err(), "should reject wrong tag");
}

#[test]
fn test_enum_values() {
    assert_eq!(HashAlgorithm::Sha256 as u8, 1);
    assert_eq!(HashAlgorithm::Sha384 as u8, 2);
    assert_eq!(HashAlgorithm::Sha512 as u8, 3);

    assert_eq!(AttestationTier::SoftwareOnly as u8, 1);
    assert_eq!(AttestationTier::AttestedSoftware as u8, 2);
    assert_eq!(AttestationTier::HardwareBound as u8, 3);
    assert_eq!(AttestationTier::HardwareHardened as u8, 4);

    assert_eq!(ContentTier::Core as u8, 1);
    assert_eq!(ContentTier::Enhanced as u8, 2);
    assert_eq!(ContentTier::Maximum as u8, 3);

    assert_eq!(ProofAlgorithm::SwfSha256 as u8, 10);
    assert_eq!(ProofAlgorithm::SwfArgon2id as u8, 20);
    assert_eq!(ProofAlgorithm::SwfArgon2idEntangled as u8, 21);

    assert_eq!(Verdict::Authentic as u8, 1);
    assert_eq!(Verdict::Inconclusive as u8, 2);
    assert_eq!(Verdict::Suspicious as u8, 3);
    assert_eq!(Verdict::Invalid as u8, 4);

    assert_eq!(HashSaltMode::Unsalted as u8, 0);
    assert_eq!(HashSaltMode::AuthorSalted as u8, 1);

    assert_eq!(CostUnit::Usd as u8, 1);
    assert_eq!(CostUnit::CpuHours as u8, 2);

    assert_eq!(AbsenceType::ComputationallyBound as u8, 1);
    assert_eq!(AbsenceType::MonitoringDependent as u8, 2);
    assert_eq!(AbsenceType::Environmental as u8, 3);

    assert_eq!(ProbeType::GaltonBoard as u8, 1);
    assert_eq!(ProbeType::ReflexGate as u8, 2);
    assert_eq!(ProbeType::SpatialTarget as u8, 3);

    assert_eq!(BindingType::TlsExporter as u8, 1);
}

#[test]
fn test_untagged_cbor_roundtrip() {
    let packet = create_test_evidence_packet();

    let encoded = packet
        .encode_cbor_untagged()
        .expect("untagged encode should succeed");

    assert!(
        !codec::cbor::has_tag(&encoded, CBOR_TAG_EVIDENCE_PACKET),
        "untagged packet should not have tag"
    );

    let decoded =
        EvidencePacketWire::decode_cbor_untagged(&encoded).expect("untagged decode should succeed");
    assert_eq!(decoded.version, 1);
}

#[test]
fn test_evidence_packet_with_optional_fields() {
    let mut packet = create_test_evidence_packet();

    packet.limitations = Some(vec![
        "No hardware attestation available".to_string(),
        "Single device session".to_string(),
    ]);

    packet.profile = Some(ProfileDeclarationWire {
        profile_id: "urn:ietf:params:pop:profile:1.0".to_string(),
        feature_flags: vec![1, 3, 5],
    });

    packet.previous_packet_ref = Some(HashValue::sha256(vec![0xEE; 32]));
    packet.packet_sequence = Some(2);

    let encoded = packet.encode_cbor().expect("encode");
    let decoded = EvidencePacketWire::decode_cbor(&encoded).expect("decode");

    assert_eq!(decoded.limitations.as_ref().unwrap().len(), 2);
    assert!(decoded.profile.is_some());
    assert_eq!(
        decoded.profile.as_ref().unwrap().feature_flags,
        vec![1, 3, 5]
    );
    assert!(decoded.previous_packet_ref.is_some());
    assert_eq!(decoded.packet_sequence, Some(2));
}

#[test]
fn test_checkpoint_with_jitter_and_physical() {
    let mut packet = create_test_evidence_packet();

    packet.checkpoints[0].jitter_binding = Some(JitterBindingWire {
        intervals: vec![120, 85, 200, 150, 95, 180, 110, 160],
        entropy_estimate: 350,
        jitter_seal: vec![0x55; 32],
    });

    packet.checkpoints[0].physical_state = Some(PhysicalState {
        thermal: vec![45000, 45100, 45200, 45150],
        entropy_delta: -50,
        kernel_commitment: Some([0x66; 32]),
    });

    packet.checkpoints[0].entangled_mac = Some(vec![0x77; 32]);

    let encoded = packet.encode_cbor().expect("encode");
    let decoded = EvidencePacketWire::decode_cbor(&encoded).expect("decode");

    let cp0 = &decoded.checkpoints[0];
    assert!(cp0.jitter_binding.is_some());
    let jb = cp0.jitter_binding.as_ref().unwrap();
    assert_eq!(jb.intervals.len(), 8);
    assert_eq!(jb.entropy_estimate, 350);

    assert!(cp0.physical_state.is_some());
    let ps = cp0.physical_state.as_ref().unwrap();
    assert_eq!(ps.thermal.len(), 4);
    assert_eq!(ps.entropy_delta, -50);
    assert!(ps.kernel_commitment.is_some());

    assert!(cp0.entangled_mac.is_some());
}

#[test]
fn test_attestation_result_with_absence_claims() {
    let mut result = create_test_attestation_result();

    result.absence_claims = Some(vec![AbsenceClaim {
        absence_type: AbsenceType::ComputationallyBound,
        window: TimeWindow {
            start: 1700000000000,
            end: 1700003600000,
        },
        claim_id: "swf-irreversibility".to_string(),
        threshold: None,
        assertion: true,
    }]);

    result.warnings = Some(vec!["Low entropy in first checkpoint".to_string()]);

    let encoded = result.encode_cbor().expect("encode");
    let decoded = AttestationResultWire::decode_cbor(&encoded).expect("decode");

    assert!(decoded.absence_claims.is_some());
    let claims = decoded.absence_claims.unwrap();
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].absence_type, AbsenceType::ComputationallyBound);
    assert!(claims[0].assertion);

    assert!(decoded.warnings.is_some());
    assert_eq!(decoded.warnings.unwrap().len(), 1);
}

#[test]
fn test_checkpoint_with_active_probes() {
    let mut packet = create_test_evidence_packet();

    packet.checkpoints[0].active_probes = Some(vec![ActiveProbe {
        probe_type: ProbeType::GaltonBoard,
        stimulus_time: 1700000001000,
        response_time: 1700000001250,
        stimulus_data: vec![0x88; 16],
        response_data: vec![0x99; 32],
        response_latency: Some(250),
    }]);

    let encoded = packet.encode_cbor().expect("encode");
    let decoded = EvidencePacketWire::decode_cbor(&encoded).expect("decode");

    let probes = decoded.checkpoints[0].active_probes.as_ref().unwrap();
    assert_eq!(probes.len(), 1);
    assert_eq!(probes[0].probe_type, ProbeType::GaltonBoard);
    assert_eq!(probes[0].response_latency, Some(250));
}

#[test]
fn test_checkpoint_with_self_receipts() {
    let mut packet = create_test_evidence_packet();

    packet.checkpoints[0].receipts = Some(vec![Receipt::SelfReceipt(SelfReceipt {
        tool_id: "vscode-writerslogic".to_string(),
        output_commit: HashValue::sha256(vec![0xAA; 32]),
        evidence_ref: HashValue::sha256(vec![0xBB; 32]),
        transfer_time: 1700000002000,
    })]);

    let encoded = packet.encode_cbor().expect("encode");
    let decoded = EvidencePacketWire::decode_cbor(&encoded).expect("decode");

    let receipts = decoded.checkpoints[0].receipts.as_ref().unwrap();
    assert_eq!(receipts.len(), 1);
    match &receipts[0] {
        Receipt::SelfReceipt(sr) => assert_eq!(sr.tool_id, "vscode-writerslogic"),
        Receipt::Tool(_) => panic!("expected SelfReceipt"),
    }
}

#[test]
fn test_evidence_packet_with_physical_liveness() {
    let mut packet = create_test_evidence_packet();

    packet.physical_liveness = Some(PhysicalLiveness {
        thermal_trajectory: vec![
            (1700000000000, 45000),
            (1700000001000, 45100),
            (1700000002000, 45200),
        ],
        entropy_anchor: [0xAB; 32],
    });

    let encoded = packet.encode_cbor().expect("encode");
    let decoded = EvidencePacketWire::decode_cbor(&encoded).expect("decode");

    assert!(decoded.physical_liveness.is_some());
    let pl = decoded.physical_liveness.unwrap();
    assert_eq!(pl.thermal_trajectory.len(), 3);
    assert_eq!(pl.entropy_anchor, [0xAB; 32]);
}

#[test]
fn test_evidence_packet_with_presence_and_channel() {
    let mut packet = create_test_evidence_packet();

    packet.presence_challenges = Some(vec![PresenceChallenge {
        challenge_nonce: vec![0x11; 32],
        device_signature: vec![0x22; 64],
        response_time: 1700000001500,
    }]);

    packet.channel_binding = Some(ChannelBinding {
        binding_type: BindingType::TlsExporter,
        binding_value: [0x33; 32],
    });

    let encoded = packet.encode_cbor().expect("encode");
    let decoded = EvidencePacketWire::decode_cbor(&encoded).expect("decode");

    assert!(decoded.presence_challenges.is_some());
    let pc = decoded.presence_challenges.as_ref().unwrap();
    assert_eq!(pc.len(), 1);
    assert_eq!(pc[0].challenge_nonce.len(), 32);

    assert!(decoded.channel_binding.is_some());
    let cb = decoded.channel_binding.as_ref().unwrap();
    assert_eq!(cb.binding_type, BindingType::TlsExporter);
    assert_eq!(cb.binding_value, [0x33; 32]);
}

#[test]
fn test_hash_value_constructors() {
    let h256 = HashValue::sha256(vec![1; 32]);
    assert_eq!(h256.algorithm, HashAlgorithm::Sha256);
    assert_eq!(h256.digest.len(), 32);

    let h384 = HashValue::sha384(vec![2; 48]);
    assert_eq!(h384.algorithm, HashAlgorithm::Sha384);
    assert_eq!(h384.digest.len(), 48);

    let h512 = HashValue::sha512(vec![3; 64]);
    assert_eq!(h512.algorithm, HashAlgorithm::Sha512);
    assert_eq!(h512.digest.len(), 64);

    let zero = HashValue::zero_sha256();
    assert_eq!(zero.algorithm, HashAlgorithm::Sha256);
    assert!(zero.digest.iter().all(|&b| b == 0));
}
