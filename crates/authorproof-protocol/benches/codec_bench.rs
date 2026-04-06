// SPDX-License-Identifier: Apache-2.0
use cpop_protocol::codec::{decode_evidence, encode_evidence};
use cpop_protocol::rfc::{Checkpoint, DocumentRef, EvidencePacket, HashAlgorithm, HashValue};
use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;

fn create_mock_packet(checkpoint_count: usize) -> EvidencePacket {
    let hash = HashValue {
        algorithm: HashAlgorithm::Sha256,
        digest: vec![0u8; 32],
    };

    let checkpoints = (0..checkpoint_count)
        .map(|i| Checkpoint {
            sequence: i as u64,
            checkpoint_id: vec![0u8; 16],
            timestamp: 1700000000 + i as u64,
            content_hash: hash.clone(),
            char_count: 1000 + i as u64,
            prev_hash: hash.clone(),
            checkpoint_hash: hash.clone(),
            jitter_hash: Some(hash.clone()),
        })
        .collect();

    EvidencePacket {
        version: 1,
        profile_uri: "urn:ietf:params:pop:profile:1.0".to_string(),
        packet_id: vec![0u8; 16],
        created: 1700000000,
        document: DocumentRef {
            content_hash: hash.clone(),
            filename: Some("test.txt".to_string()),
            byte_length: 1024,
            char_count: 1000,
        },
        checkpoints,
        attestation_tier: None,
        baseline_verification: None,
    }
}

pub fn bench_codec(c: &mut Criterion) {
    let packet = create_mock_packet(100);
    let encoded = encode_evidence(&packet).unwrap();

    let mut group = c.benchmark_group("codec");

    group.bench_function("encode_evidence_100", |b| {
        b.iter(|| encode_evidence(black_box(&packet)))
    });

    group.bench_function("decode_evidence_100", |b| {
        b.iter(|| decode_evidence(black_box(&encoded)))
    });

    group.finish();
}

criterion_group!(benches, bench_codec);
criterion_main!(benches);
