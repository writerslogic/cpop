// SPDX-License-Identifier: Apache-2.0
use cpop_jitter::{
    Evidence, EvidenceChain, HumanModel, HybridEngine, Jitter, JitterEngine, PureJitter,
};
use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;

fn bench_pure_jitter(c: &mut Criterion) {
    let engine = PureJitter::default();
    let secret = [42u8; 32];
    let inputs = b"keystroke data";
    let entropy = [0u8; 32].into();

    c.bench_function("PureJitter::compute_jitter", |b| {
        b.iter(|| engine.compute_jitter(black_box(&secret), black_box(inputs), black_box(entropy)))
    });
}

fn bench_hybrid_engine(c: &mut Criterion) {
    let engine = HybridEngine::default();
    let secret = [42u8; 32];
    let inputs = b"keystroke data";

    c.bench_function("HybridEngine::sample", |b| {
        b.iter(|| engine.sample(black_box(&secret), black_box(inputs)))
    });
}

fn bench_evidence_chain_append(c: &mut Criterion) {
    let secret = [42u8; 32];

    c.bench_function("EvidenceChain::append", |b| {
        b.iter_with_setup(
            || EvidenceChain::with_secret(&secret),
            |mut chain| {
                chain.append(Evidence::pure(1500)).unwrap();
                chain
            },
        )
    });
}

fn bench_human_model_validate(c: &mut Criterion) {
    let model = HumanModel::default();
    let jitters: Vec<Jitter> = (0..1000).map(|i| 500 + ((i * 37) % 2500) as u32).collect();

    c.bench_function("HumanModel::validate (1000 samples)", |b| {
        b.iter(|| model.validate(black_box(&jitters)))
    });
}

fn bench_evidence_chain_verify_integrity(c: &mut Criterion) {
    let secret = [42u8; 32];
    let mut chain = EvidenceChain::with_secret(&secret);
    for i in 0..100 {
        chain
            .append(Evidence::pure(500 + (i % 2500) as u32))
            .unwrap();
    }

    c.bench_function("EvidenceChain::verify_integrity (100 records)", |b| {
        b.iter(|| chain.verify_integrity(black_box(&secret)))
    });
}

criterion_group!(
    benches,
    bench_pure_jitter,
    bench_hybrid_engine,
    bench_evidence_chain_append,
    bench_human_model_validate,
    bench_evidence_chain_verify_integrity,
);
criterion_main!(benches);
