use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::time::Duration;
use witnessd_engine::vdf;

pub fn bench_vdf(c: &mut Criterion) {
    let mut group = c.benchmark_group("vdf");
    let input = [0xABu8; 32];

    // Benchmark 10,000 iterations of SHA-256 chain
    group.bench_function("vdf_compute_10k", |b| {
        b.iter(|| vdf::compute_iterations(black_box(input), black_box(10_000)))
    });

    let proof = vdf::compute_iterations(input, 10_000);
    group.bench_function("vdf_verify_10k", |b| {
        b.iter(|| vdf::verify(black_box(&proof)))
    });

    group.finish();
}

criterion_group!(benches, bench_vdf);
criterion_main!(benches);
