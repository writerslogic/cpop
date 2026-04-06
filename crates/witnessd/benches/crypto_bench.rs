use criterion::{black_box, criterion_group, criterion_main, Criterion};
use cpop_engine::crypto::{compute_event_hash, compute_event_hmac, EventData};
use cpop_engine::utils::stats::{mean, std_dev, coefficient_of_variation};

fn bench_event_hashing(c: &mut Criterion) {
    let device_id = [0x01; 16];
    let content_hash = [0xAB; 32];
    let previous_hash = [0x00; 32];
    let file_path = "/path/to/my/document/authorship/session/test.txt";
    
    let data = EventData {
        device_id,
        timestamp_ns: 1_700_000_000_000_000_000,
        file_path: file_path.to_string(),
        content_hash,
        file_size: 1024 * 1024,
        size_delta: 100,
        previous_hash,
    };

    c.bench_function("compute_event_hash", |b| b.iter(|| compute_event_hash(black_box(&data))));
    
    let hmac_key = [0x42; 32];
    c.bench_function("compute_event_hmac", |b| b.iter(|| compute_event_hmac(black_box(&hmac_key), black_box(&data))));
}

fn bench_stats(c: &mut Criterion) {
    let data: Vec<f64> = (0..1000).map(|i| i as f64 * 0.1).collect();
    
    c.bench_function("stats_mean", |b| b.iter(|| mean(black_box(&data))));
    c.bench_function("stats_std_dev", |b| b.iter(|| std_dev(black_box(&data))));
    c.bench_function("stats_cv", |b| b.iter(|| coefficient_of_variation(black_box(&data))));
}

criterion_group!(benches, bench_event_hashing, bench_stats);
criterion_main!(benches);
