//! Decoding a sample stream with [`creche_wire::Records`].

use std::hint::black_box;

use creche_wire::{Records, sample};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};

fn decode(c: &mut Criterion) {
    let stream = sample::stream(1000);
    let mut group = c.benchmark_group("wire");
    group.throughput(Throughput::Bytes(stream.len() as u64));
    group.bench_function("decode_sample_stream", |b| {
        b.iter(|| {
            let mut records = Records::new(black_box(&stream));
            let count = (&mut records).flatten().count();
            black_box((count, records.consumed()))
        });
    });
    group.finish();
}

criterion_group!(benches, decode);
criterion_main!(benches);
