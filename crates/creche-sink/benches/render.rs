//! Turning a sample stream into JSON lines, the sink's per-event work.

use std::hint::black_box;

use creche_sink::stream::StreamDecoder;
use creche_wire::sample;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};

fn render(c: &mut Criterion) {
    let stream = sample::stream(1000);
    let mut group = c.benchmark_group("sink");
    group.throughput(Throughput::Bytes(stream.len() as u64));
    let mut out = Vec::new();
    group.bench_function("render_sample_stream", |b| {
        b.iter(|| {
            out.clear();
            let mut decoder = StreamDecoder::default();
            let fed = decoder.feed(black_box(&stream), "sandbox", &mut out);
            black_box((fed.is_ok(), out.len()))
        });
    });
    group.finish();
}

criterion_group!(benches, render);
criterion_main!(benches);
