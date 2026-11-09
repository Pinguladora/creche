//! Turning a sample stream into JSON lines, the sink's per-event work.

use std::hint::black_box;

use creche_sink::json::{Attribution, Origin};
use creche_sink::k8s::Pod;
use creche_sink::stream::StreamDecoder;
use creche_wire::sample;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};

fn render(c: &mut Criterion) {
    let stream = sample::stream(1000);
    let mut group = c.benchmark_group("sink");
    group.throughput(Throughput::Bytes(stream.len() as u64));
    // Lines carry the pod, as in a cluster.
    let origin = Origin::new(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        &Attribution::Pod(Pod {
            name: "agent-7".into(),
            namespace: "agents".into(),
            uid: "1f2e3d4c-0000-4000-8000-000000000001".into(),
        }),
    );
    let mut out = Vec::new();
    group.bench_function("render_sample_stream", |b| {
        b.iter(|| {
            out.clear();
            let mut decoder = StreamDecoder::default();
            let fed = decoder.feed(black_box(&stream), &origin, &mut out);
            black_box((fed.is_ok(), out.len()))
        });
    });
    group.finish();
}

criterion_group!(benches, render);
criterion_main!(benches);
