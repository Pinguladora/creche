//! Queueing and flushing records, the observer's per-event userspace work.

use std::hint::black_box;
use std::io;

use creche_observer::queue::RecordQueue;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};

/// Records of the guest benchmark mix: mostly short file writes, some execs.
fn records() -> Vec<Vec<u8>> {
    [27_usize, 27, 27, 27, 24, 76, 24, 40]
        .iter()
        .map(|&len| {
            let mut r = vec![7_u8; len];
            if let Some(field) = r.get_mut(2..4) {
                field.copy_from_slice(&u16::try_from(len).unwrap_or(0).to_ne_bytes());
            }
            r
        })
        .collect()
}

fn queue(c: &mut Criterion) {
    let records = records();
    let batch: usize = 4096;
    let bytes: usize = records.iter().map(Vec::len).sum::<usize>() * batch / records.len();
    let mut group = c.benchmark_group("observer");
    group.throughput(Throughput::Bytes(bytes as u64));
    let mut queue = RecordQueue::new(1 << 20);
    group.bench_function("push_and_flush_batch", |b| {
        b.iter(|| {
            for record in records.iter().cycle().take(batch) {
                queue.push(black_box(record));
            }
            black_box(queue.flush(&mut io::sink()).is_ok())
        });
    });
    group.finish();
}

criterion_group!(benches, queue);
criterion_main!(benches);
