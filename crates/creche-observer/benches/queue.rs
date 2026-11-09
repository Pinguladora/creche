//! Queueing and flushing records, the observer's per-event userspace work.

use std::hint::black_box;
use std::io;

use creche_observer::cgroups::Cgroups;
use creche_observer::queue::RecordQueue;
use creche_wire::{peek_cgroup_id, peek_len, sample};
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

/// The records of a sample stream: forks, execs, file writes, connects, exits
/// and a task record every eighth process.
fn stream_records() -> Vec<Vec<u8>> {
    let stream = sample::stream(512);
    let mut records = Vec::new();
    let mut rest = &stream[..];
    while let Some(len) = peek_len(rest) {
        let (record, tail) = rest.split_at(len);
        records.push(record.to_vec());
        rest = tail;
    }
    records
}

/// Forwarding a batch as the observer's loop does, with and without the step
/// that describes each new cgroup. Every cgroup in the stream is described
/// before measuring, as in a running guest, where only a cgroup's first record
/// pays for its description.
fn cgroups(c: &mut Criterion) {
    let records = stream_records();
    let bytes: usize = records.iter().map(Vec::len).sum();
    let mut group = c.benchmark_group("observer");
    group.throughput(Throughput::Bytes(bytes as u64));
    // Each variant has a queue of its own, grown before measuring.
    let warm = |queue: &mut RecordQueue| {
        for record in &records {
            queue.push(record);
        }
        let _ = queue.flush(&mut io::sink());
    };
    let mut cgroups = Cgroups::new(std::env::temp_dir());
    for record in &records {
        if let Some(id) = peek_cgroup_id(record) {
            let _ = cgroups.describe(id, 1, 1);
        }
    }
    let mut queue = RecordQueue::new(1 << 20);
    warm(&mut queue);
    group.bench_function("forward_stream_describing_cgroups", |b| {
        b.iter(|| {
            for record in &records {
                let record = black_box(record);
                if let Some(description) =
                    peek_cgroup_id(record).and_then(|id| cgroups.describe(id, 1, 1))
                {
                    queue.push(description);
                }
                queue.push(record);
            }
            black_box(queue.flush(&mut io::sink()).is_ok())
        });
    });
    let mut queue = RecordQueue::new(1 << 20);
    warm(&mut queue);
    group.bench_function("forward_stream", |b| {
        b.iter(|| {
            for record in &records {
                queue.push(black_box(record));
            }
            black_box(queue.flush(&mut io::sink()).is_ok())
        });
    });
    group.finish();
}

criterion_group!(benches, queue, cgroups);
criterion_main!(benches);
