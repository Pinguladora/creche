//! Writes seed inputs into `corpus/<target>/`: a sample stream and records
//! with every variable-length field at its maximum, made of bytes that JSON
//! must escape. The fuzzer starts from valid records instead of finding the
//! header layout on its own.

use std::fs;
use std::path::Path;

use creche_sink::json::Origin;
use creche_sink::stream::{Format, StreamDecoder};
use creche_wire::{
    ARGS_LEN, CGROUP_LEN, CGROUP_PATH_LEN, Header, Kind, LABEL_KEY_LEN, LABEL_VALUE_LEN,
    MAX_LABELS, MAX_RECORD_LEN, PATH_LEN, encode_cgroup, sample,
};
use zerocopy::IntoBytes as _;

/// A record of `kind` for pid 7 with `body` after its header.
fn record(kind: Kind, body: &[&[u8]]) -> Vec<u8> {
    let len = size_of::<Header>() + body.iter().map(|part| part.len()).sum::<usize>();
    let header = Header {
        kind: kind.code(),
        len: u16::try_from(len).unwrap(),
        pid: 7,
        ts_ns: 1,
    };
    let mut rec = header.as_bytes().to_vec();
    for part in body {
        rec.extend_from_slice(part);
    }
    rec
}

/// Context fields shared by task and exec records: ppid, uid, cgroup id, name.
fn context() -> Vec<u8> {
    let mut c = Vec::new();
    c.extend_from_slice(&1_u32.to_ne_bytes());
    c.extend_from_slice(&0_u32.to_ne_bytes());
    c.extend_from_slice(&9_u64.to_ne_bytes());
    c.extend_from_slice(&[0x01; 16]);
    c
}

/// The archive a sink writes for one stream of `records`.
fn archive(records: &[u8]) -> Vec<u8> {
    let origin = Origin::from("sb").with_stream("s1");
    let mut decoder = StreamDecoder::new(Format::Json).with_audit();
    let mut out = Vec::new();
    decoder.event(&origin, "creche.stream.start", 1, &[], &mut out);
    let _ = decoder.feed_at(records, &origin, 2, &mut out);
    decoder.event(&origin, "creche.stream.end", 3, &[], &mut out);
    decoder.finish(&origin, 3, &mut out);
    out
}

fn main() {
    let control = [0x01_u8; PATH_LEN + ARGS_LEN];
    let task = record(Kind::Task, &[&context(), &control[..CGROUP_LEN]]);
    let path_len = u16::try_from(PATH_LEN).unwrap().to_ne_bytes();
    let args_len = u16::try_from(ARGS_LEN).unwrap().to_ne_bytes();
    let exec = record(
        Kind::Exec,
        &[
            &context(),
            &path_len,
            &args_len,
            &control[..PATH_LEN + ARGS_LEN],
        ],
    );
    let open_len = u32::try_from(PATH_LEN).unwrap().to_ne_bytes();
    let open = record(Kind::OpenWrite, &[&open_len, &control[..PATH_LEN]]);
    let fork = record(Kind::Fork, &[&1_u32.to_ne_bytes(), &[0; 4]]);
    // The task's cgroup, described first: the longest path and every label at
    // its longest, with values JSON must escape.
    let keys: Vec<String> = (0..MAX_LABELS)
        .map(|i| format!("{i}{}", "k".repeat(LABEL_KEY_LEN - 1)))
        .collect();
    let value = "\"\\".repeat(LABEL_VALUE_LEN / 2);
    let labels: Vec<(&[u8], &[u8])> = keys
        .iter()
        .map(|k| (k.as_bytes(), value.as_bytes()))
        .collect();
    let mut cgroup = vec![0; MAX_RECORD_LEN];
    let len = encode_cgroup(7, 1, 9, 0, &[b'"'; CGROUP_PATH_LEN], &labels, &mut cgroup).unwrap();
    cgroup.truncate(len);
    let seeds = [
        sample::stream(8),
        [task.clone(), exec].concat(),
        [task.clone(), fork.clone(), open].concat(),
        [cgroup, task, fork].concat(),
    ];

    let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus");
    // verify_tamper reads its edit from the first 8 bytes, verify_report an
    // archive the sink wrote.
    for (target, prefix) in [("verify_tamper", &[1_u8, 9, 0, 2, 5, 1, 0, 0][..])] {
        let dir = corpus.join(target);
        fs::create_dir_all(&dir).unwrap();
        for (i, seed) in seeds.iter().enumerate() {
            fs::write(dir.join(format!("seed-{i}")), [prefix, seed].concat()).unwrap();
        }
    }
    let dir = corpus.join("verify_report");
    fs::create_dir_all(&dir).unwrap();
    for (i, seed) in seeds.iter().enumerate() {
        fs::write(dir.join(format!("seed-{i}")), archive(seed)).unwrap();
    }
    for target in ["decode", "sink_stream"] {
        let dir = corpus.join(target);
        fs::create_dir_all(&dir).unwrap();
        for (i, seed) in seeds.iter().enumerate() {
            // sink_stream reads its chunk size from the first byte.
            let input = if target == "sink_stream" {
                [&[7][..], seed].concat()
            } else {
                seed.clone()
            };
            fs::write(dir.join(format!("seed-{i}")), input).unwrap();
        }
    }
}
