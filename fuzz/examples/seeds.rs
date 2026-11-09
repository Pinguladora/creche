//! Writes seed inputs into `corpus/<target>/`: a sample stream and records
//! with every variable-length field at its maximum, made of bytes that JSON
//! must escape. The fuzzer starts from valid records instead of finding the
//! header layout on its own.

use std::fs;
use std::path::Path;

use creche_wire::{ARGS_LEN, CGROUP_LEN, Header, Kind, PATH_LEN, sample};
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
    let seeds = [
        sample::stream(8),
        [task.clone(), exec].concat(),
        [task, fork, open].concat(),
    ];

    let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus");
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
