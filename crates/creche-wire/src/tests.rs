extern crate std;

use std::vec;
use std::vec::Vec;

use proptest::prelude::*;

use super::*;

const HDR: usize = size_of::<Header>();

fn header(kind: u16, len: usize) -> Header {
    Header {
        kind,
        len: u16::try_from(len).unwrap(),
        pid: 42,
        ts_ns: 7,
    }
}

/// A record of `len` bytes with `fields` written at their offsets.
fn record(kind: Kind, len: usize, fields: &[(usize, &[u8])]) -> Vec<u8> {
    let mut rec = vec![0; len];
    rec[..HDR].copy_from_slice(header(kind.code(), len).as_bytes());
    for (offset, bytes) in fields {
        rec[*offset..offset + bytes.len()].copy_from_slice(bytes);
    }
    rec
}

fn decode_one(buf: &[u8]) -> Record<'_> {
    let (record, len) = decode(buf).unwrap().unwrap();
    assert_eq!(len, buf.len());
    record
}

#[test]
fn kind_codes_round_trip() {
    for kind in [
        Kind::Exec,
        Kind::Fork,
        Kind::Exit,
        Kind::Connect,
        Kind::OpenWrite,
        Kind::Task,
        Kind::Hello,
        Kind::Heartbeat,
    ] {
        assert_eq!(Kind::from_code(kind.code()), Some(kind));
    }
    assert_eq!(Kind::from_code(0), None);
    assert_eq!(Kind::from_code(7), None);
}

/// The context the test task and exec records carry.
const CONTEXT: Context<'static> = Context {
    ppid: 1,
    uid: 1000,
    cgroup_id: 9,
    comm: b"sh",
};

/// The context fields of a record, at the offsets task and exec records share.
fn context_fields(comm: &[u8]) -> [(usize, Vec<u8>); 4] {
    [
        (offset_of!(TaskRecord, ppid), 1_u32.to_ne_bytes().to_vec()),
        (offset_of!(TaskRecord, uid), 1000_u32.to_ne_bytes().to_vec()),
        (
            offset_of!(TaskRecord, cgroup_id),
            9_u64.to_ne_bytes().to_vec(),
        ),
        (offset_of!(TaskRecord, comm), comm.to_vec()),
    ]
}

/// An exec record with `path` and `args` packed after each other.
fn exec(path: &[u8], args: &[u8]) -> Vec<u8> {
    let data = offset_of!(ExecRecord, data);
    let path_len = u16::try_from(path.len()).unwrap().to_ne_bytes();
    let args_len = u16::try_from(args.len()).unwrap().to_ne_bytes();
    let ctx = context_fields(b"sh\0");
    record(
        Kind::Exec,
        data + path.len() + args.len(),
        &[
            (ctx[0].0, &ctx[0].1),
            (ctx[1].0, &ctx[1].1),
            (ctx[2].0, &ctx[2].1),
            (ctx[3].0, &ctx[3].1),
            (offset_of!(ExecRecord, path_len), &path_len),
            (offset_of!(ExecRecord, args_len), &args_len),
            (data, path),
            (data + path.len(), args),
        ],
    )
}

#[test]
fn exec_path_and_args_are_packed() {
    let rec = exec(b"/bin/ls\0", b"ls\0-l\0/tmp\0");
    let r = decode_one(&rec);
    assert_eq!(r.header.pid, 42);
    assert_eq!(
        r.body,
        Body::Exec {
            context: CONTEXT,
            path: b"/bin/ls",
            args: b"ls\0-l\0/tmp",
        }
    );
}

#[test]
fn exec_without_args_or_path() {
    assert_eq!(
        decode_one(&exec(b"/bin/true\0", b"")).body,
        Body::Exec {
            context: CONTEXT,
            path: b"/bin/true",
            args: b""
        }
    );
    assert_eq!(
        decode_one(&exec(b"", b"")).body,
        Body::Exec {
            context: CONTEXT,
            path: b"",
            args: b""
        }
    );
}

#[test]
fn exec_lengths_beyond_the_record_are_truncated() {
    let mut rec = exec(b"/bin/ls\0", b"ls\0");
    rec.pop();
    let len = u16::try_from(rec.len()).unwrap();
    rec[2..4].copy_from_slice(&len.to_ne_bytes());
    assert_eq!(
        decode(&rec),
        Err(DecodeError::Truncated {
            kind: Kind::Exec,
            len,
        })
    );
    for len in [offset_of!(ExecRecord, path_len) + 3, HDR + 4] {
        let rec = record(Kind::Exec, len, &[]);
        assert!(
            matches!(
                decode(&rec),
                Err(DecodeError::Truncated {
                    kind: Kind::Exec,
                    ..
                })
            ),
            "len {len}"
        );
    }
}

/// A task record with its cgroup name cut after the NUL.
fn task(comm: &[u8], cgroup: &[u8]) -> Vec<u8> {
    let at = offset_of!(TaskRecord, cgroup);
    let ctx = context_fields(comm);
    record(
        Kind::Task,
        at + cgroup.len(),
        &[
            (ctx[0].0, &ctx[0].1),
            (ctx[1].0, &ctx[1].1),
            (ctx[2].0, &ctx[2].1),
            (ctx[3].0, &ctx[3].1),
            (at, cgroup),
        ],
    )
}

#[test]
fn task_records_carry_the_context() {
    assert_eq!(
        decode_one(&task(b"sh\0", b"cri-containerd-abc.scope\0")).body,
        Body::Task {
            context: CONTEXT,
            cgroup: b"cri-containerd-abc.scope",
        }
    );
    // A full 16-byte name has no NUL, and the cgroup name may be empty.
    let rec = task(b"0123456789abcdef", b"");
    let r = decode_one(&rec);
    assert!(matches!(
        r.body,
        Body::Task {
            context: Context {
                comm: b"0123456789abcdef",
                ..
            },
            cgroup: b"",
        }
    ));
    let rec = record(Kind::Task, offset_of!(TaskRecord, cgroup) - 1, &[]);
    assert!(matches!(
        decode(&rec),
        Err(DecodeError::Truncated {
            kind: Kind::Task,
            ..
        })
    ));
}

#[test]
fn open_write_path() {
    let path = b"/workspace/notes.txt\0";
    let off = offset_of!(OpenRecord, path);
    let rec = record(Kind::OpenWrite, off + path.len(), &[(off, path)]);
    assert_eq!(
        decode_one(&rec).body,
        Body::OpenWrite {
            path: b"/workspace/notes.txt"
        }
    );
}

#[test]
fn fork_and_exit() {
    let rec = record(
        Kind::Fork,
        size_of::<ForkRecord>(),
        &[(offset_of!(ForkRecord, ppid), &5_u32.to_ne_bytes())],
    );
    assert_eq!(decode_one(&rec).body, Body::Fork { ppid: 5 });
    let rec = record(Kind::Fork, HDR, &[]);
    assert!(matches!(
        decode(&rec),
        Err(DecodeError::Truncated {
            kind: Kind::Fork,
            ..
        })
    ));

    let code = (-3_i32).to_ne_bytes();
    let rec = record(
        Kind::Exit,
        size_of::<ExitRecord>(),
        &[(offset_of!(ExitRecord, exit_code), &code)],
    );
    assert_eq!(decode_one(&rec).body, Body::Exit { code: -3 });

    let rec = record(Kind::Exit, HDR + 2, &[]);
    assert!(matches!(
        decode(&rec),
        Err(DecodeError::Truncated {
            kind: Kind::Exit,
            ..
        })
    ));
}

fn connect(family: u16, daddr: [u8; 16], port: u16) -> Vec<u8> {
    record(
        Kind::Connect,
        size_of::<ConnectRecord>(),
        &[
            (offset_of!(ConnectRecord, family), &family.to_ne_bytes()),
            (offset_of!(ConnectRecord, dport), &port.to_ne_bytes()),
            (offset_of!(ConnectRecord, daddr), &daddr),
        ],
    )
}

#[test]
fn connect_ipv4_ipv6_and_other_families() {
    let mut v4 = [0; 16];
    v4[..4].copy_from_slice(&[10, 43, 0, 10]);
    assert_eq!(
        decode_one(&connect(AF_INET, v4, 53)).body,
        Body::Connect {
            addr: Some(IpAddr::V4(Ipv4Addr::new(10, 43, 0, 10))),
            port: 53,
        }
    );

    let v6 = Ipv6Addr::LOCALHOST.octets();
    assert_eq!(
        decode_one(&connect(AF_INET6, v6, 443)).body,
        Body::Connect {
            addr: Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            port: 443,
        }
    );

    assert_eq!(
        decode_one(&connect(1, v4, 9)).body,
        Body::Connect {
            addr: None,
            port: 9
        }
    );
}

#[test]
fn observer_records_round_trip() {
    let hello = HelloRecord {
        header: Header::for_observer(Kind::Hello, HELLO_LEN, 7, 11),
        version: VERSION,
        flags: HelloFlags::DEDUP.with(HelloFlags::PROCESS_ONLY),
    };
    let r = decode_one(hello.as_bytes());
    assert_eq!(r.header, hello.header);
    assert_eq!(
        r.body,
        Body::Hello {
            version: VERSION,
            flags: hello.flags
        }
    );
    assert!(hello.flags.contains(HelloFlags::DEDUP));
    assert!(!HelloFlags::default().contains(HelloFlags::DEDUP));
    assert_eq!(hello.flags.bits(), 3);

    let hb = HeartbeatRecord {
        header: Header::for_observer(Kind::Heartbeat, HEARTBEAT_LEN, 7, 12),
        ringbuf_drops: 1,
        sent_bytes: 2,
        dropped_bytes: 3,
        rss_kb: 4,
        cpu_ms: 5,
        bpf_run_ns: 6,
        bpf_run_cnt: 7,
    };
    assert_eq!(decode_one(hb.as_bytes()).body, Body::Heartbeat(hb));
}

#[test]
fn observer_headers_carry_their_fields() {
    let h = Header::for_observer(Kind::Hello, HELLO_LEN, 7, 11);
    assert_eq!(
        (h.kind, h.len, h.pid, h.ts_ns),
        (Kind::Hello.code(), HELLO_LEN, 7, 11)
    );
    assert_eq!(
        Header::default(),
        Header {
            kind: 0,
            len: 0,
            pid: 0,
            ts_ns: 0
        }
    );
}

#[test]
fn flags_combine_idempotently() {
    assert_eq!(HelloFlags::DEDUP.with(HelloFlags::DEDUP), HelloFlags::DEDUP);
    assert!(
        HelloFlags::DEDUP
            .with(HelloFlags::PROCESS_ONLY)
            .contains(HelloFlags::DEDUP)
    );
    assert!(!HelloFlags::DEDUP.contains(HelloFlags::PROCESS_ONLY));
}

#[test]
fn unknown_kinds_are_skipped_by_length() {
    let mut rec = vec![0; HDR + 5];
    rec[..HDR].copy_from_slice(header(999, HDR + 5).as_bytes());
    rec[HDR..].copy_from_slice(b"extra");
    assert_eq!(decode_one(&rec).body, Body::Unknown { body: b"extra" });
}

#[test]
fn incomplete_input_needs_more_bytes() {
    let rec = record(Kind::Fork, size_of::<ForkRecord>(), &[]);
    assert_eq!(decode(&rec[..HDR - 1]), Ok(None));
    assert_eq!(decode(&[]), Ok(None));

    let rec = record(Kind::Exit, size_of::<ExitRecord>(), &[]);
    assert_eq!(decode(&rec[..=HDR]), Ok(None));
}

#[test]
fn out_of_bounds_lengths_are_corrupt() {
    for len in [0, 1, HDR - 1, MAX_RECORD_LEN + 1, usize::from(u16::MAX)] {
        let mut rec = vec![0; HDR];
        let mut h = header(Kind::Fork.code(), HDR);
        h.len = u16::try_from(len).unwrap();
        rec.copy_from_slice(h.as_bytes());
        assert_eq!(
            decode(&rec),
            Err(DecodeError::BadLength { len: h.len }),
            "len {len}"
        );
    }
}

#[test]
fn peek_len_reads_only_the_length_field() {
    let rec = record(Kind::Exit, size_of::<ExitRecord>(), &[]);
    assert_eq!(peek_len(&rec), Some(size_of::<ExitRecord>()));
    // The length field is enough, the rest of the record need not be there.
    assert_eq!(peek_len(&rec[..4]), Some(size_of::<ExitRecord>()));
    assert_eq!(peek_len(&rec[..3]), None);
    assert_eq!(peek_len(&[]), None);
    for len in [0, HDR - 1, MAX_RECORD_LEN + 1] {
        let mut h = header(Kind::Fork.code(), HDR);
        h.len = u16::try_from(len).unwrap();
        assert_eq!(peek_len(h.as_bytes()), None, "len {len}");
    }
    let h = header(Kind::Fork.code(), MAX_RECORD_LEN);
    assert_eq!(peek_len(h.as_bytes()), Some(MAX_RECORD_LEN));
}

#[test]
fn boundary_lengths_are_accepted() {
    let rec = header(500, HDR);
    assert!(decode(rec.as_bytes()).unwrap().is_some());

    let mut rec = vec![0; MAX_RECORD_LEN];
    rec[..HDR].copy_from_slice(header(500, MAX_RECORD_LEN).as_bytes());
    assert_eq!(decode(&rec).unwrap().unwrap().1, MAX_RECORD_LEN);
}

#[test]
fn records_iterator_stops_at_partial_record_and_reports_consumed() {
    let fork = record(Kind::Fork, size_of::<ForkRecord>(), &[]);
    let exit = record(Kind::Exit, size_of::<ExitRecord>(), &[]);
    let mut stream = [fork.as_slice(), exit.as_slice()].concat();
    stream.extend_from_slice(&fork[..10]);

    let mut records = Records::new(&stream);
    assert_eq!((&mut records).count(), 2);
    assert_eq!(records.consumed(), fork.len() + exit.len());
}

#[test]
fn records_iterator_yields_one_error_then_stops() {
    let fork = record(Kind::Fork, size_of::<ForkRecord>(), &[]);
    let mut bad = fork.clone();
    bad[2..4].copy_from_slice(&1_u16.to_ne_bytes());
    let stream = [fork.as_slice(), bad.as_slice(), fork.as_slice()].concat();

    let results: Vec<_> = Records::new(&stream).collect();
    assert_eq!(results.len(), 2);
    assert!(results[0].is_ok());
    assert_eq!(results[1], Err(DecodeError::BadLength { len: 1 }));
}

#[test]
fn errors_display() {
    use std::string::ToString;
    assert_eq!(
        DecodeError::BadLength { len: 3 }.to_string(),
        "record length 3 out of bounds"
    );
    assert_eq!(
        DecodeError::Truncated {
            kind: Kind::Exit,
            len: 20
        }
        .to_string(),
        "Exit record truncated to 20 bytes"
    );
}

#[test]
fn until_nul_and_trailing_nuls() {
    assert_eq!(until_nul(b"ab\0cd"), b"ab");
    assert_eq!(until_nul(b"abc"), b"abc");
    assert_eq!(until_nul(b"\0"), b"");
    assert_eq!(trim_trailing_nuls(b"a\0b\0\0"), b"a\0b");
    assert_eq!(trim_trailing_nuls(b"\0\0"), b"");
    assert_eq!(trim_trailing_nuls(b""), b"");
}

proptest! {
    #[test]
    fn arbitrary_bytes_never_panic_or_over_consume(buf in proptest::collection::vec(any::<u8>(), 0..8192)) {
        if let Ok(Some((_, len))) = decode(&buf) {
            prop_assert!(len <= buf.len());
            prop_assert!(len >= HDR);
        }
        // peek_len agrees with decode on every record decode accepts.
        if let Ok(Some((_, len))) = decode(&buf) {
            prop_assert_eq!(peek_len(&buf), Some(len));
        }
        let mut records = Records::new(&buf);
        for _ in &mut records {}
        prop_assert!(records.consumed() <= buf.len());
    }

    #[test]
    fn heartbeats_round_trip(values in any::<[u64; 7]>(), pid in any::<u32>(), ts in any::<u64>()) {
        let [a, b, c, d, e, f, g] = values;
        let hb = HeartbeatRecord {
            header: Header::for_observer(Kind::Heartbeat, HEARTBEAT_LEN, pid, ts),
            ringbuf_drops: a, sent_bytes: b, dropped_bytes: c, rss_kb: d, cpu_ms: e, bpf_run_ns: f, bpf_run_cnt: g,
        };
        let stream = [hb.as_bytes(), hb.as_bytes()].concat();
        let mut records = Records::new(&stream);
        for record in &mut records {
            prop_assert_eq!(record.unwrap().body, Body::Heartbeat(hb));
        }
        prop_assert_eq!(records.consumed(), stream.len());
    }

    #[test]
    fn open_paths_round_trip(path in "/[a-z0-9/._-]{0,200}") {
        let mut bytes = path.clone().into_bytes();
        bytes.push(0);
        let off = offset_of!(OpenRecord, path);
        let rec = record(Kind::OpenWrite, off + bytes.len(), &[(off, &bytes)]);
        prop_assert_eq!(decode_one(&rec).body, Body::OpenWrite { path: path.as_bytes() });
    }

    #[test]
    fn exec_records_round_trip(path in "/[a-z0-9/._-]{0,200}", args in proptest::collection::vec("[a-z0-9-]{1,20}", 0..10)) {
        let mut p = path.clone().into_bytes();
        p.push(0);
        let a: Vec<u8> = args.iter().flat_map(|s| s.bytes().chain([0])).collect();
        let joined = args.join("\0");
        let rec = exec(&p, &a);
        prop_assert_eq!(
            decode_one(&rec).body,
            Body::Exec { context: CONTEXT, path: path.as_bytes(), args: joined.as_bytes() }
        );
    }
}
