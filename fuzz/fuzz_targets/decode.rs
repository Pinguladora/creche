//! The wire decoder on arbitrary bytes: it never panics, never reads past its
//! input, agrees with `peek_len`, and keeps every field within its maximum.
#![no_main]

use creche_wire::{ARGS_LEN, Body, CGROUP_LEN, PATH_LEN, Records, decode, peek_len};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut records = Records::new(data);
    let mut at = 0;
    let mut failed = false;
    for record in &mut records {
        assert!(!failed, "records continue after an error");
        let Ok(record) = record else {
            failed = true;
            continue;
        };
        let rest = &data[at..];
        let (again, len) = decode(rest).unwrap().unwrap();
        assert_eq!(again, record);
        assert_eq!(peek_len(rest), Some(len));
        assert_eq!(usize::from(record.header.len), len);
        match record.body {
            Body::Task { cgroup, .. } => assert!(cgroup.len() <= CGROUP_LEN),
            Body::Exec { path, args, .. } => {
                assert!(path.len() <= PATH_LEN);
                assert!(args.len() <= ARGS_LEN);
            }
            Body::OpenWrite { path } => assert!(path.len() <= PATH_LEN),
            _ => {}
        }
        at += len;
    }
    assert_eq!(records.consumed(), at);
    assert!(at <= data.len());
});
