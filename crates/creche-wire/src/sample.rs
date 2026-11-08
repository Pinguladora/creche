//! Sample record streams for benchmarks (feature `sample`).
//!
//! The mix follows the guest benchmark loops: for each process a fork, an exec
//! carrying its context, file writes, a connect and an exit, with a task record
//! for every eighth process (a context the host has not seen).

extern crate alloc;

use alloc::vec::Vec;
use core::mem::size_of;

use zerocopy::IntoBytes as _;

use crate::{Header, Kind};

/// File writes per process in [`stream`].
pub const OPENS_PER_PROCESS: usize = 15;

/// Appends a record of `kind` for `pid` with `body` after its header.
fn push(out: &mut Vec<u8>, kind: Kind, pid: u32, body: &[&[u8]]) {
    let body_len: usize = body.iter().map(|part| part.len()).sum();
    let len = size_of::<Header>().saturating_add(body_len);
    let header = Header {
        kind: kind.code(),
        len: u16::try_from(len).unwrap_or(u16::MAX),
        pid,
        ts_ns: u64::from(pid),
    };
    out.extend_from_slice(header.as_bytes());
    for part in body {
        out.extend_from_slice(part);
    }
}

/// The context fields task and exec records share: ppid, uid, cgroup id, name.
fn context(ppid: u32, comm: &[u8; 16]) -> [u8; 32] {
    let mut c = [0; 32];
    let fields: [&[u8]; 4] = [
        &ppid.to_ne_bytes(),
        &1000_u32.to_ne_bytes(),
        &7_u64.to_ne_bytes(),
        comm,
    ];
    let mut at: usize = 0;
    for field in fields {
        if let Some(dst) = c.get_mut(at..at.saturating_add(field.len())) {
            dst.copy_from_slice(field);
        }
        at = at.saturating_add(field.len());
    }
    c
}

/// A stream for `processes` processes, each forked from pid 1.
#[must_use]
pub fn stream(processes: u32) -> Vec<u8> {
    const SH: &[u8; 16] = b"sh\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    const NOP: &[u8; 16] = b"nop\0\0\0\0\0\0\0\0\0\0\0\0\0";
    const PATH: &[u8] = b"/bin/nop\0";
    const ARGS: &[u8] = b"nop\0-x\0";
    const FILE: &[u8] = b"/tmp/agent/f\0";

    let path_len = u16::try_from(PATH.len()).unwrap_or(0).to_ne_bytes();
    let args_len = u16::try_from(ARGS.len()).unwrap_or(0).to_ne_bytes();
    let file_len = u32::try_from(FILE.len()).unwrap_or(0).to_ne_bytes();
    let reserved = [0_u8; 4];
    let mut daddr = [0_u8; 16];
    if let Some(v4) = daddr.get_mut(..4) {
        v4.copy_from_slice(&[10, 43, 0, 10]);
    }

    let mut out = Vec::new();
    for i in 0..processes {
        let pid = i.saturating_add(100);
        if i % 8 == 0 {
            push(&mut out, Kind::Task, 1, &[&context(0, SH), b"pod-a\0"]);
        }
        push(
            &mut out,
            Kind::Fork,
            pid,
            &[&1_u32.to_ne_bytes(), &reserved],
        );
        push(
            &mut out,
            Kind::Exec,
            pid,
            &[&context(1, NOP), &path_len, &args_len, PATH, ARGS],
        );
        for _ in 0..OPENS_PER_PROCESS {
            push(&mut out, Kind::OpenWrite, pid, &[&file_len, FILE]);
        }
        push(
            &mut out,
            Kind::Connect,
            pid,
            &[
                &2_u16.to_ne_bytes(),
                &53_u16.to_ne_bytes(),
                &daddr,
                &reserved,
            ],
        );
        push(
            &mut out,
            Kind::Exit,
            pid,
            &[&0_i32.to_ne_bytes(), &reserved],
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Body, Records};

    #[test]
    fn the_sample_stream_decodes_completely() {
        let data = stream(16);
        let mut records = Records::new(&data);
        let mut kinds = [0_usize; 7];
        for record in &mut records {
            let record = record.expect("sample records decode");
            let slot = match record.body {
                Body::Task { .. } => 0,
                Body::Fork { ppid: 1 } => 1,
                Body::Exec {
                    path: b"/bin/nop",
                    args: b"nop\0-x",
                    ..
                } => 2,
                Body::OpenWrite {
                    path: b"/tmp/agent/f",
                } => 3,
                Body::Connect { port: 53, .. } => 4,
                Body::Exit { code: 0 } => 5,
                _ => 6,
            };
            kinds[slot] += 1;
        }
        assert_eq!(records.consumed(), data.len());
        assert_eq!(kinds, [2, 16, 16, 16 * OPENS_PER_PROCESS, 16, 16, 0]);
    }
}
