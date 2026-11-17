//! The audit chain against an archive edited after the fact. A stream the sink
//! wrote from arbitrary records verifies as complete. Lines reordered still
//! do. Lines removed, the tail cut off, or a byte of an event line changed
//! never do. Removing a whole stream is out of reach of its chain (ADR 0012),
//! so edits that leave none of it are skipped.
#![no_main]

use creche_fuzz::archive;
use creche_sink::audit::verify;
use libfuzzer_sys::fuzz_target;

/// Bytes at the start of the input that choose the edit.
const EDIT: usize = 8;

/// `line`, a checkpoint, with its `creche.seq.last` set to `last`.
fn stretch(line: &[u8], last: u64) -> Vec<u8> {
    let key = b"\"creche.seq.last\":";
    let Some(at) = line.windows(key.len()).position(|w| w == key) else {
        return line.to_vec();
    };
    let digits = at + key.len();
    let end = digits
        + line[digits..]
            .iter()
            .take_while(|b| b.is_ascii_digit())
            .count();
    [&line[..digits], last.to_string().as_bytes(), &line[end..]].concat()
}

fn is_checkpoint(line: &[u8]) -> bool {
    line.windows(25)
        .any(|w| w == b"\"creche.audit.checkpoint\"")
}

fuzz_target!(|input: &[u8]| {
    if input.len() < EDIT {
        return;
    }
    let (edit, records) = input.split_at(EDIT);
    let out = archive(records);
    let lines: Vec<&[u8]> = out.split_inclusive(|&b| b == b'\n').collect();
    let n = lines.len();
    assert!(verify(&out, None).complete(), "the sink's own archive");

    let at = usize::from(u16::from_le_bytes([edit[1], edit[2]])) % n;
    let count = 1 + usize::from(edit[3]) % n;
    let (tampered, must_fail): (Vec<u8>, bool) = match edit[0] % 4 {
        // Reordered: lines may arrive in any order.
        0 => {
            let mut moved = lines.clone();
            moved.rotate_left(at);
            (moved.concat(), false)
        }
        // Some lines removed, wherever they are.
        1 => {
            let end = (at + count).min(n);
            ([&lines[..at], &lines[end..]].concat().concat(), true)
        }
        // The tail cut off, at any line.
        2 => (lines[..at].concat(), true),
        // One byte of an event line changed, and maybe every checkpoint's
        // range stretched, so it would cover lines that are not there.
        // Checkpoints carry fields that are not checked, so their other bytes
        // are left alone.
        _ => {
            let Some(i) = (0..n)
                .map(|k| (at + k) % n)
                .find(|&i| !is_checkpoint(lines[i]))
            else {
                return;
            };
            let mut line = lines[i].to_vec();
            let pos = usize::from(edit[4]) % line.len();
            line[pos] ^= edit[5].max(1);
            let mut changed: Vec<Vec<u8>> = lines.iter().map(|l| l.to_vec()).collect();
            changed[i] = line;
            if edit[6] & 1 == 1 {
                let last = if edit[7] == u8::MAX {
                    u64::MAX
                } else {
                    u64::try_from(n).unwrap() + u64::from(edit[7])
                };
                for line in changed.iter_mut().filter(|l| is_checkpoint(l)) {
                    *line = stretch(line, last);
                }
            }
            (changed.concat(), true)
        }
    };
    if tampered.is_empty() {
        return;
    }
    let report = verify(&tampered, None);
    if must_fail {
        assert!(
            !report.complete(),
            "edit {:?} went unnoticed: {report}",
            edit[0] % 4
        );
    } else {
        assert!(report.complete(), "{report}");
    }
});
