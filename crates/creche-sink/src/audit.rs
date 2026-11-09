//! Tamper evidence for the sink's output.
//!
//! Every line of a stream carries `creche.seq`, its place in the stream from 0.
//! Once [`CHECKPOINT_LINES`] lines are not yet covered, or [`CHECKPOINT_NS`]
//! after the first of them, and when the stream ends, the sink writes a
//! `creche.audit.checkpoint` line after the input it is decoding. It covers the lines since the previous one,
//! `creche.seq.first` to `creche.seq.last`, with
//! `creche.audit.hash = SHA-256(previous hash || the exact bytes of those lines)`.
//! The first checkpoint's previous hash is 32 zero bytes. Checkpoint lines are
//! not hashed themselves.
//!
//! A gap in `creche.seq` shows a removed line, and a hash that does not match
//! shows a changed, reordered or inserted one. The chain is only as strong as the
//! place its checkpoints are kept: whoever can rewrite every checkpoint can
//! rewrite the lines. [`verify`] checks a file of sink output.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::mem;

use miniserde::{Deserialize, json};
use sha2::{Digest as _, Sha256};

use crate::json::{Origin, Value, sink_event};

/// Uncovered lines that make a checkpoint due. It is written after the input
/// that crossed the mark, so it may cover a few more.
pub const CHECKPOINT_LINES: u64 = 256;
/// How long the first uncovered line waits before a checkpoint is due, checked
/// whenever the stream has new input.
pub const CHECKPOINT_NS: u64 = 1_000_000_000;

/// The audit chain of one stream.
#[derive(Debug)]
pub struct Chain {
    /// Hash of the lines since the last checkpoint, seeded with `prev`.
    hasher: Sha256,
    /// The last checkpoint's hash, zero before the first.
    prev: [u8; 32],
    /// First line not yet covered by a checkpoint.
    first: u64,
    /// One past the last line hashed.
    next: u64,
    /// When the first line not yet covered was hashed.
    since_ns: Option<u64>,
}

impl Default for Chain {
    fn default() -> Self {
        let prev = [0; 32];
        Self {
            hasher: seeded(&prev),
            prev,
            first: 0,
            next: 0,
            since_ns: None,
        }
    }
}

fn seeded(prev: &[u8; 32]) -> Sha256 {
    let mut hasher = Sha256::new();
    hasher.update(prev);
    hasher
}

impl Chain {
    /// Hashes `lines`, the bytes of the stream's lines up to, not including,
    /// line `next`, written at `now_ns`.
    pub fn absorb(&mut self, lines: &[u8], next: u64, now_ns: u64) {
        if lines.is_empty() {
            return;
        }
        self.hasher.update(lines);
        self.next = next;
        self.since_ns.get_or_insert(now_ns);
    }

    /// Whether a checkpoint is due at `now_ns`.
    #[must_use]
    pub fn due(&self, now_ns: u64) -> bool {
        let pending = self.next.saturating_sub(self.first);
        pending >= CHECKPOINT_LINES
            || self
                .since_ns
                .is_some_and(|since| now_ns.saturating_sub(since) >= CHECKPOINT_NS)
    }

    /// Writes a checkpoint for the lines hashed since the last one, if any.
    pub fn checkpoint(&mut self, origin: &Origin, now_ns: u64, out: &mut Vec<u8>) {
        if self.next == self.first {
            return;
        }
        let hasher = mem::replace(&mut self.hasher, Sha256::new());
        let hash: [u8; 32] = hasher.finalize().into();
        sink_event(
            origin,
            "creche.audit.checkpoint",
            now_ns,
            None,
            &[
                ("creche.seq.first", Value::Num(self.first)),
                ("creche.seq.last", Value::Num(self.next.saturating_sub(1))),
                ("creche.audit.prev", Value::Str(&hex(&self.prev))),
                ("creche.audit.hash", Value::Str(&hex(&hash))),
            ],
            out,
        );
        self.prev = hash;
        self.hasher = seeded(&hash);
        self.first = self.next;
        self.since_ns = None;
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::with_capacity(64), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// The fields of an output line the verifier reads. Others are skipped.
#[derive(Deserialize)]
struct Entry {
    #[serde(rename = "creche.stream.id")]
    stream: Option<String>,
    #[serde(rename = "event.name")]
    event: Option<String>,
    #[serde(rename = "creche.seq")]
    seq: Option<u64>,
    #[serde(rename = "creche.seq.first")]
    first: Option<u64>,
    #[serde(rename = "creche.seq.last")]
    last: Option<u64>,
    #[serde(rename = "creche.audit.prev")]
    prev: Option<String>,
    #[serde(rename = "creche.audit.hash")]
    hash: Option<String>,
}

/// A checkpoint as read back.
struct Checkpoint {
    first: u64,
    last: u64,
    prev: String,
    hash: String,
}

/// What [`verify`] found in one stream.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct StreamReport {
    /// Lines with a sequence number.
    pub lines: u64,
    /// Checkpoints that matched.
    pub checkpoints: u64,
    /// Lines covered by a matching checkpoint.
    pub verified: u64,
    /// Whether the stream's end event is present.
    pub ended: bool,
    /// Everything that does not add up. Empty when the stream is intact.
    pub problems: Vec<String>,
}

/// What [`verify`] found, per stream id.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Per stream.
    pub streams: BTreeMap<String, StreamReport>,
    /// Lines that belong to no stream, such as refused connections.
    pub outside: u64,
    /// Lines that are not JSON objects.
    pub unreadable: u64,
}

impl Report {
    /// Whether every stream is intact and every line was readable.
    #[must_use]
    pub fn intact(&self) -> bool {
        self.unreadable == 0 && self.streams.values().all(|s| s.problems.is_empty())
    }
}

/// Checks the audit chains in `output`, the bytes the sink wrote. Lines of
/// different streams may be interleaved and each stream's lines may be in any
/// order, but their bytes must be unchanged.
#[must_use]
pub fn verify(output: &[u8]) -> Report {
    let mut report = Report::default();
    let mut lines: BTreeMap<String, Vec<(u64, &[u8])>> = BTreeMap::new();
    let mut checkpoints: BTreeMap<String, Vec<Checkpoint>> = BTreeMap::new();
    for line in output.split_inclusive(|&b| b == b'\n') {
        let entry = std::str::from_utf8(line)
            .ok()
            .and_then(|text| json::from_str::<Entry>(text).ok());
        let Some(entry) = entry else {
            report.unreadable = report.unreadable.saturating_add(1);
            continue;
        };
        let Some(stream) = entry.stream else {
            report.outside = report.outside.saturating_add(1);
            continue;
        };
        let event = entry.event.unwrap_or_default();
        let status = report.streams.entry(stream.clone()).or_default();
        if event == "creche.stream.end" {
            status.ended = true;
        }
        if event == "creche.audit.checkpoint" {
            if let (Some(first), Some(last), Some(prev), Some(hash)) =
                (entry.first, entry.last, entry.prev, entry.hash)
            {
                checkpoints.entry(stream).or_default().push(Checkpoint {
                    first,
                    last,
                    prev,
                    hash,
                });
            } else {
                status
                    .problems
                    .push("checkpoint with missing fields".into());
            }
        } else if let Some(seq) = entry.seq {
            lines.entry(stream).or_default().push((seq, line));
        } else {
            status
                .problems
                .push(format!("{event} line without creche.seq"));
        }
    }
    for (stream, status) in &mut report.streams {
        let mut stream_lines = lines.remove(stream).unwrap_or_default();
        let mut stream_checkpoints = checkpoints.remove(stream).unwrap_or_default();
        check(&mut stream_lines, &mut stream_checkpoints, status);
    }
    report
}

/// Checks one stream's lines against its checkpoints.
fn check(lines: &mut [(u64, &[u8])], checkpoints: &mut [Checkpoint], status: &mut StreamReport) {
    lines.sort_by_key(|(seq, _)| *seq);
    status.lines = u64::try_from(lines.len()).unwrap_or(u64::MAX);
    for (expected, (seq, _)) in (0_u64..).zip(lines.iter()) {
        if *seq != expected {
            status
                .problems
                .push(format!("expected line {expected}, found {seq}"));
            return;
        }
    }
    checkpoints.sort_by_key(|c| c.first);
    let mut prev = [0_u8; 32];
    let mut next = 0_u64;
    for checkpoint in checkpoints.iter() {
        if checkpoint.first != next || checkpoint.last < checkpoint.first {
            status.problems.push(format!(
                "checkpoint covers {} to {}, expected one from {next}",
                checkpoint.first, checkpoint.last
            ));
            return;
        }
        if checkpoint.prev != hex(&prev) {
            status.problems.push(format!(
                "checkpoint from {} does not follow the previous one",
                checkpoint.first
            ));
            return;
        }
        let covered = usize::try_from(checkpoint.first)
            .ok()
            .zip(usize::try_from(checkpoint.last).ok())
            .and_then(|(first, last)| lines.get(first..=last));
        let Some(covered) = covered else {
            status.problems.push(format!(
                "checkpoint covers {} to {}, beyond the lines present",
                checkpoint.first, checkpoint.last
            ));
            return;
        };
        let mut hasher = seeded(&prev);
        for (_, bytes) in covered {
            hasher.update(bytes);
        }
        let hash: [u8; 32] = hasher.finalize().into();
        if checkpoint.hash != hex(&hash) {
            status.problems.push(format!(
                "lines {} to {} do not match their checkpoint",
                checkpoint.first, checkpoint.last
            ));
            return;
        }
        status.checkpoints = status.checkpoints.saturating_add(1);
        prev = hash;
        next = checkpoint.last.saturating_add(1);
    }
    status.verified = next;
    if status.ended && next != status.lines {
        status.problems.push(format!(
            "lines {next} to {} of an ended stream have no checkpoint",
            status.lines.saturating_sub(1)
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origin() -> Origin {
        Origin::from("sb").with_stream("s1")
    }

    /// `n` sink event lines of stream `s1`, from seq `from`, through `chain`,
    /// with checkpoints as they fall due, then a final one.
    fn stream(n: u64) -> Vec<u8> {
        let (origin, mut chain, mut out) = (origin(), Chain::default(), Vec::new());
        for seq in 0..n {
            let start = out.len();
            sink_event(&origin, "creche.test", seq, Some(seq), &[], &mut out);
            let line = out[start..].to_vec();
            chain.absorb(&line, seq + 1, seq);
            if chain.due(seq) {
                chain.checkpoint(&origin, seq, &mut out);
            }
        }
        let start = out.len();
        sink_event(&origin, "creche.stream.end", n, Some(n), &[], &mut out);
        let line = out[start..].to_vec();
        chain.absorb(&line, n + 1, n);
        chain.checkpoint(&origin, n, &mut out);
        out
    }

    fn lines(out: &[u8]) -> Vec<&[u8]> {
        out.split_inclusive(|&b| b == b'\n').collect()
    }

    #[test]
    fn an_untouched_stream_verifies() {
        let out = stream(600);
        let report = verify(&out);
        let s = &report.streams["s1"];
        assert!(report.intact(), "{report:?}");
        assert_eq!(
            (s.lines, s.verified, s.checkpoints, s.ended),
            (601, 601, 3, true)
        );
    }

    #[test]
    fn lines_may_arrive_in_any_order() {
        let out = stream(300);
        let mut shuffled = lines(&out);
        shuffled.reverse();
        assert!(verify(&shuffled.concat()).intact());
    }

    #[test]
    fn a_removed_line_is_a_gap() {
        let out = stream(10);
        let mut l = lines(&out);
        l.remove(3);
        let report = verify(&l.concat());
        assert_eq!(report.streams["s1"].problems, ["expected line 3, found 4"]);
    }

    #[test]
    fn a_changed_line_breaks_its_checkpoint() {
        let out = String::from_utf8(stream(10)).unwrap();
        let changed = out.replacen("creche.test", "creche.tesT", 1);
        let report = verify(changed.as_bytes());
        assert_eq!(
            report.streams["s1"].problems,
            ["lines 0 to 10 do not match their checkpoint"]
        );
    }

    #[test]
    fn swapped_lines_break_the_checkpoint() {
        // Same bytes, but their sequence numbers swapped.
        let out = String::from_utf8(stream(10)).unwrap();
        let swapped = out
            .replacen("\"creche.seq\":1,", "\"creche.seq\":X,", 1)
            .replacen("\"creche.seq\":2,", "\"creche.seq\":1,", 1)
            .replacen("\"creche.seq\":X,", "\"creche.seq\":2,", 1);
        assert!(!verify(swapped.as_bytes()).intact());
    }

    #[test]
    fn a_removed_checkpoint_leaves_lines_unverified() {
        let out = stream(600);
        let l: Vec<_> = lines(&out)
            .into_iter()
            .filter(|l| !String::from_utf8_lossy(l).contains("\"creche.seq.first\":512"))
            .collect();
        let report = verify(&l.concat());
        let s = &report.streams["s1"];
        assert_eq!(s.verified, 512);
        assert_eq!(
            s.problems,
            ["lines 512 to 600 of an ended stream have no checkpoint"]
        );
    }

    #[test]
    fn a_forged_checkpoint_does_not_chain() {
        let out = String::from_utf8(stream(600)).unwrap();
        let forged = out.replacen(
            "\"creche.audit.prev\":\"00",
            "\"creche.audit.prev\":\"11",
            1,
        );
        let report = verify(forged.as_bytes());
        assert_eq!(
            report.streams["s1"].problems,
            ["checkpoint from 0 does not follow the previous one"]
        );
    }

    #[test]
    fn checkpoints_fall_due_by_count_and_by_time() {
        let mut chain = Chain::default();
        assert!(!chain.due(u64::MAX));
        chain.absorb(b"x\n", 1, 100);
        assert!(!chain.due(100 + CHECKPOINT_NS - 1));
        assert!(chain.due(100 + CHECKPOINT_NS));
        let mut out = Vec::new();
        chain.checkpoint(&origin(), 0, &mut out);
        assert!(!chain.due(u64::MAX));
        chain.absorb(b"", 9, 0);
        assert!(!chain.due(u64::MAX), "nothing absorbed");
        chain.absorb(&b"x\n".repeat(255), CHECKPOINT_LINES, 0);
        assert!(!chain.due(0));
        chain.absorb(b"x\n", CHECKPOINT_LINES + 1, 0);
        assert!(chain.due(0));
        // A checkpoint with nothing new writes nothing.
        let mut out = Vec::new();
        chain.checkpoint(&origin(), 0, &mut out);
        let len = out.len();
        chain.checkpoint(&origin(), 0, &mut out);
        assert_eq!(out.len(), len);
    }

    #[test]
    fn other_lines_are_counted_apart() {
        let mut out = stream(2);
        sink_event(
            &Origin::from("sb"),
            "creche.sink.refused",
            0,
            None,
            &[],
            &mut out,
        );
        out.extend_from_slice(b"not json\n");
        let report = verify(&out);
        assert_eq!((report.outside, report.unreadable), (1, 1));
        assert!(!report.intact());
    }

    #[test]
    fn hex_is_lowercase_and_padded() {
        assert_eq!(hex(&[0, 1, 0xab, 0xff]), "0001abff");
    }
}
