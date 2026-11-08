//! Turning a byte stream from one sandbox into output: JSON lines, or the
//! records themselves in frames (see [`Format::Raw`]).

use std::time::{SystemTime, UNIX_EPOCH};

use creche_wire::{Body, DecodeError, Records};

use crate::json;
use crate::tasks::{TaskInfo, Tasks};

/// What the sink writes for each stream.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Format {
    /// One JSON object per event, with OpenTelemetry attribute names.
    #[default]
    Json,
    /// The validated records unchanged, in frames that name their sandbox, for
    /// consumers that decode the creche wire format themselves. A frame is a
    /// native-endian `u16` length and that many bytes of sandbox id, then a
    /// native-endian `u32` length and that many bytes of whole records. Task
    /// records are included, so a consumer can keep process context itself.
    Raw,
}

/// Decodes one connection's stream. Only an incomplete trailing record is ever
/// copied. Complete records are decoded straight from the input.
#[derive(Debug, Default)]
pub struct StreamDecoder {
    format: Format,
    /// Incomplete record carried over from the previous input.
    pending: Vec<u8>,
    /// Context of the stream's processes, from its task records (JSON only).
    tasks: Tasks,
}

impl StreamDecoder {
    /// A decoder writing `format`.
    #[must_use]
    pub fn new(format: Format) -> Self {
        Self {
            format,
            ..Self::default()
        }
    }

    /// Decodes the complete records available after appending `data` and writes
    /// them to `out` in the decoder's format. Records are stamped with the
    /// current wall clock as their observed time.
    ///
    /// # Errors
    ///
    /// When the stream is corrupt. The connection should then be dropped.
    pub fn feed(
        &mut self,
        data: &[u8],
        sandbox: &str,
        out: &mut Vec<u8>,
    ) -> Result<(), DecodeError> {
        self.feed_at(data, sandbox, now_ns(), out)
    }

    /// [`StreamDecoder::feed`] with an explicit observed time, in nanoseconds
    /// since the Unix epoch.
    ///
    /// # Errors
    ///
    /// When the stream is corrupt. The connection should then be dropped.
    pub fn feed_at(
        &mut self,
        data: &[u8],
        sandbox: &str,
        observed_ns: u64,
        out: &mut Vec<u8>,
    ) -> Result<(), DecodeError> {
        let format = self.format;
        if self.pending.is_empty() {
            let used = write_all(format, data, sandbox, observed_ns, &mut self.tasks, out)?;
            self.pending
                .extend_from_slice(data.get(used..).unwrap_or_default());
        } else {
            self.pending.extend_from_slice(data);
            let used = write_all(
                format,
                &self.pending,
                sandbox,
                observed_ns,
                &mut self.tasks,
                out,
            )?;
            self.pending.drain(..used);
        }
        Ok(())
    }

    /// Bytes of an incomplete record waiting for more input.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.pending.len()
    }
}

/// Nanoseconds since the Unix epoch, 0 if the clock is before it.
fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

/// Writes every complete record in `buf` and returns the bytes they took.
fn write_all(
    format: Format,
    buf: &[u8],
    sandbox: &str,
    observed_ns: u64,
    tasks: &mut Tasks,
    out: &mut Vec<u8>,
) -> Result<usize, DecodeError> {
    match format {
        Format::Json => render_all(buf, sandbox, observed_ns, tasks, out),
        Format::Raw => frame_all(buf, sandbox, out),
    }
}

/// Renders every complete record in `buf` as a JSON line and returns the bytes
/// they took. Task records update the process contexts instead of being rendered.
fn render_all(
    buf: &[u8],
    sandbox: &str,
    observed_ns: u64,
    tasks: &mut Tasks,
    out: &mut Vec<u8>,
) -> Result<usize, DecodeError> {
    let mut records = Records::new(buf);
    for record in &mut records {
        let record = record?;
        let pid = record.header.pid;
        match record.body {
            Body::Task { context, cgroup } => tasks.set(pid, TaskInfo::new(&context, cgroup)),
            Body::Exec { context, .. } => {
                tasks.exec(pid, &context);
                json::render(sandbox, &record, tasks.get(pid), observed_ns, out);
            }
            Body::Fork { ppid } => {
                tasks.fork(ppid, pid);
                json::render(sandbox, &record, tasks.get(pid), observed_ns, out);
            }
            Body::Exit { .. } => {
                json::render(sandbox, &record, tasks.get(pid), observed_ns, out);
                tasks.exit(pid);
            }
            _ => json::render(sandbox, &record, tasks.get(pid), observed_ns, out),
        }
    }
    Ok(records.consumed())
}

/// Validates the complete records in `buf`, writes them as one frame (see
/// [`Format::Raw`]) and returns the bytes they took. Writes nothing when no
/// record is complete yet.
fn frame_all(buf: &[u8], sandbox: &str, out: &mut Vec<u8>) -> Result<usize, DecodeError> {
    let mut records = Records::new(buf);
    for record in &mut records {
        record?;
    }
    let used = records.consumed();
    if used > 0 {
        // A sandbox id longer than u16::MAX is cut, and a frame holds at most
        // u32::MAX bytes. Reads are 64 KiB, so neither happens in practice.
        let id = sandbox.as_bytes();
        let id = id.get(..usize::from(u16::MAX)).unwrap_or(id);
        let records = buf.get(..used).unwrap_or_default();
        out.extend_from_slice(&u16::try_from(id.len()).unwrap_or(u16::MAX).to_ne_bytes());
        out.extend_from_slice(id);
        out.extend_from_slice(
            &u32::try_from(records.len())
                .unwrap_or(u32::MAX)
                .to_ne_bytes(),
        );
        out.extend_from_slice(records);
    }
    Ok(used)
}

#[cfg(test)]
mod tests {
    use super::*;
    use creche_wire::{HEARTBEAT_LEN, Header, HeartbeatRecord, Kind};
    use proptest::prelude::*;
    use zerocopy::IntoBytes as _;

    fn heartbeat(n: u64) -> Vec<u8> {
        HeartbeatRecord {
            header: Header::for_observer(Kind::Heartbeat, HEARTBEAT_LEN, 1, n),
            cpu_ms: n,
            ..HeartbeatRecord::default()
        }
        .as_bytes()
        .to_vec()
    }

    fn stream(count: u64) -> Vec<u8> {
        (0..count).flat_map(heartbeat).collect()
    }

    #[test]
    fn whole_stream_at_once() {
        let mut d = StreamDecoder::default();
        let mut out = Vec::new();
        d.feed_at(&stream(3), "sb", 7, &mut out).unwrap();
        assert_eq!(std::str::from_utf8(&out).unwrap().lines().count(), 3);
        assert_eq!(d.pending(), 0);
    }

    #[test]
    fn an_incomplete_record_is_kept_until_the_rest_arrives() {
        let mut d = StreamDecoder::default();
        let mut out = Vec::new();
        let rec = heartbeat(1);
        d.feed_at(&rec[..10], "sb", 7, &mut out).unwrap();
        assert_eq!(d.pending(), 10);
        assert_eq!(out, b"");
        d.feed_at(&rec[10..], "sb", 7, &mut out).unwrap();
        assert_eq!(d.pending(), 0);
        assert_ne!(out, b"");
    }

    #[test]
    fn corrupt_stream_is_an_error() {
        let mut bad = heartbeat(1);
        bad[2..4].copy_from_slice(&3_u16.to_ne_bytes());
        let mut out = Vec::new();
        assert_eq!(
            StreamDecoder::default().feed_at(&bad, "sb", 7, &mut out),
            Err(DecodeError::BadLength { len: 3 })
        );
    }

    #[test]
    fn corruption_after_a_partial_record_is_an_error() {
        let mut d = StreamDecoder::default();
        let mut out = Vec::new();
        let rec = heartbeat(1);
        d.feed_at(&rec[..10], "sb", 7, &mut out).unwrap();
        let mut rest = rec[10..].to_vec();
        rest.extend_from_slice(&[0xff; 60]);
        assert!(d.feed_at(&rest, "sb", 7, &mut out).is_err());
    }

    /// A record of `kind` for `pid` with `body` after the header.
    fn rec(kind: Kind, pid: u32, body: &[u8]) -> Vec<u8> {
        let len = u16::try_from(size_of::<Header>() + body.len()).unwrap();
        let header = Header {
            kind: kind.code(),
            len,
            pid,
            ts_ns: 1,
        };
        [header.as_bytes(), body].concat()
    }

    fn task(pid: u32, parent: u32, comm: &[u8; 16], cgroup: &[u8]) -> Vec<u8> {
        let body = [
            &parent.to_ne_bytes()[..],
            &1000_u32.to_ne_bytes(),
            &9_u64.to_ne_bytes(),
            comm,
            cgroup,
        ]
        .concat();
        rec(Kind::Task, pid, &body)
    }

    fn lines(out: &[u8]) -> Vec<serde_json::Value> {
        out.split(|&b| b == b'\n')
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_slice(l).unwrap())
            .collect()
    }

    #[test]
    fn records_get_their_process_context() {
        let sh = *b"sh\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        let ls = *b"ls\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        let open = [&8_u32.to_ne_bytes()[..], b"/tmp/f\0\0"].concat();
        // An exec carries the new context (here the name), but not the cgroup name.
        let exec = [
            &10_u32.to_ne_bytes()[..],
            &1000_u32.to_ne_bytes(),
            &9_u64.to_ne_bytes(),
            &ls,
            &3_u16.to_ne_bytes(),
            &0_u16.to_ne_bytes(),
            b"/l\0",
        ]
        .concat();
        let data = [
            task(10, 1, &sh, b"pod-a\0"),
            rec(Kind::OpenWrite, 10, &open),
            rec(
                Kind::Fork,
                11,
                &[&10_u32.to_ne_bytes()[..], &[0; 4]].concat(),
            ),
            rec(Kind::Exec, 11, &exec),
            rec(Kind::Exit, 11, &[0; 8]),
            rec(Kind::OpenWrite, 11, &open),
        ]
        .concat();
        let mut out = Vec::new();
        StreamDecoder::default()
            .feed_at(&data, "sb", 7, &mut out)
            .unwrap();
        let l = lines(&out);
        let summary: Vec<_> = l
            .iter()
            .map(|v| {
                (
                    v["event.name"].as_str().unwrap().to_owned(),
                    v["process.pid"].as_u64(),
                    v["process.parent_pid"].as_u64(),
                    v["process.executable.name"].as_str().map(str::to_owned),
                )
            })
            .collect();
        let s = |t: &str, pid, ppid, comm: Option<&str>| {
            (t.to_owned(), Some(pid), ppid, comm.map(str::to_owned))
        };
        assert_eq!(
            summary,
            [
                // Task records are not printed.
                s("creche.file.open_write", 10, Some(1), Some("sh")),
                // The child inherits the parent's context, with the parent as ppid.
                s("creche.process.fork", 11, Some(10), Some("sh")),
                s("creche.process.exec", 11, Some(10), Some("ls")),
                s("creche.process.exit", 11, Some(10), Some("ls")),
                // After the exit the pid is unknown again.
                s("creche.file.open_write", 11, None, None),
            ]
        );
        assert_eq!(l[0]["creche.cgroup.name"], "pod-a");
        assert_eq!(l[0]["process.real_user.id"], 1000);
        // The child kept the cgroup name it inherited.
        assert_eq!(l[2]["creche.cgroup.name"], "pod-a");
    }

    #[test]
    fn feed_stamps_records_with_the_wall_clock() {
        let before = now_ns();
        let mut out = Vec::new();
        StreamDecoder::default()
            .feed(&heartbeat(1), "sb", &mut out)
            .unwrap();
        let after = now_ns();
        let line: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let observed = line["observed_time_unix_nano"].as_u64().unwrap();
        // After 2020-01-01, and taken during the call.
        assert!(before > 1_577_836_800_000_000_000);
        assert!((before..=after).contains(&observed));
    }

    /// Splits raw output into (sandbox, records) frames.
    fn frames(mut out: &[u8]) -> Vec<(String, Vec<u8>)> {
        let mut frames = Vec::new();
        while !out.is_empty() {
            let id_len = usize::from(u16::from_ne_bytes([out[0], out[1]]));
            let id = String::from_utf8(out[2..2 + id_len].to_vec()).unwrap();
            out = &out[2 + id_len..];
            let len = u32::from_ne_bytes(out[..4].try_into().unwrap()) as usize;
            frames.push((id, out[4..4 + len].to_vec()));
            out = &out[4 + len..];
        }
        frames
    }

    #[test]
    fn raw_output_frames_whole_records_with_their_sandbox() {
        let data = stream(3);
        let mut d = StreamDecoder::new(Format::Raw);
        let mut out = Vec::new();
        // The first chunk ends inside the second record: only the first is framed.
        d.feed_at(&data[..100], "sb-1", 7, &mut out).unwrap();
        d.feed_at(&data[100..], "sb-1", 7, &mut out).unwrap();
        let got = frames(&out);
        assert_eq!(got.len(), 2);
        assert!(got.iter().all(|(id, _)| id == "sb-1"));
        let records: Vec<u8> = got.into_iter().flat_map(|(_, r)| r).collect();
        assert_eq!(records, data);
        assert_eq!(d.pending(), 0);
    }

    #[test]
    fn raw_output_writes_nothing_until_a_record_is_complete_and_rejects_corruption() {
        let rec = heartbeat(1);
        let mut d = StreamDecoder::new(Format::Raw);
        let mut out = Vec::new();
        d.feed_at(&rec[..10], "sb", 7, &mut out).unwrap();
        assert_eq!(out, b"");
        let mut bad = heartbeat(1);
        bad[2..4].copy_from_slice(&3_u16.to_ne_bytes());
        assert!(
            StreamDecoder::new(Format::Raw)
                .feed_at(&bad, "sb", 7, &mut out)
                .is_err()
        );
        assert_eq!(out, b"");
    }

    proptest! {
        /// However the stream is split into reads, raw frames carry the same
        /// records, each whole.
        #[test]
        fn raw_chunking_keeps_records_whole(count in 0_u64..20, cuts in proptest::collection::vec(any::<prop::sample::Index>(), 0..10)) {
            let data = stream(count);
            let mut offsets: Vec<usize> = cuts.iter().map(|i| i.index(data.len() + 1)).collect();
            offsets.sort_unstable();
            let mut d = StreamDecoder::new(Format::Raw);
            let mut out = Vec::new();
            let mut start = 0;
            for end in offsets.into_iter().chain([data.len()]) {
                d.feed_at(&data[start..end], "sb", 7, &mut out).unwrap();
                start = end;
            }
            let mut joined = Vec::new();
            for (_, records) in frames(&out) {
                // Every frame holds only whole records.
                let mut r = creche_wire::Records::new(&records);
                for record in &mut r {
                    prop_assert!(record.is_ok());
                }
                prop_assert_eq!(r.consumed(), records.len());
                joined.extend_from_slice(&records);
            }
            prop_assert_eq!(joined, data);
        }


        /// However the stream is split into reads, the output is the same as
        /// decoding it in one go.
        #[test]
        fn chunking_does_not_change_the_output(count in 0_u64..20, cuts in proptest::collection::vec(any::<prop::sample::Index>(), 0..10)) {
            let data = stream(count);
            let mut whole = Vec::new();
            StreamDecoder::default().feed_at(&data, "sb", 7, &mut whole).unwrap();

            let mut offsets: Vec<usize> = cuts.iter().map(|i| i.index(data.len() + 1)).collect();
            offsets.sort_unstable();
            let mut d = StreamDecoder::default();
            let mut chunked = Vec::new();
            let mut start = 0;
            for end in offsets.into_iter().chain([data.len()]) {
                d.feed_at(&data[start..end], "sb", 7, &mut chunked).unwrap();
                start = end;
            }
            prop_assert_eq!(chunked, whole);
            prop_assert_eq!(d.pending(), 0);
        }
    }
}
