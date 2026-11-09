//! Turning a byte stream from one sandbox into output: JSON lines, or the
//! records themselves in frames (see [`Format::Raw`]).

use std::time::{SystemTime, UNIX_EPOCH};

use creche_wire::{Body, DecodeError, Records};

use crate::audit::Chain;
use crate::json::{self, Cgroup, Origin, Value};
use crate::k8s::Containers;
use crate::tasks::{Cgroups, TaskInfo, Tasks};

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
    /// What JSON rendering keeps across inputs.
    json: JsonState,
    /// The stream's audit chain, when enabled (JSON only).
    chain: Option<Chain>,
}

/// What JSON rendering keeps across inputs.
#[derive(Debug, Default)]
struct JsonState {
    /// Context of the stream's processes, from its task records.
    tasks: Tasks,
    /// Checks the containers the guest claims, when its pod is known.
    containers: Option<Containers>,
    /// The cgroups the observer described, by id.
    cgroups: Cgroups,
    /// The next line's `creche.seq`.
    seq: u64,
}

/// Returns `*seq` and advances it.
fn next(seq: &mut u64) -> u64 {
    let current = *seq;
    *seq = current.saturating_add(1);
    current
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

    /// Also reports the pod's container each process runs in, as the guest
    /// claims it and `containers` confirms it.
    #[must_use]
    pub fn with_containers(mut self, containers: Containers) -> Self {
        self.json.containers = Some(containers);
        self
    }

    /// Also keeps an audit chain over the JSON lines, with a checkpoint line
    /// whenever one falls due (see [`crate::audit`]).
    #[must_use]
    pub fn with_audit(mut self) -> Self {
        self.chain = Some(Chain::default());
        self
    }

    /// Also keeps an audit chain, signed with keys that start from one `svid`
    /// vouches for. Returns the fields the stream's start line must carry.
    ///
    /// # Errors
    ///
    /// When the system's random source cannot be read.
    pub fn with_signed_audit(
        mut self,
        stream: &str,
        svid: &crate::spiffe::Svid,
    ) -> std::io::Result<(Self, Vec<(&'static str, String)>)> {
        let (chain, fields) = Chain::signed(stream, svid)?;
        self.chain = Some(chain);
        Ok((self, fields))
    }

    /// Writes an event the sink reports about this stream, such as its start or
    /// end, as the stream's next line. Nothing in the raw format.
    pub fn event(
        &mut self,
        origin: &Origin,
        name: &str,
        observed_ns: u64,
        fields: &[(&str, Value<'_>)],
        out: &mut Vec<u8>,
    ) {
        if self.format != Format::Json {
            return;
        }
        let start = out.len();
        let seq = next(&mut self.json.seq);
        json::sink_event(origin, name, observed_ns, Some(seq), fields, out);
        self.audit(origin, observed_ns, start, out);
    }

    /// Writes the last checkpoint, covering every line so far. For when the
    /// stream ends.
    pub fn finish(&mut self, origin: &Origin, observed_ns: u64, out: &mut Vec<u8>) {
        if let Some(chain) = &mut self.chain {
            chain.checkpoint(origin, observed_ns, out);
        }
    }

    /// Hashes the lines written to `out` since `start`, then writes a checkpoint
    /// if one is due.
    fn audit(&mut self, origin: &Origin, observed_ns: u64, start: usize, out: &mut Vec<u8>) {
        if let Some(chain) = &mut self.chain {
            chain.absorb(
                out.get(start..).unwrap_or_default(),
                self.json.seq,
                observed_ns,
            );
            if chain.due(observed_ns) {
                chain.checkpoint(origin, observed_ns, out);
            }
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
        origin: &Origin,
        out: &mut Vec<u8>,
    ) -> Result<(), DecodeError> {
        self.feed_at(data, origin, now_ns(), out)
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
        origin: &Origin,
        observed_ns: u64,
        out: &mut Vec<u8>,
    ) -> Result<(), DecodeError> {
        let format = self.format;
        let start = out.len();
        // Lines written before a corrupt record are valid and stay in `out`,
        // so they are hashed either way.
        let result = if self.pending.is_empty() {
            write_all(format, data, origin, observed_ns, &mut self.json, out).map(|used| {
                self.pending
                    .extend_from_slice(data.get(used..).unwrap_or_default());
            })
        } else {
            self.pending.extend_from_slice(data);
            write_all(
                format,
                &self.pending,
                origin,
                observed_ns,
                &mut self.json,
                out,
            )
            .map(|used| drop(self.pending.drain(..used)))
        };
        if format == Format::Json {
            self.audit(origin, observed_ns, start, out);
        }
        result
    }

    /// Bytes of an incomplete record waiting for more input.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.pending.len()
    }
}

/// Nanoseconds since the Unix epoch, 0 if the clock is before it.
pub(crate) fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

/// Writes every complete record in `buf` and returns the bytes they took.
fn write_all(
    format: Format,
    buf: &[u8],
    origin: &Origin,
    observed_ns: u64,
    state: &mut JsonState,
    out: &mut Vec<u8>,
) -> Result<usize, DecodeError> {
    match format {
        Format::Json => render_all(buf, origin, observed_ns, state, out),
        Format::Raw => frame_all(buf, origin.id(), out),
    }
}

/// Renders every complete record in `buf` as a JSON line and returns the bytes
/// they took. Task records update the process contexts instead of being rendered.
fn render_all(
    buf: &[u8],
    origin: &Origin,
    observed_ns: u64,
    state: &mut JsonState,
    out: &mut Vec<u8>,
) -> Result<usize, DecodeError> {
    let mut records = Records::new(buf);
    for record in &mut records {
        let record = record?;
        let pid = record.header.pid;
        match record.body {
            Body::Task { context, cgroup } => {
                let mut info = TaskInfo::new(&context, cgroup);
                info.cgroup_info = state.cgroups.get(context.cgroup_id);
                if let Some(containers) = state.containers.as_mut() {
                    // The path, when known, names the container a nested
                    // cgroup sits in. The leaf name alone does not.
                    let scope = info
                        .cgroup_info
                        .as_ref()
                        .map_or(&*info.cgroup, |c| c.container_scope());
                    info.container = containers.claim(scope);
                }
                state.tasks.set(pid, info);
            }
            Body::Cgroup {
                cgroup_id,
                owner_uid,
                path,
                labels,
            } => state
                .cgroups
                .set(cgroup_id, Cgroup::new(path, owner_uid, labels)),
            Body::Exec { context, .. } => {
                state.tasks.exec(pid, &context);
                let seq = next(&mut state.seq);
                json::render(origin, &record, state.tasks.get(pid), observed_ns, seq, out);
            }
            Body::Fork { ppid } => {
                state.tasks.fork(ppid, pid);
                let seq = next(&mut state.seq);
                json::render(origin, &record, state.tasks.get(pid), observed_ns, seq, out);
            }
            Body::Exit { .. } => {
                let seq = next(&mut state.seq);
                json::render(origin, &record, state.tasks.get(pid), observed_ns, seq, out);
                state.tasks.exit(pid);
            }
            _ => {
                let seq = next(&mut state.seq);
                json::render(origin, &record, state.tasks.get(pid), observed_ns, seq, out);
            }
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
        d.feed_at(&stream(3), &"sb".into(), 7, &mut out).unwrap();
        assert_eq!(std::str::from_utf8(&out).unwrap().lines().count(), 3);
        assert_eq!(d.pending(), 0);
    }

    #[test]
    fn an_incomplete_record_is_kept_until_the_rest_arrives() {
        let mut d = StreamDecoder::default();
        let mut out = Vec::new();
        let rec = heartbeat(1);
        d.feed_at(&rec[..10], &"sb".into(), 7, &mut out).unwrap();
        assert_eq!(d.pending(), 10);
        assert_eq!(out, b"");
        d.feed_at(&rec[10..], &"sb".into(), 7, &mut out).unwrap();
        assert_eq!(d.pending(), 0);
        assert_ne!(out, b"");
    }

    #[test]
    fn corrupt_stream_is_an_error() {
        let mut bad = heartbeat(1);
        bad[2..4].copy_from_slice(&3_u16.to_ne_bytes());
        let mut out = Vec::new();
        assert_eq!(
            StreamDecoder::default().feed_at(&bad, &"sb".into(), 7, &mut out),
            Err(DecodeError::BadLength { len: 3 })
        );
    }

    #[test]
    fn corruption_after_a_partial_record_is_an_error() {
        let mut d = StreamDecoder::default();
        let mut out = Vec::new();
        let rec = heartbeat(1);
        d.feed_at(&rec[..10], &"sb".into(), 7, &mut out).unwrap();
        let mut rest = rec[10..].to_vec();
        rest.extend_from_slice(&[0xff; 60]);
        assert!(d.feed_at(&rest, &"sb".into(), 7, &mut out).is_err());
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
        task_in(pid, parent, comm, 9, cgroup)
    }

    fn task_in(pid: u32, parent: u32, comm: &[u8; 16], cgroup_id: u64, cgroup: &[u8]) -> Vec<u8> {
        let body = [
            &parent.to_ne_bytes()[..],
            &1000_u32.to_ne_bytes(),
            &cgroup_id.to_ne_bytes(),
            comm,
            cgroup,
        ]
        .concat();
        rec(Kind::Task, pid, &body)
    }

    /// Container bundles under a temporary directory, each with its sandbox,
    /// all named `agent`.
    fn bundles(containers: &[(&str, &str)]) -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = tempfile::tempdir().unwrap();
        for (id, sandbox) in containers {
            let dir = tmp.path().join(id);
            std::fs::create_dir(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::write(
                dir.join("config.json"),
                format!(
                    r#"{{"annotations":{{"io.kubernetes.cri.container-type":"container",
                    "io.kubernetes.cri.sandbox-id":"{sandbox}",
                    "io.kubernetes.cri.container-name":"agent"}}}}"#
                ),
            )
            .unwrap();
        }
        tmp
    }

    fn fork(child: u32, parent: u32) -> Vec<u8> {
        rec(
            Kind::Fork,
            child,
            &[&parent.to_ne_bytes()[..], &[0; 4]].concat(),
        )
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
            .feed_at(&data, &"sb".into(), 7, &mut out)
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
    fn processes_carry_the_container_the_host_confirms() {
        use std::sync::Arc;

        let ours = "5f473572d1da5189480c50a0dc42ef5d19c1f6d1da83dc6f281837d987c78933";
        let theirs = "b".repeat(64);
        let tmp = bundles(&[(ours, "sb"), (&theirs, "other")]);
        let sh = *b"sh\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        let data = [
            task(
                10,
                1,
                &sh,
                format!("cri-containerd-{ours}.scope\0").as_bytes(),
            ),
            fork(11, 10),
            rec(Kind::Exit, 11, &[0; 8]),
            // Another pod's container, and a guest service.
            task(
                20,
                1,
                &sh,
                format!("cri-containerd-{theirs}.scope\0").as_bytes(),
            ),
            fork(21, 20),
            task(30, 1, &sh, b"kata-agent.service\0"),
            fork(31, 30),
        ]
        .concat();
        let containers = Containers::new(Arc::from(tmp.path()), Arc::from("sb"));
        let mut out = Vec::new();
        StreamDecoder::new(Format::Json)
            .with_containers(containers)
            .feed_at(&data, &"sb".into(), 7, &mut out)
            .unwrap();
        let claimed: Vec<_> = lines(&out)
            .iter()
            .map(|v| {
                (
                    v["process.pid"].as_u64().unwrap(),
                    v["creche.guest.container.id"].as_str().map(str::to_owned),
                    v["creche.guest.container.name"].as_str().map(str::to_owned),
                )
            })
            .collect();
        let agent = (Some(ours.to_owned()), Some("agent".to_owned()));
        assert_eq!(
            claimed,
            [
                (11, agent.0.clone(), agent.1.clone()),
                (11, agent.0, agent.1),
                (21, None, None),
                (31, None, None),
            ]
        );

        // Without a checker, nothing is claimed.
        let mut out = Vec::new();
        StreamDecoder::new(Format::Json)
            .feed_at(&data, &"sb".into(), 7, &mut out)
            .unwrap();
        assert!(
            lines(&out)
                .iter()
                .all(|v| v.get("creche.guest.container.id").is_none())
        );
    }

    /// A cgroup record, as the observer encodes it.
    fn cgroup(id: u64, owner: u32, path: &str, labels: &[(&str, &str)]) -> Vec<u8> {
        let labels: Vec<(&[u8], &[u8])> = labels
            .iter()
            .map(|(k, v)| (k.as_bytes(), v.as_bytes()))
            .collect();
        let mut out = vec![0; creche_wire::MAX_RECORD_LEN];
        let len = creche_wire::encode_cgroup(1, 1, id, owner, path.as_bytes(), &labels, &mut out)
            .unwrap();
        out.truncate(len);
        out
    }

    #[test]
    fn nested_agent_cgroups_carry_their_labels_and_container() {
        use std::sync::Arc;

        let ours = "5f473572d1da5189480c50a0dc42ef5d19c1f6d1da83dc6f281837d987c78933";
        let theirs = "b".repeat(64);
        let tmp = bundles(&[(ours, "sb"), (&theirs, "other")]);
        let sh = *b"sh\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        let data = [
            // An agent's own cgroup in our container, labelled by its owner.
            cgroup(
                21,
                1001,
                &format!("/kubepods/pod1/cri-containerd-{ours}.scope/planner"),
                &[("name", "planner"), ("id", "a-1")],
            ),
            task_in(10, 1, &sh, 21, b"planner\0"),
            fork(11, 10),
            // One in another sandbox's container: labelled, but no container.
            cgroup(
                22,
                1002,
                &format!("/kubepods/pod2/cri-containerd-{theirs}.scope/tools"),
                &[("name", "intruder")],
            ),
            task_in(20, 1, &sh, 22, b"tools\0"),
            fork(21, 20),
            // A cgroup the observer did not describe: its leaf name only.
            task_in(30, 1, &sh, 23, b"planner\0"),
            fork(31, 30),
        ]
        .concat();
        let containers = Containers::new(Arc::from(tmp.path()), Arc::from("sb"));
        let mut out = Vec::new();
        StreamDecoder::new(Format::Json)
            .with_containers(containers)
            .feed_at(&data, &"sb".into(), 7, &mut out)
            .unwrap();
        let l = lines(&out);
        // Cgroup records, like task records, are context and not lines.
        assert_eq!(l.len(), 3);
        let field = |v: &serde_json::Value, k: &str| v.get(k).cloned();
        let v = &l[0];
        assert_eq!(v["process.pid"], 11);
        assert_eq!(
            v["creche.cgroup.path"],
            format!("/kubepods/pod1/cri-containerd-{ours}.scope/planner")
        );
        assert_eq!(v["creche.cgroup.name"], "planner");
        assert_eq!(v["creche.cgroup.label_owner.uid"], 1001);
        assert_eq!(v["creche.guest.agent.name"], "planner");
        assert_eq!(v["creche.guest.agent.id"], "a-1");
        assert_eq!(v["creche.guest.container.id"], ours);
        let v = &l[1];
        assert_eq!(v["creche.guest.agent.name"], "intruder");
        assert_eq!(field(v, "creche.guest.container.id"), None);
        let v = &l[2];
        assert_eq!(v["creche.cgroup.name"], "planner");
        for k in [
            "creche.cgroup.path",
            "creche.cgroup.label_owner.uid",
            "creche.guest.agent.name",
            "creche.guest.container.id",
        ] {
            assert_eq!(field(v, k), None, "{k}");
        }
    }

    #[test]
    fn a_cgroup_without_labels_has_a_path_and_no_owner() {
        let sh = *b"sh\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        let data = [
            cgroup(5, 0, "/kata-agent.service", &[]),
            task_in(10, 1, &sh, 5, b"kata-agent.service\0"),
            fork(11, 10),
        ]
        .concat();
        let mut out = Vec::new();
        StreamDecoder::new(Format::Json)
            .feed_at(&data, &"sb".into(), 7, &mut out)
            .unwrap();
        let l = lines(&out);
        assert_eq!(l[0]["creche.cgroup.path"], "/kata-agent.service");
        assert!(l[0].get("creche.cgroup.label_owner.uid").is_none());
        assert!(
            l[0].as_object()
                .unwrap()
                .keys()
                .all(|k| !k.starts_with("creche.guest.agent."))
        );
    }

    #[test]
    fn audited_streams_number_their_lines_and_verify() {
        let origin = Origin::from("sb").with_stream("s1");
        let mut d = StreamDecoder::new(Format::Json).with_audit();
        let mut out = Vec::new();
        d.event(&origin, "creche.stream.start", 1, &[], &mut out);
        // 300 heartbeats in uneven chunks: one checkpoint falls due by count.
        let data = stream(300);
        for part in data.chunks(1000) {
            d.feed_at(part, &origin, 2, &mut out).unwrap();
        }
        d.event(
            &origin,
            "creche.stream.end",
            3,
            &[("creche.stream.end_reason", Value::Str("closed"))],
            &mut out,
        );
        d.finish(&origin, 3, &mut out);

        let l = lines(&out);
        let seqs: Vec<u64> = l.iter().filter_map(|v| v["creche.seq"].as_u64()).collect();
        assert_eq!(seqs, (0..302).collect::<Vec<_>>());
        let checkpoints: Vec<_> = l
            .iter()
            .filter(|v| v["event.name"] == "creche.audit.checkpoint")
            .map(|v| {
                (
                    v["creche.seq.first"].as_u64(),
                    v["creche.seq.last"].as_u64(),
                )
            })
            .collect();
        // The first falls due inside a chunk and is written after it.
        let [(Some(0), Some(cut)), (Some(next), Some(301))] = checkpoints[..] else {
            panic!("{checkpoints:?}");
        };
        assert!(cut >= 255 && next == cut + 1, "{checkpoints:?}");
        let report = crate::audit::verify(&out, None);
        assert!(report.intact(), "{report:?}");
        assert_eq!(report.streams["s1"].verified, 302);
    }

    #[test]
    fn raw_streams_have_no_sink_events() {
        let origin = Origin::from("sb").with_stream("s1");
        let mut d = StreamDecoder::new(Format::Raw).with_audit();
        let mut out = Vec::new();
        d.event(&origin, "creche.stream.start", 1, &[], &mut out);
        d.finish(&origin, 1, &mut out);
        assert_eq!(out, b"");
    }

    #[test]
    fn feed_stamps_records_with_the_wall_clock() {
        let before = now_ns();
        let mut out = Vec::new();
        StreamDecoder::default()
            .feed(&heartbeat(1), &"sb".into(), &mut out)
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
        d.feed_at(&data[..100], &"sb-1".into(), 7, &mut out)
            .unwrap();
        d.feed_at(&data[100..], &"sb-1".into(), 7, &mut out)
            .unwrap();
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
        d.feed_at(&rec[..10], &"sb".into(), 7, &mut out).unwrap();
        assert_eq!(out, b"");
        let mut bad = heartbeat(1);
        bad[2..4].copy_from_slice(&3_u16.to_ne_bytes());
        assert!(
            StreamDecoder::new(Format::Raw)
                .feed_at(&bad, &"sb".into(), 7, &mut out)
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
                d.feed_at(&data[start..end], &"sb".into(), 7, &mut out).unwrap();
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
            StreamDecoder::default().feed_at(&data, &"sb".into(), 7, &mut whole).unwrap();

            let mut offsets: Vec<usize> = cuts.iter().map(|i| i.index(data.len() + 1)).collect();
            offsets.sort_unstable();
            let mut d = StreamDecoder::default();
            let mut chunked = Vec::new();
            let mut start = 0;
            for end in offsets.into_iter().chain([data.len()]) {
                d.feed_at(&data[start..end], &"sb".into(), 7, &mut chunked).unwrap();
                start = end;
            }
            prop_assert_eq!(chunked, whole);
            prop_assert_eq!(d.pending(), 0);
        }
    }
}
