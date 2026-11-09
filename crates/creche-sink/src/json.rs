//! Rendering records as JSON lines.

use std::io::Write as _;

use creche_wire::{Body, HelloFlags, Kind, Record};

use crate::k8s::{Pod, Unresolved};
use crate::tasks::TaskInfo;

/// A JSON key with the comma before it, as one literal: `key!("pid")` is `,"pid":`.
macro_rules! key {
    ($name:literal) => {
        concat!(",\"", $name, "\":").as_bytes()
    };
}

/// What the host attests about a stream's origin, rendered once as the start
/// of every line: the sandbox id and, when known, its pod.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Origin {
    id: Box<str>,
    /// Attribute names and values, in line order.
    attributes: Vec<(&'static str, Box<str>)>,
    /// The attributes rendered as the start of a JSON object.
    json: Box<[u8]>,
}

/// What is known about the pod a sandbox belongs to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Attribution {
    /// Not looked up, as for a captured stream.
    None,
    /// The pod the container runtime recorded.
    Pod(Pod),
    /// Looked up, but not known, and why.
    Unresolved(Unresolved),
}

impl Origin {
    /// The origin of a stream from sandbox `id`.
    #[must_use]
    pub fn new(id: &str, attribution: &Attribution) -> Self {
        let mut attributes: Vec<(&'static str, Box<str>)> = vec![("creche.sandbox.id", id.into())];
        match attribution {
            Attribution::None => {}
            Attribution::Pod(pod) => attributes.extend([
                ("k8s.pod.name", (*pod.name).into()),
                ("k8s.namespace.name", (*pod.namespace).into()),
                ("k8s.pod.uid", (*pod.uid).into()),
            ]),
            Attribution::Unresolved(why) => {
                attributes.push(("creche.k8s.unresolved", why.as_str().into()));
            }
        }
        Self {
            id: id.into(),
            json: render_attributes(&attributes),
            attributes,
        }
    }

    /// The same origin, naming the stream `stream` on every line, so lines can
    /// be grouped and their audit chain checked per stream.
    #[must_use]
    pub fn with_stream(mut self, stream: &str) -> Self {
        self.attributes.push(("creche.stream.id", stream.into()));
        self.json = render_attributes(&self.attributes);
        self
    }

    /// The sandbox id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Length of the JSON every line from this origin starts with.
    pub(crate) fn json_len(&self) -> usize {
        self.json.len()
    }

    /// The attested attributes every line starts with, as name and value.
    pub fn attributes(&self) -> impl Iterator<Item = (&str, &str)> {
        self.attributes.iter().map(|(k, v)| (*k, &**v))
    }
}

/// `{"name":"value",...` without the closing brace. Names need no escaping.
fn render_attributes(attributes: &[(&'static str, Box<str>)]) -> Box<[u8]> {
    let mut json = vec![b'{'];
    for (i, (name, value)) in attributes.iter().enumerate() {
        if i > 0 {
            json.push(b',');
        }
        json.push(b'"');
        json.extend_from_slice(name.as_bytes());
        json.extend_from_slice(b"\":");
        push_json_str(&mut json, value);
    }
    json.into()
}

impl From<&str> for Origin {
    /// A sandbox id with no pod lookup.
    fn from(id: &str) -> Self {
        Self::new(id, &Attribution::None)
    }
}

/// A value in an event the sink reports about itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value<'a> {
    /// A string, escaped as needed.
    Str(&'a str),
    /// An unsigned integer.
    Num(u64),
}

/// Appends an event the sink reports about itself, such as a stream starting or
/// a refused connection, as one JSON line. `seq` is the line's place in its
/// stream, when it belongs to one. `fields` are written in order, after the
/// common ones. Their names must not need escaping.
pub fn sink_event(
    origin: &Origin,
    name: &str,
    observed_ns: u64,
    seq: Option<u64>,
    fields: &[(&str, Value<'_>)],
    out: &mut Vec<u8>,
) {
    let mut line = Line::start(out, origin);
    line.str(key!("event.name"), name);
    if let Some(seq) = seq {
        line.num(key!("creche.seq"), seq);
    }
    line.num(key!("observed_time_unix_nano"), observed_ns);
    for (name, value) in fields {
        line.out.extend_from_slice(b",\"");
        line.out.extend_from_slice(name.as_bytes());
        line.out.extend_from_slice(b"\":");
        match value {
            Value::Str(s) => push_json_str(line.out, s),
            Value::Num(n) => push_u64(line.out, *n),
        }
    }
    line.end();
}

/// Appends `record`, from `origin`, to `out` as one JSON object and a newline.
/// `task` is the context of the record's process, when the stream reported it.
/// `observed_ns` is the host's wall clock when the record arrived, in nanoseconds
/// since the Unix epoch: the guest only knows its own boot-time clock.
///
/// Attribute names follow the OpenTelemetry semantic conventions (`process.*`,
/// `file.path`, `destination.*`, `network.*`) where one exists, and use the
/// `creche.` namespace otherwise. Event names are `creche.`-namespaced too:
/// OpenTelemetry defines no process or file events to reuse.
pub fn render(
    origin: &Origin,
    record: &Record<'_>,
    task: Option<&TaskInfo>,
    observed_ns: u64,
    seq: u64,
    out: &mut Vec<u8>,
) {
    let h = &record.header;
    let mut line = Line::start(out, origin);
    line.str(key!("event.name"), event_name(h.kind));
    line.num(key!("creche.seq"), seq);
    line.num(key!("observed_time_unix_nano"), observed_ns);
    line.num(key!("creche.boot_time_ns"), h.ts_ns);
    line.num(key!("process.pid"), h.pid);
    if let Some(t) = task {
        line.num(key!("process.parent_pid"), t.ppid);
        line.num(key!("process.real_user.id"), t.uid);
        line.str(key!("process.executable.name"), &t.comm);
        line.num(key!("creche.cgroup.id"), t.cgroup_id);
        line.str(key!("creche.cgroup.name"), &t.cgroup);
        if let Some(c) = &t.container {
            line.str(key!("creche.guest.container.id"), &c.id);
            line.str(key!("creche.guest.container.name"), &c.name);
        }
    }
    match record.body {
        Body::Exec { path, args, .. } => {
            line.bytes(key!("process.executable.path"), path);
            line.args(key!("process.command_args"), args);
        }
        Body::Task { context, cgroup } => {
            line.num(key!("process.parent_pid"), context.ppid);
            line.num(key!("process.real_user.id"), context.uid);
            line.bytes(key!("process.executable.name"), context.comm);
            line.num(key!("creche.cgroup.id"), context.cgroup_id);
            line.bytes(key!("creche.cgroup.name"), cgroup);
        }
        Body::Fork { ppid } => {
            if task.is_none() {
                line.num(key!("process.parent_pid"), ppid);
            }
        }
        Body::Exit { code } => line.int(key!("process.exit.code"), code),
        Body::Connect { addr, port } => {
            match addr {
                Some(addr) => {
                    line.display(key!("destination.address"), addr);
                    let family = if addr.is_ipv4() { "ipv4" } else { "ipv6" };
                    line.str(key!("network.type"), family);
                }
                None => line.raw(key!("destination.address"), "null"),
            }
            line.num(key!("destination.port"), port);
            line.str(key!("network.transport"), "tcp");
        }
        Body::OpenWrite { path } => line.bytes(key!("file.path"), path),
        Body::Hello { version, flags } => {
            line.num(key!("creche.wire.version"), version);
            line.num(key!("creche.observer.flags"), flags.bits());
            let guarded = flags.contains(HelloFlags::GUARDED);
            line.raw(
                key!("creche.observer.guarded"),
                if guarded { "true" } else { "false" },
            );
        }
        Body::Heartbeat(hb) => {
            line.num(key!("creche.observer.ringbuf_drops"), hb.ringbuf_drops);
            line.num(key!("creche.observer.sent_bytes"), hb.sent_bytes);
            line.num(key!("creche.observer.dropped_bytes"), hb.dropped_bytes);
            line.num(key!("creche.observer.rss_kb"), hb.rss_kb);
            line.num(key!("creche.observer.cpu_ms"), hb.cpu_ms);
            line.num(key!("creche.observer.bpf_run_ns"), hb.bpf_run_ns);
            line.num(key!("creche.observer.bpf_run_cnt"), hb.bpf_run_cnt);
        }
        Body::Unknown { body } => {
            line.num(key!("creche.record.kind"), h.kind);
            line.num(
                key!("creche.record.body_len"),
                u64::try_from(body.len()).unwrap_or(u64::MAX),
            );
        }
    }
    line.end();
}

fn event_name(code: u16) -> &'static str {
    match Kind::from_code(code) {
        Some(Kind::Exec) => "creche.process.exec",
        Some(Kind::Fork) => "creche.process.fork",
        Some(Kind::Exit) => "creche.process.exit",
        Some(Kind::Connect) => "creche.network.connect",
        Some(Kind::OpenWrite) => "creche.file.open_write",
        Some(Kind::Task) => "creche.process.context",
        Some(Kind::Hello) => "creche.observer.hello",
        Some(Kind::Heartbeat) => "creche.observer.heartbeat",
        None => "creche.unknown",
    }
}

/// Writes one JSON object. Writing to a `Vec` cannot fail.
///
/// Hand-written rather than going through serde or `fmt`: every line starts with
/// the origin, rendered once per stream, every other key is a literal written in one copy, strings are
/// copied whole unless they hold a character JSON must escape, and integers are
/// formatted into a small buffer. About 2 times faster than `serde_json`
/// escaping plus `write!` for numbers (benches/render.rs).
struct Line<'a> {
    out: &'a mut Vec<u8>,
}

impl<'a> Line<'a> {
    fn start(out: &'a mut Vec<u8>, origin: &Origin) -> Self {
        out.extend_from_slice(&origin.json);
        Self { out }
    }

    fn str(&mut self, key: &[u8], value: &str) {
        self.out.extend_from_slice(key);
        push_json_str(self.out, value);
    }

    /// Guest data is not guaranteed UTF-8. Invalid sequences become U+FFFD.
    fn bytes(&mut self, key: &[u8], value: &[u8]) {
        match std::str::from_utf8(value) {
            Ok(s) => self.str(key, s),
            Err(_) => self.str(key, &String::from_utf8_lossy(value)),
        }
    }

    /// A NUL-separated argument vector, as a JSON array of strings, so the
    /// boundaries between arguments survive.
    fn args(&mut self, key: &[u8], args: &[u8]) {
        self.out.extend_from_slice(key);
        self.out.push(b'[');
        if !args.is_empty() {
            for (i, arg) in args.split(|&b| b == 0).enumerate() {
                if i > 0 {
                    self.out.push(b',');
                }
                match std::str::from_utf8(arg) {
                    Ok(s) => push_json_str(self.out, s),
                    Err(_) => push_json_str(self.out, &String::from_utf8_lossy(arg)),
                }
            }
        }
        self.out.push(b']');
    }

    /// An unsigned integer, as a bare JSON number.
    fn num(&mut self, key: &[u8], value: impl Into<u64>) {
        self.out.extend_from_slice(key);
        push_u64(self.out, value.into());
    }

    /// A signed integer, as a bare JSON number.
    fn int(&mut self, key: &[u8], value: i32) {
        self.out.extend_from_slice(key);
        if value < 0 {
            self.out.push(b'-');
        }
        push_u64(self.out, u64::from(value.unsigned_abs()));
    }

    /// A value whose `Display` form needs no escaping (an IP address), quoted.
    fn display(&mut self, key: &[u8], value: impl std::fmt::Display) {
        self.out.extend_from_slice(key);
        let _ = write!(self.out, "\"{value}\"");
    }

    fn raw(&mut self, key: &[u8], json: &str) {
        self.out.extend_from_slice(key);
        self.out.extend_from_slice(json.as_bytes());
    }

    fn end(self) {
        self.out.extend_from_slice(b"}\n");
    }
}

/// Appends `s` as a JSON string. JSON requires escaping only `"`, `\` and control
/// characters. Most guest strings (paths, names) have none, so they are checked
/// with [`needs_escape`] and copied in one go.
fn push_json_str(out: &mut Vec<u8>, s: &str) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = s.as_bytes();
    out.push(b'"');
    if !needs_escape(bytes) {
        out.extend_from_slice(bytes);
        out.push(b'"');
        return;
    }
    let mut start = 0;
    for (i, &b) in bytes.iter().enumerate() {
        let short: &[u8] = match b {
            b'"' => b"\\\"",
            b'\\' => b"\\\\",
            b'\n' => b"\\n",
            b'\r' => b"\\r",
            b'\t' => b"\\t",
            0x08 => b"\\b",
            0x0c => b"\\f",
            0..=0x1f => b"",
            _ => continue,
        };
        out.extend_from_slice(bytes.get(start..i).unwrap_or_default());
        if short.is_empty() {
            out.extend_from_slice(b"\\u00");
            out.push(HEX[usize::from(b >> 4)]);
            out.push(HEX[usize::from(b & 0xf)]);
        } else {
            out.extend_from_slice(short);
        }
        start = i.saturating_add(1);
    }
    out.extend_from_slice(bytes.get(start..).unwrap_or_default());
    out.push(b'"');
}

/// Whether `bytes` hold a character JSON must escape: a quote, a backslash or a
/// control character.
///
/// Checked 16 bytes at a time with a fold that never exits early, which the
/// compiler turns into vector compares (SSE2 on the x86-64 baseline, wider with
/// a newer target CPU). A plain short-circuiting `any` stays a scalar loop, one
/// byte per iteration. Stable Rust has no safe explicit SIMD, so this is the
/// safe way to get it.
fn needs_escape(bytes: &[u8]) -> bool {
    const fn escaped(b: u8) -> bool {
        b < 0x20 || b == b'"' || b == b'\\'
    }
    let (chunks, tail) = bytes.as_chunks::<16>();
    chunks.iter().any(|chunk| {
        chunk
            .iter()
            .fold(0_u8, |found, &b| found | u8::from(escaped(b)))
            != 0
    }) || tail.iter().any(|&b| escaped(b))
}

/// Appends `n` in decimal.
fn push_u64(out: &mut Vec<u8>, mut n: u64) {
    let mut digits = [0_u8; 20];
    let mut at = digits.len();
    loop {
        at -= 1;
        // n % 10 < 10, so the conversion cannot fail.
        digits[at] = b'0' + u8::try_from(n % 10).unwrap_or(0);
        n /= 10;
        if n == 0 {
            break;
        }
    }
    out.extend_from_slice(digits.get(at..).unwrap_or_default());
}

#[cfg(test)]
mod tests {
    use super::*;
    use creche_wire::{Context, Header, HeartbeatRecord};
    use std::net::{IpAddr, Ipv4Addr};

    fn header(kind: Kind) -> Header {
        Header {
            kind: kind.code(),
            len: 0,
            pid: 5,
            ts_ns: 99,
        }
    }

    fn wget() -> TaskInfo {
        TaskInfo {
            ppid: 4,
            uid: 0,
            cgroup_id: 7,
            comm: "wget".into(),
            cgroup: "cri-containerd-x.scope".into(),
            container: None,
        }
    }

    fn rendered_with(kind: Kind, body: Body<'_>, task: Option<&TaskInfo>) -> serde_json::Value {
        let mut out = Vec::new();
        render(
            &"sb1".into(),
            &Record {
                header: header(kind),
                body,
            },
            task,
            42,
            0,
            &mut out,
        );
        assert_eq!(out.last(), Some(&b'\n'));
        serde_json::from_slice(&out).unwrap()
    }

    fn rendered(kind: Kind, body: Body<'_>) -> serde_json::Value {
        rendered_with(kind, body, Some(&wget()))
    }

    #[test]
    fn exec_lines_have_context_argument_arrays_and_escaped_strings() {
        let v = rendered(
            Kind::Exec,
            Body::Exec {
                context: Context {
                    ppid: 0,
                    uid: 0,
                    cgroup_id: 0,
                    comm: b"ignored",
                },
                path: b"/bin/sh",
                args: b"sh\0-c\0echo \"hi\"\\\n",
            },
        );
        assert_eq!(v["creche.sandbox.id"], "sb1");
        assert_eq!(v["event.name"], "creche.process.exec");
        assert_eq!(v["observed_time_unix_nano"], 42);
        assert_eq!(v["creche.boot_time_ns"], 99);
        assert_eq!(v["process.pid"], 5);
        assert_eq!(v["process.parent_pid"], 4);
        assert_eq!(v["process.real_user.id"], 0);
        assert_eq!(v["process.executable.name"], "wget");
        assert_eq!(v["creche.cgroup.id"], 7);
        assert_eq!(v["creche.cgroup.name"], "cri-containerd-x.scope");
        assert_eq!(v["process.executable.path"], "/bin/sh");
        assert_eq!(
            v["process.command_args"],
            serde_json::json!(["sh", "-c", "echo \"hi\"\\\n"])
        );
    }

    #[test]
    fn unknown_context_is_left_out() {
        let v = rendered_with(Kind::OpenWrite, Body::OpenWrite { path: b"/a" }, None);
        assert_eq!(v["process.pid"], 5);
        for key in [
            "process.parent_pid",
            "process.real_user.id",
            "process.executable.name",
            "creche.cgroup.id",
            "creche.cgroup.name",
        ] {
            assert!(v.get(key).is_none(), "{key}");
        }
        // A fork still names its parent.
        let v = rendered_with(Kind::Fork, Body::Fork { ppid: 3 }, None);
        assert_eq!(v["process.parent_pid"], 3);
        let v = rendered(Kind::Fork, Body::Fork { ppid: 3 });
        assert_eq!(v["process.parent_pid"], 4);
    }

    #[test]
    fn task_lines_carry_their_own_fields() {
        let v = rendered_with(
            Kind::Task,
            Body::Task {
                context: Context {
                    ppid: 1,
                    uid: 2,
                    cgroup_id: 3,
                    comm: b"sh",
                },
                cgroup: b"c",
            },
            None,
        );
        assert_eq!(v["event.name"], "creche.process.context");
        assert_eq!(
            (
                &v["process.parent_pid"],
                &v["process.real_user.id"],
                &v["creche.cgroup.id"],
                &v["process.executable.name"],
                &v["creche.cgroup.name"]
            ),
            (&1.into(), &2.into(), &3.into(), &"sh".into(), &"c".into())
        );
    }

    #[test]
    fn invalid_utf8_is_replaced_not_dropped() {
        let v = rendered(Kind::OpenWrite, Body::OpenWrite { path: b"/tmp/\xff" });
        assert_eq!(v["event.name"], "creche.file.open_write");
        assert_eq!(v["file.path"], "/tmp/\u{fffd}");
    }

    #[test]
    fn connect_lines_name_the_destination() {
        let v = rendered(
            Kind::Connect,
            Body::Connect {
                addr: Some(IpAddr::V4(Ipv4Addr::new(10, 43, 0, 10))),
                port: 53,
            },
        );
        assert_eq!(
            (
                v["destination.address"].as_str(),
                v["destination.port"].as_u64(),
                v["network.type"].as_str(),
                v["network.transport"].as_str()
            ),
            (Some("10.43.0.10"), Some(53), Some("ipv4"), Some("tcp"))
        );
        let v = rendered(
            Kind::Connect,
            Body::Connect {
                addr: Some(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
                port: 443,
            },
        );
        assert_eq!(
            (
                v["destination.address"].as_str(),
                v["network.type"].as_str()
            ),
            (Some("::1"), Some("ipv6"))
        );
        let v = rendered(
            Kind::Connect,
            Body::Connect {
                addr: None,
                port: 1,
            },
        );
        assert_eq!(v.get("destination.address"), Some(&serde_json::Value::Null));
        assert!(v.get("network.type").is_none());
    }

    #[test]
    fn exit_hello_heartbeat_unknown() {
        assert_eq!(
            rendered(Kind::Exit, Body::Exit { code: -1 })["process.exit.code"],
            -1
        );

        let v = rendered_with(
            Kind::Hello,
            Body::Hello {
                version: 3,
                flags: HelloFlags::DEDUP,
            },
            None,
        );
        assert_eq!(
            (
                v["creche.wire.version"].as_u64(),
                v["creche.observer.flags"].as_u64()
            ),
            (Some(3), Some(1))
        );
        assert_eq!(v["creche.observer.guarded"], false);
        let v = rendered_with(
            Kind::Hello,
            Body::Hello {
                version: 3,
                flags: HelloFlags::DEDUP.with(HelloFlags::GUARDED),
            },
            None,
        );
        assert_eq!(v["creche.observer.flags"], 5);
        assert_eq!(v["creche.observer.guarded"], true);

        let hb = HeartbeatRecord {
            ringbuf_drops: 1,
            sent_bytes: 2,
            dropped_bytes: 3,
            rss_kb: 4,
            cpu_ms: 5,
            bpf_run_ns: 6,
            bpf_run_cnt: 7,
            ..HeartbeatRecord::default()
        };
        let v = rendered_with(Kind::Heartbeat, Body::Heartbeat(hb), None);
        for (key, value) in [
            ("creche.observer.ringbuf_drops", 1),
            ("creche.observer.sent_bytes", 2),
            ("creche.observer.dropped_bytes", 3),
            ("creche.observer.rss_kb", 4),
            ("creche.observer.cpu_ms", 5),
            ("creche.observer.bpf_run_ns", 6),
            ("creche.observer.bpf_run_cnt", 7),
        ] {
            assert_eq!(v[key], value, "{key}");
        }

        let mut out = Vec::new();
        let mut h = header(Kind::Fork);
        h.kind = 900;
        render(
            &"sb1".into(),
            &Record {
                header: h,
                body: Body::Unknown { body: b"abc" },
            },
            None,
            42,
            0,
            &mut out,
        );
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(
            (
                v["event.name"].as_str(),
                v["creche.record.kind"].as_u64(),
                v["creche.record.body_len"].as_u64()
            ),
            (Some("creche.unknown"), Some(900), Some(3))
        );
    }

    /// The JSON string `push_json_str` writes for `s`, parsed back.
    fn round_trip(s: &str) -> String {
        let mut out = Vec::new();
        push_json_str(&mut out, s);
        serde_json::from_slice(&out).unwrap()
    }

    #[test]
    fn strings_escape_quotes_backslashes_and_controls() {
        for s in [
            "",
            "plain",
            "a\"b",
            "a\\b",
            "\n\r\t\u{8}\u{c}",
            "\0\u{1f}\u{7f}",
            "\u{fc}n\u{ef}c\u{f8}d\u{e9} \u{2713}",
        ] {
            assert_eq!(round_trip(s), s);
        }
        // The exact escapes: the short forms where JSON has one, \u00XX otherwise.
        for (s, json) in [
            ("\"", "\\\""),
            ("\\", "\\\\"),
            ("\n", "\\n"),
            ("\r", "\\r"),
            ("\t", "\\t"),
            ("\u{8}", "\\b"),
            ("\u{c}", "\\f"),
            ("\u{1}", "\\u0001"),
            ("\u{1f}", "\\u001f"),
            ("a\nb", "a\\nb"),
        ] {
            let mut out = Vec::new();
            push_json_str(&mut out, s);
            assert_eq!(out, format!("\"{json}\"").as_bytes(), "{s:?}");
        }
    }

    #[test]
    fn only_quotes_backslashes_and_controls_need_escaping() {
        for b in 0_u8..=255 {
            let expected = b < 0x20 || b == b'"' || b == b'\\';
            assert_eq!(needs_escape(&[b'a', b, b'z']), expected, "byte {b:#04x}");
        }
        // Every position of a 16-byte chunk and of the tail is checked.
        for len in [15, 16, 17, 31, 32, 33, 64] {
            for at in 0..len {
                let mut bytes = vec![b'a'; len];
                bytes[at] = b'"';
                assert!(needs_escape(&bytes), "len {len}, quote at {at}");
            }
            assert!(!needs_escape(&vec![b'a'; len]));
        }
        assert!(!needs_escape(b""));
        assert!(!needs_escape(" ~\u{7f}\u{e9}".as_bytes()));
    }

    #[test]
    fn integers_cover_their_whole_range() {
        for n in [0, 1, 9, 10, 99, 100, 4_294_967_295, u64::MAX] {
            let mut out = Vec::new();
            push_u64(&mut out, n);
            assert_eq!(out, n.to_string().as_bytes());
        }
        for code in [i32::MIN, -1, 0, 1, i32::MAX] {
            let mut out = Vec::new();
            let mut line = Line::start(&mut out, &"sb".into());
            line.int(key!("c"), code);
            line.end();
            let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
            assert_eq!(v["c"], code);
        }
    }

    proptest::proptest! {
        #[test]
        fn any_string_round_trips(s in ".*") {
            proptest::prop_assert_eq!(round_trip(&s), s);
        }

        #[test]
        fn any_bytes_render_as_their_lossy_text(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..64)) {
            let mut out = Vec::new();
            let mut line = Line::start(&mut out, &"sb".into());
            line.bytes(key!("b"), &bytes);
            line.end();
            let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
            proptest::prop_assert_eq!(v["b"].as_str().unwrap(), String::from_utf8_lossy(&bytes));
        }
    }

    fn fork_line(origin: &Origin) -> serde_json::Value {
        let mut out = Vec::new();
        render(
            origin,
            &Record {
                header: header(Kind::Fork),
                body: Body::Fork { ppid: 1 },
            },
            None,
            42,
            0,
            &mut out,
        );
        serde_json::from_slice(&out).unwrap()
    }

    #[test]
    fn lines_carry_the_attested_pod_or_why_it_is_unknown() {
        let pod = Pod {
            name: "agent-\"7".into(),
            namespace: "agents".into(),
            uid: "1f2e".into(),
        };
        let v = fork_line(&Origin::new("sb1", &Attribution::Pod(pod)));
        assert_eq!(v["creche.sandbox.id"], "sb1");
        assert_eq!(v["k8s.pod.name"], "agent-\"7");
        assert_eq!(v["k8s.namespace.name"], "agents");
        assert_eq!(v["k8s.pod.uid"], "1f2e");
        assert!(v.get("creche.k8s.unresolved").is_none());

        let v = fork_line(&Origin::new(
            "sb1",
            &Attribution::Unresolved(Unresolved::NoBundle),
        ));
        assert_eq!(v["creche.k8s.unresolved"], "no_bundle");
        assert!(v.get("k8s.pod.name").is_none());

        let v = fork_line(&"sb1".into());
        assert!(v.get("creche.k8s.unresolved").is_none());
        assert!(v.get("k8s.pod.name").is_none());
        assert_eq!(Origin::from("sb1").id(), "sb1");
    }

    #[test]
    fn sandbox_ids_are_escaped() {
        let mut out = Vec::new();
        render(
            &"we\"ird".into(),
            &Record {
                header: header(Kind::Fork),
                body: Body::Fork { ppid: 1 },
            },
            None,
            42,
            0,
            &mut out,
        );
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["creche.sandbox.id"], "we\"ird");
    }
}
