//! Listening for every Kata sandbox on the host.
//!
//! Cloud Hypervisor's hybrid vsock forwards a guest connection to host port P
//! to the unix socket `<sandbox dir>/clh.sock_P`. Sandbox directories appear
//! and disappear under `/run/vc/vm` as pods start and stop, so they are rescanned
//! periodically and each gets its own listener.
//!
//! Only the sandbox's own VMM may connect (see [`crate::peer`]), so a sandbox id
//! in the output is attested by the host.

use std::collections::HashMap;
use std::io;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::task::JoinHandle;

use crate::json::{Attribution, Origin, Value, sink_event};
use crate::k8s::{self, Containers, Unresolved};
use crate::otlp::{self, Batch, Endpoint};
use crate::peer::{self, Refusal};
use crate::stream::{Format, StreamDecoder, now_ns};

/// How often sandbox directories are rescanned.
const SCAN_INTERVAL: Duration = Duration::from_millis(200);
/// Rendered batches waiting for the writer. Senders wait when it is full.
const OUTPUT_BACKLOG: usize = 1024;
/// Batches waiting for the OTLP exporter. When it is full, batches are dropped
/// rather than holding up the sink.
const OTLP_BACKLOG: usize = 1024;
/// Least time between two reports of lines the exporter dropped.
const DROP_REPORT: Duration = Duration::from_secs(10);
/// Read size per connection.
const READ_CHUNK: usize = 65_536; // 64 KiB
/// Open connections per sandbox. An observer keeps one, a restarted observer
/// briefly two. Each connection costs a decoder and a task cache.
const MAX_CONNECTIONS: usize = 4;
/// Longest sandbox id. containerd ids are at most 76 characters.
const MAX_ID_LEN: usize = 76;

/// How the sink listens.
#[derive(Clone, Debug)]
pub struct Options {
    /// The vsock port the observers connect to.
    pub port: u32,
    /// What the sink writes.
    pub format: Format,
    /// The container runtime's bundle directory, to find each sandbox's pod.
    /// `None` skips the lookup.
    pub bundles: Option<PathBuf>,
    /// Where to export the JSON lines as OpenTelemetry logs, besides stdout.
    pub otlp: Option<Endpoint>,
}

/// Listens for every sandbox under `dir`, writing to stdout until it fails.
///
/// # Errors
///
/// When stdout cannot be written.
pub async fn run(dir: PathBuf, options: Options) -> io::Result<()> {
    run_with(dir, options, tokio::io::stdout()).await
}

/// [`run`], writing to `out`.
async fn run_with<W>(dir: PathBuf, options: Options, out: W) -> io::Result<()>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (tx, rx) = mpsc::channel(OUTPUT_BACKLOG);
    let exporter = options.otlp.clone().map(|endpoint| {
        eprintln!("creche-sink: exporting to {endpoint}");
        let (otx, orx) = mpsc::channel(OTLP_BACKLOG);
        tokio::spawn(otlp::export(endpoint, orx));
        otx
    });
    let writer = tokio::spawn(write_output(rx, out, exporter));
    let mut listeners: HashMap<String, Listener> = HashMap::new();
    let mut tick = tokio::time::interval(SCAN_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    while !writer.is_finished() {
        tick.tick().await;
        scan(&dir, &options, &mut listeners, &tx).await;
    }
    writer.await.unwrap_or_else(|e| Err(io::Error::other(e)))
}

struct Listener {
    task: JoinHandle<()>,
    socket: PathBuf,
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.task.abort();
        // The sandbox directory is usually gone already.
        let _ = std::fs::remove_file(&self.socket);
    }
}

/// Starts listeners for new sandboxes and stops the ones whose directory is gone.
async fn scan(
    dir: &Path,
    options: &Options,
    listeners: &mut HashMap<String, Listener>,
    tx: &mpsc::Sender<Batch>,
) {
    let mut present = Vec::new();
    if let Ok(mut entries) = tokio::fs::read_dir(dir).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            if let Ok(name) = entry.file_name().into_string() {
                present.push(name);
            }
        }
    }
    listeners.retain(|name, _| present.contains(name));
    for name in present {
        // Ids end up in paths and in every output line.
        if listeners.contains_key(&name) || !valid_id(&name) {
            continue;
        }
        let sandbox = dir.join(&name);
        let vsock = sandbox.join("clh.sock");
        // Only once the VMM has created its vsock socket.
        let Ok(vmm) = tokio::fs::symlink_metadata(&vsock).await else {
            continue;
        };
        let socket = sandbox.join(format!("clh.sock_{}", options.port));
        let _ = tokio::fs::remove_file(&socket).await;
        let listener = match UnixListener::bind(&socket) {
            Ok(listener) => listener,
            Err(e) => {
                eprintln!("creche-sink: cannot listen on {}: {e}", socket.display());
                continue;
            }
        };
        if let Err(e) = restrict(&socket, &vmm) {
            eprintln!("creche-sink: cannot restrict {}: {e}", socket.display());
        }
        eprintln!("creche-sink: listening for sandbox {}", short(&name));
        let sandbox = Sandbox {
            id: Arc::from(name.as_str()),
            vsock: Arc::from(vsock),
            bundles: options.bundles.as_deref().map(Arc::from),
        };
        let task = tokio::spawn(accept(listener, sandbox, options.format, tx.clone()));
        listeners.insert(name, Listener { task, socket });
    }
}

/// Whether `id` is a containerd identifier: ASCII letters and digits in
/// groups joined by single `.`, `_` or `-`, at most [`MAX_ID_LEN`] long.
fn valid_id(id: &str) -> bool {
    id.len() <= MAX_ID_LEN
        && id
            .split(['.', '_', '-'])
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric()))
}

/// Lets only the VMM's user connect to `socket`. The peer check refuses other
/// processes anyway; this keeps them from getting that far.
fn restrict(socket: &Path, vmm: &std::fs::Metadata) -> io::Result<()> {
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;
    std::os::unix::fs::chown(socket, Some(vmm.uid()), Some(vmm.gid()))
}

/// A sandbox as its listener knows it.
#[derive(Clone)]
struct Sandbox {
    /// The sandbox directory's name.
    id: Arc<str>,
    /// Its VMM's listening vsock socket.
    vsock: Arc<Path>,
    /// Where to look up its pod.
    bundles: Option<Arc<Path>>,
}

async fn accept(listener: UnixListener, sandbox: Sandbox, format: Format, tx: mpsc::Sender<Batch>) {
    let connections = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    while let Ok((stream, _)) = listener.accept().await {
        let Ok(permit) = Arc::clone(&connections).try_acquire_owned() else {
            let reason = format!("{MAX_CONNECTIONS} connections already open");
            let cred = stream.peer_cred().ok();
            let peer = Peer {
                pid: cred.and_then(|c| c.pid()),
                uid: cred.map(|c| c.uid()),
            };
            refused(&sandbox.id, &reason, peer, format, &tx).await;
            continue;
        };
        tokio::spawn(admit(stream, sandbox.clone(), format, tx.clone(), permit));
    }
}

/// Receives from `stream` once its peer has proven to be the sandbox's VMM.
async fn admit(
    stream: UnixStream,
    sandbox: Sandbox,
    format: Format,
    tx: mpsc::Sender<Batch>,
    _permit: OwnedSemaphorePermit,
) {
    let cred = stream.peer_cred().ok();
    let (pid, uid) = (cred.and_then(|c| c.pid()), cred.map(|c| c.uid()));
    let verdict = match uid {
        Some(uid) => {
            let vsock = Arc::clone(&sandbox.vsock);
            tokio::task::spawn_blocking(move || peer::check(pid, uid, &vsock))
                .await
                .unwrap_or(Err(Refusal::Io(io::ErrorKind::Other)))
        }
        None => Err(Refusal::NoPid),
    };
    let peer = Peer { pid, uid };
    match verdict {
        Ok(()) => {
            let (origin, containers) = origin(&sandbox).await;
            receive(stream, origin, containers, peer, format, tx).await;
        }
        Err(refusal) => refused(&sandbox.id, &refusal.to_string(), peer, format, &tx).await,
    }
}

/// Logs a refused connection and, in JSON, reports it as a
/// `creche.sink.refused` line, outside any stream.
async fn refused(
    sandbox: &str,
    reason: &str,
    peer: Peer,
    format: Format,
    tx: &mpsc::Sender<Batch>,
) {
    eprintln!(
        "creche-sink: refusing a connection to {}: {reason}",
        short(sandbox)
    );
    if format == Format::Json {
        let mut fields = vec![("creche.sink.refusal", Value::Str(reason))];
        fields.extend(peer.fields());
        let (origin, now) = (Arc::new(Origin::from(sandbox)), now_ns());
        let mut lines = Vec::new();
        sink_event(
            &origin,
            "creche.sink.refused",
            now,
            None,
            &fields,
            &mut lines,
        );
        let _ = tx
            .send(Batch {
                origin,
                observed_ns: now,
                lines,
            })
            .await;
    }
}

/// The process at the other end of a connection, as the kernel reports it.
#[derive(Clone, Copy, Debug)]
struct Peer {
    pid: Option<i32>,
    uid: Option<u32>,
}

impl Peer {
    /// `creche.peer.pid` and `creche.peer.uid`, for those known.
    fn fields(self) -> Vec<(&'static str, Value<'static>)> {
        let pid = self
            .pid
            .and_then(|pid| u64::try_from(pid).ok())
            .map(|pid| ("creche.peer.pid", Value::Num(pid)));
        let uid = self
            .uid
            .map(|uid| ("creche.peer.uid", Value::Num(u64::from(uid))));
        pid.into_iter().chain(uid).collect()
    }
}

/// A new stream id, unique across connections and sink restarts: the sink's
/// start time in hex and a counter.
fn stream_id() -> String {
    static START: OnceLock<u64> = OnceLock::new();
    static COUNT: AtomicU64 = AtomicU64::new(0);
    let start = START.get_or_init(now_ns);
    format!("{start:x}-{}", COUNT.fetch_add(1, Ordering::Relaxed))
}

/// What the host attests about `sandbox`: its id and, when a bundle directory is
/// set, the pod the container runtime recorded for it. Looked up once per
/// connection, so a stream's pod cannot change while it runs. When the pod is
/// known, also the checker for the containers the guest claims.
async fn origin(sandbox: &Sandbox) -> (Origin, Option<Containers>) {
    let Some(bundles) = sandbox.bundles.clone() else {
        return (Origin::from(&*sandbox.id), None);
    };
    let (dir, id) = (Arc::clone(&bundles), Arc::clone(&sandbox.id));
    let attribution = tokio::task::spawn_blocking(move || k8s::resolve(&dir, &id))
        .await
        .unwrap_or(Err(Unresolved::Unreadable))
        .map_or_else(Attribution::Unresolved, Attribution::Pod);
    let containers = match &attribution {
        Attribution::Pod(_) => Some(Containers::new(bundles, Arc::clone(&sandbox.id))),
        Attribution::Unresolved(why) => {
            eprintln!(
                "creche-sink: no pod for sandbox {}: {why}",
                short(&sandbox.id)
            );
            None
        }
        Attribution::None => None,
    };
    (Origin::new(&sandbox.id, &attribution), containers)
}

/// Decodes one connection until it closes or turns out to be corrupt.
///
/// The stream starts with a `creche.stream.start` line naming its peer and ends
/// with a `creche.stream.end` line saying why, then the last audit checkpoint.
async fn receive(
    mut stream: UnixStream,
    origin: Origin,
    containers: Option<Containers>,
    peer: Peer,
    format: Format,
    tx: mpsc::Sender<Batch>,
) {
    let origin = Arc::new(origin.with_stream(&stream_id()));
    let batch = |observed_ns, lines| Batch {
        origin: Arc::clone(&origin),
        observed_ns,
        lines,
    };
    let mut decoder = StreamDecoder::new(format).with_audit();
    if let Some(containers) = containers {
        decoder = decoder.with_containers(containers);
    }
    let mut lines = Vec::new();
    let now = now_ns();
    decoder.event(
        &origin,
        "creche.stream.start",
        now,
        &peer.fields(),
        &mut lines,
    );
    if !lines.is_empty() && tx.send(batch(now, lines)).await.is_err() {
        return;
    }
    let mut chunk = vec![0; READ_CHUNK];
    let reason = loop {
        let n = match stream.read(&mut chunk).await {
            Ok(0) => break "closed",
            Err(_) => break "read_error",
            Ok(n) => n,
        };
        let mut lines = Vec::new();
        let now = now_ns();
        let data = chunk.get(..n).unwrap_or_default();
        let fed = decoder.feed_at(data, &origin, now, &mut lines);
        // Lines decoded before a corrupt record are still sent.
        if !lines.is_empty() && tx.send(batch(now, lines)).await.is_err() {
            return;
        }
        if let Err(e) = fed {
            eprintln!(
                "creche-sink: dropping corrupt stream from {}: {e}",
                short(origin.id())
            );
            break "corrupt";
        }
    };
    let mut lines = Vec::new();
    let now = now_ns();
    decoder.event(
        &origin,
        "creche.stream.end",
        now,
        &[("creche.stream.end_reason", Value::Str(reason))],
        &mut lines,
    );
    decoder.finish(&origin, now, &mut lines);
    let _ = tx.send(batch(now, lines)).await;
}

/// Writes batches in arrival order, flushing whenever the backlog is empty.
async fn write_output(
    mut rx: mpsc::Receiver<Batch>,
    out: impl AsyncWrite + Unpin,
    exporter: Option<mpsc::Sender<Batch>>,
) -> io::Result<()> {
    let mut out = tokio::io::BufWriter::new(out);
    let mut dropped = Dropped::default();
    while let Some(batch) = rx.recv().await {
        out.write_all(&batch.lines).await?;
        if rx.is_empty() {
            out.flush().await?;
        }
        if let Some(exporter) = &exporter
            && let Err(full) = exporter.try_send(batch)
        {
            dropped.count(&full.into_inner().lines);
        }
    }
    out.flush().await
}

/// Lines the exporter had no room for, reported now and then.
struct Dropped {
    lines: u64,
    reported: tokio::time::Instant,
}

impl Default for Dropped {
    fn default() -> Self {
        Self {
            lines: 0,
            reported: tokio::time::Instant::now(),
        }
    }
}

impl Dropped {
    #[expect(
        clippy::naive_bytecount,
        reason = "only runs while the exporter is behind, not worth a dependency"
    )]
    fn count(&mut self, lines: &[u8]) {
        let n = lines.iter().filter(|&&b| b == b'\n').count();
        self.lines = self
            .lines
            .saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        if self.reported.elapsed() >= DROP_REPORT {
            eprintln!(
                "creche-sink: the OTLP exporter is behind, {} lines dropped so far",
                self.lines
            );
            self.reported = tokio::time::Instant::now();
        }
    }
}

/// The first 12 characters of a sandbox id, for log messages.
fn short(id: &str) -> &str {
    id.get(..12).unwrap_or(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use creche_wire::{HEARTBEAT_LEN, Header, HeartbeatRecord, Kind};
    use std::future::Future;
    use tokio::io::AsyncRead;
    use zerocopy::IntoBytes as _;

    const DEADLINE: Duration = Duration::from_secs(5);

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    /// Fails the test instead of hanging when `fut` does not finish.
    async fn within<T>(fut: impl Future<Output = T>) -> T {
        tokio::time::timeout(DEADLINE, fut)
            .await
            .expect("timed out")
    }

    /// A fresh private directory, removed when dropped. Created atomically, so
    /// nothing another user plants under the temp root is followed.
    fn test_dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn heartbeat() -> HeartbeatRecord {
        HeartbeatRecord {
            header: Header::for_observer(Kind::Heartbeat, HEARTBEAT_LEN, 9, 1),
            ..HeartbeatRecord::default()
        }
    }

    /// JSON on port 7000, looking up pods under `bundles`.
    fn options(bundles: Option<&Path>) -> Options {
        Options {
            port: 7000,
            format: Format::Json,
            bundles: bundles.map(Path::to_path_buf),
            otlp: None,
        }
    }

    /// Listens on the sandbox's vsock socket the way its VMM would, which makes
    /// this test process the VMM the sink accepts connections from.
    fn vmm(sandbox: &Path) -> std::os::unix::net::UnixListener {
        std::os::unix::net::UnixListener::bind(sandbox.join("clh.sock")).unwrap()
    }

    /// One listening sandbox under a fresh directory, served by `vmm` or not.
    async fn listening(
        serve: bool,
    ) -> (
        tempfile::TempDir,
        Option<std::os::unix::net::UnixListener>,
        HashMap<String, Listener>,
        mpsc::Receiver<Batch>,
    ) {
        let tmp = test_dir();
        let sandbox = tmp.path().join("0123456789abcdef");
        tokio::fs::create_dir_all(&sandbox).await.unwrap();
        let vmm = if serve {
            Some(vmm(&sandbox))
        } else {
            tokio::fs::write(sandbox.join("clh.sock"), b"")
                .await
                .unwrap();
            None
        };
        let (tx, rx) = mpsc::channel(8);
        let mut listeners = HashMap::new();
        scan(tmp.path(), &options(None), &mut listeners, &tx).await;
        assert_eq!(listeners.len(), 1);
        (tmp, vmm, listeners, rx)
    }

    /// Connects to the sandbox's port 7000 socket.
    async fn connect(tmp: &tempfile::TempDir) -> UnixStream {
        UnixStream::connect(tmp.path().join("0123456789abcdef/clh.sock_7000"))
            .await
            .unwrap()
    }

    /// Whether the sink closed `stream` without sending anything.
    async fn closed(stream: &mut UnixStream) -> bool {
        let mut buf = [0; 1];
        matches!(within(stream.read(&mut buf)).await, Ok(0) | Err(_))
    }

    /// The next line that is not the sink's own stream or audit line.
    async fn record_line(rx: &mut mpsc::Receiver<Batch>) -> serde_json::Value {
        loop {
            let batch = within(rx.recv()).await.unwrap();
            for line in batch.lines.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
                let v: serde_json::Value = serde_json::from_slice(line).unwrap();
                let name = v["event.name"].as_str().unwrap_or_default();
                if !name.starts_with("creche.stream.") && !name.starts_with("creche.audit.") {
                    return v;
                }
            }
        }
    }

    /// The first line in the next read from `out`.
    async fn read_line(out: &mut (impl AsyncRead + Unpin)) -> serde_json::Value {
        let mut buf = vec![0; 4096];
        let n = within(out.read(&mut buf)).await.unwrap();
        let first = buf[..n].split(|&b| b == b'\n').next().unwrap();
        serde_json::from_slice(first).unwrap()
    }

    #[test]
    fn listens_only_once_the_vmm_socket_exists_and_stops_when_the_sandbox_goes() {
        runtime().block_on(async {
            let tmp = test_dir();
            let dir = tmp.path();
            let sandbox = dir.join("0123456789abcdef");
            tokio::fs::create_dir_all(&sandbox).await.unwrap();
            let (tx, mut rx) = mpsc::channel(8);
            let mut listeners = HashMap::new();

            scan(dir, &options(None), &mut listeners, &tx).await;
            assert!(listeners.is_empty(), "no clh.sock yet");

            let _vmm = vmm(&sandbox);
            scan(dir, &options(None), &mut listeners, &tx).await;
            assert_eq!(listeners.len(), 1);
            let mode = std::fs::metadata(sandbox.join("clh.sock_7000"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);

            let mut guest = UnixStream::connect(sandbox.join("clh.sock_7000"))
                .await
                .unwrap();
            guest.write_all(heartbeat().as_bytes()).await.unwrap();
            let line = record_line(&mut rx).await;
            assert_eq!(line["creche.sandbox.id"], "0123456789abcdef");
            assert_eq!(line["event.name"], "creche.observer.heartbeat");

            tokio::fs::remove_dir_all(&sandbox).await.unwrap();
            scan(dir, &options(None), &mut listeners, &tx).await;
            assert!(listeners.is_empty());
        });
    }

    #[test]
    fn run_writes_lines_until_its_output_fails() {
        runtime().block_on(async {
            let tmp = test_dir();
            let dir = tmp.path().to_path_buf();
            let sandbox = dir.join("fedcba9876543210");
            tokio::fs::create_dir_all(&sandbox).await.unwrap();
            let _vmm = vmm(&sandbox);
            let (out, mut reader) = tokio::io::duplex(64 * 1024);
            let server = tokio::spawn(run_with(
                dir.clone(),
                Options {
                    port: 7001,
                    ..options(None)
                },
                out,
            ));

            let socket = sandbox.join("clh.sock_7001");
            within(async {
                while !socket.exists() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await;
            let mut guest = UnixStream::connect(&socket).await.unwrap();
            guest.write_all(heartbeat().as_bytes()).await.unwrap();
            let line = read_line(&mut reader).await;
            assert_eq!(line["creche.sandbox.id"], "fedcba9876543210");

            // Closing the output ends the sink with an error.
            drop(reader);
            guest.write_all(heartbeat().as_bytes()).await.unwrap();
            assert!(within(server).await.unwrap().is_err());
        });
    }

    #[test]
    fn a_corrupt_stream_ends_with_its_reason_and_last_checkpoint() {
        runtime().block_on(async {
            let (tx, mut rx) = mpsc::channel(8);
            let (mut guest, host) = UnixStream::pair().unwrap();
            let task = tokio::spawn(receive(
                host,
                Origin::from("sb"),
                None,
                Peer {
                    pid: None,
                    uid: None,
                },
                Format::Json,
                tx,
            ));
            // One good record, then a corrupt one.
            let mut bad = heartbeat();
            bad.header.len = 3;
            guest
                .write_all(&[heartbeat().as_bytes(), bad.as_bytes()].concat())
                .await
                .unwrap();
            within(task).await.unwrap();
            let mut output = Vec::new();
            while let Ok(batch) = rx.try_recv() {
                output.extend(batch.lines);
            }
            let names: Vec<String> = output
                .split(|&b| b == b'\n')
                .filter(|l| !l.is_empty())
                .map(|l| {
                    let v: serde_json::Value = serde_json::from_slice(l).unwrap();
                    assert!(v["creche.stream.id"].is_string());
                    format!("{} {}", v["event.name"], v["creche.stream.end_reason"])
                })
                .collect();
            assert_eq!(
                names,
                [
                    "\"creche.stream.start\" null",
                    "\"creche.observer.heartbeat\" null",
                    "\"creche.stream.end\" \"corrupt\"",
                    "\"creche.audit.checkpoint\" null",
                ]
            );
            let report = crate::audit::verify(&output);
            assert!(report.intact(), "{report:?}");
            assert!(report.streams.values().all(|s| s.ended && s.verified == 3));
        });
    }

    #[test]
    fn dropping_a_listener_removes_its_socket() {
        runtime().block_on(async {
            let tmp = test_dir();
            let socket = tmp.path().join("clh.sock_7002");
            let listener = UnixListener::bind(&socket).unwrap();
            let task = tokio::spawn(async move {
                let _ = listener.accept().await;
            });
            drop(Listener {
                task,
                socket: socket.clone(),
            });
            assert!(!socket.exists());
        });
    }

    #[test]
    fn only_the_sandbox_vmm_may_connect() {
        runtime().block_on(async {
            // The vsock socket exists, but no process serves it: whoever
            // connects is not the VMM.
            let (tmp, _vmm, _listeners, mut rx) = listening(false).await;
            let mut intruder = connect(&tmp).await;
            intruder.write_all(heartbeat().as_bytes()).await.unwrap();
            assert!(closed(&mut intruder).await);
            // Reported, with the intruder's pid, outside any stream.
            let refused = within(rx.recv()).await.unwrap();
            let v: serde_json::Value = serde_json::from_slice(&refused.lines).unwrap();
            assert_eq!(v["event.name"], "creche.sink.refused");
            assert_eq!(v["creche.peer.pid"], std::process::id());
            assert!(
                v["creche.sink.refusal"]
                    .as_str()
                    .unwrap()
                    .contains("not the sandbox's VMM")
            );
            assert!(v.get("creche.stream.id").is_none());
            assert!(rx.try_recv().is_err());
        });
    }

    #[test]
    fn a_sandbox_takes_a_limited_number_of_connections() {
        runtime().block_on(async {
            let (tmp, _vmm, _listeners, mut rx) = listening(true).await;
            let mut open = Vec::new();
            for _ in 0..MAX_CONNECTIONS {
                let mut guest = connect(&tmp).await;
                guest.write_all(heartbeat().as_bytes()).await.unwrap();
                record_line(&mut rx).await;
                open.push(guest);
            }
            let mut extra = connect(&tmp).await;
            assert!(closed(&mut extra).await);
            let v = record_line(&mut rx).await;
            assert_eq!(v["event.name"], "creche.sink.refused");
            assert_eq!(v["creche.sink.refusal"], "4 connections already open");

            // Closing one makes room again.
            drop(open.pop());
            let mut guest = within(async {
                loop {
                    let mut guest = connect(&tmp).await;
                    guest.write_all(heartbeat().as_bytes()).await.unwrap();
                    let line =
                        tokio::time::timeout(Duration::from_millis(100), record_line(&mut rx))
                            .await;
                    if line.is_ok_and(|v| v["event.name"] == "creche.observer.heartbeat") {
                        break guest;
                    }
                }
            })
            .await;
            guest.write_all(heartbeat().as_bytes()).await.unwrap();
            assert_eq!(
                record_line(&mut rx).await["event.name"],
                "creche.observer.heartbeat"
            );
        });
    }

    #[test]
    fn sandbox_ids_must_be_containerd_identifiers() {
        for id in [
            "0123456789abcdef",
            "a",
            "pod-1.x_y",
            &"a".repeat(MAX_ID_LEN),
        ] {
            assert!(valid_id(id), "{id}");
        }
        for id in [
            "",
            ".",
            "..",
            "-a",
            "a-",
            "a--b",
            "a b",
            "a\nb",
            "caf\u{e9}",
            &"a".repeat(MAX_ID_LEN + 1),
        ] {
            assert!(!valid_id(id), "{id:?}");
        }
        runtime().block_on(async {
            let tmp = test_dir();
            let sandbox = tmp.path().join("not valid");
            tokio::fs::create_dir_all(&sandbox).await.unwrap();
            let _vmm = vmm(&sandbox);
            let (tx, _rx) = mpsc::channel(8);
            let mut listeners = HashMap::new();
            scan(tmp.path(), &options(None), &mut listeners, &tx).await;
            assert!(listeners.is_empty());
        });
    }

    #[test]
    fn each_connection_names_the_pod_from_the_runtime_bundle() {
        runtime().block_on(async {
            let tmp = test_dir();
            let bundles = tmp.path().join("bundles");
            let vms = tmp.path().join("vm");
            for id in ["0123456789abcdef", "fedcba9876543210"] {
                tokio::fs::create_dir_all(vms.join(id)).await.unwrap();
            }
            // Only the first sandbox is a pod.
            let bundle = bundles.join("0123456789abcdef");
            std::fs::create_dir_all(&bundle).unwrap();
            std::fs::set_permissions(&bundle, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::write(
                bundle.join("config.json"),
                r#"{"annotations":{"io.kubernetes.cri.container-type":"sandbox",
                "io.kubernetes.cri.sandbox-id":"0123456789abcdef",
                "io.kubernetes.cri.sandbox-name":"agent-7",
                "io.kubernetes.cri.sandbox-namespace":"agents",
                "io.kubernetes.cri.sandbox-uid":"1f2e"}}"#,
            )
            .unwrap();
            let _vmms = [
                vmm(&vms.join("0123456789abcdef")),
                vmm(&vms.join("fedcba9876543210")),
            ];
            let (tx, mut rx) = mpsc::channel(8);
            let mut listeners = HashMap::new();
            scan(&vms, &options(Some(&bundles)), &mut listeners, &tx).await;
            assert_eq!(listeners.len(), 2);

            for (id, pod, unresolved) in [
                ("0123456789abcdef", "agent-7", serde_json::Value::Null),
                ("fedcba9876543210", "", "no_bundle".into()),
            ] {
                let mut guest = UnixStream::connect(vms.join(id).join("clh.sock_7000"))
                    .await
                    .unwrap();
                guest.write_all(heartbeat().as_bytes()).await.unwrap();
                let line = record_line(&mut rx).await;
                assert_eq!(line["creche.sandbox.id"], id);
                assert_eq!(line["k8s.pod.name"].as_str().unwrap_or(""), pod);
                assert_eq!(line["creche.k8s.unresolved"], unresolved);
            }
        });
    }

    #[test]
    fn stream_ids_are_unique_and_share_the_sink_start() {
        let (a, b) = (stream_id(), stream_id());
        assert_ne!(a, b);
        let (start_a, n_a) = a.split_once('-').unwrap();
        let (start_b, n_b) = b.split_once('-').unwrap();
        assert_eq!(start_a, start_b);
        assert!(u64::from_str_radix(start_a, 16).unwrap() > 0);
        assert!(n_b.parse::<u64>().unwrap() > n_a.parse::<u64>().unwrap());
    }

    fn batch_of(lines: &str) -> Batch {
        Batch {
            origin: Arc::new(Origin::from("sb")),
            observed_ns: 1,
            lines: lines.as_bytes().to_vec(),
        }
    }

    #[test]
    fn the_exporter_gets_what_fits_and_stdout_gets_everything() {
        runtime().block_on(async {
            let (tx, rx) = mpsc::channel(8);
            let (otx, mut orx) = mpsc::channel(1);
            let (out, mut reader) = tokio::io::duplex(64 * 1024);
            for text in ["a\n", "b\nc\n", "d\n"] {
                tx.send(batch_of(text)).await.unwrap();
            }
            drop(tx);
            write_output(rx, out, Some(otx)).await.unwrap();
            let mut written = String::new();
            reader.read_to_string(&mut written).await.unwrap();
            assert_eq!(written, "a\nb\nc\nd\n");
            // The exporter queue held one batch. The others were dropped.
            assert_eq!(orx.recv().await.unwrap().lines, b"a\n");
            assert!(orx.recv().await.is_none());
        });
    }

    #[test]
    fn dropped_lines_are_counted_and_reported_now_and_then() {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .unwrap()
            .block_on(async {
                let mut dropped = Dropped::default();
                let start = dropped.reported;
                dropped.count(b"abc\nde\n");
                dropped.count(b"fgh\n");
                assert_eq!(dropped.lines, 3);
                assert_eq!(dropped.reported, start, "too soon to report");
                tokio::time::advance(DROP_REPORT).await;
                dropped.count(b"");
                assert_eq!(dropped.lines, 3);
                assert_eq!(dropped.reported, start + DROP_REPORT, "reported");
            });
    }

    #[test]
    fn short_ids() {
        assert_eq!(short("0123456789abcdef"), "0123456789ab");
        assert_eq!(short("abc"), "abc");
    }
}
