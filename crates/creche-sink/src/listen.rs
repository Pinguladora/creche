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
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::task::JoinHandle;

use crate::peer::{self, Refusal};
use crate::stream::{Format, StreamDecoder};

/// How often sandbox directories are rescanned.
const SCAN_INTERVAL: Duration = Duration::from_millis(200);
/// Rendered batches waiting for the writer. Senders wait when it is full.
const OUTPUT_BACKLOG: usize = 1024;
/// Read size per connection.
const READ_CHUNK: usize = 65_536; // 64 KiB
/// Open connections per sandbox. An observer keeps one, a restarted observer
/// briefly two. Each connection costs a decoder and a task cache.
const MAX_CONNECTIONS: usize = 4;
/// Longest sandbox id. containerd ids are at most 76 characters.
const MAX_ID_LEN: usize = 76;

/// Listens for every sandbox under `dir` on vsock `port`, writing `format` to
/// stdout, until stdout fails.
///
/// # Errors
///
/// When stdout cannot be written.
pub async fn run(dir: PathBuf, port: u32, format: Format) -> io::Result<()> {
    run_with(dir, port, format, tokio::io::stdout()).await
}

/// [`run`], writing to `out`.
async fn run_with<W>(dir: PathBuf, port: u32, format: Format, out: W) -> io::Result<()>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (tx, rx) = mpsc::channel(OUTPUT_BACKLOG);
    let writer = tokio::spawn(write_output(rx, out));
    let mut listeners: HashMap<String, Listener> = HashMap::new();
    let mut tick = tokio::time::interval(SCAN_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    while !writer.is_finished() {
        tick.tick().await;
        scan(&dir, port, format, &mut listeners, &tx).await;
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
    port: u32,
    format: Format,
    listeners: &mut HashMap<String, Listener>,
    tx: &mpsc::Sender<Vec<u8>>,
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
        let socket = sandbox.join(format!("clh.sock_{port}"));
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
        };
        let task = tokio::spawn(accept(listener, sandbox, format, tx.clone()));
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
}

async fn accept(
    listener: UnixListener,
    sandbox: Sandbox,
    format: Format,
    tx: mpsc::Sender<Vec<u8>>,
) {
    let connections = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    while let Ok((stream, _)) = listener.accept().await {
        let Ok(permit) = Arc::clone(&connections).try_acquire_owned() else {
            eprintln!(
                "creche-sink: refusing a connection to {}: {MAX_CONNECTIONS} already open",
                short(&sandbox.id)
            );
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
    tx: mpsc::Sender<Vec<u8>>,
    _permit: OwnedSemaphorePermit,
) {
    let verdict = match stream.peer_cred() {
        Ok(cred) => {
            let vsock = Arc::clone(&sandbox.vsock);
            tokio::task::spawn_blocking(move || peer::check(cred.pid(), cred.uid(), &vsock))
                .await
                .unwrap_or(Err(Refusal::Io(io::ErrorKind::Other)))
        }
        Err(e) => Err(Refusal::from(e)),
    };
    match verdict {
        Ok(()) => receive(stream, sandbox.id, format, tx).await,
        Err(refusal) => eprintln!(
            "creche-sink: refusing a connection to {}: {refusal}",
            short(&sandbox.id)
        ),
    }
}

/// Decodes one connection until it closes or turns out to be corrupt.
async fn receive(
    mut stream: UnixStream,
    sandbox: Arc<str>,
    format: Format,
    tx: mpsc::Sender<Vec<u8>>,
) {
    let mut decoder = StreamDecoder::new(format);
    let mut chunk = vec![0; READ_CHUNK];
    loop {
        let n = match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let mut lines = Vec::new();
        if let Err(e) = decoder.feed(chunk.get(..n).unwrap_or_default(), &sandbox, &mut lines) {
            eprintln!(
                "creche-sink: dropping corrupt stream from {}: {e}",
                short(&sandbox)
            );
            break;
        }
        if !lines.is_empty() && tx.send(lines).await.is_err() {
            break;
        }
    }
}

/// Writes batches in arrival order, flushing whenever the backlog is empty.
async fn write_output(
    mut rx: mpsc::Receiver<Vec<u8>>,
    out: impl AsyncWrite + Unpin,
) -> io::Result<()> {
    let mut out = tokio::io::BufWriter::new(out);
    while let Some(batch) = rx.recv().await {
        out.write_all(&batch).await?;
        if rx.is_empty() {
            out.flush().await?;
        }
    }
    out.flush().await
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
        mpsc::Receiver<Vec<u8>>,
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
        scan(tmp.path(), 7000, Format::Json, &mut listeners, &tx).await;
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

    async fn read_line(out: &mut (impl AsyncRead + Unpin)) -> serde_json::Value {
        let mut buf = vec![0; 4096];
        let n = within(out.read(&mut buf)).await.unwrap();
        serde_json::from_slice(&buf[..n]).unwrap()
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

            scan(dir, 7000, Format::Json, &mut listeners, &tx).await;
            assert!(listeners.is_empty(), "no clh.sock yet");

            let _vmm = vmm(&sandbox);
            scan(dir, 7000, Format::Json, &mut listeners, &tx).await;
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
            let lines = within(rx.recv()).await.unwrap();
            let line: serde_json::Value = serde_json::from_slice(&lines).unwrap();
            assert_eq!(line["creche.sandbox.id"], "0123456789abcdef");
            assert_eq!(line["event.name"], "creche.observer.heartbeat");

            tokio::fs::remove_dir_all(&sandbox).await.unwrap();
            scan(dir, 7000, Format::Json, &mut listeners, &tx).await;
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
            let server = tokio::spawn(run_with(dir.clone(), 7001, Format::Json, out));

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
    fn a_corrupt_stream_is_dropped_without_output() {
        runtime().block_on(async {
            let (tx, mut rx) = mpsc::channel(8);
            let (mut guest, host) = UnixStream::pair().unwrap();
            let task = tokio::spawn(receive(host, Arc::from("sb"), Format::Json, tx));
            let mut bad = heartbeat();
            bad.header.len = 3;
            guest.write_all(bad.as_bytes()).await.unwrap();
            within(task).await.unwrap();
            assert!(rx.try_recv().is_err());
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
                within(rx.recv()).await.unwrap();
                open.push(guest);
            }
            let mut extra = connect(&tmp).await;
            assert!(closed(&mut extra).await);

            // Closing one makes room again.
            drop(open.pop());
            let mut guest = within(async {
                loop {
                    let mut guest = connect(&tmp).await;
                    guest.write_all(heartbeat().as_bytes()).await.unwrap();
                    if let Ok(Some(_)) =
                        tokio::time::timeout(Duration::from_millis(100), rx.recv()).await
                    {
                        break guest;
                    }
                }
            })
            .await;
            guest.write_all(heartbeat().as_bytes()).await.unwrap();
            within(rx.recv()).await.unwrap();
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
            scan(tmp.path(), 7000, Format::Json, &mut listeners, &tx).await;
            assert!(listeners.is_empty());
        });
    }

    #[test]
    fn short_ids() {
        assert_eq!(short("0123456789abcdef"), "0123456789ab");
        assert_eq!(short("abc"), "abc");
    }
}
