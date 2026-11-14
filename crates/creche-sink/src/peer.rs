//! Who may connect to a sandbox's socket.
//!
//! Cloud Hypervisor connects to `clh.sock_P` when its guest connects to vsock
//! port P. So the only process that ever needs to connect is the sandbox's VMM,
//! the process listening on the vsock socket `clh.sock`. The guest cannot choose
//! which socket its connection arrives on, and other host processes are refused
//! here, so the sandbox id of an accepted connection is a fact the host attests,
//! not something the guest or a neighbour claims.
//!
//! The kernel names the VMM: a connection to `clh.sock` carries the credentials
//! of the process that listens on it. No path is read back from `/proc`. A path
//! there is only the name a socket was bound under, and its binder can make that
//! name lead to any other socket with a link, or bind it in a mount namespace of
//! its own. The VMM is pinned by its pid and its start time, so a process that
//! later reuses its pid is not taken for it. Reading the start time needs only
//! `/proc/<pid>/stat`. Root on the host is trusted: it could ptrace the VMM
//! anyway.

use std::fmt;
use std::fs;
use std::io;
use std::path::Path;

use tokio::net::UnixStream;

/// Why a connection was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The kernel did not report the peer's pid.
    NoPid,
    /// The peer runs as another user than the VMM.
    Uid {
        /// The peer's user id.
        peer: u32,
        /// The VMM's user id.
        owner: u32,
    },
    /// The peer is not the process listening on the sandbox's vsock socket.
    NotVmm {
        /// The peer's pid.
        pid: i32,
    },
    /// The peer could not be inspected.
    Io(io::ErrorKind),
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoPid => write!(f, "peer pid unknown"),
            Self::Uid { peer, owner } => write!(f, "peer uid {peer} is not the VMM's {owner}"),
            Self::NotVmm { pid } => write!(f, "pid {pid} is not the sandbox's VMM"),
            Self::Io(kind) => write!(f, "cannot inspect the peer: {kind}"),
        }
    }
}

impl From<io::Error> for Refusal {
    fn from(e: io::Error) -> Self {
        Self::Io(e.kind())
    }
}

/// The process listening on a sandbox's vsock socket: its VMM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vmm {
    pid: i32,
    uid: u32,
    gid: u32,
    /// When the process started, in clock ticks since boot.
    start: u64,
}

impl Vmm {
    /// Asks the kernel who listens on `vsock`, by connecting to it and reading
    /// the credentials the connection carries. The connection is closed without
    /// sending anything, which the VMM sees as a peer that went away.
    ///
    /// # Errors
    ///
    /// When nothing listens on `vsock` yet, or the listener cannot be inspected.
    pub async fn probe(vsock: &Path) -> io::Result<Self> {
        let cred = UnixStream::connect(vsock).await?.peer_cred()?;
        let pid = cred
            .pid()
            .filter(|&pid| pid > 0)
            .ok_or_else(|| io::Error::other("the listener's pid is unknown"))?;
        Ok(Self {
            pid,
            uid: cred.uid(),
            gid: cred.gid(),
            start: start_time(Path::new("/proc"), pid)?,
        })
    }

    /// The VMM's user id.
    #[must_use]
    pub const fn uid(&self) -> u32 {
        self.uid
    }

    /// The VMM's group id.
    #[must_use]
    pub const fn gid(&self) -> u32 {
        self.gid
    }
}

#[cfg(test)]
impl Vmm {
    /// Another process standing in as a VMM run by `uid`: init.
    pub(crate) fn init(uid: u32) -> Self {
        Self {
            pid: 1,
            uid,
            gid: 0,
            start: start_time(Path::new("/proc"), 1).unwrap(),
        }
    }
}

/// Accepts a peer with `pid` and `uid` only when it is `vmm`. Blocking: it reads
/// `/proc`.
///
/// # Errors
///
/// The reason the peer is refused.
pub fn check(pid: Option<i32>, uid: u32, vmm: &Vmm) -> Result<(), Refusal> {
    let pid = pid.filter(|&pid| pid > 0).ok_or(Refusal::NoPid)?;
    if uid != vmm.uid {
        return Err(Refusal::Uid {
            peer: uid,
            owner: vmm.uid,
        });
    }
    if pid == vmm.pid && start_time(Path::new("/proc"), pid)? == vmm.start {
        Ok(())
    } else {
        Err(Refusal::NotVmm { pid })
    }
}

/// When `pid` started, from field 22 of `/proc/<pid>/stat`. The fields are
/// counted after the command name, which is in parentheses and may hold spaces
/// and parentheses itself.
fn start_time(proc: &Path, pid: i32) -> io::Result<u64> {
    let stat = fs::read_to_string(proc.join(pid.to_string()).join("stat"))?;
    stat.rsplit_once(')')
        .and_then(|(_, fields)| fields.split_ascii_whitespace().nth(19)?.parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed stat"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::net::UnixListener;

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn the_vmm_is_the_process_the_kernel_reports_listening() {
        runtime().block_on(async {
            let tmp = tempfile::tempdir().unwrap();
            let vsock = tmp.path().join("clh.sock");
            let uid = fs::metadata(tmp.path()).unwrap().uid();
            let pid = i32::try_from(std::process::id()).unwrap();

            // A plain file, or nobody listening: no VMM yet.
            fs::write(&vsock, b"").unwrap();
            assert!(Vmm::probe(&vsock).await.is_err());
            fs::remove_file(&vsock).unwrap();
            assert!(Vmm::probe(&vsock).await.is_err());

            // This process listens on it, as Cloud Hypervisor does.
            let listener = UnixListener::bind(&vsock).unwrap();
            let vmm = Vmm::probe(&vsock).await.unwrap();
            assert_eq!((vmm.pid, vmm.uid), (pid, uid));
            assert_eq!(check(Some(pid), uid, &vmm), Ok(()));
            assert_eq!(check(None, uid, &vmm), Err(Refusal::NoPid));
            assert_eq!(check(Some(0), uid, &vmm), Err(Refusal::NoPid));
            assert_eq!(
                check(Some(pid), uid + 1, &vmm),
                Err(Refusal::Uid {
                    peer: uid + 1,
                    owner: uid
                })
            );
            // Any other process is not the VMM, whatever it listens on.
            assert_eq!(check(Some(1), uid, &vmm), Err(Refusal::NotVmm { pid: 1 }));
            // Nor is a process that reuses the VMM's pid later.
            let reused = Vmm {
                start: vmm.start + 1,
                ..vmm
            };
            assert_eq!(check(Some(pid), uid, &reused), Err(Refusal::NotVmm { pid }));
            drop(listener);
        });
    }

    #[test]
    fn a_link_to_the_vsock_socket_reaches_the_same_listener() {
        runtime().block_on(async {
            // A peer may bind its own socket and then make its name lead to the
            // sandbox's vsock socket. The probe asks who listens on the vsock
            // socket itself, so such a name changes nothing.
            let tmp = tempfile::tempdir().unwrap();
            let vsock = tmp.path().join("clh.sock");
            let _vmm = UnixListener::bind(&vsock).unwrap();
            let decoy = tmp.path().join("decoy.sock");
            let _decoy = UnixListener::bind(&decoy).unwrap();
            fs::remove_file(&decoy).unwrap();
            std::os::unix::fs::symlink(&vsock, &decoy).unwrap();
            assert_eq!(
                Vmm::probe(&decoy).await.unwrap(),
                Vmm::probe(&vsock).await.unwrap()
            );
        });
    }

    #[test]
    fn start_times_are_read_after_the_command_name() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("42");
        fs::create_dir(&dir).unwrap();
        // The command name may hold spaces and parentheses.
        let fields: Vec<String> = (3..=22).map(|n| n.to_string()).collect();
        fs::write(
            dir.join("stat"),
            format!("42 (a) b (c) {} 23 24\n", fields.join(" ")),
        )
        .unwrap();
        assert_eq!(start_time(tmp.path(), 42).unwrap(), 22);
        fs::write(dir.join("stat"), "42 (a) S 1\n").unwrap();
        assert_eq!(
            start_time(tmp.path(), 42).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(start_time(tmp.path(), 43).is_err());
    }

    #[test]
    fn refusals_display() {
        assert_eq!(Refusal::NoPid.to_string(), "peer pid unknown");
        assert_eq!(
            Refusal::Uid { peer: 1, owner: 0 }.to_string(),
            "peer uid 1 is not the VMM's 0"
        );
        assert_eq!(
            Refusal::NotVmm { pid: 9 }.to_string(),
            "pid 9 is not the sandbox's VMM"
        );
        assert_eq!(
            Refusal::Io(io::ErrorKind::PermissionDenied).to_string(),
            "cannot inspect the peer: permission denied"
        );
    }
}
