//! Who may connect to a sandbox's socket.
//!
//! Cloud Hypervisor connects to `clh.sock_P` when its guest connects to vsock
//! port P. So the only process that ever needs to connect is the sandbox's VMM,
//! the process holding the listening vsock socket `clh.sock`. The guest cannot
//! choose which socket its connection arrives on, and other host processes are
//! refused here, so the sandbox id of an accepted connection is a fact the
//! host attests, not something the guest or a neighbour claims.
//!
//! The checks read `/proc/<pid>/fd` of the peer, which needs the same user as
//! the VMM or root. Root on the host is trusted: it could ptrace the VMM anyway.

use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

/// `__SO_ACCEPTCON` in the flags column of `/proc/net/unix`: a listening socket.
const ACCEPTING: u32 = 0x0001_0000;

/// Why a connection was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The kernel did not report the peer's pid.
    NoPid,
    /// The peer runs as another user than the one owning the vsock socket.
    Uid {
        /// The peer's user id.
        peer: u32,
        /// The owner of `clh.sock`.
        owner: u32,
    },
    /// The peer does not hold the sandbox's listening vsock socket.
    NotVmm {
        /// The peer's pid.
        pid: i32,
    },
    /// The peer or the socket could not be inspected.
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

/// Accepts a peer with `pid` and `uid` only when it is the VMM serving the
/// listening vsock socket at `vsock`. Blocking: it reads `/proc`.
///
/// # Errors
///
/// The reason the peer is refused.
pub fn check(pid: Option<i32>, uid: u32, vsock: &Path) -> Result<(), Refusal> {
    let pid = pid.ok_or(Refusal::NoPid)?;
    let socket = fs::symlink_metadata(vsock)?;
    if uid != socket.uid() {
        return Err(Refusal::Uid {
            peer: uid,
            owner: socket.uid(),
        });
    }
    if holds_listener(Path::new("/proc"), pid, (socket.dev(), socket.ino()))? {
        Ok(())
    } else {
        Err(Refusal::NotVmm { pid })
    }
}

/// Whether `pid` has an open listening unix socket bound to the file `file`,
/// given as (device, inode). The peer's own `net/unix` is read because the VMM
/// may run in another network namespace.
fn holds_listener(proc: &Path, pid: i32, file: (u64, u64)) -> io::Result<bool> {
    let dir = proc.join(pid.to_string());
    let table = fs::read(dir.join("net/unix"))?;
    let sockets: Vec<u64> = table
        .split(|&b| b == b'\n')
        .filter_map(|line| listener(std::str::from_utf8(line).ok()?))
        .filter(|(_, path)| fs::metadata(path).is_ok_and(|m| (m.dev(), m.ino()) == file))
        .map(|(inode, _)| inode)
        .collect();
    if sockets.is_empty() {
        return Ok(false);
    }
    for entry in fs::read_dir(dir.join("fd"))? {
        // An fd may close while the directory is read.
        let Ok(target) = entry.and_then(|e| fs::read_link(e.path())) else {
            continue;
        };
        if socket_inode(target.as_os_str()).is_some_and(|inode| sockets.contains(&inode)) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The socket inode and bound path of a listening socket's line in
/// `/proc/net/unix`: `Num RefCount Protocol Flags Type St Inode Path`, with the
/// inode right-aligned and the path running to the end of the line.
fn listener(line: &str) -> Option<(u64, &str)> {
    let mut rest = line;
    let mut fields = [""; 7];
    for field in &mut fields {
        rest = rest.trim_start_matches(' ');
        let end = rest.find(' ').unwrap_or(rest.len());
        (*field, rest) = rest.split_at_checked(end)?;
    }
    let [_, _, _, flags, _, _, inode] = fields;
    let path = rest.strip_prefix(' ').filter(|p| p.starts_with('/'))?;
    let listening = u32::from_str_radix(flags, 16).ok()? & ACCEPTING != 0;
    listening.then_some((inode.parse().ok()?, path))
}

/// The inode in an fd link of the form `socket:[N]`.
fn socket_inode(link: &OsStr) -> Option<u64> {
    link.to_str()?
        .strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::{UnixListener, UnixStream};

    #[test]
    fn listeners_are_parsed_from_proc_net_unix() {
        let line =
            "0000000000000000: 00000002 00000000 00010000 0001 01  4242 /run/vc/vm/ab/clh.sock";
        assert_eq!(listener(line), Some((4242, "/run/vc/vm/ab/clh.sock")));
        // Paths keep their spaces.
        let line = "0000000000000000: 00000002 00000000 00010000 0001 01 7 /tmp/a b";
        assert_eq!(listener(line), Some((7, "/tmp/a b")));
        for line in [
            // Connected, not listening.
            "0000000000000000: 00000003 00000000 00000000 0001 03 4242 /run/vc/vm/ab/clh.sock",
            // Abstract and unbound sockets have no file.
            "0000000000000000: 00000002 00000000 00010000 0001 01 4242 @abstract",
            "0000000000000000: 00000002 00000000 00010000 0001 01 4242",
            "Num       RefCount Protocol Flags    Type St Inode Path",
            "",
        ] {
            assert_eq!(listener(line), None, "{line}");
        }
    }

    #[test]
    fn socket_links_carry_their_inode() {
        assert_eq!(socket_inode(OsStr::new("socket:[123]")), Some(123));
        assert_eq!(socket_inode(OsStr::new("pipe:[123]")), None);
        assert_eq!(socket_inode(OsStr::new("socket:[12")), None);
        assert_eq!(socket_inode(OsStr::new("/dev/null")), None);
    }

    #[test]
    fn only_the_process_holding_the_vsock_socket_is_the_vmm() {
        let tmp = tempfile::tempdir().unwrap();
        let vsock = tmp.path().join("clh.sock");
        let uid = fs::metadata(tmp.path()).unwrap().uid();
        let pid = i32::try_from(std::process::id()).unwrap();

        // A plain file: nobody serves this sandbox.
        fs::write(&vsock, b"").unwrap();
        assert_eq!(check(Some(pid), uid, &vsock), Err(Refusal::NotVmm { pid }));
        fs::remove_file(&vsock).unwrap();

        // This process listens on it, as Cloud Hypervisor does.
        let listener = UnixListener::bind(&vsock).unwrap();
        assert_eq!(check(Some(pid), uid, &vsock), Ok(()));
        assert_eq!(check(None, uid, &vsock), Err(Refusal::NoPid));
        assert_eq!(
            check(Some(pid), uid + 1, &vsock),
            Err(Refusal::Uid {
                peer: uid + 1,
                owner: uid
            })
        );

        // Holding a connection to it is not enough, only the listener counts.
        let _client = UnixStream::connect(&vsock).unwrap();
        drop(listener);
        assert_eq!(check(Some(pid), uid, &vsock), Err(Refusal::NotVmm { pid }));

        // Another socket file at the same path is another sandbox.
        fs::remove_file(&vsock).unwrap();
        let _other = UnixListener::bind(tmp.path().join("other.sock")).unwrap();
        fs::write(&vsock, b"").unwrap();
        assert_eq!(check(Some(pid), uid, &vsock), Err(Refusal::NotVmm { pid }));
        assert_eq!(
            check(Some(pid), uid, &tmp.path().join("gone")),
            Err(Refusal::Io(io::ErrorKind::NotFound))
        );
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
