//! Where records go: the host over vsock, or stdout.

use std::fs::File;
use std::io::{self, Stdout, Write};
use std::os::fd::AsRawFd as _;

use nix::sys::socket::{AddressFamily, SockFlag, SockType, VsockAddr, connect, socket};

use creche_observer::queue::RecordQueue;

/// The host's context id on the vsock bus.
const VMADDR_CID_HOST: u32 = 2;

/// Destination of the record stream.
#[derive(Clone, Copy, Debug)]
pub enum Target {
    /// The host, on this vsock port.
    Vsock(u32),
    /// Standard output (for testing and capture).
    Stdout,
}

enum Conn {
    Vsock(File),
    Stdout(Stdout),
}

impl Write for Conn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Vsock(f) => f.write(buf),
            Self::Stdout(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Vsock(f) => f.flush(),
            Self::Stdout(s) => s.flush(),
        }
    }
}

/// A lazily (re)connected output. Every new connection starts with a hello record.
pub struct Output {
    target: Target,
    conn: Option<Conn>,
    connected_before: bool,
}

impl Output {
    /// An output that connects on first use.
    #[must_use]
    pub const fn new(target: Target) -> Self {
        Self {
            target,
            conn: None,
            connected_before: false,
        }
    }

    /// Connects if not connected. A new connection starts with the record
    /// `hello` builds. A failed attempt is retried on the next call.
    ///
    /// Returns `true` when this call reconnected: the host may have lost records
    /// sent on the previous connection, and it knows nothing of what was said on
    /// it.
    pub fn connect_if_needed<H: AsRef<[u8]>>(&mut self, hello: impl FnOnce() -> H) -> bool {
        if self.conn.is_some() {
            return false;
        }
        self.conn = self.connect(hello).ok();
        if self.conn.is_none() {
            return false;
        }
        let reconnected = self.connected_before;
        self.connected_before = true;
        reconnected
    }

    /// Sends the queued records, when connected. A failed connection is
    /// dropped and the records stay queued.
    pub fn flush(&mut self, queue: &mut RecordQueue) {
        if let Some(conn) = &mut self.conn
            && queue.flush(conn).is_err()
        {
            self.conn = None;
        }
    }

    fn connect<H: AsRef<[u8]>>(&self, hello: impl FnOnce() -> H) -> io::Result<Conn> {
        let mut conn = match self.target {
            Target::Stdout => Conn::Stdout(io::stdout()),
            Target::Vsock(port) => {
                let fd = socket(
                    AddressFamily::Vsock,
                    SockType::Stream,
                    SockFlag::SOCK_CLOEXEC,
                    None,
                )?;
                connect(fd.as_raw_fd(), &VsockAddr::new(VMADDR_CID_HOST, port))?;
                Conn::Vsock(File::from(fd))
            }
        };
        conn.write_all(hello().as_ref())?;
        Ok(conn)
    }
}
