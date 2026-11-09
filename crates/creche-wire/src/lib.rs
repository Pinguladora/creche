//! Wire format between the creche guest observer and the host sink.
//!
//! A stream is a sequence of records. Every record starts with a [`Header`] whose
//! `len` is the total record length, so a reader can skip kinds it does not know.
//! Records carry only the pid. A process's context (parent, uid, cgroup, name)
//! comes in a [`TaskRecord`], sent before the first record about the process and
//! again whenever it changes, and exec records carry it too. A reader keeps it
//! per pid, copies it from parent to child on fork, updates it on exec and drops
//! it on exit.
//! Most records are produced by the guest kernel (the BPF ring buffer records are
//! the wire format, see `crates/creche-observer/bpf/observer.bpf.c`). Hello and
//! heartbeat records are produced by the observer itself. Fields are native-endian:
//! the guest and the host share the architecture.
//!
//! Memory profile: allocation-free. Decoding borrows from the input buffer.
#![no_std]
#![deny(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
// The decoder never allocates: heap types and macros are refused (clippy.toml
// in this crate), so the guarantee does not rest on `no_std` alone.
#![deny(clippy::disallowed_types, clippy::disallowed_macros)]

use core::fmt;
use core::mem::{offset_of, size_of};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout};

/// Wire format version, sent in the hello record.
pub const VERSION: u32 = 3;
/// Length of a task command name, including the NUL terminator.
pub const COMM_LEN: usize = 16;
/// Maximum path length carried in a record.
pub const PATH_LEN: usize = 256;
/// Maximum length of the NUL-separated argument vector in an exec record.
pub const ARGS_LEN: usize = 512;
/// Maximum length of a cgroup leaf name in a task record.
pub const CGROUP_LEN: usize = 96;
/// Upper bound on a record length. Anything larger means the stream is corrupt.
pub const MAX_RECORD_LEN: usize = 4096;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

/// Record kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A process image was replaced (`execve`).
    Exec,
    /// A new process (not thread) was created.
    Fork,
    /// A process exited.
    Exit,
    /// A TCP connection was initiated.
    Connect,
    /// A file was opened for writing.
    OpenWrite,
    /// A process's context, new or changed.
    Task,
    /// First record on every connection, from the observer.
    Hello,
    /// Periodic liveness and self-cost report, from the observer.
    Heartbeat,
}

impl Kind {
    /// The on-wire value of this kind.
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::Exec => 1,
            Self::Fork => 2,
            Self::Exit => 3,
            Self::Connect => 4,
            Self::OpenWrite => 5,
            Self::Task => 6,
            Self::Hello => 100,
            Self::Heartbeat => 101,
        }
    }

    /// The kind for an on-wire value, if known.
    #[must_use]
    pub const fn from_code(code: u16) -> Option<Self> {
        Some(match code {
            1 => Self::Exec,
            2 => Self::Fork,
            3 => Self::Exit,
            4 => Self::Connect,
            5 => Self::OpenWrite,
            6 => Self::Task,
            100 => Self::Hello,
            101 => Self::Heartbeat,
            _ => return None,
        })
    }
}

/// Common prefix of every record.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct Header {
    /// Record kind, see [`Kind`].
    pub kind: u16,
    /// Total record length in bytes, header included.
    pub len: u16,
    /// Process id (thread group id) in the guest.
    pub pid: u32,
    /// Guest boot-time clock, in nanoseconds.
    pub ts_ns: u64,
}

/// Layout of a task record. Sent truncated to the used part of `cgroup`.
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, KnownLayout, Immutable)]
pub struct TaskRecord {
    /// Common header.
    pub header: Header,
    /// Parent process id.
    pub ppid: u32,
    /// Real user id.
    pub uid: u32,
    /// cgroup v2 id of the process.
    pub cgroup_id: u64,
    /// Process name (its main thread's command name), NUL-terminated.
    pub comm: [u8; COMM_LEN],
    /// cgroup v2 leaf name, e.g. `cri-containerd-<container id>.scope`.
    pub cgroup: [u8; CGROUP_LEN],
}

/// Layout of a fork record. `header.pid` is the child.
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, KnownLayout, Immutable)]
pub struct ForkRecord {
    /// Common header.
    pub header: Header,
    /// Parent process id.
    pub ppid: u32,
    /// Zero.
    pub reserved: u32,
}

/// Layout of an exit record.
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, KnownLayout, Immutable)]
pub struct ExitRecord {
    /// Common header.
    pub header: Header,
    /// Exit status (the value passed to `exit`).
    pub exit_code: i32,
    /// Zero.
    pub reserved: u32,
}

/// Layout of a connect record.
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, KnownLayout, Immutable)]
pub struct ConnectRecord {
    /// Common header.
    pub header: Header,
    /// Address family (`AF_INET` or `AF_INET6`).
    pub family: u16,
    /// Destination port, host byte order.
    pub dport: u16,
    /// Destination address, the first 4 bytes for IPv4.
    pub daddr: [u8; 16],
    /// Zero.
    pub reserved: u32,
}

/// Layout of an open-for-write record. Sent truncated to the used part of `path`.
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, KnownLayout, Immutable)]
pub struct OpenRecord {
    /// Common header.
    pub header: Header,
    /// Bytes used in `path`, including the NUL terminator.
    pub path_len: u32,
    /// Absolute path of the opened file.
    pub path: [u8; PATH_LEN],
}

/// Layout of an exec record. It carries the process's new context, all but the
/// cgroup name, which a task record sends when it changes. `data` holds
/// `path_len` bytes of the path, then `args_len` bytes of arguments. Sent
/// truncated to the used part.
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, KnownLayout, Immutable)]
pub struct ExecRecord {
    /// Common header.
    pub header: Header,
    /// Parent process id.
    pub ppid: u32,
    /// Real user id.
    pub uid: u32,
    /// cgroup v2 id of the process.
    pub cgroup_id: u64,
    /// Process name after the exec, NUL-terminated.
    pub comm: [u8; COMM_LEN],
    /// Bytes of path in `data`, including its NUL terminator.
    pub path_len: u16,
    /// Bytes of NUL-separated arguments in `data`, after the path.
    pub args_len: u16,
    /// Path of the executed binary, then its argument vector.
    pub data: [u8; PATH_LEN + ARGS_LEN],
}

/// Hello record, sent by the observer as the first record of a connection.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct HelloRecord {
    /// Common header.
    pub header: Header,
    /// Wire format version, see [`VERSION`].
    pub version: u32,
    /// Observer configuration, see [`HelloFlags`].
    pub flags: HelloFlags,
}

/// Observer configuration reported in the hello record.
#[repr(transparent)]
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable,
)]
pub struct HelloFlags(u32);

impl HelloFlags {
    /// Repeated opens of the same file by the same process are collapsed in the kernel.
    pub const DEDUP: Self = Self(1);
    /// The kernel lacks fentry support: only exec, fork and exit are reported.
    pub const PROCESS_ONLY: Self = Self(2);
    /// Only the observer can connect to the host on its port: a BPF LSM program
    /// refuses every other guest process. Without it, any guest process could
    /// send records the host takes for the observer's.
    pub const GUARDED: Self = Self(4);

    /// Raw bit value.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Whether every flag in `other` is set.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// `self` with the flags in `other` set too.
    #[must_use]
    pub const fn with(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// Heartbeat record: liveness plus the observer's own cost.
#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable,
)]
pub struct HeartbeatRecord {
    /// Common header.
    pub header: Header,
    /// Records the kernel could not queue because the ring buffer was full.
    pub ringbuf_drops: u64,
    /// Bytes delivered to the host so far.
    pub sent_bytes: u64,
    /// Bytes dropped because the forwarding queue was full.
    pub dropped_bytes: u64,
    /// Observer resident set size, in KiB.
    pub rss_kb: u64,
    /// Observer CPU time (user + system), in milliseconds.
    pub cpu_ms: u64,
    /// Kernel time spent in the observer's BPF programs (0 unless stats are enabled).
    pub bpf_run_ns: u64,
    /// Number of BPF program runs (0 unless stats are enabled).
    pub bpf_run_cnt: u64,
}

impl Default for Header {
    fn default() -> Self {
        Self::new_zeroed()
    }
}

impl Header {
    /// A header for a record of `kind` produced by the observer itself.
    #[must_use]
    pub fn for_observer(kind: Kind, len: u16, pid: u32, ts_ns: u64) -> Self {
        Self {
            kind: kind.code(),
            len,
            pid,
            ts_ns,
        }
    }
}

/// Record lengths, checked at compile time to fit the `u16` length field.
const fn record_len(size: usize) -> u16 {
    assert!(size <= MAX_RECORD_LEN);
    #[expect(
        clippy::cast_possible_truncation,
        reason = "bounded by MAX_RECORD_LEN above"
    )]
    let len = size as u16;
    len
}

/// Length of a hello record.
pub const HELLO_LEN: u16 = record_len(size_of::<HelloRecord>());
/// Length of a heartbeat record.
pub const HEARTBEAT_LEN: u16 = record_len(size_of::<HeartbeatRecord>());

// The layout contract with the C side (observer.bpf.c / creche.h). The
// observer's build.rs also turns this layout into C static asserts.
const _: () = {
    assert!(size_of::<Header>() == 16);
    assert!(size_of::<TaskRecord>() == 144);
    assert!(size_of::<ForkRecord>() == 24);
    assert!(size_of::<ExitRecord>() == 24);
    assert!(size_of::<ConnectRecord>() == 40);
    assert!(size_of::<OpenRecord>() == 280);
    assert!(size_of::<ExecRecord>() == 824);
    assert!(size_of::<HelloRecord>() == 24);
    assert!(size_of::<HeartbeatRecord>() == 72);
    assert!(offset_of!(TaskRecord, cgroup) == 48);
    assert!(offset_of!(OpenRecord, path) == 20);
    assert!(offset_of!(ExecRecord, comm) == offset_of!(TaskRecord, comm));
    assert!(offset_of!(ExecRecord, data) == 52);
};

/// Why a stream could not be decoded. Any of these means the stream is corrupt
/// and the connection should be dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The header's length is shorter than a header or longer than [`MAX_RECORD_LEN`].
    BadLength {
        /// The length found in the header.
        len: u16,
    },
    /// The record is shorter than the fixed part its kind requires.
    Truncated {
        /// The record kind.
        kind: Kind,
        /// The length found in the header.
        len: u16,
    },
    /// A variable-length field is longer than its maximum, or its length field
    /// disagrees with the bytes the record carries.
    BadField {
        /// The record kind.
        kind: Kind,
        /// The length found in the header.
        len: u16,
    },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadLength { len } => write!(f, "record length {len} out of bounds"),
            Self::Truncated { kind, len } => write!(f, "{kind:?} record truncated to {len} bytes"),
            Self::BadField { kind, len } => {
                write!(
                    f,
                    "{kind:?} record of {len} bytes has a field out of bounds"
                )
            }
        }
    }
}

impl core::error::Error for DecodeError {}

/// A decoded record, borrowing its variable-length fields from the input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record<'a> {
    /// Common header.
    pub header: Header,
    /// Kind-specific part.
    pub body: Body<'a>,
}

/// Kind-specific part of a record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Body<'a> {
    /// See [`ExecRecord`].
    Exec {
        /// The process's context after the exec.
        context: Context<'a>,
        /// Path of the executed binary.
        path: &'a [u8],
        /// NUL-separated argument vector, without trailing NULs.
        args: &'a [u8],
    },
    /// See [`TaskRecord`].
    Task {
        /// The process's context.
        context: Context<'a>,
        /// cgroup v2 leaf name.
        cgroup: &'a [u8],
    },
    /// A new process. `header.pid` is the child.
    Fork {
        /// Parent process id.
        ppid: u32,
    },
    /// See [`ExitRecord`].
    Exit {
        /// Exit status.
        code: i32,
    },
    /// See [`ConnectRecord`].
    Connect {
        /// Destination address, `None` for families other than IPv4 and IPv6.
        addr: Option<IpAddr>,
        /// Destination port.
        port: u16,
    },
    /// See [`OpenRecord`].
    OpenWrite {
        /// Absolute path of the opened file.
        path: &'a [u8],
    },
    /// See [`HelloRecord`].
    Hello {
        /// Wire format version.
        version: u32,
        /// Observer configuration.
        flags: HelloFlags,
    },
    /// See [`HeartbeatRecord`].
    Heartbeat(HeartbeatRecord),
    /// A kind this decoder does not know, skipped by its length.
    Unknown {
        /// The record bytes after the header.
        body: &'a [u8],
    },
}

/// The header and context at the start of task and exec records.
#[repr(C)]
#[derive(FromBytes, KnownLayout, Immutable)]
struct ContextPrefix {
    header: Header,
    ppid: u32,
    uid: u32,
    cgroup_id: u64,
    comm: [u8; COMM_LEN],
}

const _: () = {
    assert!(size_of::<ContextPrefix>() == offset_of!(TaskRecord, cgroup));
    assert!(size_of::<ContextPrefix>() == offset_of!(ExecRecord, path_len));
};

/// A process's context, from a task or exec record. The cgroup name is only
/// in task records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Context<'a> {
    /// Parent process id.
    pub ppid: u32,
    /// Real user id.
    pub uid: u32,
    /// cgroup v2 id.
    pub cgroup_id: u64,
    /// Process name.
    pub comm: &'a [u8],
}

/// The bytes before the first NUL (all of them if there is none).
#[must_use]
pub fn until_nul(bytes: &[u8]) -> &[u8] {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    bytes.get(..end).unwrap_or(bytes)
}

fn trim_trailing_nuls(bytes: &[u8]) -> &[u8] {
    let end = bytes
        .iter()
        .rposition(|&b| b != 0)
        .map_or(0, |i| i.saturating_add(1));
    bytes.get(..end).unwrap_or(bytes)
}

/// Length of the record at the start of `buf`, read from its header without
/// decoding it. `None` when `buf` is too short to hold the length field or the
/// length is out of range (shorter than a header or longer than [`MAX_RECORD_LEN`]).
#[must_use]
pub fn peek_len(buf: &[u8]) -> Option<usize> {
    let field = buf.get(offset_of!(Header, len)..)?.first_chunk()?;
    let len = usize::from(u16::from_ne_bytes(*field));
    (size_of::<Header>()..=MAX_RECORD_LEN)
        .contains(&len)
        .then_some(len)
}

/// Decodes the first record in `buf`.
///
/// Returns `Ok(None)` when `buf` does not yet hold a complete record, and the
/// record with the number of bytes it occupies otherwise.
///
/// # Errors
///
/// A [`DecodeError`] when the stream is corrupt. The caller should drop it.
pub fn decode(buf: &[u8]) -> Result<Option<(Record<'_>, usize)>, DecodeError> {
    let Ok((header, _)) = Header::read_from_prefix(buf) else {
        return Ok(None);
    };
    let len = usize::from(header.len);
    if !(size_of::<Header>()..=MAX_RECORD_LEN).contains(&len) {
        return Err(DecodeError::BadLength { len: header.len });
    }
    let Some(rec) = buf.get(..len) else {
        return Ok(None);
    };
    let body = match Kind::from_code(header.kind) {
        None => Body::Unknown {
            body: rec.get(size_of::<Header>()..).unwrap_or_default(),
        },
        Some(kind) => decode_body(kind, header, rec)?,
    };
    Ok(Some((Record { header, body }, len)))
}

fn decode_body(kind: Kind, header: Header, rec: &[u8]) -> Result<Body<'_>, DecodeError> {
    let truncated = DecodeError::Truncated {
        kind,
        len: header.len,
    };
    let bad_field = DecodeError::BadField {
        kind,
        len: header.len,
    };
    // Variable-length records are cut after their last used byte, so their tail
    // field runs from its offset to the end of the record.
    let tail = |offset: usize| rec.get(offset..).ok_or(truncated);
    let field = |offset: usize, len: usize| {
        offset
            .checked_add(len)
            .and_then(|end| rec.get(offset..end))
            .ok_or(truncated)
    };
    Ok(match kind {
        Kind::Exec => {
            let context = context(rec).ok_or(truncated)?;
            let lens = field(offset_of!(ExecRecord, path_len), 4)?;
            let (path_len, args_len) = match lens {
                [a, b, c, d] => (
                    usize::from(u16::from_ne_bytes([*a, *b])),
                    usize::from(u16::from_ne_bytes([*c, *d])),
                ),
                _ => return Err(truncated),
            };
            if path_len > PATH_LEN || args_len > ARGS_LEN {
                return Err(bad_field);
            }
            let data = offset_of!(ExecRecord, data);
            let args_at = data.checked_add(path_len).ok_or(truncated)?;
            Body::Exec {
                context,
                path: until_nul(field(data, path_len)?),
                args: trim_trailing_nuls(field(args_at, args_len)?),
            }
        }
        Kind::Task => {
            let context = context(rec).ok_or(truncated)?;
            let cgroup = tail(offset_of!(TaskRecord, cgroup))?;
            if cgroup.len() > CGROUP_LEN {
                return Err(bad_field);
            }
            Body::Task {
                context,
                cgroup: until_nul(cgroup),
            }
        }
        Kind::Fork => {
            let (f, _) = ForkRecord::read_from_prefix(rec).map_err(|_| truncated)?;
            Body::Fork { ppid: f.ppid }
        }
        Kind::Exit => {
            let (exit, _) = ExitRecord::read_from_prefix(rec).map_err(|_| truncated)?;
            Body::Exit {
                code: exit.exit_code,
            }
        }
        Kind::Connect => {
            let (c, _) = ConnectRecord::read_from_prefix(rec).map_err(|_| truncated)?;
            Body::Connect {
                addr: ip_addr(c.family, c.daddr),
                port: c.dport,
            }
        }
        Kind::OpenWrite => {
            let path_len = field(offset_of!(OpenRecord, path_len), 4)?
                .first_chunk()
                .map(|len| u32::from_ne_bytes(*len))
                .ok_or(truncated)?;
            let path = tail(offset_of!(OpenRecord, path))?;
            // The record ends right after the path, so the two lengths agree.
            if path.len() > PATH_LEN || usize::try_from(path_len) != Ok(path.len()) {
                return Err(bad_field);
            }
            Body::OpenWrite {
                path: until_nul(path),
            }
        }
        Kind::Hello => {
            let (h, _) = HelloRecord::read_from_prefix(rec).map_err(|_| truncated)?;
            Body::Hello {
                version: h.version,
                flags: h.flags,
            }
        }
        Kind::Heartbeat => {
            let (hb, _) = HeartbeatRecord::read_from_prefix(rec).map_err(|_| truncated)?;
            Body::Heartbeat(hb)
        }
    })
}

/// The context at the start of a task or exec record, `None` if it is cut short.
fn context(rec: &[u8]) -> Option<Context<'_>> {
    let (prefix, _) = ContextPrefix::read_from_prefix(rec).ok()?;
    let comm = rec.get(offset_of!(ContextPrefix, comm)..size_of::<ContextPrefix>())?;
    Some(Context {
        ppid: prefix.ppid,
        uid: prefix.uid,
        cgroup_id: prefix.cgroup_id,
        comm: until_nul(comm),
    })
}

fn ip_addr(family: u16, daddr: [u8; 16]) -> Option<IpAddr> {
    match family {
        AF_INET => {
            let [a, b, c, d, ..] = daddr;
            Some(IpAddr::V4(Ipv4Addr::new(a, b, c, d)))
        }
        AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(daddr))),
        _ => None,
    }
}

/// Iterator over the complete records in a buffer.
///
/// Stops at the first incomplete record (see [`Records::consumed`] to keep the
/// rest for later) or after yielding the first error.
///
/// # Examples
///
/// ```
/// use creche_wire::{Body, HEARTBEAT_LEN, Header, HeartbeatRecord, Kind, Records};
/// use zerocopy::IntoBytes as _;
///
/// let heartbeat = HeartbeatRecord {
///     header: Header::for_observer(Kind::Heartbeat, HEARTBEAT_LEN, 1, 0),
///     cpu_ms: 12,
///     ..HeartbeatRecord::default()
/// };
/// // A whole record, then the first 10 bytes of the next one.
/// let mut stream = heartbeat.as_bytes().to_vec();
/// stream.extend_from_slice(&heartbeat.as_bytes()[..10]);
///
/// let mut records = Records::new(&stream);
/// let first = records.next().unwrap().unwrap();
/// assert_eq!(first.body, Body::Heartbeat(heartbeat));
/// assert!(records.next().is_none());
/// // The incomplete record stays for the next read.
/// assert_eq!(records.consumed(), usize::from(HEARTBEAT_LEN));
/// ```
#[derive(Clone, Debug)]
pub struct Records<'a> {
    buf: &'a [u8],
    consumed: usize,
    failed: bool,
}

impl<'a> Records<'a> {
    /// Iterates over the records at the start of `buf`.
    #[must_use]
    pub const fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            consumed: 0,
            failed: false,
        }
    }

    /// Bytes taken by the records yielded so far.
    #[must_use]
    pub const fn consumed(&self) -> usize {
        self.consumed
    }
}

impl<'a> Iterator for Records<'a> {
    type Item = Result<Record<'a>, DecodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        let rest = self.buf.get(self.consumed..)?;
        match decode(rest) {
            Ok(None) => None,
            Ok(Some((record, len))) => {
                self.consumed = self.consumed.saturating_add(len);
                Some(Ok(record))
            }
            Err(e) => {
                self.failed = true;
                Some(Err(e))
            }
        }
    }
}

#[cfg(feature = "sample")]
#[expect(
    clippy::disallowed_types,
    reason = "benchmark fixtures build owned streams, outside the decoder"
)]
pub mod sample;

#[cfg(test)]
#[expect(
    clippy::arithmetic_side_effects,
    clippy::disallowed_types,
    clippy::disallowed_macros,
    reason = "test fixtures compute offsets and build owned records"
)]
mod tests;
