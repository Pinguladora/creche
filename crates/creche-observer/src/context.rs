//! What the host needs again after a reconnect. The host knows a stream's
//! processes and cgroups only from task and cgroup records sent on that
//! connection. Records still queued when a connection broke go out on the next
//! one, but the task and cgroup records that explain them may have gone out on
//! the broken one. So before the queue is flushed on a new connection, a cgroup
//! description for each cgroup they or those task records name, and a task
//! record for each of their processes still running, go in front of them. The processes include the
//! parents of queued forks, whose context the host gives their children. A
//! process that started after the first queued record naming its pid is not
//! the one the record is about, the pid having been reused, and gets none.

use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use creche_wire::{Context, ForkRecord, Header, Kind, MAX_RECORD_LEN, encode_task, peek_cgroup_id};
use nix::unistd::{SysconfVar, sysconf};
use zerocopy::FromBytes as _;

use crate::cgroups::Cgroups;
use crate::queue::RecordQueue;

/// Most bytes of task records, and most of cgroup descriptions, put in front
/// of the queue. Processes past it go without, and cgroups past it are
/// described later.
const BUDGET: usize = 256 * 1024;

/// Puts the context of the queued records in front of them: see the module.
/// `pid` and `ts_ns` stamp the records written, the observer's own pid and the
/// guest's boot-time clock. `proc` and `cgroup_root` are where `/proc` and the
/// cgroup v2 hierarchy are mounted.
pub fn restore(
    queue: &mut RecordQueue,
    cgroups: &mut Cgroups,
    pid: u32,
    ts_ns: u64,
    proc: &Path,
    cgroup_root: &Path,
) {
    let mut ids = Vec::new();
    let mut pids = Vec::new();
    let (mut named_cgroups, mut named_processes) = (HashSet::new(), HashSet::new());
    for record in queue.backlog() {
        if let Some(id) = peek_cgroup_id(record)
            && named_cgroups.insert(id)
        {
            ids.push(id);
        }
        if let Ok((header, _)) = Header::read_from_prefix(record)
            && is_process(header.kind)
        {
            // A fork's child takes its context from the parent, so the parent
            // goes first.
            if header.kind == Kind::Fork.code()
                && let Ok((fork, _)) = ForkRecord::read_from_prefix(record)
                && named_processes.insert(fork.ppid)
            {
                pids.push((fork.ppid, header.ts_ns));
            }
            if named_processes.insert(header.pid) {
                pids.push((header.pid, header.ts_ns));
            }
        }
    }
    // The task records first, for the cgroups they name.
    let mut tasks = Vec::new();
    let mut record = [0; MAX_RECORD_LEN];
    for (of, named_at) in pids {
        if let Some(len) = task_record(proc, cgroup_root, of, named_at, ts_ns, &mut record)
            && let Some(bytes) = record.get(..len)
            && tasks.len().saturating_add(len) <= BUDGET
        {
            if let Some(id) = peek_cgroup_id(bytes)
                && named_cgroups.insert(id)
            {
                ids.push(id);
            }
            tasks.extend_from_slice(bytes);
        }
    }
    // A cgroup new since the last walk would wait for the next, and the
    // records it explains would go out first.
    cgroups.map(&ids, ts_ns);
    let mut context = Vec::new();
    for id in ids {
        let Some(description) = cgroups.describe(id, pid, ts_ns) else {
            continue;
        };
        if context.len().saturating_add(description.len()) <= BUDGET {
            context.extend_from_slice(description);
        } else {
            cgroups.retract(id);
        }
    }
    context.extend_from_slice(&tasks);
    queue.prepend(&context);
}

/// Whether records of `kind` are about the process in their header.
fn is_process(kind: u16) -> bool {
    [
        Kind::Exec,
        Kind::Fork,
        Kind::Exit,
        Kind::Connect,
        Kind::OpenWrite,
        Kind::Task,
    ]
    .iter()
    .any(|k| k.code() == kind)
}

/// A task record for process `pid`, read from `proc`, written into `out`, with
/// its length. `None` once the process is gone, or when the process running
/// under `pid` started after `named_at` (boot-time clock), so is not the one a
/// record from then is about.
pub fn task_record(
    proc: &Path,
    cgroup_root: &Path,
    pid: u32,
    named_at: u64,
    ts_ns: u64,
    out: &mut [u8],
) -> Option<usize> {
    let dir = proc.join(pid.to_string());
    let stat = fs::read_to_string(dir.join("stat")).ok()?;
    // The fields after the command name, which may hold spaces and parentheses:
    // state, parent, and the start time is the twentieth.
    let mut fields = stat.rsplit_once(')')?.1.split_whitespace();
    let parent = fields.nth(1)?.parse().ok()?;
    let started: u64 = fields.nth(17)?.parse().ok()?;
    // In clock ticks since boot, rounded down.
    if started.saturating_mul(tick_ns()) > named_at {
        return None;
    }
    let status = fs::read_to_string(dir.join("status")).ok()?;
    let uid = status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    let comm = fs::read(dir.join("comm")).ok()?;
    let comm = comm.strip_suffix(b"\n").unwrap_or(&comm);
    // cgroup v2 alone: one line, `0::<path>`.
    let membership = fs::read_to_string(dir.join("cgroup")).ok()?;
    let path = membership
        .lines()
        .find_map(|l| l.strip_prefix("0::"))?
        .trim_start_matches('/');
    let cgroup_id = fs::metadata(cgroup_root.join(path)).ok()?.ino();
    let leaf = path.rsplit('/').next().unwrap_or_default();
    let context = Context {
        ppid: parent,
        uid,
        cgroup_id,
        comm,
    };
    let header = Header::for_observer(Kind::Task, 0, pid, ts_ns);
    encode_task(header, &context, leaf.as_bytes(), out)
}

/// Length of the clock tick `/proc` counts times in, in nanoseconds.
fn tick_ns() -> u64 {
    sysconf(SysconfVar::CLK_TCK)
        .ok()
        .flatten()
        .and_then(|hz| u64::try_from(hz).ok())
        .and_then(|hz| 1_000_000_000_u64.checked_div(hz))
        .unwrap_or(10_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;
    use creche_wire::{Body, HEARTBEAT_LEN, HeartbeatRecord, decode};
    use std::path::PathBuf;

    /// A fake `/proc` with process `pid`, started at boot, and a cgroup root
    /// holding its cgroup.
    fn system(pid: u32) -> (tempfile::TempDir, PathBuf, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let proc = tmp.path().join("proc");
        let root = tmp.path().join("cgroup");
        fs::create_dir_all(root.join("kubepods/agent")).unwrap();
        process(&proc, pid);
        (tmp, proc, root)
    }

    /// Adds process `pid`, started at boot, to `proc`, in the cgroup of
    /// [`system`].
    fn process(proc: &Path, pid: u32) {
        let dir = proc.join(pid.to_string());
        fs::create_dir_all(&dir).unwrap();
        start(proc, pid, 0);
        fs::write(
            dir.join("status"),
            "Name:\tsh\nUid:\t1001\t1001\t1001\t1001\n",
        )
        .unwrap();
        fs::write(dir.join("comm"), "sh\n").unwrap();
        fs::write(dir.join("cgroup"), "0::/kubepods/agent\n").unwrap();
    }

    /// Makes process `pid` in `proc` one started `ticks` clock ticks after boot.
    fn start(proc: &Path, pid: u32, ticks: u64) {
        let stat = format!("{pid} (a b) c) S 7 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 {ticks} 0");
        fs::write(proc.join(pid.to_string()).join("stat"), stat).unwrap();
    }

    #[test]
    fn task_records_are_read_from_proc() {
        let (_tmp, proc, root) = system(42);
        let mut out = [0; MAX_RECORD_LEN];
        let len = task_record(&proc, &root, 42, 0, 5, &mut out).unwrap();
        let (rec, _) = decode(&out[..len]).unwrap().unwrap();
        let Body::Task { context, cgroup } = rec.body else {
            panic!("not a task record: {rec:?}");
        };
        let id = fs::metadata(root.join("kubepods/agent")).unwrap().ino();
        assert_eq!(rec.header.pid, 42);
        assert_eq!(
            (
                context.ppid,
                context.uid,
                context.cgroup_id,
                context.comm,
                cgroup
            ),
            (7, 1001, id, &b"sh"[..], &b"agent"[..])
        );
        // A process that is gone has none.
        assert_eq!(task_record(&proc, &root, 43, 0, 5, &mut out), None);
        // Nor has one that started after the record naming its pid: the pid
        // was reused.
        let tick = tick_ns();
        start(&proc, 42, 3);
        assert_eq!(
            task_record(&proc, &root, 42, 3 * tick - 1, 5, &mut out),
            None
        );
        assert!(task_record(&proc, &root, 42, 3 * tick, 5, &mut out).is_some());
    }

    /// A fork record of child `child` and parent `parent`.
    fn fork(child: u32, parent: u32) -> Vec<u8> {
        let header = Header::for_observer(Kind::Fork, 24, child, 1);
        [
            zerocopy::IntoBytes::as_bytes(&header),
            &parent.to_ne_bytes(),
            &[0; 4],
        ]
        .concat()
    }

    #[test]
    fn queued_records_get_their_context_in_front() {
        let (_tmp, proc, root) = system(42);
        let id = fs::metadata(root.join("kubepods/agent")).unwrap().ino();
        // What is left queued: a task record of process 42 in that cgroup, a
        // fork of process 42 from process 44, and a fork of process 43 from
        // process 42. Process 43 is gone, and so is process 44.
        let mut task = [0; MAX_RECORD_LEN];
        let context = Context {
            ppid: 7,
            uid: 1001,
            cgroup_id: id,
            comm: b"sh",
        };
        let header = Header::for_observer(Kind::Task, 0, 42, 1);
        let len = encode_task(header, &context, b"agent", &mut task).unwrap();
        let mut queue = RecordQueue::new(1 << 20);
        for record in [&task[..len], &fork(42, 44), &fork(43, 42)] {
            assert!(queue.push(record));
        }
        let mut cgroups = Cgroups::new(&root);
        restore(&mut queue, &mut cgroups, 1, 9, &proc, &root);
        let sent = waiting(&queue);
        // In front: the cgroup's description and one task record of process
        // 42, named both as a child and as a parent. Nothing for the processes
        // that are gone.
        assert_eq!(
            sent,
            [
                (Kind::Cgroup.code(), 1),
                (Kind::Task.code(), 42),
                (Kind::Task.code(), 42),
                (Kind::Fork.code(), 42),
                (Kind::Fork.code(), 43),
            ]
        );
    }

    #[test]
    fn parents_of_queued_forks_get_their_context_in_front() {
        let (_tmp, proc, root) = system(42);
        // Only forks are left queued: of process 43 from process 42, still
        // running, and of process 44 from process 45, which is gone.
        let mut queue = RecordQueue::new(1 << 20);
        for record in [fork(43, 42), fork(44, 45)] {
            assert!(queue.push(&record));
        }
        let mut cgroups = Cgroups::new(&root);
        restore(&mut queue, &mut cgroups, 1, 9, &proc, &root);
        let sent = waiting(&queue);
        // The task record names the cgroup of process 42, described first.
        assert_eq!(
            sent,
            [
                (Kind::Cgroup.code(), 1),
                (Kind::Task.code(), 42),
                (Kind::Fork.code(), 43),
                (Kind::Fork.code(), 44),
            ]
        );
    }

    /// The pids and kinds of the records waiting in `queue`.
    fn waiting(queue: &RecordQueue) -> Vec<(u16, u32)> {
        queue
            .backlog()
            .map(|r| {
                let (h, _) = Header::read_from_prefix(r).unwrap();
                (h.kind, h.pid)
            })
            .collect()
    }

    #[test]
    fn records_about_the_observer_name_no_process() {
        let (_tmp, proc, root) = system(42);
        // A heartbeat of the observer, process 42.
        let header = Header::for_observer(Kind::Heartbeat, HEARTBEAT_LEN, 42, 1);
        let heartbeat = [
            zerocopy::IntoBytes::as_bytes(&header),
            &[0; size_of::<HeartbeatRecord>() - size_of::<Header>()],
        ]
        .concat();
        let mut queue = RecordQueue::new(1 << 20);
        assert!(queue.push(&heartbeat));
        restore(&mut queue, &mut Cgroups::new(&root), 1, 9, &proc, &root);
        assert_eq!(waiting(&queue), [(Kind::Heartbeat.code(), 42)]);
    }

    #[test]
    fn many_processes_fit_in_the_budget() {
        let (_tmp, proc, root) = system(1000);
        let pids: Vec<u32> = (1000..1100).collect();
        let mut queue = RecordQueue::new(1 << 20);
        for &pid in &pids {
            process(&proc, pid);
            assert!(queue.push(&fork(pid, 1)));
        }
        restore(&mut queue, &mut Cgroups::new(&root), 1, 9, &proc, &root);
        let tasks = waiting(&queue)
            .iter()
            .filter(|(kind, _)| *kind == Kind::Task.code())
            .count();
        assert_eq!(tasks, pids.len());
    }

    #[test]
    fn times_in_proc_count_hundredths_of_a_second() {
        // USER_HZ, 100 on every architecture Linux runs the observer on.
        assert_eq!(tick_ns(), 10_000_000);
    }

    /// A task record of process `pid`, gone, in cgroup `id`.
    fn task_in(pid: u32, id: u64) -> Vec<u8> {
        let mut out = [0; MAX_RECORD_LEN];
        let context = Context {
            ppid: 1,
            uid: 0,
            cgroup_id: id,
            comm: b"sh",
        };
        let header = Header::for_observer(Kind::Task, 0, pid, 2);
        let len = encode_task(header, &context, b"x", &mut out).unwrap();
        out[..len].to_vec()
    }

    #[test]
    fn a_cgroup_new_since_the_last_walk_is_described_at_once() {
        let (_tmp, proc, root) = system(42);
        let mut cgroups = Cgroups::new(&root);
        // A walk at 1, then a cgroup made and named within the gap.
        assert!(cgroups.describe(ino(&root), 1, 1).is_some());
        let new = root.join("kubepods/new");
        fs::create_dir(&new).unwrap();
        let mut queue = RecordQueue::new(1 << 20);
        assert!(queue.push(&task_in(50, ino(&new))));
        restore(&mut queue, &mut cgroups, 1, 2, &proc, &root);
        assert_eq!(
            waiting(&queue),
            [(Kind::Cgroup.code(), 1), (Kind::Task.code(), 50)]
        );
    }

    #[test]
    fn cgroups_past_the_budget_are_described_later() {
        let (_tmp, proc, root) = system(42);
        // Cgroups with long paths, more of them than the budget describes.
        let mut queue = RecordQueue::new(1 << 20);
        let mut ids = Vec::new();
        for i in 0..700 {
            let dir = root
                .join(format!("{i}{}", "a".repeat(200)))
                .join("b".repeat(200));
            fs::create_dir_all(&dir).unwrap();
            ids.push(ino(&dir));
            assert!(queue.push(&task_in(100_000 + i, ino(&dir))));
        }
        let mut cgroups = Cgroups::new(&root);
        restore(&mut queue, &mut cgroups, 1, 2, &proc, &root);
        let described = waiting(&queue)
            .iter()
            .filter(|(kind, _)| *kind == Kind::Cgroup.code())
            .count();
        assert!(described > 0 && described < ids.len());
        // The others wait to be described.
        let mut later = cgroups.take_ready(u64::MAX);
        later.sort_unstable();
        let mut rest: Vec<u64> = ids[described..].to_vec();
        rest.sort_unstable();
        assert_eq!(later, rest);
    }

    fn ino(path: &Path) -> u64 {
        fs::metadata(path).unwrap().ino()
    }
}
