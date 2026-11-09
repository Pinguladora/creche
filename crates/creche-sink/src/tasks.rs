//! The context of each process in one stream, kept from its task records.

use std::collections::HashMap;
use std::sync::Arc;

use creche_wire::Context;

use crate::json::Cgroup;
use crate::k8s::Container;

/// Most processes tracked per stream. Exits remove them, so this is only reached
/// when exit records were lost. Then an arbitrary entry makes room.
const MAX_TASKS: usize = 1 << 16;

/// A process's context, as last reported by the guest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskInfo {
    /// Parent process id.
    pub ppid: u32,
    /// Real user id.
    pub uid: u32,
    /// cgroup v2 id.
    pub cgroup_id: u64,
    /// Process name. Shared with forked children until they change it.
    pub comm: Arc<str>,
    /// cgroup v2 leaf name, shared the same way.
    pub cgroup: Arc<str>,
    /// The pod's container the guest claims for that cgroup, when the host
    /// confirms it belongs to this sandbox.
    pub container: Option<Arc<Container>>,
    /// The cgroup's path and labels, when the observer described it.
    pub cgroup_info: Option<Arc<Cgroup>>,
}

impl TaskInfo {
    /// The context from a task record. Guest data is not guaranteed UTF-8.
    /// Invalid sequences become U+FFFD, once here rather than on every record.
    #[must_use]
    pub fn new(context: &Context<'_>, cgroup: &[u8]) -> Self {
        Self {
            ppid: context.ppid,
            uid: context.uid,
            cgroup_id: context.cgroup_id,
            comm: lossy(context.comm),
            cgroup: lossy(cgroup),
            container: None,
            cgroup_info: None,
        }
    }
}

fn lossy(bytes: &[u8]) -> Arc<str> {
    String::from_utf8_lossy(bytes).into()
}

/// Most cgroups kept per stream. A guest has a few dozen. The bound only keeps
/// one stream from growing the sink without end.
const MAX_CGROUPS: usize = 4096;

/// The cgroups a stream's observer described, by id.
#[derive(Debug, Default)]
pub struct Cgroups {
    by_id: HashMap<u64, Arc<Cgroup>>,
}

impl Cgroups {
    /// The cgroup `id`, if the observer described it.
    #[must_use]
    pub fn get(&self, id: u64) -> Option<Arc<Cgroup>> {
        self.by_id.get(&id).cloned()
    }

    /// Records the cgroup `id`, replacing any earlier description.
    pub fn set(&mut self, id: u64, cgroup: Cgroup) {
        if self.by_id.len() >= MAX_CGROUPS
            && !self.by_id.contains_key(&id)
            && let Some(&evict) = self.by_id.keys().next()
        {
            self.by_id.remove(&evict);
        }
        self.by_id.insert(id, Arc::new(cgroup));
    }
}

/// Process contexts by pid.
#[derive(Debug, Default)]
pub struct Tasks {
    by_pid: HashMap<u32, TaskInfo>,
}

impl Tasks {
    /// The context of `pid`, if the stream has reported it.
    #[must_use]
    pub fn get(&self, pid: u32) -> Option<&TaskInfo> {
        self.by_pid.get(&pid)
    }

    /// Records the context of `pid`, replacing any earlier one.
    pub fn set(&mut self, pid: u32, info: TaskInfo) {
        if self.by_pid.len() >= MAX_TASKS
            && !self.by_pid.contains_key(&pid)
            && let Some(&evict) = self.by_pid.keys().next()
        {
            self.by_pid.remove(&evict);
        }
        self.by_pid.insert(pid, info);
    }

    /// A new process starts with its parent's context.
    pub fn fork(&mut self, ppid: u32, child: u32) {
        if let Some(parent) = self.by_pid.get(&ppid) {
            let info = TaskInfo {
                ppid,
                ..parent.clone()
            };
            self.set(child, info);
        }
    }

    /// An exec record's context replaces all but the cgroup name and what
    /// follows from it, which only task records carry. The guest sends one
    /// first when the cgroup changed.
    pub fn exec(&mut self, pid: u32, context: &Context<'_>) {
        let (cgroup, container, cgroup_info) = self.by_pid.get(&pid).map_or_else(
            || (Arc::from(""), None, None),
            |known| {
                (
                    Arc::clone(&known.cgroup),
                    known.container.clone(),
                    known.cgroup_info.clone(),
                )
            },
        );
        let comm = match self.by_pid.get(&pid) {
            Some(known) if known.comm.as_bytes() == context.comm => Arc::clone(&known.comm),
            _ => lossy(context.comm),
        };
        self.set(
            pid,
            TaskInfo {
                ppid: context.ppid,
                uid: context.uid,
                cgroup_id: context.cgroup_id,
                comm,
                cgroup,
                container,
                cgroup_info,
            },
        );
    }

    /// Forgets `pid` once its process has exited.
    pub fn exit(&mut self, pid: u32) {
        self.by_pid.remove(&pid);
    }

    /// Processes tracked.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.by_pid.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(ppid: u32, comm: &str) -> TaskInfo {
        TaskInfo {
            ppid,
            uid: 1000,
            cgroup_id: 9,
            comm: comm.into(),
            cgroup: "cri-containerd-x.scope".into(),
            container: None,
            cgroup_info: None,
        }
    }

    #[test]
    fn task_records_are_kept_with_lossy_names() {
        let c = Context {
            ppid: 1,
            uid: 0,
            cgroup_id: 3,
            comm: b"sh\xff",
        };
        let i = TaskInfo::new(&c, b"");
        assert_eq!((&*i.comm, &*i.cgroup), ("sh\u{fffd}", ""));
        assert_eq!((i.ppid, i.uid, i.cgroup_id), (1, 0, 3));
    }

    #[test]
    fn children_inherit_and_exits_forget() {
        let mut tasks = Tasks::default();
        tasks.set(10, info(1, "sh"));
        tasks.fork(10, 11);
        assert_eq!(tasks.get(11), Some(&info(10, "sh")));
        // The parent keeps its own parent.
        assert_eq!(tasks.get(10).map(|i| i.ppid), Some(1));
        tasks.exit(11);
        assert_eq!(tasks.get(11), None);
        assert_eq!(tasks.len(), 1);
        // A fork from an unknown parent leaves the child unknown.
        tasks.fork(99, 100);
        assert_eq!(tasks.get(100), None);
    }

    #[test]
    fn exec_replaces_the_context_but_keeps_the_cgroup_name() {
        let mut tasks = Tasks::default();
        tasks.set(10, info(1, "sh"));
        let ls = Context {
            ppid: 2,
            uid: 5,
            cgroup_id: 9,
            comm: b"ls",
        };
        tasks.exec(10, &ls);
        let got = tasks.get(10).unwrap();
        assert_eq!(
            (got.ppid, got.uid, got.cgroup_id, &*got.comm, &*got.cgroup),
            (2, 5, 9, "ls", "cri-containerd-x.scope")
        );
        // The same name again keeps the shared string.
        let before = Arc::clone(&got.comm);
        tasks.exec(10, &ls);
        assert!(Arc::ptr_eq(&before, &tasks.get(10).unwrap().comm));
        // An unknown process gets an empty cgroup name.
        tasks.exec(20, &ls);
        assert_eq!(&*tasks.get(20).unwrap().cgroup, "");
    }

    #[test]
    fn the_map_stays_bounded() {
        let mut tasks = Tasks::default();
        for pid in 0..u32::try_from(MAX_TASKS).unwrap() {
            tasks.set(pid, info(1, "x"));
        }
        assert_eq!(tasks.len(), MAX_TASKS);
        // Replacing a known pid needs no room.
        tasks.set(0, info(2, "y"));
        assert_eq!(tasks.len(), MAX_TASKS);
        assert_eq!(tasks.get(0), Some(&info(2, "y")));
        // A new pid evicts one.
        tasks.set(u32::MAX, info(1, "z"));
        assert_eq!(tasks.len(), MAX_TASKS);
        assert!(tasks.get(u32::MAX).is_some());
    }

    #[test]
    fn the_cgroup_map_stays_bounded() {
        let cgroup = |path: &str| Cgroup::new(path.as_bytes(), 0, creche_wire::Labels::default());
        let mut cgroups = Cgroups::default();
        for id in 0..u64::try_from(MAX_CGROUPS).unwrap() {
            cgroups.set(id, cgroup("/x"));
        }
        assert_eq!(cgroups.by_id.len(), MAX_CGROUPS);
        // Replacing a known id needs no room.
        cgroups.set(0, cgroup("/y"));
        assert_eq!(cgroups.by_id.len(), MAX_CGROUPS);
        assert_eq!(&*cgroups.get(0).unwrap().path, "/y");
        // A new id evicts one.
        cgroups.set(u64::MAX, cgroup("/z"));
        assert_eq!(cgroups.by_id.len(), MAX_CGROUPS);
        assert!(cgroups.get(u64::MAX).is_some());
    }
}
