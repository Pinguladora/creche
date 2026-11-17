//! Describes guest cgroups to the host: each one's path, and the labels its
//! owner set as `user.creche.agent.<key>` extended attributes.
//!
//! The kernel reports a process's cgroup by id and leaf name only. The first
//! time a task or exec record names a cgroup on a connection, the observer
//! sends a cgroup record ahead of it. Agent runtimes label the cgroup they
//! delegate to each agent before moving the agent into it, and a cgroup
//! without labels takes those of its nearest labelled ancestor, so the agent's
//! own child cgroups carry its labels too.
//!
//! On cgroup v2 a cgroup's id is the inode number of its directory, so one
//! walk of the hierarchy maps every id to its path. The walk runs only when a
//! record names an id it has not seen, and at most a tenth of the time. A cgroup
//! first named in between is described as soon as the next walk may run, even
//! if no record names it again, and lines from then on carry its path and
//! labels. The walk, the paths and the ids described or waiting are bounded.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::time::Instant;

use creche_wire::{
    CGROUP_PATH_LEN, LABEL_VALUE_LEN, MAX_LABELS, MAX_RECORD_LEN, encode_cgroup, label_key_ok,
    label_value_ok,
};

/// Where cgroup v2 is mounted in the guest.
pub const CGROUP_ROOT: &str = "/sys/fs/cgroup";
/// The extended attribute names labels are read from, before their key.
pub const LABEL_PREFIX: &str = "user.creche.agent.";
/// Deepest the walk goes below the root.
const MAX_DEPTH: usize = 32;
/// Most cgroups the walk maps, and most ids remembered as described. A guest
/// has a few dozen.
const MAX_CGROUPS: usize = 4096;
/// After a walk, the next waits at least this many times as long as it took.
const WALK_GAP_FACTOR: u64 = 10;
/// And at least this long, in nanoseconds.
const MIN_WALK_GAP_NS: u64 = 1_000_000;

/// What the observer knows of the guest's cgroups and has told the host.
#[derive(Debug)]
pub struct Cgroups {
    root: PathBuf,
    /// Paths by cgroup id, from the last walk.
    paths: HashMap<u64, PathBuf>,
    /// Ids described on this connection, or found nowhere.
    described: HashSet<u64>,
    /// When the next walk may run, on the clock records are stamped with.
    next_walk_ns: u64,
    /// Ids to describe once a walk may run again: named too soon after the
    /// last one, or described in a record that did not reach the queue.
    deferred: HashSet<u64>,
    /// How many of them the last walk did not map.
    unmapped: usize,
    /// Room for the longest record, which the longest cgroup record fits.
    record: Box<[u8; MAX_RECORD_LEN]>,
}

impl Cgroups {
    /// Cgroups under `root`, the cgroup v2 mount.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            paths: HashMap::new(),
            described: HashSet::new(),
            next_walk_ns: 0,
            deferred: HashSet::new(),
            unmapped: 0,
            record: Box::new([0; MAX_RECORD_LEN]),
        }
    }

    /// A cgroup record for cgroup `id`, to send before the record that named
    /// it at `ts_ns`, when it was not described on this connection yet. `None`
    /// once it has been, when it no longer exists, or when it is new and too
    /// soon after the last walk to look for it.
    pub fn describe(&mut self, id: u64, pid: u32, ts_ns: u64) -> Option<&[u8]> {
        if self.described.contains(&id) {
            return None;
        }
        if !self.paths.contains_key(&id) {
            // Too soon after the last walk, it waits for the next, unless as
            // many wait unmapped as a walk can map: then it walks now, rather
            // than forget one. That is a walk per MAX_CGROUPS new cgroups at
            // most.
            if ts_ns < self.next_walk_ns && self.unmapped < MAX_CGROUPS {
                self.defer(id);
                return None;
            }
            self.walk(ts_ns);
        }
        // Forgetting them all costs only descriptions sent again.
        if self.described.len() >= MAX_CGROUPS {
            self.described.clear();
        }
        self.described.insert(id);
        let dir = self.paths.get(&id)?;
        let path = relative(&self.root, dir)?;
        let (owner, labels) = labels(&self.root, dir);
        let labels: Vec<(&[u8], &[u8])> = labels
            .iter()
            .map(|(k, v)| (k.as_bytes(), v.as_slice()))
            .collect();
        let len = encode_cgroup(
            pid,
            ts_ns,
            id,
            owner,
            path.as_bytes(),
            &labels,
            &mut self.record[..],
        )?;
        self.record.get(..len)
    }

    /// Maps every cgroup now, at `ts_ns`, and waits before the next walk. The
    /// cgroups waiting that it does not find are gone, and stop waiting, so
    /// those waiting are at most as many as it maps, and the unmapped since.
    fn walk(&mut self, ts_ns: u64) {
        let started = Instant::now();
        self.paths = walk(&self.root);
        let paths = &self.paths;
        self.deferred.retain(|id| paths.contains_key(id));
        self.unmapped = 0;
        let took = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        let gap = took.saturating_mul(WALK_GAP_FACTOR).max(MIN_WALK_GAP_NS);
        self.next_walk_ns = ts_ns.saturating_add(gap);
    }

    /// Maps every cgroup now, at `ts_ns`, if one of `ids` is not mapped yet,
    /// so that each can be described at once. For a new connection, whose
    /// queued records need them before they go out.
    pub fn map(&mut self, ids: &[u64], ts_ns: u64) {
        if ids.iter().any(|id| !self.paths.contains_key(id)) {
            self.walk(ts_ns);
        }
    }

    /// Forgets that cgroup `id` was described, when its description did not
    /// reach the queue, and describes it again soon (see [`Self::take_ready`]).
    pub fn retract(&mut self, id: u64) {
        self.described.remove(&id);
        self.defer(id);
    }

    /// Describes cgroup `id` once a walk may run (see [`Self::take_ready`]),
    /// if it is not described by then. At most [`MAX_CGROUPS`] wait unmapped,
    /// and as many mapped, waiting for room in the queue.
    pub fn defer(&mut self, id: u64) {
        if self.deferred.len() < 2 * MAX_CGROUPS
            && self.deferred.insert(id)
            && !self.paths.contains_key(&id)
        {
            self.unmapped = self.unmapped.saturating_add(1);
        }
    }

    /// Whether cgroups wait to be described.
    #[must_use]
    pub fn deferring(&self) -> bool {
        !self.deferred.is_empty()
    }

    /// The deferred cgroups that can be described at `ts_ns`, which stop
    /// waiting: those known since the last walk, and the others too once a
    /// walk may run. One pass, however many wait.
    pub fn take_ready(&mut self, ts_ns: u64) -> Vec<u64> {
        let walk = ts_ns >= self.next_walk_ns;
        let paths = &self.paths;
        let (ready, waiting): (Vec<u64>, Vec<u64>) = self
            .deferred
            .drain()
            .partition(|id| walk || paths.contains_key(id));
        if walk {
            self.unmapped = 0;
        }
        self.deferred.extend(waiting);
        ready
    }

    /// Forgets what the host was told, for a new connection or after records
    /// were lost.
    pub fn forget(&mut self) {
        self.described.clear();
    }
}

/// Every cgroup directory under `root`, by inode number, at most
/// [`MAX_CGROUPS`] of them. Directories are queued only while they could still
/// fit, so neither the map nor the queue grows past that.
fn walk(root: &Path) -> HashMap<u64, PathBuf> {
    let mut found = HashMap::new();
    let mut pending = vec![(root.to_path_buf(), 0_usize)];
    while let Some((dir, depth)) = pending.pop() {
        let Ok(meta) = fs::metadata(&dir) else {
            continue;
        };
        found.insert(meta.ino(), dir.clone());
        if depth >= MAX_DEPTH {
            continue;
        }
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if found.len().saturating_add(pending.len()) >= MAX_CGROUPS {
                break;
            }
            if entry.file_type().is_ok_and(|t| t.is_dir()) {
                pending.push((entry.path(), depth.saturating_add(1)));
            }
        }
    }
    found
}

/// `dir` from the cgroup root, starting with `/`, if it fits a record.
fn relative(root: &Path, dir: &Path) -> Option<String> {
    let rest = dir.strip_prefix(root).ok()?.to_str()?;
    let path = format!("/{rest}");
    (path.len() <= CGROUP_PATH_LEN).then_some(path)
}

/// The labels that apply to the cgroup at `dir`, its own or its nearest
/// labelled ancestor's, sorted by key, with the owner of the cgroup they were
/// read from, or of `dir` itself when there are none. Labels whose key or
/// value a record cannot carry are skipped.
fn labels(root: &Path, dir: &Path) -> (u32, Vec<(String, Vec<u8>)>) {
    let own = fs::metadata(dir).map_or(0, |m| m.uid());
    for cgroup in dir.ancestors().take_while(|d| d.starts_with(root)) {
        let found = read_labels(cgroup);
        if !found.is_empty() {
            return (fs::metadata(cgroup).map_or(own, |m| m.uid()), found);
        }
    }
    (own, Vec::new())
}

/// The labels set on one cgroup.
fn read_labels(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut names = [0_u8; 4096];
    let Ok(len) = rustix::fs::listxattr(dir, &mut names[..]) else {
        return Vec::new();
    };
    let mut labels: Vec<(String, Vec<u8>)> = names
        .get(..len)
        .unwrap_or_default()
        .split(|&b| b == 0)
        .filter_map(|name| std::str::from_utf8(name).ok())
        .filter_map(|name| {
            let key = name.strip_prefix(LABEL_PREFIX)?;
            if !label_key_ok(key.as_bytes()) {
                return None;
            }
            let mut value = [0_u8; LABEL_VALUE_LEN];
            let len = rustix::fs::getxattr(dir, name, &mut value[..]).ok()?;
            let value = value.get(..len)?;
            label_value_ok(value).then(|| (key.to_owned(), value.to_vec()))
        })
        .collect();
    labels.sort();
    labels.truncate(MAX_LABELS);
    labels
}

#[cfg(test)]
mod tests {
    use super::*;
    use creche_wire::{Body, decode};
    use rustix::fs::{XattrFlags, setxattr};

    /// A cgroup-like tree in a temporary directory: `<root>/pod/ctr/agent/tool`.
    fn tree() -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let tool = tmp.path().join("pod/ctr/agent/tool");
        fs::create_dir_all(&tool).unwrap();
        (tmp, tool)
    }

    fn label(dir: &Path, key: &str, value: &str) {
        setxattr(
            dir,
            format!("{LABEL_PREFIX}{key}"),
            value.as_bytes(),
            XattrFlags::empty(),
        )
        .unwrap();
    }

    fn ino(dir: &Path) -> u64 {
        fs::metadata(dir).unwrap().ino()
    }

    /// The path, owner and labels a cgroup record carries.
    fn decoded(record: &[u8]) -> (String, u32, Vec<(String, String)>) {
        let (rec, len) = decode(record).unwrap().unwrap();
        assert_eq!(len, record.len());
        let Body::Cgroup {
            path,
            owner_uid,
            labels,
            ..
        } = rec.body
        else {
            panic!("not a cgroup record: {rec:?}");
        };
        let labels = labels
            .iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();
        (String::from_utf8(path.to_vec()).unwrap(), owner_uid, labels)
    }

    #[test]
    fn a_cgroup_is_described_once_per_connection() {
        let (tmp, tool) = tree();
        let agent = tool.parent().unwrap();
        label(agent, "name", "planner");
        label(agent, "id", "a-1");
        let mut cgroups = Cgroups::new(tmp.path());
        let record = cgroups.describe(ino(agent), 7, 1).unwrap().to_vec();
        let uid = fs::metadata(agent).unwrap().uid();
        assert_eq!(
            decoded(&record),
            (
                "/pod/ctr/agent".to_owned(),
                uid,
                vec![
                    ("id".to_owned(), "a-1".to_owned()),
                    ("name".to_owned(), "planner".to_owned()),
                ]
            )
        );
        assert!(cgroups.describe(ino(agent), 7, 2).is_none());
        cgroups.retract(ino(agent));
        assert!(cgroups.describe(ino(agent), 7, 2).is_some());
        cgroups.forget();
        assert!(cgroups.describe(ino(agent), 7, 3).is_some());
    }

    #[test]
    fn a_child_takes_its_nearest_labelled_ancestors_labels() {
        let (tmp, tool) = tree();
        let agent = tool.parent().unwrap();
        label(agent.parent().unwrap(), "name", "container-wide");
        label(agent, "name", "planner");
        let mut cgroups = Cgroups::new(tmp.path());
        let (path, _, labels) = decoded(cgroups.describe(ino(&tool), 1, 1).unwrap());
        assert_eq!(path, "/pod/ctr/agent/tool");
        assert_eq!(labels, [("name".to_owned(), "planner".to_owned())]);
        // Unlabelled up to the root: no labels.
        let pod = tmp.path().join("pod");
        let (path, _, labels) = decoded(cgroups.describe(ino(&pod), 1, 1).unwrap());
        assert_eq!((path.as_str(), labels.len()), ("/pod", 0));
    }

    #[test]
    fn labels_a_record_cannot_carry_are_skipped() {
        let (tmp, tool) = tree();
        label(&tool, "Name", "upper-case key");
        label(&tool, "ok", "fine");
        label(&tool, "bell", "a\u{7}b");
        label(&tool, "long", &"x".repeat(LABEL_VALUE_LEN + 1));
        setxattr(&tool, "user.other", b"x", XattrFlags::empty()).unwrap();
        let mut cgroups = Cgroups::new(tmp.path());
        let (_, _, labels) = decoded(cgroups.describe(ino(&tool), 1, 1).unwrap());
        assert_eq!(labels, [("ok".to_owned(), "fine".to_owned())]);
    }

    #[test]
    fn at_most_max_labels_are_sent() {
        let (tmp, tool) = tree();
        for i in 0..MAX_LABELS + 2 {
            label(&tool, &format!("k{i:02}"), "v");
        }
        let mut cgroups = Cgroups::new(tmp.path());
        let (_, _, labels) = decoded(cgroups.describe(ino(&tool), 1, 1).unwrap());
        assert_eq!(labels.len(), MAX_LABELS);
        assert_eq!(labels[0].0, "k00");
    }

    #[test]
    fn walks_are_spaced_out_and_what_they_skip_is_described_later() {
        let (tmp, tool) = tree();
        let mut cgroups = Cgroups::new(tmp.path());
        assert!(cgroups.describe(ino(&tool), 1, 1).is_some());
        let late = tool.join("late");
        fs::create_dir(&late).unwrap();
        // Too soon after the walk: not looked for, and not taken as gone.
        assert!(cgroups.describe(ino(&late), 1, MIN_WALK_GAP_NS).is_none());
        assert!(!cgroups.described.contains(&ino(&late)));
        // Known cgroups need no walk.
        let agent = tool.parent().unwrap();
        assert!(cgroups.describe(ino(agent), 1, 2).is_some());
        // Its next record, later, finds it.
        let later = 1 + MIN_WALK_GAP_NS * 1000;
        assert!(cgroups.describe(ino(&late), 1, later).is_some());
        // A gap of at least MIN_WALK_GAP_NS follows each walk, and a walk may
        // run once it is over.
        assert!(cgroups.next_walk_ns >= later + MIN_WALK_GAP_NS);
        let last = tool.join("last");
        fs::create_dir(&last).unwrap();
        assert!(
            cgroups
                .describe(ino(&last), 1, cgroups.next_walk_ns)
                .is_some()
        );
    }

    #[test]
    fn a_cgroup_skipped_in_the_gap_is_described_once_a_walk_may_run() {
        let (tmp, tool) = tree();
        let mut cgroups = Cgroups::new(tmp.path());
        assert!(cgroups.describe(ino(&tool), 1, 1).is_some());
        let late = tool.join("late");
        fs::create_dir(&late).unwrap();
        assert!(cgroups.describe(ino(&late), 1, 2).is_none());
        assert!(cgroups.deferring());
        // Not before the gap is over.
        assert_eq!(cgroups.take_ready(3), []);
        let later = cgroups.next_walk_ns;
        assert_eq!(cgroups.take_ready(later), [ino(&late)]);
        assert!(!cgroups.deferring());
        let record = cgroups.describe(ino(&late), 1, later).unwrap();
        assert_eq!(decoded(record).0, "/pod/ctr/agent/tool/late");
        // A description that did not reach the queue waits again. Known now,
        // it needs no walk.
        cgroups.retract(ino(&late));
        assert_eq!(cgroups.take_ready(later), [ino(&late)]);
    }

    #[test]
    fn known_cgroups_waiting_go_before_those_needing_a_walk() {
        let (tmp, tool) = tree();
        let mut cgroups = Cgroups::new(tmp.path());
        assert!(cgroups.describe(ino(&tool), 1, 1).is_some());
        // One known cgroup and one found nowhere wait together.
        cgroups.retract(ino(&tool));
        assert!(cgroups.describe(u64::MAX, 1, 2).is_none());
        assert_eq!(cgroups.take_ready(3), [ino(&tool)]);
        // The other waits for the next walk.
        assert!(cgroups.deferring());
        assert_eq!(cgroups.take_ready(cgroups.next_walk_ns), [u64::MAX]);
    }

    #[test]
    fn deferring_a_described_cgroup_keeps_it_described() {
        let (tmp, tool) = tree();
        let mut cgroups = Cgroups::new(tmp.path());
        assert!(cgroups.describe(ino(&tool), 1, 1).is_some());
        cgroups.defer(ino(&tool));
        assert_eq!(cgroups.take_ready(2), [ino(&tool)]);
        assert!(cgroups.describe(ino(&tool), 1, 2).is_none());
    }

    #[test]
    fn a_full_wait_list_walks_at_once_instead_of_forgetting() {
        let (tmp, tool) = tree();
        let mut cgroups = Cgroups::new(tmp.path());
        assert!(cgroups.describe(ino(&tool), 1, 1).is_some());
        for id in 0..u64::try_from(MAX_CGROUPS).unwrap() {
            cgroups.defer(u64::MAX - id);
        }
        let late = tool.join("late");
        fs::create_dir(&late).unwrap();
        // Within the gap, but the wait list is full.
        let (path, _, _) = decoded(cgroups.describe(ino(&late), 1, 2).unwrap());
        assert_eq!(path, "/pod/ctr/agent/tool/late");
        // The walk did not find those waiting, which are gone: they stop
        // waiting, and take no room from new ones.
        assert!(cgroups.deferred.is_empty());
        // A mapped cgroup waiting for room in the queue is not one to walk for.
        cgroups.retract(ino(&late));
        assert_eq!(cgroups.unmapped, 0);
        // That walk mapped those waiting: the next new one waits again, so a
        // full wait list does not walk for each new cgroup.
        let later = tool.join("later");
        fs::create_dir(&later).unwrap();
        assert!(cgroups.describe(ino(&later), 1, 3).is_none());
        assert!(cgroups.deferred.contains(&ino(&later)));
        assert_eq!(cgroups.unmapped, 1);
    }

    #[test]
    fn the_cgroups_waiting_stay_bounded() {
        let mut cgroups = Cgroups::new(std::env::temp_dir());
        for id in 0..=u64::try_from(2 * MAX_CGROUPS).unwrap() {
            cgroups.retract(id);
        }
        assert_eq!(cgroups.deferred.len(), 2 * MAX_CGROUPS);
    }

    #[test]
    fn the_walk_and_the_ids_described_stay_bounded() {
        let tmp = tempfile::tempdir().unwrap();
        for i in 0..MAX_CGROUPS + 10 {
            fs::create_dir(tmp.path().join(i.to_string())).unwrap();
        }
        assert_eq!(walk(tmp.path()).len(), MAX_CGROUPS);
        // One walk finds them all, then each is described without another.
        let mut cgroups = Cgroups::new(tmp.path());
        assert!(cgroups.describe(ino(tmp.path()), 1, 1).is_some());
        let ids: Vec<u64> = cgroups.paths.keys().copied().collect();
        for &id in &ids {
            let _ = cgroups.describe(id, 1, 2);
        }
        assert_eq!(cgroups.described.len(), MAX_CGROUPS);
        // One more starts over rather than growing.
        let _ = cgroups.describe(u64::MAX, 1, u64::MAX);
        assert_eq!(cgroups.described.len(), 1);
    }

    #[test]
    fn the_walk_stops_at_its_depth() {
        let tmp = tempfile::tempdir().unwrap();
        let mut dir = tmp.path().to_path_buf();
        let mut chain = Vec::new();
        for _ in 0..=MAX_DEPTH {
            dir.push("d");
            chain.push(dir.clone());
        }
        fs::create_dir_all(&dir).unwrap();
        let mut cgroups = Cgroups::new(tmp.path());
        // chain[i] is i + 1 levels below the root.
        assert!(cgroups.describe(ino(&chain[MAX_DEPTH - 1]), 1, 1).is_some());
        assert!(cgroups.describe(ino(&chain[MAX_DEPTH]), 1, 1).is_none());
    }

    #[test]
    fn new_cgroups_are_found_and_vanished_ones_are_not_retried() {
        let (tmp, tool) = tree();
        let mut cgroups = Cgroups::new(tmp.path());
        assert!(cgroups.describe(ino(&tool), 1, 1).is_some());
        // Created after the first walk.
        let late = tool.join("late");
        fs::create_dir(&late).unwrap();
        let later = 1 + MIN_WALK_GAP_NS * 1000;
        let (path, _, _) = decoded(cgroups.describe(ino(&late), 1, later).unwrap());
        assert_eq!(path, "/pod/ctr/agent/tool/late");
        assert!(cgroups.describe(u64::MAX, 1, later * 2).is_none());
        assert!(cgroups.described.contains(&u64::MAX));
    }
}
