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
//! record names an id it has not seen.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

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
/// Most cgroups the walk maps. A guest has a few dozen.
const MAX_CGROUPS: usize = 4096;

/// What the observer knows of the guest's cgroups and has told the host.
#[derive(Debug)]
pub struct Cgroups {
    root: PathBuf,
    /// Paths by cgroup id, from the last walk.
    paths: HashMap<u64, PathBuf>,
    /// Ids described on this connection, or found nowhere.
    described: HashSet<u64>,
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
            record: Box::new([0; MAX_RECORD_LEN]),
        }
    }

    /// A cgroup record for cgroup `id`, to send before the record that named
    /// it, when it was not described on this connection yet. `None` once it
    /// has been, or when it no longer exists.
    pub fn describe(&mut self, id: u64, pid: u32, ts_ns: u64) -> Option<&[u8]> {
        if !self.described.insert(id) {
            return None;
        }
        if !self.paths.contains_key(&id) {
            self.paths = walk(&self.root);
        }
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

    /// Forgets what the host was told, for a new connection or after records
    /// were lost.
    pub fn forget(&mut self) {
        self.described.clear();
    }
}

/// Every cgroup directory under `root`, by inode number.
fn walk(root: &Path) -> HashMap<u64, PathBuf> {
    let mut found = HashMap::new();
    let mut pending = vec![(root.to_path_buf(), 0_usize)];
    while let Some((dir, depth)) = pending.pop() {
        let Ok(meta) = fs::metadata(&dir) else {
            continue;
        };
        found.insert(meta.ino(), dir.clone());
        if found.len() >= MAX_CGROUPS || depth >= MAX_DEPTH {
            continue;
        }
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
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
        let (path, _, _) = decoded(cgroups.describe(ino(&late), 1, 1).unwrap());
        assert_eq!(path, "/pod/ctr/agent/tool/late");
        assert!(cgroups.describe(u64::MAX, 1, 1).is_none());
        assert!(cgroups.described.contains(&u64::MAX));
    }
}
