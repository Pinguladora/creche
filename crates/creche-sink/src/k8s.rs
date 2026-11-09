//! The Kubernetes pod a sandbox belongs to, from what the container runtime wrote
//! on the host.
//!
//! containerd writes each sandbox's OCI spec to `<bundles>/<sandbox id>/config.json`
//! in a directory only root can enter. Its CRI plugin sets the pod's name,
//! namespace and uid as annotations from kubelet's request, after any pod
//! annotations it passes through, so a pod author cannot override them. Nothing
//! here comes from the guest: the sandbox id is the one the peer check attested,
//! and the spec is read once, when a connection is accepted.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::fs;
use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;
use std::sync::Arc;

use miniserde::{Deserialize, json};

/// Where containerd keeps the bundles of the CRI namespace.
pub const CONTAINERD_BUNDLES: &str = "/run/containerd/io.containerd.runtime.v2.task/k8s.io";

/// Largest spec read. Sandbox specs are tens of KiB.
const MAX_SPEC_LEN: u64 = 1 << 20;
/// Longest value taken from an annotation: a DNS subdomain, the longest
/// Kubernetes name.
const MAX_VALUE_LEN: usize = 253;

const CONTAINER_TYPE: &str = "io.kubernetes.cri.container-type";
const SANDBOX_ID: &str = "io.kubernetes.cri.sandbox-id";
const SANDBOX_NAME: &str = "io.kubernetes.cri.sandbox-name";
const SANDBOX_NAMESPACE: &str = "io.kubernetes.cri.sandbox-namespace";
const SANDBOX_UID: &str = "io.kubernetes.cri.sandbox-uid";
const CONTAINER_NAME: &str = "io.kubernetes.cri.container-name";

/// Distinct container claims looked up per stream. A guest names a few
/// containers. Past this, new claims are not looked up, so a hostile guest
/// cannot make the sink read the disk without bound.
const MAX_CLAIMS: usize = 256;

/// A pod, as the container runtime recorded it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pod {
    /// `k8s.pod.name`.
    pub name: Arc<str>,
    /// `k8s.namespace.name`.
    pub namespace: Arc<str>,
    /// `k8s.pod.uid`.
    pub uid: Arc<str>,
}

/// Why a sandbox's pod is not known. Reported on every line instead of a pod.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unresolved {
    /// No bundle for this sandbox: not a Kubernetes pod, or another runtime.
    NoBundle,
    /// The bundle or its spec could be written by someone other than root or
    /// this process's user.
    Untrusted,
    /// The spec could not be read, or is larger than any sandbox spec.
    Unreadable,
    /// The spec is not the JSON of an OCI spec.
    Malformed,
    /// The spec is not a sandbox's, or names another sandbox id.
    Mismatch,
    /// A pod annotation is missing, empty or too long.
    Annotation,
}

impl Unresolved {
    /// The value of `creche.k8s.unresolved`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoBundle => "no_bundle",
            Self::Untrusted => "untrusted_bundle",
            Self::Unreadable => "unreadable_spec",
            Self::Malformed => "malformed_spec",
            Self::Mismatch => "sandbox_mismatch",
            Self::Annotation => "bad_annotation",
        }
    }
}

impl fmt::Display for Unresolved {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The part of an OCI spec read here. Other fields are skipped.
#[derive(Deserialize)]
struct Spec {
    annotations: Option<BTreeMap<String, String>>,
}

/// The pod of sandbox `id`, from its bundle under `bundles`. Blocking.
///
/// # Errors
///
/// Why the pod is not known.
pub fn resolve(bundles: &Path, id: &str) -> Result<Pod, Unresolved> {
    pod(&annotations(bundles, id)?, id)
}

/// The annotations of the spec in bundle `id` under `bundles`, when the bundle
/// and its spec can only have been written by a trusted user. Blocking.
fn annotations(bundles: &Path, id: &str) -> Result<BTreeMap<String, String>, Unresolved> {
    let trusted = trusted_owners();
    let bundle = bundles.join(id);
    let dir = fs::symlink_metadata(&bundle).map_err(|_| Unresolved::NoBundle)?;
    if !dir.is_dir() || !private(&dir, &trusted) {
        return Err(Unresolved::Untrusted);
    }
    let spec = bundle.join("config.json");
    let file = fs::symlink_metadata(&spec).map_err(|_| Unresolved::Unreadable)?;
    if !file.is_file() || !trusted.contains(&file.uid()) {
        return Err(Unresolved::Untrusted);
    }
    let mut text = String::new();
    fs::File::open(&spec)
        .and_then(|f| {
            f.take(MAX_SPEC_LEN.saturating_add(1))
                .read_to_string(&mut text)
        })
        .map_err(|_| Unresolved::Unreadable)?;
    if u64::try_from(text.len()).map_or(true, |len| len > MAX_SPEC_LEN) {
        return Err(Unresolved::Unreadable);
    }
    parse(&text)
}

/// The annotations of the OCI spec `text`.
fn parse(text: &str) -> Result<BTreeMap<String, String>, Unresolved> {
    let spec: Spec = json::from_str(text).map_err(|_| Unresolved::Malformed)?;
    Ok(spec.annotations.unwrap_or_default())
}

/// The annotation `key`, when present, non-empty and at most [`MAX_VALUE_LEN`].
fn value(annotations: &BTreeMap<String, String>, key: &str) -> Result<Arc<str>, Unresolved> {
    annotations
        .get(key)
        .filter(|v| !v.is_empty() && v.len() <= MAX_VALUE_LEN)
        .map(|v| Arc::from(v.as_str()))
        .ok_or(Unresolved::Annotation)
}

/// Whether `annotations` are those of a `kind` (`sandbox` or `container`) in
/// sandbox `sandbox`.
fn belongs(annotations: &BTreeMap<String, String>, kind: &str, sandbox: &str) -> bool {
    let get = |key: &str| annotations.get(key).map(String::as_str);
    get(CONTAINER_TYPE) == Some(kind) && get(SANDBOX_ID) == Some(sandbox)
}

/// The pod in sandbox `id`'s annotations.
fn pod(annotations: &BTreeMap<String, String>, id: &str) -> Result<Pod, Unresolved> {
    if !belongs(annotations, "sandbox", id) {
        return Err(Unresolved::Mismatch);
    }
    Ok(Pod {
        name: value(annotations, SANDBOX_NAME)?,
        namespace: value(annotations, SANDBOX_NAMESPACE)?,
        uid: value(annotations, SANDBOX_UID)?,
    })
}

/// A container of the pod, which the guest claims a process runs in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Container {
    /// `creche.guest.container.id`.
    pub id: Arc<str>,
    /// `creche.guest.container.name`, the name in the pod spec.
    pub name: Arc<str>,
}

/// The container id a guest cgroup name claims: kata-agent names a container's
/// cgroup `cri-containerd-<id>.scope` with the systemd driver and `<id>` with
/// cgroupfs. Container ids are 64 lowercase hex digits.
#[must_use]
pub fn claimed_id(cgroup: &str) -> Option<&str> {
    let id = cgroup
        .strip_prefix("cri-containerd-")
        .and_then(|rest| rest.strip_suffix(".scope"))
        .unwrap_or(cgroup);
    (id.len() == 64 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))).then_some(id)
}

/// The containers one stream's guest claims, checked against the runtime's
/// bundles. A claim holds only when the claimed id is a container of this
/// stream's sandbox. Each distinct cgroup name is looked up once.
#[derive(Debug)]
pub struct Containers {
    bundles: Arc<Path>,
    sandbox: Arc<str>,
    claims: HashMap<Arc<str>, Option<Arc<Container>>>,
}

impl Containers {
    /// Claims from sandbox `sandbox`, checked against `bundles`.
    #[must_use]
    pub fn new(bundles: Arc<Path>, sandbox: Arc<str>) -> Self {
        Self {
            bundles,
            sandbox,
            claims: HashMap::new(),
        }
    }

    /// The container a process in guest cgroup `cgroup` runs in, if the claim
    /// holds. Blocking on the first claim of each cgroup name.
    pub fn claim(&mut self, cgroup: &Arc<str>) -> Option<Arc<Container>> {
        if let Some(known) = self.claims.get(cgroup) {
            return known.clone();
        }
        let id = claimed_id(cgroup)?;
        if self.claims.len() >= MAX_CLAIMS {
            return None;
        }
        let found = annotations(&self.bundles, id)
            .ok()
            .filter(|a| belongs(a, "container", &self.sandbox))
            .and_then(|a| value(&a, CONTAINER_NAME).ok())
            .map(|name| {
                Arc::new(Container {
                    id: Arc::from(id),
                    name,
                })
            });
        self.claims.insert(Arc::clone(cgroup), found.clone());
        found
    }
}

/// Users whose files are trusted: root and the user this process runs as, read
/// from the owner of `/proc/self`.
fn trusted_owners() -> [u32; 2] {
    let me = fs::metadata("/proc/self").map_or(0, |m| m.uid());
    [0, me]
}

/// Whether only a trusted owner can enter or change the directory `dir`.
#[expect(
    clippy::verbose_bit_mask,
    reason = "a permission mask reads clearer than counting trailing zeros"
)]
fn private(dir: &fs::Metadata, trusted: &[u32]) -> bool {
    trusted.contains(&dir.uid()) && dir.mode() & 0o077 == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    const ID: &str = "0123456789abcdef";

    fn spec(annotations: &[(&str, &str)]) -> String {
        let fields: Vec<String> = annotations
            .iter()
            .map(|(k, v)| format!("\"{k}\":\"{v}\""))
            .collect();
        format!(
            "{{\"ociVersion\":\"1.2.0\",\"process\":{{\"args\":[\"/pause\"]}},\"annotations\":{{{}}}}}",
            fields.join(",")
        )
    }

    fn sandbox_spec() -> Vec<(&'static str, &'static str)> {
        vec![
            (CONTAINER_TYPE, "sandbox"),
            (SANDBOX_ID, ID),
            (SANDBOX_NAME, "agent-7"),
            (SANDBOX_NAMESPACE, "agents"),
            (SANDBOX_UID, "1f2e3d4c-0000-4000-8000-000000000001"),
            ("io.katacontainers.config.hypervisor.default_vcpus", "2"),
        ]
    }

    /// A bundle directory for `ID` holding `text`, private to this user.
    fn bundle(text: &str) -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(ID);
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(dir.join("config.json"), text).unwrap();
        tmp
    }

    #[test]
    fn the_pod_comes_from_the_sandbox_annotations() {
        let tmp = bundle(&spec(&sandbox_spec()));
        assert_eq!(
            resolve(tmp.path(), ID),
            Ok(Pod {
                name: "agent-7".into(),
                namespace: "agents".into(),
                uid: "1f2e3d4c-0000-4000-8000-000000000001".into(),
            })
        );
    }

    #[test]
    fn another_sandbox_or_a_container_spec_is_a_mismatch() {
        let mut other = sandbox_spec();
        other[1] = (SANDBOX_ID, "fedcba9876543210");
        let mut container = sandbox_spec();
        container[0] = (CONTAINER_TYPE, "container");
        let mut untyped = sandbox_spec();
        untyped.remove(0);
        for annotations in [other, container, untyped] {
            assert_eq!(
                pod(&parse(&spec(&annotations)).unwrap(), ID),
                Err(Unresolved::Mismatch)
            );
        }
        assert_eq!(pod(&parse("{}").unwrap(), ID), Err(Unresolved::Mismatch));
    }

    #[test]
    fn pod_annotations_must_be_present_and_bounded() {
        let long = "n".repeat(MAX_VALUE_LEN + 1);
        let at_limit = "n".repeat(MAX_VALUE_LEN);
        for key in [SANDBOX_NAME, SANDBOX_NAMESPACE, SANDBOX_UID] {
            let without: Vec<_> = sandbox_spec()
                .into_iter()
                .filter(|(k, _)| *k != key)
                .collect();
            assert_eq!(
                pod(&parse(&spec(&without)).unwrap(), ID),
                Err(Unresolved::Annotation),
                "{key}"
            );
            for (value, expected) in [
                ("", false),
                (long.as_str(), false),
                (at_limit.as_str(), true),
            ] {
                let set: Vec<_> = sandbox_spec()
                    .into_iter()
                    .map(|(k, v)| if k == key { (k, value) } else { (k, v) })
                    .collect();
                assert_eq!(
                    pod(&parse(&spec(&set)).unwrap(), ID).is_ok(),
                    expected,
                    "{key} of {} bytes",
                    value.len()
                );
            }
        }
    }

    #[test]
    fn malformed_specs_are_reported() {
        for text in [
            "",
            "not json",
            "{\"annotations\":[1]}",
            "{\"annotations\":{\"a\":1}}",
        ] {
            assert_eq!(parse(text), Err(Unresolved::Malformed), "{text}");
        }
    }

    #[test]
    fn deep_nesting_does_not_overflow_the_stack() {
        let deep = format!(
            "{{\"process\":{}{}}}",
            "[".repeat(100_000),
            "]".repeat(100_000)
        );
        assert_eq!(parse(&deep).map(|a| a.len()), Ok(0));
    }

    #[test]
    fn missing_or_open_bundles_are_not_used() {
        let tmp = bundle(&spec(&sandbox_spec()));
        assert_eq!(
            resolve(tmp.path(), "fedcba9876543210"),
            Err(Unresolved::NoBundle)
        );

        let dir = tmp.path().join(ID);
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o750)).unwrap();
        assert_eq!(resolve(tmp.path(), ID), Err(Unresolved::Untrusted));
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();

        // A symlinked bundle or spec is not followed.
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        assert_eq!(resolve(tmp.path(), "link"), Err(Unresolved::Untrusted));
        let spec_path = dir.join("config.json");
        fs::rename(&spec_path, dir.join("real.json")).unwrap();
        std::os::unix::fs::symlink(dir.join("real.json"), &spec_path).unwrap();
        assert_eq!(resolve(tmp.path(), ID), Err(Unresolved::Untrusted));
        fs::remove_file(&spec_path).unwrap();
        assert_eq!(resolve(tmp.path(), ID), Err(Unresolved::Unreadable));
    }

    #[test]
    fn oversized_specs_are_not_read() {
        let mut text = spec(&sandbox_spec());
        text.push_str(&" ".repeat(usize::try_from(MAX_SPEC_LEN).unwrap() - text.len()));
        let tmp = bundle(&text);
        assert!(resolve(tmp.path(), ID).is_ok());
        let tmp = bundle(&format!("{text} "));
        assert_eq!(resolve(tmp.path(), ID), Err(Unresolved::Unreadable));
    }

    #[test]
    fn only_root_and_this_user_are_trusted() {
        let tmp = tempfile::tempdir().unwrap();
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mine = fs::metadata(tmp.path()).unwrap();
        assert_eq!(trusted_owners(), [0, mine.uid()]);
        assert!(private(&mine, &[mine.uid()]));
        assert!(!private(&mine, &[mine.uid().wrapping_add(1)]));
    }

    const CID: &str = "5f473572d1da5189480c50a0dc42ef5d19c1f6d1da83dc6f281837d987c78933";

    #[test]
    fn cgroup_names_claim_container_ids() {
        let scope = format!("cri-containerd-{CID}.scope");
        assert_eq!(claimed_id(&scope), Some(CID));
        assert_eq!(claimed_id(CID), Some(CID));
        for name in [
            "kata-agent.service",
            "cri-containerd-abc.scope",
            &format!("cri-containerd-{CID}"),
            &format!("{CID}.scope"),
            &CID.to_uppercase(),
            &CID[1..],
            &format!("{CID}0"),
            "",
        ] {
            assert_eq!(claimed_id(name), None, "{name}");
        }
    }

    /// Bundles for sandbox `ID` and the containers in `containers`, each as
    /// (container id, sandbox id, container type).
    fn bundles(containers: &[(&str, &str, &str)]) -> tempfile::TempDir {
        let tmp = bundle(&spec(&sandbox_spec()));
        for (id, sandbox, kind) in containers {
            let dir = tmp.path().join(id);
            fs::create_dir(&dir).unwrap();
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
            let text = spec(&[
                (CONTAINER_TYPE, kind),
                (SANDBOX_ID, sandbox),
                (CONTAINER_NAME, "agent"),
            ]);
            fs::write(dir.join("config.json"), text).unwrap();
        }
        tmp
    }

    #[test]
    fn a_claim_holds_only_for_a_container_of_this_sandbox() {
        let other = "a".repeat(64);
        let foreign = "b".repeat(64);
        let sandboxed = "c".repeat(64);
        let tmp = bundles(&[
            (CID, ID, "container"),
            (&foreign, "fedcba9876543210", "container"),
            (&sandboxed, ID, "sandbox"),
        ]);
        let mut containers = Containers::new(Arc::from(tmp.path()), Arc::from(ID));
        let claim = |c: &mut Containers, name: &str| c.claim(&Arc::from(name));
        assert_eq!(
            claim(&mut containers, &format!("cri-containerd-{CID}.scope")).as_deref(),
            Some(&Container {
                id: CID.into(),
                name: "agent".into()
            })
        );
        // Another pod's container, a sandbox, an unknown id, guest services.
        for name in [&foreign, &sandboxed, &other, "kata-agent.service"] {
            assert_eq!(claim(&mut containers, name), None, "{name}");
        }
    }

    #[test]
    fn claims_are_looked_up_once_and_bounded() {
        let tmp = bundles(&[(CID, ID, "container")]);
        let mut containers = Containers::new(Arc::from(tmp.path()), Arc::from(ID));
        let name: Arc<str> = Arc::from(CID);
        assert!(containers.claim(&name).is_some());
        // Cached: the bundle is gone, the answer stays.
        fs::remove_dir_all(tmp.path().join(CID)).unwrap();
        assert!(containers.claim(&name).is_some());

        let tmp = bundles(&[(CID, ID, "container")]);
        let mut containers = Containers::new(Arc::from(tmp.path()), Arc::from(ID));
        for i in 0..MAX_CLAIMS {
            assert_eq!(containers.claim(&Arc::from(format!("{i:064x}"))), None);
        }
        assert_eq!(containers.claims.len(), MAX_CLAIMS);
        // Full: even a real container is no longer looked up.
        assert_eq!(containers.claim(&name), None);
        assert_eq!(containers.claims.len(), MAX_CLAIMS);
        // Names that claim nothing are not counted.
        assert_eq!(containers.claim(&Arc::from("kata-agent.service")), None);
    }

    #[test]
    fn unresolved_reasons_are_snake_case() {
        let all = [
            Unresolved::NoBundle,
            Unresolved::Untrusted,
            Unresolved::Unreadable,
            Unresolved::Malformed,
            Unresolved::Mismatch,
            Unresolved::Annotation,
        ];
        let names: Vec<String> = all.iter().map(ToString::to_string).collect();
        assert_eq!(
            names,
            [
                "no_bundle",
                "untrusted_bundle",
                "unreadable_spec",
                "malformed_spec",
                "sandbox_mismatch",
                "bad_annotation"
            ]
        );
    }
}
