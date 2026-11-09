//! The Kubernetes pod a sandbox belongs to, from what the container runtime wrote
//! on the host.
//!
//! containerd writes each sandbox's OCI spec to `<bundles>/<sandbox id>/config.json`
//! in a directory only root can enter. Its CRI plugin sets the pod's name,
//! namespace and uid as annotations from kubelet's request, after any pod
//! annotations it passes through, so a pod author cannot override them. Nothing
//! here comes from the guest: the sandbox id is the one the peer check attested,
//! and the spec is read once, when a connection is accepted.

use std::collections::BTreeMap;
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
    pod(&text, id)
}

/// The pod in spec `text`, which must be sandbox `id`'s.
fn pod(text: &str, id: &str) -> Result<Pod, Unresolved> {
    let spec: Spec = json::from_str(text).map_err(|_| Unresolved::Malformed)?;
    let annotations = spec.annotations.unwrap_or_default();
    let get = |key: &str| annotations.get(key).map(String::as_str);
    if get(CONTAINER_TYPE) != Some("sandbox") || get(SANDBOX_ID) != Some(id) {
        return Err(Unresolved::Mismatch);
    }
    let value = |key: &str| {
        get(key)
            .filter(|v| !v.is_empty() && v.len() <= MAX_VALUE_LEN)
            .map(Arc::from)
            .ok_or(Unresolved::Annotation)
    };
    Ok(Pod {
        name: value(SANDBOX_NAME)?,
        namespace: value(SANDBOX_NAMESPACE)?,
        uid: value(SANDBOX_UID)?,
    })
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
            assert_eq!(pod(&spec(&annotations), ID), Err(Unresolved::Mismatch));
        }
        assert_eq!(pod("{}", ID), Err(Unresolved::Mismatch));
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
                pod(&spec(&without), ID),
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
                    pod(&spec(&set), ID).is_ok(),
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
            assert_eq!(pod(text, ID), Err(Unresolved::Malformed), "{text}");
        }
    }

    #[test]
    fn deep_nesting_does_not_overflow_the_stack() {
        let deep = format!(
            "{{\"process\":{}{}}}",
            "[".repeat(100_000),
            "]".repeat(100_000)
        );
        assert_eq!(pod(&deep, ID), Err(Unresolved::Mismatch));
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
