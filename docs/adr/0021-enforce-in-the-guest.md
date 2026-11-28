# 0021. Enforce policy in the guest with BPF LSM, policy from the host

- Status: Proposed
- Date: 2026-11-28

## Context

creche records what an agent did ([0001](0001-observe-inside-the-guest.md)) but
cannot stop it, and the host cannot either: it sees the VMM, not the guest's
processes. The guest kernel has BPF LSM ([0002](0002-guest-kernel.md)), and the
observer already uses it ([0015](0015-observer-guards-its-port.md)).

The sandbox must not pick its own policy. Agent labels are workload claims
([0017](0017-agent-labels.md)). The pod is attested by the host
([0010](0010-pod-from-the-runtime-bundle.md)), and a process cannot leave its
delegated cgroup subtree ([0011](0011-identity-within-a-pod.md)).

## Decision

The observer attaches BPF LSM programs to `bprm_check_security`, `file_open`,
`socket_connect` and `socket_sendmsg`, and returns `EPERM` for what the policy
forbids. Files match by path prefix and by device and inode, addresses by
network and port. A policy can also refuse to execute files whose inode changed
after it came into force, so copied, downloaded or built binaries do not run.

Policies are files on the node, such as a mounted ConfigMap, that select pods by
namespace and name. A pod no file selects gets an empty policy. The sink sends
the policy after the observer's hello, on the same vsock connection, as wire
records ([0004](0004-records-are-the-wire-format.md)). Only the sink and the
observer hold its ends, so the policy needs no signature. Rules bind a cgroup
and apply to its whole subtree, checked through the process's cgroup ancestry.
Labels select nothing.

A policy has a default, allow or deny, and allow, deny or audit rules. It starts
in audit mode until it says to enforce. Denials, and would-be denials in audit
mode, go into the audit trail ([0012](0012-audit-chain.md)) with the matching
rule, at most once a second per process and rule. The observer confirms each
policy by its SHA-256 digest.

The observer reports ready, and kata-agent starts, only once a policy is in
force. If the sink is down, the sandbox fails to start. A guest image can opt
out of this. While enforcing, the observer refuses to every other process the
`bpf` syscall, module loading, and tracing or signalling the observer.

## Alternatives

- Killing after the fact (Tetragon's `SIGKILL`): the action already ran.
  Overriding return values works only on error-injection functions.
- SELinux in the guest: Kata's guest kernel has it, but its policy is compiled
  and loaded in the guest, binds process labels rather than cgroups, handles
  addresses poorly, and logs denials to the kernel audit log. A guest image can
  still load one as a fixed baseline under creche's policy.
- AppArmor: not in Kata's guest kernel, and its profiles too are loaded by tools
  in the guest.
- KubeArmor in the guest: it reads policy from the cluster API, which an
  untrusted guest should not reach.
- Seccomp: per syscall, not per path or address, fixed at start, set by the pod
  author.
- Policy by agent label: the agent could pick its own.
- Pinning programs past the observer's exit: a restarted observer cannot be told
  from an impostor asking for `bpf` without a secret in the guest.
- Starting before the policy arrives: the first actions go unchecked.
- Policies as CRDs: the sink would need API access, and pod starts would depend
  on the API. A controller can render CRDs into the files instead.
- Host-only enforcement: cannot tell guest processes apart. It stays the
  backstop, for egress in particular.

## Consequences

Each exec, open, connect and datagram runs an LSM program when the policy has
rules. An empty policy costs nothing beyond observation. The cost is measured
before this record is accepted.

Enforcement holds against workloads that cannot load BPF or take over the
observer, as the guard does ([0015](0015-observer-guards-its-port.md)). A guest
kernel compromise undoes it. Between an observer's exit and restart nothing is
enforced, and the stream's end shows it. Workloads that need `bpf` or modules
break.

Path deny rules are weak: a copy is a new file. Inode matching stops hard links
and mounts, and the change-time rule stops copies, but also packages installed
at run time. Allow-lists with a deny default are what hold. Host names in rules
are resolved by the sink, since the kernel sees only addresses.

Pods on a node start only while its sink runs, which the trail needs anyway.
