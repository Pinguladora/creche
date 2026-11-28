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
([0010](0010-pod-from-the-runtime-bundle.md)), and the guest kernel knows each
process's cgroup. Delegation keeps a process in its cgroup subtree only while it
cannot write an ancestor's `cgroup.procs` or bypass file permissions
([0011](0011-identity-within-a-pod.md)).

## Decision

The observer attaches BPF LSM programs to `bprm_check_security`, `mmap_file`
and `file_mprotect` (executable mappings), `file_open` and `socket_connect`,
and a cgroup `sendmsg` program for UDP sent without connecting. They return
`EPERM` for what the policy forbids. Files match by path prefix and by device
and inode, addresses by network and port. A policy can also refuse to execute or
map as code any file whose inode changed after the policy came into force, so a
copied, downloaded or built binary or library does not run, whether exec'd or
loaded through the dynamic loader.

Policies are files on the node, such as a mounted ConfigMap, that select pods by
namespace and name. A pod no file selects gets an empty policy. A pod more than
one file selects gets none, so it does not start. The sink sends the policy
after the observer's hello, on the same vsock connection, as wire records
([0004](0004-records-are-the-wire-format.md)), and sends a replacement when the
file changes or a host name in it resolves to new addresses. Only the sink
writes to the observer's connection, so the policy needs no signature. Rules
bind a cgroup and apply to its whole subtree, checked through the process's
cgroup ancestry. Labels select nothing.

A policy has a default, allow or deny, and allow, deny or audit rules. It starts
in audit mode until it says to enforce. Denials, and would-be denials in audit
mode, go into the audit trail ([0012](0012-audit-chain.md)) with the matching
rule, at most once a second per process and rule. The observer swaps in each
policy whole and confirms it by its SHA-256 digest.

The observer reports ready, and kata-agent starts, only once a policy is in
force and the guard has seen its programs run: an LSM program can attach and
never run ([0015](0015-observer-guards-its-port.md)). If the sink is down or BPF
LSM is inactive, the sandbox fails to start. A guest image can opt out of this.

While enforcing, the observer refuses to every other process the `bpf` syscall,
module loading, tracing or signalling the observer, and leaving a ruled
cgroup's subtree, by opening a `cgroup.procs` or `cgroup.threads` outside it for
writing or by cloning into another cgroup.

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
- `socket_sendmsg` for UDP: it runs on every send, TCP writes included.
- Merging the files that select one pod: which rule wins would be a guess.
- Pinning programs past the observer's exit: a restarted observer cannot be told
  from an impostor asking for `bpf` without a secret in the guest.
- Starting before the policy arrives: the first actions go unchecked.
- Policies as CRDs: the sink would need API access, and pod starts would depend
  on the API. A controller can render CRDs into the files instead.
- Host-only enforcement: cannot tell guest processes apart. It stays the
  backstop, for egress in particular.

## Consequences

Each exec, executable mapping, open and connect, and each unconnected UDP send,
runs a program when the policy has rules. An empty policy costs nothing beyond
observation. The cost is measured before this record is accepted.

Enforcement holds against workloads that cannot load BPF or take over the
observer, as the guard does ([0015](0015-observer-guards-its-port.md)). A guest
kernel compromise undoes it. Between an observer's exit and restart nothing is
enforced, and the stream's end shows it. In that window another process can
connect in its place and read the policy, so policies are not secret, but it
cannot change what the observer enforces. Workloads that need `bpf`, modules or
`CLONE_INTO_CGROUP` break.

Path deny rules are weak: a copy is a new file. Inode matching stops hard links
and mounts, and the change-time rule stops copies, but also packages installed
at run time. It stops native code only: interpreters read scripts as data, so
policies restrict the interpreters themselves, and code a JIT writes into
anonymous memory is out of reach. Allow-lists with a deny default are what
hold. Host names are resolved by the sink, since the kernel sees only
addresses, and the guest may resolve them differently, so rules on names are
approximate.

Pods on a node start only while its sink runs, which the trail needs anyway.
