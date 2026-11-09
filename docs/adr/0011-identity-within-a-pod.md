# 0011. Identity within a pod: cgroup and uid per agent

- Status: Accepted
- Date: 2026-11-09

## Context

Agent platforms do not always run one agent per pod. Some run several agents as
separate processes in one pod, and some serve many sessions from a single
process. An audit trail must still say which agent did what, and must be honest
about how much each answer can be trusted.

The microVM is the pod, so the host sees one sandbox per pod. The host attests
the sandbox ([0009](0009-host-attests-the-sandbox.md)) and its pod
([0010](0010-pod-from-the-runtime-bundle.md)). Everything below that comes from
inside the guest ([0001](0001-observe-inside-the-guest.md)).

## Decision

Every attribute belongs to one of three tiers, and its name says which.

1. Host attested: the sandbox id and the pod's name, namespace and uid. Only root
   on the host can forge them.
2. Observed by the guest kernel: pid, process tree, uid, cgroup id and name, exec
   path. They hold only while the observer is the one sending records, so only
   what controls the guest kernel or the observer can forge them.
3. Claimed by the workload: anything a process announces about itself. Reported
   under `creche.guest.*`, checked against the host where possible, as with the
   container a cgroup names.

Per-agent identity inside one pod rests on tier 2. Each agent runs in its own
cgroup, a delegated cgroup v2 subtree inside its container, under its own uid.
Only that uid may write the `cgroup.procs` files of its subtree, and no agent may
write those of a common ancestor. Moving a process needs write access to both the
destination's and the common ancestor's `cgroup.procs`, so no agent can move a
process into another's cgroup. Each agent's files are closed to the other uids,
by mode and ACL, or kept on a separate filesystem, and no agent may gain a
privilege that changes its uid, such as `CAP_SETUID` or a setuid binary. creche reports the cgroup and uid on every event, and
maps a cgroup to an agent name only as a tier 3 claim.

Where identity must hold against a compromised agent, run one agent or one
session per Kata pod, so the separation is the VM boundary and the identity is
tier 1.

## Alternatives

- One identity per pod only: correct, but useless for platforms that share a pod
  between agents.
- Agent names announced by the runtime, without kernel grouping: any process in
  the pod could claim any name.
- Per-session attribution inside one process: the kernel sees one pid, so no
  observer below the runtime can split it. That stays the runtime's own
  telemetry, which creche events can be correlated with by pid and time.

## Consequences

Agent platforms get per-agent attribution by giving each agent a cgroup and a
uid, which also limits what agents can do to each other. Shared uids or loose
permissions weaken it: an agent able to write both a sibling's and their common
ancestor's `cgroup.procs` can move into the sibling's cgroup, and one able to
change its uid can read the sibling's files.

Tier 2 needs the observer to be the only sender. Any guest process that can open
a vsock socket could connect to the observer's port and send records of its own,
which the host cannot tell from the observer's, unless the observer refuses that
port to other processes. A workload in the pod can forge tier 2 fields wherever
the observer is not guarded. A process that can load BPF programs or take over
the observer can forge tiers 2 and 3 anyway, which is why strong separation means
one agent per VM. Sessions multiplexed in one process are out of reach of kernel
observation.
