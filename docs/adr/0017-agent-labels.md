# 0017. Agents label their cgroups with extended attributes

- Status: Accepted
- Date: 2026-11-09

## Context

Per-agent identity within a pod rests on each agent's own cgroup and uid, and an
agent's name is only ever a claim ([0011](0011-identity-within-a-pod.md)). The
guest kernel reports a process's cgroup by id and leaf name. That leaves no way
for an agent runtime to say which agent a cgroup belongs to, and an agent's
cgroup nested inside its container's loses the container, whose name is not its
leaf. Whatever carries the name must not let one agent name another's cgroup,
and must cost nothing on the path every event takes
([0006](0006-context-once.md), [0007](0007-one-wakeup-per-batch.md)).

## Decision

The runtime, or the agent itself, sets `user.creche.agent.<key>` extended
attributes on the agent's delegated cgroup, such as `name` and `id`, before any
process moves in. cgroup v2 supports user extended attributes, and only the
cgroup directory's owner, or a process allowed to bypass file permissions, can
set them. Under the delegation of [0011](0011-identity-within-a-pod.md) an agent
can label only its own cgroups.

The first time a task or exec record names a cgroup on a connection, the
observer sends a cgroup record ahead of it, built in userspace: the cgroup's path
from the cgroup v2 root, and its labels, or those of its nearest labelled
ancestor, with the uid owning the cgroup they came from. A cgroup's id is its
directory's inode number, so one walk of the hierarchy maps every id to its
path, and the walk runs only for an id not seen before. The kernel side does not
change. Keys, values and their number are bounded, and a record that breaks a
bound is corrupt. Readers that do not know the record skip it by its length.

The sink keeps the cgroups per stream and adds to every line from a process in
one the path as `creche.cgroup.path` and the owner as
`creche.cgroup.label_owner.uid`, which the guest kernel knows, and each label as
`creche.guest.agent.<key>`, which the workload claims. A container claim comes
from the deepest container cgroup on the path, so a nested agent cgroup keeps
its container, and the claim names a cgroup the process actually sits under.

## Alternatives

- Agent names in cgroup directory names: one value with no room for others, and
  it ties identity to a layout the runtime may not control.
- Reading the labels from BPF: only recent kernels let a program read a cgroup's
  extended attributes, and the labels would travel with every task record
  instead of once per cgroup.
- The runtime announcing agents to the observer over a socket: a second
  protocol, and any process that can reach the socket can claim any cgroup.
- Pod annotations mapping cgroups to agents: attested by the host, but fixed
  when the pod starts, while agents come and go inside it.

## Consequences

Events from several agents in one pod carry the agent each came from, at the
cost of one copy per line, and nested cgroups keep their container. A label says
what the cgroup's owner, or root in the guest, claims and nothing more. Its
owner uid lets a reader check it against the process's uid. Labels set or
changed after a cgroup was first described apply from the next connection, so a
runtime labels before it moves an agent in.
