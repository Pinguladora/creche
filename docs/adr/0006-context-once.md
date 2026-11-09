# 0006. Process context once, from a pid slot cache

- Status: Accepted
- Date: 2026-11-09

## Context

Wire format v2 repeated the process context (parent, uid, cgroup, name) in a
48-byte header on every record, 193 MB for 2.1M events. The first fix kept the
context in BPF task storage, but allocating and freeing that storage per process
cost about 1.7 us per process, most of the exec loop's overhead.

## Decision

Records carry only the pid. A task record sends the context when it first appears
or changes, exec records carry the new context themselves, and forks hand the
parent's context to the child on the host. In the kernel, a 4096-slot array
indexed by pid remembers what was sent, with no allocation per process. An epoch
counter makes every process resend after a reconnect or a drop. The sink keeps
the context per pid and adds it to every JSON line.

## Alternatives

- Context on every record: the v2 cost in bytes and CPU.
- BPF task storage: correct but allocates per process.
- A hash map keyed by pid: allocation and locking on the hot path.

## Consequences

Bytes fell from 193 MB to 66 MB and observer CPU roughly halved. Two pids sharing a
slot only cause an extra task record. The sink must bound its own per-stream
state: it tracks at most 65536 processes.
