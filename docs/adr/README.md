# Architecture decision records

Each record explains one significant decision: the forces at play, what was
chosen, what was rejected and what it costs. Records are not rewritten when a
decision changes. A new record supersedes the old one, and the old one says so in
its status, so the history of how creche evolved stays readable.

Records 0001 to 0008 were written down on 2026-11-09, after the decisions were
made. Their numbers follow the order in which the decisions were taken. A record
links only to earlier records, never to later ones.

| Record | Status |
|---|---|
| [0000 Record architecture decisions](0000-record-architecture-decisions.md) | Accepted |
| [0001 Observe from inside the guest with eBPF](0001-observe-inside-the-guest.md) | Accepted |
| [0002 Kata's guest kernel with an eBPF fragment](0002-guest-kernel.md) | Accepted |
| [0003 BPF programs in C, userspace in Rust with aya](0003-c-bpf-rust-userspace.md) | Accepted |
| [0004 Ring buffer records are the wire format](0004-records-are-the-wire-format.md) | Accepted |
| [0005 Hybrid vsock to a host sink](0005-hybrid-vsock-transport.md) | Accepted |
| [0006 Process context once, from a pid slot cache](0006-context-once.md) | Accepted |
| [0007 One wakeup per batch](0007-one-wakeup-per-batch.md) | Accepted |
| [0008 OpenTelemetry JSON lines and raw frames](0008-output-formats.md) | Accepted |
| [0009 The host attests the sandbox](0009-host-attests-the-sandbox.md) | Proposed |
| [0010 The pod comes from the container runtime's bundle](0010-pod-from-the-runtime-bundle.md) | Proposed |
| [0011 Identity within a pod: cgroup and uid per agent](0011-identity-within-a-pod.md) | Proposed |

## Writing a record

Copy [template.md](template.md) to the next free number. Keep it short: the
reader should learn why, not every detail of how. Link measurements instead of
repeating them. A record starts as Proposed and becomes Accepted once the
decision is in effect.
