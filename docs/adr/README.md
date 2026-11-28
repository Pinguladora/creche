# Architecture decision records

Each record explains one significant decision: the forces at play, what was
chosen, what was rejected and what it costs. Records are not rewritten when a
decision changes. A new record supersedes the old one, and the old one says so in
its status, so the history of how creche evolved stays readable.

Records 0001 to 0008 were written down on 2026-11-09, after the decisions were
made. Their numbers follow the order in which the decisions were taken. Between
records, a record links only to earlier ones. The one exception is a superseded
record's status, which names the record that replaced it. Links to measurements
and other documents are welcome.

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
| [0009 The host attests the sandbox](0009-host-attests-the-sandbox.md) | Accepted |
| [0010 The pod comes from the container runtime's bundle](0010-pod-from-the-runtime-bundle.md) | Accepted |
| [0011 Identity within a pod: cgroup and uid per agent](0011-identity-within-a-pod.md) | Accepted |
| [0012 Numbered streams chained with SHA-256 checkpoints](0012-audit-chain.md) | Accepted |
| [0013 OTLP export over gRPC with zstd, the line as the body](0013-otlp-export.md) | Accepted |
| [0014 Checkpoints signed with a ratchet anchored to a SPIFFE SVID](0014-signed-checkpoints.md) | Accepted |
| [0015 The observer guards its vsock port with BPF LSM](0015-observer-guards-its-port.md) | Accepted |
| [0016 Streams are bound to the node their sandbox ran on](0016-streams-bound-to-their-node.md) | Accepted |
| [0017 Agents label their cgroups with extended attributes](0017-agent-labels.md) | Accepted |
| [0018 The kernel names the VMM](0018-kernel-names-the-vmm.md) | Accepted |
| [0019 The host judges the observer's guard claim](0019-host-judges-the-guard-claim.md) | Accepted |
| [0020 A stream that does not open with a hello is not the observer](0020-streams-open-with-a-hello.md) | Accepted |
| [0021 Enforce policy in the guest with BPF LSM, policy from the host](0021-enforce-in-the-guest.md) | Proposed |

## Writing a record

Copy [template.md](template.md) to the next free number. Keep it short: the
reader should learn why, not every detail of how. Link measurements instead of
repeating them. A record starts as Proposed and becomes Accepted once the
decision is in effect.
