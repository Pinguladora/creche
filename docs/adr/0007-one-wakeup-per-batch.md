# 0007. One wakeup per batch

- Status: Accepted
- Date: 2026-11-09

## Context

A kernel profile of the open loop showed every APIC write coming from
`bpf_ringbuf_output` waking the reader. Each wakeup is an interrupt, a timer and a
vsock doorbell ([0005](0005-hybrid-vsock-transport.md)), all VM exits, and the
observer slept through its batch window anyway.

## Decision

The BPF side asks for a wakeup only for the first record after a drain. The
observer drains at most once per 20 ms, counted from the last drain: a sparse
event is drained at once, and a burst waits for the end of the window. Idle, the
observer sleeps until its 5 s heartbeat.

## Alternatives

- The ring buffer's default wakeup on every record: one VM exit per record.
- A fixed timer: adds latency to sparse events and wakes an idle guest.
- A longer window: 50 ms overflowed the 1 MiB ring buffer in the open loop.

## Consequences

Exec, open and connect loops reached +6%, +8% and +4% at 20 ms with no drops.
Latency for a burst is up to 20 ms. Heartbeats report ring buffer and queue drops,
so silence can be told from blindness.
