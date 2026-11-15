# 0019. The host judges the observer's guard claim

- Status: Accepted
- Date: 2026-11-15

## Context

The observer reports whether its vsock port is guarded in its hello record, and
the sink wrote that as `creche.observer.guarded`
([0015](0015-observer-guards-its-port.md)). Whether tier 2 fields can be
believed rests on that attribute ([0011](0011-identity-within-a-pod.md)). But the
hello is the guest's own claim, and it can be forged exactly where the guard is
missing: on a kernel without BPF LSM, or between an observer's exit and its
restart, any guest process can connect and claim the port is guarded. Its
records then carry an attribute that says they can be believed.

## Decision

The sink judges each claim against what it sees across all streams of the
sandbox, and writes its verdict as `creche.observer.guarded`.

- The first hello of a sandbox decides what later ones may claim. Whether the
  port can be guarded is fixed by the guest kernel for the life of the VM, and
  the observer starts before any workload, so the first hello is the observer's.
  A later hello counts as guarded only if the first one claimed so too.
- A guarded port lets only the observer connect, and the observer opens a new
  connection only once the last one broke. A stream that still sends records
  after a newer stream of the same sandbox said hello shows two senders at once.
  Each stream of the sandbox then gets a `creche.stream.unguarded` line, with
  `creche.stream.unguarded_reason` `concurrent_streams`, and no later hello of
  the sandbox counts as guarded.

A hello whose claim the sink does not take also carries
`creche.observer.guard_claimed: true`, and its raw flags stay in
`creche.observer.flags`.

## Alternatives

- Reporting the claim under a `creche.guest.*` name, as tier 3: honest, but it
  takes away the only signal operators have without giving them a better one.
- Refusing connections after the first: a restarted observer could no longer
  connect (0015).
- Taking any two open streams as evidence: a restarted observer can leave its
  broken connection open for a moment, so that would mark honest restarts.

## Consequences

On a kernel without BPF LSM, no stream of the sandbox is reported as guarded,
whatever it claims. A process that races the observer in the restart window of
a guarded kernel can still claim the guard, as 0015 already accepts, though if
the observer comes back and both send, every stream of the sandbox loses it. The
first hello is pinned for as long as the sink runs. A sink that restarts pins
whatever reconnects first, which a process waiting in the guest could be. In the
raw output format the claim is passed on unjudged.
