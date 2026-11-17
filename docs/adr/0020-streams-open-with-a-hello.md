# 0020. A stream that does not open with a hello is not the observer

- Status: Accepted
- Date: 2026-11-16

## Context

The sink judges the observer's guard claim against what the sandbox's streams
show ([0019](0019-host-judges-the-guard-claim.md)). Two streams sending at once
show the port is not guarded, but the window for that opens with the newer
stream's hello. A process that reached the port while it was not guarded, before
the guard was attached or in the observer's restart window
([0015](0015-observer-guards-its-port.md)), can send records without ever saying
hello, so the window never opens and its records are written under the sandbox's
host-attested identity with the guard still taken.

## Decision

The observer opens every connection with a hello. A stream whose first complete
record is anything else, or is malformed, is not the observer, so the sink takes the sandbox's
port as not guarded from then on, as it does for two senders at once. Each
stream of the sandbox gets a `creche.stream.unguarded` line when it next sends
or ends, with `creche.stream.unguarded_reason` `no_hello`.

## Alternatives

- Opening the window on a newer stream's first record of any kind: it still
  gives such a stream two seconds, and a stream that sends now and then less.
- Refusing records before a hello: the host would lose what an intruder sends,
  which is what the trail is for.

## Consequences

An intruder that sends a hello first is judged as before. The raw output format
passes records on unjudged, as it does the claim.
