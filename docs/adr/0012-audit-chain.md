# 0012. Numbered streams chained with SHA-256 checkpoints

- Status: Proposed
- Date: 2026-11-09

## Context

An audit trail must show when lines were removed, changed, reordered or added
after the sink wrote them. Attribution is attested by the host
([0009](0009-host-attests-the-sandbox.md),
[0010](0010-pod-from-the-runtime-bundle.md)), but nothing yet protected the output
itself, and refused connections only reached the sink's log.

## Decision

Each accepted connection is a stream with an id unique across sink restarts. It
opens with a `creche.stream.start` line naming the peer and closes with
`creche.stream.end` and its reason. Every line of a stream carries `creche.seq`.

Once 256 lines are uncovered, or a second after the first of them, and when the
stream ends, a `creche.audit.checkpoint` line covers the lines since the previous
checkpoint: `SHA-256(previous hash || the exact bytes of those lines)`, from 32
zero bytes. Checkpoints are written after the input that made them due, and are
not hashed themselves. `creche-sink --verify` checks saved output.

Refused connections become `creche.sink.refused` lines, outside any stream.
Lines decoded before a corrupt record are kept.

## Alternatives

- A hash on every line: verification would not need checkpoints, but hashing per
  line roughly triples the sink's cost per event.
- BLAKE3: measured at about 12 GB/s on 64 KiB updates against SHA-256's 2.5 GB/s
  with SHA-NI, but about 1 GB/s on small updates. SHA-256 is checkable with any
  standard tool and library. BLAKE3 stays the candidate if the sink's own cost
  starts to matter.
- One chain per sandbox across connections: a sink restart breaks it anyway, and
  start and end lines already tie streams to their sandbox.
- Signing every checkpoint: needs key management in the sink. The chain is kept
  so that signing or exporting checkpoints can be added on top.

## Consequences

The audited render of the sample stream takes 6.0 ms against 1.7 ms, about three
million events per second on one core, all on the host. Verification needs the
exact bytes the sink wrote, so it runs on archived output, not on lines a shipper
has parsed and serialized again. A gap in `creche.seq` shows a removed line and a
mismatched hash a changed one, but whoever can rewrite every checkpoint can
rewrite the lines too: the chain proves integrity only as far as its checkpoints
are kept out of reach. The raw format carries no sequence numbers or checkpoints.
