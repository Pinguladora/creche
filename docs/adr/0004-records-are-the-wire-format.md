# 0004. Ring buffer records are the wire format

- Status: Accepted
- Date: 2026-11-09

## Context

Every byte the observer touches costs CPU inside the sandbox. A conventional
design would decode records in the guest and serialize them again for the host.

## Decision

The records the BPF programs write to the ring buffer are the wire format. The
observer copies them to the socket unchanged, and all decoding happens on the
host. `creche-wire` is the single definition: `no_std`, no allocation, no
`unsafe`, a strict clippy configuration, and a decoder that treats every length
and offset as attacker controlled. Records have a 16-byte header (kind, length,
pid, boot time) and variable-length records are cut after their last used byte.
A hello record carries the format version.

## Alternatives

- Decoding in the guest and sending JSON or protobuf: several times the CPU and
  bytes inside the sandbox.
- A self-describing format (CBOR, MessagePack): framing and type tags on every
  record for flexibility the two ends do not need, since they ship together.

## Consequences

The guest does almost no work per record. Changing a record means changing the C
struct, the Rust struct and the version together. The build fails if their sizes
or field offsets disagree, but not on a change of field type of the same size or
a forgotten version bump. The host decoder carries the whole burden of validation: it must accept
any bytes without panicking, reading out of bounds or allocating without limit.
