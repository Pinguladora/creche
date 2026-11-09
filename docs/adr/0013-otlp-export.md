# 0013. OTLP export over gRPC with zstd, the line as the body

- Status: Proposed
- Date: 2026-11-09

## Context

Collectors, SIEMs and log backends take OpenTelemetry logs. JSON lines on stdout
reach them only through a file shipper ([0008](0008-output-formats.md)). Lines
must keep the exact bytes their audit chain covers
([0012](0012-audit-chain.md)), and exporting must never slow down or block the
sink's own output.

## Decision

The sink can also export every JSON line as an OTLP log record, over gRPC by
default and over OTLP/HTTP as a fallback, as protobuf compressed with zstd, in
cleartext to a collector on the node.

- The record's body is the line's exact text and its `eventName` the line's
  `event.name`. A collector can parse the body into attributes, and the bodies,
  each followed by a newline, verify like the sink's own output.
- Each stream is one resource: its sandbox, pod and stream id.
- Lines reach the exporter through a bounded queue. When it is full, they are
  dropped from the export only, counted, and show as gaps in `creche.seq`
  downstream, unless they were a stream's last lines or all of them, which only
  an independent signal, such as the sink's own archive, reveals. Transient failures are retried with backoff, permanent ones drop
  the request.
- gRPC uses `h2` directly, messages are a hand-written `prost` subset of the
  OTLP protos, and zstd is `ruzstd`. All are pure Rust, so the sink still builds
  as a static musl binary.

## Alternatives

- OTLP/HTTP with JSON encoding: no protobuf dependency, but larger and slower to
  parse. Kept out in favour of one encoding for both transports.
- tonic: a complete gRPC stack and generated code for one unary call.
- TLS in the sink, with rustls: certificates and their rotation on every node
  for a hop that stays on the node.
- The `zstd` crate: faster compression, but it builds the C library, which the
  static musl build cannot do without a musl C toolchain.
- Attributes for every field instead of the line as the body: collectors would
  re-serialize them and the audit chain could no longer be checked.

## Consequences

The sink speaks to any OpenTelemetry collector without a file shipper, and an
exported stream can still be verified from what the collector stored. ruzstd
compresses at roughly zstd level 1, enough for repetitive log lines. The sink
does not do TLS or authentication: it exports to a collector on the node, and
that collector owns TLS, authentication and routing onward, so the sink carries
no certificates or credentials. The collector's receiver must therefore be
reachable by the sink alone, for example on a socket or port other workloads
cannot reach: anything that can send to it can submit lines naming any sandbox.
Signed streams expose such lines to a verifier, unsigned ones do not. The
collector must accept zstd, which the OpenTelemetry Collector does.
