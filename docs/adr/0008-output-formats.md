# 0008. OpenTelemetry JSON lines and raw frames

- Status: Accepted
- Date: 2026-11-09

## Context

creche sees what host tools cannot, so its events should reach the pipelines that
Tetragon, Falco and KubeArmor already feed. Some consumers want to decode the
records themselves.

## Decision

The sink writes JSON lines by default, with attribute names from the
OpenTelemetry semantic conventions where one exists (`process.pid`,
`process.executable.path`, `file.path`, `destination.address`) and the
`creche.` namespace for the rest. `-o raw` writes the validated records unchanged
in frames naming their sandbox. The JSON writer is hand written: literal keys,
escaping checked 16 bytes at a time, no serde at run time.

## Alternatives

- MessagePack, FlatBuffers or protobuf: smaller and faster to parse, but no log
  shipper reads them without a plugin, and the host side cost is not the
  bottleneck.
- serde_json: the first, serde based writer was 1.6 to 2 times slower in the
  render benchmark for this flat shape, and serde is a large dependency. It stays a dev-dependency to check the writer's output.
- Direct OTLP export: planned as an additional output, not a replacement.

## Consequences

Any collector with a file log receiver can take the output. The writer must keep
every line valid JSON for any guest bytes. Field names are a contract, so renaming
one is a breaking change.
