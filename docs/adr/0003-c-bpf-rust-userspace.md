# 0003. BPF programs in C, userspace in Rust with aya

- Status: Accepted
- Date: 2026-11-09

## Context

The first observer was C on libbpf. Rust was preferred for the daemons, for
memory safety and to share one definition of the wire format between guest and
host. The guest
binary must be static, since the Kata guest image does not promise a libc.

## Decision

Keep the BPF programs in C with CO-RE (`vmlinux.h`, clang). Write the observer
and the sink in Rust, and load the programs with aya, a pure Rust loader.
`creche-wire` defines the record layout in Rust and `wire.h` mirrors it in C.
`build.rs` asserts that their struct sizes and field offsets agree. It does not
compare field types.

## Alternatives

- BPF in Rust (aya-ebpf): it does not support CO-RE field relocations, so
  programs would depend on one kernel's struct layouts. C with CO-RE is the mature path the verifier and the
  kernel documentation assume.
- libbpf-rs: wraps libbpf, which brings C dependencies (libbpf, libelf, zlib) into
  a static musl build.
- Staying with C userspace: no memory safety in a daemon that parses and forwards
  data, and the wire format would be defined twice.

## Consequences

With the same design the Rust observer streams at the same cost as the C one.
musl's `memcpy` made small copies slow, so the queue copies fixed 16-byte chunks
in safe Rust. aya scans kernel BTF linearly where libbpf indexes it, which makes
startup slower than C on 6.18. A one pass candidate search in aya brings it below
C.
