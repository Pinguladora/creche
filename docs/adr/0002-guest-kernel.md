# 0002. Kata's guest kernel with an eBPF fragment

- Status: Accepted
- Date: 2026-11-09

## Context

Observing from inside the guest ([0001](0001-observe-inside-the-guest.md)) needs
a guest kernel that can load modern BPF programs. Kata's default guest kernel has `CONFIG_BPF_SYSCALL` but no JIT, BTF or tracing
support, so CO-RE, `tp_btf`, fentry and LSM programs cannot load. Its debug kernel
has them but no BPF LSM, and carries debugging extras.

## Decision

Build Kata's guest kernel with Kata's own `build-kernel.sh` and an extra fragment,
`kernel/kata-guest-ebpf.conf`: BTF, the JIT (always on), kprobe events, BPF
events, the function tracer and BPF LSM, with unprivileged BPF off. Track the
version Kata ships (6.18.56 for Kata 4.3.1). [The Kata
proposal](../kata-guest-ebpf-proposal.md) describes the fragment and its cost.

## Alternatives

- Kata's debug kernel: no BPF LSM, and extras not meant for production.
- A newer kernel than Kata ships: 7.3.3 was measured. Run time overhead is the
  same, and sorted BTF makes loading faster, but it is not what Kata ships and its
  config needs `CONFIG_SYSCTL=y` added or vsock fails to register.

## Consequences

On 6.18 the fragment costs 9.8 MB of kernel image, about 14 MB of host memory per
VM and about 55 ms of boot in the nested lab, and nothing measurable at run time.
BPF LSM makes enforcement possible later. Until Kata ships the fragment, users
build their own kernel.
