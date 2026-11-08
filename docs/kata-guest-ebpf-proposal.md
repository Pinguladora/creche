# Guest kernel: build in BTF, BPF JIT and BPF LSM for in-guest eBPF

## Summary

Offer a Kata guest kernel that can run modern eBPF programs, so that workloads in a
Kata sandbox can be observed and policed from inside the guest without a custom
kernel. Concretely: a config fragment that adds BTF, the BPF JIT, the tracing
support BPF programs need and BPF LSM. On Kata 4.3.1's guest kernel (Linux 6.18.56)
it costs 9.8 MB of kernel image, 14 MB of host memory per VM and about 55 ms of boot
in our nested setup, and nothing measurable at run time.

## Motivation

Kata is increasingly used to sandbox untrusted code, AI agents among it. Agents
spawn tools, open files and make connections that nobody reviewed, and operators
want to see that activity and to block parts of it.

Host side tools cannot help. For a Kata pod, Tetragon or Falco on the host see
`cloud-hypervisor` and `virtiofsd`, not the processes in the guest. Tetragon as a
sidecar inside the pod reported no events in our tests, and on the default guest
kernel its programs cannot load at all.

The tool for this job is eBPF in the guest kernel, but no Kata kernel supports it:

- The default guest kernel has `CONFIG_BPF_SYSCALL` and `CONFIG_CGROUP_BPF`, but no
  JIT, no BTF and no tracing support. CO-RE programs, `tp_btf`, fentry and LSM
  programs cannot load.
- The debug kernel has BTF, the JIT and tracing, but no BPF LSM, so it can observe
  but not enforce. It also carries debugging extras (uprobes, syscall tracepoints,
  IKCONFIG) that are not meant for production.

So users who need this build and maintain their own guest kernel, which drifts from
Kata's releases and is easy to get wrong. Ant Group runs in-guest eBPF on Kata in
production (their CWPP whitepaper on katacontainers.io), on their own stack.

## Proposal

A config fragment, `ebpf.conf`, with only what CO-RE, `tp_btf`, fentry and BPF LSM
programs need:

```
# BTF is generated from DWARF, which needs the debug info choice.
CONFIG_DEBUG_KERNEL=y
CONFIG_DEBUG_INFO=y
CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=y
CONFIG_DEBUG_INFO_BTF=y

# JIT only: no interpreter, also a hardening default.
CONFIG_BPF_JIT=y
CONFIG_BPF_JIT_ALWAYS_ON=y
# Kata's configs start from allnoconfig, which turns this kernel default off and
# leaves unprivileged BPF enabled.
CONFIG_BPF_UNPRIV_DEFAULT_OFF=y

# Tracing programs need BPF_EVENTS, which needs kprobe or uprobe events.
CONFIG_FTRACE=y
CONFIG_KPROBES=y
CONFIG_KPROBE_EVENTS=y
CONFIG_BPF_EVENTS=y

# fentry and BPF LSM attach through BPF trampolines, which patch the fentry
# call that the function tracer adds to every kernel function.
CONFIG_FUNCTION_TRACER=y
CONFIG_DYNAMIC_FTRACE=y
CONFIG_BPF_LSM=y
```

The default `CONFIG_LSM` list already ends in `bpf`, so no boot parameter is needed.
DWARF is only needed at build time. The shipped `vmlinux` can be stripped of it
(`strip --strip-debug` keeps `.BTF`), as the release debug kernel already is.

Two ways to ship it, in order of preference:

1. A new release kernel next to the default and debug ones (for example
   `vmlinux-ebpf.container`), selected with `kernel =` in the runtime configuration.
   Nothing changes for existing users.
2. Fold it into the default kernel, if the costs below are acceptable for everyone.

## Cost

Measured without `CONFIG_BPF_UNPRIV_DEFAULT_OFF`, which only sets a sysctl default,
on Kata 4.3.1's guest kernel (Linux 6.18.56), rebuilt with Kata's own
`build-kernel.sh` in Ubuntu 22.04 (gcc 11.4, the release toolchain). Our debug build
matches the released debug kernel section for section, so the pipeline is faithful.
Each variant is compared against the same pipeline without the fragment. The guests
are Cloud Hypervisor VMs with 1 vCPU and 2 GB, booting an initramfs, 10 boots each,
nested under WSL2 (L2). Nesting inflates absolute boot times, so the differences
matter more than the totals.

| | Kata config | + fragment | + fragment, no function tracer | Kata debug |
|---|---|---|---|---|
| Kernel image loaded in memory | 25.1 MB | 34.9 MB | 34.8 MB | 34.9 MB |
| of which BTF | 0 | 5.3 MB | 5.2 MB | 5.3 MB |
| Host memory per idle VM (VMM RSS) | 103.4 MB | 117.4 MB | 117.4 MB | 117.4 MB |
| Guest memory used after boot | 52.7 MB | 58.5 MB | 57.8 MB | 58.6 MB |
| VMM start to power-off | 82 ms | 137 ms | 124 ms | 138 ms |
| Kernel start to init | 30 ms | 85 ms | 70 ms | 90 ms |
| exec, open, connect loops, no BPF loaded | baseline | within 2% | within 2% | +2% |
| Active LSMs | capability, landlock, selinux | + bpf | same as Kata | same as Kata |

Where the boot time goes (`initcall_debug`):

- About 20 ms is the first `tracing_init_dentry()`, reached through
  `init_kprobe_trace`. That sets up tracefs and the trace event tree, which any BPF
  tracing support needs.
- About 7 ms is the function tracer allocating its table of 46,687 functions.
- The rest is spread over many initcalls.

Without the function tracer, the fragment still gives BTF, CO-RE and `tp_btf`
(process lifecycle events), but no fentry and no BPF LSM. That saves about 15 ms of
boot and 0.3 MB of text.

At run time, the kernel options cost nothing measurable while no BPF program is
attached. The cost of an observer depends on the observer. Ours (process, connect
and file-write events streamed to the host over vsock) adds 4 to 7% to tight exec,
open and connect loops on a single vCPU, which is a worst case.

## Security considerations

- **Today's Kata kernels allow unprivileged BPF.** Kata builds its config on top of
  `allnoconfig`, so `CONFIG_BPF_UNPRIV_DEFAULT_OFF` (default `y` in the kernel) is
  off and `kernel.unprivileged_bpf_disabled` starts at 0 in every Kata guest
  (checked on the 4.3.1 release kernel, we did not check whether guest images set
  the sysctl later). The fragment turns it back on. It is worth fixing in the default kernel whatever
  happens to the rest of this proposal.
- With it on, loading BPF programs needs `CAP_BPF` or `CAP_SYS_ADMIN` in the guest.
  Only guest root, which Kata already treats as untrusted, gains anything, and the
  VM boundary still protects the host.
- `CONFIG_BPF_JIT_ALWAYS_ON` removes the BPF interpreter, a known Spectre gadget.
- BPF LSM lets a guest agent enforce policy that guest userspace cannot bypass. It
  can also protect the agent's own programs from being detached.
- The added attack surface is inside the guest kernel: the BPF verifier and JIT,
  and kprobes. That is the same surface every BPF-enabled host kernel has.

## Alternatives considered

- **Host-side eBPF:** cannot see inside the guest.
- **A sidecar in the pod:** Tetragon reported no events this way, and the default
  guest kernel cannot load its programs.
- **The debug kernel:** no BPF LSM, plus debugging extras. It is meant for
  debugging, not production.
- **kprobes without BTF:** no CO-RE, so programs break with every kernel update and
  cannot enforce.
- **A custom kernel per user:** what happens today. It drifts and duplicates work.

## Open questions

- A separate kernel variant, or the default?
- BTF is the largest cost (5.3 MB per VM). Can it be trimmed, for example by
  building fewer subsystems into Kata's kernel?
- The tracefs setup cost is an upstream kernel matter. Is there appetite to make
  it lazy?
- arm64 and s390x: the same fragment should work, but it is untested.
