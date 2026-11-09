# 0001. Observe from inside the guest with eBPF

- Status: Accepted
- Date: 2026-11-09

## Context

Kata runs each pod in a microVM, which is the point: untrusted code, AI agents
among it, gets its own kernel. That same boundary blinds host side security
tools. For a Kata pod, Tetragon or Falco on the host see `cloud-hypervisor` and
`virtiofsd`, not the processes in the guest. A Tetragon sidecar inside the pod
reported no events, and on Kata's default guest kernel its programs cannot load.
See the motivation in [the Kata proposal](../kata-guest-ebpf-proposal.md).

## Decision

Observe with eBPF in the guest kernel, from a small daemon (`creche-observer`)
started from the guest image before kata-agent, and decode on the host. The
guest sends process execs, forks and exits, opens of files for writing, and
connects. It does not report each write, so writes through a descriptor opened
before the observer started, or inherited, leave no file event. Opens of
character devices, FIFOs and sockets are left out, and so are opens on a fixed
list of kernel filesystems (proc, sysfs, cgroup, debugfs, tracefs, bpf,
securityfs, devpts and a few more). Other filesystems, tmpfs among them, are
reported. With dedup on, repeated opens of a file by one process within a second
are reported once. No event is therefore no proof that nothing was opened.

## Alternatives

- Host side tools: they cannot see into the VM.
- A sidecar container: it lives in the same guest but in the pod's namespaces.
  Tetragon there reported no events, and on Kata's default kernel, which has no
  BTF, CO-RE programs cannot load. That kernel lacks the tracing support kprobe
  programs need too, so even a privileged sidecar with simpler programs needs
  another guest kernel, and it gives up the portability CO-RE brings.
- Auditd in the guest: the kernel filters by rule, but formats every matching
  event as a text record and sends it to a daemon, so each event costs a record
  that repeats the process context.
- Ptrace in the guest: it stops the traced process at every event.
- Hypervisor introspection: tied to one VMM and to guest kernel internals, and
  it must reconstruct processes from memory.

## Consequences

creche needs a guest kernel with BTF, the BPF JIT and tracing support. The guest
is untrusted, so everything it sends is a claim, never a fact, and the host must
survive any bytes it sends. The observer's cost lands inside the sandbox, so
overhead per event is the main engineering constraint.
