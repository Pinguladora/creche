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
guest sends process execs, forks and exits, file writes and connects.

## Alternatives

- Host side tools: they cannot see into the VM.
- A sidecar container: it lives in the same guest but in a pod's namespaces, and
  without BTF and the JIT in the guest kernel nothing modern loads.
- Auditd or ptrace in the guest: far more overhead per event and no kernel side
  filtering.
- Hypervisor introspection: tied to one VMM and to guest kernel internals, and
  it must reconstruct processes from memory.

## Consequences

creche needs a guest kernel with BTF, the BPF JIT and tracing support. The guest
is untrusted, so everything it sends is a claim, never a fact, and the host must
survive any bytes it sends. The observer's cost lands inside the sandbox, so
overhead per event is the main engineering constraint.
