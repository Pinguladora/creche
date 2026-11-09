# 0005. Hybrid vsock to a host sink

- Status: Accepted
- Date: 2026-11-09

## Context

The guest sends raw records ([0004](0004-records-are-the-wire-format.md)), and
they must reach a host decoder. Events must leave the guest without depending on the pod's network, which the
workload controls and which may be absent or locked down.

## Decision

The observer connects to vsock port 7000. Cloud Hypervisor and Firecracker use
hybrid vsock: a guest connection to port P arrives on the host as a connection to
the unix socket `<sandbox dir>/clh.sock_P`. One host daemon, `creche-sink`,
watches `/run/vc/vm` and listens in every sandbox directory, so the directory
names the sandbox.

## Alternatives

- The pod network: controlled by the workload and absent in some sandboxes.
- A file on a shared virtio-fs mount: more host machinery and no back pressure.
- A channel through kata-agent: ties creche to the agent's protocol and release
  cycle.

## Consequences

No guest network configuration and no kata-agent changes. Each vsock packet is a
VM exit (the virtio doorbell), so sends must be batched. The sandbox identity
comes from which socket a connection arrives on, which the guest cannot choose.
QEMU uses native vsock instead and would need its own listener.
