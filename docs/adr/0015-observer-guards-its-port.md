# 0015. The observer guards its vsock port with BPF LSM

- Status: Accepted
- Date: 2026-11-09

## Context

The host attests which VM a connection comes from
([0009](0009-host-attests-the-sandbox.md)), but not which process in the guest
opened it. Any guest process able to create a vsock socket could connect to the
observer's port and send records the host takes for the observer's, so the
fields observed by the guest kernel could be forged by any workload
([0011](0011-identity-within-a-pod.md)). The guest kernel already has BPF LSM
([0002](0002-guest-kernel.md)).

## Decision

The observer attaches a BPF LSM program to `socket_connect` that refuses a vsock
connection to the host on the observer's port from every process but the
observer, whose process id and port are set before the program loads.

An LSM program attaches even when BPF LSM is not among the kernel's active
LSMs, and then never runs. So the guard counts the connections to its port it
sees, and after connecting the observer checks that the guard saw its own. It
reports the result in its hello record, which the sink writes as
`creche.observer.guarded`. On a kernel without BPF LSM the observer still runs,
and every stream it sends says it is unguarded.

## Alternatives

- Authenticating the observer to the host with a secret: the secret would have
  to live in the guest, where the processes it must be kept from also run, and
  it would need provisioning per VM.
- Accepting only the first connection of each VM, which is the observer's since
  it starts before any workload: a restarted observer could no longer connect.
- A seccomp profile refusing vsock sockets to containers: it depends on every
  pod's security settings, and processes outside containers stay free.
- A cgroup BPF hook on connect: it covers only IPv4 and IPv6 addresses, not
  vsock.

## Consequences

Guest kernel fields hold against workloads that cannot load BPF programs or take
over the observer, root in a container included, on kernels with BPF LSM. A
process that can load or detach BPF programs, or replace the observer, can still
forge them. Between an observer's exit and its restart the port is unguarded.
The check needs no securityfs in the guest.
