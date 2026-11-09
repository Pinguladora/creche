# 0009. The host attests the sandbox

- Status: Accepted
- Date: 2026-11-09

## Context

creche output is meant for an audit trail, so attribution must not be forgeable.
The guest is untrusted ([0001](0001-observe-inside-the-guest.md)), and a
connection's sandbox is named by the socket it arrives on
([0005](0005-hybrid-vsock-transport.md)). The sink named a connection's sandbox after the directory its socket sits in, but
never checked who connected. Any host process able to reach
`/run/vc/vm/<id>/clh.sock_7000` could inject events under that sandbox's id.

## Decision

Separate what the host attests from what the guest claims.

- Attested by the host: the sandbox id, and later the pod it belongs to, and the
  host clock in `observed_time_unix_nano`. The sink accepts a connection only from
  the process holding that sandbox's listening vsock socket, checked through the
  peer's credentials and its `/proc` entries, matched by device and inode. Each
  socket is mode 0600 and owned by the VMM's user. Sandbox ids must be containerd
  identifiers. Each sandbox gets at most 4 connections.
- Claimed by the guest: everything inside the stream, including pids, paths and
  the cgroup that names a container. A compromised guest can lie about these.
  Fields derived from them stay distinguishable from attested ones.

## Alternatives

- Trusting socket permissions alone: any process running as the VMM's user, or a
  wrong umask, gets in.
- Authenticating the guest with a secret: the guest is the untrusted party, and a
  secret inside it proves nothing about which VM sent the data.

## Consequences

The sink must run as root or as the VMM's user to read the VMM's `/proc` entries.
Root on the host can still forge, since it can ptrace the VMM. Refusals are logged
but not part of the output, and nothing yet lets a reader of the output detect
lines removed or reordered after the sink wrote them.
