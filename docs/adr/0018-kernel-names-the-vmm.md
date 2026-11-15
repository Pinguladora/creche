# 0018. The kernel names the VMM

- Status: Accepted
- Date: 2026-11-15

## Context

The sink accepts a connection only from the sandbox's VMM
([0009](0009-host-attests-the-sandbox.md)), the process listening on the
sandbox's vsock socket `clh.sock`. It found that process in the peer's
`/proc/<pid>/net/unix`: the peer had to hold a listening socket whose bound path
resolved, by device and inode, to `clh.sock`.

A bound path there is only the name the socket was bound under, as the binder
gave it. The binder can unlink that name and put a symlink to another sandbox's
`clh.sock` in its place, or a hardlink when it owns that file, or bind under the
very same path in a mount namespace of its own. Any process running as the
VMM's user, the VMM of another sandbox included, could so pass as the VMM of any
sandbox and inject events under its id.

## Decision

The sink asks the kernel who listens. Once `clh.sock` exists, it connects to it
and reads the credentials the connection carries, which are those of the process
that called `listen` on it. That process is the sandbox's VMM. The sink closes
the connection without sending anything, and pins the VMM by its pid and its
start time from `/proc/<pid>/stat`, so a process that later reuses the pid is
not taken for it. It connects again after reading the start time and expects
the same pid, so the start time cannot be that of a process that took the pid
while it was read.

A connection to `clh.sock_P` is accepted only when its credentials name that
same process: the same user, the same pid and the same start time. No path is
read back from `/proc`. The sink still restricts `clh.sock_P` to mode 0600,
owned by the VMM's user and group as the credentials report them.

## Alternatives

- Checking bound paths more strictly, by comparing them to the expected path or
  resolving them in the peer's root: a hardlink or a private mount namespace
  still gives a matching name.
- The kernel's socket diagnostics, which report the inode a socket is bound to:
  they only see the caller's network namespace, and the VMM runs in the pod's.

## Consequences

The VMM sees two connections from the sink per sandbox that end before they
send anything. A sandbox whose `clh.sock` exists but has no listener yet gets no
listener of its own until it has one. Taking over the VMM process itself, by
ptrace as its user or as root, still passes, as before.
