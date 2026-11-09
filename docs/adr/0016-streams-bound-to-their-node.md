# 0016. Streams are bound to the node their sandbox ran on

- Status: Accepted
- Date: 2026-11-09

## Context

A verifier checks that a stream was signed by one of the sinks it expects
([0014](0014-signed-checkpoints.md)). Every node runs a sink, so the set holds
all of them, and a sink on one node could sign a stream for a sandbox that ran on
another. Whoever takes over one node could then forge the audit trail of every
sandbox in the cluster. Which pod a stream belongs to is attested by the host
([0009](0009-host-attests-the-sandbox.md), [0010](0010-pod-from-the-runtime-bundle.md)),
but which node it ran on is not in the output, and the sink is the one under
check, so its word is not enough.

## Decision

Each node's sink has a SPIFFE ID that names its node, registered with the node's
own SPIRE agent as parent, so no other node can be issued it. The verifier takes
the node of each sandbox from outside the sink's output, from the cluster's pod
history: lines of a pod uid, or a sandbox id when there is no pod, and a node
name. The expected sink IDs are templates holding `{node}`. A stream must be
signed by the template filled in with the node its pod or sandbox ran on, and a
stream whose sandbox is missing from the history fails.

## Alternatives

- The sink writing its node name into each stream: the sink is what is being
  checked, so it could write any node.
- A file mapping each pod straight to a SPIFFE ID: the same check, with the ID
  repeated on every line and the naming convention left to each operator.
- No binding, the expected set alone: any node can forge any sandbox's stream.

## Consequences

Taking over one node lets an attacker sign streams only for the sandboxes the
history places on that node. Verifying needs a pod history that covers the
streams, kept as long as the output, and node names that are DNS subdomains so
they fit a SPIFFE ID path. The sink does not change. Sink registrations that
match several agents, through a shared node selector, undo the binding.
