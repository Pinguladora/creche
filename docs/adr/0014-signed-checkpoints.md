# 0014. Checkpoints signed with a ratchet anchored to a SPIFFE SVID

- Status: Proposed
- Date: 2026-11-09

## Context

A hash chain shows changed or missing lines only while its checkpoints are kept
out of reach ([0012](0012-audit-chain.md)). Whoever can rewrite the archive can
recompute every hash. The output should also prove which sink wrote a stream,
without key files to provision and rotate on every node, and a later compromise
of the sink must not let anyone rewrite what was already sealed.

## Decision

Each stream starts with a fresh P-256 key from the system's random source. The
sink's X.509-SVID, from the SPIFFE Workload API on a local socket, signs the
stream's first public key on its start line, next to the SVID chain. Each
checkpoint is signed by the stream's current key and names the next key, derived
from the current one and the checkpoint hash by SHA-256, which cannot be run
backwards, and the current key is then erased.

A verifier checks the SVID against a SPIFFE trust bundle as of the stream's
start, that its SPIFFE ID is one of the sinks it expects, the first key's
signature, then every checkpoint's signature in turn. Any workload in the trust
domain has an SVID, so the expected sink IDs are required.

## Alternatives

- A key file per node: a long-lived secret on every node, and stealing it lets
  anyone sign anything, past streams included.
- The SVID signing every checkpoint: whoever holds the SVID later can sign past
  data again, so nothing is sealed.
- Keyless signing with Fulcio and Rekor from the sink: TLS and internet access on
  every node, an OIDC issuer Fulcio trusts, and a transparency log entry per
  checkpoint. A public, timestamped anchor stays useful, but off the node and
  for periodic checkpoint heads.
- Ed25519 for the stream keys: its implementation's licence falls outside the
  project's allowed list, and P-256 is the curve SPIRE issues anyway.

## Consequences

The sink holds no key of its own, and SPIRE attests and rotates its identity.
Taking over the sink yields only the current stream keys, so checkpoints signed
before are sealed. Lines after the last checkpoint, at most about a second of a
stream, are not. Whoever steals an SVID key can fabricate whole new streams in an
archive copy, backdated to any time the SVID was valid, even after it expired.
Copies already exported elsewhere expose them, and a trusted timestamp, such as a
transparency log entry, would bound them. Only
P-256 SVIDs, SPIRE's default, are supported. A stream started before the agent
handed over an SVID is not signed, and a verifier with a bundle reports it.
