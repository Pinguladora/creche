# 0010. The pod comes from the container runtime's bundle

- Status: Accepted
- Date: 2026-11-09

## Context

An audit trail needs to say which pod did what, and the sandbox id alone does not
name a pod. The host attests the sandbox id
([0009](0009-host-attests-the-sandbox.md)), so the pod must come from a host
source keyed by that id, never from the guest. Whatever names the pod must be out
of reach of the pod's author.

## Decision

When a connection is accepted, the sink reads the sandbox's OCI spec,
`<bundles>/<sandbox id>/config.json`, which containerd writes in a bundle
directory only root can enter. It takes `io.kubernetes.cri.sandbox-name`,
`-namespace` and `-uid` and adds them to every line as `k8s.pod.name`,
`k8s.namespace.name` and `k8s.pod.uid`.

The spec is used only when the bundle directory is owned by root and private to
it, the spec is a root-owned regular file of at most 1 MiB, its
`io.kubernetes.cri.container-type` is `sandbox` and its
`io.kubernetes.cri.sandbox-id` is the attested id. Otherwise every line carries
`creche.k8s.unresolved` with the reason, and nothing is guessed. The spec is read
once per connection, so a stream's pod cannot change while it runs.

The spec is parsed with miniserde, which keeps its parser state on the heap and
cannot overflow the stack however deep the nesting.

## Alternatives

- The CRI API (`PodSandboxStatus` on containerd's socket): the same source of
  truth, but a gRPC stack in the sink for one call per connection.
- The Kubernetes API: needs credentials on every node and adds the API server to
  what must be trusted, while the runtime already holds the answer locally.
- Pod annotations or labels sent by the guest: forgeable by the workload.
- serde_json or nanoserde for parsing: serde is a large dependency for one small
  struct, and nanoserde parses recursively.

## Consequences

The pod is as trustworthy as kubelet and the runtime's socket. A pod author cannot
forge it: containerd's CRI plugin writes its own annotations after the pod
annotations it passes through, so a passed-through key of the same name is
overwritten. This holds in containerd 2.4.2, but containerd has no explicit check
for reserved keys, so the guarantee rests on that order. CRI-O deletes its
reserved keys from pod annotations, keeps its bundles elsewhere and uses other
annotation names, so it needs its own reader. Kata without Kubernetes runs with
the lookup turned off. Which container in the pod an event came from is still only
the guest's claim, since root in the guest can move a process between cgroups.
