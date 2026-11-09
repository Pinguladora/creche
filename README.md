# creche

Visibility into what runs inside Kata Containers microVMs: process trees, outgoing
connections and file writes of the tools an AI agent spawns, streamed to the host.

Host-side tools (Tetragon, Falco) cannot see inside a microVM: the guest runs its
own kernel. creche puts a small eBPF observer in the guest and forwards its events
to the host over vsock, where they are decoded and attributed to the sandbox.

## Components

| Crate | Runs | Does |
|---|---|---|
| `creche-observer` | in the guest, from the Kata guest image, before kata-agent | loads the BPF programs (aya), forwards their records over vsock, reports its own cost |
| `creche-sink` | on the host | listens on every sandbox's hybrid vsock socket, writes the events as JSON lines or as raw framed records |
| `creche-wire` | both | the wire format and a bounds-checked, zero-copy decoder (`no_std`) |

The BPF programs (`crates/creche-observer/bpf/`) are C compiled by clang: Rust BPF
programs cannot carry CO-RE relocations, and those let one binary run on any guest
kernel with BTF. They use a minimal header instead of libbpf or a generated
`vmlinux.h`. Everything that parses data is Rust.

## Design

- **The BPF records are the wire format.** The guest copies ring buffer records to
  the socket as they are. All decoding happens on the host.
- **Noise is dropped in the kernel**, before any copy: writes to pseudo filesystems,
  pipes, sockets and character devices never reach the ring buffer.
- **Context once, not per record.** Records carry only the pid and a timestamp in
  a 16-byte header. A process's parent, uid, cgroup and name go in a task record,
  sent only when they change (tracked in a pid-indexed cache in the kernel, with
  no allocation per process). Exec records carry the new context themselves.
  Forks hand the
  parent's context to the child, and an epoch counter makes every process resend
  it after a reconnect or a drop. The sink keeps the context per pid and adds it to
  every JSON line.
- **One wakeup per batch.** The kernel wakes the observer only for the first record
  after a drain. The observer drains at most once per 20 ms: right away when the
  last drain was longer ago, so sparse events arrive without delay, otherwise at
  the end of the window, so a burst costs one wakeup. Each wakeup is an interrupt,
  a timer and a vsock doorbell, all VM exits. Idle, it sleeps until the 5 s
  heartbeat.
- **Whole records only.** The forwarding queue is bounded and never splits a record
  across connections. Heartbeats report drops so silence can be told from blindness.
- **The host attests the sandbox.** Each sandbox's socket is mode 0600, owned by
  its VMM's user, and the sink accepts only the process holding that sandbox's
  listening vsock socket, checked through the peer's credentials and `/proc`.
  The sandbox id on every line comes from the host, never from the guest. What
  the guest reports inside the stream is the guest's claim. Sandbox ids must be
  containerd identifiers, and each sandbox gets at most 4 connections.
- **The host names the pod.** When a connection is accepted, the sink reads the
  sandbox's OCI spec from containerd's root-only bundle directory and takes the
  pod's name, namespace and uid from the annotations containerd sets from
  kubelet's request. The spec must name the same sandbox and be a sandbox's, and
  the bundle must be private to root or the sink's user. Otherwise every line says
  why the pod is unknown, and nothing is guessed.
- **The container is the guest's claim, checked.** A process's guest cgroup
  (`cri-containerd-<id>.scope`) claims a container. The sink reports it as
  `creche.guest.container.*` only when that id is a container of the same pod in
  the runtime's bundles, so a guest cannot point at another pod. Root in the
  guest can still move a process between its own pod's containers.
- **Layout guard.** `build.rs` generates C static assertions from `creche-wire`'s
  layout, so a wire struct mismatch between C and Rust fails the build.

## Guest kernel requirements

BTF (`CONFIG_DEBUG_INFO_BTF`), BPF JIT, tracepoints and, for connect and file-write
events, fentry (`CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS`). Kata's default guest
kernel has none of these, but its debug kernel has all of them. Without fentry the
observer falls back to process events only.

[`kernel/kata-guest-ebpf.conf`](kernel/kata-guest-ebpf.conf) is the minimum as a
Kata config fragment, BPF LSM included (Kata's debug kernel has no BPF LSM). Built
into Kata 4.3.1's guest kernel (Linux 6.18.56) with Kata's own `build-kernel.sh`,
measured at L2 against the same pipeline without it:

| | Kata config | with the fragment |
|---|---|---|
| Kernel image loaded in guest memory | 25.1 MB | 34.9 MB (5.3 MB of it BTF) |
| Host memory per idle VM (VMM RSS, 2 GB guest) | 103 MB | 117 MB |
| Boot to init | 30 ms | 85 ms |
| exec, open, connect without an observer | baseline | within 2% (noise) |

About 20 ms of the boot cost is tracefs and trace event setup, which BPF tracing
programs depend on, and 7 ms is the function tracer's table of 46,687 functions.
Without the function tracer (no fentry, no BPF LSM) boot to init is 70 ms.

[`docs/kata-guest-ebpf-proposal.md`](docs/kata-guest-ebpf-proposal.md) proposes it to Kata.

## Building

Requirements: [mise](https://mise.jdx.dev) (installs Rust, the musl target and the
tools below), clang, and the kernel UAPI headers (`linux/bpf.h`).

```sh
mise install
cargo build --release -p creche-sink
cargo build --release -p creche-observer --target x86_64-unknown-linux-musl   # static, for the guest image
```

## Checks

```sh
mise run test      # unit, property and doc tests, then again with release-assertions
mise run mutants   # mutation testing
mise run bench     # criterion: wire decoding, observer queue, sink rendering
hk check           # all linters (fmt, clippy, cargo-deny, YAML, Actions, ...)
```

## Running

```sh
creche-sink                     # on the host, as root or the VMM's user: listens for every sandbox under /run/vc/vm
creche-observer                 # in the guest (systemd unit before kata-agent)
creche-observer --stdout | creche-sink -f -    # local capture and decode
creche-sink -o raw              # the records unchanged, in frames naming their sandbox
creche-sink -b /run/k3s/containerd/io.containerd.runtime.v2.task/k8s.io   # k3s keeps containerd's state here
creche-sink --no-pods           # Kata without Kubernetes: no pod lookup
creche-sink --verify out.jsonl  # check the audit chains in saved output
creche-sink --otlp http://127.0.0.1:4317 > archive.jsonl   # export to a node collector, keep an archive
```

## Output

creche runs inside the microVM, where host tools such as Tetragon, Falco or
KubeArmor cannot see. It is meant to sit next to them, so its output is shaped for
the pipelines they already feed.

- **JSON lines** (default): one object per event, read by any log shipper (an
  OpenTelemetry collector's file log receiver, fluentd, Vector). Attribute names
  follow the OpenTelemetry semantic conventions where one exists:
  `process.pid`, `process.parent_pid`, `process.real_user.id`,
  `process.executable.name`, `process.executable.path`, `process.command_args`
  (an array), `process.exit.code`, `file.path`, `destination.address`,
  `destination.port`, `network.type`, `network.transport`, and
  `k8s.pod.name`, `k8s.namespace.name` and `k8s.pod.uid` for sandboxes that are
  pods. The rest are in the
  `creche.` namespace: `creche.sandbox.id`, `creche.k8s.unresolved` (why a
  sandbox's pod is unknown), `creche.guest.container.id` and
  `creche.guest.container.name` (the container the guest claims, confirmed to be
  in the pod), `creche.cgroup.id`,
  `creche.cgroup.name`, `creche.boot_time_ns` (the guest's boot-time clock) and
  the observer's own figures. Event names (`event.name`) are `creche.process.exec`,
  `creche.process.fork`, `creche.process.exit`, `creche.network.connect`,
  `creche.file.open_write`, `creche.observer.hello` and
  `creche.observer.heartbeat`. `observed_time_unix_nano` is the host's clock when
  the event arrived: the guest only knows its own boot time.
- **Audit trail** (JSON only): each connection is a stream with its own
  `creche.stream.id`, opened by a `creche.stream.start` line naming the peer
  (`creche.peer.pid`, `creche.peer.uid`) and closed by `creche.stream.end` with
  `creche.stream.end_reason` (`closed`, `read_error` or `corrupt`). Every line of a
  stream has `creche.seq`, counting from 0. A `creche.audit.checkpoint` line
  follows once 256 lines or a second have passed and when the stream ends. It
  covers `creche.seq.first` to `creche.seq.last` with
  `creche.audit.hash = SHA-256(creche.audit.prev || the exact bytes of those lines)`,
  starting from 32 zero bytes. A missing line shows as a gap in `creche.seq`, a
  changed one as a mismatched hash. `creche-sink --verify FILE` checks saved
  output. Refused connections are `creche.sink.refused` lines, outside any stream,
  with the peer and `creche.sink.refusal`. The chain proves integrity only as far
  as its checkpoints are kept out of reach, for example shipped to a second store.
- **OpenTelemetry logs** (`--otlp URL`, with JSON output): the same lines,
  also exported to a collector as OTLP over gRPC (`--otlp-protocol grpc`, the
  default, port 4317) or OTLP/HTTP (`--otlp-protocol http`, port 4318), protobuf
  compressed with zstd, in cleartext to a collector on the node. Each line is one
  log record whose body is the line's exact text and whose `eventName` is the
  line's `event.name`. The stream's sandbox, pod and stream id are the resource.
  A collector can parse the body into attributes, and the bodies, each followed
  by a newline, still pass `--verify`. The exporter never holds up stdout: when it
  falls behind, lines are dropped from the export only, counted on stderr, and
  show as gaps in `creche.seq` downstream.
- **Raw** (`-o raw`): the validated wire records unchanged, for consumers that
  decode the creche format themselves (`creche-wire`). Each frame is a
  native-endian `u16` length and the sandbox id, then a native-endian `u32` length
  and that many bytes of whole records. Task records are included, so a consumer
  can track process context itself. Frames name the sandbox, not its pod.

## Working with coding agents

The repository ships the integrations of the tools it already uses:

- `.mcp.json` registers the MCP servers of hk (`hk mcp`, plans and runs the
  checks) and mise (`mise mcp`, tools, tasks and config). The mise server also
  exposes environment variables, secrets included.
- `hk agent hooks --target claude-code` prints a Stop hook for local agent
  settings, so an agent's edits are checked the same way a commit would be.
- `AGENTS.md` holds the project rules for agents.

Builds go through mr-boxington (`mr_boxington = true` in `mise.toml`), which
shares compiled dependencies across checkouts. `mbx stats` and `mbx analyze` show
what it saved and what still compiles from scratch.

## References

Prior work on visibility and enforcement inside VM sandboxes:

- Ant Group, Kata Containers and eBPF for container workload protection
  (AntCWPP): [Kata Containers whitepaper](https://katacontainers.io/collateral/kata-containers-ant-group-cwpp-ebpf_whitepaper.pdf),
  [Linux Foundation case study](https://www.linuxfoundation.org/hubfs/eBPF/eBPF%20Ant%20Group%20Case%20Study.pdf),
  [eBPF Foundation article](https://ebpf.foundation/ant-group-secures-their-platform-with-kata-containers-and-ebpf-for-fine-grained-control/).
  A host agent loads eBPF programs into every Kata guest and delivers policy as
  map updates. Not open source.
- [eBPF-PATROL: Protective Agent for Threat Recognition and Overreach Limitation
  using eBPF in Containerized and Virtualized Environments](https://arxiv.org/abs/2511.18155)
  (arXiv 2511.18155).
- [gVisor runtime monitoring](https://gvisor.dev/docs/user_guide/runtimemonitor/),
  the same goal for a user space kernel: the sandbox streams syscall events to
  an external monitor.
- [OpenTelemetry eBPF Instrumentation issue 3210](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/3210),
  a proposal for process and I/O visibility in sandboxed AI agent workloads.

Building blocks:

- [Kata Containers vsock design](https://github.com/kata-containers/kata-containers/blob/main/docs/design/VSocks.md),
  including the hybrid vsock used by Cloud Hypervisor and Firecracker.
- [aya](https://aya-rs.dev/), the pure Rust eBPF loader.
- Cloudflare's eBPF replatforming series:
  [part 2](https://ebpf.io/blog/cloudflare-replatforming-2/) on BPF LSM, including
  LSM programs that stop the policy programs from being disabled,
  [part 4](https://ebpf.io/blog/cloudflare-replatforming-4/) on BPF JIT memory
  exhaustion making program loads fail silently, and
  [part 5](https://ebpf.io/blog/cloudflare-replatforming-5/) on atomic program
  upgrades with `bpf_link`, pinned state and staged rollouts.
