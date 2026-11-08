//! The parts of creche-observer that run without a kernel: the forwarding queue,
//! exposed as a library so it can be benchmarked. The binary in `main.rs` loads
//! the BPF programs and drives the queue.

pub mod queue;
