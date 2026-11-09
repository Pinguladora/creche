//! The parts of creche-observer that run without its BPF programs: the
//! forwarding queue, exposed as a library so it can be benchmarked, and the
//! cgroup descriptions. The binary in `main.rs` loads the BPF programs and
//! drives both.

pub mod cgroups;
pub mod queue;
