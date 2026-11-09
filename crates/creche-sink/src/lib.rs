//! creche-sink as a library: decoding record streams into JSON lines and
//! listening on every sandbox's socket. The binary in `main.rs` is the command
//! line around it, and the benchmarks use it directly.
//!
//! Memory profile: allocation-conscious. Per connection, one read buffer plus
//! at most one incomplete record. Output batches are bounded by a channel.

pub mod audit;
pub mod json;
pub mod k8s;
pub mod listen;
pub mod otlp;
pub mod peer;
pub mod stream;
pub mod tasks;
