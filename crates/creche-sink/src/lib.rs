//! creche-sink as a library: decoding record streams into JSON lines and
//! listening on every sandbox's socket. The binary in `main.rs` is the command
//! line around it, and the benchmarks use it directly.
//!
//! Memory profile: allocation-conscious. Per connection, one read buffer, at
//! most one incomplete record and the lines one read renders to. Lines waiting
//! for the writer, and for the OTLP exporter, are bounded in bytes.

pub mod audit;
pub mod json;
pub mod k8s;
pub mod listen;
pub mod otlp;
pub mod peer;
pub mod spiffe;
pub mod stream;
pub mod tasks;
