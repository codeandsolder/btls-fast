//! Shared TLS benchmark implementation.

mod rustls_benchmark;
mod support;

pub use support::{BenchTarget, BoxError, Clock, Direction, Transport, bench, criterion};
