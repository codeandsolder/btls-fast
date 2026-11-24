//! Shared TLS benchmark implementation.

mod rustls_benchmark;
mod support;

pub use support::{bench, criterion, BenchTarget, BoxError, Clock, Direction, Transport};
