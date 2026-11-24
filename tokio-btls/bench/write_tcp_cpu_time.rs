//! Benchmarks TLS client writes over loopback TCP in client thread CPU time.

use tokio_btls_bench as support;

use criterion::{Criterion, criterion_group, criterion_main};
use support::{BenchTarget, Clock, Direction, Transport};

/// Target dimensions for the loopback TCP CPU-time write benchmark.
const TARGET: BenchTarget = BenchTarget {
    direction: Direction::Write,
    transport: Transport::Tcp,
    clock: Clock::Cpu,
};

/// Runs the full body matrix for this target.
///
/// Panics if a case fails to configure, execute, or verify its data.
fn benchmark(c: &mut Criterion) {
    support::bench(c, TARGET).expect("failed to run loopback TCP CPU-time write benchmark");
}

criterion_group!(
    name = benches;
    config = support::criterion();
    targets = benchmark
);
criterion_main!(benches);
