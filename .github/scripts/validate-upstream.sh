#!/usr/bin/env bash
set -euo pipefail
git submodule update --init --recursive
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets --features mldsa,mlkem,prf,rpk,underscore-wildcards,relax-cert-validation
cargo test --locked -p btls -p btls-sys -p tokio-btls --features mldsa,mlkem,prf,rpk,underscore-wildcards,relax-cert-validation
cargo doc --locked --no-deps -p btls -p btls-sys -p tokio-btls --features mldsa,mlkem,prf,rpk,underscore-wildcards,relax-cert-validation
