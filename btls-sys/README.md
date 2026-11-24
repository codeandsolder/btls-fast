# Low-level bindings to BoringSSL

[BoringSSL](https://boringssl.googlesource.com/boringssl) is Google's fork of OpenSSL for Chrome/Chromium and Android.

This crate builds the BoringSSL library (or optionally links a pre-built version) and generates FFI bindings for it.
It supports [FIPS-compatible builds of BoringSSL](https://boringssl.googlesource.com/boringssl/+/master/crypto/fipsmodule/FIPS.md),
as well as [Post-Quantum crypto](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/)
and [Raw Public Key](https://docs.rs/btls/latest/btls/ssl/struct.SslRef.html#method.peer_pubkey) extensions.

To use BoringSSL from Rust, prefer the [higher-level safe API](https://docs.rs/btls).

## Native source inputs

For a Git checkout, initialize the vendored source before building with
`git submodule update --init --recursive`. The build does not fetch it.
Cargo tracks the native source, headers, and patch inputs for rebuilds.
A caller-provided `BORING_BSSL{,_FIPS}_SOURCE_PATH` must already contain the
required patches and be accompanied by `BORING_BSSL{,_FIPS}_ASSUME_PATCHED`.
The build never applies patches to caller-owned sources.

## Speeding up the build

Compiling BoringSSL from source is by far the most expensive part of building
this crate. The build script applies accelerations automatically:

- **Compiler caching.** `RUSTC_WRAPPER` only caches `rustc`, so the ~370
  BoringSSL translation units are recompiled on every clean build even when
  [`sccache`](https://github.com/mozilla/sccache) or
  [`ccache`](https://ccache.dev/) is configured.  
  If `RUSTC_WRAPPER`/`RUSTC_WORKSPACE_WRAPPER` points at `sccache` or
  `ccache` it is reused as-is; otherwise set `BORING_BSSL_COMPILER_LAUNCHER`
  explicitly:

  ```sh
  # Reuse an existing sccache automatically:
  export RUSTC_WRAPPER=sccache

  # ...or point the BoringSSL build at a cache explicitly:
  export BORING_BSSL_COMPILER_LAUNCHER=sccache
  ```

## Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed under the terms of both the Apache License,
Version 2.0 and the MIT license without any additional terms or conditions.
