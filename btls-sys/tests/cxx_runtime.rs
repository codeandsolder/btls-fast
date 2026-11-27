#[path = "../build/cxx_runtime.rs"]
mod cxx_runtime;

use cxx_runtime::{Toolchain, resolve};
use std::{
    fs, io,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        loop {
            let path = std::env::temp_dir().join(format!(
                "btls-cxx-runtime-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (),
                Err(error) => return Err(error),
            }
        }
    }

    fn archive(&self, name: &str) -> io::Result<PathBuf> {
        let path = self.0.join(format!("lib{name}.a"));
        fs::write(&path, b"!<arch>\n")?;
        Ok(path)
    }

    fn compiler(&self, libraries: &[&str]) -> Toolchain {
        Toolchain {
            libraries: libraries.iter().map(|name| (*name).into()).collect(),
            directories: vec![self.0.clone()],
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn compiler_not_target_or_host_selects_runtime() -> io::Result<()> {
    let fixture = Fixture::new()?;
    let gnu = fixture.archive("stdc++")?;
    let llvm = fixture.archive("c++")?;
    let abi = fixture.archive("c++abi")?;
    let unwind = fixture.archive("unwind")?;
    assert_eq!(
        resolve(
            Some(&fixture.compiler(&["stdc++", "m", "gcc_s"])),
            &[],
            None
        )?,
        [gnu]
    );
    assert_eq!(
        resolve(Some(&fixture.compiler(&["c++", "unwind"])), &[], None)?,
        [llvm, abi, unwind]
    );
    assert!(resolve(Some(&fixture.compiler(&["stdc++"])), &[], Some("c++")).is_err());
    assert_eq!(
        cxx_runtime::dynamic_name(&fixture.compiler(&["/target/lib/libc++.so.1"]))?,
        "c++"
    );
    assert_eq!(
        cxx_runtime::dynamic_name(&fixture.compiler(&["stdc++"]))?,
        "stdc++"
    );
    assert!(cxx_runtime::dynamic_name(&fixture.compiler(&["stdc++", "c++"])).is_err());
    Ok(())
}

#[test]
fn prebuilt_requires_supplied_matching_archive_and_rejects_ambiguity() -> io::Result<()> {
    let fixture = Fixture::new()?;
    let dirs = std::slice::from_ref(&fixture.0);
    assert!(resolve(None, dirs, None).is_err());
    let gnu = fixture.archive("stdc++")?;
    assert_eq!(resolve(None, dirs, None)?, [gnu.clone()]);
    fixture.archive("c++")?;
    assert!(resolve(None, dirs, None).is_err());
    assert_eq!(resolve(None, dirs, Some("stdc++"))?, [gnu]);
    Ok(())
}

#[test]
fn no_fallback_to_host_or_dynamic_library() -> io::Result<()> {
    let fixture = Fixture::new()?;
    fs::write(fixture.0.join("libstdc++.so"), [])?;
    assert!(resolve(Some(&fixture.compiler(&["stdc++"])), &[], None).is_err());
    assert!(resolve(Some(&fixture.compiler(&["c++"])), &[], None).is_err());
    let compiler = Toolchain {
        libraries: vec!["stdc++".into()],
        directories: vec![PathBuf::from("relative-host-directory")],
    };
    assert!(resolve(Some(&compiler), &[], None).is_err());
    Ok(())
}

#[test]
fn reads_cmake_file_api_and_bundles_only_selected_archive() -> io::Result<()> {
    let fixture = Fixture::new()?;
    cxx_runtime::request_toolchains(&fixture.0)?;
    assert!(
        fixture
            .0
            .join(".cmake/api/v1/query/toolchains-v1")
            .is_file()
    );
    let reply = fixture.0.join(".cmake/api/v1/reply");
    fs::create_dir_all(&reply)?;
    fs::write(
        reply.join("index-1.json"),
        r#"{"reply":{"toolchains-v1":{"jsonFile":"tools.json"}}}"#,
    )?;
    fs::write(
        reply.join("tools.json"),
        serde_json::to_vec(&serde_json::json!({"toolchains":[
            {"language":"C","compiler":{"implicit":{"linkLibraries":["c"],"linkDirectories":[]}}},
            {"language":"CXX","compiler":{"implicit":{"linkLibraries":["stdc++","gcc_s"],"linkDirectories":[fixture.0]}}}
        ]})).map_err(io::Error::other)?,
    )?;
    let runtime = fixture.archive("stdc++")?;
    let compiler = cxx_runtime::toolchain(&fixture.0)?;
    let selected = resolve(Some(&compiler), &[], None)?;
    assert_eq!(selected, [runtime.clone()]);
    cxx_runtime::emit(&fixture.0, &selected)?;
    assert_eq!(
        fs::read(fixture.0.join("cxx-runtime/libbtls_cxx_runtime_0.a"))?,
        fs::read(&runtime)?
    );
    let export = fixture.0.join("export");
    fs::create_dir(&export)?;
    cxx_runtime::export_archives(&export, &selected)?;
    assert_eq!(fs::read(export.join("libstdc++.a"))?, fs::read(&runtime)?);
    assert_eq!(
        resolve(None, std::slice::from_ref(&export), None)?,
        [export.join("libstdc++.a")]
    );
    fs::write(&runtime, b"INPUT(libstdc++.so)")?;
    assert!(cxx_runtime::emit(&fixture.0, &selected).is_err());
    Ok(())
}

#[test]
fn configure_identity_changes_invalidate_only_native_build() -> io::Result<()> {
    let fixture = Fixture::new()?;
    cxx_runtime::prepare_configure(&fixture.0, b"gcc")?;
    let build = fixture.0.join("build");
    cxx_runtime::request_toolchains(&build)?;
    let sentinel = build.join("compiled");
    fs::write(&sentinel, b"object")?;
    cxx_runtime::prepare_configure(&fixture.0, b"gcc")?;
    assert!(sentinel.exists());
    cxx_runtime::prepare_configure(&fixture.0, b"clang libc++")?;
    assert!(!build.exists());
    let compiler = fixture.compiler(&["c++"]);
    assert!(cxx_runtime::dynamic_directory(&compiler, "c++").is_none());
    fs::write(fixture.0.join("libc++.so"), [])?;
    assert_eq!(
        cxx_runtime::dynamic_directory(&compiler, "c++"),
        Some(fixture.0.as_path())
    );
    Ok(())
}
