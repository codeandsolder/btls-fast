use std::io;
use std::path::{Path, PathBuf};

/// Validate native source selection before using any caller-owned files.
pub const fn validate_native_input(
    prebuilt: Option<&Path>,
    source: Option<&Path>,
    headers: Option<&Path>,
    patched: bool,
    export: Option<&Path>,
) -> Result<(), &'static str> {
    let prebuilt = prebuilt.is_some();
    let source = source.is_some();
    if prebuilt && source {
        return Err("choose either a precompiled BoringSSL library or a source tree, not both");
    }
    if (prebuilt || source) && !patched {
        return Err(
            "external BoringSSL must contain all required patches; confirm with BORING_BSSL{,_FIPS}_ASSUME_PATCHED=1",
        );
    }
    if !(prebuilt || source) && patched {
        return Err("patch confirmation is only valid for caller-provided native inputs");
    }
    if headers.is_some() && !prebuilt {
        return Err(
            "separate headers are only supported for precompiled BoringSSL; source builds must generate bindings from the compiled source tree",
        );
    }
    if prebuilt && export.is_some() {
        return Err("cannot export a precompiled BoringSSL library");
    }
    Ok(())
}

/// Locate each archive using the same ordered directories as the linker.
pub fn find_archives(
    build_dir: &Path,
    target_env: &str,
    msvc_subdir: Option<&str>,
) -> io::Result<[PathBuf; 2]> {
    let mut directories = Vec::new();
    for subdir in ["lib", "crypto", "ssl", ""] {
        let dir = build_dir.join(subdir);
        if let Some(configuration) = msvc_subdir {
            directories.push(dir.join(configuration));
        }
        directories.push(dir);
    }
    let find = |library: &str| {
        let name = if target_env == "msvc" {
            format!("{library}.lib")
        } else {
            format!("lib{library}.a")
        };
        directories
            .iter()
            .map(|dir| dir.join(&name))
            .find(|path| path.is_file())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("missing {name} under {}", build_dir.display()),
                )
            })
    };
    let mut archives = [find("crypto")?, find("ssl")?];
    // Preserve search priority when the archives live in different directories.
    // Otherwise an earlier link-search path could shadow the selected archive.
    archives.sort_by_key(|archive| {
        directories
            .iter()
            .position(|dir| archive.parent() == Some(dir))
    });
    Ok(archives)
}
