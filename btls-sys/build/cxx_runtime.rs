//! Resolve the static C++ runtime from the native compiler's CMake file API.
//! Never search the host's default library directories for a cross target.

use std::{
    fs,
    io::{self, Read as _},
    path::{Path, PathBuf},
};

#[derive(Debug)]
pub struct Toolchain {
    pub libraries: Vec<String>,
    pub directories: Vec<PathBuf>,
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}

/// CMake retains its compiler identity and inferred implicit libraries even
/// when Cargo reruns a build script. Reconfigure when the actual inputs change.
pub fn prepare_configure(out: &Path, identity: &[u8]) -> io::Result<()> {
    let stamp = out.join("configure-inputs");
    match fs::read(&stamp) {
        Ok(previous) if previous == identity => return Ok(()),
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let build = out.join("build");
    if build.exists() {
        fs::remove_dir_all(build)?;
    }
    fs::create_dir_all(out)?;
    fs::write(stamp, identity)
}

pub fn request_toolchains(build: &Path) -> io::Result<()> {
    let query = build.join(".cmake/api/v1/query");
    fs::create_dir_all(&query)?;
    fs::write(query.join("toolchains-v1"), [])
}

fn json(path: &Path) -> io::Result<serde_json::Value> {
    serde_json::from_slice(&fs::read(path)?).map_err(io::Error::other)
}

pub fn toolchain(build: &Path) -> io::Result<Toolchain> {
    let reply = build.join(".cmake/api/v1/reply");
    let index = fs::read_dir(&reply)?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with("index-") && name.ends_with(".json"))
        })
        .map(|entry| entry.path())
        .max()
        .ok_or_else(|| invalid("CMake did not publish its compiler toolchains"))?;
    let index = json(&index)?;
    let file = index["reply"]["toolchains-v1"]["jsonFile"]
        .as_str()
        .filter(|name| {
            Path::new(name)
                .file_name()
                .is_some_and(|file| file == *name)
        })
        .ok_or_else(|| invalid("CMake toolchains-v1 reply missing"))?;
    let tools = json(&reply.join(file))?;
    let cxx = tools["toolchains"]
        .as_array()
        .and_then(|tools| tools.iter().find(|tool| tool["language"] == "CXX"))
        .ok_or_else(|| invalid("CMake C++ toolchain missing"))?;
    let implicit = &cxx["compiler"]["implicit"];
    let strings = |key: &str| {
        implicit[key]
            .as_array()
            .ok_or_else(|| invalid(format!("missing C++ implicit {key}")))?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| invalid(format!("invalid C++ implicit {key}")))
            })
            .collect::<io::Result<Vec<_>>>()
    };
    Ok(Toolchain {
        libraries: strings("linkLibraries")?,
        directories: strings("linkDirectories")?
            .into_iter()
            .map(PathBuf::from)
            .collect(),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Runtime {
    Gnu,
    Llvm,
}

impl Runtime {
    const fn name(self) -> &'static str {
        match self {
            Self::Gnu => "stdc++",
            Self::Llvm => "c++",
        }
    }

    fn from_name(name: &str) -> io::Result<Self> {
        match name {
            "stdc++" => Ok(Self::Gnu),
            "c++" => Ok(Self::Llvm),
            _ => Err(invalid(format!(
                "unsupported static C++ runtime {name:?}; select stdc++ or c++"
            ))),
        }
    }
}

fn archive(directories: &[PathBuf], name: &str) -> Option<PathBuf> {
    directories
        .iter()
        .filter(|directory| directory.is_absolute())
        .map(|directory| directory.join(format!("lib{name}.a")))
        .find(|path| path.is_file())
}

fn choose(gnu: bool, llvm: bool, explicit: Option<&str>) -> io::Result<Runtime> {
    if let Some(name) = explicit {
        let runtime = Runtime::from_name(name)?;
        if match runtime {
            Runtime::Gnu => gnu,
            Runtime::Llvm => llvm,
        } {
            return Ok(runtime);
        }
        return Err(invalid(format!(
            "selected C++ runtime {name} is not available in the target toolchain or prebuilt package"
        )));
    }
    match (gnu, llvm) {
        (true, false) => Ok(Runtime::Gnu),
        (false, true) => Ok(Runtime::Llvm),
        (false, false) => Err(invalid(
            "no supported C++ runtime in target toolchain or prebuilt package",
        )),
        (true, true) => Err(invalid(
            "ambiguous C++ runtime; select stdc++ or c++ explicitly",
        )),
    }
}

fn contains_library(compiler: &Toolchain, name: &str) -> bool {
    let archive_name = format!("lib{name}.a");
    let shared_name = format!("lib{name}.so");
    compiler.libraries.iter().any(|library| {
        if library == name {
            return true;
        }
        Path::new(library)
            .file_name()
            .and_then(|file| file.to_str())
            .is_some_and(|file| {
                file == archive_name
                    || file == shared_name
                    || file
                        .strip_prefix(&shared_name)
                        .is_some_and(|suffix| suffix.starts_with('.'))
            })
    })
}

pub fn dynamic_name(compiler: &Toolchain) -> io::Result<&'static str> {
    Ok(choose(
        contains_library(compiler, "stdc++"),
        contains_library(compiler, "c++"),
        None,
    )?
    .name())
}

/// Preserve the target compiler's selected search directory for shared linkage.
pub fn dynamic_directory<'a>(compiler: &'a Toolchain, name: &str) -> Option<&'a Path> {
    let filename = format!("lib{name}.so");
    compiler
        .directories
        .iter()
        .filter(|directory| directory.is_absolute())
        .find(|directory| directory.join(&filename).is_file())
        .map(PathBuf::as_path)
}

/// For compiled sources, the actual CMake C++ link line determines the ABI.
/// For prebuilt sources, only archives explicitly supplied with the native
/// libraries are considered: a foreign compiler's ABI cannot be inferred
/// from the Rust target triple or from the host's installed standard library.
pub fn resolve(
    compiler: Option<&Toolchain>,
    prebuilt_directories: &[PathBuf],
    explicit: Option<&str>,
) -> io::Result<Vec<PathBuf>> {
    let (gnu, llvm, directories) = if let Some(compiler) = compiler {
        (
            contains_library(compiler, "stdc++"),
            contains_library(compiler, "c++"),
            compiler.directories.as_slice(),
        )
    } else {
        (
            archive(prebuilt_directories, "stdc++").is_some(),
            archive(prebuilt_directories, "c++").is_some(),
            prebuilt_directories,
        )
    };
    let runtime = choose(gnu, llvm, explicit)?;
    let required = |name| {
        archive(directories, name).ok_or_else(|| {
        invalid(format!("missing target static C++ archive lib{name}.a; install the matching compiler's static runtime (or supply it with the prebuilt package)"))
    })
    };
    let mut archives = vec![required(runtime.name())?];
    if runtime == Runtime::Llvm {
        // libc++ can either incorporate its ABI library or ship it separately.
        // Include the separate archive when present. Rust's final link detects
        // unresolved ABI symbols if a split runtime was incompletely supplied.
        archives.extend(archive(directories, "c++abi"));
    }
    if compiler.is_some_and(|tool| contains_library(tool, "unwind")) {
        archives.push(required("unwind")?);
    } else if compiler.is_none() && runtime == Runtime::Llvm {
        archives.extend(archive(directories, "unwind"));
    }
    Ok(archives)
}

fn validate_archive(archive: &Path) -> io::Result<PathBuf> {
    let source = archive.canonicalize()?;
    let mut magic = [0; 8];
    fs::File::open(&source)?.read_exact(&mut magic)?;
    if &magic != b"!<arch>\n" {
        return Err(invalid(format!(
            "{} is not a self-contained static archive",
            source.display()
        )));
    }
    println!("cargo:rerun-if-changed={}", archive.display());
    if source != *archive {
        println!("cargo:rerun-if-changed={}", source.display());
    }
    Ok(source)
}

/// Include the exact runtime archives in packages produced for prebuilt use.
pub fn export_archives(directory: &Path, archives: &[PathBuf]) -> io::Result<()> {
    for archive in archives {
        let source = validate_archive(archive)?;
        let name = archive
            .file_name()
            .ok_or_else(|| invalid("native runtime archive has no name"))?;
        fs::copy(source, directory.join(name))?;
    }
    Ok(())
}

/// Copy the selected archives to distinct private names. This both avoids
/// shadowing by a different native search directory and bundles the exact
/// target runtime in the Rust rlib rather than relying on a final-link host.
pub fn emit(out: &Path, archives: &[PathBuf]) -> io::Result<()> {
    let directory = out.join("cxx-runtime");
    fs::create_dir_all(&directory)?;
    println!("cargo:rustc-link-search=native={}", directory.display());
    for (index, archive) in archives.iter().enumerate() {
        let source = validate_archive(archive)?;
        let name = format!("btls_cxx_runtime_{index}");
        fs::copy(&source, directory.join(format!("lib{name}.a")))?;
        println!("cargo:rustc-link-lib=static={name}");
    }
    Ok(())
}
