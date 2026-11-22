use fslock::LockFile;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::process::{Command, Output};

use crate::config::Config;
use crate::prefix::{
    audit_prefixed_symbols, find_archive, regenerate_prefix_symbols, PrefixCallback, PREFIX,
};

mod cache;
mod config;
mod prefix;

fn should_use_cmake_cross_compilation(config: &Config) -> bool {
    if config.host == config.target {
        return false;
    }
    match config.target_os.as_str() {
        "macos" | "ios" | "tvos" => {
            // Cross-compiling for Apple platforms on macOS is supported using the normal Xcode
            // tools, along with the settings from `cmake_params_apple`.
            !config.host.ends_with("-darwin")
        }
        _ => true,
    }
}

// Android NDK >= 19.
const CMAKE_PARAMS_ANDROID_NDK: &[(&str, &[(&str, &str)])] = &[
    ("aarch64", &[("ANDROID_ABI", "arm64-v8a")]),
    ("arm", &[("ANDROID_ABI", "armeabi-v7a")]),
    ("x86", &[("ANDROID_ABI", "x86")]),
    ("x86_64", &[("ANDROID_ABI", "x86_64")]),
];

fn cmake_params_android(config: &Config) -> &'static [(&'static str, &'static str)] {
    for (android_arch, params) in CMAKE_PARAMS_ANDROID_NDK {
        if *android_arch == config.target_arch {
            return params;
        }
    }
    &[]
}

const CMAKE_PARAMS_APPLE: &[(&str, &[(&str, &str)])] = &[
    // iOS
    (
        "aarch64-apple-ios",
        &[
            ("CMAKE_OSX_ARCHITECTURES", "arm64"),
            ("CMAKE_OSX_SYSROOT", "iphoneos"),
            ("CMAKE_MACOSX_BUNDLE", "OFF"),
        ],
    ),
    (
        "aarch64-apple-ios-sim",
        &[
            ("CMAKE_OSX_ARCHITECTURES", "arm64"),
            ("CMAKE_OSX_SYSROOT", "iphonesimulator"),
            ("CMAKE_MACOSX_BUNDLE", "OFF"),
        ],
    ),
    (
        "x86_64-apple-ios",
        &[
            ("CMAKE_OSX_ARCHITECTURES", "x86_64"),
            ("CMAKE_OSX_SYSROOT", "iphonesimulator"),
            ("CMAKE_MACOSX_BUNDLE", "OFF"),
        ],
    ),
    // tvOS
    (
        "aarch64-apple-tvos",
        &[
            ("CMAKE_OSX_ARCHITECTURES", "arm64"),
            ("CMAKE_OSX_SYSROOT", "appletvos"),
            ("CMAKE_MACOSX_BUNDLE", "OFF"),
        ],
    ),
    (
        "aarch64-apple-tvos-sim",
        &[
            ("CMAKE_OSX_ARCHITECTURES", "arm64"),
            ("CMAKE_OSX_SYSROOT", "appletvsimulator"),
            ("CMAKE_MACOSX_BUNDLE", "OFF"),
        ],
    ),
    (
        "x86_64-apple-tvos",
        &[
            ("CMAKE_OSX_ARCHITECTURES", "x86_64"),
            ("CMAKE_OSX_SYSROOT", "appletvsimulator"),
            ("CMAKE_MACOSX_BUNDLE", "OFF"),
        ],
    ),
    // macOS
    (
        "aarch64-apple-darwin",
        &[
            ("CMAKE_OSX_ARCHITECTURES", "arm64"),
            ("CMAKE_OSX_SYSROOT", "macosx"),
        ],
    ),
    (
        "x86_64-apple-darwin",
        &[
            ("CMAKE_OSX_ARCHITECTURES", "x86_64"),
            ("CMAKE_OSX_SYSROOT", "macosx"),
        ],
    ),
];

fn cmake_params_apple(config: &Config) -> &'static [(&'static str, &'static str)] {
    for (next_target, params) in CMAKE_PARAMS_APPLE {
        if *next_target == config.target {
            return params;
        }
    }
    &[]
}

fn get_apple_sdk_name(config: &Config) -> io::Result<&'static str> {
    cmake_params_apple(config)
        .iter()
        .find_map(|(name, value)| (*name == "CMAKE_OSX_SYSROOT").then_some(*value))
        .ok_or_else(|| io::Error::other(format!("cannot find SDK for {}", config.target)))
}

/// Prepare the native source once, before patching or configuring it.
fn prepare_source(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    if config.env.path.is_some() {
        return Ok(());
    }
    if let Some(path) = &config.env.source_path {
        if !path.is_dir() {
            return Err(format!("BoringSSL source path does not exist: {}", path.display()).into());
        }
        return Ok(());
    }

    let submodule = config.manifest_dir.join("deps/boringssl");
    if !submodule.join("CMakeLists.txt").exists() {
        println!("cargo:warning=fetching boringssl git submodule");
        run_command(
            Command::new("git")
                .args(["submodule", "update", "--init", "--recursive"])
                .arg(&submodule),
        )?;
    }

    if config.source_dir.exists() {
        fs::remove_dir_all(&config.source_dir)?;
    }
    fs_extra::dir::copy(
        &submodule,
        &config.out_dir,
        &fs_extra::dir::CopyOptions::default(),
    )
    .inspect_err(|_| {
        let _ = fs::remove_dir_all(&config.source_dir);
    })?;

    // Git metadata must not keep the copied source tied to the original checkout.
    let git = config.source_dir.join(".git");
    if git.is_dir() {
        fs::remove_dir_all(git)?;
    } else if git.exists() {
        fs::remove_file(git)?;
    }
    Ok(())
}

/// Returns the platform-specific output path for lib.
///
/// MSVC generator on Windows place static libs in a target sub-folder,
/// so adjust library location based on platform and build target.
/// See issue: <https://github.com/alexcrichton/cmake-rs/issues/18>
fn msvc_lib_subdir(config: &Config) -> io::Result<Option<&'static str>> {
    if !config.target.ends_with("-msvc") {
        return Ok(None);
    }
    // Match cmake-rs's profile selection.
    let debug = match config
        .env
        .debug
        .as_deref()
        .and_then(std::ffi::OsStr::to_str)
    {
        Some("false") => false,
        Some("true") => true,
        other => {
            return Err(io::Error::other(format!(
                "invalid or missing DEBUG: {other:?}"
            )))
        }
    };
    let subdir = match config
        .env
        .opt_level
        .as_deref()
        .and_then(std::ffi::OsStr::to_str)
    {
        Some("0") => "Debug",
        Some("1" | "2" | "3") => {
            if debug {
                "RelWithDebInfo"
            } else {
                "Release"
            }
        }
        Some("s" | "z") => "MinSizeRel",
        other => {
            return Err(io::Error::other(format!(
                "invalid or missing OPT_LEVEL: {other:?}"
            )))
        }
    };
    Ok(Some(subdir))
}

/// Returns a new `cmake::Config` for building `BoringSSL`.
///
/// It will add platform-specific parameters if needed.
fn get_boringssl_cmake_config(config: &Config) -> io::Result<cmake::Config> {
    let src_path = &config.source_dir;
    let mut boringssl_cmake = cmake::Config::new(src_path);

    // Cargo builds only libssl and libcrypto, not BoringSSL's test suite.
    boringssl_cmake.define("BUILD_TESTING", "OFF");

    if config.features.prefix_symbols {
        boringssl_cmake.define("BORINGSSL_PREFIX", PREFIX.as_str());
    }

    if config.env.cmake_toolchain_file.is_some() {
        return Ok(boringssl_cmake);
    }

    if config.target_os == "windows" {
        // Explicitly use the non-debug CRT.
        // This is required now because newest BoringSSL requires CMake 3.22 which
        // uses the new logic with CMAKE_MSVC_RUNTIME_LIBRARY introduced in CMake 3.15.
        // https://github.com/rust-lang/cmake-rs/pull/30#issuecomment-2969758499
        if config.target_features.iter().any(|f| f == "crt-static") {
            boringssl_cmake.define("CMAKE_MSVC_RUNTIME_LIBRARY", "MultiThreaded");
        } else {
            boringssl_cmake.define("CMAKE_MSVC_RUNTIME_LIBRARY", "MultiThreadedDLL");
        }
    }

    if config.host == config.target {
        if config.target == "aarch64-pc-windows-msvc" {
            // MSVC cannot assemble BoringSSL's Arm64 .S sources.
            boringssl_cmake.define("OPENSSL_NO_ASM", "YES");
        }
        return Ok(boringssl_cmake);
    }

    if should_use_cmake_cross_compilation(config) {
        boringssl_cmake
            .define("CMAKE_CROSSCOMPILING", "true")
            .define("CMAKE_C_COMPILER_TARGET", &config.target)
            .define("CMAKE_CXX_COMPILER_TARGET", &config.target)
            .define("CMAKE_ASM_COMPILER_TARGET", &config.target);
    }

    if !config.features.fips {
        if let Some(cc) = &config.env.cc {
            boringssl_cmake.define("CMAKE_C_COMPILER", cc);
        }
        if let Some(cxx) = &config.env.cxx {
            boringssl_cmake.define("CMAKE_CXX_COMPILER", cxx);
        }
    }

    if let Some(sysroot) = &config.env.sysroot {
        boringssl_cmake.define("CMAKE_SYSROOT", sysroot);
    }

    if let Some(toolchain) = &config.env.compiler_external_toolchain {
        boringssl_cmake
            .define("CMAKE_C_COMPILER_EXTERNAL_TOOLCHAIN", toolchain)
            .define("CMAKE_CXX_COMPILER_EXTERNAL_TOOLCHAIN", toolchain)
            .define("CMAKE_ASM_COMPILER_EXTERNAL_TOOLCHAIN", toolchain);
    }

    configure_target_platform(config, &mut boringssl_cmake)?;
    Ok(boringssl_cmake)
}

fn configure_target_platform(
    config: &Config,
    boringssl_cmake: &mut cmake::Config,
) -> io::Result<()> {
    let src_path = &config.source_dir;
    // Add platform-specific parameters for cross-compilation.
    match &*config.target_os {
        "android" => {
            // We need ANDROID_NDK_HOME to be set properly.
            let android_ndk_home =
                config.env.android_ndk_home.as_ref().ok_or_else(|| {
                    io::Error::other("Please set ANDROID_NDK_HOME for Android build")
                })?;
            for (name, value) in cmake_params_android(config) {
                eprintln!("android arch={} add {name}={value}", config.target_arch);
                boringssl_cmake.define(name, value);
            }
            let toolchain_file = android_ndk_home.join("build/cmake/android.toolchain.cmake");
            eprintln!("android toolchain={}", toolchain_file.display());
            boringssl_cmake.define("CMAKE_TOOLCHAIN_FILE", toolchain_file);

            // 21 is the minimum level tested. You can give higher value.
            boringssl_cmake.define("CMAKE_SYSTEM_VERSION", "21");
            boringssl_cmake.define("CMAKE_ANDROID_STL_TYPE", "c++_shared");
        }

        "macos" => {
            for (name, value) in cmake_params_apple(config) {
                eprintln!("macos arch={} add {name}={value}", config.target_arch);
                boringssl_cmake.define(name, value);
            }
        }

        "ios" => {
            for (name, value) in cmake_params_apple(config) {
                eprintln!("ios arch={} add {name}={value}", config.target_arch);
                boringssl_cmake.define(name, value);
            }

            // Bitcode is always on.
            let bitcode_cflag = "-fembed-bitcode";

            // Hack for Xcode 10.1.
            let target_cflag = if config.target_arch == "x86_64" {
                "-target x86_64-apple-ios-simulator"
            } else {
                ""
            };

            let cflag = format!("{bitcode_cflag} {target_cflag}");
            boringssl_cmake.define("CMAKE_ASM_FLAGS", &cflag);
            boringssl_cmake.cflag(&cflag);
        }

        "tvos" => {
            // Unlike the `ios` arm above, no bitcode flag: bitcode was deprecated in
            // Xcode 14 and the tvOS targets postdate it, so the SDK never wants it.
            for (name, value) in cmake_params_apple(config) {
                eprintln!("tvos arch={} add {name}={value}", config.target_arch);
                boringssl_cmake.define(name, value);
            }
        }

        "windows" if config.host.contains("windows") => {
            // BoringSSL's CMakeLists.txt isn't set up for cross-compiling using Visual Studio.
            // Disable assembly support so that it at least builds.
            boringssl_cmake.define("OPENSSL_NO_ASM", "YES");
        }

        "linux" => match &*config.target_arch {
            "x86" => {
                boringssl_cmake.define(
                    "CMAKE_TOOLCHAIN_FILE",
                    // `src_path` can be a path relative to the manifest dir, but
                    // cmake hates that.
                    config
                        .manifest_dir
                        .join(src_path)
                        .join("util/32-bit-toolchain.cmake")
                        .as_os_str(),
                );
            }
            "aarch64" => {
                boringssl_cmake.define(
                    "CMAKE_TOOLCHAIN_FILE",
                    config
                        .manifest_dir
                        .join("cmake/aarch64-linux.cmake")
                        .as_os_str(),
                );
            }
            "arm" => {
                boringssl_cmake.define(
                    "CMAKE_TOOLCHAIN_FILE",
                    config
                        .manifest_dir
                        .join("cmake/armv7-linux.cmake")
                        .as_os_str(),
                );
            }
            _ => {
                println!(
                    "cargo:warning=no toolchain file configured by btls-sys for {}",
                    config.target
                );
            }
        },

        _ => {}
    }

    Ok(())
}

fn pick_best_android_ndk_toolchain(toolchains_dir: &Path) -> io::Result<OsString> {
    let toolchains = fs::read_dir(toolchains_dir)?.collect::<Result<Vec<_>, _>>()?;
    // First look for one of the toolchains that Google has documented.
    // https://developer.android.com/ndk/guides/other_build_systems
    for known_toolchain in ["linux-x86_64", "darwin-x86_64", "windows-x86_64"] {
        if let Some(toolchain) = toolchains
            .iter()
            .find(|entry| entry.file_name() == known_toolchain)
        {
            return Ok(toolchain.file_name());
        }
    }
    // Then fall back to any subdirectory, in case Google has added support for a new host.
    // (Maybe there's a linux-aarch64 toolchain now.)
    if let Some(toolchain) = toolchains
        .into_iter()
        .find(|entry| entry.file_type().is_ok_and(|ty| ty.is_dir()))
    {
        return Ok(toolchain.file_name());
    }
    // Finally give up.
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "no subdirectories at given path",
    ))
}

fn get_extra_clang_args_for_bindgen(
    config: &Config,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut params = Vec::new();

    // Add platform-specific parameters.
    match &*config.target_os {
        "ios" | "macos" | "tvos" => {
            // When cross-compiling for Apple targets, tell bindgen to use SDK sysroot,
            // and *don't* use system headers of the host macOS.
            let sdk = get_apple_sdk_name(config)?;
            let output =
                run_command(Command::new("xcrun").args(["--show-sdk-path", "--sdk", sdk]))?;
            let sysroot = std::str::from_utf8(&output.stdout)?;
            params.push("-isysroot".to_string());
            params.push(sysroot.trim_end().to_owned());
        }
        "android" => {
            let mut android_sysroot = config
                .env
                .android_ndk_home
                .clone()
                .ok_or("Please set ANDROID_NDK_HOME for Android build")?;

            android_sysroot.extend(["toolchains", "llvm", "prebuilt"]);

            let toolchain = pick_best_android_ndk_toolchain(&android_sysroot)?;
            android_sysroot.push(toolchain);
            android_sysroot.push("sysroot");
            params.push("--sysroot".to_string());
            params.push(
                android_sysroot
                    .to_str()
                    .ok_or("Android sysroot path is not Unicode")?
                    .to_owned(),
            );
        }
        _ => {}
    }

    Ok(params)
}

fn ensure_patches_applied(config: &Config) -> io::Result<()> {
    if config.env.assume_patched || config.env.path.is_some() {
        println!(
            "cargo:warning=skipping git patches application, provided\
            native BoringSSL is expected to have the patches included"
        );
        return Ok(());
    } else if config.env.source_path.is_some()
        && (config.features.rpk
            || config.features.underscore_wildcards
            || config.features.relax_cert_validation)
    {
        return Err(io::Error::other("BORING_BSSL_ASSUME_PATCHED must be set when setting BORING_BSSL_SOURCE_PATH and using rpk, underscore-wildcards or relax-cert-validation"));
    }

    let mut lock_file = LockFile::open(&config.out_dir.join(".patch_lock"))?;
    let src_path = &config.source_dir;
    let has_git = src_path.join(".git").exists();

    lock_file.lock()?;

    // NOTE: init git in the copied files, so we can apply patches
    if !has_git {
        run_command(Command::new("git").arg("init").current_dir(src_path))?;
    }

    if config.features.allow_crl_extensions_bad_version {
        println!(
            "cargo:warning=applying the patch for disabling certificate and \
            CRL version validation for extensions"
        );
        apply_patch(config, "bad-cert-verification.patch")?;
    }

    println!("cargo:warning=applying post quantum crypto patch to boringssl");
    apply_patch(config, "boring-pq.patch")?;

    if config.features.rpk {
        println!("cargo:warning=applying RPK patch to boringssl");
        apply_patch(config, "rpk.patch")?;
    }

    if !config.features.fips {
        for patch_name in [
            "0001-boringssl-ffdhe.patch",
            "0002-boringssl-legacy-ciphers.patch",
            "0003-boringssl-tls-options.patch",
            "0004-boringssl-extension-order.patch",
            "0005-record-size-limit.patch",
            "0006-delegated-credentials.patch",
            "0007-boringssl-f5-padding.patch",
            "0008-boringssl-sigalgs.patch",
            "0009-boringssl-zstd-cert-compression.patch",
            "0010-boringssl-build-compat.patch",
            "0011-boringssl-seal-app-data.patch",
            "0012-boringssl-cheap-error-reset.patch",
            "0013-ech-grease-payload-policy.patch",
        ] {
            println!("cargo:warning=applying {patch_name} to boringssl");
            apply_patch(config, patch_name)?;
        }
    }

    // FIPS builds compile the same module source, so they need this fix too.
    println!("cargo:warning=applying rand double-free fix to boringssl");
    apply_patch(config, "boringssl-rand-double-free.patch")?;

    // Only the symbol audit reads this tool, and only a prefixed build runs it.
    if config.features.prefix_symbols {
        println!("cargo:warning=applying symbol audit patch to boringssl");
        apply_patch(config, "boringssl-audit-symbols.patch")?;
    }

    println!("cargo:warning=applying loongarch patch to boringssl");
    apply_patch(config, "boringssl-loongarch.patch")?;

    if config.features.underscore_wildcards {
        println!("cargo:warning=applying underscore wildcards patch to boringssl");
        apply_patch(config, "underscore-wildcards.patch")?;
    }

    if config.features.relax_cert_validation {
        println!("cargo:warning=applying RSA key-usage enforcement relaxation patch");
        apply_patch(config, "relax-cert-validation.patch")?;
    }

    Ok(())
}

fn apply_patch(config: &Config, patch_name: &str) -> io::Result<()> {
    let src_path = &config.source_dir;
    #[cfg(not(windows))]
    let cmd_path = config
        .manifest_dir
        .join("patches")
        .join(patch_name)
        .canonicalize()?;

    #[cfg(windows)]
    let cmd_path = config.manifest_dir.join("patches").join(patch_name);

    let mut args = vec!["apply", "-v", "--whitespace=fix"];

    // non-bazel versions of BoringSSL have no src/ dir
    if config.is_bazel {
        args.push("-p2");
    }

    run_command(
        Command::new("git")
            .args(&args)
            .arg(cmd_path)
            .current_dir(src_path),
    )?;

    Ok(())
}

fn run_command(command: &mut Command) -> io::Result<Output> {
    let out = command.output().map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "can't run {}: {e}\n{command:?} failed",
                command.get_program().to_string_lossy(),
            ),
        )
    })?;

    io::stderr().write_all(&out.stderr)?;
    io::stdout().write_all(&out.stdout)?;

    if !out.status.success() {
        let err = out.status.code().map_or_else(
            || format!("{command:?} was terminated by signal"),
            |code| format!("{command:?} exited with status: {code}"),
        );

        return Err(io::Error::other(err));
    }

    Ok(out)
}

fn build_boringssl_or_get_prebuilt(config: &Config) -> io::Result<PathBuf> {
    if let Some(path) = &config.env.path {
        if !path.is_dir() {
            return Err(io::Error::other(format!(
                "built path does not exist: {}",
                path.display()
            )));
        }
        return Ok(path.clone());
    }

    let mut cfg = get_boringssl_cmake_config(config)?;

    let num_jobs = std::env::var("NUM_JOBS").ok().or_else(|| {
        std::thread::available_parallelism()
            .ok()
            .map(|t| t.to_string())
    });
    if let Some(num_jobs) = num_jobs {
        cfg.env("CMAKE_BUILD_PARALLEL_LEVEL", num_jobs);
    }

    if config.features.fips {
        cfg.define("CMAKE_C_COMPILER", "clang")
            .define("CMAKE_CXX_COMPILER", "clang++")
            .define("CMAKE_ASM_COMPILER", "clang")
            .define("FIPS", "1");
    }

    if config.features.prefix_symbols {
        cfg.define("CMAKE_POSITION_INDEPENDENT_CODE", "ON");
    }

    cache::apply(config, &mut cfg);

    // BoringSSL's ssl target already depends on crypto.
    let path = cfg.build_target("ssl").build();
    let build_dir = path.join("build");
    Ok(if build_dir.exists() { build_dir } else { path })
}

fn get_cpp_runtime_lib(config: &Config) -> Option<String> {
    if let Some(ref cpp_lib) = config.env.cpp_runtime_lib {
        return cpp_lib.clone().into_string().ok();
    }

    match &*config.target_os {
        "macos" | "ios" | "tvos" | "freebsd" | "openbsd" | "android" => Some("c++".into()),
        _ if config.unix || config.target_env == "gnu" => Some("stdc++".into()),
        // TODO(rmehra): figure out how to do this for windows
        _ => None,
    }
}

/// Copies built `BoringSSL` artifacts (libraries and patched headers) into a
/// user-specified directory. This is intended for producing a pre-built package.
///
/// The destination directory must exist and be empty. Writes:
///
///   - `lib/libcrypto.a`
///   - `lib/libssl.a`
///   - `lib/bcm.o` (if FIPS is enabled)
///   - `include/openssl/...` (patched headers)
fn install_artifacts(
    config: &Config,
    install_dir: &Path,
    bssl_build_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let install_dir = match install_dir.canonicalize() {
        Ok(dir) if dir.read_dir().is_ok_and(|mut d| d.next().is_none()) => dir,
        dir => {
            let path = dir.as_deref().unwrap_or(install_dir).display();
            return Err(format!("{path} must be an empty dir").into());
        }
    };

    let lib_dir = install_dir.join("lib");
    fs::create_dir(&lib_dir)?;

    for lib in ["libcrypto.a", "libssl.a", "bcm.o"] {
        if !config.features.fips && lib == "bcm.o" {
            continue;
        }
        fs::copy(bssl_build_dir.join(lib), lib_dir.join(lib))?;
    }

    fs_extra::dir::copy(
        get_include_path(config)?,
        &install_dir,
        &fs_extra::dir::CopyOptions::default(),
    )?;

    eprintln!(
        "installed BoringSSL artifacts into {}",
        install_dir.display()
    );
    Ok(())
}

fn main() -> ExitCode {
    if let Err(e) = run() {
        eprintln!("boring-sys failed: {e}");
        println!(
            "cargo::error={}",
            e.to_string().trim_ascii().replace('\n', "\ncargo::error=")
        );
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env()?;
    emit_rerun_if_changed();
    prepare_source(&config)?;
    ensure_patches_applied(&config)?;

    if config.features.prefix_symbols && config.env.path.is_some() {
        println!(
            "cargo:warning=a precompiled BoringSSL was provided, so this build cannot apply or \
            verify symbol prefixing; the generated bindings still expect prefixed symbols, so the \
            provided library must have been built with `-DBORINGSSL_PREFIX={}`",
            PREFIX.as_str()
        );
    }

    if config.features.prefix_symbols && !config.env.docs_rs && config.env.path.is_none() {
        regenerate_prefix_symbols(&config.source_dir, &config.out_dir)
            .map_err(|e| format!("could not generate BoringSSL's prefixed symbol list: {e}"))?;
    }

    let build_dir = if !config.env.docs_rs || config.env.export_to_install_dir.is_some() {
        Some(build_boringssl_or_get_prebuilt(&config)?)
    } else {
        None
    };
    if !config.env.docs_rs {
        let bssl_dir = build_dir
            .as_deref()
            .ok_or("missing native build directory")?;
        emit_link_directives(&config, bssl_dir)?;
        if config.features.prefix_symbols && config.env.path.is_none() {
            let msvc_subdir = msvc_lib_subdir(&config)?;
            // libssl holds the C++ symbols that `prefix_symbols.h` cannot rename, so it
            // needs the audit at least as much as libcrypto does.
            let archives = ["crypto", "ssl"]
                .into_iter()
                .map(|library| find_archive(bssl_dir, &config.target_env, msvc_subdir, library))
                .collect::<io::Result<Vec<_>>>()?;
            audit_prefixed_symbols(&config.source_dir, &archives, &config.target_os)
                .map_err(|e| format!("BoringSSL's prefixed symbol audit failed: {e}"))?;
        }
    }
    generate_bindings(&config).map_err(|e| format!("could not generate bindings: {e}"))?;
    if let Some(install_dir) = &config.env.export_to_install_dir {
        install_artifacts(
            &config,
            install_dir,
            build_dir
                .as_deref()
                .ok_or("missing native build directory")?,
        )
        .map_err(|e| format!("install artifacts failed: {e}"))?;
    }
    Ok(())
}

fn emit_rerun_if_changed() {
    println!("cargo:rerun-if-changed=patches");
}

fn emit_link_directives(config: &Config, bssl_dir: &Path) -> io::Result<()> {
    let msvc_lib_subdir = msvc_lib_subdir(config)?;

    let subdirs =
        if config.is_bazel || (config.features.is_fips_like() && config.env.path.is_some()) {
            &["lib"][..]
        } else {
            &["lib", "crypto", "ssl", ""][..]
        };

    for subdir in subdirs {
        let dir = bssl_dir.join(subdir);
        let dir = msvc_lib_subdir
            .map(|s| dir.join(s))
            .filter(|d| d.exists())
            .unwrap_or(dir);
        if dir.is_dir() {
            println!("cargo:rustc-link-search=native={}", dir.display());
        }
    }

    if let Some(cpp_lib) = get_cpp_runtime_lib(config) {
        println!("cargo:rustc-link-lib={cpp_lib}");
    }
    println!("cargo:rustc-link-lib=static=crypto");
    println!("cargo:rustc-link-lib=static=ssl");

    if config.target_os == "windows" {
        // Rust 1.87.0 compat - https://github.com/rust-lang/rust/pull/138233
        println!("cargo:rustc-link-lib=advapi32");
    }
    Ok(())
}

fn check_include_path(path: PathBuf) -> Result<PathBuf, String> {
    if path.join("openssl").join("x509v3.h").exists() {
        Ok(path)
    } else {
        Err(format!(
            "Include path {} {}",
            path.display(),
            if path.exists() {
                "does not have expected openssl/x509v3.h"
            } else {
                "does not exist"
            }
        ))
    }
}

fn get_include_path(config: &Config) -> Result<PathBuf, String> {
    if let Some(path) = &config.env.include_path {
        return check_include_path(path.to_owned());
    }

    if let Some(bssl_path) = &config.env.path {
        return check_include_path(bssl_path.join("include"));
    }

    let src_path = &config.source_dir;
    check_include_path(src_path.join("include"))
        .or_else(|_| check_include_path(src_path.join("src").join("include")))
}

fn generate_bindings(config: &Config) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let include_path = get_include_path(config)?;

    let target_rust_version = bindgen::RustTarget::stable(77, 0)
        .map_err(|e| format!("bindgen does not recognize target rust version: {e}"))?;

    let mut builder = bindgen::Builder::default()
        .rust_target(target_rust_version) // bindgen MSRV is 1.70, so this is enough
        .derive_copy(true)
        .derive_debug(true)
        .derive_default(true)
        .derive_eq(false)
        .derive_partialeq(false)
        .default_enum_style(bindgen::EnumVariation::NewType {
            is_bitfield: false,
            is_global: false,
        })
        .default_macro_constant_type(bindgen::MacroTypeVariation::Signed)
        .generate_comments(true)
        .fit_macro_constants(false)
        .size_t_is_usize(true)
        .layout_tests(config.env.debug.is_some())
        .merge_extern_blocks(true)
        .prepend_enum_name(true)
        .blocklist_type("max_align_t") // Not supported by bindgen on all targets, not used by BoringSSL
        // The C allocator functions are clang builtins, and libclang reports
        // them without the `size_t` typedef, so bindgen emits `c_ulong` instead
        // of `usize` (https://github.com/rust-lang/rust-bindgen/issues/1770).
        // Rust 1.99 flags such declarations of runtime symbols
        // (`suspicious_runtime_symbol_definitions`). Use `libc` for these.
        .blocklist_function("malloc|calloc|realloc|free")
        // Only BoringSSL's own declarations, not transitive system headers. Match any
        // `openssl/` directory, as `BORING_BSSL_INCLUDE_PATH` need not end in `include`.
        .allowlist_file(r".*[/\\]openssl[/\\].*")
        .opaque_type("FILE")
        .clang_args(get_extra_clang_args_for_bindgen(config)?)
        .clang_arg("-I")
        .clang_arg(include_path.display().to_string());

    if let Some(sysroot) = &config.env.sysroot {
        builder = builder
            .clang_arg("--sysroot")
            .clang_arg(sysroot.display().to_string());

        // we need to add special platform header file with env for support cross building
        let target_include_dir = sysroot.join(format!(
            "usr/include/{}-{}-{}",
            config.target_arch, config.target_os, config.target_env
        ));
        if target_include_dir.is_dir() {
            builder = builder
                .clang_arg("-I")
                .clang_arg(target_include_dir.display().to_string());
        }
    }

    if config.features.prefix_symbols {
        builder = builder.parse_callbacks(Box::new(PrefixCallback::new(
            &config.target_os,
            &config.target_arch,
        )));
    }

    let builder = bindgen_headers(builder, &include_path)?;

    let bindings = builder.generate()?;
    let mut source_code = Vec::new();
    bindings
        .write(&mut source_code)
        .map_err(|e| format!("Couldn't serialize bindings: {e}"))?;
    ensure_err_lib_enum_is_named(&mut source_code);
    let bindings_path = config.out_dir.join("bindings.rs");
    fs::write(&bindings_path, source_code).map_err(|e| {
        format!(
            "Couldn't write bindings to {}: {e}",
            bindings_path.display()
        )
    })?;
    fs::write(config.out_dir.join("bindings_module.rs"), GENERATED_MODULE)?;
    Ok(bindings_path)
}

// The generator emits the C ABI unchanged. These exceptions are limited to the
// generated declarations and bindgen's generated helper implementations.
const GENERATED_MODULE: &str = r#"
#[allow(
    clippy::allow_attributes_without_reason,
    clippy::branches_sharing_code,
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::default_trait_access,
    clippy::derive_partial_eq_without_eq,
    clippy::manual_div_ceil,
    clippy::missing_const_for_fn,
    clippy::missing_safety_doc,
    clippy::must_use_candidate,
    clippy::ptr_as_ptr,
    clippy::ptr_offset_with_cast,
    clippy::pub_underscore_fields,
    clippy::redundant_static_lifetimes,
    clippy::semicolon_if_nothing_returned,
    clippy::too_many_arguments,
    clippy::undocumented_unsafe_blocks,
    clippy::unreadable_literal,
    clippy::upper_case_acronyms,
    clippy::use_self,
    clippy::used_underscore_binding,
    clippy::used_underscore_items,
    clippy::useless_transmute,
    dead_code,
    improper_ctypes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unknown_lints,
    unnecessary_transmutes,
    unused_imports,
    reason = "Generated by bindgen from BoringSSL headers; C names, layout and generated helper code are not handwritten Rust."
)]
mod generated {
    include!("bindings.rs");
}
"#;

fn bindgen_headers(
    mut builder: bindgen::Builder,
    include_path: &Path,
) -> Result<bindgen::Builder, Box<dyn std::error::Error>> {
    let must_have_headers = [
        "aes.h",
        "asn1_mac.h",
        "asn1t.h",
        "blake2.h",
        "blowfish.h",
        "cast.h",
        "chacha.h",
        "cmac.h",
        "cpu.h",
        "curve25519.h",
        "des.h",
        "dtls1.h",
        "err.h",
        "hkdf.h",
        "hpke.h",
        "ossl_typ.h",
        "pkcs12.h",
        "poly1305.h",
        // `src/lib.rs` re-exports `CRYPTO_tls1_prf` from this header unconditionally, so
        // a missing one should fail here rather than as an unresolved import later.
        "tls_prf.h",
        "x509v3.h",
    ];
    let headers = [
        "hmac.h",
        "hrss.h",
        "md4.h",
        "md5.h",
        "mldsa.h",
        "mlkem.h",
        "obj_mac.h",
        "objects.h",
        "opensslv.h",
        "rand.h",
        "rc4.h",
        "ripemd.h",
        "siphash.h",
        "srtp.h",
        "trust_token.h",
    ];
    for (i, header) in must_have_headers.into_iter().chain(headers).enumerate() {
        let header_path = include_path.join("openssl").join(header);
        if header_path.exists() {
            builder = builder.header(
                header_path
                    .to_str()
                    .ok_or("BoringSSL header path is not Unicode")?,
            );
        } else {
            let err = format!("'openssl/{header}' is missing from '{}'. The include path may be incorrect or contain an outdated version of OpenSSL/BoringSSL", include_path.display());
            if i < must_have_headers.len() {
                return Err(err.into());
            }
            println!("cargo::warning={err}");
        }
    }

    Ok(builder)
}

/// err.h has anonymous `enum { ERR_LIB_NONE = 1 }`, which makes a dodgy `_bindgen_ty_1` name
fn ensure_err_lib_enum_is_named(source_code: &mut Vec<u8>) {
    let src = String::from_utf8_lossy(source_code);
    let enum_type = src
        .split_once("ERR_LIB_SSL:")
        .and_then(|(_, def)| Some(def.split_once('=')?.0))
        .unwrap_or("_bindgen_ty_1");

    source_code.extend_from_slice(
        format!("\n/// Newtype for [`ERR_LIB_SSL`] constants\npub use {enum_type} as ErrLib;\n")
            .as_bytes(),
    );
}
