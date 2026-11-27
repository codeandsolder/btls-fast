use std::env;
use std::ffi::OsString;
use std::path::PathBuf;

use crate::native_input::validate_native_input;

pub struct Config {
    pub manifest_dir: PathBuf,
    pub out_dir: PathBuf,
    pub source_dir: PathBuf,
    pub is_bazel: bool,
    pub host: String,
    pub target: String,
    pub target_arch: String,
    pub target_os: String,
    pub unix: bool,
    pub target_env: String,
    pub target_features: Vec<String>,
    pub features: Features,
    pub env: Env,
}

#[expect(
    clippy::struct_excessive_bools,
    reason = "These fields record independent Cargo feature switches; only the incompatible combinations are rejected during configuration."
)]
pub struct Features {
    pub fips: bool,
    pub static_cxx_runtime: bool,
    pub rpk: bool,
    pub underscore_wildcards: bool,
    pub prefix_symbols: bool,
    pub allow_crl_extensions_bad_version: bool,
    pub relax_cert_validation: bool,
}

pub struct Env {
    pub path: Option<PathBuf>,
    pub include_path: Option<PathBuf>,
    pub source_path: Option<PathBuf>,
    pub assume_patched: bool,
    pub sysroot: Option<PathBuf>,
    pub compiler_external_toolchain: Option<PathBuf>,
    pub debug: Option<OsString>,
    pub opt_level: Option<OsString>,
    pub android_ndk_home: Option<PathBuf>,
    pub cmake_toolchain_file: Option<PathBuf>,
    pub cpp_runtime_lib: Option<OsString>,
    /// C compiler (ignored if using FIPS)
    pub cc: Option<OsString>,
    pub cxx: Option<OsString>,
    pub native_environment: Vec<(String, Option<OsString>)>,
    pub docs_rs: bool,
    /// If set, built artifacts (libraries and patched headers) will be copied
    /// into this directory. The directory must exist and be empty.
    pub export_to_install_dir: Option<PathBuf>,
}

impl Config {
    pub fn from_env() -> Result<Self, &'static str> {
        let manifest_dir = env::var_os("CARGO_MANIFEST_DIR")
            .ok_or("CARGO_MANIFEST_DIR")?
            .into();
        let out_dir: PathBuf = env::var_os("OUT_DIR").ok_or("OUT_DIR")?.into();
        let host = env::var("HOST").map_err(|_| "HOST is missing or not Unicode")?;
        let target = env::var("TARGET").map_err(|_| "TARGET is missing or not Unicode")?;
        let target_arch = env::var("CARGO_CFG_TARGET_ARCH")
            .map_err(|_| "CARGO_CFG_TARGET_ARCH is missing or not Unicode")?;
        let target_os = env::var("CARGO_CFG_TARGET_OS")
            .map_err(|_| "CARGO_CFG_TARGET_OS is missing or not Unicode")?;
        let target_env = env::var("CARGO_CFG_TARGET_ENV")
            .map_err(|_| "CARGO_CFG_TARGET_ENV is missing or not Unicode")?;
        let unix = env::var("CARGO_CFG_UNIX").is_ok();

        let target_features = env::var("CARGO_CFG_TARGET_FEATURE")
            .unwrap_or_default()
            .split(',')
            .map(str::to_owned)
            .collect();

        let features = Features::from_env();
        let env = Env::from_env(&host, &target, features.is_fips_like());

        let source_dir = env
            .source_path
            .clone()
            .unwrap_or_else(|| out_dir.join("boringssl"));
        let is_bazel = env
            .source_path
            .as_ref()
            .is_some_and(|path| path.join("src").exists());

        // DEP_BTLS_VERSION_MAJOR
        println!(
            "cargo:version_major={}",
            env::var("CARGO_PKG_VERSION_MAJOR").unwrap_or_default()
        );

        let config = Self {
            manifest_dir,
            out_dir,
            source_dir,
            is_bazel,
            host,
            target,
            target_arch,
            target_os,
            unix,
            target_env,
            target_features,
            features,
            env,
        };

        config.check_feature_compatibility()?;

        Ok(config)
    }

    pub fn linux_cxx_runtime(&self) -> bool {
        self.target_os == "linux" && matches!(self.target_env.as_str(), "gnu" | "musl")
    }

    pub fn static_cxx_runtime(&self) -> bool {
        self.features.static_cxx_runtime
            || (self.linux_cxx_runtime()
                && self
                    .target_features
                    .iter()
                    .any(|feature| feature == "crt-static"))
    }

    fn check_feature_compatibility(&self) -> Result<(), &'static str> {
        if self.features.static_cxx_runtime && !self.linux_cxx_runtime() {
            return Err("static-cxx-runtime requires a Linux GNU or musl target");
        }

        if self.features.fips && self.features.rpk {
            return Err("`fips` and `rpk` features are mutually exclusive");
        }

        // BoringSSL's BUILDING.md: "symbol prefixing cannot be used with the combination of
        // FIPS and static libraries". This crate always links BoringSSL statically, so the
        // combination is unsupported and would silently produce an unprefixed FIPS module.
        if self.features.is_fips_like() && self.features.prefix_symbols {
            return Err(
                "`fips` and `prefix-symbols` features are mutually exclusive, because BoringSSL \
                does not support symbol prefixing for static FIPS builds",
            );
        }

        // Symbol prefixing regenerates BoringSSL's prefix list from the patched headers,
        // which means writing into the source tree. A caller-owned tree may be read-only,
        // shared between concurrent target builds, or expected to stay untouched.
        if self.features.prefix_symbols && self.env.source_path.is_some() {
            return Err(
                "`prefix-symbols` cannot be used with `BORING_BSSL{,_FIPS}_SOURCE_PATH`, \
                because symbol prefixing regenerates BoringSSL's prefix list and would write \
                it into the provided source tree. Build from the vendored submodule instead.",
            );
        }

        validate_native_input(
            self.env.path.as_deref(),
            self.env.source_path.as_deref(),
            self.env.include_path.as_deref(),
            self.env.assume_patched,
            self.env.export_to_install_dir.as_deref(),
        )?;
        Ok(())
    }
}

impl Features {
    const fn from_env() -> Self {
        Self {
            fips: cfg!(feature = "fips"),
            static_cxx_runtime: cfg!(feature = "static-cxx-runtime"),
            rpk: cfg!(feature = "rpk"),
            underscore_wildcards: cfg!(feature = "underscore-wildcards"),
            prefix_symbols: cfg!(feature = "prefix-symbols"),
            allow_crl_extensions_bad_version: cfg!(feature = "allow-crl-extensions-bad-version"),
            relax_cert_validation: cfg!(feature = "relax-cert-validation"),
        }
    }

    pub const fn enables_patch(&self, condition: crate::patches::Condition) -> bool {
        use crate::patches::Condition;
        match condition {
            Condition::Always => true,
            Condition::NonFips => !self.fips,
            Condition::Rpk => self.rpk,
            Condition::PrefixSymbols => self.prefix_symbols,
            Condition::AllowCrlExtensionsBadVersion => self.allow_crl_extensions_bad_version,
            Condition::UnderscoreWildcards => self.underscore_wildcards,
            Condition::RelaxCertValidation => self.relax_cert_validation,
        }
    }

    pub const fn is_fips_like(&self) -> bool {
        self.fips
    }
}

impl Env {
    fn from_env(host: &str, target: &str, is_fips_like: bool) -> Self {
        let var_prefix = if host == target { "HOST" } else { "TARGET" };
        let target_with_underscores = target.replace('-', "_");

        let target_only_var = |name: &str| {
            var(&format!("{name}_{target}"))
                .or_else(|| var(&format!("{name}_{target_with_underscores}")))
                .or_else(|| var(&format!("{var_prefix}_{name}")))
        };
        let target_var = |name: &str| target_only_var(name).or_else(|| var(name));
        // Track the inputs read by cmake/cc as well as our own configuration.
        // Query all precedence levels, including unset variables: introducing
        // a higher-priority override must invalidate a previous configure.
        let native_environment = [
            "CC",
            "CXX",
            "AR",
            "RANLIB",
            "CFLAGS",
            "CXXFLAGS",
            "ASMFLAGS",
            "CMAKE",
            "CMAKE_GENERATOR",
            "CMAKE_GENERATOR_PLATFORM",
            "CMAKE_GENERATOR_TOOLSET",
            "CMAKE_TOOLCHAIN_FILE",
            "CMAKE_PREFIX_PATH",
            "CMAKE_MAKE_PROGRAM",
            "CMAKE_SYSROOT",
            "CMAKE_C_COMPILER",
            "CMAKE_CXX_COMPILER",
            "SDKROOT",
            "MACOSX_DEPLOYMENT_TARGET",
            "CROSS_COMPILE",
            "PATH",
            "CARGO_ENCODED_RUSTFLAGS",
        ]
        .into_iter()
        .flat_map(|name| {
            [
                format!("{name}_{target}"),
                format!("{name}_{target_with_underscores}"),
                format!("{var_prefix}_{name}"),
                name.to_owned(),
            ]
        })
        .map(|name| {
            let value = var(&name);
            (name, value)
        })
        .collect();

        let boringssl_var = |name: &str| {
            const BORING_BSSL_PREFIX: &str = "BORING_BSSL_";
            const BORING_BSSL_FIPS_PREFIX: &str = "BORING_BSSL_FIPS_";

            // The passed name is the non-fips version of the environment variable,
            // to help look for them in the repository.
            assert!(name.starts_with(BORING_BSSL_PREFIX));

            let non_fips = target_var(name);
            if is_fips_like {
                let fips_name = name.replace(BORING_BSSL_PREFIX, BORING_BSSL_FIPS_PREFIX);
                let fips = target_var(&fips_name);
                if fips.is_none() && non_fips.is_some() {
                    println!(
                        "cargo:warning=env var {name} ignored, because FIPS is enabled. Set {fips_name} instead."
                    );
                }
                fips
            } else {
                non_fips
            }
        };

        Self {
            path: boringssl_var("BORING_BSSL_PATH").map(PathBuf::from), // gets BORING_BSSL_FIPS_PATH if fips is enabled
            include_path: boringssl_var("BORING_BSSL_INCLUDE_PATH").map(PathBuf::from), // gets BORING_BSSL_FIPS_INCLUDE_PATH if fips is enabled
            source_path: boringssl_var("BORING_BSSL_SOURCE_PATH").map(PathBuf::from), // gets BORING_BSSL_FIPS_SOURCE_PATH if fips is enabled
            assume_patched: boringssl_var("BORING_BSSL_ASSUME_PATCHED") // gets BORING_BSSL_FIPS_ASSUME_PATCHED if fips is enabled
                .is_some_and(|v| v == "1"),
            sysroot: boringssl_var("BORING_BSSL_SYSROOT").map(PathBuf::from), // gets BORING_BSSL_FIPS_SYSROOT if fips is enabled
            compiler_external_toolchain: boringssl_var("BORING_BSSL_COMPILER_EXTERNAL_TOOLCHAIN") // gets BORING_BSSL_FIPS_COMPILER_EXTERNAL_TOOLCHAIN if fips is enabled
                .map(PathBuf::from),
            debug: target_var("DEBUG"),
            opt_level: target_var("OPT_LEVEL"),
            android_ndk_home: target_var("ANDROID_NDK_HOME").map(Into::into),
            cmake_toolchain_file: target_var("CMAKE_TOOLCHAIN_FILE").map(Into::into),
            cpp_runtime_lib: target_var("BORING_BSSL_RUST_CPPLIB"),
            // matches the `cc` crate
            cc: target_var("CC"),
            cxx: target_var("CXX"),
            native_environment,
            docs_rs: var("DOCS_RS").is_some(),
            export_to_install_dir: boringssl_var("BORING_BSSL_INSTALL_DIR").map(PathBuf::from),
        }
    }
}

fn var(name: &str) -> Option<OsString> {
    println!("cargo:rerun-if-env-changed={name}");

    env::var_os(name)
}
