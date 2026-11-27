#[path = "../build/copy_tree.rs"]
mod copy_tree;
#[path = "../build/native_input.rs"]
mod native_input;
#[path = "../build/patches.rs"]
mod patches;

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        loop {
            let path = std::env::temp_dir().join(format!(
                "btls-copy-tree-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed),
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (),
                Err(error) => return Err(error),
            }
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn copies_nested_and_empty_directories_without_overwriting() -> io::Result<()> {
    let fixture = Fixture::new()?;
    let source = fixture.0.join("source");
    let destination = fixture.0.join("destination");
    fs::create_dir_all(source.join("nested/empty"))?;
    fs::write(source.join("nested/data"), b"contents")?;
    copy_tree::copy_tree(&source, &destination)?;
    assert!(destination.join("nested/empty").is_dir());
    assert_eq!(fs::read(destination.join("nested/data"))?, b"contents");
    assert!(copy_tree::copy_tree(&source, &destination).is_err());
    Ok(())
}

#[cfg(unix)]
#[test]
fn follows_links_but_rejects_cycles() -> io::Result<()> {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new()?;
    let source = fixture.0.join("source");
    let destination = fixture.0.join("destination");
    fs::create_dir_all(source.join("nested"))?;
    fs::write(source.join("nested/data"), b"contents")?;
    symlink("nested", source.join("alias"))?;
    symlink("nested/data", source.join("file"))?;
    copy_tree::copy_tree(&source, &destination)?;
    assert_eq!(fs::read(destination.join("alias/data"))?, b"contents");
    assert_eq!(fs::read(destination.join("file"))?, b"contents");
    symlink("..", source.join("nested/cycle"))?;
    assert!(copy_tree::copy_tree(&source, &fixture.0.join("cycle")).is_err());
    Ok(())
}

#[test]
fn rejects_copy_inside_source() -> io::Result<()> {
    let fixture = Fixture::new()?;
    assert!(copy_tree::copy_tree(&fixture.0, &fixture.0.join("nested")).is_err());
    assert!(!fixture.0.join("nested").exists());
    Ok(())
}

#[test]
fn external_native_input_requires_explicit_patch_confirmation() {
    use native_input::validate_native_input as validate;

    let path = Some(Path::new("provided"));
    assert!(validate(None, None, None, false, None).is_ok());
    assert!(validate(None, None, None, true, None).is_err());
    assert!(validate(path, None, None, false, None).is_err());
    assert!(validate(None, path, None, false, None).is_err());
    assert!(validate(path, None, path, true, None).is_ok());
    assert!(validate(None, path, None, true, path).is_ok());
    assert!(validate(path, path, None, true, None).is_err());
    assert!(validate(path, None, None, true, path).is_err());
    assert!(validate(None, None, path, false, None).is_err());
    assert!(validate(None, path, path, true, None).is_err());
}

#[test]
fn requires_both_archives_and_respects_platform_layout() -> io::Result<()> {
    let fixture = Fixture::new()?;
    let root = &fixture.0;
    assert!(native_input::find_archives(root, "gnu", None).is_err());
    fs::create_dir(root.join("crypto"))?;
    fs::create_dir(root.join("ssl"))?;
    let crypto = root.join("crypto/libcrypto.a");
    let ssl = root.join("ssl/libssl.a");
    fs::write(&crypto, [])?;
    assert!(native_input::find_archives(root, "gnu", None).is_err());
    fs::write(&ssl, [])?;
    assert_eq!(
        native_input::find_archives(root, "gnu", None)?,
        [crypto, ssl]
    );
    fs::create_dir_all(root.join("lib/Release"))?;
    let crypto = root.join("lib/Release/crypto.lib");
    let ssl = root.join("lib/Release/ssl.lib");
    fs::write(&crypto, [])?;
    fs::write(&ssl, [])?;
    assert_eq!(
        native_input::find_archives(root, "msvc", Some("Release"))?,
        [crypto, ssl]
    );
    Ok(())
}

#[test]
fn archive_resolution_preserves_directory_priority() -> io::Result<()> {
    let fixture = Fixture::new()?;
    let root = &fixture.0;
    fs::create_dir(root.join("lib"))?;
    fs::create_dir(root.join("crypto"))?;
    let preferred_ssl = root.join("lib/libssl.a");
    let crypto = root.join("crypto/libcrypto.a");
    fs::write(&preferred_ssl, [])?;
    fs::write(&crypto, [])?;
    fs::write(root.join("crypto/libssl.a"), [])?;
    assert_eq!(
        native_input::find_archives(root, "gnu", None)?,
        [preferred_ssl, crypto]
    );
    Ok(())
}

#[test]
fn patch_manifest_covers_every_patch() -> io::Result<()> {
    use patches::Condition;
    use std::collections::BTreeSet;
    let series = patches::series()?;
    let listed: BTreeSet<_> = series.iter().map(|patch| patch.file.to_owned()).collect();
    let disk: BTreeSet<_> = fs::read_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("patches"))?
        .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
        .collect::<io::Result<Vec<_>>>()?
        .into_iter()
        .filter(|name| {
            Path::new(name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("patch"))
        })
        .collect();
    assert_eq!(listed, disk);
    // These are mandatory for both FIPS and normal native builds.
    for name in [
        "boringssl-rand-double-free.patch",
        "boringssl-pem-secret-cleanup.patch",
    ] {
        assert!(
            series
                .iter()
                .any(|patch| patch.file == name && patch.condition == Condition::Always)
        );
    }
    Ok(())
}
