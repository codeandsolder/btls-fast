#[path = "../build/copy_tree.rs"]
mod copy_tree;

use std::fs;
use std::io;
use std::path::PathBuf;
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
