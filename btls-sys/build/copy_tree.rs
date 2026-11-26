use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Copy a complete source directory into a new destination directory.
/// Follow source symlinks as the previous copy implementation did, but reject
/// directory cycles and non-regular files rather than recursing indefinitely
/// or blocking on a special file. Preserve file permissions via `fs::copy`.
pub(crate) fn copy_tree(source: &Path, destination: &Path) -> io::Result<()> {
    let source = source.canonicalize()?;
    let parent = destination
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "destination has no parent"))?;
    let name = destination.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "destination has no file name")
    })?;
    let destination = parent.canonicalize()?.join(name);
    if destination.starts_with(&source) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "copy destination is inside source tree",
        ));
    }
    copy_directory(&source, &destination, &destination, &mut BTreeSet::new())
}

fn copy_directory(
    source: &Path,
    destination: &Path,
    destination_root: &Path,
    ancestors: &mut BTreeSet<PathBuf>,
) -> io::Result<()> {
    let canonical = source.canonicalize()?;
    if canonical.starts_with(destination_root) || !ancestors.insert(canonical.clone()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("cyclic copy source: {}", source.display()),
        ));
    }
    // All callers supply a new destination. Never merge or overwrite a tree.
    fs::create_dir(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let from = entry.path();
        let to = destination.join(entry.file_name());
        let metadata = fs::metadata(&from)?;
        if metadata.is_dir() {
            copy_directory(&from, &to, destination_root, ancestors)?;
        } else if metadata.is_file() {
            if to.try_exists()? {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    to.display().to_string(),
                ));
            }
            fs::copy(&from, &to)?;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("not a regular file or directory: {}", from.display()),
            ));
        }
    }
    ancestors.remove(&canonical);
    Ok(())
}
