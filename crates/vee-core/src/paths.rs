//! Canonical paths that compare and convert consistently on every platform.

use std::path::{Path, PathBuf};

/// Canonicalization for every containment check and path-to-URL conversion.
///
/// `std::fs::canonicalize` returns Windows paths in verbatim form (`\\?\C:\...`),
/// which neither round-trips through `file://` URLs nor compares equal to the
/// paths that language servers and other tools report. This returns the plain
/// form whenever Windows can express the path without the prefix, and is
/// identical to `std::fs::canonicalize` elsewhere. Use it for every
/// canonicalization so that all compared paths share one form.
pub trait CanonicalPath {
    /// The canonical, absolute form of this path, with symlinks resolved.
    fn canonical(&self) -> std::io::Result<PathBuf>;
}

impl CanonicalPath for Path {
    #[allow(clippy::disallowed_methods)] // The one sanctioned canonicalization.
    fn canonical(&self) -> std::io::Result<PathBuf> {
        dunce::canonicalize(self)
    }
}

/// [`CanonicalPath::canonical`] for any path-like value.
pub fn canonicalize(path: impl AsRef<Path>) -> std::io::Result<PathBuf> {
    path.as_ref().canonical()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_paths_are_absolute_and_resolve_relative_segments() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir(directory.path().join("child")).unwrap();
        let canonical = directory.path().join("child/..").canonical().unwrap();
        assert!(canonical.is_absolute());
        assert_eq!(canonical, directory.path().canonical().unwrap());
        assert!(!canonical.to_string_lossy().starts_with(r"\\?\"));
    }
}
