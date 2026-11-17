use std::{
    path::{Path, PathBuf},
    process::Command,
};
use vero_core::{snapshot_files, snapshot_index_files, ChangeSet};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChangeScope {
    Staged,
    WorkingTree,
    BaseAndWorktree { base_oid: Option<String> },
    Commit { oid: String },
    CommitRange { from: String, to: String },
}

impl ChangeScope {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Staged => "staged",
            Self::WorkingTree => "working_tree",
            Self::BaseAndWorktree { .. } => "base_and_worktree",
            Self::Commit { .. } => "commit",
            Self::CommitRange { .. } => "commit_range",
        }
    }

    fn staged(&self) -> bool {
        matches!(self, Self::Staged)
    }
}

pub fn commit_scope(specification: &str) -> Result<ChangeScope, String> {
    if let Some((from, to)) = specification.split_once("..") {
        if from.trim().is_empty() || to.trim().is_empty() || to.contains("..") {
            return Err("commit range must be FROM..TO with both refs specified".into());
        }
        Ok(ChangeScope::CommitRange {
            from: from.to_string(),
            to: to.to_string(),
        })
    } else if specification.trim().is_empty() {
        Err("commit ref cannot be empty".into())
    } else {
        Ok(ChangeScope::Commit {
            oid: specification.to_string(),
        })
    }
}

pub fn repository_root(path: &Path) -> Result<PathBuf, String> {
    let output = git(path, &["rev-parse", "--show-toplevel"])?;
    let root = String::from_utf8(output).map_err(|error| error.to_string())?;
    Ok(PathBuf::from(root.trim()))
}

pub fn merge_base(path: &Path, base_ref: &str) -> Result<String, String> {
    let output = git(path, &["merge-base", base_ref, "HEAD"])?;
    String::from_utf8(output)
        .map(|value| value.trim().to_string())
        .map_err(|error| error.to_string())
}

pub fn tracked_paths(path: &Path) -> Result<Vec<PathBuf>, String> {
    let root = repository_root(path)?;
    let output = git(&root, &["ls-files", "-z"])?;
    let mut paths = Vec::new();
    add_paths(&mut paths, output)?;
    paths.sort();
    paths.dedup();
    Ok(paths)
}

/// Whether commands run from the checkout would observe the staged index tree for
/// tracked files, with no non-ignored untracked files that could affect results.
pub fn working_tree_matches_index(path: &Path) -> Result<bool, String> {
    let root = repository_root(path)?;
    let unstaged = git(
        &root,
        &["diff", "--ignore-submodules=none", "--name-only", "-z"],
    )?;
    if !unstaged.is_empty() {
        return Ok(false);
    }
    let untracked = git(&root, &["ls-files", "--others", "--exclude-standard", "-z"])?;
    Ok(untracked.is_empty())
}

pub fn read_head_file(root: &Path, relative: &Path) -> Result<Option<Vec<u8>>, String> {
    read_tree_file(root, "HEAD", relative)
}

pub fn read_tree_file(
    root: &Path,
    treeish: &str,
    relative: &Path,
) -> Result<Option<Vec<u8>>, String> {
    validate_relative_path(relative)?;
    let spec = format!("{treeish}:{}", relative.to_string_lossy());
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["show", spec.as_str()])
        .output()
        .map_err(|error| error.to_string())?;
    if output.status.success() {
        Ok(Some(output.stdout))
    } else {
        Ok(None)
    }
}

/// Read a file from a commit or commit-range snapshot's endpoint tree.
pub fn read_snapshot_tree_file(
    root: &Path,
    change_set: &ChangeSet,
    relative: &Path,
) -> Result<Option<Vec<u8>>, String> {
    validate_relative_path(relative)?;
    let normalized = relative.to_string_lossy().replace('\\', "/");
    if let Some(entry) = change_set.files.iter().find(|file| file.path == normalized) {
        if entry.status == "deleted" {
            return Ok(None);
        }
        let bytes = read_captured_file(root, &change_set.scope, relative)?
            .ok_or_else(|| format!("snapshot file is missing: {normalized}"))?;
        if vero_core::digest(&bytes) != entry.content_digest {
            return Err(format!("snapshot file changed after capture: {normalized}"));
        }
        return Ok(Some(bytes));
    }
    if change_set.scope == "working_tree" || change_set.scope == "base_and_worktree" {
        let captured_head = change_set
            .head_oid
            .as_deref()
            .ok_or("working-tree snapshot is missing captured HEAD")?;
        let current_head = String::from_utf8(git(root, &["rev-parse", "HEAD"])?)
            .map_err(|error| error.to_string())?;
        if current_head.trim() != captured_head {
            return Err("repository HEAD changed after working-tree snapshot capture".into());
        }
    }
    let treeish = if let Some(range) = change_set.scope.strip_prefix("commit_range:") {
        range
            .split_once("..")
            .ok_or("invalid stored commit range")?
            .1
    } else if change_set.scope.starts_with("commit:") {
        change_set
            .head_oid
            .as_deref()
            .ok_or("commit snapshot is missing its commit OID")?
    } else if change_set.scope == "staged" {
        return read_captured_file(root, "staged", relative);
    } else if change_set.scope == "working_tree" || change_set.scope == "base_and_worktree" {
        let head = change_set
            .head_oid
            .as_deref()
            .ok_or("working-tree snapshot is missing captured HEAD")?;
        match read_tree_file(root, head, relative)? {
            Some(bytes) => return Ok(Some(bytes)),
            None => return read_captured_file(root, &change_set.scope, relative),
        }
    } else {
        return Err(
            "snapshot does not retain an immutable tree for unchanged source context".into(),
        );
    };
    read_tree_file(root, treeish, relative)
}

/// Read a file as represented by a captured ChangeSet. Changed files are verified
/// against their manifest digest; unchanged files are read from the captured HEAD OID.
pub fn read_snapshot_file(
    root: &Path,
    change_set: &ChangeSet,
    relative: &Path,
) -> Result<Option<Vec<u8>>, String> {
    validate_relative_path(relative)?;
    let normalized = relative.to_string_lossy().replace('\\', "/");
    if let Some(entry) = change_set.files.iter().find(|file| file.path == normalized) {
        if entry.status == "deleted" {
            return Ok(None);
        }
        let bytes = read_captured_file(root, &change_set.scope, relative)?
            .ok_or_else(|| format!("snapshot file is missing: {normalized}"))?;
        let observed = vero_core::digest(&bytes);
        if observed != entry.content_digest {
            return Err(format!("snapshot file changed after capture: {normalized}"));
        }
        return Ok(Some(bytes));
    }
    if let Some(head) = change_set.head_oid.as_deref() {
        read_tree_file(root, head, relative)
    } else {
        Ok(None)
    }
}

/// Read the comparison-side bytes for a changed path from the snapshot's Git base.
/// Working-tree and staged scopes use the captured HEAD; commit and range scopes use
/// their recorded parent/from OID. Added paths have no baseline and return `None`.
pub fn read_snapshot_base_file(
    root: &Path,
    change_set: &ChangeSet,
    relative: &Path,
) -> Result<Option<Vec<u8>>, String> {
    validate_relative_path(relative)?;
    let Some(base_oid) = change_set.base_oid.as_deref() else {
        return Ok(None);
    };
    read_tree_file(root, base_oid, relative)
}

pub fn capture(path: &Path, scope: ChangeScope) -> Result<ChangeSet, String> {
    let root = repository_root(path)?;
    if let ChangeScope::Commit { oid } = &scope {
        return capture_commit(&root, oid);
    }
    if let ChangeScope::CommitRange { from, to } = &scope {
        return capture_commit_range(&root, from, to);
    }
    let head = String::from_utf8(git(&root, &["rev-parse", "HEAD"])?)
        .map_err(|error| error.to_string())?
        .trim()
        .to_string();
    let mut paths = Vec::<PathBuf>::new();
    match &scope {
        ChangeScope::Staged => add_paths(
            &mut paths,
            git(
                &root,
                &[
                    "diff",
                    "--cached",
                    "--ignore-submodules=none",
                    "--no-renames",
                    "--name-only",
                    "-z",
                ],
            )?,
        )?,
        ChangeScope::WorkingTree => {
            add_paths(
                &mut paths,
                git(
                    &root,
                    &[
                        "diff",
                        "--ignore-submodules=none",
                        "--no-renames",
                        "--name-only",
                        "-z",
                    ],
                )?,
            )?;
            add_paths(
                &mut paths,
                git(&root, &["ls-files", "--others", "--exclude-standard", "-z"])?,
            )?;
        }
        ChangeScope::BaseAndWorktree { base_oid } => {
            if let Some(base) = base_oid {
                add_paths(
                    &mut paths,
                    git(
                        &root,
                        &[
                            "diff",
                            "--ignore-submodules=none",
                            "--no-renames",
                            "--name-only",
                            "-z",
                            base,
                            "HEAD",
                        ],
                    )?,
                )?;
            }
            add_paths(
                &mut paths,
                git(
                    &root,
                    &[
                        "diff",
                        "--ignore-submodules=none",
                        "--no-renames",
                        "--name-only",
                        "-z",
                        "HEAD",
                    ],
                )?,
            )?;
            add_paths(
                &mut paths,
                git(&root, &["ls-files", "--others", "--exclude-standard", "-z"])?,
            )?;
        }
        ChangeScope::Commit { .. } => unreachable!("commit scopes returned above"),
        ChangeScope::CommitRange { .. } => unreachable!("commit range scopes returned above"),
    }
    paths.retain(|path| {
        path.components()
            .next()
            .is_none_or(|component| component.as_os_str() != ".vero")
            && path != Path::new(".vero.yaml")
    });
    paths.sort();
    paths.dedup();
    let files = if scope.staged() {
        snapshot_index_files(&root, &paths)?
    } else {
        snapshot_worktree_files(&root, &paths)?
    };
    let head_after = String::from_utf8(git(&root, &["rev-parse", "HEAD"])?)
        .map_err(|error| error.to_string())?
        .trim()
        .to_string();
    if head != head_after {
        return Err("HEAD changed while the change snapshot was being captured".into());
    }
    let base = match &scope {
        ChangeScope::Staged | ChangeScope::WorkingTree => Some(head.clone()),
        ChangeScope::BaseAndWorktree { base_oid } => {
            base_oid.clone().or_else(|| Some(head.clone()))
        }
        ChangeScope::Commit { .. } => unreachable!("commit scopes returned above"),
        ChangeScope::CommitRange { .. } => unreachable!("commit range scopes returned above"),
    };
    let mut change_set = ChangeSet::from_entries(base, Some(head), scope.name(), files);
    if matches!(
        scope,
        ChangeScope::WorkingTree | ChangeScope::BaseAndWorktree { .. }
    ) {
        let ignored = git(
            &root,
            &[
                "ls-files",
                "--others",
                "--ignored",
                "--exclude-standard",
                "-z",
            ],
        )?;
        let mut ignored_paths = Vec::new();
        add_paths(&mut ignored_paths, ignored)?;
        ignored_paths.sort();
        ignored_paths.dedup();
        if !ignored_paths.is_empty() {
            change_set.warnings.push(format!(
                "{} ignored untracked path(s) were excluded by Git ignore rules",
                ignored_paths.len()
            ));
        }
    }
    Ok(change_set)
}

fn snapshot_worktree_files(
    root: &Path,
    paths: &[PathBuf],
) -> Result<Vec<vero_core::SnapshotFile>, String> {
    let mut files = snapshot_files(root, paths)?;
    let canonical_root = std::fs::canonicalize(root).map_err(|error| error.to_string())?;
    for relative in paths {
        let candidate = root.join(relative);
        match std::fs::symlink_metadata(&candidate) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            _ => continue,
        }
        let canonical_candidate = std::fs::canonicalize(&candidate).map_err(|error| {
            format!(
                "resolving possible submodule {}: {error}",
                relative.display()
            )
        })?;
        if !canonical_candidate.starts_with(&canonical_root) {
            return Err(format!(
                "submodule path escapes repository root: {}",
                relative.display()
            ));
        }
        let submodule_root = match repository_root(&candidate) {
            Ok(path) => std::fs::canonicalize(path).map_err(|error| error.to_string())?,
            Err(_) => continue,
        };
        if submodule_root != canonical_candidate {
            continue;
        }
        let commit_before = String::from_utf8(git(&candidate, &["rev-parse", "HEAD"])?)
            .map_err(|error| error.to_string())?
            .trim()
            .to_string();
        let status = git(
            &candidate,
            &[
                "status",
                "--porcelain",
                "--untracked-files=all",
                "--ignore-submodules=none",
            ],
        )?;
        if !status.is_empty() {
            return Err(format!(
                "submodule worktree is dirty and cannot be snapshotted by commit OID: {}",
                relative.display()
            ));
        }
        let commit_after = String::from_utf8(git(&candidate, &["rev-parse", "HEAD"])?)
            .map_err(|error| error.to_string())?
            .trim()
            .to_string();
        if commit_before != commit_after {
            return Err(format!(
                "submodule HEAD changed while snapshot was being captured: {}",
                relative.display()
            ));
        }
        let path = relative.to_string_lossy().replace('\\', "/");
        files.retain(|file| file.path != path);
        files.push(vero_core::SnapshotFile {
            path,
            mode: 0o160000,
            content_digest: vero_core::digest(commit_after.as_bytes()),
            status: "submodule".into(),
        });
    }
    files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(files)
}

pub fn capture_current(path: &Path, previous: &ChangeSet) -> Result<ChangeSet, String> {
    let scope = match previous.scope.as_str() {
        "staged" => ChangeScope::Staged,
        "working_tree" => ChangeScope::WorkingTree,
        scope if scope.starts_with("commit:") => {
            return capture_commit_snapshot(path, previous);
        }
        scope if scope.starts_with("commit_range:") => {
            let range = scope.strip_prefix("commit_range:").unwrap_or_default();
            let (from, to) = range
                .split_once("..")
                .ok_or("invalid stored commit range")?;
            return capture_commit_range(path, from, to);
        }
        _ => ChangeScope::BaseAndWorktree {
            base_oid: previous.base_oid.clone(),
        },
    };
    capture(path, scope)
}

fn capture_commit_snapshot(root: &Path, previous: &ChangeSet) -> Result<ChangeSet, String> {
    let oid = previous
        .head_oid
        .as_deref()
        .ok_or("commit snapshot is missing its commit OID")?;
    capture_commit(root, oid)
}

fn resolve_commit(root: &Path, requested: &str) -> Result<String, String> {
    String::from_utf8(git(
        root,
        &[
            "rev-parse",
            "--verify",
            "--end-of-options",
            &format!("{requested}^{{commit}}"),
        ],
    )?)
    .map(|value| value.trim().to_string())
    .map_err(|error| error.to_string())
}

fn capture_commit_range(root: &Path, from: &str, to: &str) -> Result<ChangeSet, String> {
    let from_oid = resolve_commit(root, from)?;
    let to_oid = resolve_commit(root, to)?;
    let mut changed = Vec::new();
    add_paths(
        &mut changed,
        git(
            root,
            &[
                "diff",
                "--name-only",
                "--no-renames",
                "--ignore-submodules=none",
                "-z",
                &from_oid,
                &to_oid,
            ],
        )?,
    )?;
    changed.sort();
    changed.dedup();
    let files = snapshot_tree_files(root, &to_oid, &changed)?;
    Ok(ChangeSet::from_entries(
        Some(from_oid.clone()),
        Some(to_oid.clone()),
        format!("commit_range:{from_oid}..{to_oid}"),
        files,
    ))
}

fn capture_commit(root: &Path, requested: &str) -> Result<ChangeSet, String> {
    let oid = resolve_commit(root, requested)?;
    let parents = String::from_utf8(git(root, &["rev-list", "--parents", "-n", "1", &oid])?)
        .map_err(|error| error.to_string())?;
    let mut fields = parents.split_whitespace();
    let commit_oid = fields
        .next()
        .ok_or("git returned an invalid commit")?
        .to_string();
    let parent = fields.next().map(str::to_string);
    let mut changed = Vec::new();
    if let Some(parent_oid) = parent.as_deref() {
        add_paths(
            &mut changed,
            git(
                root,
                &[
                    "diff",
                    "--name-only",
                    "--no-renames",
                    "--ignore-submodules=none",
                    "-z",
                    parent_oid,
                    &commit_oid,
                ],
            )?,
        )?;
    } else {
        add_paths(
            &mut changed,
            git(
                root,
                &[
                    "diff-tree",
                    "--root",
                    "--no-commit-id",
                    "--name-only",
                    "--no-renames",
                    "-r",
                    "-z",
                    &commit_oid,
                ],
            )?,
        )?;
    }
    changed.sort();
    changed.dedup();
    let files = snapshot_tree_files(root, &commit_oid, &changed)?;
    Ok(ChangeSet::from_entries(
        parent,
        Some(commit_oid.clone()),
        format!("commit:{commit_oid}"),
        files,
    ))
}

fn snapshot_tree_files(
    root: &Path,
    commit: &str,
    paths: &[PathBuf],
) -> Result<Vec<vero_core::SnapshotFile>, String> {
    let output = git(root, &["ls-tree", "-rz", "--full-tree", commit])?;
    let mut entries = std::collections::BTreeMap::<String, (u32, String)>::new();
    for raw in output
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
    {
        let Some(tab) = raw.iter().position(|byte| *byte == b'\t') else {
            return Err("malformed Git tree entry".into());
        };
        let metadata =
            std::str::from_utf8(&raw[..tab]).map_err(|_| "non-UTF8 Git tree metadata")?;
        let mut fields = metadata.split_whitespace();
        let mode = u32::from_str_radix(fields.next().ok_or("missing tree mode")?, 8)
            .map_err(|_| "invalid tree mode")?;
        let kind = fields.next().ok_or("missing tree object kind")?;
        let oid = fields.next().ok_or("missing tree object ID")?.to_string();
        let path = String::from_utf8_lossy(&raw[tab + 1..]).replace('\\', "/");
        if kind == "blob" {
            entries.insert(path, (mode, oid));
        }
    }
    let mut files = Vec::with_capacity(paths.len());
    for relative in paths {
        validate_relative_path(relative)?;
        let path = relative.to_string_lossy().replace('\\', "/");
        if let Some((mode, oid)) = entries.get(&path) {
            let bytes = git(root, &["cat-file", "blob", oid])?;
            files.push(vero_core::SnapshotFile {
                path,
                mode: *mode,
                content_digest: vero_core::digest(&bytes),
                status: if *mode == 0o120000 {
                    "symlink"
                } else {
                    "present"
                }
                .into(),
            });
        } else {
            files.push(vero_core::SnapshotFile {
                path,
                mode: 0,
                content_digest: "deleted".into(),
                status: "deleted".into(),
            });
        }
    }
    Ok(files)
}

pub fn read_captured_file(
    root: &Path,
    scope: &str,
    relative: &Path,
) -> Result<Option<Vec<u8>>, String> {
    validate_relative_path(relative)?;
    if scope.starts_with("commit:") || scope.starts_with("commit_range:") {
        let oid = if let Some(oid) = scope.strip_prefix("commit:") {
            oid
        } else {
            let range = scope.strip_prefix("commit_range:").unwrap_or_default();
            range
                .split_once("..")
                .ok_or("invalid stored commit range")?
                .1
        };
        let spec = format!("{oid}:{}", relative.to_string_lossy());
        let output = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["show", spec.as_str()])
            .output()
            .map_err(|error| error.to_string())?;
        if output.status.success() {
            Ok(Some(output.stdout))
        } else {
            Ok(None)
        }
    } else if scope == "staged" {
        let path = format!(":{}", relative.to_string_lossy());
        let output = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["show", path.as_str()])
            .output()
            .map_err(|error| error.to_string())?;
        if output.status.success() {
            Ok(Some(output.stdout))
        } else {
            Ok(None)
        }
    } else {
        let canonical_root = std::fs::canonicalize(root).map_err(|error| error.to_string())?;
        let path = root.join(relative);
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("reading {}: {error}", relative.display())),
        };
        if metadata.file_type().is_symlink() {
            let parent = path.parent().unwrap_or(root);
            let canonical_parent =
                std::fs::canonicalize(parent).map_err(|error| error.to_string())?;
            if !canonical_parent.starts_with(&canonical_root) {
                return Err(format!(
                    "path escapes repository root through a symlink: {}",
                    relative.display()
                ));
            }
            let target = std::fs::read_link(&path).map_err(|error| error.to_string())?;
            return Ok(Some(target.to_string_lossy().as_bytes().to_vec()));
        }
        let canonical_path = std::fs::canonicalize(&path).map_err(|error| error.to_string())?;
        if !canonical_path.starts_with(&canonical_root) {
            return Err(format!(
                "path escapes repository root through a symlink: {}",
                relative.display()
            ));
        }
        std::fs::read(canonical_path)
            .map(Some)
            .map_err(|error| format!("reading {}: {error}", relative.display()))
    }
}

fn validate_relative_path(relative: &Path) -> Result<(), String> {
    if relative.is_absolute()
        || relative.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        })
    {
        return Err(format!(
            "path escapes repository root: {}",
            relative.display()
        ));
    }
    Ok(())
}

fn add_paths(paths: &mut Vec<PathBuf>, bytes: Vec<u8>) -> Result<(), String> {
    for path in bytes
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
    {
        let path = std::str::from_utf8(path)
            .map_err(|error| format!("Git returned a non-UTF-8 path: {error}"))?;
        paths.push(PathBuf::from(path));
    }
    Ok(())
}

fn git(path: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(path)
        .args(args)
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(format!("git command failed: {}", args.join(" ")));
    }
    Ok(output.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    struct Repo(tempfile::TempDir);
    impl Repo {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let repo = Self(dir);
            repo.git(&["init", "-q"]);
            repo.git(&["config", "user.email", "vero@example.invalid"]);
            repo.git(&["config", "user.name", "Vero test"]);
            fs::write(repo.path().join("tracked.rs"), "fn main() {}\n").unwrap();
            repo.git(&["add", "tracked.rs"]);
            repo.git(&["commit", "-qm", "initial"]);
            repo
        }
        fn path(&self) -> &Path {
            self.0.path()
        }
        fn git(&self, args: &[&str]) {
            assert!(Command::new("git")
                .arg("-C")
                .arg(self.path())
                .args(args)
                .status()
                .unwrap()
                .success());
        }
    }

    #[test]
    fn working_tree_scope_captures_unstaged_and_untracked_but_excludes_staged_only() {
        let repo = Repo::new();
        fs::write(repo.path().join("tracked.rs"), "fn main() { let _ = 1; }\n").unwrap();
        fs::write(repo.path().join("new.rs"), "fn new() {}\n").unwrap();
        fs::write(repo.path().join(".vero.yaml"), "version: 1\n").unwrap();
        fs::create_dir_all(repo.path().join(".vero")).unwrap();
        fs::write(repo.path().join(".vero/cache"), "state").unwrap();

        let change = capture(repo.path(), ChangeScope::WorkingTree).unwrap();

        let paths: Vec<_> = change.files.iter().map(|file| file.path.as_str()).collect();
        assert_eq!(paths, vec!["new.rs", "tracked.rs"]);
    }

    #[test]
    fn working_tree_capture_reports_ignored_untracked_paths() {
        let repo = Repo::new();
        fs::write(repo.path().join(".gitignore"), "secret.local\n").unwrap();
        repo.git(&["add", ".gitignore"]);
        repo.git(&["commit", "-qm", "ignore local secret"]);
        fs::write(repo.path().join("secret.local"), "ignored\n").unwrap();

        let change = capture(repo.path(), ChangeScope::WorkingTree).unwrap();

        assert!(change.files.is_empty());
        assert_eq!(change.warnings.len(), 1);
        assert!(change.warnings[0].contains("ignored untracked path(s)"));
    }

    #[test]
    fn snapshots_identify_lfs_pointer_blobs_without_fetching_them() {
        let repo = Repo::new();
        let pointer =
            b"version https://git-lfs.github.com/spec/v1\noid sha256:0123456789abcdef\nsize 42\n";
        fs::write(repo.path().join("large.bin"), pointer).unwrap();

        let worktree = capture(repo.path(), ChangeScope::WorkingTree).unwrap();
        let entry = worktree
            .files
            .iter()
            .find(|file| file.path == "large.bin")
            .unwrap();
        assert_eq!(entry.status, "lfs_pointer");
        assert!(worktree
            .warnings
            .iter()
            .any(|warning| warning.contains("object contents were not fetched")));

        repo.git(&["add", "large.bin"]);
        let staged = capture(repo.path(), ChangeScope::Staged).unwrap();
        assert_eq!(staged.files[0].status, "lfs_pointer");
        assert!(staged
            .warnings
            .iter()
            .any(|warning| warning.contains("Git LFS pointer")));
    }

    #[test]
    fn staged_scope_reads_index_content_even_when_worktree_has_more_edits() {
        let repo = Repo::new();
        fs::write(repo.path().join("tracked.rs"), "fn main() { let _ = 1; }\n").unwrap();
        repo.git(&["add", "tracked.rs"]);
        fs::write(repo.path().join("tracked.rs"), "fn main() { let _ = 2; }\n").unwrap();

        let change = capture(repo.path(), ChangeScope::Staged).unwrap();

        assert_eq!(change.files.len(), 1);
        assert_eq!(
            change.files[0].content_digest,
            vero_core::digest(b"fn main() { let _ = 1; }\n")
        );
    }

    #[test]
    fn index_match_check_rejects_unstaged_and_untracked_worktree_content() {
        let repo = Repo::new();
        assert!(working_tree_matches_index(repo.path()).unwrap());

        fs::write(repo.path().join("tracked.rs"), "fn staged() {}\n").unwrap();
        repo.git(&["add", "tracked.rs"]);
        assert!(working_tree_matches_index(repo.path()).unwrap());

        fs::write(repo.path().join("tracked.rs"), "fn unstaged() {}\n").unwrap();
        assert!(!working_tree_matches_index(repo.path()).unwrap());

        fs::write(repo.path().join("tracked.rs"), "fn staged() {}\n").unwrap();
        fs::write(repo.path().join("untracked.rs"), "fn untracked() {}\n").unwrap();
        assert!(!working_tree_matches_index(repo.path()).unwrap());
    }

    #[test]
    fn capture_current_preserves_prior_scope_and_base() {
        let repo = Repo::new();
        let base = String::from_utf8(
            Command::new("git")
                .arg("-C")
                .arg(repo.path())
                .args(["rev-parse", "HEAD"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_owned();
        let prior = ChangeSet::from_entries(Some(base.clone()), Some(base), "working_tree", vec![]);
        fs::write(repo.path().join("tracked.rs"), "fn main() { let _ = 1; }\n").unwrap();

        let current = capture_current(repo.path(), &prior).unwrap();

        assert_eq!(current.scope, "working_tree");
        assert_eq!(current.files.len(), 1);
    }

    #[test]
    fn base_scope_includes_committed_branch_changes_and_current_worktree_bytes() {
        let repo = Repo::new();
        let base = String::from_utf8(
            Command::new("git")
                .arg("-C")
                .arg(repo.path())
                .args(["rev-parse", "HEAD"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_owned();
        fs::write(repo.path().join("tracked.rs"), "fn committed_change() {}\n").unwrap();
        repo.git(&["add", "tracked.rs"]);
        repo.git(&["commit", "-qm", "branch change"]);
        fs::write(
            repo.path().join("tracked.rs"),
            "fn working_tree_change() {}\n",
        )
        .unwrap();

        let change = capture(
            repo.path(),
            ChangeScope::BaseAndWorktree {
                base_oid: Some(base.clone()),
            },
        )
        .unwrap();

        assert_eq!(change.base_oid.as_deref(), Some(base.as_str()));
        assert_eq!(change.files.len(), 1);
        assert_eq!(
            change.files[0].content_digest,
            vero_core::digest(b"fn working_tree_change() {}\n")
        );
    }

    #[test]
    fn base_scope_manifest_records_both_sides_of_a_rename() {
        let repo = Repo::new();
        let base = String::from_utf8(
            Command::new("git")
                .arg("-C")
                .arg(repo.path())
                .args(["rev-parse", "HEAD"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_owned();
        repo.git(&["mv", "tracked.rs", "renamed.rs"]);

        let change = capture(
            repo.path(),
            ChangeScope::BaseAndWorktree {
                base_oid: Some(base),
            },
        )
        .unwrap();

        let entries: Vec<_> = change
            .files
            .iter()
            .map(|file| (file.path.as_str(), file.status.as_str()))
            .collect();
        assert_eq!(
            entries,
            vec![("renamed.rs", "present"), ("tracked.rs", "deleted")]
        );
    }

    #[test]
    fn staged_scope_manifest_records_both_sides_of_a_rename() {
        let repo = Repo::new();
        repo.git(&["mv", "tracked.rs", "renamed.rs"]);

        let change = capture(repo.path(), ChangeScope::Staged).unwrap();

        let entries: Vec<_> = change
            .files
            .iter()
            .map(|file| (file.path.as_str(), file.status.as_str()))
            .collect();
        assert_eq!(
            entries,
            vec![("renamed.rs", "present"), ("tracked.rs", "deleted")]
        );
    }

    #[test]
    fn worktree_scope_records_changed_submodule_commit_oid() {
        let repo = Repo::new();
        let checked_out_submodule = repo.path().join("modules/dep");
        fs::create_dir_all(&checked_out_submodule).unwrap();
        assert!(Command::new("git")
            .arg("init")
            .arg("-q")
            .arg(&checked_out_submodule)
            .status()
            .unwrap()
            .success());
        for (key, value) in [
            ("user.email", "vero@example.invalid"),
            ("user.name", "Vero test"),
        ] {
            assert!(Command::new("git")
                .arg("-C")
                .arg(&checked_out_submodule)
                .args(["config", key, value])
                .status()
                .unwrap()
                .success());
        }
        fs::write(checked_out_submodule.join("dep.rs"), "fn first() {}\n").unwrap();
        let nested_git = |args: &[&str]| {
            assert!(Command::new("git")
                .arg("-C")
                .arg(&checked_out_submodule)
                .args(args)
                .status()
                .unwrap()
                .success());
        };
        nested_git(&["add", "."]);
        nested_git(&["commit", "-qm", "first"]);
        let initial_oid = String::from_utf8(
            Command::new("git")
                .arg("-C")
                .arg(&checked_out_submodule)
                .args(["rev-parse", "HEAD"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_owned();
        fs::write(
            repo.path().join(".gitmodules"),
            "[submodule \"modules/dep\"]\n\tpath = modules/dep\n\turl = ../dep\n",
        )
        .unwrap();
        repo.git(&["add", ".gitmodules"]);
        let gitlink = format!("160000,{initial_oid},modules/dep");
        repo.git(&["update-index", "--add", "--cacheinfo", &gitlink]);
        repo.git(&["commit", "-qam", "add submodule"]);

        fs::write(checked_out_submodule.join("dep.rs"), "fn second() {}\n").unwrap();
        let submodule_git = |args: &[&str]| {
            assert!(Command::new("git")
                .arg("-C")
                .arg(&checked_out_submodule)
                .args(args)
                .status()
                .unwrap()
                .success());
        };
        submodule_git(&["add", "."]);
        submodule_git(&["commit", "-qm", "second"]);
        let expected_oid = String::from_utf8(
            Command::new("git")
                .arg("-C")
                .arg(&checked_out_submodule)
                .args(["rev-parse", "HEAD"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_owned();

        repo.git(&["config", "diff.ignoreSubmodules", "all"]);

        let change = capture(repo.path(), ChangeScope::WorkingTree).unwrap();

        let submodule = change
            .files
            .iter()
            .find(|file| file.path == "modules/dep")
            .expect("changed submodule must be included in the manifest");
        assert_eq!(submodule.status, "submodule");
        assert_eq!(submodule.mode, 0o160000);
        assert_eq!(
            submodule.content_digest,
            vero_core::digest(expected_oid.as_bytes())
        );

        fs::write(checked_out_submodule.join("dep.rs"), "fn dirty() {}\n").unwrap();
        let error = capture(repo.path(), ChangeScope::WorkingTree).unwrap_err();
        assert!(error.contains("submodule worktree is dirty"));
    }

    #[test]
    fn commit_scope_captures_immutable_tree_and_revalidates_same_commit() {
        let repo = Repo::new();
        fs::write(repo.path().join("tracked.rs"), "fn committed() {}\n").unwrap();
        repo.git(&["add", "tracked.rs"]);
        repo.git(&["commit", "-qm", "target commit"]);
        let oid = String::from_utf8(
            Command::new("git")
                .arg("-C")
                .arg(repo.path())
                .args(["rev-parse", "HEAD"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_owned();
        fs::write(repo.path().join("tracked.rs"), "fn dirty_worktree() {}\n").unwrap();

        let change = capture(repo.path(), ChangeScope::Commit { oid: oid.clone() }).unwrap();
        let source = read_captured_file(repo.path(), &change.scope, Path::new("tracked.rs"))
            .unwrap()
            .unwrap();
        let current = capture_current(repo.path(), &change).unwrap();

        assert_eq!(source, b"fn committed() {}\n");
        assert_eq!(change.digest, current.digest);
        assert!(change.scope.starts_with("commit:"));
    }

    #[test]
    fn commit_range_uses_endpoint_tree_and_revalidates_range_after_worktree_edits() {
        let repo = Repo::new();
        let from = String::from_utf8(
            Command::new("git")
                .arg("-C")
                .arg(repo.path())
                .args(["rev-parse", "HEAD"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_owned();
        fs::write(repo.path().join("tracked.rs"), "fn in_range() {}\n").unwrap();
        repo.git(&["add", "tracked.rs"]);
        repo.git(&["commit", "-qm", "range endpoint"]);
        let to = String::from_utf8(
            Command::new("git")
                .arg("-C")
                .arg(repo.path())
                .args(["rev-parse", "HEAD"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_owned();
        fs::write(repo.path().join("tracked.rs"), "fn outside_range() {}\n").unwrap();

        let scope = commit_scope(&format!("{from}..{to}")).unwrap();
        let change = capture(repo.path(), scope).unwrap();
        let source = read_captured_file(repo.path(), &change.scope, Path::new("tracked.rs"))
            .unwrap()
            .unwrap();
        let current = capture_current(repo.path(), &change).unwrap();

        assert_eq!(source, b"fn in_range() {}\n");
        assert_eq!(change.digest, current.digest);
        assert_eq!(change.base_oid.as_deref(), Some(from.as_str()));
        assert_eq!(change.head_oid.as_deref(), Some(to.as_str()));
        assert!(change.scope.starts_with("commit_range:"));
    }

    #[test]
    fn rejects_malformed_commit_range_specifications() {
        assert!(commit_scope("..HEAD").is_err());
        assert!(commit_scope("HEAD..").is_err());
        assert!(commit_scope("A..B..C").is_err());
    }

    #[test]
    fn snapshot_reader_rejects_worktree_content_changed_after_capture() {
        let repo = Repo::new();
        fs::write(repo.path().join("tracked.rs"), "fn captured() {}\n").unwrap();
        let snapshot = capture(repo.path(), ChangeScope::WorkingTree).unwrap();
        fs::write(
            repo.path().join("tracked.rs"),
            "fn changed_after_capture() {}\n",
        )
        .unwrap();

        let error =
            read_snapshot_file(repo.path(), &snapshot, Path::new("tracked.rs")).unwrap_err();

        assert!(error.contains("changed after capture"));
    }

    #[cfg(unix)]
    #[test]
    fn context_read_does_not_follow_symlink_outside_repository() {
        let repo = Repo::new();
        let outside = tempfile::NamedTempFile::new().unwrap();
        fs::write(outside.path(), "secret contents").unwrap();
        std::os::unix::fs::symlink(outside.path(), repo.path().join("link.rs")).unwrap();

        let bytes = read_captured_file(repo.path(), "working_tree", Path::new("link.rs"))
            .unwrap()
            .unwrap();

        assert_eq!(bytes, outside.path().to_string_lossy().as_bytes());
        assert!(!String::from_utf8(bytes)
            .unwrap()
            .contains("secret contents"));
    }
}
