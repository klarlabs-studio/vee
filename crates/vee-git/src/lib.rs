use std::{
    path::{Path, PathBuf},
    process::Command,
};
use vee_core::{digest, is_lfs_pointer, ChangeSet, SnapshotFile};

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

/// Reject a caller-supplied revision that git could parse as an option (leading
/// `-`), or that is empty or contains whitespace or control characters. Callers pass
/// revisions from the CLI, MCP, and HTTP API, so this is the injection boundary.
pub fn validate_revision(revision: &str) -> Result<(), String> {
    if revision.is_empty() {
        return Err("revision cannot be empty".into());
    }
    if revision.starts_with('-') {
        return Err(format!("revision {revision:?} must not start with '-'"));
    }
    if revision
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(format!(
            "revision {revision:?} must not contain whitespace or control characters"
        ));
    }
    Ok(())
}

pub fn commit_scope(specification: &str) -> Result<ChangeScope, String> {
    if let Some((from, to)) = specification.split_once("..") {
        if from.trim().is_empty() || to.trim().is_empty() || to.contains("..") {
            return Err("commit range must be FROM..TO with both refs specified".into());
        }
        validate_revision(from)?;
        validate_revision(to)?;
        Ok(ChangeScope::CommitRange {
            from: from.to_string(),
            to: to.to_string(),
        })
    } else if specification.trim().is_empty() {
        Err("commit ref cannot be empty".into())
    } else {
        validate_revision(specification)?;
        Ok(ChangeScope::Commit {
            oid: specification.to_string(),
        })
    }
}

pub fn repository_root(path: &Path) -> Result<PathBuf, String> {
    let output = git(path, &["rev-parse", "--show-toplevel"]).map_err(|error| {
        if error.starts_with("git command failed") {
            format!("{} is not inside a Git repository", path.display())
        } else {
            error
        }
    })?;
    let root = String::from_utf8(output).map_err(|error| error.to_string())?;
    Ok(PathBuf::from(root.trim()))
}

pub fn merge_base(path: &Path, base_ref: &str) -> Result<String, String> {
    validate_revision(base_ref)?;
    let output = git(path, &["merge-base", base_ref, "HEAD"])?;
    String::from_utf8(output)
        .map(|value| value.trim().to_string())
        .map_err(|error| error.to_string())
}

/// The merge base of two commits, or `None` when either is not available
/// locally or they share no history.
pub fn merge_base_of(path: &Path, left: &str, right: &str) -> Option<String> {
    validate_revision(left).ok()?;
    validate_revision(right).ok()?;
    let output = git(path, &["merge-base", left, right]).ok()?;
    String::from_utf8(output)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// The commit `HEAD` points at, or `None` on an unborn branch.
pub fn head_oid(path: &Path) -> Option<String> {
    commit_oid(path, "HEAD")
}

/// The full ID of the commit `revision` names, or `None` when it names no
/// commit available locally.
pub fn commit_oid(path: &Path, revision: &str) -> Option<String> {
    validate_revision(revision).ok()?;
    let output = git(
        path,
        &[
            "rev-parse",
            "--verify",
            "--quiet",
            "--end-of-options",
            &format!("{revision}^{{commit}}"),
        ],
    )
    .ok()?;
    String::from_utf8(output)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Where Git runs the named hook from, honouring `core.hooksPath` and linked
/// worktrees.
pub fn hook_path(path: &Path, name: &str) -> Result<PathBuf, String> {
    if name.is_empty()
        || !name
            .chars()
            .all(|character| character.is_ascii_lowercase() || character == '-')
    {
        return Err(format!("{name:?} is not a Git hook name"));
    }
    let output = git(path, &["rev-parse", "--git-path", &format!("hooks/{name}")])?;
    let relative = String::from_utf8(output).map_err(|error| error.to_string())?;
    let relative = Path::new(relative.trim_end_matches(['\r', '\n']));
    Ok(if relative.is_absolute() {
        relative.to_path_buf()
    } else {
        path.join(relative)
    })
}

/// One commit in first-parent history: its author's email and the paths it changed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryCommit {
    pub author_email: String,
    pub paths: Vec<String>,
}

/// The newest `limit` commits reachable from `revision`, newest first,
/// following first parents only and without rename detection. Merge commits
/// contribute no paths. Bound to `revision`, the result is the same on every run.
pub fn commit_history(
    root: &Path,
    revision: &str,
    limit: usize,
) -> Result<Vec<HistoryCommit>, String> {
    validate_revision(revision)?;
    let limit = format!("--max-count={limit}");
    let output = git(
        root,
        &[
            "log",
            "-z",
            "--first-parent",
            "--no-renames",
            "--format=%x01%ae%x02",
            "--name-only",
            &limit,
            revision,
            "--",
        ],
    )?;
    let mut commits = Vec::new();
    for record in output.split(|byte| *byte == 0x01).skip(1) {
        let split = record
            .iter()
            .position(|byte| *byte == 0x02)
            .ok_or("unexpected git log record")?;
        let author_email =
            String::from_utf8(record[..split].to_vec()).map_err(|error| error.to_string())?;
        let paths = record[split + 1..]
            .split(|byte| *byte == 0)
            .map(|path| path.strip_prefix(b"\n").unwrap_or(path))
            .filter(|path| !path.is_empty())
            .map(|path| String::from_utf8(path.to_vec()).map_err(|error| error.to_string()))
            .collect::<Result<Vec<_>, _>>()?;
        commits.push(HistoryCommit {
            author_email,
            paths,
        });
    }
    Ok(commits)
}

/// The paths each of the newest `limit` commits reachable from `revision`
/// changed (see [`commit_history`]).
pub fn commit_paths(root: &Path, revision: &str, limit: usize) -> Result<Vec<Vec<String>>, String> {
    Ok(commit_history(root, revision, limit)?
        .into_iter()
        .map(|commit| commit.paths)
        .collect())
}

/// The author name and email of every commit in `base..head`, oldest first.
pub fn commit_authors(
    root: &Path,
    base: &str,
    head: &str,
) -> Result<Vec<(String, String)>, String> {
    validate_revision(base)?;
    validate_revision(head)?;
    let range = format!("{base}..{head}");
    let output = git(
        root,
        &[
            "log",
            "-z",
            "--reverse",
            "--format=%an%x01%ae",
            &range,
            "--",
        ],
    )?;
    output
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
        .map(|record| {
            let text = String::from_utf8(record.to_vec()).map_err(|error| error.to_string())?;
            let (name, email) = text
                .trim_start_matches('\n')
                .split_once('\u{1}')
                .ok_or("unexpected git log author record")?;
            Ok((name.to_owned(), email.to_owned()))
        })
        .collect()
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

/// Bytes that change whenever the live checkout changes in a way Git can see:
/// the current `HEAD`, the porcelain status including untracked files, and the
/// size and modification time of every path that status lists. Callers hash it
/// to tell whether a result derived from the live workspace is still current.
pub fn workspace_state(path: &Path) -> Result<Vec<u8>, String> {
    let root = repository_root(path)?;
    // An unborn branch has no HEAD; the status below still describes the tree.
    let mut state = git(&root, &["rev-parse", "--verify", "--quiet", "HEAD"]).unwrap_or_default();
    let status = git(
        &root,
        &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    )?;
    for entry in status
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
    {
        state.extend_from_slice(entry);
        state.push(0);
        // Rename sources follow their entry without a status prefix; statting
        // them as `XY path` simply finds nothing, which is still deterministic.
        let Some(relative) = entry
            .get(3..)
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
        else {
            continue;
        };
        if let Ok(metadata) = std::fs::symlink_metadata(root.join(relative)) {
            let modified = metadata
                .modified()
                .ok()
                .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |duration| duration.as_nanos());
            state.extend_from_slice(&metadata.len().to_le_bytes());
            state.extend_from_slice(&modified.to_le_bytes());
        }
    }
    Ok(state)
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
        .map_err(git_spawn_error)?;
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
        if vee_core::digest(&bytes) != entry.content_digest {
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

/// Paths of the snapshot tree: the captured head tree's tracked files with
/// the change applied, so added files are present and deleted ones absent.
/// Sorted; paths that are not UTF-8 are skipped. Never reads the working tree.
pub fn snapshot_paths(root: &Path, change_set: &ChangeSet) -> Result<Vec<String>, String> {
    let mut paths = std::collections::BTreeSet::new();
    if let Some(head) = change_set.head_oid.as_deref() {
        validate_revision(head)?;
        let output = git(
            root,
            &["ls-tree", "-r", "-z", "--name-only", "--full-tree", head],
        )?;
        for raw in output
            .split(|byte| *byte == 0)
            .filter(|raw| !raw.is_empty())
        {
            if let Ok(path) = String::from_utf8(raw.to_vec()) {
                paths.insert(path);
            }
        }
    }
    for file in &change_set.files {
        if file.status == "deleted" {
            paths.remove(&file.path);
        } else {
            paths.insert(file.path.clone());
        }
    }
    Ok(paths.into_iter().collect())
}

/// One line of a tree search.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeMatch {
    pub path: String,
    pub line: u64,
    pub text: String,
}

/// Lines of text files in commit `treeish` that contain `needle` as a fixed
/// string, at most `per_file` per file, sorted by path and line. Binary files
/// are skipped. Reads Git objects only, never the working tree.
pub fn grep_tree(
    root: &Path,
    treeish: &str,
    needle: &str,
    ignore_case: bool,
    per_file: usize,
) -> Result<Vec<TreeMatch>, String> {
    validate_revision(treeish)?;
    if needle.is_empty() || needle.contains('\n') || needle.contains('\0') {
        return Err("search pattern must be one non-empty line".into());
    }
    let per_file = per_file.max(1).to_string();
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(root)
        .args([
            "grep",
            "--null",
            "-n",
            "-I",
            "-F",
            "--no-color",
            "--max-count",
        ])
        .arg(&per_file);
    if ignore_case {
        command.arg("-i");
    }
    let output = command
        .args(["-e", needle, treeish])
        .output()
        .map_err(git_spawn_error)?;
    match output.status.code() {
        Some(0) => {}
        // `git grep` exits 1 when nothing matches.
        Some(1) => return Ok(Vec::new()),
        _ => return Err("git grep failed".into()),
    }
    let prefix = format!("{treeish}:");
    let mut matches = Vec::new();
    for record in output.stdout.split(|byte| *byte == b'\n') {
        // `<treeish>:<path>\0<line>\0<text>`
        let mut fields = record.splitn(3, |byte| *byte == 0);
        let (Some(location), Some(line), Some(text)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let Ok(location) = std::str::from_utf8(location) else {
            continue;
        };
        let Some(path) = location.strip_prefix(prefix.as_str()) else {
            continue;
        };
        let Some(line) = std::str::from_utf8(line)
            .ok()
            .and_then(|line| line.parse().ok())
        else {
            continue;
        };
        matches.push(TreeMatch {
            path: path.to_string(),
            line,
            text: String::from_utf8_lossy(text).into_owned(),
        });
    }
    Ok(matches)
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
        let observed = vee_core::digest(&bytes);
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

/// Read many snapshot files at once: changed paths exactly as
/// [`read_snapshot_file`] does, and unchanged paths from the snapshot's head tree
/// through a single `git cat-file --batch` process instead of one `git show` per
/// path. Results are in input order.
pub fn read_snapshot_files(
    root: &Path,
    change_set: &ChangeSet,
    relatives: &[PathBuf],
) -> Result<Vec<Option<Vec<u8>>>, String> {
    let mut results: Vec<Option<Option<Vec<u8>>>> = vec![None; relatives.len()];
    let mut batched = Vec::new();
    for (index, relative) in relatives.iter().enumerate() {
        validate_relative_path(relative)?;
        let normalized = relative.to_string_lossy().replace('\\', "/");
        let changed = change_set.files.iter().any(|file| file.path == normalized);
        if changed || change_set.head_oid.is_none() || normalized.contains('\n') {
            results[index] = Some(read_snapshot_file(root, change_set, relative)?);
        } else {
            batched.push((index, normalized));
        }
    }
    if let (Some(head), false) = (change_set.head_oid.as_deref(), batched.is_empty()) {
        let specs: Vec<String> = batched
            .iter()
            .map(|(_, path)| format!("{head}:{path}"))
            .collect();
        for ((index, _), bytes) in batched.iter().zip(cat_file_batch(root, &specs)?) {
            results[*index] = Some(bytes);
        }
    }
    Ok(results.into_iter().map(Option::unwrap_or_default).collect())
}

/// Resolve `specs` (`<treeish>:<path>`, no newlines) with one `git cat-file
/// --batch`. Each result is the blob's bytes, or `None` when the object is
/// missing or not a blob.
fn cat_file_batch(root: &Path, specs: &[String]) -> Result<Vec<Option<Vec<u8>>>, String> {
    use std::io::{BufRead, Read, Write};
    let mut child = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["cat-file", "--batch"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(git_spawn_error)?;
    let mut stdin = child.stdin.take().ok_or("git cat-file stdin unavailable")?;
    let input: Vec<u8> = specs
        .iter()
        .flat_map(|spec| spec.bytes().chain(std::iter::once(b'\n')))
        .collect();
    // Write from another thread so a large response cannot deadlock the pipes.
    let writer = std::thread::spawn(move || stdin.write_all(&input));
    let mut reader = std::io::BufReader::new(
        child
            .stdout
            .take()
            .ok_or("git cat-file stdout unavailable")?,
    );
    let mut results = Vec::with_capacity(specs.len());
    let mut header = String::new();
    for spec in specs {
        header.clear();
        if reader
            .read_line(&mut header)
            .map_err(|error| error.to_string())?
            == 0
        {
            return Err(format!("git cat-file ended before answering {spec}"));
        }
        let fields: Vec<&str> = header.trim_end_matches('\n').split(' ').collect();
        match fields.as_slice() {
            [_, kind, size] => {
                let size: usize = size
                    .parse()
                    .map_err(|_| format!("git cat-file returned an invalid size for {spec}"))?;
                let mut bytes = vec![0; size + 1];
                reader
                    .read_exact(&mut bytes)
                    .map_err(|error| error.to_string())?;
                bytes.pop(); // trailing newline after the object
                results.push((*kind == "blob").then_some(bytes));
            }
            // `<spec> missing` or `<spec> ambiguous`
            _ => results.push(None),
        }
    }
    writer
        .join()
        .map_err(|_| "git cat-file writer panicked".to_owned())?
        .map_err(|error| error.to_string())?;
    let status = child.wait().map_err(|error| error.to_string())?;
    if !status.success() {
        return Err(format!("git cat-file --batch failed: {status}"));
    }
    Ok(results)
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

/// Read the base-side bytes of several changed paths with one `git cat-file
/// --batch`, in `relatives` order. Results match `read_snapshot_base_file`:
/// `None` for an added path or a snapshot without a base.
pub fn read_snapshot_base_files(
    root: &Path,
    change_set: &ChangeSet,
    relatives: &[PathBuf],
) -> Result<Vec<Option<Vec<u8>>>, String> {
    let mut results = vec![None; relatives.len()];
    let Some(base_oid) = change_set.base_oid.as_deref() else {
        return Ok(results);
    };
    let mut batched = Vec::new();
    for (index, relative) in relatives.iter().enumerate() {
        validate_relative_path(relative)?;
        let normalized = relative.to_string_lossy().replace('\\', "/");
        if normalized.contains('\n') {
            // A batch request is one line per object.
            results[index] = read_tree_file(root, base_oid, relative)?;
        } else {
            batched.push((index, format!("{base_oid}:{normalized}")));
        }
    }
    if !batched.is_empty() {
        let specs: Vec<String> = batched.iter().map(|(_, spec)| spec.clone()).collect();
        for ((index, _), bytes) in batched.iter().zip(cat_file_batch(root, &specs)?) {
            results[*index] = bytes;
        }
    }
    Ok(results)
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
            .is_none_or(|component| component.as_os_str() != ".vee")
            && path != Path::new(".vee.yaml")
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
) -> Result<Vec<vee_core::SnapshotFile>, String> {
    let mut files = snapshot_files(root, paths)?;
    let canonical_root = vee_core::paths::canonicalize(root).map_err(|error| error.to_string())?;
    for relative in paths {
        let candidate = root.join(relative);
        match std::fs::symlink_metadata(&candidate) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            _ => continue,
        }
        let canonical_candidate = vee_core::paths::canonicalize(&candidate).map_err(|error| {
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
            Ok(path) => vee_core::paths::canonicalize(path).map_err(|error| error.to_string())?,
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
        files.push(vee_core::SnapshotFile {
            path,
            mode: 0o160000,
            content_digest: vee_core::digest(commit_after.as_bytes()),
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
) -> Result<Vec<vee_core::SnapshotFile>, String> {
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
            files.push(vee_core::SnapshotFile {
                path,
                mode: *mode,
                content_digest: vee_core::digest(&bytes),
                status: if *mode == 0o120000 {
                    "symlink"
                } else {
                    "present"
                }
                .into(),
            });
        } else {
            files.push(vee_core::SnapshotFile {
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
            .map_err(git_spawn_error)?;
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
            .map_err(git_spawn_error)?;
        if output.status.success() {
            Ok(Some(output.stdout))
        } else {
            Ok(None)
        }
    } else {
        let canonical_root =
            vee_core::paths::canonicalize(root).map_err(|error| error.to_string())?;
        let path = root.join(relative);
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("reading {}: {error}", relative.display())),
        };
        if metadata.file_type().is_symlink() {
            let parent = path.parent().unwrap_or(root);
            let canonical_parent =
                vee_core::paths::canonicalize(parent).map_err(|error| error.to_string())?;
            if !canonical_parent.starts_with(&canonical_root) {
                return Err(format!(
                    "path escapes repository root through a symlink: {}",
                    relative.display()
                ));
            }
            let target = std::fs::read_link(&path).map_err(|error| error.to_string())?;
            return Ok(Some(target.to_string_lossy().as_bytes().to_vec()));
        }
        let canonical_path =
            vee_core::paths::canonicalize(&path).map_err(|error| error.to_string())?;
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

fn git_spawn_error(error: std::io::Error) -> String {
    if error.kind() == std::io::ErrorKind::NotFound {
        "git is not installed or not on PATH".into()
    } else {
        format!("could not run git: {error}")
    }
}

fn git(path: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(path)
        .args(args)
        .output()
        .map_err(git_spawn_error)?;
    if !output.status.success() {
        return Err(format!("git command failed: {}", args.join(" ")));
    }
    Ok(output.stdout)
}

/// Hash the current tree's tracked changes against an optional git base diff manifest.
/// Git CLI is kept outside this domain helper; callers supply the paths selected by Git.
pub fn snapshot_files(root: &Path, paths: &[PathBuf]) -> Result<Vec<SnapshotFile>, String> {
    use std::path::Component;
    let canonical_root =
        vee_core::paths::canonicalize(root).map_err(|e| format!("{}: {e}", root.display()))?;
    let mut files = Vec::with_capacity(paths.len());
    for relative in paths {
        if relative.is_absolute()
            || relative.components().any(|c| {
                matches!(
                    c,
                    Component::ParentDir | Component::RootDir | Component::Prefix(_)
                )
            })
        {
            return Err(format!(
                "path escapes repository root: {}",
                relative.display()
            ));
        }
        let normalized = relative.to_string_lossy().replace('\\', "/");
        let path = root.join(relative);
        let mut ancestor = path.parent().unwrap_or(root).to_path_buf();
        let canonical_ancestor = loop {
            match vee_core::paths::canonicalize(&ancestor) {
                Ok(canonical) => break canonical,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    if !ancestor.pop() {
                        return Err(format!(
                            "could not resolve parent for {}",
                            relative.display()
                        ));
                    }
                }
                Err(error) => return Err(format!("{}: {error}", ancestor.display())),
            }
        };
        if !canonical_ancestor.starts_with(&canonical_root) {
            return Err(format!(
                "path escapes repository root through a symlink: {}",
                relative.display()
            ));
        }
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                files.push(SnapshotFile {
                    path: normalized,
                    mode: 0,
                    content_digest: "deleted".into(),
                    status: "deleted".into(),
                });
                continue;
            }
            Err(error) => return Err(format!("{}: {error}", path.display())),
        };
        if metadata.file_type().is_symlink() {
            let target =
                std::fs::read_link(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            files.push(SnapshotFile {
                path: normalized,
                mode: 0o120000,
                content_digest: digest(target.to_string_lossy().as_bytes()),
                status: "symlink".into(),
            });
        } else if metadata.is_file() {
            let content = read_consistent_file(&path)?;
            let after =
                std::fs::symlink_metadata(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            if metadata.len() != after.len() || metadata.modified().ok() != after.modified().ok() {
                return Err(format!(
                    "file changed while snapshot was being captured: {}",
                    path.display()
                ));
            }
            #[cfg(unix)]
            let mode = {
                use std::os::unix::fs::PermissionsExt;
                metadata.permissions().mode() & 0o777
            };
            #[cfg(not(unix))]
            let mode = 0o644;
            files.push(SnapshotFile {
                path: normalized,
                mode,
                content_digest: digest(&content),
                status: if is_lfs_pointer(&content) {
                    "lfs_pointer".into()
                } else {
                    "present".into()
                },
            });
        }
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(files)
}

fn read_consistent_file(path: &Path) -> Result<Vec<u8>, String> {
    read_consistent_file_with(path, || {})
}

fn read_consistent_file_with(path: &Path, between_reads: impl FnOnce()) -> Result<Vec<u8>, String> {
    let before =
        std::fs::symlink_metadata(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let content = std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    between_reads();
    let second = std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let after =
        std::fs::symlink_metadata(path).map_err(|error| format!("{}: {error}", path.display()))?;
    if before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
        || content.len() as u64 != after.len()
        || digest(&content) != digest(&second)
    {
        return Err(format!(
            "file changed while snapshot was being captured: {}",
            path.display()
        ));
    }
    Ok(content)
}

/// Capture the selected paths from Git's index. Worktree bytes and permissions are ignored.
pub fn snapshot_index_files(root: &Path, paths: &[PathBuf]) -> Result<Vec<SnapshotFile>, String> {
    use std::path::Component;
    let index_tree_before = git_index_tree(root)?;
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["ls-files", "--stage", "-z"])
        .output()
        .map_err(|error| format!("running git ls-files: {error}"))?;
    if !output.status.success() {
        return Err("git ls-files --stage failed".into());
    }
    let mut entries = std::collections::BTreeMap::<String, (u32, String, u8)>::new();
    for raw in output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
    {
        let Some(tab) = raw.iter().position(|byte| *byte == b'\t') else {
            return Err("malformed git index entry".into());
        };
        let metadata =
            std::str::from_utf8(&raw[..tab]).map_err(|_| "non-UTF8 git index metadata")?;
        let mut fields = metadata.split_whitespace();
        let mode = u32::from_str_radix(fields.next().ok_or("missing index mode")?, 8)
            .map_err(|_| "invalid git index mode")?;
        let oid = fields.next().ok_or("missing index object ID")?.to_string();
        let stage = fields
            .next()
            .ok_or("missing index stage")?
            .parse::<u8>()
            .map_err(|_| "invalid git index stage")?;
        let path = std::str::from_utf8(&raw[tab + 1..])
            .map_err(|_| "non-UTF8 path in Git index; this platform cannot represent it safely")?
            .replace('\\', "/");
        entries.insert(path, (mode, oid, stage));
    }
    let mut files = Vec::with_capacity(paths.len());
    for relative in paths {
        if relative.is_absolute()
            || relative.components().any(|component| {
                matches!(
                    component,
                    Component::ParentDir | Component::RootDir | Component::Prefix(_)
                )
            })
        {
            return Err(format!(
                "path escapes repository root: {}",
                relative.display()
            ));
        }
        let path = relative.to_string_lossy().replace('\\', "/");
        match entries.get(&path) {
            None => files.push(SnapshotFile {
                path,
                mode: 0,
                content_digest: "deleted".into(),
                status: "deleted".into(),
            }),
            Some((_, _, stage)) if *stage != 0 => {
                return Err(format!(
                    "unmerged index entry cannot be snapshotted: {path}"
                ))
            }
            Some((mode, oid, _)) if *mode == 0o160000 => files.push(SnapshotFile {
                path,
                mode: *mode,
                content_digest: digest(oid.as_bytes()),
                status: "submodule".into(),
            }),
            Some((mode, oid, _)) => {
                let blob = std::process::Command::new("git")
                    .arg("-C")
                    .arg(root)
                    .args(["cat-file", "blob", oid])
                    .output()
                    .map_err(|error| format!("reading index blob: {error}"))?;
                if !blob.status.success() {
                    return Err(format!("could not read index blob for {path}"));
                }
                let status = if *mode == 0o120000 {
                    "symlink"
                } else if is_lfs_pointer(&blob.stdout) {
                    "lfs_pointer"
                } else {
                    "present"
                };
                files.push(SnapshotFile {
                    path,
                    mode: *mode,
                    content_digest: digest(&blob.stdout),
                    status: status.into(),
                });
            }
        }
    }
    let index_tree_after = git_index_tree(root)?;
    if index_tree_before != index_tree_after {
        return Err("Git index changed while staged snapshot was being captured".into());
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(files)
}

fn git_index_tree(root: &Path) -> Result<String, String> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["write-tree"])
        .output()
        .map_err(|error| format!("running git write-tree: {error}"))?;
    if !output.status.success() {
        return Err("could not create a stable tree from the Git index".into());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[cfg(test)]
mod tests {

    #[test]
    fn commit_paths_lists_each_commit_newest_first() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let git = |args: &[&str]| {
            assert!(std::process::Command::new("git")
                .arg("-C")
                .arg(root)
                .args(args)
                .status()
                .unwrap()
                .success());
        };
        git(&["init", "-q"]);
        git(&["config", "user.email", "vee@example.invalid"]);
        git(&["config", "user.name", "Vee test"]);
        std::fs::write(root.join("a.rs"), "1").unwrap();
        std::fs::write(root.join("b c.rs"), "1").unwrap();
        git(&["add", "."]);
        git(&["commit", "-qm", "first"]);
        std::fs::write(root.join("a.rs"), "2").unwrap();
        git(&["commit", "-qam", "second"]);

        let commits = super::commit_paths(root, "HEAD", 10).unwrap();

        assert_eq!(
            commits,
            vec![
                vec!["a.rs".to_owned()],
                vec!["a.rs".to_owned(), "b c.rs".to_owned()]
            ]
        );
        assert_eq!(super::commit_paths(root, "HEAD", 1).unwrap().len(), 1);
        assert_eq!(
            super::commit_history(root, "HEAD", 1).unwrap()[0].author_email,
            "vee@example.invalid"
        );
        let first = String::from_utf8(
            std::process::Command::new("git")
                .arg("-C")
                .arg(root)
                .args(["rev-list", "--max-parents=0", "HEAD"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap();
        assert_eq!(
            super::commit_authors(root, first.trim(), "HEAD").unwrap(),
            vec![("Vee test".to_owned(), "vee@example.invalid".to_owned())]
        );
    }

    #[test]
    fn batched_snapshot_reads_match_single_reads() {
        let repo = Repo::new();
        let root = repo.0.path();
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/a.rs"), "fn a() {}\n").unwrap();
        fs::write(root.join("src/b.rs"), vec![b'x'; 200_000]).unwrap();
        fs::write(root.join("src/c.rs"), "fn c() {}\n").unwrap();
        repo.git(&["add", "."]);
        repo.git(&["commit", "-qm", "base"]);
        fs::write(root.join("src/c.rs"), "fn c() { 1 }\n").unwrap();
        let change_set = capture(root, ChangeScope::WorkingTree).unwrap();
        let paths: Vec<PathBuf> = ["src/a.rs", "src/b.rs", "src/c.rs", "src/missing.rs", "src"]
            .iter()
            .map(PathBuf::from)
            .collect();
        let batched = read_snapshot_files(root, &change_set, &paths).unwrap();
        for (path, batched) in paths.iter().zip(&batched) {
            let single = read_snapshot_file(root, &change_set, path).unwrap();
            if path == Path::new("src") {
                // `git show` lists a tree; cat-file reports it is not a blob.
                assert!(batched.is_none());
                continue;
            }
            assert_eq!(batched, &single, "{}", path.display());
        }
        assert_eq!(batched[1].as_ref().unwrap().len(), 200_000);
        assert_eq!(batched[2].as_deref(), Some(&b"fn c() { 1 }\n"[..]));
        assert!(batched[3].is_none());
    }

    #[test]
    fn batched_base_reads_match_single_reads() {
        let repo = Repo::new();
        let root = repo.0.path();
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/a.rs"), "fn a() {}\n").unwrap();
        fs::write(root.join("src/b.rs"), vec![b'x'; 200_000]).unwrap();
        repo.git(&["add", "."]);
        repo.git(&["commit", "-qm", "base"]);
        fs::write(root.join("src/a.rs"), "fn a() { 1 }\n").unwrap();
        fs::write(root.join("src/b.rs"), "fn b() {}\n").unwrap();
        fs::write(root.join("src/added.rs"), "fn added() {}\n").unwrap();
        let change_set = capture(root, ChangeScope::WorkingTree).unwrap();
        let paths: Vec<PathBuf> = ["src/a.rs", "src/b.rs", "src/added.rs"]
            .iter()
            .map(PathBuf::from)
            .collect();
        let batched = read_snapshot_base_files(root, &change_set, &paths).unwrap();
        for (path, batched) in paths.iter().zip(&batched) {
            let single = read_snapshot_base_file(root, &change_set, path).unwrap();
            assert_eq!(batched, &single, "{}", path.display());
        }
        assert_eq!(batched[0].as_deref(), Some(&b"fn a() {}\n"[..]));
        assert_eq!(batched[1].as_ref().unwrap().len(), 200_000);
        assert!(batched[2].is_none(), "an added file has no base");

        let no_base = ChangeSet {
            base_oid: None,
            ..change_set
        };
        assert_eq!(
            read_snapshot_base_files(root, &no_base, &paths).unwrap(),
            vec![None, None, None]
        );
    }

    #[test]
    fn revisions_that_git_would_parse_as_options_are_rejected() {
        for revision in ["--output=/tmp/x", "-h", "", " ", "main\0x", "a\nb"] {
            assert!(
                validate_revision(revision).is_err(),
                "{revision:?} must be rejected"
            );
            assert!(commit_scope(&format!("{revision}..HEAD")).is_err());
            assert!(commit_scope(&format!("HEAD..{revision}")).is_err());
        }
        assert!(commit_scope("--all").is_err());
        assert!(merge_base(std::path::Path::new("."), "--is-ancestor").is_err());
        for revision in ["main", "origin/main", "HEAD~2", "v1.0.0", "a1b2c3d"] {
            assert!(
                validate_revision(revision).is_ok(),
                "{revision:?} is a valid revision"
            );
        }
    }

    use super::*;
    use std::fs;

    struct Repo(tempfile::TempDir);
    impl Repo {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let repo = Self(dir);
            repo.git(&["init", "-q"]);
            repo.git(&["config", "user.email", "vee@example.invalid"]);
            repo.git(&["config", "user.name", "Vee test"]);
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
        fs::write(repo.path().join(".vee.yaml"), "version: 1\n").unwrap();
        fs::create_dir_all(repo.path().join(".vee")).unwrap();
        fs::write(repo.path().join(".vee/cache"), "state").unwrap();

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
            vee_core::digest(b"fn main() { let _ = 1; }\n")
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
            vee_core::digest(b"fn working_tree_change() {}\n")
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
            ("user.email", "vee@example.invalid"),
            ("user.name", "Vee test"),
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
            vee_core::digest(expected_oid.as_bytes())
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

    #[test]
    fn manifest_is_order_independent_and_hashes_current_file_contents() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/a.rs"), "one").unwrap();
        std::fs::write(dir.path().join("src/b.rs"), "two").unwrap();
        let first = snapshot_files(dir.path(), &["src/b.rs".into(), "src/a.rs".into()]).unwrap();
        let second = snapshot_files(dir.path(), &["src/a.rs".into(), "src/b.rs".into()]).unwrap();
        let original_digest = ChangeSet::from_entries(None, None, "working_tree", first).digest;
        assert_eq!(
            original_digest,
            ChangeSet::from_entries(None, None, "working_tree", second).digest
        );
        std::fs::write(dir.path().join("src/a.rs"), "changed").unwrap();
        let changed = snapshot_files(dir.path(), &["src/a.rs".into(), "src/b.rs".into()]).unwrap();
        assert_ne!(
            original_digest,
            ChangeSet::from_entries(None, None, "working_tree", changed).digest
        );
    }

    #[test]
    fn consistent_file_reader_rejects_content_change_during_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("source.rs");
        std::fs::write(&path, "fn source() {}\n").unwrap();
        let result = read_consistent_file_with(&path, || {
            std::fs::write(&path, "fn changed() {}\n").unwrap();
        });
        assert!(result.unwrap_err().contains("changed while snapshot"));
    }

    #[test]
    fn snapshot_rejects_paths_outside_repository_root() {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        let outside = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(outside.path(), dir.path().join("escape")).unwrap();
            assert!(snapshot_files(dir.path(), &[PathBuf::from("../secret")]).is_err());
            assert!(snapshot_files(dir.path(), &[PathBuf::from("escape/secret")]).is_err());
        }
        #[cfg(not(unix))]
        assert!(snapshot_files(dir.path(), &[PathBuf::from("../secret")]).is_err());
    }
}
