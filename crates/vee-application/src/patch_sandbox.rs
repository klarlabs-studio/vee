use std::path::{Component, Path, PathBuf};
use vee_core::SnapshotFile;

#[derive(serde::Serialize, serde::Deserialize)]
pub struct PatchSandboxResult {
    pub input_files: Vec<SnapshotFile>,
    pub result_files: Vec<SnapshotFile>,
    pub result_digest: String,
}

pub fn validate(root: &Path, patch: &Path) -> Result<PatchSandboxResult, String> {
    let bytes = std::fs::read(patch).map_err(|error| error.to_string())?;
    validate_bytes(root, &bytes)
}

pub fn validate_bytes(root: &Path, patch: &[u8]) -> Result<PatchSandboxResult, String> {
    let paths = patch_paths(root, patch)?;
    if paths.is_empty() {
        return Err("patch contains no file changes".into());
    }
    let input_files = vee_git::snapshot_files(root, &paths)?;
    let sandbox = tempfile::tempdir().map_err(|error| error.to_string())?;
    materialize(root, sandbox.path(), &input_files)?;
    let copied = vee_git::snapshot_files(sandbox.path(), &paths)?;
    if copied != input_files {
        return Err("patch inputs changed while preparing the isolated sandbox".into());
    }
    run_git(
        sandbox.path(),
        &["apply", "--no-index", "--check", "--"],
        patch,
    )?;
    run_git(sandbox.path(), &["apply", "--no-index", "--"], patch)?;
    let result_files = vee_git::snapshot_files(sandbox.path(), &paths)?;
    check_result(sandbox.path(), &input_files, &result_files)?;
    let canonical =
        serde_json::to_vec(&(&input_files, &result_files)).map_err(|error| error.to_string())?;
    Ok(PatchSandboxResult {
        input_files,
        result_files,
        result_digest: vee_core::digest(&canonical),
    })
}

pub fn input_digest(files: &[SnapshotFile]) -> Result<String, String> {
    serde_json::to_vec(files)
        .map(|bytes| vee_core::digest(&bytes))
        .map_err(|error| error.to_string())
}

pub fn apply_bytes(root: &Path, args: &[&str], patch: &[u8]) -> Result<(), String> {
    run_git(root, args, patch)
}

fn patch_paths(root: &Path, patch: &[u8]) -> Result<Vec<PathBuf>, String> {
    let output = run_git_output(root, &["apply", "--numstat", "-z", "--"], patch)?;
    if !output.status.success() {
        return Err(format!(
            "could not enumerate patch paths: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let mut records = output.stdout.split(|byte| *byte == 0);
    let mut paths = Vec::new();
    while let Some(record) = records.next() {
        if record.is_empty() {
            continue;
        }
        let mut fields = record.splitn(3, |byte| *byte == b'\t');
        let _added = fields.next().ok_or("malformed git apply numstat output")?;
        let _deleted = fields.next().ok_or("malformed git apply numstat output")?;
        let name = fields.next().ok_or("malformed git apply numstat output")?;
        if name.is_empty() {
            for _ in 0..2 {
                let rename_path = records
                    .next()
                    .ok_or("malformed rename in git apply numstat output")?;
                add_path(&mut paths, rename_path)?;
            }
        } else {
            add_path(&mut paths, name)?;
        }
    }
    paths.sort();
    paths.dedup();
    for (index, path) in paths.iter().enumerate() {
        if paths
            .iter()
            .skip(index + 1)
            .any(|other| other.starts_with(path))
        {
            return Err("patch contains conflicting parent and child paths".into());
        }
    }
    Ok(paths)
}

fn add_path(paths: &mut Vec<PathBuf>, bytes: &[u8]) -> Result<(), String> {
    let value = std::str::from_utf8(bytes).map_err(|error| error.to_string())?;
    let path = PathBuf::from(value);
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
        || path.components().next().is_none()
    {
        return Err(format!(
            "patch path is outside the allowed repository scope: {value}"
        ));
    }
    if is_protected_path(value) {
        return Err(format!(
            "a patch may not change Vee configuration, CI or Git hooks: {value}"
        ));
    }
    paths.push(path);
    Ok(())
}

/// Paths whose contents decide what runs: Vee's own configuration and
/// state, CI definitions and Git hooks. A proposed patch never changes them;
/// a person edits them directly.
const PROTECTED_PREFIXES: &[&str] = &[
    ".vee/",
    ".git/",
    ".github/workflows/",
    ".github/actions/",
    ".gitlab/",
    ".circleci/",
    ".buildkite/",
    ".githooks/",
    ".husky/",
];
const PROTECTED_FILES: &[&str] = &[
    ".vee.yaml",
    ".vee",
    ".git",
    ".gitlab-ci.yml",
    ".gitmodules",
    "azure-pipelines.yml",
    "bitbucket-pipelines.yml",
    "Jenkinsfile",
    ".pre-commit-config.yaml",
];

fn is_protected_path(path: &str) -> bool {
    PROTECTED_FILES.contains(&path)
        || PROTECTED_PREFIXES
            .iter()
            .any(|prefix| path.starts_with(prefix))
}

/// The result of a patch may not newly make a file executable, and every
/// symlink it leaves must point inside the repository.
fn check_result(
    sandbox: &Path,
    input_files: &[SnapshotFile],
    result_files: &[SnapshotFile],
) -> Result<(), String> {
    for result in result_files {
        let before = input_files.iter().find(|input| input.path == result.path);
        if result.status == "symlink" {
            let relative = Path::new(&result.path);
            let link =
                std::fs::read_link(sandbox.join(relative)).map_err(|error| error.to_string())?;
            validate_link_target(relative, &link)?;
            continue;
        }
        let executable = |file: &SnapshotFile| file.mode != 0o120000 && file.mode & 0o111 != 0;
        if executable(result) && !before.is_some_and(executable) {
            return Err(format!(
                "a patch may not make a file executable: {}",
                result.path
            ));
        }
    }
    Ok(())
}

fn materialize(root: &Path, sandbox: &Path, files: &[SnapshotFile]) -> Result<(), String> {
    let canonical_sandbox =
        vee_core::paths::canonicalize(sandbox).map_err(|error| error.to_string())?;
    for entry in files {
        let relative = Path::new(&entry.path);
        let source = root.join(relative);
        let target = sandbox.join(relative);
        if entry.status == "deleted" {
            continue;
        }
        let source_metadata =
            std::fs::symlink_metadata(&source).map_err(|error| error.to_string())?;
        let parent = target.parent().ok_or("patch path has no parent")?;
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        let canonical_parent =
            vee_core::paths::canonicalize(parent).map_err(|error| error.to_string())?;
        if !canonical_parent.starts_with(&canonical_sandbox) {
            return Err(format!(
                "patch path escapes isolated sandbox: {}",
                entry.path
            ));
        }
        if source_metadata.file_type().is_symlink() {
            let link = std::fs::read_link(&source).map_err(|error| error.to_string())?;
            if vee_core::digest(link.to_string_lossy().as_bytes()) != entry.content_digest {
                return Err(format!("patch input changed while copying: {}", entry.path));
            }
            validate_link_target(relative, &link)?;
            create_symlink(&link, &target)?;
        } else if source_metadata.is_file() {
            let bytes = std::fs::read(&source).map_err(|error| error.to_string())?;
            if vee_core::digest(&bytes) != entry.content_digest {
                return Err(format!("patch input changed while copying: {}", entry.path));
            }
            std::fs::write(&target, bytes).map_err(|error| error.to_string())?;
            set_mode(&target, entry.mode)?;
        } else {
            return Err(format!("unsupported patch input type: {}", entry.path));
        }
    }
    Ok(())
}

fn validate_link_target(link_path: &Path, target: &Path) -> Result<(), String> {
    if target.is_absolute() {
        return Err(format!(
            "absolute symlink patch input is not supported: {}",
            link_path.display()
        ));
    }
    let parent_depth = link_path
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .components()
        .filter(|component| matches!(component, Component::Normal(_)))
        .count();
    let mut depth = parent_depth;
    for component in target.components() {
        match component {
            Component::Normal(_) => depth += 1,
            Component::ParentDir if depth > 0 => depth -= 1,
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(format!(
                    "symlink patch input escapes isolated sandbox: {}",
                    link_path.display()
                ));
            }
            Component::CurDir => {}
        }
    }
    Ok(())
}

fn run_git(root: &Path, args: &[&str], patch: &[u8]) -> Result<(), String> {
    let output = run_git_output(root, args, patch)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "patch sandbox rejected the diff: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn run_git_output(
    root: &Path,
    args: &[&str],
    patch: &[u8],
) -> Result<std::process::Output, String> {
    use std::io::Write;
    let mut child = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| error.to_string())?;
    let mut stdin = child.stdin.take().ok_or("git stdin unavailable")?;
    let patch = patch.to_vec();
    let writer = std::thread::spawn(move || stdin.write_all(&patch));
    let output = child
        .wait_with_output()
        .map_err(|error| error.to_string())?;
    writer
        .join()
        .map_err(|_| "patch input writer task panicked".to_owned())?
        .map_err(|error| error.to_string())?;
    Ok(output)
}

#[cfg(unix)]
fn create_symlink(source: &Path, target: &Path) -> Result<(), String> {
    std::os::unix::fs::symlink(source, target).map_err(|error| error.to_string())
}

#[cfg(windows)]
fn create_symlink(source: &Path, target: &Path) -> Result<(), String> {
    std::os::windows::fs::symlink_file(source, target).map_err(|error| error.to_string())
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = std::fs::metadata(path)
        .map_err(|error| error.to_string())?
        .permissions();
    permissions.set_mode(mode & 0o777);
    std::fs::set_permissions(path, permissions).map_err(|error| error.to_string())
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repository() -> tempfile::TempDir {
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
        std::fs::write(root.join("src.rs"), "fn a() {}\n").unwrap();
        std::fs::write(root.join(".vee.yaml"), "version: 1\n").unwrap();
        git(&["add", "."]);
        git(&[
            "-c",
            "user.email=vee@example.invalid",
            "-c",
            "user.name=Vee",
            "commit",
            "-qm",
            "base",
        ]);
        directory
    }

    #[test]
    fn an_ordinary_source_change_is_accepted() {
        let directory = repository();
        let patch = "--- a/src.rs\n+++ b/src.rs\n@@ -1 +1 @@\n-fn a() {}\n+fn a() { 1; }\n";
        validate_bytes(directory.path(), patch.as_bytes()).unwrap();
    }

    #[test]
    fn patches_to_vee_configuration_ci_or_hooks_are_refused() {
        let directory = repository();
        for (path, patch) in [
            (
                ".vee.yaml",
                "--- a/.vee.yaml\n+++ b/.vee.yaml\n@@ -1 +1,2 @@\n version: 1\n+offline: false\n"
                    .to_string(),
            ),
            (
                ".github/workflows/ci.yml",
                "--- /dev/null\n+++ b/.github/workflows/ci.yml\n@@ -0,0 +1 @@\n+on: push\n"
                    .to_string(),
            ),
            (
                ".gitlab-ci.yml",
                "--- /dev/null\n+++ b/.gitlab-ci.yml\n@@ -0,0 +1 @@\n+job: {}\n".to_string(),
            ),
            (
                ".husky/pre-commit",
                "--- /dev/null\n+++ b/.husky/pre-commit\n@@ -0,0 +1 @@\n+true\n".to_string(),
            ),
        ] {
            let error = validate_bytes(directory.path(), patch.as_bytes())
                .err()
                .unwrap_or_else(|| panic!("{path} was accepted"));
            assert!(error.contains(path), "{path}: {error}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_patch_may_not_make_files_executable_or_link_outside_the_repository() {
        let directory = repository();
        let executable = "diff --git a/run.sh b/run.sh\nnew file mode 100755\n--- /dev/null\n+++ b/run.sh\n@@ -0,0 +1 @@\n+echo hi\n";
        let error = validate_bytes(directory.path(), executable.as_bytes())
            .err()
            .unwrap();
        assert!(
            error.contains("executable") && error.contains("run.sh"),
            "{error}"
        );

        let mode_change = "diff --git a/src.rs b/src.rs\nold mode 100644\nnew mode 100755\n";
        let error = validate_bytes(directory.path(), mode_change.as_bytes())
            .err()
            .unwrap();
        assert!(error.contains("executable"), "{error}");

        let link = "diff --git a/escape b/escape\nnew file mode 120000\n--- /dev/null\n+++ b/escape\n@@ -0,0 +1 @@\n+/etc/passwd\n\\ No newline at end of file\n";
        assert!(validate_bytes(directory.path(), link.as_bytes()).is_err());
    }
}
