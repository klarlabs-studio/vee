use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GateStatus {
    Pass,
    Block,
    Incomplete,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    Open,
    Verified,
    Refuted,
    Resolved,
    Waived,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    Passed,
    Failed,
    TimedOut,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VerificationProfile {
    pub executable: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env_allowlist: Vec<String>,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_verification_output_limit")]
    pub output_limit_bytes: usize,
}

/// Resolve configured environment variable names from the invoking process.
/// Values stay out of repository configuration and persisted config digests.
pub fn resolve_environment_allowlist<F>(
    names: &[String],
    mut lookup: F,
) -> Result<Vec<(String, String)>, String>
where
    F: FnMut(&str) -> Option<String>,
{
    let mut seen = std::collections::BTreeSet::new();
    let mut resolved = Vec::new();
    for name in names {
        if name.is_empty() || name.contains('=') || name.contains('\0') {
            return Err("environment allowlist contains an invalid variable name".into());
        }
        if !seen.insert(name) {
            return Err(format!("environment allowlist repeats variable {name}"));
        }
        if let Some(value) = lookup(name) {
            resolved.push((name.clone(), value));
        }
    }
    Ok(resolved)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationRun {
    pub schema_version: u32,
    pub run_id: String,
    pub snapshot_id: String,
    pub profile_id: String,
    #[serde(default)]
    pub finding_id: Option<String>,
    pub command_digest: String,
    pub status: VerificationStatus,
    pub exit_code: Option<i32>,
    pub stdout_digest: String,
    pub stderr_digest: String,
    #[serde(default)]
    pub stdout_artifact: Option<ArtifactReference>,
    #[serde(default)]
    pub stderr_artifact: Option<ArtifactReference>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactReference {
    pub digest: String,
    pub path: String,
    pub size_bytes: u64,
}

#[derive(Clone, Debug)]
pub struct VerificationExecution {
    pub run: VerificationRun,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

fn default_verification_output_limit() -> usize {
    1_048_576
}

pub fn execute_verification(
    snapshot_id: &str,
    profile_id: &str,
    working_directory: &Path,
    profile: &VerificationProfile,
) -> Result<VerificationRun, String> {
    Ok(execute_verification_capture(snapshot_id, profile_id, working_directory, profile)?.run)
}

pub fn execute_verification_capture(
    snapshot_id: &str,
    profile_id: &str,
    working_directory: &Path,
    profile: &VerificationProfile,
) -> Result<VerificationExecution, String> {
    use std::{
        io::Read,
        process::{Command, Stdio},
        thread,
        time::{Duration, Instant},
    };
    if profile.executable.trim().is_empty() || profile.timeout_seconds == 0 {
        return Err("verification executable and positive timeout are required".into());
    }
    let command_digest = digest(&serde_json::to_vec(profile).map_err(|error| error.to_string())?);
    let environment =
        resolve_environment_allowlist(&profile.env_allowlist, |name| std::env::var(name).ok())?;
    let mut command = Command::new(&profile.executable);
    command.args(&profile.args);
    configure_process_group(&mut command);
    let mut child = command
        .env_clear()
        .envs(environment.iter().cloned())
        .current_dir(working_directory)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("starting verification profile {profile_id}: {error}"))?;
    let limit = profile.output_limit_bytes;
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let stdout_thread = thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stdout.take((limit + 1) as u64).read_to_end(&mut bytes);
        bytes
    });
    let stderr_thread = thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stderr.take((limit + 1) as u64).read_to_end(&mut bytes);
        bytes
    });
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            break if status.success() {
                VerificationStatus::Passed
            } else {
                VerificationStatus::Failed
            };
        }
        if started.elapsed() >= Duration::from_secs(profile.timeout_seconds) {
            terminate_process_tree(&mut child);
            break VerificationStatus::TimedOut;
        }
        thread::sleep(Duration::from_millis(10));
    };
    let exit_code = child
        .try_wait()
        .ok()
        .flatten()
        .and_then(|status| status.code());
    let mut stdout = stdout_thread
        .join()
        .map_err(|_| "verification stdout reader failed")?;
    let mut stderr = stderr_thread
        .join()
        .map_err(|_| "verification stderr reader failed")?;
    if stdout.len().saturating_add(stderr.len()) > limit {
        return Err("verification output exceeded configured limit".into());
    }
    redact_output_values(&mut stdout, &environment);
    redact_output_values(&mut stderr, &environment);
    let stdout_digest = digest(&stdout);
    let stderr_digest = digest(&stderr);
    let run_id = digest(
        &serde_json::to_vec(&(
            snapshot_id,
            profile_id,
            &command_digest,
            status,
            exit_code,
            &stdout_digest,
            &stderr_digest,
        ))
        .map_err(|error| error.to_string())?,
    );
    Ok(VerificationExecution {
        run: VerificationRun {
            schema_version: SCHEMA_VERSION,
            run_id,
            snapshot_id: snapshot_id.into(),
            profile_id: profile_id.into(),
            finding_id: None,
            command_digest,
            status,
            exit_code,
            stdout_digest,
            stderr_digest,
            stdout_artifact: None,
            stderr_artifact: None,
        },
        stdout,
        stderr,
    })
}

fn redact_output_values(output: &mut Vec<u8>, environment: &[(String, String)]) {
    let mut values: Vec<&[u8]> = environment
        .iter()
        .map(|(_, value)| value.as_bytes())
        .filter(|value| !value.is_empty())
        .collect();
    values.sort_by_key(|value| std::cmp::Reverse(value.len()));
    for secret in values {
        let mut redacted = Vec::with_capacity(output.len());
        let mut cursor = 0;
        while cursor < output.len() {
            if output[cursor..].starts_with(secret) {
                redacted.extend_from_slice(b"[REDACTED]");
                cursor += secret.len();
            } else {
                redacted.push(output[cursor]);
                cursor += 1;
            }
        }
        *output = redacted;
    }
}

impl FindingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Verified => "verified",
            Self::Refuted => "refuted",
            Self::Resolved => "resolved",
            Self::Waived => "waived",
        }
    }

    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "open" => Ok(Self::Open),
            "verified" => Ok(Self::Verified),
            "refuted" => Ok(Self::Refuted),
            "resolved" => Ok(Self::Resolved),
            "waived" => Ok(Self::Waived),
            other => Err(format!("invalid finding status {other}")),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingRecord {
    pub finding: Finding,
    pub status: FindingStatus,
    pub status_reason: Option<String>,
    pub occurrence_count: u64,
    pub first_seen: String,
    pub last_seen: String,
    pub occurrences: Vec<FindingOccurrence>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReviewSummary {
    pub review_id: String,
    pub snapshot_id: String,
    pub status: String,
    pub created_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingOccurrence {
    pub review_id: String,
    pub snapshot_id: String,
    pub observed_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Finding {
    pub id: String,
    pub fingerprint: String,
    pub category: String,
    pub severity: Severity,
    pub confidence: Option<u8>,
    pub rationale: String,
    pub path: Option<String>,
    pub line: Option<u32>,
    pub provenance: String,
    #[serde(default)]
    pub evidence_ids: Vec<String>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Source,
    StaticAnalysis,
    Test,
    ModelInference,
    DependencyPath,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClassification {
    Observed,
    Inferred,
    Unknown,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceVerification {
    Unverified,
    Supported,
    Reproduced,
    Refuted,
    Inconclusive,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Evidence {
    pub id: String,
    pub kind: EvidenceKind,
    pub provenance: String,
    pub source_path: String,
    pub start_line: Option<u32>,
    pub end_line: Option<u32>,
    pub content_digest: String,
    pub classification: EvidenceClassification,
    pub verification: EvidenceVerification,
}

/// Untrusted finding fields accepted from a reviewer provider. Identity, lifecycle,
/// and provenance are assigned by Vero after parsing this transport contract.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderFinding {
    pub category: String,
    pub severity: Severity,
    pub confidence: Option<u8>,
    pub rationale: String,
    pub path: Option<String>,
    pub line: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderFindingsOutput {
    pub schema_version: u32,
    pub findings: Vec<ProviderFinding>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GateDecision {
    pub schema_version: u32,
    pub decision_id: String,
    pub snapshot_id: String,
    #[serde(default)]
    pub effective_config_digest: String,
    pub policy_digest: String,
    pub status: GateStatus,
    pub blocking_findings: Vec<String>,
    pub verification_run_ids: Vec<String>,
    pub evidence_digest: String,
    pub reasons: Vec<String>,
}

/// A waiver applies only to one finding fingerprint in one immutable snapshot and expires.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Waiver {
    pub schema_version: u32,
    pub id: String,
    pub finding_fingerprint: String,
    pub snapshot_id: String,
    pub reason: String,
    pub author: String,
    pub provenance: String,
    pub created_at_unix: i64,
    pub expires_at_unix: i64,
}

#[derive(Clone, Copy, Debug)]
pub struct WaiverEvaluation<'a> {
    pub records: &'a [Waiver],
    pub evaluation_time_unix: i64,
}

#[derive(Clone, Debug)]
pub struct Policy {
    pub block_severities: Vec<Severity>,
    pub minimum_confidence: u8,
    pub required_review_complete: bool,
    pub required_verifications: Vec<String>,
}

#[derive(Clone, Copy, Debug)]
pub struct GateDigests<'a> {
    pub effective_config_digest: &'a str,
    pub policy_digest: &'a str,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotFile {
    pub path: String,
    pub mode: u32,
    pub content_digest: String,
    pub status: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChangeSet {
    pub schema_version: u32,
    pub base_oid: Option<String>,
    pub head_oid: Option<String>,
    pub scope: String,
    pub files: Vec<SnapshotFile>,
    #[serde(default)]
    pub warnings: Vec<String>,
    pub digest: String,
}

impl ChangeSet {
    pub fn from_entries(
        base_oid: Option<String>,
        head_oid: Option<String>,
        scope: impl Into<String>,
        mut files: Vec<SnapshotFile>,
    ) -> Self {
        files.sort_by(|a, b| a.path.cmp(&b.path));
        let base_oid = base_oid.filter(|oid| !oid.is_empty());
        let head_oid = head_oid.filter(|oid| !oid.is_empty());
        let scope = scope.into();
        let canonical = serde_json::to_vec(&(
            SCHEMA_VERSION,
            base_oid.as_deref(),
            head_oid.as_deref(),
            scope.as_str(),
            &files,
        ))
        .expect("serializing snapshot manifest");
        let lfs_pointer_count = files
            .iter()
            .filter(|file| file.status == "lfs_pointer")
            .count();
        Self {
            schema_version: SCHEMA_VERSION,
            base_oid,
            head_oid,
            scope,
            files,
            warnings: if lfs_pointer_count == 0 {
                Vec::new()
            } else {
                vec![format!(
                    "{lfs_pointer_count} Git LFS pointer(s) were captured as pointer files; object contents were not fetched"
                )]
            },
            digest: digest(&canonical),
        }
    }
}

/// Identify the canonical Git LFS pointer header without fetching its object.
pub fn is_lfs_pointer(content: &[u8]) -> bool {
    content.starts_with(b"version https://git-lfs.github.com/spec/v1\n")
}

/// Hash the current tree's tracked changes against an optional git base diff manifest.
/// Git CLI is kept outside this domain helper; callers supply the paths selected by Git.
pub fn snapshot_files(root: &Path, paths: &[PathBuf]) -> Result<Vec<SnapshotFile>, String> {
    use std::path::Component;
    let canonical_root =
        std::fs::canonicalize(root).map_err(|e| format!("{}: {e}", root.display()))?;
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
            match std::fs::canonicalize(&ancestor) {
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

pub fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex(&Sha256::digest(bytes)))
}

fn is_sha256_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

pub fn fingerprint(category: &str, path: Option<&str>, anchor: &str) -> String {
    let key = format!(
        "{}\0{}\0{}",
        category.trim().to_lowercase(),
        path.unwrap_or("").replace('\\', "/"),
        anchor.trim()
    );
    digest(key.as_bytes())
}

/// Normalize untrusted provider output into model-inference findings.
/// Providers cannot self-assert static or reproduced evidence and cannot choose identity hashes.
pub fn normalize_provider_findings(
    findings: Vec<Finding>,
    repository_root: &Path,
) -> Result<Vec<Finding>, String> {
    normalize_provider_findings_with_anchor(findings, repository_root, |_| Ok(None))
}

/// Normalize findings while resolving optional code anchors from the immutable source snapshot.
/// The domain owns identity construction; adapters supply only captured source context.
pub fn normalize_provider_findings_with_anchor<F>(
    findings: Vec<Finding>,
    repository_root: &Path,
    mut resolve_anchor: F,
) -> Result<Vec<Finding>, String>
where
    F: FnMut(&Finding) -> Result<Option<String>, String>,
{
    use std::path::Component;
    let mut normalized = Vec::with_capacity(findings.len());
    let mut seen = std::collections::BTreeSet::new();
    for mut finding in findings {
        if finding.category.trim().is_empty() || finding.rationale.trim().is_empty() {
            return Err("provider finding must include category and rationale".into());
        }
        if finding
            .confidence
            .is_some_and(|confidence| confidence > 100)
        {
            return Err("provider finding confidence must be 0..=100".into());
        }
        if let Some(path) = finding.path.as_mut() {
            let parsed = Path::new(path);
            if parsed.is_absolute()
                || parsed.components().any(|component| {
                    matches!(
                        component,
                        Component::ParentDir | Component::RootDir | Component::Prefix(_)
                    )
                })
            {
                return Err(format!("provider finding path escapes repository: {path}"));
            }
            *path = parsed.to_string_lossy().replace('\\', "/");
            let absolute = repository_root.join(path.as_str());
            if let Ok(canonical_root) = std::fs::canonicalize(repository_root) {
                if let Ok(canonical_parent) =
                    std::fs::canonicalize(absolute.parent().unwrap_or(repository_root))
                {
                    if !canonical_parent.starts_with(canonical_root) {
                        return Err(format!(
                            "provider finding path escapes repository through symlink: {path}"
                        ));
                    }
                }
            }
        }
        if finding.line == Some(0) {
            return Err("provider finding line must be positive".into());
        }
        let anchor = resolve_anchor(&finding)?.unwrap_or_else(|| finding.rationale.clone());
        let stable_fingerprint = fingerprint(&finding.category, finding.path.as_deref(), &anchor);
        finding.fingerprint = stable_fingerprint.clone();
        finding.id = format!("find_{}", &stable_fingerprint[7..19]);
        finding.provenance = "model_inference".into();
        if seen.insert(finding.fingerprint.clone()) {
            normalized.push(finding);
        }
    }
    normalized.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
    Ok(normalized)
}

pub fn parse_provider_findings(
    bytes: &[u8],
    repository_root: &Path,
) -> Result<Vec<Finding>, String> {
    parse_provider_findings_with_anchor(bytes, repository_root, |_| Ok(None))
}

pub fn parse_provider_findings_with_anchor<F>(
    bytes: &[u8],
    repository_root: &Path,
    resolve_anchor: F,
) -> Result<Vec<Finding>, String>
where
    F: FnMut(&Finding) -> Result<Option<String>, String>,
{
    let output: ProviderFindingsOutput = serde_json::from_slice(bytes)
        .map_err(|error| format!("provider output does not match findings schema v1: {error}"))?;
    if output.schema_version != 1 {
        return Err(format!(
            "unsupported provider findings schema version {}",
            output.schema_version
        ));
    }
    let findings = output
        .findings
        .into_iter()
        .map(|finding| Finding {
            id: String::new(),
            fingerprint: String::new(),
            category: finding.category,
            severity: finding.severity,
            confidence: finding.confidence,
            rationale: finding.rationale,
            path: finding.path,
            line: finding.line,
            provenance: "model_inference".into(),
            evidence_ids: Vec::new(),
        })
        .collect();
    normalize_provider_findings_with_anchor(findings, repository_root, resolve_anchor)
}

pub fn evaluate_gate(
    snapshot_id: &str,
    effective_config_digest: &str,
    policy_digest: &str,
    findings: &[Finding],
    policy: &Policy,
    complete: bool,
    verification_runs: &[VerificationRun],
) -> GateDecision {
    evaluate_gate_with_waivers(
        snapshot_id,
        GateDigests {
            effective_config_digest,
            policy_digest,
        },
        findings,
        policy,
        complete,
        verification_runs,
        WaiverEvaluation {
            records: &[],
            evaluation_time_unix: 0,
        },
    )
}

pub fn evaluate_gate_with_waivers(
    snapshot_id: &str,
    digests: GateDigests<'_>,
    findings: &[Finding],
    policy: &Policy,
    complete: bool,
    verification_runs: &[VerificationRun],
    waiver_evaluation: WaiverEvaluation<'_>,
) -> GateDecision {
    let GateDigests {
        effective_config_digest,
        policy_digest,
    } = digests;
    let mut applied_waivers: Vec<_> = waiver_evaluation
        .records
        .iter()
        .filter(|waiver| {
            waiver.schema_version == 1
                && waiver.snapshot_id == snapshot_id
                && waiver.created_at_unix <= waiver_evaluation.evaluation_time_unix
                && waiver.expires_at_unix > waiver_evaluation.evaluation_time_unix
                && findings
                    .iter()
                    .any(|finding| finding.fingerprint == waiver.finding_fingerprint)
        })
        .collect();
    applied_waivers.sort_by(|a, b| a.id.cmp(&b.id));
    let waived_fingerprints: std::collections::BTreeSet<_> = applied_waivers
        .iter()
        .map(|waiver| waiver.finding_fingerprint.as_str())
        .collect();
    let mut blocked: Vec<String> = findings
        .iter()
        .filter(|f| {
            policy.block_severities.contains(&f.severity)
                && f.confidence.unwrap_or(0) >= policy.minimum_confidence
                && !waived_fingerprints.contains(f.fingerprint.as_str())
        })
        .map(|f| f.id.clone())
        .collect();
    blocked.sort();
    let mut verification_run_ids = Vec::new();
    let mut missing_verifications = Vec::new();
    for profile_id in &policy.required_verifications {
        match verification_runs.iter().find(|run| {
            run.finding_id.is_none()
                && run.profile_id == *profile_id
                && run.snapshot_id == snapshot_id
        }) {
            Some(run) => {
                verification_run_ids.push(run.run_id.clone());
                if run.status != VerificationStatus::Passed {
                    missing_verifications.push(profile_id.clone());
                }
            }
            None => missing_verifications.push(profile_id.clone()),
        }
    }
    verification_run_ids.sort();
    missing_verifications.sort();
    let evidence_digest = digest(
        &serde_json::to_vec(&(verification_run_ids.as_slice(), &applied_waivers))
            .expect("serializing gate evidence records"),
    );
    let verification_complete = missing_verifications.is_empty();
    let (status, mut reasons) = if !complete && policy.required_review_complete {
        (
            GateStatus::Incomplete,
            vec!["required review did not complete".to_string()],
        )
    } else if !verification_complete {
        (
            GateStatus::Incomplete,
            vec![format!(
                "required verification profiles incomplete for snapshot: {}",
                missing_verifications.join(", ")
            )],
        )
    } else if !blocked.is_empty() {
        (
            GateStatus::Block,
            vec!["unwaived findings meet blocking policy".to_string()],
        )
    } else if !complete {
        (
            GateStatus::Incomplete,
            vec!["review did not complete".to_string()],
        )
    } else {
        (GateStatus::Pass, Vec::new())
    };
    for waiver in applied_waivers {
        if let Some(finding) = findings
            .iter()
            .find(|finding| finding.fingerprint == waiver.finding_fingerprint)
        {
            reasons.push(format!(
                "waiver {} applied to finding {} until {}",
                waiver.id, finding.id, waiver.expires_at_unix
            ));
        }
    }
    let status_name = match status {
        GateStatus::Pass => "pass",
        GateStatus::Block => "block",
        GateStatus::Incomplete => "incomplete",
    };
    let decision_id = digest(
        &serde_json::to_vec(&(
            snapshot_id,
            effective_config_digest,
            policy_digest,
            status_name,
            &blocked,
            &verification_run_ids,
            &evidence_digest,
            &reasons,
        ))
        .expect("serializing gate decision identity"),
    );
    GateDecision {
        schema_version: SCHEMA_VERSION,
        decision_id,
        snapshot_id: snapshot_id.to_string(),
        effective_config_digest: effective_config_digest.to_string(),
        policy_digest: policy_digest.to_string(),
        status,
        blocking_findings: blocked,
        verification_run_ids,
        evidence_digest,
        reasons,
    }
}

pub fn stale_gate_decision(
    snapshot_id: &str,
    effective_config_digest: &str,
    policy_digest: &str,
) -> GateDecision {
    let evidence_digest = digest(b"[]");
    let reasons =
        vec!["review is stale: source snapshot or effective configuration changed".into()];
    let decision_id = digest(
        &serde_json::to_vec(&(
            snapshot_id,
            effective_config_digest,
            policy_digest,
            "incomplete",
            &Vec::<String>::new(),
            &Vec::<String>::new(),
            &evidence_digest,
            &reasons,
        ))
        .expect("serializing stale gate decision identity"),
    );
    GateDecision {
        schema_version: SCHEMA_VERSION,
        decision_id,
        snapshot_id: snapshot_id.into(),
        effective_config_digest: effective_config_digest.into(),
        policy_digest: policy_digest.into(),
        status: GateStatus::Incomplete,
        blocking_findings: Vec::new(),
        verification_run_ids: Vec::new(),
        evidence_digest,
        reasons,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environment_allowlist_resolves_only_named_host_values() {
        let values = |name: &str| match name {
            "VERO_TEST_TOKEN" => Some("secret-value".to_owned()),
            _ => None,
        };
        assert_eq!(
            resolve_environment_allowlist(
                &["VERO_TEST_TOKEN".into(), "OPTIONAL_MISSING".into()],
                values,
            )
            .unwrap(),
            vec![("VERO_TEST_TOKEN".into(), "secret-value".into())]
        );
        assert!(resolve_environment_allowlist(&["BAD=NAME".into()], |_| None).is_err());
    }

    fn finding(id: &str, severity: Severity, confidence: Option<u8>) -> Finding {
        Finding {
            id: id.into(),
            fingerprint: id.into(),
            category: "correctness".into(),
            severity,
            confidence,
            rationale: String::new(),
            path: None,
            line: None,
            provenance: "model_inference".into(),
            evidence_ids: Vec::new(),
        }
    }

    #[test]
    fn gate_blocks_only_configured_severity_at_confidence_threshold() {
        let policy = Policy {
            block_severities: vec![Severity::High],
            minimum_confidence: 80,
            required_review_complete: true,
            required_verifications: vec![],
        };
        let findings = vec![
            finding("low-confidence", Severity::High, Some(79)),
            finding("high", Severity::High, Some(80)),
            finding("medium", Severity::Medium, Some(99)),
        ];
        let decision = evaluate_gate(
            "snapshot",
            "config",
            "policy",
            &findings,
            &policy,
            true,
            &[],
        );
        assert_eq!(decision.status, GateStatus::Block);
        assert_eq!(decision.blocking_findings, vec!["high"]);
    }

    #[test]
    fn gate_decision_identity_binds_effective_configuration_digest() {
        let policy = Policy {
            block_severities: vec![],
            minimum_confidence: 0,
            required_review_complete: true,
            required_verifications: vec![],
        };
        let first = evaluate_gate("snapshot", "config-a", "policy", &[], &policy, true, &[]);
        let second = evaluate_gate("snapshot", "config-b", "policy", &[], &policy, true, &[]);
        assert_eq!(first.effective_config_digest, "config-a");
        assert_ne!(first.decision_id, second.decision_id);
        let stale_first = stale_gate_decision("snapshot", "config-a", "policy");
        let stale_second = stale_gate_decision("snapshot", "config-b", "policy");
        assert_ne!(stale_first.decision_id, stale_second.decision_id);
    }

    #[test]
    fn waiver_only_suppresses_matching_fingerprint_and_snapshot_until_expiry() {
        let policy = Policy {
            block_severities: vec![Severity::High],
            minimum_confidence: 0,
            required_review_complete: true,
            required_verifications: vec![],
        };
        let findings = [finding("finding-a", Severity::High, Some(90))];
        let waiver = Waiver {
            schema_version: 1,
            id: "waiver-1".into(),
            finding_fingerprint: "finding-a".into(),
            snapshot_id: "snapshot-a".into(),
            reason: "Accepted temporary risk".into(),
            author: "maintainer".into(),
            provenance: "local_cli".into(),
            created_at_unix: 10,
            expires_at_unix: 20,
        };
        let active = evaluate_gate_with_waivers(
            "snapshot-a",
            GateDigests {
                effective_config_digest: "config",
                policy_digest: "policy",
            },
            &findings,
            &policy,
            true,
            &[],
            WaiverEvaluation {
                records: std::slice::from_ref(&waiver),
                evaluation_time_unix: 15,
            },
        );
        assert_eq!(active.status, GateStatus::Pass);
        assert!(active.blocking_findings.is_empty());
        assert!(active.reasons[0].contains("waiver waiver-1 applied"));

        let mut amended_waiver = waiver.clone();
        amended_waiver.reason = "Different recorded rationale".into();
        let amended = evaluate_gate_with_waivers(
            "snapshot-a",
            GateDigests {
                effective_config_digest: "config",
                policy_digest: "policy",
            },
            &findings,
            &policy,
            true,
            &[],
            WaiverEvaluation {
                records: std::slice::from_ref(&amended_waiver),
                evaluation_time_unix: 15,
            },
        );
        assert_ne!(active.evidence_digest, amended.evidence_digest);

        let expired = evaluate_gate_with_waivers(
            "snapshot-a",
            GateDigests {
                effective_config_digest: "config",
                policy_digest: "policy",
            },
            &findings,
            &policy,
            true,
            &[],
            WaiverEvaluation {
                records: std::slice::from_ref(&waiver),
                evaluation_time_unix: 20,
            },
        );
        assert_eq!(expired.status, GateStatus::Block);
        assert_eq!(expired.blocking_findings, vec!["finding-a"]);

        let other_snapshot = evaluate_gate_with_waivers(
            "snapshot-b",
            GateDigests {
                effective_config_digest: "config",
                policy_digest: "policy",
            },
            &findings,
            &policy,
            true,
            &[],
            WaiverEvaluation {
                records: std::slice::from_ref(&waiver),
                evaluation_time_unix: 15,
            },
        );
        assert_eq!(other_snapshot.status, GateStatus::Block);
    }

    #[test]
    fn incomplete_required_analysis_never_passes() {
        let policy = Policy {
            block_severities: vec![],
            minimum_confidence: 0,
            required_review_complete: true,
            required_verifications: vec![],
        };
        let decision = evaluate_gate("snapshot", "config", "policy", &[], &policy, false, &[]);
        assert_eq!(decision.status, GateStatus::Incomplete);
    }

    #[test]
    fn allowed_optional_incomplete_review_does_not_hide_blocking_findings() {
        let policy = Policy {
            block_severities: vec![Severity::High],
            minimum_confidence: 0,
            required_review_complete: false,
            required_verifications: vec![],
        };
        let decision = evaluate_gate(
            "snapshot",
            "config",
            "policy",
            &[finding("high", Severity::High, Some(90))],
            &policy,
            false,
            &[],
        );
        assert_eq!(decision.status, GateStatus::Block);
        assert_eq!(decision.blocking_findings, vec!["high"]);
    }

    #[test]
    fn gate_requires_snapshot_matching_successful_verification_evidence() {
        let policy = Policy {
            block_severities: vec![],
            minimum_confidence: 0,
            required_review_complete: true,
            required_verifications: vec!["unit".into()],
        };
        let run = VerificationRun {
            schema_version: 1,
            run_id: "run-1".into(),
            snapshot_id: "snapshot-1".into(),
            profile_id: "unit".into(),
            finding_id: None,
            command_digest: digest(b"unit-command"),
            status: VerificationStatus::Passed,
            exit_code: Some(0),
            stdout_digest: digest(b""),
            stderr_digest: digest(b""),
            stdout_artifact: None,
            stderr_artifact: None,
        };
        let mut finding_specific = run.clone();
        finding_specific.finding_id = Some("find_target".into());
        assert_eq!(
            evaluate_gate(
                "snapshot-1",
                "config",
                "policy",
                &[],
                &policy,
                true,
                &[finding_specific],
            )
            .status,
            GateStatus::Incomplete,
            "a finding-scoped check must not satisfy a snapshot-wide policy requirement"
        );
        let missing = evaluate_gate("snapshot-1", "config", "policy", &[], &policy, true, &[]);
        assert_eq!(missing.status, GateStatus::Incomplete);
        assert!(missing.reasons.iter().any(|reason| reason.contains("unit")));

        let passed = evaluate_gate(
            "snapshot-1",
            "config",
            "policy",
            &[],
            &policy,
            true,
            std::slice::from_ref(&run),
        );
        assert_eq!(passed.status, GateStatus::Pass);
        assert_eq!(passed.verification_run_ids, vec!["run-1"]);
        let stale = evaluate_gate("snapshot-2", "config", "policy", &[], &policy, true, &[run]);
        assert_eq!(stale.status, GateStatus::Incomplete);
        assert_ne!(passed.evidence_digest, stale.evidence_digest);

        let mut failed_latest = VerificationRun {
            run_id: "run-2".into(),
            status: VerificationStatus::Failed,
            exit_code: Some(1),
            ..passed_run_for_test()
        };
        failed_latest.profile_id = "unit".into();
        let regression = evaluate_gate(
            "snapshot-1",
            "config",
            "policy",
            &[],
            &policy,
            true,
            &[failed_latest, passed_run_for_test()],
        );
        assert_eq!(regression.status, GateStatus::Incomplete);
        assert_eq!(regression.verification_run_ids, vec!["run-2"]);

        let dir = tempfile::tempdir().unwrap();
        let mut store = ReviewStore::open(&dir.path().join("decisions.sqlite")).unwrap();
        let evidence = Evidence {
            id: "ev_source-1".into(),
            kind: EvidenceKind::Source,
            provenance: "source_snapshot".into(),
            source_path: "src/lib.rs".into(),
            start_line: Some(3),
            end_line: Some(3),
            content_digest: digest(b"source"),
            classification: EvidenceClassification::Observed,
            verification: EvidenceVerification::Unverified,
        };
        store
            .save_review_with_decision(ReviewWrite {
                id: "rev-1",
                snapshot_id: "snapshot-1",
                config_digest: "config",
                status: "pass",
                payload: "{}",
                findings: &[],
                evidence: std::slice::from_ref(&evidence),
                snapshot_manifest: "{}",
                decision: &passed,
            })
            .unwrap();
        assert_eq!(store.evidence_for_review("rev-1").unwrap(), vec![evidence]);
        let manifest = store.snapshot_manifest("snapshot-1").unwrap().unwrap();
        assert_eq!(manifest, "{}");
        let evidence_row: (String, String, String) = store
            .connection
            .query_row(
                "SELECT kind,classification,verification FROM evidence_records WHERE evidence_id='ev_source-1'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            evidence_row,
            ("source".into(), "observed".into(), "unverified".into())
        );
        store.save_gate_decision("rev-1", &regression).unwrap();
        store
            .save_review_with_decision(ReviewWrite {
                id: "rev-2",
                snapshot_id: "snapshot-1",
                config_digest: "config",
                status: "pass",
                payload: "{}",
                findings: &[],
                evidence: &[],
                snapshot_manifest: "{}",
                decision: &passed,
            })
            .unwrap();
        let history = store.gate_decisions_for_review("rev-1").unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0], passed);
        assert_eq!(history[1], regression);
        assert_eq!(
            store.gate_decisions_for_review("rev-2").unwrap(),
            vec![passed]
        );
    }

    #[test]
    fn verification_store_migrates_legacy_table_and_persists_finding_scope() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy.sqlite");
        let legacy = rusqlite::Connection::open(&path).unwrap();
        legacy
            .execute_batch("CREATE TABLE verification_runs (run_id TEXT PRIMARY KEY, snapshot_id TEXT NOT NULL, profile_id TEXT NOT NULL, command_digest TEXT NOT NULL, status TEXT NOT NULL, exit_code INTEGER, stdout_digest TEXT NOT NULL, stderr_digest TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);")
            .unwrap();
        let existing = VerificationRun {
            schema_version: 1,
            run_id: "legacy-run".into(),
            snapshot_id: "legacy-snapshot".into(),
            profile_id: "unit".into(),
            finding_id: None,
            command_digest: digest(b"legacy-command"),
            status: VerificationStatus::Passed,
            exit_code: Some(0),
            stdout_digest: digest(b"legacy-stdout"),
            stderr_digest: digest(b""),
            stdout_artifact: None,
            stderr_artifact: None,
        };
        legacy
            .execute(
                "INSERT INTO verification_runs(run_id,snapshot_id,profile_id,command_digest,status,exit_code,stdout_digest,stderr_digest,payload) VALUES (?1,?2,?3,?4,'passed',0,?5,?6,?7)",
                rusqlite::params![
                    existing.run_id,
                    existing.snapshot_id,
                    existing.profile_id,
                    existing.command_digest,
                    existing.stdout_digest,
                    existing.stderr_digest,
                    serde_json::to_string(&existing).unwrap(),
                ],
            )
            .unwrap();
        drop(legacy);

        let mut store = ReviewStore::open(&path).unwrap();
        assert_eq!(
            store.verification("legacy-run").unwrap(),
            Some(existing),
            "migration must preserve existing verification records"
        );
        let run = VerificationRun {
            schema_version: 1,
            run_id: "targeted-run".into(),
            snapshot_id: "snapshot".into(),
            profile_id: "unit".into(),
            finding_id: Some("find_123".into()),
            command_digest: digest(b"command"),
            status: VerificationStatus::Passed,
            exit_code: Some(0),
            stdout_digest: digest(b""),
            stderr_digest: digest(b""),
            stdout_artifact: None,
            stderr_artifact: None,
        };
        store.save_verification(&run).unwrap();
        assert_eq!(store.verification("targeted-run").unwrap(), Some(run));
        let version: u32 = store
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, 6);
    }

    #[test]
    fn invalid_verification_artifact_rolls_back_run_and_artifact_rows() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ReviewStore::open(&dir.path().join("artifact-rollback.sqlite")).unwrap();
        let mut run = passed_run_for_test();
        run.stdout_artifact = Some(ArtifactReference {
            digest: digest(b"wrong bytes"),
            path: ".vero/artifacts/sha256/0000000000000000000000000000000000000000000000000000000000000000".into(),
            size_bytes: 10,
        });

        assert!(store.save_verification_with_artifacts(&run).is_err());
        assert_eq!(store.verification(&run.run_id).unwrap(), None);
        assert_eq!(
            store.verification_artifact(&run.run_id, "stdout").unwrap(),
            None
        );
    }

    #[test]
    fn provider_cache_persists_only_under_exact_request_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ReviewStore::open(&dir.path().join("provider-cache.sqlite")).unwrap();
        let request_key = digest(b"exact provider request");
        assert_eq!(store.provider_cache_get(&request_key).unwrap(), None);

        store
            .provider_cache_put(&request_key, "codex 1.2.3", b"{\"findings\":[]}")
            .unwrap();

        assert_eq!(
            store.provider_cache_get(&request_key).unwrap(),
            Some(b"{\"findings\":[]}".to_vec())
        );
        assert_eq!(
            store
                .provider_cache_get(&digest(b"different request"))
                .unwrap(),
            None
        );
        store
            .connection
            .execute(
                "UPDATE provider_cache SET stdout=?1 WHERE request_key=?2",
                rusqlite::params![b"tampered".as_slice(), request_key],
            )
            .unwrap();
        assert!(store.provider_cache_get(&request_key).is_err());
        let version: u32 = store
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, 6);
    }

    #[test]
    fn review_store_rejects_a_database_from_a_newer_schema_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("future.sqlite");
        let future = rusqlite::Connection::open(&path).unwrap();
        future.pragma_update(None, "user_version", 99).unwrap();
        drop(future);

        let error = match ReviewStore::open(&path) {
            Ok(_) => panic!("future schema version should be rejected"),
            Err(error) => error,
        };

        assert!(error.contains("schema version 99"));
    }

    #[test]
    fn version_two_gate_history_migrates_config_digest_from_review() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v2.sqlite");
        let legacy = rusqlite::Connection::open(&path).unwrap();
        legacy
            .execute_batch(
                "CREATE TABLE reviews (id TEXT PRIMARY KEY, config_digest TEXT NOT NULL);
                CREATE TABLE verification_runs (run_id TEXT PRIMARY KEY);
                CREATE TABLE gate_decisions (decision_id TEXT NOT NULL, review_id TEXT NOT NULL, snapshot_id TEXT NOT NULL, policy_digest TEXT NOT NULL, evidence_digest TEXT NOT NULL, status TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(review_id,decision_id));
                INSERT INTO reviews(id,config_digest) VALUES ('rev-old','sha256:config');
                INSERT INTO gate_decisions(decision_id,review_id,snapshot_id,policy_digest,evidence_digest,status,payload) VALUES ('sha256:decision','rev-old','sha256:snapshot','sha256:policy','sha256:evidence','pass','{\"schema_version\":1,\"decision_id\":\"sha256:decision\",\"snapshot_id\":\"sha256:snapshot\",\"policy_digest\":\"sha256:policy\",\"status\":\"pass\",\"blocking_findings\":[],\"verification_run_ids\":[],\"evidence_digest\":\"sha256:evidence\",\"reasons\":[]}');
                PRAGMA user_version=2;",
            )
            .unwrap();
        drop(legacy);

        let store = ReviewStore::open(&path).unwrap();
        let decisions = store.gate_decisions_for_review("rev-old").unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].effective_config_digest, "sha256:config");
    }

    #[test]
    fn failed_storage_migration_rolls_back_schema_changes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invalid-v1.sqlite");
        let legacy = rusqlite::Connection::open(&path).unwrap();
        legacy
            .execute_batch(
                "CREATE TABLE verification_runs (run_id TEXT PRIMARY KEY);
                PRAGMA user_version=1;",
            )
            .unwrap();
        drop(legacy);

        assert!(ReviewStore::open(&path).is_err());
        let check = rusqlite::Connection::open(&path).unwrap();
        let version: u32 = check
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        let has_finding_id: bool = check
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_table_info('verification_runs') WHERE name='finding_id')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, 1);
        assert!(!has_finding_id, "failed migration must roll back its ALTER");
    }

    fn passed_run_for_test() -> VerificationRun {
        VerificationRun {
            schema_version: 1,
            run_id: "run-1".into(),
            snapshot_id: "snapshot-1".into(),
            profile_id: "unit".into(),
            finding_id: None,
            command_digest: digest(b"unit-command"),
            status: VerificationStatus::Passed,
            exit_code: Some(0),
            stdout_digest: digest(b""),
            stderr_digest: digest(b""),
            stdout_artifact: None,
            stderr_artifact: None,
        }
    }

    #[test]
    fn fingerprint_normalizes_category_and_path_separators() {
        assert_eq!(
            fingerprint(" Correctness ", Some("src\\lib.rs"), " x "),
            fingerprint("correctness", Some("src/lib.rs"), "x")
        );
    }

    #[test]
    fn provider_findings_cannot_forge_provenance_or_identity() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.rs"), "fn a() {}\n").unwrap();
        let mut candidate = finding("model-id", Severity::High, Some(90));
        candidate.rationale = "unsafe operation".into();
        candidate.fingerprint = "provider-chosen".into();
        candidate.provenance = "reproduced_by_test".into();
        candidate.path = Some("a.rs".into());
        let output = normalize_provider_findings(vec![candidate], dir.path()).unwrap();
        assert_eq!(output[0].provenance, "model_inference");
        assert_ne!(output[0].fingerprint, "provider-chosen");
        assert!(output[0].id.starts_with("find_"));
    }

    #[test]
    fn provider_findings_reject_invalid_confidence_and_paths() {
        let dir = tempfile::tempdir().unwrap();
        let mut candidate = finding("id", Severity::High, Some(101));
        candidate.rationale = "unsafe operation".into();
        assert!(normalize_provider_findings(vec![candidate.clone()], dir.path()).is_err());
        candidate.confidence = Some(80);
        candidate.path = Some("../outside.rs".into());
        assert!(normalize_provider_findings(vec![candidate], dir.path()).is_err());
    }

    #[test]
    fn provider_output_v1_assigns_identity_and_provenance_after_strict_parse() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("src.rs"), "fn f() {}\n").unwrap();
        let bytes = br#"{"schema_version":1,"findings":[{"category":"correctness","severity":"high","confidence":92,"rationale":"incorrect bounds check","path":"src.rs","line":1}]}"#;
        let findings = parse_provider_findings(bytes, dir.path()).unwrap();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].id.starts_with("find_"));
        assert_ne!(findings[0].fingerprint, "");
        assert_eq!(findings[0].provenance, "model_inference");
    }

    #[test]
    fn provider_output_v1_rejects_unknown_fields_and_versions() {
        let dir = tempfile::tempdir().unwrap();
        let unknown = br#"{"schema_version":1,"findings":[{"id":"forged","category":"correctness","severity":"high","confidence":90,"rationale":"bug"}]}"#;
        assert!(parse_provider_findings(unknown, dir.path()).is_err());
        let version = br#"{"schema_version":2,"findings":[]}"#;
        assert!(parse_provider_findings(version, dir.path())
            .unwrap_err()
            .contains("unsupported provider findings schema version"));
        let malformed = br#"{"schema_version":1,"findings":[{"category":"correctness","severity":"urgent","confidence":90,"rationale":"bug"}]}"#;
        assert!(parse_provider_findings(malformed, dir.path()).is_err());
    }

    #[test]
    fn snapshot_digest_changes_with_file_contents() {
        assert_ne!(digest(b"file.rs\0one"), digest(b"file.rs\0two"));
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
    fn snapshot_identity_binds_base_head_and_scope() {
        let entry = SnapshotFile {
            path: "a.rs".into(),
            mode: 0o644,
            content_digest: digest(b"code"),
            status: "present".into(),
        };
        let from_head = ChangeSet::from_entries(
            Some("base-a".into()),
            Some("head".into()),
            "working_tree",
            vec![entry.clone()],
        );
        let from_other_base = ChangeSet::from_entries(
            Some("base-b".into()),
            Some("head".into()),
            "working_tree",
            vec![entry.clone()],
        );
        let staged = ChangeSet::from_entries(
            Some("base-a".into()),
            Some("head".into()),
            "staged",
            vec![entry],
        );
        assert_ne!(from_head.digest, from_other_base.digest);
        assert_ne!(from_head.digest, staged.digest);
    }

    #[test]
    fn snapshot_rejects_paths_outside_repository_root() {
        let dir = tempfile::tempdir().unwrap();
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

    #[test]
    fn config_rejects_unknown_provider_and_bad_confidence() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(".vero.yaml");
        std::fs::write(&file, "version: 1\nreviewers:\n  correctness:\n    provider: missing\n    instructions_file: reviewer.md\n    enabled: true\n").unwrap();
        assert!(RepositoryConfig::load(&file)
            .unwrap_err()
            .contains("unknown provider"));
        std::fs::write(&file, "version: 1\npolicy:\n  minimum_confidence: 101\n").unwrap();
        assert!(RepositoryConfig::load(&file)
            .unwrap_err()
            .contains("0..=100"));
        std::fs::write(&file, "version: 1\nreview:\n  max_concurrency: 33\n").unwrap();
        assert!(RepositoryConfig::load(&file)
            .unwrap_err()
            .contains("max_concurrency must be in 1..=32"));
        std::fs::write(
            &file,
            "version: 1\npolicy:\n  required_verifications: [missing]\n",
        )
        .unwrap();
        assert!(RepositoryConfig::load(&file)
            .unwrap_err()
            .contains("unknown verification profile"));
        std::fs::write(
            &file,
            "version: 1\npolicy:\n  block_severities: [catastrophic]\n",
        )
        .unwrap();
        assert!(RepositoryConfig::load(&file)
            .unwrap_err()
            .contains("unknown blocking severity"));
        std::fs::write(&file, "version: 1\npolicy:\n  on_incomplete: ignore\n").unwrap();
        assert!(RepositoryConfig::load(&file)
            .unwrap_err()
            .contains("on_incomplete"));
        std::fs::write(
            &file,
            "version: 1\npolicy:\n  required_reviewers: [missing]\n",
        )
        .unwrap();
        assert!(RepositoryConfig::load(&file)
            .unwrap_err()
            .contains("unknown reviewer"));
        std::fs::write(
            &file,
            "version: 1\nproviders:\n  p:\n    kind: api\n    executable: x\n",
        )
        .unwrap();
        assert!(RepositoryConfig::load(&file).unwrap_err().contains("api"));
    }

    #[test]
    fn user_provider_defaults_are_merged_before_validation_and_repo_wins() {
        let dir = tempfile::tempdir().unwrap();
        let repository = dir.path().join(".vero.yaml");
        let user = dir.path().join("user.yaml");
        std::fs::write(
            &repository,
            "version: 1\nreviewers:\n  correctness:\n    provider: codex\n    instructions_file: reviewer.md\n",
        )
        .unwrap();
        std::fs::write(
            &user,
            "version: 1\nproviders:\n  codex: { kind: cli, executable: codex-user }\n  extra: { kind: cli, executable: extra-user }\n",
        )
        .unwrap();

        let config =
            RepositoryConfig::load_with_provider_defaults(&repository, Some(&user)).unwrap();
        assert_eq!(config.providers["codex"].executable, "codex-user");
        assert_eq!(config.providers["extra"].executable, "extra-user");

        std::fs::write(
            &repository,
            "version: 1\nproviders:\n  codex: { kind: cli, executable: codex-repo }\nreviewers:\n  correctness:\n    provider: codex\n    instructions_file: reviewer.md\n",
        )
        .unwrap();
        let config =
            RepositoryConfig::load_with_provider_defaults(&repository, Some(&user)).unwrap();
        assert_eq!(config.providers["codex"].executable, "codex-repo");
        assert_eq!(config.providers["extra"].executable, "extra-user");

        std::fs::write(&user, "version: 2\nproviders: {}\n").unwrap();
        assert!(
            RepositoryConfig::load_with_provider_defaults(&repository, Some(&user))
                .unwrap_err()
                .contains("unsupported user config version 2")
        );
    }

    #[test]
    fn named_policy_profiles_select_deterministic_policy_and_reject_unknown_names() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(".vero.yaml");
        std::fs::write(
            &file,
            r#"
version: 1
providers:
  p: { kind: cli, executable: fake }
reviewers:
  correctness: { provider: p, instructions_file: reviewer.md }
policy:
  required_reviewers: [correctness]
policy_profiles:
  strict:
    required_reviewers: [correctness]
    block_severities: [critical, high, medium]
    minimum_confidence: 65
    on_incomplete: block
"#,
        )
        .unwrap();
        let mut config = RepositoryConfig::load(&file).unwrap();
        config.select_policy_profile(Some("strict")).unwrap();
        assert_eq!(config.policy.minimum_confidence, 65);
        assert_eq!(
            config.policy.block_severities,
            ["critical", "high", "medium"]
        );
        assert_eq!(config.active_policy_profile.as_deref(), Some("strict"));
        assert!(config.select_policy_profile(Some("missing")).is_err());
    }

    #[test]
    fn config_rejects_unknown_fields_at_root_and_nested_levels() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(".vero.yaml");
        for invalid in [
            "version: 1\npolciy: {}\n",
            "version: 1\npolicy:\n  minumum_confidence: 80\n",
            "version: 1\nreviewers:\n  correctness:\n    provider: p\n    instructions_file: reviewer.md\n    incldue: [\"src/**\"]\nproviders:\n  p: { kind: cli, executable: codex }\n",
            "version: 1\nproviders:\n  p:\n    kind: cli\n    executable: codex\n    timeuot_seconds: 5\n",
            "version: 1\nproviders:\n  p:\n    kind: cli\n    executable: codex\n    env: { API_TOKEN: plaintext-secret }\n",
        ] {
            std::fs::write(&file, invalid).unwrap();
            assert!(
                RepositoryConfig::load(&file).is_err(),
                "accepted invalid config: {invalid}"
            );
        }
    }

    #[test]
    fn offline_config_rejects_network_providers_and_codex_cannot_claim_local_egress() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(".vero.yaml");
        std::fs::write(
            &file,
            "version: 1\noffline: true\nproviders:\n  hosted: { kind: codex_cli, executable: codex }\n",
        )
        .unwrap();
        assert!(RepositoryConfig::load(&file)
            .unwrap_err()
            .contains("offline mode rejects network provider hosted"));

        std::fs::write(
            &file,
            "version: 1\noffline: true\nproviders:\n  local: { kind: cli, egress: local, executable: local-reviewer }\n",
        )
        .unwrap();
        assert!(RepositoryConfig::load(&file).is_ok());

        std::fs::write(
            &file,
            "version: 1\nproviders:\n  hosted: { kind: codex_cli, egress: local, executable: codex }\n",
        )
        .unwrap();
        assert!(RepositoryConfig::load(&file)
            .unwrap_err()
            .contains("codex_cli cannot be declared local"));
    }

    #[test]
    fn openai_compatible_provider_requires_a_valid_endpoint_and_local_loopback_in_offline_mode() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(".vero.yaml");
        std::fs::write(
            &file,
            "version: 1\noffline: true\nproviders:\n  local:\n    kind: openai_compatible\n    egress: local\n    endpoint: http://127.0.0.1:11434/v1/chat/completions\n    model: qwen-local\n",
        )
        .unwrap();
        let config = RepositoryConfig::load(&file).unwrap();
        assert_eq!(
            config.providers["local"].kind,
            ProviderKind::OpenAiCompatible
        );

        std::fs::write(
            &file,
            "version: 1\noffline: true\nproviders:\n  local:\n    kind: openai_compatible\n    egress: local\n    endpoint: https://example.com/v1/chat/completions\n    model: qwen-local\n",
        )
        .unwrap();
        assert!(RepositoryConfig::load(&file)
            .unwrap_err()
            .contains("local egress requires a loopback endpoint"));

        std::fs::write(
            &file,
            "version: 1\nproviders:\n  hosted:\n    kind: openai_compatible\n    endpoint: file:///etc/passwd\n    model: remote\n",
        )
        .unwrap();
        assert!(RepositoryConfig::load(&file)
            .unwrap_err()
            .contains("must use http or https"));

        for endpoint in [
            "http://user:password@127.0.0.1/chat",
            "http://127.0.0.1/chat?api_key=secret",
            "http://127.0.0.1/chat#fragment",
        ] {
            std::fs::write(
                &file,
                format!("version: 1\nproviders:\n  p:\n    kind: openai_compatible\n    egress: local\n    endpoint: {endpoint}\n    model: local\n"),
            )
            .unwrap();
            assert!(RepositoryConfig::load(&file).is_err(), "{endpoint}");
        }
    }

    #[test]
    fn review_store_persists_payload_and_staleness_is_exact() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ReviewStore::open(&dir.path().join("reviews.sqlite")).unwrap();
        store
            .save(
                "rev_1",
                "sha256:a",
                "sha256:c",
                "incomplete",
                "{\"status\":\"incomplete\"}",
            )
            .unwrap();
        assert_eq!(
            store.get("rev_1").unwrap().as_deref(),
            Some("{\"status\":\"incomplete\"}")
        );
        assert!(snapshot_is_current("sha256:a", "sha256:a"));
        assert!(!snapshot_is_current("sha256:a", "sha256:b"));
    }

    #[test]
    fn snapshot_manifest_is_immutable_per_snapshot_identity() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ReviewStore::open(&dir.path().join("snapshot-manifest.sqlite")).unwrap();
        let change_set = ChangeSet::from_entries(None, None, "working_tree", vec![]);
        let manifest = serde_json::to_string(&(
            change_set.schema_version,
            change_set.base_oid.as_deref(),
            change_set.head_oid.as_deref(),
            change_set.scope.as_str(),
            &change_set.files,
        ))
        .unwrap();
        let decision = GateDecision {
            schema_version: 1,
            decision_id: "decision-b".into(),
            snapshot_id: change_set.digest.clone(),
            effective_config_digest: "config".into(),
            policy_digest: "policy".into(),
            status: GateStatus::Pass,
            blocking_findings: vec![],
            verification_run_ids: vec![],
            evidence_digest: "evidence".into(),
            reasons: vec![],
        };
        store
            .save_review_with_decision(ReviewWrite {
                id: "rev-a",
                snapshot_id: &change_set.digest,
                config_digest: "config",
                status: "pass",
                payload: "{}",
                findings: &[],
                evidence: &[],
                snapshot_manifest: &manifest,
                decision: &decision,
            })
            .unwrap();
        let conflict = store.save_review_with_decision(ReviewWrite {
            id: "rev-b",
            snapshot_id: &change_set.digest,
            config_digest: "config",
            status: "pass",
            payload: "{}",
            findings: &[],
            evidence: &[],
            snapshot_manifest: "{}",
            decision: &decision,
        });
        assert!(conflict.unwrap_err().contains("different manifest"));
        assert!(store.get("rev-b").unwrap().is_none());
    }

    #[test]
    fn evidence_identity_can_recur_across_reviews_for_the_same_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ReviewStore::open(&dir.path().join("evidence-occurrences.sqlite")).unwrap();
        let evidence = Evidence {
            id: "ev-stable".into(),
            kind: EvidenceKind::Source,
            provenance: "snapshot".into(),
            source_path: "src/lib.rs".into(),
            start_line: Some(1),
            end_line: Some(1),
            content_digest: digest(b"same source"),
            classification: EvidenceClassification::Observed,
            verification: EvidenceVerification::Unverified,
        };
        let decision = GateDecision {
            schema_version: 1,
            decision_id: "decision-1".into(),
            snapshot_id: "snapshot-1".into(),
            effective_config_digest: "config".into(),
            policy_digest: "policy".into(),
            status: GateStatus::Pass,
            blocking_findings: vec![],
            verification_run_ids: vec![],
            evidence_digest: "evidence".into(),
            reasons: vec![],
        };
        for review_id in ["rev-1", "rev-2"] {
            store
                .save_review_with_decision(ReviewWrite {
                    id: review_id,
                    snapshot_id: "snapshot-1",
                    config_digest: "config",
                    status: "pass",
                    payload: "{}",
                    findings: &[],
                    evidence: std::slice::from_ref(&evidence),
                    snapshot_manifest: "{}",
                    decision: &decision,
                })
                .unwrap();
        }
        assert_eq!(
            store.evidence_for_review("rev-1").unwrap(),
            vec![evidence.clone()]
        );
        assert_eq!(store.evidence_for_review("rev-2").unwrap(), vec![evidence]);
    }

    #[test]
    fn schema_six_migration_backfills_normalized_evidence_records() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("evidence-v5.sqlite");
        let mut store = ReviewStore::open(&path).unwrap();
        let evidence = Evidence {
            id: "ev-legacy".into(),
            kind: EvidenceKind::Source,
            provenance: "snapshot".into(),
            source_path: "src/lib.rs".into(),
            start_line: Some(2),
            end_line: Some(2),
            content_digest: digest(b"legacy source"),
            classification: EvidenceClassification::Observed,
            verification: EvidenceVerification::Unverified,
        };
        let change_set = ChangeSet::from_entries(
            Some("base-oid".into()),
            Some("head-oid".into()),
            "base",
            vec![SnapshotFile {
                path: "src/lib.rs".into(),
                mode: 0o100644,
                content_digest: digest(b"legacy source"),
                status: "modified".into(),
            }],
        );
        let payload = serde_json::json!({ "change_set": change_set.clone() });
        let payload = serde_json::to_string(&payload).unwrap();
        let decision = GateDecision {
            schema_version: 1,
            decision_id: "decision-legacy".into(),
            snapshot_id: change_set.digest.clone(),
            effective_config_digest: "config".into(),
            policy_digest: "policy".into(),
            status: GateStatus::Pass,
            blocking_findings: vec![],
            verification_run_ids: vec![],
            evidence_digest: "evidence".into(),
            reasons: vec![],
        };
        store
            .save_review_with_decision(ReviewWrite {
                id: "rev-legacy",
                snapshot_id: &change_set.digest,
                config_digest: "config",
                status: "pass",
                payload: &payload,
                findings: &[],
                evidence: std::slice::from_ref(&evidence),
                snapshot_manifest: "{}",
                decision: &decision,
            })
            .unwrap();
        drop(store);
        let legacy = rusqlite::Connection::open(&path).unwrap();
        legacy
            .execute_batch(
                "DROP TABLE evidence_records; DROP TABLE snapshots; PRAGMA user_version=5;",
            )
            .unwrap();
        drop(legacy);

        let upgraded = ReviewStore::open(&path).unwrap();
        assert_eq!(
            upgraded.evidence_for_review("rev-legacy").unwrap(),
            vec![evidence]
        );
        let expected_manifest = serde_json::to_string(&(
            change_set.schema_version,
            change_set.base_oid.as_deref(),
            change_set.head_oid.as_deref(),
            change_set.scope.as_str(),
            &change_set.files,
        ))
        .unwrap();
        assert_eq!(
            upgraded
                .snapshot_manifest(&change_set.digest)
                .unwrap()
                .as_deref(),
            Some(expected_manifest.as_str())
        );
    }

    #[test]
    fn finding_lifecycle_tracks_occurrences_filters_and_reopens_resolved_items() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ReviewStore::open(&dir.path().join("lifecycle.sqlite")).unwrap();
        let mut item = finding("id-one", Severity::High, Some(95));
        item.fingerprint = "stable-fingerprint".into();
        item.rationale = "unsafe operation".into();
        store
            .save_review("rev-1", "snap-1", "cfg", "block", "{}", &[item.clone()])
            .unwrap();
        let waiver = Waiver {
            schema_version: 1,
            id: "waiver-snap-1".into(),
            finding_fingerprint: item.fingerprint.clone(),
            snapshot_id: "snap-1".into(),
            reason: "Temporary accepted risk".into(),
            author: "maintainer".into(),
            provenance: "local_cli".into(),
            created_at_unix: 10,
            expires_at_unix: 20,
        };
        store.create_waiver(&waiver).unwrap();
        assert_eq!(store.waivers_for_snapshot("snap-1").unwrap(), vec![waiver]);
        store
            .set_finding_status(
                "id-one",
                FindingStatus::Verified,
                "reviewed source evidence",
            )
            .unwrap();
        store
            .save_review("rev-2", "snap-2", "cfg", "block", "{}", &[item.clone()])
            .unwrap();
        let verified = store.finding("id-one").unwrap().unwrap();
        assert_eq!(verified.status, FindingStatus::Verified);
        assert_eq!(verified.occurrence_count, 2);
        assert_eq!(verified.occurrences.len(), 2);
        assert_eq!(verified.occurrences[1].review_id, "rev-2");
        assert_eq!(verified.occurrences[1].snapshot_id, "snap-2");
        store
            .set_finding_status("id-one", FindingStatus::Resolved, "fixed in change")
            .unwrap();
        store
            .save_review("rev-3", "snap-3", "cfg", "block", "{}", &[item])
            .unwrap();
        let reopened = store.finding("id-one").unwrap().unwrap();
        assert_eq!(reopened.status, FindingStatus::Open);
        assert_eq!(reopened.occurrence_count, 3);
        assert_eq!(
            store
                .list_findings(Some(Severity::High), Some(FindingStatus::Open), None)
                .unwrap()
                .len(),
            1
        );
        assert!(store
            .list_findings(Some(Severity::Low), None, None)
            .unwrap()
            .is_empty());
        assert!(store
            .set_finding_status("id-one", FindingStatus::Waived, "ignore")
            .unwrap_err()
            .contains("waivers require scoped provenance and expiry"));
    }

    #[test]
    fn finding_pages_apply_limit_and_offset_in_storage_and_return_filtered_total() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ReviewStore::open(&dir.path().join("finding-pages.sqlite")).unwrap();
        let findings = [
            finding("id-one", Severity::High, Some(90)),
            finding("id-two", Severity::Low, Some(80)),
            finding("id-three", Severity::High, Some(70)),
        ];
        store
            .save_review("rev-pages", "snap-pages", "cfg", "block", "{}", &findings)
            .unwrap();

        let (page, total) = store
            .list_findings_page(None, None, Some("rev-pages"), 2, 1)
            .unwrap();
        assert_eq!(total, 3);
        assert_eq!(page.len(), 2);
        let (high_page, high_total) = store
            .list_findings_page(Some(Severity::High), None, Some("rev-pages"), 1, 1)
            .unwrap();
        assert_eq!(high_total, 2);
        assert_eq!(high_page.len(), 1);
        let (empty_page, total) = store
            .list_findings_page(None, None, Some("rev-pages"), 2, 9)
            .unwrap();
        assert_eq!(total, 3);
        assert!(empty_page.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn provider_receives_stdin_without_shell_and_enforces_output_bound() {
        let working_dir = tempfile::tempdir().unwrap();
        let ok = ProviderRequest {
            kind: ProviderKind::Cli,
            executable: "/usr/bin/touch".into(),
            args: vec!["provider-relative-file".into()],
            model: None,
            working_directory: working_dir.path().into(),
            stdin: vec![],
            timeout_seconds: 2,
            output_limit_bytes: 4096,
            environment: vec![("VERO_TEST_ALLOWED".into(), "present".into())],
        };
        let _result = execute_provider(&ok).unwrap();
        assert!(!working_dir.path().join("provider-relative-file").exists());
        let too_small = ProviderRequest {
            kind: ProviderKind::Cli,
            executable: "/bin/echo".into(),
            args: vec!["this output is too large".into()],
            model: None,
            working_directory: ".".into(),
            stdin: vec![],
            output_limit_bytes: 3,
            environment: vec![],
            timeout_seconds: 2,
        };
        assert!(execute_provider(&too_small)
            .unwrap_err()
            .contains("output exceeded"));
    }

    #[cfg(unix)]
    #[test]
    fn relative_provider_executable_resolves_before_working_directory_isolation() {
        use std::os::unix::fs::PermissionsExt;

        let repository = tempfile::tempdir().unwrap();
        let executable = repository.path().join("tools/provider");
        std::fs::create_dir_all(executable.parent().unwrap()).unwrap();
        std::fs::write(&executable, "#!/bin/sh\nprintf provider-ok\n").unwrap();
        let mut permissions = std::fs::metadata(&executable).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&executable, permissions).unwrap();

        let result = execute_provider(&ProviderRequest {
            kind: ProviderKind::Cli,
            executable: "./tools/provider".into(),
            args: vec![],
            model: None,
            working_directory: repository.path().into(),
            stdin: vec![],
            timeout_seconds: 2,
            output_limit_bytes: 4096,
            environment: vec![],
        })
        .unwrap();

        assert_eq!(result.stdout, b"provider-ok");
    }

    #[cfg(unix)]
    #[test]
    fn provider_cancellation_terminates_child_process() {
        let cancellation = tokio_util::sync::CancellationToken::new();
        let child_cancellation = cancellation.clone();
        let cancel_thread = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(50));
            child_cancellation.cancel();
        });
        let request = ProviderRequest {
            kind: ProviderKind::Cli,
            executable: "/bin/sleep".into(),
            args: vec!["10".into()],
            model: None,
            working_directory: ".".into(),
            stdin: vec![],
            timeout_seconds: 20,
            output_limit_bytes: 128,
            environment: vec![],
        };
        let error = execute_provider_cancellable(&request, Some(&cancellation)).unwrap_err();
        cancel_thread.join().unwrap();
        assert!(error.contains("cancelled"));
    }

    #[cfg(unix)]
    #[test]
    fn provider_timeout_terminates_descendant_processes() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("provider-child.pid");
        let request = ProviderRequest {
            kind: ProviderKind::Cli,
            executable: "/bin/sh".into(),
            args: vec![
                "-c".into(),
                format!(
                    "sleep 30 >/dev/null 2>&1 & echo $! > '{}'; wait",
                    pid_file.display()
                ),
            ],
            model: None,
            working_directory: ".".into(),
            stdin: vec![],
            timeout_seconds: 1,
            output_limit_bytes: 128,
            environment: vec![],
        };
        assert!(execute_provider(&request)
            .unwrap_err()
            .contains("timed out"));
        assert_descendant_stopped(&pid_file);
    }

    #[cfg(unix)]
    #[test]
    fn provider_cancellation_terminates_descendant_processes() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("provider-cancelled-child.pid");
        let cancellation = tokio_util::sync::CancellationToken::new();
        let child_cancellation = cancellation.clone();
        let cancel_thread = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(100));
            child_cancellation.cancel();
        });
        let request = ProviderRequest {
            kind: ProviderKind::Cli,
            executable: "/bin/sh".into(),
            args: vec![
                "-c".into(),
                format!(
                    "sleep 30 >/dev/null 2>&1 & echo $! > '{}'; wait",
                    pid_file.display()
                ),
            ],
            model: None,
            working_directory: ".".into(),
            stdin: vec![],
            timeout_seconds: 10,
            output_limit_bytes: 128,
            environment: vec![],
        };
        assert!(execute_provider_cancellable(&request, Some(&cancellation))
            .unwrap_err()
            .contains("cancelled"));
        cancel_thread.join().unwrap();
        assert_descendant_stopped(&pid_file);
    }

    #[cfg(unix)]
    #[test]
    fn verification_runs_explicit_argv_and_records_deterministic_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let profile = VerificationProfile {
            executable: "/bin/sh".into(),
            args: vec!["-c".into(), "printf ok; exit 7".into()],
            timeout_seconds: 2,
            output_limit_bytes: 64,
            env_allowlist: vec![],
        };
        let first = execute_verification("snapshot-1", "tests", dir.path(), &profile).unwrap();
        let second = execute_verification("snapshot-1", "tests", dir.path(), &profile).unwrap();
        assert_eq!(first.status, VerificationStatus::Failed);
        assert_eq!(first.exit_code, Some(7));
        assert_eq!(first.stdout_digest, second.stdout_digest);
        assert_eq!(first.command_digest, second.command_digest);
        assert_eq!(first.snapshot_id, "snapshot-1");
        let db = dir.path().join("verification.sqlite");
        let mut store = ReviewStore::open(&db).unwrap();
        store.save_verification(&first).unwrap();
        assert_eq!(store.verification(&first.run_id).unwrap(), Some(first));
    }

    #[cfg(unix)]
    #[test]
    fn verification_uses_only_configured_environment() {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("VERO_VERIFICATION_ALLOWED", "yes");
        let profile = VerificationProfile {
            executable: "/usr/bin/env".into(),
            args: vec![],
            env_allowlist: vec!["VERO_VERIFICATION_ALLOWED".into()],
            timeout_seconds: 2,
            output_limit_bytes: 1024,
        };
        let run = execute_verification("snapshot", "env", dir.path(), &profile).unwrap();
        std::env::remove_var("VERO_VERIFICATION_ALLOWED");
        assert_eq!(run.status, VerificationStatus::Passed);
        assert_eq!(
            run.stdout_digest,
            digest(b"VERO_VERIFICATION_ALLOWED=[REDACTED]\n")
        );
    }

    #[cfg(unix)]
    #[test]
    fn verification_rejects_output_over_limit() {
        let dir = tempfile::tempdir().unwrap();
        let profile = VerificationProfile {
            executable: "/bin/sh".into(),
            args: vec!["-c".into(), "printf 123456789".into()],
            timeout_seconds: 2,
            output_limit_bytes: 4,
            env_allowlist: vec![],
        };
        assert!(
            execute_verification("snap", "bounded", dir.path(), &profile)
                .unwrap_err()
                .contains("output exceeded")
        );
    }

    #[test]
    fn verification_logs_redact_allowlisted_environment_values_before_hashing() {
        let mut output = b"token=very-secret-value path=/bin".to_vec();
        redact_output_values(
            &mut output,
            &[
                ("API_TOKEN".into(), "very-secret-value".into()),
                ("PATH".into(), "/bin".into()),
            ],
        );
        assert_eq!(output, b"token=[REDACTED] path=[REDACTED]");
    }

    #[cfg(unix)]
    #[test]
    fn verification_times_out_and_binds_limits_into_command_digest() {
        let dir = tempfile::tempdir().unwrap();
        let profile = VerificationProfile {
            executable: "/bin/sleep".into(),
            args: vec!["2".into()],
            timeout_seconds: 1,
            output_limit_bytes: 64,
            env_allowlist: vec![],
        };
        let run = execute_verification("snapshot", "slow", dir.path(), &profile).unwrap();
        assert_eq!(run.status, VerificationStatus::TimedOut);
        let changed_limit = VerificationProfile {
            output_limit_bytes: 65,
            ..profile
        };
        let other = execute_verification("snapshot", "slow", dir.path(), &changed_limit).unwrap();
        assert_ne!(run.command_digest, other.command_digest);
    }

    #[cfg(unix)]
    #[test]
    fn verification_timeout_terminates_descendant_processes() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("verification-child.pid");
        let profile = VerificationProfile {
            executable: "/bin/sh".into(),
            args: vec![
                "-c".into(),
                format!(
                    "sleep 30 >/dev/null 2>&1 & echo $! > '{}'; wait",
                    pid_file.display()
                ),
            ],
            timeout_seconds: 1,
            output_limit_bytes: 128,
            env_allowlist: vec![],
        };
        let run = execute_verification("snapshot", "descendant", dir.path(), &profile).unwrap();
        assert_eq!(run.status, VerificationStatus::TimedOut);
        assert_descendant_stopped(&pid_file);
    }

    #[cfg(unix)]
    fn assert_descendant_stopped(pid_file: &Path) {
        let pid: i32 = std::fs::read_to_string(pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let running = unsafe { libc::kill(pid, 0) == 0 };
            if !running || std::time::Instant::now() >= deadline {
                if running {
                    unsafe { libc::kill(pid, libc::SIGKILL) };
                }
                assert!(!running, "descendant process {pid} survived timeout");
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryConfig {
    pub version: u32,
    #[serde(default)]
    pub offline: bool,
    #[serde(default)]
    pub review: ReviewConfig,
    #[serde(default)]
    pub providers: std::collections::BTreeMap<String, ProviderConfig>,
    #[serde(default)]
    pub reviewers: std::collections::BTreeMap<String, ReviewerConfig>,
    #[serde(default)]
    pub verification: std::collections::BTreeMap<String, VerificationProfile>,
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub policy_profiles: std::collections::BTreeMap<String, PolicyConfig>,
    #[serde(skip)]
    pub active_policy_profile: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewConfig {
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default = "default_review_concurrency")]
    pub max_concurrency: usize,
}

impl Default for ReviewConfig {
    fn default() -> Self {
        Self {
            include: Vec::new(),
            exclude: Vec::new(),
            max_concurrency: default_review_concurrency(),
        }
    }
}

fn default_review_concurrency() -> usize {
    4
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    pub kind: ProviderKind,
    #[serde(default)]
    pub egress: ProviderEgress,
    #[serde(default)]
    pub executable: String,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub version_args: Vec<String>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub env_allowlist: Vec<String>,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    #[default]
    Cli,
    CodexCli,
    GeminiCli,
    ClaudeCli,
    #[serde(rename = "openai_compatible")]
    OpenAiCompatible,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderEgress {
    Local,
    #[default]
    Network,
}
fn default_timeout() -> u64 {
    120
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewerConfig {
    pub provider: String,
    pub instructions_file: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
}
fn default_enabled() -> bool {
    true
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    #[serde(default)]
    pub required_reviewers: Vec<String>,
    #[serde(default)]
    pub required_verifications: Vec<String>,
    #[serde(default = "default_severities")]
    pub block_severities: Vec<String>,
    #[serde(default = "default_confidence")]
    pub minimum_confidence: u8,
    #[serde(default = "default_incomplete")]
    pub on_incomplete: String,
}
impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            required_reviewers: vec![],
            required_verifications: vec![],
            block_severities: default_severities(),
            minimum_confidence: default_confidence(),
            on_incomplete: default_incomplete(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UserProviderConfig {
    pub version: u32,
    #[serde(default)]
    pub providers: std::collections::BTreeMap<String, ProviderConfig>,
}
fn default_severities() -> Vec<String> {
    vec!["critical".into(), "high".into()]
}
fn default_confidence() -> u8 {
    80
}
fn default_incomplete() -> String {
    "block".into()
}

impl RepositoryConfig {
    pub fn select_policy_profile(&mut self, profile: Option<&str>) -> Result<(), String> {
        self.active_policy_profile = None;
        if let Some(profile_id) = profile {
            self.policy = self
                .policy_profiles
                .get(profile_id)
                .cloned()
                .ok_or_else(|| format!("unknown policy profile {profile_id}"))?;
            self.active_policy_profile = Some(profile_id.to_string());
        }
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        Self::load_with_provider_defaults(path, None)
    }

    pub fn load_with_provider_defaults(
        path: &Path,
        user_config_path: Option<&Path>,
    ) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let mut config: Self =
            serde_yaml::from_str(&raw).map_err(|e| format!("{}: {e}", path.display()))?;
        if let Some(user_path) = user_config_path {
            let user_raw = std::fs::read_to_string(user_path)
                .map_err(|error| format!("{}: {error}", user_path.display()))?;
            let user: UserProviderConfig = serde_yaml::from_str(&user_raw)
                .map_err(|error| format!("{}: {error}", user_path.display()))?;
            if user.version != 1 {
                return Err(format!(
                    "{}: unsupported user config version {}",
                    user_path.display(),
                    user.version
                ));
            }
            for (id, provider) in user.providers {
                config.providers.entry(id).or_insert(provider);
            }
        }
        if config.version != 1 {
            return Err(format!("unsupported config version {}", config.version));
        }
        if !(1..=32).contains(&config.review.max_concurrency) {
            return Err("review.max_concurrency must be in 1..=32".into());
        }
        if config.policy.minimum_confidence > 100 {
            return Err("minimum_confidence must be 0..=100".into());
        }
        if config.policy.on_incomplete != "block" && config.policy.on_incomplete != "allow" {
            return Err("policy.on_incomplete must be 'block' or 'allow'".into());
        }
        for severity in &config.policy.block_severities {
            if !matches!(
                severity.as_str(),
                "critical" | "high" | "medium" | "low" | "info"
            ) {
                return Err(format!("unknown blocking severity {severity}"));
            }
        }
        for (id, provider) in &config.providers {
            if provider.kind == ProviderKind::OpenAiCompatible {
                let endpoint = provider.endpoint.as_deref().ok_or_else(|| {
                    format!("provider {id} openai_compatible requires an endpoint")
                })?;
                let url = url::Url::parse(endpoint)
                    .map_err(|_| format!("provider {id} endpoint must use http or https"))?;
                if !matches!(url.scheme(), "http" | "https") || url.host().is_none() {
                    return Err(format!("provider {id} endpoint must use http or https"));
                }
                if !url.username().is_empty() || url.password().is_some() {
                    return Err(format!(
                        "provider {id} endpoint must not contain credentials"
                    ));
                }
                if url.query().is_some() || url.fragment().is_some() {
                    return Err(format!(
                        "provider {id} endpoint must not contain a query or fragment"
                    ));
                }
                if provider.egress == ProviderEgress::Local {
                    let loopback = match url.host() {
                        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
                        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
                        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
                        None => false,
                    };
                    if !loopback {
                        return Err(format!(
                            "provider {id} local egress requires a loopback endpoint"
                        ));
                    }
                }
                if !provider.executable.is_empty()
                    || !provider.args.is_empty()
                    || !provider.version_args.is_empty()
                {
                    return Err(format!(
                        "provider {id} openai_compatible does not accept executable arguments"
                    ));
                }
                if provider
                    .model
                    .as_deref()
                    .unwrap_or_default()
                    .trim()
                    .is_empty()
                {
                    return Err(format!("provider {id} openai_compatible requires a model"));
                }
                if provider
                    .env_allowlist
                    .iter()
                    .any(|name| name != "OPENAI_API_KEY")
                {
                    return Err(format!("provider {id} openai_compatible only accepts OPENAI_API_KEY in env_allowlist"));
                }
                if provider.timeout_seconds == 0 {
                    return Err(format!("provider {id} requires a positive timeout"));
                }
                resolve_environment_allowlist(&provider.env_allowlist, |_| None)
                    .map_err(|error| format!("provider {id}: {error}"))?;
                if config.offline && provider.egress != ProviderEgress::Local {
                    return Err(format!("offline mode rejects network provider {id}; configure a local provider explicitly"));
                }
                continue;
            }
            if provider.endpoint.is_some() {
                return Err(format!(
                    "provider {id} endpoint is only valid for openai_compatible"
                ));
            }
            resolve_environment_allowlist(&provider.env_allowlist, |_| None)
                .map_err(|error| format!("provider {id}: {error}"))?;
            if provider.kind == ProviderKind::Cli && provider.model.is_some() {
                return Err(format!(
                    "provider {id} can only set model with a provider-specific adapter"
                ));
            }
            if (provider.kind == ProviderKind::CodexCli
                || provider.kind == ProviderKind::ClaudeCli
                || provider.kind == ProviderKind::GeminiCli)
                && !provider.args.is_empty()
            {
                return Err(format!(
                    "provider {id} provider-specific arguments are controlled by the adapter"
                ));
            }
            if (provider.kind == ProviderKind::CodexCli || provider.kind == ProviderKind::ClaudeCli)
                && !provider.version_args.is_empty()
            {
                return Err(format!(
                    "provider {id} provider-specific version arguments are fixed by the adapter"
                ));
            }
            if provider.kind == ProviderKind::CodexCli && provider.egress == ProviderEgress::Local {
                return Err(format!(
                    "provider {id} codex_cli cannot be declared local; use a local inference adapter"
                ));
            }
            if provider.kind == ProviderKind::GeminiCli && !provider.args.is_empty() {
                return Err(format!(
                    "provider {id} Gemini CLI arguments are controlled by the adapter"
                ));
            }
            if provider.kind == ProviderKind::GeminiCli && provider.egress == ProviderEgress::Local
            {
                return Err(format!(
                    "provider {id} gemini_cli cannot be declared local; use a local inference adapter"
                ));
            }
            if provider.kind == ProviderKind::ClaudeCli && !provider.version_args.is_empty() {
                return Err(format!(
                    "provider {id} Claude CLI version probing is controlled by the adapter"
                ));
            }
            if provider.kind == ProviderKind::ClaudeCli && provider.egress == ProviderEgress::Local
            {
                return Err(format!(
                    "provider {id} claude_cli cannot be declared local; use a local inference adapter"
                ));
            }
            if config.offline && provider.egress != ProviderEgress::Local {
                return Err(format!(
                    "offline mode rejects network provider {id}; configure a local provider explicitly"
                ));
            }
            if provider.executable.trim().is_empty() || provider.timeout_seconds == 0 {
                return Err(format!(
                    "provider {id} requires an executable and positive timeout"
                ));
            }
        }
        for (id, reviewer) in &config.reviewers {
            if !config.providers.contains_key(&reviewer.provider) {
                return Err(format!(
                    "reviewer {id} references unknown provider {}",
                    reviewer.provider
                ));
            }
            if reviewer.instructions_file.trim().is_empty() {
                return Err(format!("reviewer {id} has an empty instructions_file"));
            }
        }
        for reviewer_id in &config.policy.required_reviewers {
            if !config.reviewers.contains_key(reviewer_id) {
                return Err(format!("policy requires unknown reviewer {reviewer_id}"));
            }
        }
        for (id, profile) in &config.verification {
            resolve_environment_allowlist(&profile.env_allowlist, |_| None)
                .map_err(|error| format!("verification profile {id}: {error}"))?;
            if profile.executable.trim().is_empty() {
                return Err(format!("verification profile {id} has an empty executable"));
            }
            if profile.timeout_seconds == 0 {
                return Err(format!(
                    "verification profile {id} timeout must be positive"
                ));
            }
            if profile.output_limit_bytes == 0 {
                return Err(format!(
                    "verification profile {id} output limit must be positive"
                ));
            }
        }
        for profile_id in &config.policy.required_verifications {
            if !config.verification.contains_key(profile_id) {
                return Err(format!(
                    "policy requires unknown verification profile {profile_id}"
                ));
            }
        }
        for (profile_id, profile) in &config.policy_profiles {
            if profile.minimum_confidence > 100 {
                return Err(format!(
                    "policy profile {profile_id} minimum_confidence must be 0..=100"
                ));
            }
            if profile.on_incomplete != "block" && profile.on_incomplete != "allow" {
                return Err(format!(
                    "policy profile {profile_id} on_incomplete must be 'block' or 'allow'"
                ));
            }
            for severity in &profile.block_severities {
                if !matches!(
                    severity.as_str(),
                    "critical" | "high" | "medium" | "low" | "info"
                ) {
                    return Err(format!(
                        "policy profile {profile_id} has unknown blocking severity {severity}"
                    ));
                }
            }
            for reviewer in &profile.required_reviewers {
                if !config.reviewers.contains_key(reviewer) {
                    return Err(format!(
                        "policy profile {profile_id} requires unknown reviewer {reviewer}"
                    ));
                }
            }
            for verification in &profile.required_verifications {
                if !config.verification.contains_key(verification) {
                    return Err(format!(
                        "policy profile {profile_id} requires unknown verification profile {verification}"
                    ));
                }
            }
        }
        Ok(config)
    }
}

pub struct ReviewStore {
    connection: rusqlite::Connection,
}

fn validate_snapshot_manifest(snapshot_id: &str, manifest_json: &str) -> Result<(), String> {
    if manifest_json == "{}" {
        return Ok(());
    }
    let (schema_version, base_oid, head_oid, scope, files): (
        u32,
        Option<String>,
        Option<String>,
        String,
        Vec<SnapshotFile>,
    ) = serde_json::from_str(manifest_json)
        .map_err(|error| format!("invalid snapshot manifest: {error}"))?;
    let canonical = serde_json::to_vec(&(
        schema_version,
        base_oid.as_deref(),
        head_oid.as_deref(),
        scope.as_str(),
        &files,
    ))
    .map_err(|error| error.to_string())?;
    if digest(&canonical) != snapshot_id {
        return Err("snapshot manifest does not match its content digest".into());
    }
    Ok(())
}

const STORAGE_SCHEMA_VERSION: u32 = 6;

fn migrate_storage(connection: &mut rusqlite::Connection) -> Result<(), String> {
    use rusqlite::TransactionBehavior;

    connection
        .execute_batch("PRAGMA foreign_keys=ON")
        .map_err(|error| error.to_string())?;
    let mut version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| error.to_string())?;
    if version > STORAGE_SCHEMA_VERSION {
        return Err(format!(
            "database schema version {version} is newer than supported version {STORAGE_SCHEMA_VERSION}"
        ));
    }

    if version < 1 {
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS reviews (id TEXT PRIMARY KEY, snapshot_id TEXT NOT NULL, config_digest TEXT NOT NULL, status TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE IF NOT EXISTS findings (id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL UNIQUE, category TEXT NOT NULL, severity TEXT NOT NULL, confidence INTEGER, status TEXT NOT NULL CHECK(status IN ('open','verified','refuted','resolved','waived')), status_reason TEXT, finding_json TEXT NOT NULL, first_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, last_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE IF NOT EXISTS finding_occurrences (review_id TEXT NOT NULL REFERENCES reviews(id) ON DELETE CASCADE, finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE, snapshot_id TEXT NOT NULL, finding_json TEXT NOT NULL, observed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(review_id, finding_id));
            CREATE TABLE IF NOT EXISTS evidence (review_id TEXT NOT NULL REFERENCES reviews(id) ON DELETE CASCADE, evidence_id TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(review_id,evidence_id));
            CREATE TABLE IF NOT EXISTS verification_runs (run_id TEXT PRIMARY KEY, snapshot_id TEXT NOT NULL, profile_id TEXT NOT NULL, command_digest TEXT NOT NULL, status TEXT NOT NULL, exit_code INTEGER, stdout_digest TEXT NOT NULL, stderr_digest TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE IF NOT EXISTS gate_decisions (decision_id TEXT NOT NULL, review_id TEXT NOT NULL REFERENCES reviews(id) ON DELETE CASCADE, snapshot_id TEXT NOT NULL, policy_digest TEXT NOT NULL, evidence_digest TEXT NOT NULL, status TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(review_id,decision_id));
            CREATE TABLE IF NOT EXISTS waivers (id TEXT PRIMARY KEY, finding_fingerprint TEXT NOT NULL, snapshot_id TEXT NOT NULL, reason TEXT NOT NULL, author TEXT NOT NULL, provenance TEXT NOT NULL, created_at_unix INTEGER NOT NULL, expires_at_unix INTEGER NOT NULL);
            CREATE INDEX IF NOT EXISTS idx_waivers_snapshot ON waivers(snapshot_id,expires_at_unix);
            CREATE INDEX IF NOT EXISTS idx_gate_decisions_review ON gate_decisions(review_id,created_at);
            CREATE INDEX IF NOT EXISTS idx_findings_severity_status ON findings(severity, status);
            CREATE INDEX IF NOT EXISTS idx_occurrences_finding ON finding_occurrences(finding_id, observed_at);",
        )
        .map_err(|error| error.to_string())?;
        tx.pragma_update(None, "user_version", 1u32)
            .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        version = 1;
    }

    if version < 2 {
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let mut statement = tx
            .prepare("PRAGMA table_info(verification_runs)")
            .map_err(|error| error.to_string())?;
        let columns = statement
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        drop(statement);
        if !columns.iter().any(|column| column == "finding_id") {
            tx.execute(
                "ALTER TABLE verification_runs ADD COLUMN finding_id TEXT",
                [],
            )
            .map_err(|error| error.to_string())?;
        }
        tx.execute(
            "CREATE INDEX IF NOT EXISTS idx_verification_finding ON verification_runs(finding_id, snapshot_id, created_at)",
            [],
        )
        .map_err(|error| error.to_string())?;
        tx.pragma_update(None, "user_version", 2u32)
            .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        version = 2;
    }

    if version < 3 {
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        tx.execute(
            "ALTER TABLE gate_decisions ADD COLUMN effective_config_digest TEXT NOT NULL DEFAULT ''",
            [],
        )
        .map_err(|error| error.to_string())?;
        tx.execute(
            "UPDATE gate_decisions SET effective_config_digest=(SELECT config_digest FROM reviews WHERE reviews.id=gate_decisions.review_id)",
            [],
        )
        .map_err(|error| error.to_string())?;
        tx.pragma_update(None, "user_version", 3u32)
            .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        version = 3;
    }

    if version < 4 {
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS artifacts (digest TEXT PRIMARY KEY, path TEXT NOT NULL, size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0));
            CREATE TABLE IF NOT EXISTS verification_artifacts (run_id TEXT NOT NULL REFERENCES verification_runs(run_id) ON DELETE CASCADE, stream TEXT NOT NULL CHECK(stream IN ('stdout','stderr')), digest TEXT NOT NULL REFERENCES artifacts(digest), PRIMARY KEY(run_id,stream));
            CREATE INDEX IF NOT EXISTS idx_verification_artifacts_digest ON verification_artifacts(digest);",
        )
        .map_err(|error| error.to_string())?;
        tx.pragma_update(None, "user_version", 4u32)
            .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        version = 4;
    }

    if version < 5 {
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS provider_cache (request_key TEXT PRIMARY KEY, provider_version TEXT NOT NULL, stdout_digest TEXT NOT NULL, stdout BLOB NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);",
        )
        .map_err(|error| error.to_string())?;
        tx.pragma_update(None, "user_version", 5u32)
            .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        version = 5;
    }

    if version < 6 {
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS snapshots (snapshot_id TEXT PRIMARY KEY, manifest_json TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE IF NOT EXISTS evidence_records (evidence_id TEXT NOT NULL, review_id TEXT NOT NULL REFERENCES reviews(id) ON DELETE CASCADE, kind TEXT NOT NULL, provenance TEXT NOT NULL, source_path TEXT NOT NULL, content_digest TEXT NOT NULL, classification TEXT NOT NULL, verification TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(review_id,evidence_id));
            CREATE INDEX IF NOT EXISTS idx_evidence_review ON evidence_records(review_id,evidence_id);",
        )
        .map_err(|error| error.to_string())?;
        let review_columns = {
            let mut statement = tx
                .prepare("PRAGMA table_info(reviews)")
                .map_err(|error| error.to_string())?;
            let columns = statement
                .query_map([], |row| row.get::<_, String>(1))
                .map_err(|error| error.to_string())?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| error.to_string())?;
            columns
        };
        if review_columns.iter().any(|column| column == "snapshot_id") {
            tx.execute(
                "INSERT OR IGNORE INTO snapshots(snapshot_id,manifest_json) SELECT DISTINCT snapshot_id,'{}' FROM reviews",
                [],
            )
            .map_err(|error| error.to_string())?;
            if review_columns.iter().any(|column| column == "payload") {
                let legacy_reviews = {
                    let mut statement = tx
                        .prepare("SELECT snapshot_id,payload FROM reviews")
                        .map_err(|error| error.to_string())?;
                    let rows = statement
                        .query_map([], |row| {
                            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                        })
                        .map_err(|error| error.to_string())?;
                    rows.collect::<Result<Vec<_>, _>>()
                        .map_err(|error| error.to_string())?
                };
                for (snapshot_id, payload) in legacy_reviews {
                    let Ok(value) = serde_json::from_str::<serde_json::Value>(&payload) else {
                        continue;
                    };
                    let Some(change_set_value) = value.get("change_set") else {
                        continue;
                    };
                    let Ok(change_set) =
                        serde_json::from_value::<ChangeSet>(change_set_value.clone())
                    else {
                        continue;
                    };
                    let manifest = serde_json::to_string(&(
                        change_set.schema_version,
                        change_set.base_oid.as_deref(),
                        change_set.head_oid.as_deref(),
                        change_set.scope.as_str(),
                        &change_set.files,
                    ))
                    .map_err(|error| error.to_string())?;
                    if validate_snapshot_manifest(&snapshot_id, &manifest).is_ok() {
                        tx.execute(
                            "UPDATE snapshots SET manifest_json=?1 WHERE snapshot_id=?2 AND manifest_json='{}'",
                            rusqlite::params![manifest, snapshot_id],
                        )
                        .map_err(|error| error.to_string())?;
                    }
                }
            }
        }
        let evidence_table_exists: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='evidence')",
                [],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        let legacy_evidence = if evidence_table_exists {
            let mut statement = tx
                .prepare("SELECT review_id,evidence_id,payload FROM evidence")
                .map_err(|error| error.to_string())?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })
                .map_err(|error| error.to_string())?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|error| error.to_string())?
        } else {
            Vec::new()
        };
        for (review_id, evidence_id, payload) in legacy_evidence {
            let evidence: Evidence = serde_json::from_str(&payload)
                .map_err(|error| format!("cannot migrate evidence {evidence_id}: {error}"))?;
            let kind = serde_json::to_value(evidence.kind)
                .map_err(|error| error.to_string())?
                .as_str()
                .unwrap_or("unknown")
                .to_string();
            let classification = serde_json::to_value(evidence.classification)
                .map_err(|error| error.to_string())?
                .as_str()
                .unwrap_or("unknown")
                .to_string();
            let verification = serde_json::to_value(evidence.verification)
                .map_err(|error| error.to_string())?
                .as_str()
                .unwrap_or("unknown")
                .to_string();
            tx.execute(
                "INSERT OR IGNORE INTO evidence_records(evidence_id,review_id,kind,provenance,source_path,content_digest,classification,verification,payload) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                rusqlite::params![evidence_id, review_id, kind, evidence.provenance, evidence.source_path, evidence.content_digest, classification, verification, payload],
            )
            .map_err(|error| error.to_string())?;
        }
        tx.pragma_update(None, "user_version", 6u32)
            .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
    }
    Ok(())
}

pub struct ReviewWrite<'a> {
    pub id: &'a str,
    pub snapshot_id: &'a str,
    pub config_digest: &'a str,
    pub status: &'a str,
    pub payload: &'a str,
    pub findings: &'a [Finding],
    pub evidence: &'a [Evidence],
    pub snapshot_manifest: &'a str,
    pub decision: &'a GateDecision,
}

struct ReviewPersistence<'a> {
    id: &'a str,
    snapshot_id: &'a str,
    config_digest: &'a str,
    status: &'a str,
    payload: &'a str,
    findings: &'a [Finding],
    evidence: &'a [Evidence],
    snapshot_manifest: &'a str,
    decision: Option<&'a GateDecision>,
}

impl ReviewStore {
    pub fn open(path: &Path) -> Result<Self, String> {
        let mut connection = rusqlite::Connection::open(path).map_err(|e| e.to_string())?;
        migrate_storage(&mut connection)?;
        Ok(Self { connection })
    }

    /// Retrieve a successful provider response keyed by the complete request and tool identity.
    pub fn provider_cache_get(&self, request_key: &str) -> Result<Option<Vec<u8>>, String> {
        let cached: Option<(String, Vec<u8>)> = self
            .connection
            .query_row(
                "SELECT stdout_digest,stdout FROM provider_cache WHERE request_key=?1",
                [request_key],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        match cached {
            Some((expected, stdout)) if digest(&stdout) == expected => Ok(Some(stdout)),
            Some(_) => Err("provider cache response failed its content digest check".into()),
            None => Ok(None),
        }
    }

    /// Store a validated successful response. Callers must validate the provider schema first.
    pub fn provider_cache_put(
        &mut self,
        request_key: &str,
        provider_version: &str,
        stdout: &[u8],
    ) -> Result<(), String> {
        if !is_sha256_digest(request_key) {
            return Err("provider cache key must be a SHA-256 digest".into());
        }
        if provider_version.trim().is_empty() {
            return Err("provider cache requires a known provider version".into());
        }
        self.connection
            .execute(
                "INSERT OR IGNORE INTO provider_cache(request_key,provider_version,stdout_digest,stdout) VALUES (?1,?2,?3,?4)",
                rusqlite::params![request_key, provider_version, digest(stdout), stdout],
            )
            .map_err(|error| error.to_string())?;
        Ok(())
    }
    pub fn save(
        &mut self,
        id: &str,
        snapshot_id: &str,
        config_digest: &str,
        status: &str,
        payload: &str,
    ) -> Result<(), String> {
        let tx = self.connection.transaction().map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT OR IGNORE INTO snapshots(snapshot_id,manifest_json) VALUES (?1,'{}')",
            [snapshot_id],
        )
        .map_err(|e| e.to_string())?;
        tx.execute("INSERT INTO reviews(id,snapshot_id,config_digest,status,payload) VALUES (?1,?2,?3,?4,?5)", rusqlite::params![id,snapshot_id,config_digest,status,payload]).map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())
    }
    pub fn get(&self, id: &str) -> Result<Option<String>, String> {
        self.connection
            .query_row("SELECT payload FROM reviews WHERE id=?1", [id], |row| {
                row.get(0)
            })
            .optional()
            .map_err(|e| e.to_string())
    }

    pub fn snapshot_manifest(&self, snapshot_id: &str) -> Result<Option<String>, String> {
        self.connection
            .query_row(
                "SELECT manifest_json FROM snapshots WHERE snapshot_id=?1",
                [snapshot_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())
    }

    pub fn list_reviews(&self) -> Result<Vec<ReviewSummary>, String> {
        let mut statement = self
            .connection
            .prepare("SELECT id,snapshot_id,status,created_at FROM reviews ORDER BY created_at DESC,id DESC")
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map([], |row| {
                Ok(ReviewSummary {
                    review_id: row.get(0)?,
                    snapshot_id: row.get(1)?,
                    status: row.get(2)?,
                    created_at: row.get(3)?,
                })
            })
            .map_err(|error| error.to_string())?;
        rows.map(|row| row.map_err(|error| error.to_string()))
            .collect()
    }

    pub fn save_verification(&mut self, run: &VerificationRun) -> Result<(), String> {
        self.save_verification_with_artifacts(run)
    }

    pub fn save_verification_with_artifacts(
        &mut self,
        run: &VerificationRun,
    ) -> Result<(), String> {
        let payload = serde_json::to_string(run).map_err(|error| error.to_string())?;
        let tx = self
            .connection
            .transaction()
            .map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT OR IGNORE INTO verification_runs(run_id,snapshot_id,profile_id,finding_id,command_digest,status,exit_code,stdout_digest,stderr_digest,payload) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            rusqlite::params![run.run_id, run.snapshot_id, run.profile_id, run.finding_id, run.command_digest, match run.status { VerificationStatus::Passed => "passed", VerificationStatus::Failed => "failed", VerificationStatus::TimedOut => "timed_out" }, run.exit_code, run.stdout_digest, run.stderr_digest, payload],
        ).map_err(|error| error.to_string())?;
        for (stream, reference) in [
            ("stdout", run.stdout_artifact.as_ref()),
            ("stderr", run.stderr_artifact.as_ref()),
        ] {
            if let Some(reference) = reference {
                let expected_digest = if stream == "stdout" {
                    &run.stdout_digest
                } else {
                    &run.stderr_digest
                };
                if &reference.digest != expected_digest
                    || !reference.path.starts_with(".vero/artifacts/sha256/")
                    || reference.path.contains("..")
                {
                    return Err(format!("invalid {stream} verification artifact reference"));
                }
                tx.execute(
                    "INSERT OR IGNORE INTO artifacts(digest,path,size_bytes) VALUES (?1,?2,?3)",
                    rusqlite::params![reference.digest, reference.path, reference.size_bytes],
                )
                .map_err(|error| error.to_string())?;
                tx.execute(
                    "INSERT OR IGNORE INTO verification_artifacts(run_id,stream,digest) VALUES (?1,?2,?3)",
                    rusqlite::params![run.run_id, stream, reference.digest],
                )
                .map_err(|error| error.to_string())?;
            }
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn verification_artifact(
        &self,
        run_id: &str,
        stream: &str,
    ) -> Result<Option<ArtifactReference>, String> {
        if !matches!(stream, "stdout" | "stderr") {
            return Err("verification artifact stream must be stdout or stderr".into());
        }
        self.connection
            .query_row(
                "SELECT artifacts.digest,artifacts.path,artifacts.size_bytes FROM verification_artifacts JOIN artifacts USING(digest) WHERE run_id=?1 AND stream=?2",
                rusqlite::params![run_id, stream],
                |row| {
                    let size_bytes: i64 = row.get(2)?;
                    Ok(ArtifactReference {
                        digest: row.get(0)?,
                        path: row.get(1)?,
                        size_bytes: size_bytes.max(0) as u64,
                    })
                },
            )
            .optional()
            .map_err(|error| error.to_string())
    }

    pub fn verification(&self, run_id: &str) -> Result<Option<VerificationRun>, String> {
        self.connection
            .query_row(
                "SELECT payload FROM verification_runs WHERE run_id=?1",
                [run_id],
                |row| {
                    let payload: String = row.get(0)?;
                    serde_json::from_str(&payload).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })
                },
            )
            .optional()
            .map_err(|error| error.to_string())
    }

    pub fn verifications_for_snapshot(
        &self,
        snapshot_id: &str,
    ) -> Result<Vec<VerificationRun>, String> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT payload FROM verification_runs WHERE snapshot_id=?1 ORDER BY rowid DESC",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map([snapshot_id], |row| {
                let payload: String = row.get(0)?;
                serde_json::from_str(&payload).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })
            })
            .map_err(|error| error.to_string())?;
        rows.map(|row| row.map_err(|error| error.to_string()))
            .collect()
    }

    pub fn save_review(
        &mut self,
        id: &str,
        snapshot_id: &str,
        config_digest: &str,
        status: &str,
        payload: &str,
        findings: &[Finding],
    ) -> Result<(), String> {
        self.save_review_inner(ReviewPersistence {
            id,
            snapshot_id,
            config_digest,
            status,
            payload,
            findings,
            evidence: &[],
            snapshot_manifest: "{}",
            decision: None,
        })
    }

    pub fn save_review_with_decision(&mut self, write: ReviewWrite<'_>) -> Result<(), String> {
        self.save_review_inner(ReviewPersistence {
            id: write.id,
            snapshot_id: write.snapshot_id,
            config_digest: write.config_digest,
            status: write.status,
            payload: write.payload,
            findings: write.findings,
            evidence: write.evidence,
            snapshot_manifest: write.snapshot_manifest,
            decision: Some(write.decision),
        })
    }

    fn save_review_inner(&mut self, record: ReviewPersistence<'_>) -> Result<(), String> {
        validate_snapshot_manifest(record.snapshot_id, record.snapshot_manifest)?;
        let tx = self.connection.transaction().map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT OR IGNORE INTO snapshots(snapshot_id,manifest_json) VALUES (?1,?2)",
            rusqlite::params![record.snapshot_id, record.snapshot_manifest],
        )
        .map_err(|e| e.to_string())?;
        let saved_manifest: String = tx
            .query_row(
                "SELECT manifest_json FROM snapshots WHERE snapshot_id=?1",
                [record.snapshot_id],
                |row| row.get(0),
            )
            .map_err(|e| e.to_string())?;
        if saved_manifest == "{}" && record.snapshot_manifest != "{}" {
            tx.execute(
                "UPDATE snapshots SET manifest_json=?2 WHERE snapshot_id=?1 AND manifest_json='{}'",
                rusqlite::params![record.snapshot_id, record.snapshot_manifest],
            )
            .map_err(|e| e.to_string())?;
        } else if saved_manifest != record.snapshot_manifest {
            return Err("snapshot ID was previously stored with a different manifest".into());
        }
        tx.execute("INSERT INTO reviews(id,snapshot_id,config_digest,status,payload) VALUES (?1,?2,?3,?4,?5)", rusqlite::params![record.id,record.snapshot_id,record.config_digest,record.status,record.payload]).map_err(|e| e.to_string())?;
        for finding in record.findings {
            let severity = match finding.severity {
                Severity::Critical => "critical",
                Severity::High => "high",
                Severity::Medium => "medium",
                Severity::Low => "low",
                Severity::Info => "info",
            };
            let finding_json = serde_json::to_string(finding).map_err(|e| e.to_string())?;
            tx.execute("INSERT INTO findings(id,fingerprint,category,severity,confidence,status,finding_json) VALUES (?1,?2,?3,?4,?5,'open',?6)
                ON CONFLICT(fingerprint) DO UPDATE SET category=excluded.category,severity=excluded.severity,confidence=excluded.confidence,finding_json=excluded.finding_json,last_seen=CURRENT_TIMESTAMP,
                status=CASE WHEN findings.status IN ('resolved','waived') THEN 'open' ELSE findings.status END,
                status_reason=CASE WHEN findings.status IN ('resolved','waived') THEN 'reappeared in a later review' ELSE findings.status_reason END",
                rusqlite::params![finding.id,finding.fingerprint,finding.category,severity,finding.confidence,finding_json]).map_err(|e| e.to_string())?;
            tx.execute("INSERT INTO finding_occurrences(review_id,finding_id,snapshot_id,finding_json) VALUES (?1,?2,?3,?4)", rusqlite::params![record.id,finding.id,record.snapshot_id,finding_json]).map_err(|e| e.to_string())?;
        }
        for evidence in record.evidence {
            let payload = serde_json::to_string(evidence).map_err(|error| error.to_string())?;
            tx.execute(
                "INSERT INTO evidence(review_id,evidence_id,payload) VALUES (?1,?2,?3)",
                rusqlite::params![record.id, evidence.id, payload],
            )
            .map_err(|error| error.to_string())?;
            let kind = serde_json::to_value(evidence.kind)
                .map_err(|error| error.to_string())?
                .as_str()
                .unwrap_or("unknown")
                .to_string();
            let classification = serde_json::to_value(evidence.classification)
                .map_err(|error| error.to_string())?
                .as_str()
                .unwrap_or("unknown")
                .to_string();
            let verification = serde_json::to_value(evidence.verification)
                .map_err(|error| error.to_string())?
                .as_str()
                .unwrap_or("unknown")
                .to_string();
            tx.execute(
                "INSERT INTO evidence_records(evidence_id,review_id,kind,provenance,source_path,content_digest,classification,verification,payload) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                rusqlite::params![evidence.id, record.id, kind, evidence.provenance, evidence.source_path, evidence.content_digest, classification, verification, payload],
            )
            .map_err(|error| error.to_string())?;
        }
        if let Some(decision) = record.decision {
            save_gate_decision_tx(&tx, record.id, decision)?;
        }
        tx.commit().map_err(|e| e.to_string())
    }

    pub fn evidence_for_review(&self, review_id: &str) -> Result<Vec<Evidence>, String> {
        let mut statement = self
            .connection
            .prepare("SELECT payload FROM evidence_records WHERE review_id=?1 ORDER BY evidence_id")
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map([review_id], |row| {
                let payload: String = row.get(0)?;
                serde_json::from_str(&payload).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })
            })
            .map_err(|error| error.to_string())?;
        rows.map(|row| row.map_err(|error| error.to_string()))
            .collect()
    }

    pub fn save_gate_decision(
        &self,
        review_id: &str,
        decision: &GateDecision,
    ) -> Result<(), String> {
        save_gate_decision_connection(&self.connection, review_id, decision)
    }

    pub fn gate_decisions_for_review(&self, review_id: &str) -> Result<Vec<GateDecision>, String> {
        let mut statement = self
            .connection
            .prepare("SELECT payload,effective_config_digest FROM gate_decisions WHERE review_id=?1 ORDER BY rowid")
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map([review_id], |row| {
                let payload: String = row.get(0)?;
                let config_digest: String = row.get(1)?;
                let mut decision: GateDecision =
                    serde_json::from_str(&payload).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?;
                if decision.effective_config_digest.is_empty() {
                    decision.effective_config_digest = config_digest;
                }
                Ok(decision)
            })
            .map_err(|error| error.to_string())?;
        rows.map(|row| row.map_err(|error| error.to_string()))
            .collect()
    }

    pub fn set_finding_status(
        &mut self,
        id: &str,
        status: FindingStatus,
        reason: &str,
    ) -> Result<(), String> {
        if status == FindingStatus::Waived {
            return Err(
                "waivers require scoped provenance and expiry; waiver records are not implemented"
                    .into(),
            );
        }
        if reason.trim().is_empty() {
            return Err("finding status reason must not be empty".into());
        }
        let changed = self.connection.execute("UPDATE findings SET status=?2,status_reason=?3,last_seen=CURRENT_TIMESTAMP WHERE id=?1", rusqlite::params![id,status.as_str(),reason]).map_err(|e| e.to_string())?;
        if changed == 0 {
            return Err(format!("finding {id} was not found"));
        }
        Ok(())
    }

    pub fn create_waiver(&mut self, waiver: &Waiver) -> Result<(), String> {
        if waiver.schema_version != 1 {
            return Err(format!(
                "unsupported waiver schema version {}",
                waiver.schema_version
            ));
        }
        if waiver.id.trim().is_empty()
            || waiver.finding_fingerprint.trim().is_empty()
            || waiver.snapshot_id.trim().is_empty()
            || waiver.reason.trim().is_empty()
            || waiver.author.trim().is_empty()
            || waiver.provenance.trim().is_empty()
        {
            return Err("waiver fields must not be empty".into());
        }
        if waiver.expires_at_unix <= waiver.created_at_unix {
            return Err("waiver expiry must be after creation".into());
        }
        self.connection
            .execute(
                "INSERT INTO waivers(id,finding_fingerprint,snapshot_id,reason,author,provenance,created_at_unix,expires_at_unix) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                rusqlite::params![
                    waiver.id,
                    waiver.finding_fingerprint,
                    waiver.snapshot_id,
                    waiver.reason,
                    waiver.author,
                    waiver.provenance,
                    waiver.created_at_unix,
                    waiver.expires_at_unix,
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn waivers_for_snapshot(&self, snapshot_id: &str) -> Result<Vec<Waiver>, String> {
        let mut statement = self.connection.prepare(
            "SELECT id,finding_fingerprint,snapshot_id,reason,author,provenance,created_at_unix,expires_at_unix FROM waivers WHERE snapshot_id=?1 ORDER BY id",
        ).map_err(|error| error.to_string())?;
        let rows = statement
            .query_map([snapshot_id], |row| {
                Ok(Waiver {
                    schema_version: 1,
                    id: row.get(0)?,
                    finding_fingerprint: row.get(1)?,
                    snapshot_id: row.get(2)?,
                    reason: row.get(3)?,
                    author: row.get(4)?,
                    provenance: row.get(5)?,
                    created_at_unix: row.get(6)?,
                    expires_at_unix: row.get(7)?,
                })
            })
            .map_err(|error| error.to_string())?;
        rows.map(|row| row.map_err(|error| error.to_string()))
            .collect()
    }

    pub fn finding(&self, id: &str) -> Result<Option<FindingRecord>, String> {
        let mut record = self.connection.query_row("SELECT f.finding_json,f.status,f.status_reason,(SELECT COUNT(*) FROM finding_occurrences o WHERE o.finding_id=f.id),f.first_seen,f.last_seen FROM findings f WHERE f.id=?1", [id], finding_record_from_row).optional().map_err(|e| e.to_string())?;
        if let Some(record) = &mut record {
            record.occurrences = self.load_occurrences(&record.finding.id)?;
        }
        Ok(record)
    }

    pub fn list_findings(
        &self,
        severity: Option<Severity>,
        status: Option<FindingStatus>,
        review_id: Option<&str>,
    ) -> Result<Vec<FindingRecord>, String> {
        let severity = severity.map(severity_name);
        let status = status.map(FindingStatus::as_str);
        let mut statement = self.connection.prepare("SELECT f.finding_json,f.status,f.status_reason,(SELECT COUNT(*) FROM finding_occurrences o WHERE o.finding_id=f.id),f.first_seen,f.last_seen FROM findings f WHERE (?1 IS NULL OR f.severity=?1) AND (?2 IS NULL OR f.status=?2) AND (?3 IS NULL OR EXISTS(SELECT 1 FROM finding_occurrences x WHERE x.finding_id=f.id AND x.review_id=?3)) ORDER BY f.last_seen DESC,f.id").map_err(|e| e.to_string())?;
        let records = statement
            .query_map(
                rusqlite::params![severity, status, review_id],
                finding_record_from_row,
            )
            .map_err(|e| e.to_string())?;
        let mut records: Vec<FindingRecord> = records
            .map(|record| record.map_err(|e| e.to_string()))
            .collect::<Result<_, _>>()?;
        for record in &mut records {
            record.occurrences = self.load_occurrences(&record.finding.id)?;
        }
        Ok(records)
    }

    pub fn list_findings_page(
        &self,
        severity: Option<Severity>,
        status: Option<FindingStatus>,
        review_id: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<(Vec<FindingRecord>, usize), String> {
        if limit == 0 {
            return Err("finding page limit must be positive".into());
        }
        let limit = i64::try_from(limit).map_err(|error| error.to_string())?;
        let offset = i64::try_from(offset).map_err(|error| error.to_string())?;
        let severity = severity.map(severity_name);
        let status = status.map(FindingStatus::as_str);
        let total: i64 = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM findings f WHERE (?1 IS NULL OR f.severity=?1) AND (?2 IS NULL OR f.status=?2) AND (?3 IS NULL OR EXISTS(SELECT 1 FROM finding_occurrences x WHERE x.finding_id=f.id AND x.review_id=?3))",
                rusqlite::params![severity, status, review_id],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        let total = usize::try_from(total).map_err(|error| error.to_string())?;
        let mut statement = self
            .connection
            .prepare("SELECT f.finding_json,f.status,f.status_reason,(SELECT COUNT(*) FROM finding_occurrences o WHERE o.finding_id=f.id),f.first_seen,f.last_seen FROM findings f WHERE (?1 IS NULL OR f.severity=?1) AND (?2 IS NULL OR f.status=?2) AND (?3 IS NULL OR EXISTS(SELECT 1 FROM finding_occurrences x WHERE x.finding_id=f.id AND x.review_id=?3)) ORDER BY f.last_seen DESC,f.id LIMIT ?4 OFFSET ?5")
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(
                rusqlite::params![severity, status, review_id, limit, offset],
                finding_record_from_row,
            )
            .map_err(|error| error.to_string())?;
        let mut records: Vec<FindingRecord> = rows
            .map(|record| record.map_err(|error| error.to_string()))
            .collect::<Result<_, _>>()?;
        for record in &mut records {
            record.occurrences = self.load_occurrences(&record.finding.id)?;
        }
        Ok((records, total))
    }

    fn load_occurrences(&self, finding_id: &str) -> Result<Vec<FindingOccurrence>, String> {
        let mut statement = self.connection.prepare("SELECT review_id,snapshot_id,observed_at FROM finding_occurrences WHERE finding_id=?1 ORDER BY observed_at,review_id").map_err(|e| e.to_string())?;
        let rows = statement
            .query_map([finding_id], |row| {
                Ok(FindingOccurrence {
                    review_id: row.get(0)?,
                    snapshot_id: row.get(1)?,
                    observed_at: row.get(2)?,
                })
            })
            .map_err(|e| e.to_string())?;
        rows.map(|row| row.map_err(|e| e.to_string())).collect()
    }
}

fn save_gate_decision_tx(
    tx: &rusqlite::Transaction<'_>,
    review_id: &str,
    decision: &GateDecision,
) -> Result<(), String> {
    let status = match decision.status {
        GateStatus::Pass => "pass",
        GateStatus::Block => "block",
        GateStatus::Incomplete => "incomplete",
    };
    let payload = serde_json::to_string(decision).map_err(|error| error.to_string())?;
    tx.execute(
        "INSERT OR IGNORE INTO gate_decisions(decision_id,review_id,snapshot_id,effective_config_digest,policy_digest,evidence_digest,status,payload) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        rusqlite::params![decision.decision_id, review_id, decision.snapshot_id, decision.effective_config_digest, decision.policy_digest, decision.evidence_digest, status, payload],
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

fn save_gate_decision_connection(
    connection: &rusqlite::Connection,
    review_id: &str,
    decision: &GateDecision,
) -> Result<(), String> {
    let status = match decision.status {
        GateStatus::Pass => "pass",
        GateStatus::Block => "block",
        GateStatus::Incomplete => "incomplete",
    };
    let payload = serde_json::to_string(decision).map_err(|error| error.to_string())?;
    connection
        .execute(
            "INSERT OR IGNORE INTO gate_decisions(decision_id,review_id,snapshot_id,effective_config_digest,policy_digest,evidence_digest,status,payload) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            rusqlite::params![decision.decision_id, review_id, decision.snapshot_id, decision.effective_config_digest, decision.policy_digest, decision.evidence_digest, status, payload],
        )
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn severity_name(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

fn finding_record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<FindingRecord> {
    let finding_json: String = row.get(0)?;
    let status: String = row.get(1)?;
    let status_reason: Option<String> = row.get(2)?;
    let occurrence_count: i64 = row.get(3)?;
    let first_seen: String = row.get(4)?;
    let last_seen: String = row.get(5)?;
    let finding = serde_json::from_str(&finding_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
    })?;
    let status = FindingStatus::parse(&status).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, error.into())
    })?;
    Ok(FindingRecord {
        finding,
        status,
        status_reason,
        occurrence_count: occurrence_count.max(0) as u64,
        first_seen,
        last_seen,
        occurrences: Vec::new(),
    })
}

pub fn snapshot_is_current(reviewed: &str, current: &str) -> bool {
    reviewed == current
}

#[derive(Clone, Debug)]
pub struct ProviderResult {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: Option<i32>,
}
#[derive(Clone, Debug)]
pub struct ProviderRequest {
    pub kind: ProviderKind,
    pub executable: String,
    pub args: Vec<String>,
    pub model: Option<String>,
    pub working_directory: PathBuf,
    pub stdin: Vec<u8>,
    pub timeout_seconds: u64,
    pub output_limit_bytes: usize,
    pub environment: Vec<(String, String)>,
}
pub fn execute_provider(request: &ProviderRequest) -> Result<ProviderResult, String> {
    execute_provider_cancellable(request, None)
}

pub fn execute_provider_cancellable(
    request: &ProviderRequest,
    cancellation: Option<&tokio_util::sync::CancellationToken>,
) -> Result<ProviderResult, String> {
    use std::{
        io::{Read, Write},
        process::{Command, Stdio},
        thread,
        time::{Duration, Instant},
    };
    if request.executable.trim().is_empty() {
        return Err("provider executable is empty".into());
    }
    if request.kind != ProviderKind::Cli {
        return Err("provider-specific requests must use their adapter".into());
    }
    let executable = Path::new(&request.executable);
    let executable = if executable.is_absolute() || executable.components().count() > 1 {
        let rooted = if executable.is_absolute() {
            executable.to_path_buf()
        } else {
            request.working_directory.join(executable)
        };
        rooted.canonicalize().map_err(|error| {
            format!(
                "resolving provider executable {}: {error}",
                rooted.display()
            )
        })?
    } else {
        executable.to_path_buf()
    };
    let isolated_directory = tempfile::tempdir()
        .map_err(|error| format!("creating provider working directory: {error}"))?;
    let mut command = Command::new(executable);
    command.args(&request.args);
    command.current_dir(isolated_directory.path());
    configure_process_group(&mut command);
    let mut child = command
        .env_clear()
        .envs(request.environment.iter().cloned())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("starting provider: {e}"))?;
    let mut input = child.stdin.take().expect("piped stdin");
    let request_input = request.stdin.clone();
    let input_thread = thread::spawn(move || input.write_all(&request_input));
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let limit = request.output_limit_bytes;
    let stdout_thread = thread::spawn(move || {
        let mut b = Vec::new();
        let _ = stdout.take((limit + 1) as u64).read_to_end(&mut b);
        b
    });
    let stderr_thread = thread::spawn(move || {
        let mut b = Vec::new();
        let _ = stderr.take((limit + 1) as u64).read_to_end(&mut b);
        b
    });
    let started = Instant::now();
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|e| format!("waiting for provider: {e}"))?
        {
            let _ = input_thread.join();
            let stdout = stdout_thread
                .join()
                .map_err(|_| "provider stdout reader failed")?;
            let stderr = stderr_thread
                .join()
                .map_err(|_| "provider stderr reader failed")?;
            if stdout.len() + stderr.len() > request.output_limit_bytes {
                return Err("provider output exceeded configured limit".into());
            }
            if !status.success() {
                return Err(format!(
                    "provider exited with {}",
                    status.code().map_or("signal".into(), |c| c.to_string())
                ));
            }
            return Ok(ProviderResult {
                stdout,
                stderr,
                exit_code: status.code(),
            });
        }
        if cancellation.is_some_and(|token| token.is_cancelled()) {
            terminate_process_tree(&mut child);
            let _ = input_thread.join();
            let _ = stdout_thread.join();
            let _ = stderr_thread.join();
            return Err("provider execution cancelled".into());
        }
        if started.elapsed() >= Duration::from_secs(request.timeout_seconds) {
            terminate_process_tree(&mut child);
            let _ = input_thread.join();
            let _ = stdout_thread.join();
            let _ = stderr_thread.join();
            return Err("provider timed out".into());
        }
        thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(unix)]
fn configure_process_group(command: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
}

#[cfg(not(unix))]
fn configure_process_group(_command: &mut std::process::Command) {}

#[cfg(unix)]
fn terminate_process_tree(child: &mut std::process::Child) {
    let process_group = child.id() as i32;
    unsafe {
        libc::kill(-process_group, libc::SIGKILL);
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(not(unix))]
fn terminate_process_tree(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}
