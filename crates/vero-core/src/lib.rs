use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub mod packs;
pub mod ports;
pub use packs::{PackReference, PolicyPack};

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

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FindingFeedbackLabel {
    Confirmed,
    FalsePositive,
    Actionable,
    NotActionable,
}

impl FindingFeedbackLabel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::FalsePositive => "false_positive",
            Self::Actionable => "actionable",
            Self::NotActionable => "not_actionable",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingFeedback {
    pub schema_version: u32,
    pub feedback_id: String,
    pub finding_id: String,
    pub snapshot_id: String,
    pub label: FindingFeedbackLabel,
    pub reason: String,
    pub reviewer: String,
    pub created_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleApproval {
    pub schema_version: u32,
    pub approval_id: String,
    #[serde(default = "default_rule_approval_version")]
    pub version: u32,
    pub candidate_id: String,
    pub evidence_digest: String,
    #[serde(default)]
    pub source_feedback_ids: Vec<String>,
    #[serde(default)]
    pub activated_at_unix: Option<i64>,
    pub category: String,
    pub feedback_label: FindingFeedbackLabel,
    pub scope: String,
    pub instruction: String,
    pub approver: String,
    pub approval_reason: String,
    #[serde(default)]
    pub supersedes_approval_id: Option<String>,
    #[serde(default)]
    pub expires_at_unix: Option<i64>,
    pub created_at: String,
    pub status: String,
    pub events: Vec<RuleApprovalEvent>,
}

fn default_rule_approval_version() -> u32 {
    1
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleApprovalEvent {
    pub event_id: String,
    pub event: String,
    pub actor: String,
    pub reason: String,
    pub created_at: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    Passed,
    Failed,
    TimedOut,
    Incomplete,
}

/// Durable webhook claim result. An expired or released claim may be retried;
/// a completed delivery is never claimed again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WebhookClaim {
    Acquired { lease_token: String },
    InProgress,
    AlreadyProcessed,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VerificationProfile {
    pub executable: String,
    /// Declared network behavior of the configured check. `local` is an
    /// operator assertion; it does not provide OS-level network isolation.
    #[serde(default)]
    pub egress: ProviderEgress,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env_allowlist: Vec<String>,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_verification_output_limit")]
    pub output_limit_bytes: usize,
    /// Treat this profile as a trusted static analyzer whose stdout is SARIF 2.1.0.
    /// Results on changed lines whose level is listed in `block_levels` block the gate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sarif: Option<SarifAnalyzerConfig>,
}

/// Gate policy for a SARIF-producing verification profile.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SarifAnalyzerConfig {
    /// SARIF result levels that block the gate when reported on a changed line.
    /// An empty list makes the analyzer advisory.
    #[serde(default)]
    pub block_levels: Vec<SarifLevel>,
}

/// SARIF 2.1.0 result level.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum SarifLevel {
    Error,
    Warning,
    Note,
    None,
}

/// One analyzer result located on a changed line of the verified snapshot.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnalyzerFinding {
    /// `analyzer:<profile>:<fingerprint prefix>`; appears in gate `blocking_findings`.
    pub id: String,
    /// Digest of profile, rule, path, and the trimmed source line; stable across line shifts.
    pub fingerprint: String,
    pub rule_id: String,
    pub level: SarifLevel,
    pub path: String,
    pub line: u64,
    pub message: String,
}

/// Results of one SARIF analyzer run, restricted to the run's snapshot changes.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnalyzerReport {
    pub schema_version: u32,
    pub run_id: String,
    pub profile_id: String,
    pub snapshot_id: String,
    /// Tool names and versions from the SARIF `driver` objects.
    pub tools: Vec<String>,
    /// False when the run produced no valid SARIF; the gate then treats the
    /// analyzer as incomplete.
    pub parsed: bool,
    pub problem: Option<String>,
    pub findings: Vec<AnalyzerFinding>,
    pub results_total: usize,
    /// Results the tool itself marked as suppressed (SARIF `suppressions` with an
    /// accepted or unspecified status); they never block.
    pub results_suppressed: usize,
    /// Results outside the snapshot's changed lines (pre-existing issues).
    pub results_outside_changes: usize,
    pub limitations: Vec<String>,
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
    /// Package or test targets selected from the snapshot's impact assessment.
    #[serde(default)]
    pub targets: Vec<String>,
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

/// Bounded metadata view used by local analytics without loading stored logs.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationSummary {
    pub run_id: String,
    pub snapshot_id: String,
    pub profile_id: String,
    pub status: String,
    pub created_at: String,
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
    let environment =
        resolve_environment_allowlist(&profile.env_allowlist, |name| std::env::var(name).ok())?;
    let executable = resolve_verification_executable(&profile.executable, working_directory)?;
    let executable_digest = digest_file(&executable)?;
    let executable_identity = verification_executable_identity(&profile.executable, &executable);
    let environment_digests = environment
        .iter()
        .map(|(name, value)| (name, digest(value.as_bytes())))
        .collect::<Vec<_>>();
    let command_digest = verification_invocation_digest(
        profile,
        &executable_identity,
        &executable_digest,
        &environment_digests,
    )?;
    let mut command = Command::new(&executable);
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
    let mut status = loop {
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
    if status == VerificationStatus::Failed
        && is_known_incomplete_verification_output(&stdout, &stderr)
    {
        status = VerificationStatus::Incomplete;
    }
    if stdout.len().saturating_add(stderr.len()) > limit {
        return Err("verification output exceeded configured limit".into());
    }
    if digest_file(&executable)? != executable_digest {
        return Err("verification executable changed while the command was running".into());
    }
    let current_environment =
        resolve_environment_allowlist(&profile.env_allowlist, |name| std::env::var(name).ok())?;
    let current_environment_digests = current_environment
        .iter()
        .map(|(name, value)| (name, digest(value.as_bytes())))
        .collect::<Vec<_>>();
    if current_environment_digests != environment_digests {
        return Err("verification environment changed while the command was running".into());
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
            targets: Vec::new(),
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

/// Classify well-known offline dependency-resolution failures as incomplete
/// verification, not failing tests. Markers are deliberately narrow: generic
/// nonzero exits remain test failures, and the raw output remains available.
fn is_known_incomplete_verification_output(stdout: &[u8], stderr: &[u8]) -> bool {
    const MARKERS: [&str; 3] = [
        "module lookup disabled by GOPROXY",
        "module lookup disabled by GOSUMDB",
        "attempting to make an HTTP request, but --offline was specified",
    ];
    MARKERS.iter().any(|marker| {
        stdout
            .windows(marker.len())
            .any(|window| window == marker.as_bytes())
            || stderr
                .windows(marker.len())
                .any(|window| window == marker.as_bytes())
    })
}

/// Fingerprint the configured invocation together with the resolved executable bytes and
/// digests of present allowlisted environment values. Raw environment values are never returned.
pub fn verification_command_digest(
    profile: &VerificationProfile,
    working_directory: &Path,
) -> Result<String, String> {
    let environment =
        resolve_environment_allowlist(&profile.env_allowlist, |name| std::env::var(name).ok())?;
    let executable = resolve_verification_executable(&profile.executable, working_directory)?;
    let executable_digest = digest_file(&executable)?;
    let executable_identity = verification_executable_identity(&profile.executable, &executable);
    let environment_digests = environment
        .iter()
        .map(|(name, value)| (name, digest(value.as_bytes())))
        .collect::<Vec<_>>();
    verification_invocation_digest(
        profile,
        &executable_identity,
        &executable_digest,
        &environment_digests,
    )
}

fn verification_invocation_digest(
    profile: &VerificationProfile,
    executable_identity: &str,
    executable_digest: &str,
    environment_digests: &[(&String, String)],
) -> Result<String, String> {
    Ok(digest(
        &serde_json::to_vec(&(
            "vero-verification-invocation-v2",
            profile,
            executable_identity,
            executable_digest,
            environment_digests,
        ))
        .map_err(|error| error.to_string())?,
    ))
}

fn verification_executable_identity(requested: &str, resolved: &Path) -> String {
    let path = Path::new(requested);
    if path.is_absolute() || path.components().count() > 1 {
        requested.replace('\\', "/")
    } else {
        resolved.to_string_lossy().replace('\\', "/")
    }
}

fn resolve_verification_executable(
    executable: &str,
    working_directory: &Path,
) -> Result<PathBuf, String> {
    resolve_verification_executable_with_path(
        executable,
        working_directory,
        std::env::var_os("PATH"),
    )
}

fn default_verification_search_path() -> std::ffi::OsString {
    #[cfg(unix)]
    {
        "/usr/bin:/bin".into()
    }
    #[cfg(windows)]
    {
        let system_root = std::env::var_os("SystemRoot")
            .or_else(|| std::env::var_os("WINDIR"))
            .unwrap_or_else(|| r"C:\Windows".into());
        let system32 = PathBuf::from(&system_root).join("System32");
        std::env::join_paths([system32, PathBuf::from(system_root)]).unwrap_or_default()
    }
    #[cfg(not(any(unix, windows)))]
    {
        std::ffi::OsString::new()
    }
}

fn resolve_verification_executable_with_path(
    executable: &str,
    working_directory: &Path,
    path: Option<std::ffi::OsString>,
) -> Result<PathBuf, String> {
    let requested = Path::new(executable);
    let has_path_component = requested.components().count() > 1 || requested.is_absolute();
    let mut candidates = Vec::new();
    if has_path_component {
        let explicit_path = if requested.is_absolute() {
            requested.to_path_buf()
        } else {
            working_directory.join(requested)
        };
        candidates.push(explicit_path.clone());
        #[cfg(windows)]
        if requested.extension().is_none() {
            let extensions =
                std::env::var_os("PATHEXT").unwrap_or_else(|| ".COM;.EXE;.BAT;.CMD".into());
            for extension in extensions.to_string_lossy().split(';') {
                candidates.push(PathBuf::from(format!(
                    "{}{extension}",
                    explicit_path.display()
                )));
            }
        }
    } else {
        let search_path = path.unwrap_or_else(default_verification_search_path);
        for directory in std::env::split_paths(&search_path) {
            let directory = if directory.is_absolute() {
                directory
            } else {
                working_directory.join(directory)
            };
            candidates.push(directory.join(requested));
            #[cfg(windows)]
            if requested.extension().is_none() {
                let extensions =
                    std::env::var_os("PATHEXT").unwrap_or_else(|| ".COM;.EXE;.BAT;.CMD".into());
                for extension in extensions.to_string_lossy().split(';') {
                    candidates.push(directory.join(format!("{executable}{extension}")));
                }
            }
        }
    }
    if let Some(candidate) = first_executable_candidate(candidates)? {
        let absolute = if candidate.is_absolute() {
            candidate
        } else {
            std::env::current_dir()
                .map_err(|error| error.to_string())?
                .join(candidate)
        };
        if std::fs::symlink_metadata(&absolute)
            .map_err(|error| error.to_string())?
            .file_type()
            .is_symlink()
        {
            // Preserve argv[0] for command-name-dispatching shims such as
            // rustup's `cargo` and `rustc` symlinks. File reads still follow
            // the link, so executable hashing binds the underlying bytes.
            return Ok(absolute);
        }
        return absolute.canonicalize().map_err(|error| {
            format!(
                "resolving verification executable {}: {error}",
                absolute.display()
            )
        });
    }
    Err(format!(
        "verification executable {executable:?} was not found as an executable file"
    ))
}

fn first_executable_candidate(
    candidates: impl IntoIterator<Item = PathBuf>,
) -> Result<Option<PathBuf>, String> {
    for candidate in candidates {
        if candidate.is_file() && is_executable_file(&candidate)? {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

fn is_executable_file(path: &Path) -> Result<bool, String> {
    let metadata = std::fs::metadata(path).map_err(|error| error.to_string())?;
    if !metadata.is_file() {
        return Ok(false);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        Ok(metadata.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        Ok(true)
    }
}

fn digest_file(path: &Path) -> Result<String, String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).map_err(|error| {
        format!(
            "reading verification executable {}: {error}",
            path.display()
        )
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|error| error.to_string())?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("sha256:{}", hex(&hasher.finalize())))
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

    pub fn parse(value: &str) -> Result<Self, String> {
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
    #[serde(default)]
    pub assessments: Vec<Finding>,
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
    /// Reviewer IDs that independently reported this finding in the current review.
    #[serde(default)]
    pub reviewer_ids: Vec<String>,
    #[serde(default)]
    pub evidence_ids: Vec<String>,
    /// Human-approved rule candidates explicitly attributed by a reviewer.
    /// These links are claims from model output, constrained to approvals supplied to that run.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rule_attributions: Vec<RuleAttribution>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct RuleAttribution {
    /// Stable identity of the human-approved rule candidate.
    pub rule_id: String,
    /// Exact active approval version supplied to the reviewer.
    pub approval_id: String,
    /// Reviewer whose output reported this attribution; assigned by Vero.
    pub reviewer_id: String,
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
    #[serde(default)]
    pub rule_attributions: Vec<ProviderRuleAttribution>,
}

/// Untrusted provider claim; the application accepts it only if the exact pair
/// was in the active, in-scope guidance supplied for this review.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderRuleAttribution {
    pub rule_id: String,
    pub approval_id: String,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_inputs: Option<GateReplayInputs>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GateReplayInputs {
    pub schema_version: u32,
    pub policy: Policy,
    pub reviewer_policies: std::collections::BTreeMap<String, ReviewerPolicy>,
    pub complete: bool,
    pub verification_runs: Vec<VerificationRun>,
    pub waivers: Vec<Waiver>,
    #[serde(default)]
    pub evidence: Vec<Evidence>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub analyzer_reports: Vec<AnalyzerReport>,
    pub evaluation_time_unix: i64,
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Policy {
    pub block_severities: Vec<Severity>,
    pub minimum_confidence: u8,
    pub required_review_complete: bool,
    pub required_verifications: Vec<String>,
    /// Required verification profiles that are SARIF analyzers, with the result
    /// levels that block. Omitted when empty so earlier decisions replay unchanged.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub analyzer_block_levels: std::collections::BTreeMap<String, Vec<SarifLevel>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReviewerPolicy {
    pub block_severities: Vec<Severity>,
    pub minimum_confidence: u8,
}

#[derive(Clone, Copy, Debug)]
pub struct GateDigests<'a> {
    pub effective_config_digest: &'a str,
    pub policy_digest: &'a str,
}

#[derive(Clone, Copy, Debug)]
pub struct GateEvidence<'a> {
    pub verification_runs: &'a [VerificationRun],
    pub source_evidence: &'a [Evidence],
    /// Reports derived from SARIF analyzer runs on this snapshot.
    pub analyzer_reports: &'a [AnalyzerReport],
}

#[derive(Clone, Copy, Debug)]
pub struct GateEvaluationOptions<'a> {
    pub waiver_evaluation: WaiverEvaluation<'a>,
    pub reviewer_policies: &'a std::collections::BTreeMap<String, ReviewerPolicy>,
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

/// Whether `value` is `sha256:` followed by 64 lowercase hex digits.
pub fn is_sha256_digest(value: &str) -> bool {
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
        normalized.push(finding);
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
            reviewer_ids: Vec::new(),
            evidence_ids: Vec::new(),
            rule_attributions: finding
                .rule_attributions
                .into_iter()
                .map(|attribution| RuleAttribution {
                    rule_id: attribution.rule_id,
                    approval_id: attribution.approval_id,
                    reviewer_id: String::new(),
                })
                .collect(),
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
    evidence: GateEvidence<'_>,
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
        evidence,
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
    evidence: GateEvidence<'_>,
    waiver_evaluation: WaiverEvaluation<'_>,
) -> GateDecision {
    evaluate_gate_with_waivers_and_reviewer_policies(
        snapshot_id,
        digests,
        findings,
        policy,
        complete,
        evidence,
        GateEvaluationOptions {
            waiver_evaluation,
            reviewer_policies: &std::collections::BTreeMap::new(),
        },
    )
}

pub fn evaluate_gate_with_waivers_and_reviewer_policies(
    snapshot_id: &str,
    digests: GateDigests<'_>,
    findings: &[Finding],
    policy: &Policy,
    complete: bool,
    gate_evidence: GateEvidence<'_>,
    options: GateEvaluationOptions<'_>,
) -> GateDecision {
    let GateEvaluationOptions {
        waiver_evaluation,
        reviewer_policies,
    } = options;
    let GateDigests {
        effective_config_digest,
        policy_digest,
    } = digests;
    let GateEvidence {
        verification_runs,
        source_evidence: evidence,
        analyzer_reports,
    } = gate_evidence;
    // Only reports for runs of required analyzer profiles on this snapshot count.
    let analyzer_reports: Vec<&AnalyzerReport> = analyzer_reports
        .iter()
        .filter(|report| {
            report.snapshot_id == snapshot_id
                && policy
                    .analyzer_block_levels
                    .contains_key(&report.profile_id)
                && verification_runs
                    .iter()
                    .any(|run| run.run_id == report.run_id && run.profile_id == report.profile_id)
        })
        .collect();
    let mut applied_waivers: Vec<_> = waiver_evaluation
        .records
        .iter()
        .filter(|waiver| {
            waiver.schema_version == 1
                && waiver.snapshot_id == snapshot_id
                && waiver.created_at_unix <= waiver_evaluation.evaluation_time_unix
                && waiver.expires_at_unix > waiver_evaluation.evaluation_time_unix
                && (findings
                    .iter()
                    .any(|finding| finding.fingerprint == waiver.finding_fingerprint)
                    || analyzer_reports.iter().any(|report| {
                        report
                            .findings
                            .iter()
                            .any(|finding| finding.fingerprint == waiver.finding_fingerprint)
                    }))
        })
        .collect();
    applied_waivers.sort_by(|a, b| a.id.cmp(&b.id));
    let waived_fingerprints: std::collections::BTreeSet<_> = applied_waivers
        .iter()
        .map(|waiver| waiver.finding_fingerprint.as_str())
        .collect();
    let meets_blocking_policy = |f: &Finding| {
        policy.block_severities.contains(&f.severity)
            && f.confidence.unwrap_or(0) >= policy.minimum_confidence
            || f.reviewer_ids.iter().any(|reviewer_id| {
                reviewer_policies
                    .get(reviewer_id)
                    .is_some_and(|reviewer_policy| {
                        reviewer_policy.block_severities.contains(&f.severity)
                            && f.confidence.unwrap_or(0) >= reviewer_policy.minimum_confidence
                    })
            })
    };
    let unlocated_blockers: Vec<String> = findings
        .iter()
        .filter(|finding| {
            meets_blocking_policy(finding)
                && (finding.path.is_none() || finding.line.is_none())
                && !waived_fingerprints.contains(finding.fingerprint.as_str())
        })
        .map(|finding| finding.id.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let unobserved_blockers: Vec<String> = findings
        .iter()
        .filter(|finding| {
            meets_blocking_policy(finding)
                && finding
                    .path
                    .as_ref()
                    .zip(finding.line)
                    .is_some_and(|(path, line)| {
                        !finding.evidence_ids.iter().any(|evidence_id| {
                            evidence.iter().any(|item| {
                                item.id == *evidence_id
                                    && item.kind == EvidenceKind::Source
                                    && item.classification == EvidenceClassification::Observed
                                    && item.source_path == *path
                                    && item.start_line == Some(line)
                            })
                        })
                    })
                && !waived_fingerprints.contains(finding.fingerprint.as_str())
        })
        .map(|finding| finding.id.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let blocked: Vec<String> = findings
        .iter()
        .filter(|f| {
            meets_blocking_policy(f)
                && f.path.is_some()
                && f.line.is_some()
                && !unobserved_blockers.contains(&f.id)
                && !waived_fingerprints.contains(f.fingerprint.as_str())
        })
        .map(|f| f.id.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut verification_run_ids = Vec::new();
    let mut missing_verifications = Vec::new();
    for profile_id in &policy.required_verifications {
        match verification_runs.iter().find(|run| {
            run.finding_id.is_none()
                && run.targets.is_empty()
                && run.profile_id == *profile_id
                && run.snapshot_id == snapshot_id
        }) {
            Some(run) => {
                verification_run_ids.push(run.run_id.clone());
                let complete = if policy.analyzer_block_levels.contains_key(profile_id) {
                    // Analyzers commonly exit non-zero when they report results; the
                    // run is complete when it finished and produced valid SARIF.
                    matches!(
                        run.status,
                        VerificationStatus::Passed | VerificationStatus::Failed
                    ) && analyzer_reports
                        .iter()
                        .any(|report| report.run_id == run.run_id && report.parsed)
                } else {
                    run.status == VerificationStatus::Passed
                };
                if !complete {
                    missing_verifications.push(profile_id.clone());
                }
            }
            None => missing_verifications.push(profile_id.clone()),
        }
    }
    verification_run_ids.sort();
    missing_verifications.sort();
    let analyzer_blocked: Vec<String> = analyzer_reports
        .iter()
        .filter(|report| verification_run_ids.contains(&report.run_id))
        .flat_map(|report| {
            let levels = &policy.analyzer_block_levels[&report.profile_id];
            report
                .findings
                .iter()
                .filter(move |finding| levels.contains(&finding.level))
        })
        .filter(|finding| !waived_fingerprints.contains(finding.fingerprint.as_str()))
        .map(|finding| finding.id.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    // Analyzer reports join the evidence digest only when present, so decisions
    // without analyzers keep their earlier identities.
    let evidence_digest = if analyzer_reports.is_empty() {
        digest(
            &serde_json::to_vec(&(verification_run_ids.as_slice(), &applied_waivers, evidence))
                .expect("serializing gate evidence records"),
        )
    } else {
        digest(
            &serde_json::to_vec(&(
                verification_run_ids.as_slice(),
                &applied_waivers,
                evidence,
                &analyzer_reports,
            ))
            .expect("serializing gate evidence records"),
        )
    };
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
    } else if !unlocated_blockers.is_empty() {
        (
            GateStatus::Incomplete,
            vec![format!(
                "blocking-policy findings lack a source path or line: {}",
                unlocated_blockers.join(", ")
            )],
        )
    } else if !unobserved_blockers.is_empty() {
        (
            GateStatus::Incomplete,
            vec![format!(
                "blocking-policy findings lack source evidence on a changed line: {}",
                unobserved_blockers.join(", ")
            )],
        )
    } else if !blocked.is_empty() || !analyzer_blocked.is_empty() {
        let mut reasons = Vec::new();
        if !blocked.is_empty() {
            reasons.push("unwaived findings meet blocking policy".to_string());
        }
        if !analyzer_blocked.is_empty() {
            reasons.push(format!(
                "trusted analyzers reported blocking results on changed lines: {}",
                analyzer_blocked.join(", ")
            ));
        }
        (GateStatus::Block, reasons)
    } else if !complete {
        (
            GateStatus::Incomplete,
            vec!["review did not complete".to_string()],
        )
    } else {
        (GateStatus::Pass, Vec::new())
    };
    if status == GateStatus::Block {
        let mut reviewer_reasons = std::collections::BTreeSet::new();
        for finding in findings
            .iter()
            .filter(|finding| blocked.contains(&finding.id))
        {
            for reviewer_id in &finding.reviewer_ids {
                if reviewer_policies
                    .get(reviewer_id)
                    .is_some_and(|reviewer_policy| {
                        reviewer_policy.block_severities.contains(&finding.severity)
                            && finding.confidence.unwrap_or(0) >= reviewer_policy.minimum_confidence
                    })
                {
                    reviewer_reasons.insert(format!(
                        "reviewer {reviewer_id} policy blocked finding {}",
                        finding.id
                    ));
                }
            }
        }
        reasons.extend(reviewer_reasons);
    }
    for waiver in applied_waivers {
        let finding_id = findings
            .iter()
            .find(|finding| finding.fingerprint == waiver.finding_fingerprint)
            .map(|finding| finding.id.as_str())
            .or_else(|| {
                analyzer_reports
                    .iter()
                    .flat_map(|report| &report.findings)
                    .find(|finding| finding.fingerprint == waiver.finding_fingerprint)
                    .map(|finding| finding.id.as_str())
            });
        if let Some(finding_id) = finding_id {
            reasons.push(format!(
                "waiver {} applied to finding {} until {}",
                waiver.id, finding_id, waiver.expires_at_unix
            ));
        }
    }
    let status_name = match status {
        GateStatus::Pass => "pass",
        GateStatus::Block => "block",
        GateStatus::Incomplete => "incomplete",
    };
    let blocked: Vec<String> = blocked.into_iter().chain(analyzer_blocked).collect();
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
        replay_inputs: Some(GateReplayInputs {
            schema_version: 1,
            policy: policy.clone(),
            reviewer_policies: reviewer_policies.clone(),
            complete,
            verification_runs: verification_runs.to_vec(),
            waivers: waiver_evaluation.records.to_vec(),
            evidence: evidence.to_vec(),
            analyzer_reports: analyzer_reports.into_iter().cloned().collect(),
            evaluation_time_unix: waiver_evaluation.evaluation_time_unix,
        }),
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
        replay_inputs: None,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn verification_path_lookup_skips_non_executable_files() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let earlier = directory.path().join("earlier");
        let later = directory.path().join("later");
        std::fs::create_dir_all(&earlier).unwrap();
        std::fs::create_dir_all(&later).unwrap();
        let earlier_candidate = earlier.join("cargo");
        let later_candidate = later.join("cargo");
        std::fs::write(&earlier_candidate, "not executable").unwrap();
        std::fs::set_permissions(&earlier_candidate, std::fs::Permissions::from_mode(0o644))
            .unwrap();
        std::fs::write(&later_candidate, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&later_candidate, std::fs::Permissions::from_mode(0o755)).unwrap();

        let resolved =
            first_executable_candidate([earlier_candidate, later_candidate.clone()]).unwrap();
        assert_eq!(resolved, Some(later_candidate));
    }

    #[cfg(unix)]
    #[test]
    fn verification_executable_uses_platform_default_when_path_is_unset() {
        let directory = tempfile::tempdir().unwrap();
        let resolved =
            resolve_verification_executable_with_path("sh", directory.path(), None).unwrap();
        assert!(resolved.ends_with("sh"), "resolved {resolved:?}");
        assert!(resolved.is_absolute());
    }

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
            path: Some("src/lib.rs".into()),
            line: Some(1),
            provenance: "model_inference".into(),
            reviewer_ids: Vec::new(),
            evidence_ids: Vec::new(),
            rule_attributions: Vec::new(),
        }
    }

    fn observed_test_evidence(findings: &mut [Finding]) -> Vec<Evidence> {
        findings
            .iter_mut()
            .filter_map(|finding| {
                let path = finding.path.clone()?;
                let line = finding.line?;
                let id = format!("evidence-{}", finding.id);
                finding.evidence_ids = vec![id.clone()];
                Some(Evidence {
                    id,
                    kind: EvidenceKind::Source,
                    provenance: "source_snapshot_fixture".into(),
                    source_path: path,
                    start_line: Some(line),
                    end_line: Some(line),
                    content_digest: "sha256:fixture".into(),
                    classification: EvidenceClassification::Observed,
                    verification: EvidenceVerification::Unverified,
                })
            })
            .collect()
    }

    fn analyzer_run(run_id: &str, profile_id: &str, snapshot_id: &str) -> VerificationRun {
        VerificationRun {
            schema_version: 1,
            run_id: run_id.into(),
            snapshot_id: snapshot_id.into(),
            profile_id: profile_id.into(),
            finding_id: None,
            targets: vec![],
            command_digest: "sha256:command".into(),
            status: VerificationStatus::Failed,
            exit_code: Some(1),
            stdout_digest: "sha256:out".into(),
            stderr_digest: "sha256:err".into(),
            stdout_artifact: None,
            stderr_artifact: None,
        }
    }

    fn analyzer_report(run: &VerificationRun, level: SarifLevel) -> AnalyzerReport {
        AnalyzerReport {
            schema_version: 1,
            run_id: run.run_id.clone(),
            profile_id: run.profile_id.clone(),
            snapshot_id: run.snapshot_id.clone(),
            tools: vec!["lint 1".into()],
            parsed: true,
            problem: None,
            findings: vec![AnalyzerFinding {
                id: format!("analyzer:{}:000000000000", run.profile_id),
                fingerprint: format!("sha256:{}", run.profile_id),
                rule_id: "R1".into(),
                level,
                path: "src/lib.rs".into(),
                line: 2,
                message: "defect".into(),
            }],
            results_total: 1,
            results_suppressed: 0,
            results_outside_changes: 0,
            limitations: vec![],
        }
    }

    #[test]
    fn analyzer_results_block_only_for_required_profiles_on_the_gated_snapshot() {
        let policy = Policy {
            block_severities: vec![],
            minimum_confidence: 0,
            required_review_complete: true,
            required_verifications: vec!["lint".into()],
            analyzer_block_levels: [("lint".to_owned(), vec![SarifLevel::Error])].into(),
        };
        let gate = |runs: &[VerificationRun], reports: &[AnalyzerReport]| {
            evaluate_gate(
                "snapshot",
                "config",
                "policy",
                &[],
                &policy,
                true,
                GateEvidence {
                    verification_runs: runs,
                    source_evidence: &[],
                    analyzer_reports: reports,
                },
            )
        };
        let lint = analyzer_run("run-lint", "lint", "snapshot");
        let blocked = gate(
            std::slice::from_ref(&lint),
            &[analyzer_report(&lint, SarifLevel::Error)],
        );
        assert_eq!(blocked.status, GateStatus::Block);
        assert_eq!(
            blocked.blocking_findings,
            vec!["analyzer:lint:000000000000"]
        );

        // A non-blocking level passes; the analyzer still counts as complete.
        let advisory = gate(
            std::slice::from_ref(&lint),
            &[analyzer_report(&lint, SarifLevel::Warning)],
        );
        assert_eq!(advisory.status, GateStatus::Pass);

        // Reports for other profiles or other snapshots are not trusted evidence.
        let other = analyzer_run("run-other", "other", "snapshot");
        let stale = analyzer_run("run-lint", "lint", "older-snapshot");
        let ignored = gate(
            std::slice::from_ref(&lint),
            &[
                AnalyzerReport {
                    findings: vec![],
                    ..analyzer_report(&lint, SarifLevel::Error)
                },
                analyzer_report(&other, SarifLevel::Error),
                analyzer_report(&stale, SarifLevel::Error),
            ],
        );
        assert_eq!(ignored.status, GateStatus::Pass);

        // Without a parsed report the required analyzer is incomplete, not passing.
        let missing = gate(std::slice::from_ref(&lint), &[]);
        assert_eq!(missing.status, GateStatus::Incomplete);
        let unparsed = gate(
            std::slice::from_ref(&lint),
            &[AnalyzerReport {
                parsed: false,
                ..analyzer_report(&lint, SarifLevel::Error)
            }],
        );
        assert_eq!(unparsed.status, GateStatus::Incomplete);

        // The decision replays from its recorded inputs alone.
        let inputs = blocked.replay_inputs.clone().unwrap();
        let replayed = evaluate_gate(
            "snapshot",
            "config",
            "policy",
            &[],
            &inputs.policy,
            inputs.complete,
            GateEvidence {
                verification_runs: &inputs.verification_runs,
                source_evidence: &inputs.evidence,
                analyzer_reports: &inputs.analyzer_reports,
            },
        );
        assert_eq!(replayed.decision_id, blocked.decision_id);
    }

    #[test]
    fn gate_blocks_only_configured_severity_at_confidence_threshold() {
        let policy = Policy {
            block_severities: vec![Severity::High],
            minimum_confidence: 80,
            required_review_complete: true,
            required_verifications: vec![],
            analyzer_block_levels: Default::default(),
        };
        let mut findings = vec![
            finding("low-confidence", Severity::High, Some(79)),
            finding("high", Severity::High, Some(80)),
            finding("medium", Severity::Medium, Some(99)),
        ];
        let evidence = observed_test_evidence(&mut findings);
        let decision = evaluate_gate(
            "snapshot",
            "config",
            "policy",
            &findings,
            &policy,
            true,
            GateEvidence {
                verification_runs: &[],
                source_evidence: &evidence,
                analyzer_reports: &[],
            },
        );
        assert_eq!(decision.status, GateStatus::Block);
        assert_eq!(decision.blocking_findings, vec!["high"]);
    }

    #[test]
    fn gate_marks_unlocated_blocking_finding_incomplete() {
        let policy = Policy {
            block_severities: vec![Severity::High],
            minimum_confidence: 80,
            required_review_complete: true,
            required_verifications: vec![],
            analyzer_block_levels: Default::default(),
        };
        let mut unlocated = finding("unlocated", Severity::High, Some(95));
        unlocated.path = None;
        unlocated.line = None;
        let decision = evaluate_gate(
            "snapshot",
            "config",
            "policy",
            &[unlocated],
            &policy,
            true,
            GateEvidence {
                verification_runs: &[],
                source_evidence: &[],
                analyzer_reports: &[],
            },
        );
        assert_eq!(decision.status, GateStatus::Incomplete);
        assert!(decision.blocking_findings.is_empty());
        assert!(decision.reasons[0].contains("lack a source path or line"));
    }

    #[test]
    fn evidence_bound_gate_requires_observed_source_on_the_finding_line() {
        let policy = Policy {
            block_severities: vec![Severity::High],
            minimum_confidence: 80,
            required_review_complete: true,
            required_verifications: vec![],
            analyzer_block_levels: Default::default(),
        };
        let mut finding = finding("changed-line", Severity::High, Some(95));
        finding.evidence_ids = vec!["source-evidence".into()];
        let evidence = Evidence {
            id: "source-evidence".into(),
            kind: EvidenceKind::Source,
            provenance: "source_snapshot".into(),
            source_path: "src/lib.rs".into(),
            start_line: Some(1),
            end_line: Some(1),
            content_digest: "sha256:file".into(),
            classification: EvidenceClassification::Unknown,
            verification: EvidenceVerification::Unverified,
        };
        let reviewer_policies = std::collections::BTreeMap::new();
        let evaluate = |evidence: &[Evidence]| {
            evaluate_gate_with_waivers_and_reviewer_policies(
                "snapshot",
                GateDigests {
                    effective_config_digest: "config",
                    policy_digest: "policy",
                },
                &[finding.clone()],
                &policy,
                true,
                GateEvidence {
                    verification_runs: &[],
                    source_evidence: evidence,
                    analyzer_reports: &[],
                },
                GateEvaluationOptions {
                    waiver_evaluation: WaiverEvaluation {
                        records: &[],
                        evaluation_time_unix: 0,
                    },
                    reviewer_policies: &reviewer_policies,
                },
            )
        };
        let unknown = evaluate(std::slice::from_ref(&evidence));
        assert_eq!(unknown.status, GateStatus::Incomplete);
        assert!(unknown.reasons[0].contains("changed line"));

        let observed = Evidence {
            classification: EvidenceClassification::Observed,
            ..evidence
        };
        let blocked = evaluate(&[observed]);
        assert_eq!(blocked.status, GateStatus::Block);
        assert_eq!(blocked.blocking_findings, ["changed-line"]);
        assert_eq!(blocked.replay_inputs.unwrap().evidence.len(), 1);
    }

    #[test]
    fn reviewer_policy_blocks_findings_only_when_reported_by_that_reviewer() {
        let mut security = finding("security-finding", Severity::Critical, Some(55));
        security.reviewer_ids = vec!["security".into()];
        let mut correctness = finding("correctness-finding", Severity::Critical, Some(55));
        correctness.reviewer_ids = vec!["correctness".into()];
        let policy = Policy {
            block_severities: vec![],
            minimum_confidence: 90,
            required_review_complete: true,
            required_verifications: vec![],
            analyzer_block_levels: Default::default(),
        };
        let reviewer_policies = std::collections::BTreeMap::from([(
            "security".into(),
            ReviewerPolicy {
                block_severities: vec![Severity::Critical],
                minimum_confidence: 50,
            },
        )]);
        let mut findings = [security, correctness];
        let evidence = observed_test_evidence(&mut findings);
        let decision = evaluate_gate_with_waivers_and_reviewer_policies(
            "snapshot",
            GateDigests {
                effective_config_digest: "config",
                policy_digest: "policy",
            },
            &findings,
            &policy,
            true,
            GateEvidence {
                verification_runs: &[],
                source_evidence: &evidence,
                analyzer_reports: &[],
            },
            GateEvaluationOptions {
                waiver_evaluation: WaiverEvaluation {
                    records: &[],
                    evaluation_time_unix: 0,
                },
                reviewer_policies: &reviewer_policies,
            },
        );
        assert_eq!(decision.status, GateStatus::Block);
        assert_eq!(decision.blocking_findings, ["security-finding"]);
        assert!(decision
            .reasons
            .iter()
            .any(|reason| reason == "reviewer security policy blocked finding security-finding"));
    }

    #[test]
    fn gate_deduplicates_repeated_reports_for_the_same_finding() {
        let policy = Policy {
            block_severities: vec![Severity::High],
            minimum_confidence: 80,
            required_review_complete: true,
            required_verifications: vec![],
            analyzer_block_levels: Default::default(),
        };
        let duplicate = finding("same-finding", Severity::High, Some(99));
        let mut findings = [duplicate.clone(), duplicate];
        let evidence = observed_test_evidence(&mut findings);
        let decision = evaluate_gate(
            "snapshot",
            "config",
            "policy",
            &findings,
            &policy,
            true,
            GateEvidence {
                verification_runs: &[],
                source_evidence: &evidence,
                analyzer_reports: &[],
            },
        );
        assert_eq!(decision.status, GateStatus::Block);
        assert_eq!(decision.blocking_findings, vec!["same-finding"]);
    }

    #[test]
    fn gate_decision_identity_binds_effective_configuration_digest() {
        let policy = Policy {
            block_severities: vec![],
            minimum_confidence: 0,
            required_review_complete: true,
            required_verifications: vec![],
            analyzer_block_levels: Default::default(),
        };
        let first = evaluate_gate(
            "snapshot",
            "config-a",
            "policy",
            &[],
            &policy,
            true,
            GateEvidence {
                verification_runs: &[],
                source_evidence: &[],
                analyzer_reports: &[],
            },
        );
        let second = evaluate_gate(
            "snapshot",
            "config-b",
            "policy",
            &[],
            &policy,
            true,
            GateEvidence {
                verification_runs: &[],
                source_evidence: &[],
                analyzer_reports: &[],
            },
        );
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
            analyzer_block_levels: Default::default(),
        };
        let mut findings = [finding("finding-a", Severity::High, Some(90))];
        let evidence = observed_test_evidence(&mut findings);
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
            GateEvidence {
                verification_runs: &[],
                source_evidence: &evidence,
                analyzer_reports: &[],
            },
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
            GateEvidence {
                verification_runs: &[],
                source_evidence: &evidence,
                analyzer_reports: &[],
            },
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
            GateEvidence {
                verification_runs: &[],
                source_evidence: &evidence,
                analyzer_reports: &[],
            },
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
            GateEvidence {
                verification_runs: &[],
                source_evidence: &evidence,
                analyzer_reports: &[],
            },
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
            analyzer_block_levels: Default::default(),
        };
        let decision = evaluate_gate(
            "snapshot",
            "config",
            "policy",
            &[],
            &policy,
            false,
            GateEvidence {
                verification_runs: &[],
                source_evidence: &[],
                analyzer_reports: &[],
            },
        );
        assert_eq!(decision.status, GateStatus::Incomplete);
    }

    #[test]
    fn allowed_optional_incomplete_review_does_not_hide_blocking_findings() {
        let policy = Policy {
            block_severities: vec![Severity::High],
            minimum_confidence: 0,
            required_review_complete: false,
            required_verifications: vec![],
            analyzer_block_levels: Default::default(),
        };
        let mut findings = [finding("high", Severity::High, Some(90))];
        let evidence = observed_test_evidence(&mut findings);
        let decision = evaluate_gate(
            "snapshot",
            "config",
            "policy",
            &findings,
            &policy,
            false,
            GateEvidence {
                verification_runs: &[],
                source_evidence: &evidence,
                analyzer_reports: &[],
            },
        );
        assert_eq!(decision.status, GateStatus::Block);
        assert_eq!(decision.blocking_findings, vec!["high"]);
    }

    #[test]
    fn impact_targeted_verification_cannot_satisfy_snapshot_wide_gate_requirement() {
        let policy = Policy {
            block_severities: vec![],
            minimum_confidence: 0,
            required_review_complete: true,
            required_verifications: vec!["unit".into()],
            analyzer_block_levels: Default::default(),
        };
        let mut targeted = passed_run_for_test();
        targeted.targets = vec!["./pkg".into()];
        let decision = evaluate_gate(
            "snapshot-1",
            "config",
            "policy",
            &[],
            &policy,
            true,
            GateEvidence {
                verification_runs: &[targeted],
                source_evidence: &[],
                analyzer_reports: &[],
            },
        );
        assert_eq!(decision.status, GateStatus::Incomplete);
        assert!(decision.verification_run_ids.is_empty());
        assert!(decision.reasons[0].contains("unit"));
    }

    fn passed_run_for_test() -> VerificationRun {
        VerificationRun {
            schema_version: 1,
            run_id: "run-1".into(),
            snapshot_id: "snapshot-1".into(),
            profile_id: "unit".into(),
            finding_id: None,
            targets: Vec::new(),
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
    fn provider_normalization_preserves_same_fingerprint_reports_for_policy() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("src.rs"), "fn f() { unsafe {} }\n").unwrap();
        let bytes = br#"{"schema_version":1,"findings":[{"category":"correctness","severity":"critical","confidence":40,"rationale":"unsafe operation","path":"src.rs","line":1},{"category":"correctness","severity":"high","confidence":95,"rationale":"unsafe operation","path":"src.rs","line":1}]}"#;
        let findings = parse_provider_findings(bytes, dir.path()).unwrap();
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].fingerprint, findings[1].fingerprint);
        assert_eq!(findings[0].id, findings[1].id);
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
            "version: 1\nreview:\n  max_context_file_bytes: 4194305\n",
        )
        .unwrap();
        assert!(RepositoryConfig::load(&file)
            .unwrap_err()
            .contains("max_context_file_bytes must be in 1..=4194304"));
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
    fn reviewer_specific_policy_is_validated_and_bound_to_configuration() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(".vero.yaml");
        std::fs::write(
            &file,
            "version: 1\nproviders:\n  p: { kind: cli, executable: provider }\nreviewers:\n  security:\n    provider: p\n    instructions_file: security.md\n    policy:\n      block_severities: [critical]\n      minimum_confidence: 35\n",
        )
        .unwrap();
        let valid = RepositoryConfig::load(&file).unwrap();
        assert_eq!(
            valid.reviewers["security"].policy.minimum_confidence,
            Some(35)
        );
        let valid_digest = digest(&serde_json::to_vec(&valid).unwrap());
        std::fs::write(
            &file,
            "version: 1\nproviders:\n  p: { kind: cli, executable: provider }\nreviewers:\n  security:\n    provider: p\n    instructions_file: security.md\n    policy:\n      block_severities: [critical]\n      minimum_confidence: 36\n",
        )
        .unwrap();
        let changed = RepositoryConfig::load(&file).unwrap();
        assert_ne!(valid_digest, digest(&serde_json::to_vec(&changed).unwrap()));
        std::fs::write(
            &file,
            "version: 1\nproviders:\n  p: { kind: cli, executable: provider }\nreviewers:\n  security:\n    provider: p\n    instructions_file: security.md\n    policy:\n      block_severities: [catastrophic]\n",
        )
        .unwrap();
        assert!(RepositoryConfig::load(&file)
            .unwrap_err()
            .contains("unknown blocking severity"));
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
            "version: 1\nproviders:\n  p:\n    kind: cli\n    executable: codex\n    pricing:\n      model-a:\n        input_usd_per_million: -1\n        output_usd_per_million: 2\n",
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
    fn hosting_defaults_validate_provider_endpoints_and_environment_names() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(".vero.yaml");
        std::fs::write(
            &file,
            "version: 1\nhosting: { provider: gitlab, host: gitlab.example, api_base: https://gitlab.example/api/v4/, token_env: GITLAB_TOKEN, webhook_secret_env: VERO_WEBHOOK_SECRET, actor_login: vero-bot }\n",
        )
        .unwrap();
        let config = RepositoryConfig::load(&file).unwrap();
        assert_eq!(config.hosting.provider.as_deref(), Some("gitlab"));
        assert_eq!(config.hosting.token_env.as_deref(), Some("GITLAB_TOKEN"));

        for invalid in [
            "version: 1\nhosting: { provider: bitbucket-cloud }\n",
            "version: 1\nhosting: { token_env: 'TOKEN;echo bad' }\n",
            "version: 1\nhosting: { api_base: http://example.com/api/ }\n",
            "version: 1\nhosting: { api_base: https://user:secret@example.com/ }\n",
        ] {
            std::fs::write(&file, invalid).unwrap();
            assert!(RepositoryConfig::load(&file).is_err(), "accepted {invalid}");
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
            "version: 1\noffline: true\nverification:\n  unit: { executable: cargo, args: [test] }\n",
        )
        .unwrap();
        assert!(RepositoryConfig::load(&file)
            .unwrap_err()
            .contains("offline mode rejects network verification profile unit"));

        std::fs::write(
            &file,
            "version: 1\noffline: true\nverification:\n  unit: { executable: cargo, egress: local, args: [test, --offline] }\n",
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
    fn provider_input_token_budget_is_validated_and_defaults_to_unset() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(".vero.yaml");
        std::fs::write(
            &file,
            "version: 1\nproviders:\n  local: { kind: openai_compatible, egress: local, endpoint: http://127.0.0.1:11434/v1/chat/completions, model: gemma3:12b, max_input_tokens: 12000 }\n",
        )
        .unwrap();
        let config = RepositoryConfig::load(&file).unwrap();
        assert_eq!(config.providers["local"].max_input_tokens, Some(12_000));

        for tokens in ["0", "1023", "131073"] {
            std::fs::write(
                &file,
                format!(
                    "version: 1\nproviders:\n  local: {{ kind: cli, executable: reviewer, max_input_tokens: {tokens} }}\n"
                ),
            )
            .unwrap();
            assert!(
                RepositoryConfig::load(&file)
                    .unwrap_err()
                    .contains("max_input_tokens must be in 1024..=131072"),
                "accepted token budget {tokens}"
            );
        }

        std::fs::write(
            &file,
            "version: 1\nproviders:\n  local: { kind: cli, executable: reviewer }\n",
        )
        .unwrap();
        assert_eq!(
            RepositoryConfig::load(&file).unwrap().providers["local"].max_input_tokens,
            None
        );
    }

    #[test]
    fn ollama_native_provider_requires_loopback_and_explicit_context_budget() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(".vero.yaml");
        std::fs::write(
            &file,
            "version: 1\noffline: true\nproviders:\n  local:\n    kind: ollama_native\n    egress: local\n    endpoint: http://127.0.0.1:11434/api/chat\n    model: gemma3:12b\n    max_input_tokens: 28000\n    context_window_tokens: 32768\n    max_output_tokens: 4096\n",
        )
        .unwrap();
        let config = RepositoryConfig::load(&file).unwrap();
        assert_eq!(config.providers["local"].kind, ProviderKind::OllamaNative);
        assert_eq!(config.providers["local"].max_output_tokens, Some(4096));
        assert_eq!(
            config.providers["local"].context_window_tokens,
            Some(32_768)
        );

        std::fs::write(
            &file,
            "version: 1\noffline: true\nproviders:\n  local:\n    kind: ollama_native\n    egress: local\n    endpoint: http://127.0.0.1:11434/api/chat\n    model: gemma3:12b\n    max_input_tokens: 30000\n    context_window_tokens: 32768\n",
        )
        .unwrap();
        let defaulted = RepositoryConfig::load(&file).unwrap();
        assert_eq!(defaulted.providers["local"].max_output_tokens, None);

        for invalid in [
            "version: 1\nproviders:\n  local: { kind: ollama_native, endpoint: https://127.0.0.1:11434/api/chat, model: m, max_input_tokens: 30000, context_window_tokens: 32768 }\n",
            "version: 1\nproviders:\n  local: { kind: ollama_native, egress: local, endpoint: http://example.com/api/chat, model: m, max_input_tokens: 30000, context_window_tokens: 32768 }\n",
            "version: 1\nproviders:\n  local: { kind: ollama_native, egress: local, endpoint: http://127.0.0.1:11434/api/chat, model: m, max_input_tokens: 30000 }\n",
            "version: 1\nproviders:\n  local: { kind: ollama_native, egress: local, endpoint: http://127.0.0.1:11434/api/chat, model: m, max_input_tokens: 32000, context_window_tokens: 32768 }\n",
            "version: 1\nproviders:\n  local: { kind: ollama_native, egress: local, endpoint: http://127.0.0.1:11434/api/chat, model: m, max_input_tokens: 30000, context_window_tokens: 32768, max_output_tokens: 4096 }\n",
            "version: 1\nproviders:\n  local: { kind: ollama_native, egress: local, endpoint: http://127.0.0.1:11434/api/chat, model: m, max_input_tokens: 30000, context_window_tokens: 32768, max_output_tokens: 0 }\n",
            "version: 1\nproviders:\n  local: { kind: ollama_native, egress: local, endpoint: http://127.0.0.1:11434/api/chat, model: m, max_input_tokens: 30000, context_window_tokens: 32768, max_output_tokens: 131073 }\n",
            "version: 1\nproviders:\n  local: { kind: cli, executable: reviewer, max_output_tokens: 4096 }\n",
        ] {
            std::fs::write(&file, invalid).unwrap();
            assert!(RepositoryConfig::load(&file).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn forced_offline_mode_cannot_be_weakened_by_repository_configuration() {
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join(".vero.yaml");
        std::fs::write(
            &config_path,
            "version: 1\noffline: false\nproviders:\n  hosted: { kind: cli, executable: reviewer, egress: network }\n",
        )
        .unwrap();

        let error =
            RepositoryConfig::load_with_provider_defaults_and_offline(&config_path, None, true)
                .unwrap_err();
        assert!(error.contains("offline mode rejects network provider hosted"));
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
    fn vendor_api_keys_are_accepted_only_for_their_vendor_endpoint() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(".vero.yaml");
        let load = |env: &str, endpoint: &str| {
            std::fs::write(
                &file,
                format!("version: 1\nproviders:\n  api:\n    kind: openai_compatible\n    egress: network\n    endpoint: {endpoint}\n    model: some-model\n    env_allowlist: [{env}]\n"),
            )
            .unwrap();
            RepositoryConfig::load(&file)
        };
        for (env, endpoint) in [
            (
                "OPENAI_API_KEY",
                "https://api.openai.com/v1/chat/completions",
            ),
            (
                "OPENAI_API_KEY",
                "https://llm.internal.example/v1/chat/completions",
            ),
            (
                "ANTHROPIC_API_KEY",
                "https://api.anthropic.com/v1/chat/completions",
            ),
            (
                "GEMINI_API_KEY",
                "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
            ),
        ] {
            assert!(load(env, endpoint).is_ok(), "{env} -> {endpoint}");
        }
        for (env, endpoint, message) in [
            (
                "ANTHROPIC_API_KEY",
                "https://attacker.example/v1/chat/completions",
                "only to its vendor endpoint",
            ),
            (
                "GEMINI_API_KEY",
                "http://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
                "only to its vendor endpoint",
            ),
            (
                "AWS_SECRET_ACCESS_KEY",
                "https://api.openai.com/v1/chat/completions",
                "accepts only",
            ),
            (
                "OPENAI_API_KEY, ANTHROPIC_API_KEY",
                "https://api.anthropic.com/v1/chat/completions",
                "at most one API key",
            ),
        ] {
            let error = load(env, endpoint).unwrap_err();
            assert!(error.contains(message), "{env} -> {endpoint}: {error}");
        }
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
            context_window_tokens: None,
            max_output_tokens: None,
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
            context_window_tokens: None,
            max_output_tokens: None,
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
            context_window_tokens: None,
            max_output_tokens: None,
            environment: vec![],
        })
        .unwrap();

        assert_eq!(result.stdout, b"provider-ok");
    }

    #[cfg(unix)]
    #[test]
    fn provider_failure_reports_bounded_redacted_stderr() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("provider");
        std::fs::write(
            &executable,
            "#!/bin/sh\nprintf 'Error: token=%s\\n' \"$API_TOKEN\" >&2\nexit 7\n",
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&executable).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&executable, permissions).unwrap();

        let error = execute_provider(&ProviderRequest {
            kind: ProviderKind::Cli,
            executable: executable.to_string_lossy().into_owned(),
            args: vec![],
            model: None,
            working_directory: directory.path().into(),
            stdin: vec![],
            timeout_seconds: 2,
            output_limit_bytes: 4096,
            context_window_tokens: None,
            max_output_tokens: None,
            environment: vec![("API_TOKEN".into(), "secret-value".into())],
        })
        .unwrap_err();

        assert!(error.contains("provider exited with 7"));
        assert!(error.contains("Error:token=[REDACTED]"));
        assert!(!error.contains("secret-value"));
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
            context_window_tokens: None,
            max_output_tokens: None,
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
            context_window_tokens: None,
            max_output_tokens: None,
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
        let child_pid_file = pid_file.clone();
        let cancel_thread = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while !child_pid_file.exists() && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
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
            context_window_tokens: None,
            max_output_tokens: None,
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
    fn offline_dependency_resolution_failure_is_incomplete() {
        let dir = tempfile::tempdir().unwrap();
        let profile = VerificationProfile {
            egress: Default::default(),
            executable: "/bin/sh".into(),
            args: vec![
                "-c".into(),
                "printf 'module lookup disabled by GOPROXY\\n' >&2; exit 1".into(),
            ],
            timeout_seconds: 2,
            output_limit_bytes: 256,
            env_allowlist: vec![],
            sarif: None,
        };
        let run = execute_verification("snapshot-1", "tests", dir.path(), &profile).unwrap();
        assert_eq!(run.status, VerificationStatus::Incomplete);
        assert_eq!(run.exit_code, Some(1));
    }

    #[cfg(unix)]
    #[test]
    fn cargo_offline_dependency_download_failure_is_incomplete() {
        let dir = tempfile::tempdir().unwrap();
        let profile = VerificationProfile {
            egress: Default::default(),
            executable: "/bin/sh".into(),
            args: vec![
                "-c".into(),
                "printf 'attempting to make an HTTP request, but --offline was specified\\n' >&2; exit 101".into(),
            ],
            timeout_seconds: 2,
            output_limit_bytes: 256,
            env_allowlist: vec![],
            sarif: None,
        };
        let run = execute_verification("snapshot-1", "cargo-tests", dir.path(), &profile).unwrap();
        assert_eq!(run.status, VerificationStatus::Incomplete);
        assert_eq!(run.exit_code, Some(101));
    }

    #[cfg(unix)]
    #[test]
    fn verification_uses_only_configured_environment() {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("VERO_VERIFICATION_ALLOWED", "yes");
        let profile = VerificationProfile {
            egress: Default::default(),
            executable: "/usr/bin/env".into(),
            args: vec![],
            env_allowlist: vec!["VERO_VERIFICATION_ALLOWED".into()],
            timeout_seconds: 2,
            output_limit_bytes: 1024,
            sarif: None,
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
            egress: Default::default(),
            executable: "/bin/sh".into(),
            args: vec!["-c".into(), "printf 123456789".into()],
            timeout_seconds: 2,
            output_limit_bytes: 4,
            env_allowlist: vec![],
            sarif: None,
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
            egress: Default::default(),
            executable: "/bin/sleep".into(),
            args: vec!["2".into()],
            timeout_seconds: 1,
            output_limit_bytes: 64,
            env_allowlist: vec![],
            sarif: None,
        };
        let run = execute_verification("snapshot", "slow", dir.path(), &profile).unwrap();
        assert_eq!(run.status, VerificationStatus::TimedOut);
        let changed_limit = VerificationProfile {
            egress: Default::default(),
            output_limit_bytes: 65,
            ..profile
        };
        let other = execute_verification("snapshot", "slow", dir.path(), &changed_limit).unwrap();
        assert_ne!(run.command_digest, other.command_digest);
        let local_profile = VerificationProfile {
            egress: ProviderEgress::Local,
            ..changed_limit
        };
        let local = execute_verification("snapshot", "slow", dir.path(), &local_profile).unwrap();
        assert_ne!(other.command_digest, local.command_digest);
    }

    #[cfg(unix)]
    #[test]
    fn verification_command_digest_tracks_executable_and_environment_without_exposing_values() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("verify.sh");
        std::fs::write(&executable, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
        let profile = VerificationProfile {
            egress: Default::default(),
            executable: "./verify.sh".into(),
            args: vec![],
            timeout_seconds: 5,
            output_limit_bytes: 64,
            env_allowlist: vec!["VERO_TEST_SECRET".into()],
            sarif: None,
        };
        let name = "VERO_TEST_SECRET".to_string();
        let executable_digest = digest_file(&executable).unwrap();
        let executable_identity =
            verification_executable_identity(&profile.executable, &executable);
        let first_environment = vec![(&name, digest(b"secret-one"))];
        let second_environment = vec![(&name, digest(b"secret-two"))];
        let first_with_environment = verification_invocation_digest(
            &profile,
            &executable_identity,
            &executable_digest,
            &first_environment,
        )
        .unwrap();
        let second_with_environment = verification_invocation_digest(
            &profile,
            &executable_identity,
            &executable_digest,
            &second_environment,
        )
        .unwrap();
        assert_ne!(first_with_environment, second_with_environment);
        assert!(!first_with_environment.contains("secret-one"));
        let first = verification_command_digest(&profile, dir.path()).unwrap();
        std::fs::write(&executable, "#!/bin/sh\nexit 1\n").unwrap();
        let second = verification_command_digest(&profile, dir.path()).unwrap();
        assert_ne!(first, second);
        assert!(first.starts_with("sha256:"));
        assert!(second.starts_with("sha256:"));
    }

    #[cfg(unix)]
    #[test]
    fn verification_timeout_terminates_descendant_processes() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("verification-child.pid");
        let profile = VerificationProfile {
            egress: Default::default(),
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
            sarif: None,
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
            if !process_is_running(pid) {
                return;
            }
            if std::time::Instant::now() >= deadline {
                if process_is_running(pid) {
                    unsafe { libc::kill(pid, libc::SIGKILL) };
                }
                assert!(
                    !process_is_running(pid),
                    "descendant process {pid} survived timeout"
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    #[cfg(target_os = "linux")]
    fn process_is_running(pid: i32) -> bool {
        // kill(pid, 0) also succeeds for zombies. Containers with a minimal
        // PID 1 may leave killed grandchildren unreaped, even though they
        // cannot execute or retain resources. Read the kernel state so the
        // process-tree termination assertion checks execution, not reaping.
        if let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            if let Some(state) = stat
                .rsplit_once(") ")
                .and_then(|(_, rest)| rest.chars().next())
            {
                return !matches!(state, 'Z' | 'X');
            }
        }
        unsafe { libc::kill(pid, 0) == 0 }
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    fn process_is_running(pid: i32) -> bool {
        unsafe { libc::kill(pid, 0) == 0 }
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
    pub test_generation: TestGenerationConfig,
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
    /// Non-secret defaults for optional Git hosting integrations. Tokens and
    /// webhook secrets are always read from the named environment variables.
    #[serde(default)]
    pub hosting: HostingConfig,
    #[serde(skip)]
    pub active_policy_profile: Option<String>,
    /// Digest-pinned policy packs merged into this configuration at load time.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub packs: Vec<PackReference>,
    /// Approved rules contributed by packs; their pins are covered by `packs`.
    #[serde(skip)]
    pub pack_rules: Vec<RuleApproval>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TestGenerationConfig {
    /// Estimated prompt token budget for snapshot-bound test proposals.
    #[serde(default = "default_test_generation_tokens")]
    pub max_context_tokens: usize,
}

impl Default for TestGenerationConfig {
    fn default() -> Self {
        Self {
            max_context_tokens: default_test_generation_tokens(),
        }
    }
}

fn default_test_generation_tokens() -> usize {
    20_000
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostingConfig {
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub api_base: Option<String>,
    #[serde(default)]
    pub token_env: Option<String>,
    #[serde(default)]
    pub webhook_secret_env: Option<String>,
    #[serde(default)]
    pub actor_login: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
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
    #[serde(default = "default_context_files")]
    pub max_context_files: usize,
    #[serde(default = "default_context_file_bytes")]
    pub max_context_file_bytes: usize,
    #[serde(default = "default_context_bytes")]
    pub max_context_bytes: usize,
}

impl Default for ReviewConfig {
    fn default() -> Self {
        Self {
            include: Vec::new(),
            exclude: Vec::new(),
            max_concurrency: default_review_concurrency(),
            max_context_files: default_context_files(),
            max_context_file_bytes: default_context_file_bytes(),
            max_context_bytes: default_context_bytes(),
        }
    }
}

fn default_review_concurrency() -> usize {
    4
}

fn default_context_files() -> usize {
    512
}

fn default_context_file_bytes() -> usize {
    128 * 1024
}

fn default_context_bytes() -> usize {
    512 * 1024
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
    /// Approximate maximum input tokens for this provider. When set, review
    /// context is trimmed deterministically before execution; changed source
    /// is never silently dropped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_input_tokens: Option<usize>,
    /// Maximum generated tokens for local Ollama inference. Defaults to 2048.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<usize>,
    /// Context window sent to local Ollama's native API. Ollama may otherwise
    /// use a smaller server default than the model's advertised capacity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_window_tokens: Option<usize>,
    #[serde(default)]
    pub env_allowlist: Vec<String>,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    /// Optional user-maintained token prices. Estimates never affect review gates.
    #[serde(default)]
    pub pricing: std::collections::BTreeMap<String, ModelTokenPricing>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelTokenPricing {
    pub input_usd_per_million: f64,
    pub output_usd_per_million: f64,
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
    OllamaNative,
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
    /// Trusted configuration paths whose current repository contents provide
    /// supplemental, untrusted source context to this reviewer.
    #[serde(default)]
    pub context_files: Vec<String>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default)]
    pub policy: ReviewerPolicyConfig,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewerPolicyConfig {
    /// Additional severities that this reviewer can independently block.
    #[serde(default)]
    pub block_severities: Vec<String>,
    /// Reviewer-specific confidence threshold; defaults to the repository threshold.
    #[serde(default)]
    pub minimum_confidence: Option<u8>,
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
    #[serde(default)]
    pub acceptance: AcceptancePolicyConfig,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptancePolicyConfig {
    /// Require at least one passing snapshot-bound verification per met criterion.
    #[serde(default)]
    pub require_passing_verification: bool,
    /// Require each listed verification profile to pass for every met criterion.
    #[serde(default)]
    pub required_verification_profiles: Vec<String>,
}
impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            required_reviewers: vec![],
            required_verifications: vec![],
            block_severities: default_severities(),
            minimum_confidence: default_confidence(),
            on_incomplete: default_incomplete(),
            acceptance: AcceptancePolicyConfig::default(),
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
/// API key environment variables an HTTP provider may forward, with the vendor
/// host each key is bound to. `OPENAI_API_KEY` is also the conventional key for
/// self-hosted OpenAI-compatible servers, so it is not host-bound.
pub const PROVIDER_API_KEYS: &[(&str, Option<&str>)] = &[
    ("OPENAI_API_KEY", None),
    ("ANTHROPIC_API_KEY", Some("api.anthropic.com")),
    ("GEMINI_API_KEY", Some("generativelanguage.googleapis.com")),
];

/// A repository configuration must not be able to route a vendor credential to an
/// arbitrary endpoint, so vendor keys are accepted only for their vendor's HTTPS host.
fn validate_api_key_binding(id: &str, names: &[String], endpoint: &url::Url) -> Result<(), String> {
    if names.len() > 1 {
        return Err(format!(
            "provider {id} openai_compatible forwards at most one API key"
        ));
    }
    let Some(name) = names.first() else {
        return Ok(());
    };
    let Some((_, host)) = PROVIDER_API_KEYS.iter().find(|(key, _)| key == name) else {
        let accepted: Vec<_> = PROVIDER_API_KEYS.iter().map(|(key, _)| *key).collect();
        return Err(format!(
            "provider {id} openai_compatible accepts only {} in env_allowlist",
            accepted.join(", ")
        ));
    };
    if let Some(host) = host {
        let bound = endpoint.scheme() == "https" && endpoint.host_str() == Some(*host);
        if !bound {
            return Err(format!(
                "provider {id}: {name} is forwarded only to its vendor endpoint https://{host}"
            ));
        }
    }
    Ok(())
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
        Self::load_with_provider_defaults_and_offline(path, user_config_path, false)
    }

    /// Load repository and user provider configuration while allowing the caller
    /// to force offline mode. The override only strengthens the repository setting.
    pub fn load_with_provider_defaults_and_offline(
        path: &Path,
        user_config_path: Option<&Path>,
        force_offline: bool,
    ) -> Result<Self, String> {
        let root = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        Self::load_for_repository(path, root, user_config_path, force_offline)
    }

    /// Load `path` as the configuration of the repository at `root`; pinned
    /// packs resolve against `root`, which matters when validating a candidate
    /// configuration written to a temporary file.
    pub fn load_for_repository(
        path: &Path,
        root: &Path,
        user_config_path: Option<&Path>,
        force_offline: bool,
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
        packs::apply_packs(&mut config, root)?;
        config.offline |= force_offline;
        if !(1..=32).contains(&config.review.max_concurrency) {
            return Err("review.max_concurrency must be in 1..=32".into());
        }
        if !(1..=2048).contains(&config.review.max_context_files) {
            return Err("review.max_context_files must be in 1..=2048".into());
        }
        if !(1..=4 * 1024 * 1024).contains(&config.review.max_context_file_bytes) {
            return Err("review.max_context_file_bytes must be in 1..=4194304".into());
        }
        if !(1..=16 * 1024 * 1024).contains(&config.review.max_context_bytes) {
            return Err("review.max_context_bytes must be in 1..=16777216".into());
        }
        for (id, provider) in &config.providers {
            if let Some(context_window) = provider.context_window_tokens {
                if !(1024..=131_072).contains(&context_window) {
                    return Err(format!(
                        "provider {id} context_window_tokens must be in 1024..=131072"
                    ));
                }
                if provider.kind != ProviderKind::OllamaNative {
                    return Err(format!(
                        "provider {id} context_window_tokens is only valid for ollama_native"
                    ));
                }
            }
            if provider
                .max_input_tokens
                .is_some_and(|tokens| !(1024..=131_072).contains(&tokens))
            {
                return Err(format!(
                    "providers.{id}.max_input_tokens must be in 1024..=131072"
                ));
            }
            if provider
                .max_output_tokens
                .is_some_and(|tokens| !(1..=131_072).contains(&tokens))
            {
                return Err(format!(
                    "providers.{id}.max_output_tokens must be in 1..=131072"
                ));
            }
            if provider.max_output_tokens.is_some() && provider.kind != ProviderKind::OllamaNative {
                return Err(format!(
                    "provider {id} max_output_tokens is only valid for ollama_native"
                ));
            }
        }
        if !(1024..=131_072).contains(&config.test_generation.max_context_tokens) {
            return Err("test_generation.max_context_tokens must be in 1024..=131072".into());
        }
        if let Some(provider) = config.hosting.provider.as_deref() {
            if !matches!(
                provider,
                "github" | "gitlab" | "bitbucket" | "azure-devops" | "gerrit"
            ) {
                return Err(format!("unsupported hosting provider {provider}"));
            }
        }
        if let Some(host) = config.hosting.host.as_deref() {
            if host.is_empty()
                || !host.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':' | b'[' | b']')
                })
            {
                return Err("hosting.host must be a hostname or IP address".into());
            }
        }
        for (field, value) in [
            ("hosting.token_env", config.hosting.token_env.as_deref()),
            (
                "hosting.webhook_secret_env",
                config.hosting.webhook_secret_env.as_deref(),
            ),
        ] {
            if let Some(value) = value {
                let mut bytes = value.bytes();
                let valid_first = bytes
                    .next()
                    .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_');
                if !valid_first || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_') {
                    return Err(format!("{field} must be an environment variable name"));
                }
            }
        }
        if let Some(api_base) = config.hosting.api_base.as_deref() {
            let url = url::Url::parse(api_base)
                .map_err(|_| "hosting.api_base must be an absolute HTTP(S) URL".to_string())?;
            if !matches!(url.scheme(), "http" | "https")
                || url.host().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
            {
                return Err(
                    "hosting.api_base must not contain credentials, a query, or a fragment".into(),
                );
            }
            let loopback = match url.host() {
                Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
                Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
                Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
                None => false,
            };
            if url.scheme() != "https" && !loopback {
                return Err("hosting.api_base must use HTTPS except for loopback fixtures".into());
            }
        }
        for (field, value) in [
            ("hosting.actor_login", config.hosting.actor_login.as_deref()),
            ("hosting.username", config.hosting.username.as_deref()),
        ] {
            if value.is_some_and(|value| value.len() > 256 || value.chars().any(char::is_control)) {
                return Err(format!("{field} is invalid or too long"));
            }
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
            for (model, pricing) in &provider.pricing {
                if model.trim().is_empty()
                    || !pricing.input_usd_per_million.is_finite()
                    || !pricing.output_usd_per_million.is_finite()
                    || pricing.input_usd_per_million < 0.0
                    || pricing.output_usd_per_million < 0.0
                {
                    return Err(format!(
                        "provider {id} pricing for model {model:?} must use a non-empty model name and finite non-negative USD per million token rates"
                    ));
                }
            }
            if provider.kind == ProviderKind::OpenAiCompatible
                || provider.kind == ProviderKind::OllamaNative
            {
                let provider_label = if provider.kind == ProviderKind::OllamaNative {
                    "ollama_native"
                } else {
                    "openai_compatible"
                };
                let endpoint = provider.endpoint.as_deref().ok_or_else(|| {
                    format!("provider {id} {provider_label} requires an endpoint")
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
                if provider.kind == ProviderKind::OllamaNative && url.scheme() != "http" {
                    return Err(format!(
                        "provider {id} ollama_native requires an http loopback endpoint"
                    ));
                }
                if provider.kind == ProviderKind::OllamaNative
                    && provider.egress != ProviderEgress::Local
                {
                    return Err(format!("provider {id} ollama_native requires local egress"));
                }
                if !provider.executable.is_empty()
                    || !provider.args.is_empty()
                    || !provider.version_args.is_empty()
                {
                    return Err(format!(
                        "provider {id} {provider_label} does not accept executable arguments"
                    ));
                }
                if provider
                    .model
                    .as_deref()
                    .unwrap_or_default()
                    .trim()
                    .is_empty()
                {
                    return Err(format!("provider {id} {provider_label} requires a model"));
                }
                if provider.kind == ProviderKind::OllamaNative
                    && provider.context_window_tokens.is_none()
                {
                    return Err(format!(
                        "provider {id} ollama_native requires context_window_tokens"
                    ));
                }
                if provider.kind == ProviderKind::OllamaNative {
                    let context_window = provider.context_window_tokens.unwrap_or_default();
                    let input_budget = provider.max_input_tokens.unwrap_or_default();
                    let output_budget = provider.max_output_tokens.unwrap_or(2048);
                    if input_budget < 1024
                        || output_budget == 0
                        || input_budget.saturating_add(output_budget) > context_window
                    {
                        return Err(format!(
                            "provider {id} ollama_native requires max_input_tokens and max_output_tokens (default 2048) to fit within context_window_tokens"
                        ));
                    }
                }
                if provider.kind == ProviderKind::OllamaNative && !provider.env_allowlist.is_empty()
                {
                    return Err(format!(
                        "provider {id} ollama_native does not accept environment variables"
                    ));
                }
                validate_api_key_binding(id, &provider.env_allowlist, &url)?;
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
                    "provider {id} endpoint is only valid for HTTP provider adapters"
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
            if reviewer.context_files.len() > 128 {
                return Err(format!("reviewer {id} has more than 128 context_files"));
            }
            let mut context_files = std::collections::BTreeSet::new();
            for path in &reviewer.context_files {
                let relative = std::path::Path::new(path);
                if path.trim().is_empty()
                    || relative.is_absolute()
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
                        "reviewer {id} has unsafe context file path {path:?}"
                    ));
                }
                if !context_files.insert(path) {
                    return Err(format!("reviewer {id} has duplicate context file {path:?}"));
                }
            }
            if reviewer
                .policy
                .minimum_confidence
                .is_some_and(|value| value > 100)
            {
                return Err(format!("reviewer {id} minimum_confidence must be 0..=100"));
            }
            for severity in &reviewer.policy.block_severities {
                if !matches!(
                    severity.as_str(),
                    "critical" | "high" | "medium" | "low" | "info"
                ) {
                    return Err(format!(
                        "reviewer {id} has unknown blocking severity {severity}"
                    ));
                }
            }
        }
        for reviewer_id in &config.policy.required_reviewers {
            if !config.reviewers.contains_key(reviewer_id) {
                return Err(format!("policy requires unknown reviewer {reviewer_id}"));
            }
        }
        for (id, profile) in &config.verification {
            if config.offline && profile.egress != ProviderEgress::Local {
                return Err(format!(
                    "offline mode rejects network verification profile {id}; declare a trusted local profile explicitly"
                ));
            }
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
        for profile_id in &config.policy.acceptance.required_verification_profiles {
            if !config.verification.contains_key(profile_id) {
                return Err(format!(
                    "acceptance policy requires unknown verification profile {profile_id}"
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
            for verification in &profile.acceptance.required_verification_profiles {
                if !config.verification.contains_key(verification) {
                    return Err(format!(
                        "policy profile {profile_id} acceptance policy requires unknown verification profile {verification}"
                    ));
                }
            }
        }
        Ok(config)
    }
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
pub fn snapshot_is_current(reviewed: &str, current: &str) -> bool {
    reviewed == current
}

#[derive(Clone, Debug)]
pub struct ProviderResult {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: Option<i32>,
    pub usage: Option<ProviderUsage>,
}
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ProviderUsage {
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
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
    pub context_window_tokens: Option<usize>,
    pub max_output_tokens: Option<usize>,
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
                return Err(format!(
                    "provider output exceeded configured limit (stdout {} bytes, stderr {} bytes, limit {} bytes)",
                    stdout.len(),
                    stderr.len(),
                    request.output_limit_bytes
                ));
            }
            if !status.success() {
                let mut stderr = stderr;
                redact_output_values(&mut stderr, &request.environment);
                let detail = String::from_utf8_lossy(&stderr);
                let detail = detail
                    .rsplit_once("Error:")
                    .map(|(_, message)| format!("Error:{}", message.trim()))
                    .unwrap_or_else(|| {
                        if detail.trim().is_empty() {
                            String::new()
                        } else {
                            format!("provider wrote {} bytes of stderr", stderr.len())
                        }
                    });
                let detail: String = detail.chars().take(2048).collect();
                let detail = if detail.is_empty() {
                    String::new()
                } else {
                    format!("; stderr: {detail}")
                };
                return Err(format!(
                    "provider exited with {}{detail}",
                    status.code().map_or("signal".into(), |c| c.to_string()),
                ));
            }
            return Ok(ProviderResult {
                stdout,
                stderr,
                exit_code: status.code(),
                usage: None,
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
