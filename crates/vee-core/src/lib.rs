use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub mod lifecycle;
pub mod packs;
pub mod paths;
pub mod ports;
pub mod sampling;
pub use lifecycle::{ActorName, FindingStatusChange, Reason, RuleApprovalStatus};
pub use packs::{PackReference, PolicyPack};
pub use sampling::{merge_sampled_findings, SampleAgreement};

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

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Info => "info",
        }
    }

    /// Higher is more severe.
    pub fn rank(self) -> u8 {
        match self {
            Self::Critical => 4,
            Self::High => 3,
            Self::Medium => 2,
            Self::Low => 1,
            Self::Info => 0,
        }
    }
}

/// A minimum severity for findings in selected paths or categories
/// ([ADR 0018](../../docs/adr/0018-fixed-finding-rubric-and-severity-floors.md)).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SeverityFloor {
    /// Path globs; when set, the finding's path must match one of them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    /// Categories; when set, the finding's category must be one of them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub categories: Vec<String>,
    pub minimum: Severity,
}

impl SeverityFloor {
    /// The floor's selectors, for gate reasons: `paths a/**, b/**; categories security`.
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if !self.paths.is_empty() {
            parts.push(format!("paths {}", self.paths.join(", ")));
        }
        if !self.categories.is_empty() {
            parts.push(format!("categories {}", self.categories.join(", ")));
        }
        parts.join("; ")
    }

    pub fn applies_to(&self, finding: &Finding) -> bool {
        let path_matches = self.paths.is_empty()
            || finding
                .path
                .as_deref()
                .is_some_and(|path| self.paths.iter().any(|pattern| glob_matches(pattern, path)));
        let category_matches = self.categories.is_empty()
            || self
                .categories
                .iter()
                .any(|category| category.eq_ignore_ascii_case(&finding.category));
        path_matches && category_matches
    }
}

const MAX_SEVERITY_FLOORS: usize = 64;
const MAX_FLOOR_SELECTORS: usize = 256;

/// Each floor selects by paths, categories or both, with bounded, non-empty patterns.
pub fn validate_severity_floors(label: &str, floors: &[SeverityFloor]) -> Result<(), String> {
    if floors.len() > MAX_SEVERITY_FLOORS {
        return Err(format!(
            "{label}.severity_floors has more than {MAX_SEVERITY_FLOORS} floors"
        ));
    }
    for floor in floors {
        if floor.paths.is_empty() && floor.categories.is_empty() {
            return Err(format!(
                "{label}.severity_floors entries must select paths or categories"
            ));
        }
        if floor.paths.len() + floor.categories.len() > MAX_FLOOR_SELECTORS
            || floor.paths.iter().chain(&floor.categories).any(|value| {
                value.trim().is_empty() || value.len() > 512 || value.chars().any(char::is_control)
            })
        {
            return Err(format!(
                "{label}.severity_floors has an empty, invalid, or too long path or category"
            ));
        }
    }
    Ok(())
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
    /// Derived from `events` and expiry when loaded; see [`RuleApproval::status_at`].
    #[serde(default)]
    pub status: RuleApprovalStatus,
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
    /// Agreement across a sampled reviewer's runs; absent for unsampled reviewers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample_agreement: Option<SampleAgreement>,
    /// Reported only by advisory reviewers: shown, but never blocks the gate.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub advisory: bool,
    /// A reviewer's replacement for the finding's lines, published as a
    /// suggestion a person can commit. Not part of the finding's identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<FindingSuggestion>,
}

/// Replace lines `line..=end_line` of the finding's file with `replacement`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FindingSuggestion {
    pub end_line: u32,
    /// The new text of those lines, without a trailing newline; empty deletes them.
    pub replacement: String,
}

/// The most lines a suggestion may replace or contain.
pub const MAX_SUGGESTION_LINES: u32 = 30;
/// The most bytes a suggestion's replacement may hold.
pub const MAX_SUGGESTION_BYTES: usize = 4096;

impl FindingSuggestion {
    /// A reviewer's suggestion for a finding at `line`, or `None` when it
    /// cannot be published safely: a range that ends before it starts or is
    /// too long, oversized or binary text, or text holding Vee's own markers.
    pub fn accepted(line: u32, end_line: Option<u32>, replacement: &str) -> Option<Self> {
        let end_line = end_line.unwrap_or(line);
        let replacement = replacement
            .strip_suffix('\n')
            .unwrap_or(replacement)
            .replace("\r\n", "\n");
        let forged_marker = ["vee:fingerprint", "vee:idempotency", "vee:moved"]
            .iter()
            .any(|marker| replacement.contains(marker));
        let usable = end_line >= line
            && end_line - line < MAX_SUGGESTION_LINES
            && replacement.len() <= MAX_SUGGESTION_BYTES
            && replacement.lines().count() <= MAX_SUGGESTION_LINES as usize
            && !replacement.contains('\0')
            && !replacement.contains('\r')
            && !forged_marker;
        usable.then_some(Self {
            end_line,
            replacement,
        })
    }
}

impl Finding {
    /// Whether enough of a sampled reviewer's runs reported this finding for it to block.
    /// Unsampled findings always qualify.
    pub fn meets_sample_quorum(&self) -> bool {
        self.sample_agreement
            .is_none_or(|agreement| agreement.meets_quorum())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct RuleAttribution {
    /// Stable identity of the human-approved rule candidate.
    pub rule_id: String,
    /// Exact active approval version supplied to the reviewer.
    pub approval_id: String,
    /// Reviewer whose output reported this attribution; assigned by Vee.
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
/// and provenance are assigned by Vee after parsing this transport contract.
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
    #[serde(default)]
    pub suggestion: Option<ProviderSuggestion>,
}

/// Untrusted replacement text from a reviewer for the finding's lines.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderSuggestion {
    #[serde(default)]
    pub end_line: Option<u32>,
    pub replacement: String,
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
    /// Minimum severities by path or category. Omitted when empty so earlier
    /// decisions replay unchanged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub severity_floors: Vec<SeverityFloor>,
}

impl Policy {
    /// The severity the gate evaluates: the reported severity, raised to the
    /// highest matching floor. Floors never lower a severity.
    pub fn effective_severity(&self, finding: &Finding) -> Severity {
        self.raising_floor(finding)
            .map_or(finding.severity, |floor| floor.minimum)
    }

    /// Whether `severities` blocks this finding: some severity from the reported
    /// one up to the effective one is in the list. Raising a severity therefore
    /// never moves a finding out of a list with gaps, such as `[high]` alone.
    pub fn blocks_at(&self, severities: &[Severity], finding: &Finding) -> bool {
        let (low, high) = (
            finding.severity.rank(),
            self.effective_severity(finding).rank(),
        );
        severities
            .iter()
            .any(|severity| (low..=high).contains(&severity.rank()))
    }

    /// The first floor with the highest minimum above the reported severity.
    pub fn raising_floor(&self, finding: &Finding) -> Option<&SeverityFloor> {
        self.severity_floors
            .iter()
            .filter(|floor| {
                floor.minimum.rank() > finding.severity.rank() && floor.applies_to(finding)
            })
            .fold(None, |best: Option<&SeverityFloor>, floor| match best {
                Some(current) if current.minimum.rank() >= floor.minimum.rank() => Some(current),
                _ => Some(floor),
            })
    }
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
        if let Some(raw) = finding.path.take() {
            // Models sometimes cite `dir/../other/file`. Resolve `.` and `..`
            // lexically; a path that climbs above the root, or is absolute,
            // escapes the repository. One that resolves to the root itself
            // (`.`, `dir/..`) names no file, so the finding stays unanchored.
            let mut parts: Vec<String> = Vec::new();
            for component in Path::new(raw.as_str()).components() {
                match component {
                    Component::Normal(part) => parts.push(part.to_string_lossy().into_owned()),
                    Component::CurDir => {}
                    Component::ParentDir if parts.pop().is_some() => {}
                    Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                        return Err(format!("provider finding path escapes repository: {raw}"));
                    }
                }
            }
            if !parts.is_empty() {
                let path = parts.join("/").replace('\\', "/");
                let absolute = repository_root.join(path.as_str());
                if let Ok(canonical_root) = crate::paths::canonicalize(repository_root) {
                    if let Ok(canonical_parent) =
                        crate::paths::canonicalize(absolute.parent().unwrap_or(repository_root))
                    {
                        if !canonical_parent.starts_with(canonical_root) {
                            return Err(format!(
                                "provider finding path escapes repository through symlink: {path}"
                            ));
                        }
                    }
                }
                finding.path = Some(path);
            }
        }
        if finding.line == Some(0) {
            return Err("provider finding line must be positive".into());
        }
        // A suggestion replaces lines of the finding's file, so it needs both.
        if finding.path.is_none() || finding.line.is_none() {
            finding.suggestion = None;
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
            sample_agreement: None,
            advisory: false,
            suggestion: match (finding.line, finding.suggestion) {
                (Some(line), Some(suggestion)) if line > 0 => {
                    FindingSuggestion::accepted(line, suggestion.end_line, &suggestion.replacement)
                }
                _ => None,
            },
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
        !f.advisory
            && f.meets_sample_quorum()
            && (policy.blocks_at(&policy.block_severities, f)
                && f.confidence.unwrap_or(0) >= policy.minimum_confidence
                || f.reviewer_ids.iter().any(|reviewer_id| {
                    reviewer_policies
                        .get(reviewer_id)
                        .is_some_and(|reviewer_policy| {
                            policy.blocks_at(&reviewer_policy.block_severities, f)
                                && f.confidence.unwrap_or(0) >= reviewer_policy.minimum_confidence
                        })
                }))
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
        let mut floor_reasons = std::collections::BTreeSet::new();
        for finding in findings
            .iter()
            .filter(|finding| blocked.contains(&finding.id))
        {
            let severity = policy.effective_severity(finding);
            if let Some(floor) = policy.raising_floor(finding) {
                floor_reasons.insert(format!(
                    "severity floor ({}) raised finding {} from {} to {}",
                    floor.describe(),
                    finding.id,
                    finding.severity.as_str(),
                    severity.as_str()
                ));
            }
            for reviewer_id in &finding.reviewer_ids {
                if reviewer_policies
                    .get(reviewer_id)
                    .is_some_and(|reviewer_policy| {
                        policy.blocks_at(&reviewer_policy.block_severities, finding)
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
        reasons.extend(floor_reasons);
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

    #[test]
    fn environment_allowlist_resolves_only_named_host_values() {
        let values = |name: &str| match name {
            "VEE_TEST_TOKEN" => Some("secret-value".to_owned()),
            _ => None,
        };
        assert_eq!(
            resolve_environment_allowlist(
                &["VEE_TEST_TOKEN".into(), "OPTIONAL_MISSING".into()],
                values,
            )
            .unwrap(),
            vec![("VEE_TEST_TOKEN".into(), "secret-value".into())]
        );
        assert!(resolve_environment_allowlist(&["BAD=NAME".into()], |_| None).is_err());
    }

    fn finding(id: &str, severity: Severity, confidence: Option<u8>) -> Finding {
        Finding {
            suggestion: None,
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
            sample_agreement: None,
            advisory: false,
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
            severity_floors: Vec::new(),
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
            severity_floors: Vec::new(),
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

    fn floor(paths: &[&str], categories: &[&str], minimum: Severity) -> SeverityFloor {
        SeverityFloor {
            paths: paths.iter().map(|path| path.to_string()).collect(),
            categories: categories.iter().map(|value| value.to_string()).collect(),
            minimum,
        }
    }

    #[test]
    fn severity_floors_raise_matching_findings_until_they_block_and_say_why() {
        let policy = Policy {
            block_severities: vec![Severity::Critical, Severity::High],
            minimum_confidence: 80,
            required_review_complete: true,
            required_verifications: vec![],
            analyzer_block_levels: Default::default(),
            severity_floors: vec![
                floor(&["payments/**"], &[], Severity::High),
                floor(&[], &["security"], Severity::Critical),
            ],
        };
        let mut in_payments = finding("in-payments", Severity::Low, Some(90));
        in_payments.path = Some("payments/charge.rs".into());
        let elsewhere = finding("elsewhere", Severity::Medium, Some(90));
        let mut security = finding("security", Severity::Low, Some(90));
        security.category = "Security".into();
        let mut findings = vec![in_payments, elsewhere, security];
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
        assert_eq!(decision.blocking_findings, vec!["in-payments", "security"]);
        assert!(decision.reasons.contains(
            &"severity floor (paths payments/**) raised finding in-payments from low to high"
                .to_string()
        ));
        assert!(decision.reasons.contains(
            &"severity floor (categories security) raised finding security from low to critical"
                .to_string()
        ));
        assert_eq!(policy.effective_severity(&findings[1]), Severity::Medium);
    }

    #[test]
    fn severity_floors_never_lower_a_severity_and_path_floors_skip_unlocated_findings() {
        let policy = Policy {
            block_severities: vec![Severity::High],
            minimum_confidence: 0,
            required_review_complete: true,
            required_verifications: vec![],
            analyzer_block_levels: Default::default(),
            severity_floors: vec![floor(&["**"], &[], Severity::Medium)],
        };
        let critical = finding("critical", Severity::Critical, Some(90));
        assert_eq!(policy.effective_severity(&critical), Severity::Critical);
        let mut unlocated = finding("unlocated", Severity::Low, Some(90));
        unlocated.path = None;
        assert_eq!(policy.effective_severity(&unlocated), Severity::Low);
    }

    #[test]
    fn a_floor_never_stops_a_finding_that_would_block_from_blocking() {
        // `[high]` alone: a floor that raises a high finding to critical must
        // not move it out of the blocking set.
        let policy = Policy {
            block_severities: vec![Severity::High],
            minimum_confidence: 0,
            required_review_complete: true,
            required_verifications: vec![],
            analyzer_block_levels: Default::default(),
            severity_floors: vec![floor(&[], &["security"], Severity::Critical)],
        };
        let mut high = finding("high-security", Severity::High, Some(90));
        high.category = "security".into();
        let mut low = finding("low-security", Severity::Low, Some(90));
        low.category = "security".into();
        let mut findings = vec![high, low];
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
        // Both pass through `high` on the way to `critical`, so both block.
        assert_eq!(decision.status, GateStatus::Block);
        assert_eq!(
            decision.blocking_findings,
            vec!["high-security", "low-security"]
        );
    }

    #[test]
    fn empty_severity_floors_keep_recorded_policies_unchanged() {
        let policy = Policy {
            block_severities: vec![Severity::High],
            minimum_confidence: 80,
            required_review_complete: true,
            required_verifications: vec![],
            analyzer_block_levels: Default::default(),
            severity_floors: vec![],
        };
        let recorded = serde_json::to_value(&policy).unwrap();
        assert!(recorded.get("severity_floors").is_none());
        let replayed: Policy = serde_json::from_value(recorded).unwrap();
        assert_eq!(replayed, policy);
    }

    #[test]
    fn severity_floors_need_a_selector_and_valid_patterns() {
        assert!(
            validate_severity_floors("policy", &[floor(&["src/**"], &[], Severity::High)]).is_ok()
        );
        assert!(
            validate_severity_floors("policy", &[floor(&[], &[], Severity::High)])
                .unwrap_err()
                .contains("paths or categories")
        );
        assert!(
            validate_severity_floors("policy", &[floor(&[" "], &[], Severity::High)])
                .unwrap_err()
                .contains("empty, invalid, or too long")
        );
        assert!(
            validate_severity_floors("policy", &[floor(&[], &[""], Severity::High)])
                .unwrap_err()
                .contains("empty, invalid, or too long")
        );
    }

    #[test]
    fn gate_blocks_a_sampled_finding_only_at_its_quorum() {
        let policy = Policy {
            block_severities: vec![Severity::High],
            minimum_confidence: 80,
            required_review_complete: true,
            required_verifications: vec![],
            analyzer_block_levels: Default::default(),
            severity_floors: Vec::new(),
        };
        let agreement = |reported| {
            Some(SampleAgreement {
                reported,
                samples: 3,
                quorum: 2,
            })
        };
        let mut minority = finding("minority", Severity::High, Some(95));
        minority.sample_agreement = agreement(1);
        let mut majority = finding("majority", Severity::High, Some(95));
        majority.sample_agreement = agreement(2);
        let mut unlocated_minority = finding("unlocated-minority", Severity::High, Some(95));
        unlocated_minority.sample_agreement = agreement(1);
        unlocated_minority.line = None;
        let mut findings = vec![minority, majority, unlocated_minority];
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
        assert_eq!(decision.blocking_findings, vec!["majority"]);
        assert!(
            decision
                .reasons
                .iter()
                .all(|reason| !reason.contains("lack a source path")),
            "an advisory minority finding without a line does not make the gate incomplete: {:?}",
            decision.reasons
        );
    }

    #[test]
    fn gate_never_blocks_on_an_advisory_finding() {
        let policy = Policy {
            block_severities: vec![Severity::High],
            minimum_confidence: 80,
            required_review_complete: true,
            required_verifications: vec![],
            analyzer_block_levels: Default::default(),
            severity_floors: Vec::new(),
        };
        let mut advisory = finding("advisory", Severity::Critical, Some(99));
        advisory.advisory = true;
        let mut unlocated_advisory = finding("unlocated-advisory", Severity::Critical, Some(99));
        unlocated_advisory.advisory = true;
        unlocated_advisory.line = None;
        let mut findings = vec![advisory, unlocated_advisory];
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
        assert_eq!(decision.status, GateStatus::Pass, "{:?}", decision.reasons);
        assert!(decision.blocking_findings.is_empty());
    }

    #[test]
    fn gate_marks_unlocated_blocking_finding_incomplete() {
        let policy = Policy {
            block_severities: vec![Severity::High],
            minimum_confidence: 80,
            required_review_complete: true,
            required_verifications: vec![],
            analyzer_block_levels: Default::default(),
            severity_floors: Vec::new(),
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
            severity_floors: Vec::new(),
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
            severity_floors: Vec::new(),
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
            severity_floors: Vec::new(),
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
            severity_floors: Vec::new(),
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
            severity_floors: Vec::new(),
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
            severity_floors: Vec::new(),
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
            severity_floors: Vec::new(),
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
            severity_floors: Vec::new(),
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
    fn provider_finding_paths_resolve_parent_steps_inside_the_repository() {
        let dir = tempfile::tempdir().unwrap();
        let mut candidate = finding("id", Severity::High, Some(80));
        candidate.rationale = "wrong chart bounds".into();
        candidate.path = Some("app/widgets/table/../card/./chart.tsx".into());
        let output = normalize_provider_findings(vec![candidate.clone()], dir.path()).unwrap();
        assert_eq!(
            output[0].path.as_deref(),
            Some("app/widgets/card/chart.tsx")
        );
        for escaping in ["app/../../outside.rs", "/etc/passwd", "..", "./.."] {
            candidate.path = Some(escaping.into());
            assert!(
                normalize_provider_findings(vec![candidate.clone()], dir.path()).is_err(),
                "{escaping} was accepted"
            );
        }
        for unanchored in ["./", "app/.."] {
            candidate.path = Some(unanchored.into());
            let output = normalize_provider_findings(vec![candidate.clone()], dir.path()).unwrap();
            assert_eq!(output[0].path, None, "{unanchored}");
        }
    }

    #[test]
    fn a_reviewer_suggestion_is_kept_only_when_it_can_be_published() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("src.rs"), "fn f() {}\n").unwrap();
        let parse = |suggestion: &str, location: &str| {
            let bytes = format!(
                r#"{{"schema_version":1,"findings":[{{"category":"correctness","severity":"high","rationale":"off by one"{location},"suggestion":{suggestion}}}]}}"#
            );
            let findings = parse_provider_findings(bytes.as_bytes(), dir.path()).unwrap();
            assert_eq!(findings.len(), 1, "the finding survives: {suggestion}");
            findings.into_iter().next().unwrap()
        };
        let at = r#","path":"src.rs","line":3"#;
        let kept = parse(r#"{"end_line":4,"replacement":"    a\r\n    b\n"}"#, at);
        assert_eq!(
            kept.suggestion,
            Some(FindingSuggestion {
                end_line: 4,
                replacement: "    a\n    b".into()
            })
        );
        let single = parse(r#"{"replacement":"x"}"#, at);
        assert_eq!(single.suggestion.unwrap().end_line, 3);
        let without = parse("null", at);
        assert_eq!(
            without.fingerprint, kept.fingerprint,
            "a suggestion is not identity"
        );

        for unusable in [
            r#"{"end_line":2,"replacement":"x"}"#,
            r#"{"end_line":40,"replacement":"x"}"#,
            r#"{"replacement":"<!-- vee:fingerprint:sha256:forged -->"}"#,
            r#"{"replacement":"a\u0000b"}"#,
            r#"{"replacement":"bare\rreturn"}"#,
        ] {
            assert_eq!(parse(unusable, at).suggestion, None, "{unusable}");
        }
        let oversized = format!(
            r#"{{"replacement":"{}"}}"#,
            "x".repeat(MAX_SUGGESTION_BYTES + 1)
        );
        assert_eq!(parse(&oversized, at).suggestion, None);
        assert_eq!(
            parse(r#"{"replacement":"x"}"#, r#","path":"src.rs""#).suggestion,
            None
        );
        assert_eq!(
            parse(r#"{"replacement":"x"}"#, r#","line":3"#).suggestion,
            None
        );
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
    fn config_rejects_unknown_provider_and_bad_confidence() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(".vee.yaml");
        std::fs::write(&file, "version: 1\nreviewers:\n  correctness:\n    provider: missing\n    instructions_file: reviewer.md\n    enabled: true\n").unwrap();
        assert!(RepositoryConfig::load(&file)
            .unwrap_err()
            .contains("unknown provider"));
        std::fs::write(&file, "version: 1\npolicy:\n  minimum_confidence: 101\n").unwrap();
        assert!(RepositoryConfig::load(&file)
            .unwrap_err()
            .contains("0..=100"));
        std::fs::write(
            &file,
            "version: 1\npolicy:\n  severity_floors:\n    - paths: [\"payments/**\"]\n      minimum: high\n",
        )
        .unwrap();
        let floored = RepositoryConfig::load(&file).unwrap();
        assert_eq!(floored.policy.severity_floors[0].minimum, Severity::High);
        std::fs::write(
            &file,
            "version: 1\npolicy:\n  severity_floors:\n    - minimum: high\n",
        )
        .unwrap();
        assert!(RepositoryConfig::load(&file)
            .unwrap_err()
            .contains("must select paths or categories"));
        std::fs::write(
            &file,
            "version: 1\npolicy:\n  severity_floors:\n    - categories: [security]\n      minimum: urgent\n",
        )
        .unwrap();
        assert!(RepositoryConfig::load(&file).is_err());
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
            "version: 1\npolicy_profiles:\n  strict:\n    on_unreviewed: alow\n",
        )
        .unwrap();
        let error = RepositoryConfig::load(&file).unwrap_err();
        assert!(
            error.contains("policy profile strict on_unreviewed"),
            "{error}"
        );
        std::fs::write(&file, "version: 1\npolicy:\n  minimum_confidence: 80\n").unwrap();
        let config = RepositoryConfig::load(&file).unwrap();
        assert_eq!(config.policy.on_unreviewed, "block");
        assert!(
            serde_json::to_value(&config.policy)
                .unwrap()
                .get("on_unreviewed")
                .is_none(),
            "the default on_unreviewed leaves existing configuration digests unchanged"
        );
        std::fs::write(&file, "version: 1\npolicy:\n  on_unreviewed: allow\n").unwrap();
        let config = RepositoryConfig::load(&file).unwrap();
        assert_eq!(
            serde_json::to_value(&config.policy).unwrap()["on_unreviewed"],
            "allow"
        );
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
        let file = dir.path().join(".vee.yaml");
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
        let repository = dir.path().join(".vee.yaml");
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
    fn a_machine_effort_applies_only_to_reviewers_that_set_no_effort_or_samples() {
        let dir = tempfile::tempdir().unwrap();
        let repository = dir.path().join(".vee.yaml");
        let user = dir.path().join("user.yaml");
        std::fs::write(
            &repository,
            "version: 1\nproviders:\n  p: { kind: cli, executable: provider }\nreviewers:\n  open:\n    provider: p\n    instructions_file: a.md\n  pinned:\n    provider: p\n    instructions_file: b.md\n    effort: low\n  sampled:\n    provider: p\n    instructions_file: c.md\n    samples: 2\n",
        )
        .unwrap();
        std::fs::write(&user, "version: 1\nreview:\n  effort: medium\n").unwrap();
        let config =
            RepositoryConfig::load_with_provider_defaults(&repository, Some(&user)).unwrap();
        assert_eq!(config.reviewers["open"].effort, Some(ReviewEffort::Medium));
        assert_eq!(config.reviewers["pinned"].effort, Some(ReviewEffort::Low));
        assert_eq!(config.reviewers["sampled"].effort, None);
        assert_eq!(config.reviewers["sampled"].samples, Some(2));

        std::fs::write(&user, "version: 1\nreview:\n  effort: extreme\n").unwrap();
        assert!(RepositoryConfig::load_with_provider_defaults(&repository, Some(&user)).is_err());
    }

    #[test]
    fn a_selected_policy_profile_keeps_the_pack_policy_and_its_floors() {
        let mut config: RepositoryConfig = serde_yaml::from_str(
            "version: 1\npolicy_profiles:\n  fast:\n    block_severities: []\n    minimum_confidence: 90\n",
        )
        .unwrap();
        let pack: PolicyConfig = serde_yaml::from_str(
            "block_severities: [critical]\nminimum_confidence: 50\nseverity_floors:\n  - paths: [\"payments/**\"]\n    minimum: high\n",
        )
        .unwrap();
        config.add_pack_policy(&pack);
        config.select_policy_profile(Some("fast")).unwrap();
        assert_eq!(config.policy.block_severities, ["critical"]);
        assert_eq!(config.policy.minimum_confidence, 50);
        assert_eq!(config.policy.severity_floors, pack.severity_floors);
    }

    #[test]
    fn named_policy_profiles_select_deterministic_policy_and_reject_unknown_names() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(".vee.yaml");
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
        let file = dir.path().join(".vee.yaml");
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
    fn repository_hosting_config_names_only_hosting_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(".vee.yaml");
        for allowed in [
            "GH_TOKEN",
            "GITLAB_TOKEN",
            "AZURE_DEVOPS_EXT_PAT",
            "VEE_REVIEW_TOKEN",
        ] {
            std::fs::write(
                &file,
                format!("version: 1\nhosting: {{ token_env: {allowed} }}\n"),
            )
            .unwrap();
            assert!(RepositoryConfig::load(&file).is_ok(), "{allowed}");
        }
        for (field, name) in [
            ("token_env", "AWS_SECRET_ACCESS_KEY"),
            ("token_env", "OPENAI_API_KEY"),
            ("webhook_secret_env", "USER"),
        ] {
            std::fs::write(
                &file,
                format!("version: 1\nhosting: {{ {field}: {name} }}\n"),
            )
            .unwrap();
            let error = RepositoryConfig::load(&file).unwrap_err();
            assert!(
                error.contains("hosting credential"),
                "{field} {name}: {error}"
            );
        }
    }

    #[test]
    fn work_items_name_a_tracker_and_only_tracker_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(".vee.yaml");
        let load = |work_items: &str| {
            std::fs::write(&file, format!("version: 1\nwork_items: {work_items}\n")).unwrap();
            RepositoryConfig::load(&file)
        };
        assert!(load("{ provider: linear }").is_ok());
        assert!(load(
            "{ provider: jira, host: acme.atlassian.net, acceptance_field: customfield_10050 }"
        )
        .is_ok());
        for (work_items, expected) in [
            ("{ provider: asana }", "jira or linear"),
            ("{ provider: jira }", "Jira site"),
            ("{ provider: jira, host: \"evil/x\" }", "host name"),
            (
                "{ provider: linear, token_env: AWS_SECRET_ACCESS_KEY }",
                "tracker credential",
            ),
            (
                "{ provider: jira, host: a.example, user_env: HOME }",
                "tracker credential",
            ),
            (
                "{ provider: jira, host: a.example, api_base: \"http://a.example/\" }",
                "HTTPS",
            ),
            (
                "{ provider: linear, acceptance_field: customfield_1 }",
                "Jira field",
            ),
        ] {
            let error = load(work_items).unwrap_err();
            assert!(error.contains(expected), "{work_items}: {error}");
        }
    }

    #[test]
    fn a_cli_provider_may_not_allowlist_pwd() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(".vee.yaml");
        std::fs::write(
            &file,
            "version: 1\nproviders:\n  p: { kind: cli, executable: tool, env_allowlist: [HOME, PWD] }\n",
        )
        .unwrap();
        let error = RepositoryConfig::load(&file).unwrap_err();
        assert!(error.contains("remove PWD"), "{error}");
    }

    #[test]
    fn hosting_defaults_validate_provider_endpoints_and_environment_names() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(".vee.yaml");
        std::fs::write(
            &file,
            "version: 1\nhosting: { provider: gitlab, host: gitlab.example, api_base: https://gitlab.example/api/v4/, token_env: GITLAB_TOKEN, webhook_secret_env: VEE_WEBHOOK_SECRET, actor_login: vee-bot }\n",
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
        let file = dir.path().join(".vee.yaml");
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
        let file = dir.path().join(".vee.yaml");
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
    fn focused_reviewer_strategy_defaults_to_whole_change_and_requires_ollama_native() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(".vee.yaml");
        let providers = "providers:\n  local:\n    kind: ollama_native\n    egress: local\n    endpoint: http://127.0.0.1:11434/api/chat\n    model: gemma3:12b\n    max_input_tokens: 28000\n    context_window_tokens: 32768\n  cli: { kind: cli, executable: reviewer, egress: local }\n";
        let write = |reviewers: &str| {
            std::fs::write(
                &file,
                format!("version: 1\n{providers}reviewers:\n{reviewers}"),
            )
            .unwrap();
        };
        write("  default: { provider: local, instructions_file: r.md }\n  focused: { provider: local, instructions_file: r.md, strategy: focused }\n");
        let config = RepositoryConfig::load(&file).unwrap();
        assert_eq!(
            config.reviewers["default"].strategy,
            ReviewStrategy::WholeChange
        );
        assert_eq!(
            config.reviewers["focused"].strategy,
            ReviewStrategy::Focused
        );
        assert!(
            serde_json::to_value(&config.reviewers["default"])
                .unwrap()
                .get("strategy")
                .is_none(),
            "the default strategy leaves existing configuration digests unchanged"
        );

        write("  focused: { provider: cli, instructions_file: r.md, strategy: focused }\n");
        let error = RepositoryConfig::load(&file).unwrap_err();
        assert!(
            error.contains(
                "reviewer focused uses strategy focused, which requires an ollama_native provider"
            ),
            "{error}"
        );

        write("  focused: { provider: local, instructions_file: r.md, strategy: piecemeal }\n");
        assert!(RepositoryConfig::load(&file).is_err());
    }

    #[test]
    fn antigravity_cli_provider_is_a_network_adapter_with_fixed_arguments() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(".vee.yaml");
        let write = |provider: &str| {
            std::fs::write(
                &file,
                format!("version: 1\nproviders:\n  agy: {provider}\n"),
            )
            .unwrap();
        };
        write("{ kind: antigravity_cli, egress: network, executable: agy, model: gemini-3-pro }");
        let config = RepositoryConfig::load(&file).unwrap();
        assert_eq!(config.providers["agy"].kind, ProviderKind::AntigravityCli);
        for (provider, expected) in [
            (
                "{ kind: antigravity_cli, egress: network, executable: agy, args: [--yolo] }",
                "arguments are controlled by the adapter",
            ),
            (
                "{ kind: antigravity_cli, egress: network, executable: agy, version_args: [-v] }",
                "version arguments are fixed by the adapter",
            ),
            (
                "{ kind: antigravity_cli, egress: local, executable: agy }",
                "antigravity_cli cannot be declared local",
            ),
        ] {
            write(provider);
            let error = RepositoryConfig::load(&file).unwrap_err();
            assert!(error.contains(expected), "{error}");
        }
    }

    #[test]
    fn review_effort_sets_the_number_of_samples() {
        assert_eq!(ReviewEffort::Low.samples(), 1);
        assert_eq!(ReviewEffort::Medium.samples(), 3);
        assert_eq!(ReviewEffort::High.samples(), 5);

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(".vee.yaml");
        let write = |reviewers: &str| {
            std::fs::write(
                &file,
                format!("version: 1\nproviders:\n  cli: {{ kind: cli, executable: reviewer, egress: local }}\nreviewers:\n{reviewers}"),
            )
            .unwrap();
        };
        write("  medium: { provider: cli, instructions_file: r.md, effort: medium }\n  high: { provider: cli, instructions_file: r.md, effort: high, sample_quorum: 4 }\n  low: { provider: cli, instructions_file: r.md, effort: low }\n");
        let config = RepositoryConfig::load(&file).unwrap();
        assert_eq!(config.reviewers["medium"].sample_count(), 3);
        assert_eq!(config.reviewers["medium"].effective_sample_quorum(), 2);
        assert_eq!(config.reviewers["high"].sample_count(), 5);
        assert_eq!(config.reviewers["high"].effective_sample_quorum(), 4);
        assert_eq!(config.reviewers["low"].sample_count(), 1);

        for (reviewers, expected) in [
            ("  r: { provider: cli, instructions_file: r.md, effort: medium, samples: 3 }\n", "reviewer r sets both effort and samples"),
            ("  r: { provider: cli, instructions_file: r.md, effort: low, sample_quorum: 1 }\n", "reviewer r sets sample_quorum without samples"),
            ("  r: { provider: cli, instructions_file: r.md, effort: medium, sample_quorum: 4 }\n", "reviewer r sample_quorum must be 1..=3"),
            ("  r: { provider: cli, instructions_file: r.md, effort: max }\n", "unknown variant"),
        ] {
            write(reviewers);
            let error = RepositoryConfig::load(&file).unwrap_err();
            assert!(error.contains(expected), "{error}");
        }
    }

    #[test]
    fn a_review_effort_override_replaces_every_reviewers_sampling() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(".vee.yaml");
        std::fs::write(
            &file,
            "version: 1\nproviders:\n  cli: { kind: cli, executable: reviewer, egress: local }\nreviewers:\n  plain: { provider: cli, instructions_file: r.md }\n  sampled: { provider: cli, instructions_file: r.md, samples: 5, sample_quorum: 5 }\n",
        )
        .unwrap();
        let mut config = RepositoryConfig::load(&file).unwrap();
        config.override_review_effort(ReviewEffort::Medium);
        for id in ["plain", "sampled"] {
            assert_eq!(config.reviewers[id].sample_count(), 3, "{id}");
            assert_eq!(config.reviewers[id].effective_sample_quorum(), 2, "{id}");
            assert_eq!(config.reviewers[id].effort, Some(ReviewEffort::Medium));
        }
        config.override_review_effort(ReviewEffort::Low);
        assert_eq!(config.reviewers["sampled"].sample_count(), 1);
    }

    #[test]
    fn reviewer_sampling_defaults_to_one_run_and_a_majority_quorum() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(".vee.yaml");
        let write = |reviewers: &str| {
            std::fs::write(
                &file,
                format!("version: 1\nproviders:\n  cli: {{ kind: cli, executable: reviewer, egress: local }}\nreviewers:\n{reviewers}"),
            )
            .unwrap();
        };
        write("  single: { provider: cli, instructions_file: r.md }\n  sampled: { provider: cli, instructions_file: r.md, samples: 3 }\n  strict: { provider: cli, instructions_file: r.md, samples: 3, sample_quorum: 3 }\n");
        let config = RepositoryConfig::load(&file).unwrap();
        assert_eq!(config.reviewers["single"].sample_count(), 1);
        assert_eq!(config.reviewers["single"].effective_sample_quorum(), 1);
        assert_eq!(config.reviewers["sampled"].sample_count(), 3);
        assert_eq!(config.reviewers["sampled"].effective_sample_quorum(), 2);
        assert_eq!(config.reviewers["strict"].effective_sample_quorum(), 3);
        let single = serde_json::to_value(&config.reviewers["single"]).unwrap();
        assert!(
            single.get("samples").is_none() && single.get("sample_quorum").is_none(),
            "an unsampled reviewer leaves existing configuration digests unchanged"
        );

        for (reviewers, expected) in [
            (
                "  r: { provider: cli, instructions_file: r.md, samples: 0 }\n",
                "reviewer r samples must be 1..=5",
            ),
            (
                "  r: { provider: cli, instructions_file: r.md, samples: 6 }\n",
                "reviewer r samples must be 1..=5",
            ),
            (
                "  r: { provider: cli, instructions_file: r.md, samples: 3, sample_quorum: 4 }\n",
                "reviewer r sample_quorum must be 1..=3",
            ),
            (
                "  r: { provider: cli, instructions_file: r.md, samples: 3, sample_quorum: 0 }\n",
                "reviewer r sample_quorum must be 1..=3",
            ),
            (
                "  r: { provider: cli, instructions_file: r.md, sample_quorum: 1 }\n",
                "reviewer r sets sample_quorum without samples",
            ),
        ] {
            write(reviewers);
            let error = RepositoryConfig::load(&file).unwrap_err();
            assert!(error.contains(expected), "{error}");
        }
    }

    #[test]
    fn ollama_native_provider_requires_loopback_and_explicit_context_budget() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(".vee.yaml");
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
        let config_path = directory.path().join(".vee.yaml");
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
        let file = dir.path().join(".vee.yaml");
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
        let file = dir.path().join(".vee.yaml");
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
    /// The issue tracker `--work-item` reads, when it is not the code host:
    /// Jira or Linear (ADR 0033). Absent, work items come from `hosting`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub work_items: Option<WorkItemsConfig>,
    /// Guards on when a passing change is eligible for approval without a
    /// human. Absent when unset, so existing configuration digests stay the same.
    #[serde(default, skip_serializing_if = "ApprovalConfig::is_unset")]
    pub approval: ApprovalConfig,
    #[serde(skip)]
    pub active_policy_profile: Option<String>,
    /// The effort a single review applied to every reviewer, if any.
    #[serde(skip)]
    pub active_review_effort: Option<ReviewEffort>,
    /// Policies from pinned packs. They are merged into `policy` and into any
    /// selected policy profile, so a profile cannot drop a pack's baseline.
    #[serde(skip)]
    pub pack_policies: Vec<PolicyConfig>,
    /// Digest-pinned policy packs merged into this configuration at load time.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub packs: Vec<PackReference>,
    /// Approved rules contributed by packs; their pins are covered by `packs`.
    #[serde(skip)]
    pub pack_rules: Vec<RuleApproval>,
}

/// When a change whose gate passes may be approved without a human: layered
/// guards checked before and after the gate, so approval is never a side
/// effect of a passing review alone.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalConfig {
    /// Changes touching any of these paths (globs) always need a human.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub never_paths: Vec<String>,
    /// Changes with a commit by an author matching any of these (globs on the
    /// author's name or email) always need a human.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub never_authors: Vec<String>,
    /// Highest change-risk tier still eligible: `low` (default) or `elevated`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_risk: Option<String>,
    /// Changes to a file that `CODEOWNERS` on the base assigns to any of these
    /// owners (`@org/team`, `@user` or an email) always need a human.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub never_owners: Vec<String>,
    /// At most this many approvals by Vee in any 24 hours, in enforce mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_per_day: Option<u32>,
    /// `observe` (default): `vee ci run --approve` records what it would
    /// approve and approves nothing. `enforce`: it approves eligible changes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
}

impl ApprovalConfig {
    pub fn is_unset(&self) -> bool {
        self == &Self::default()
    }

    pub fn max_risk(&self) -> &str {
        self.max_risk.as_deref().unwrap_or("low")
    }

    /// Whether eligible changes are approved on the host, rather than only
    /// recorded.
    pub fn enforces(&self) -> bool {
        self.mode.as_deref() == Some("enforce")
    }
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
/// An issue tracker for `--work-item` (ADR 0033). Secrets are read from the
/// named environment variables.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkItemsConfig {
    /// `jira` or `linear`.
    pub provider: String,
    /// Jira's site, such as `acme.atlassian.net` or a Data Center host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// API base URL; derived from the host or the provider when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_base: Option<String>,
    /// Variable holding the API token: `JIRA_API_TOKEN` or `LINEAR_API_KEY`
    /// by default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_env: Option<String>,
    /// Jira Cloud: variable holding the account email for basic auth.
    /// Without it, the token is sent as a Data Center personal access token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_env: Option<String>,
    /// Jira: the field holding acceptance criteria, such as
    /// `customfield_10050`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acceptance_field: Option<String>,
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
    /// Read-only reviewer access to the review snapshot (ADR 0017).
    #[serde(default)]
    pub exploration: ReviewExplorationConfig,
    /// Bytes of repository standards (`REVIEW.md`, `AGENTS.md`, editor
    /// rules and `standards`) sent to reviewers; 0 sends none (ADR 0028).
    #[serde(default = "default_standards_bytes")]
    pub max_standards_bytes: usize,
    /// More standards documents, each optionally limited to changed paths.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub standards: Vec<StandardsSourceConfig>,
}

/// A standards document named in `.vee.yaml`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StandardsSourceConfig {
    /// Repository-relative path of the document.
    pub path: String,
    /// Globs of changed paths the document applies to; empty applies to all.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
}

/// Lets reviewers read more of the review snapshot through Vee-served tools
/// (ADR 0017). Off by default.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReviewExplorationConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Tool calls one reviewer request may make.
    #[serde(default = "default_exploration_tool_calls")]
    pub max_tool_calls: usize,
    /// Bytes of source text one reviewer request may read through tools.
    #[serde(default = "default_exploration_read_bytes")]
    pub max_read_bytes: usize,
    /// Extra path globs reviewers may never read, added to
    /// [`EXPLORATION_DENIED_PATHS`].
    #[serde(default)]
    pub deny: Vec<String>,
}

impl Default for ReviewExplorationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_tool_calls: default_exploration_tool_calls(),
            max_read_bytes: default_exploration_read_bytes(),
            deny: Vec::new(),
        }
    }
}

fn default_exploration_tool_calls() -> usize {
    24
}

fn default_exploration_read_bytes() -> usize {
    256 * 1024
}

/// Paths a reviewer may never read through exploration tools, whatever the
/// configuration: environment files, private keys and credential stores.
pub const EXPLORATION_DENIED_PATHS: &[&str] = &[
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.keystore",
    "*.jks",
    "id_rsa*",
    "id_dsa*",
    "id_ecdsa*",
    "id_ed25519*",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".git-credentials",
    ".dockercfg",
    "credentials",
    "credentials.json",
    "secrets.*",
    ".envrc",
    "*.tfvars",
    "*.tfstate",
    "*.tfstate.*",
    ".htpasswd",
    "kubeconfig*",
    ".kube",
    ".ssh",
    ".aws",
    ".gnupg",
    "*.p8",
    "*.kdbx",
];

impl Default for ReviewConfig {
    fn default() -> Self {
        Self {
            include: Vec::new(),
            exclude: Vec::new(),
            max_concurrency: default_review_concurrency(),
            max_context_files: default_context_files(),
            max_context_file_bytes: default_context_file_bytes(),
            max_context_bytes: default_context_bytes(),
            exploration: ReviewExplorationConfig::default(),
            max_standards_bytes: default_standards_bytes(),
            standards: Vec::new(),
        }
    }
}

fn default_standards_bytes() -> usize {
    48 * 1024
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
    /// Gemini CLI. Upstream deprecated it in June 2026 in favor of the Antigravity CLI.
    GeminiCli,
    ClaudeCli,
    /// Google's Antigravity CLI (`agy`), the successor to Gemini CLI.
    AntigravityCli,
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
    /// How the provider is asked to review the change.
    #[serde(default, skip_serializing_if = "ReviewStrategy::is_whole_change")]
    pub strategy: ReviewStrategy,
    /// Advisory reviewers report findings that are shown but never block the gate.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub advisory: bool,
    /// How hard the reviewer works: a preset for `samples`. Mutually exclusive with `samples`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effort: Option<ReviewEffort>,
    /// How many times the review request is sent; findings are merged by agreement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub samples: Option<u32>,
    /// How many samples must report a finding for it to block; defaults to a strict majority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample_quorum: Option<u32>,
}
impl ReviewerConfig {
    pub fn sample_count(&self) -> u32 {
        self.samples
            .or(self.effort.map(ReviewEffort::samples))
            .unwrap_or(1)
    }

    pub fn effective_sample_quorum(&self) -> u32 {
        self.sample_quorum
            .unwrap_or_else(|| sampling::default_sample_quorum(self.sample_count()))
    }
}
/// How a reviewer's provider receives the change.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReviewStrategy {
    /// One request carries every changed file and returns findings directly.
    #[default]
    WholeChange,
    /// One reasoning request per changed file, then one request that turns the
    /// reasoning into findings located by a quoted changed line. Suited to
    /// small local models; requires an `ollama_native` provider.
    Focused,
}
impl ReviewStrategy {
    pub fn is_whole_change(&self) -> bool {
        *self == ReviewStrategy::WholeChange
    }
}
/// How much work a reviewer spends on a change. Higher effort sends the review
/// request more times and merges the runs by agreement (see `samples`).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReviewEffort {
    /// One run.
    Low,
    /// Three runs.
    Medium,
    /// Five runs.
    High,
}
impl ReviewEffort {
    pub fn samples(self) -> u32 {
        match self {
            ReviewEffort::Low => 1,
            ReviewEffort::Medium => 3,
            ReviewEffort::High => sampling::MAX_REVIEWER_SAMPLES,
        }
    }
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
    /// `block` (default): a changed file inside the review filter that no
    /// reviewer received leaves the analysis incomplete. `allow`: such files
    /// are only reported.
    #[serde(
        default = "default_unreviewed",
        skip_serializing_if = "is_default_unreviewed"
    )]
    pub on_unreviewed: String,
    #[serde(default)]
    pub acceptance: AcceptancePolicyConfig,
    /// Minimum severities by path or category (ADR 0018). Omitted when empty so
    /// existing configuration and policy digests are unchanged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub severity_floors: Vec<SeverityFloor>,
    /// `false`: a change reviewed under this policy always needs a person's
    /// approval, whatever `approval` allows. Omitted, the approval guards
    /// decide. Packs can turn it off but never back on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub automatic_approval: Option<bool>,
}

impl PolicyConfig {
    /// Whether this policy lets Vee approve a change without a person.
    pub fn allows_automatic_approval(&self) -> bool {
        self.automatic_approval != Some(false)
    }
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
            automatic_approval: None,
            required_reviewers: vec![],
            required_verifications: vec![],
            block_severities: default_severities(),
            minimum_confidence: default_confidence(),
            on_incomplete: default_incomplete(),
            on_unreviewed: default_unreviewed(),
            acceptance: AcceptancePolicyConfig::default(),
            severity_floors: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UserProviderConfig {
    pub version: u32,
    #[serde(default)]
    pub providers: std::collections::BTreeMap<String, ProviderConfig>,
    #[serde(default)]
    pub review: UserReviewDefaults,
    #[serde(default, skip_serializing_if = "UserPatchSettings::is_default")]
    pub patches: UserPatchSettings,
}

/// How this machine applies proposed patches.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UserPatchSettings {
    /// Apply an approved patch without a person confirming it at a terminal,
    /// for example in automation this machine's owner set up. Off by default,
    /// so an agent that may only propose patches cannot apply them itself.
    #[serde(default)]
    pub allow_noninteractive_apply: bool,
}

impl UserPatchSettings {
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }
}

/// Review defaults for this machine. Repository configuration wins.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UserReviewDefaults {
    /// Effort for reviewers whose repository configuration sets neither
    /// `effort` nor `samples`. Effort trades review time and tokens for
    /// quality, so it is a choice for whoever runs the review.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effort: Option<ReviewEffort>,
}
/// Credential variables a repository's `hosting` configuration may name, besides
/// any `VEE_`-prefixed variable. Other variables must come from a command-line flag.
pub const HOSTING_CREDENTIAL_NAMES: &[&str] = &[
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "GL_TOKEN",
    "GITLAB_TOKEN",
    "CI_JOB_TOKEN",
    "BB_TOKEN",
    "BITBUCKET_TOKEN",
    "AZURE_DEVOPS_EXT_PAT",
    "SYSTEM_ACCESSTOKEN",
    "GERRIT_TOKEN",
    "JIRA_API_TOKEN",
    "JIRA_EMAIL",
    "LINEAR_API_KEY",
];

pub fn is_hosting_credential_name(name: &str) -> bool {
    HOSTING_CREDENTIAL_NAMES.contains(&name) || name.starts_with("VEE_")
}

fn validate_work_items(tracker: &WorkItemsConfig) -> Result<(), String> {
    if !matches!(tracker.provider.as_str(), "jira" | "linear") {
        return Err("work_items.provider must be jira or linear".into());
    }
    if tracker.provider == "jira" && tracker.host.is_none() && tracker.api_base.is_none() {
        return Err("work_items.host must name the Jira site, such as acme.atlassian.net".into());
    }
    if let Some(host) = &tracker.host {
        let valid = !host.is_empty()
            && host.len() <= 253
            && host
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b".-:".contains(&byte));
        if !valid {
            return Err("work_items.host must be a host name".into());
        }
    }
    if let Some(api_base) = &tracker.api_base {
        let url = url::Url::parse(api_base)
            .map_err(|_| "work_items.api_base must be an absolute HTTPS URL".to_string())?;
        let loopback = matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
        if !(url.scheme() == "https" || url.scheme() == "http" && loopback)
            || url.host().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err("work_items.api_base must be an HTTPS URL without credentials, a query or a fragment".into());
        }
    }
    for (field, value) in [
        ("work_items.token_env", tracker.token_env.as_deref()),
        ("work_items.user_env", tracker.user_env.as_deref()),
    ] {
        if value.is_some_and(|name| !is_hosting_credential_name(name)) {
            return Err(format!(
                "{field} must name a tracker credential (JIRA_API_TOKEN, JIRA_EMAIL, LINEAR_API_KEY or a VEE_ variable)"
            ));
        }
    }
    if let Some(field) = &tracker.acceptance_field {
        let valid = !field.is_empty()
            && field.len() <= 64
            && field
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
        if !valid || tracker.provider != "jira" {
            return Err(
                "work_items.acceptance_field must be a Jira field ID such as customfield_10050"
                    .into(),
            );
        }
    }
    Ok(())
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

fn default_unreviewed() -> String {
    "block".into()
}

/// The default is omitted when serializing, so configurations that do not set
/// `on_unreviewed` keep the digest they had before the field existed.
fn is_default_unreviewed(value: &String) -> bool {
    *value == default_unreviewed()
}

impl RepositoryConfig {
    /// Apply one effort level to every reviewer for a single review, replacing
    /// configured `effort`, `samples` and `sample_quorum` (quorum returns to a majority).
    pub fn override_review_effort(&mut self, effort: ReviewEffort) {
        self.active_review_effort = Some(effort);
        for reviewer in self.reviewers.values_mut() {
            reviewer.effort = Some(effort);
            reviewer.samples = None;
            reviewer.sample_quorum = None;
        }
    }

    /// Merge a pack's policy into the repository policy, and remember it for
    /// any policy profile selected later.
    pub fn add_pack_policy(&mut self, pack: &PolicyConfig) {
        self.policy = packs::strictest(&self.policy, pack);
        self.pack_policies.push(pack.clone());
    }

    pub fn select_policy_profile(&mut self, profile: Option<&str>) -> Result<(), String> {
        self.active_policy_profile = None;
        if let Some(profile_id) = profile {
            let selected = self
                .policy_profiles
                .get(profile_id)
                .cloned()
                .ok_or_else(|| format!("unknown policy profile {profile_id}"))?;
            self.policy = self
                .pack_policies
                .iter()
                .fold(selected, |policy, pack| packs::strictest(&policy, pack));
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
        let mut user_effort = None;
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
            user_effort = user.review.effort;
        }
        if config.version != 1 {
            return Err(format!("unsupported config version {}", config.version));
        }
        packs::apply_packs(&mut config, root)?;
        if let Some(effort) = user_effort {
            for reviewer in config.reviewers.values_mut() {
                if reviewer.effort.is_none() && reviewer.samples.is_none() {
                    reviewer.effort = Some(effort);
                }
            }
        }
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
        if config.review.max_standards_bytes > 1024 * 1024 {
            return Err("review.max_standards_bytes must be at most 1048576".into());
        }
        if config.review.standards.len() > 64
            || config.review.standards.iter().any(|source| {
                source.path.trim().is_empty()
                    || source.path.len() > 512
                    || source.path.starts_with('/')
                    || source.path.split(['/', '\\']).any(|part| part == "..")
                    || source.paths.len() > 64
                    || source
                        .paths
                        .iter()
                        .any(|glob| glob.trim().is_empty() || glob.len() > 512)
            })
        {
            return Err("review.standards entries need a relative path inside the repository and at most 64 path globs".into());
        }
        if !(1..=16 * 1024 * 1024).contains(&config.review.max_context_bytes) {
            return Err("review.max_context_bytes must be in 1..=16777216".into());
        }
        if !(1..=200).contains(&config.review.exploration.max_tool_calls) {
            return Err("review.exploration.max_tool_calls must be in 1..=200".into());
        }
        if !(1024..=4 * 1024 * 1024).contains(&config.review.exploration.max_read_bytes) {
            return Err("review.exploration.max_read_bytes must be in 1024..=4194304".into());
        }
        if config
            .review
            .exploration
            .deny
            .iter()
            .any(|pattern| pattern.trim().is_empty())
        {
            return Err("review.exploration.deny entries must not be empty".into());
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
                // The repository configuration is shared and may come from any
                // branch, so it may only name hosting credentials. Any other
                // variable is passed with --token-env or --webhook-secret-env.
                if !is_hosting_credential_name(value) {
                    return Err(format!(
                        "{field} must name a hosting credential ({} or a VEE_ variable); pass another variable with the command-line flag",
                        HOSTING_CREDENTIAL_NAMES.join(", ")
                    ));
                }
            }
        }
        if let Some(tracker) = &config.work_items {
            validate_work_items(tracker)?;
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
        if config.policy.on_unreviewed != "block" && config.policy.on_unreviewed != "allow" {
            return Err("policy.on_unreviewed must be 'block' or 'allow'".into());
        }
        if !matches!(config.approval.max_risk(), "low" | "elevated") {
            return Err("approval.max_risk must be 'low' or 'elevated'".into());
        }
        if !matches!(
            config.approval.mode.as_deref(),
            None | Some("observe" | "enforce")
        ) {
            return Err("approval.mode must be 'observe' or 'enforce'".into());
        }
        if config
            .approval
            .max_per_day
            .is_some_and(|limit| !(1..=1000).contains(&limit))
        {
            return Err("approval.max_per_day must be 1 to 1000".into());
        }
        for (field, patterns) in [
            ("approval.never_paths", &config.approval.never_paths),
            ("approval.never_authors", &config.approval.never_authors),
            ("approval.never_owners", &config.approval.never_owners),
        ] {
            if patterns.len() > 256
                || patterns.iter().any(|pattern| {
                    pattern.trim().is_empty()
                        || pattern.len() > 512
                        || pattern.chars().any(char::is_control)
                })
            {
                return Err(format!(
                    "{field} has an empty, invalid, or too long pattern"
                ));
            }
        }
        for severity in &config.policy.block_severities {
            if !matches!(
                severity.as_str(),
                "critical" | "high" | "medium" | "low" | "info"
            ) {
                return Err(format!("unknown blocking severity {severity}"));
            }
        }
        validate_severity_floors("policy", &config.policy.severity_floors)?;
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
            // Vee sets PWD to the provider's own working directory; an
            // allowlisted value would enter the digests but never reach it.
            if provider.env_allowlist.iter().any(|name| name == "PWD") {
                return Err(format!(
                    "provider {id}: remove PWD from env_allowlist; Vee sets it to the provider's working directory"
                ));
            }
            if provider.kind == ProviderKind::Cli && provider.model.is_some() {
                return Err(format!(
                    "provider {id} can only set model with a provider-specific adapter"
                ));
            }
            if (provider.kind == ProviderKind::CodexCli
                || provider.kind == ProviderKind::ClaudeCli
                || provider.kind == ProviderKind::GeminiCli
                || provider.kind == ProviderKind::AntigravityCli)
                && !provider.args.is_empty()
            {
                return Err(format!(
                    "provider {id} provider-specific arguments are controlled by the adapter"
                ));
            }
            if (provider.kind == ProviderKind::CodexCli
                || provider.kind == ProviderKind::ClaudeCli
                || provider.kind == ProviderKind::AntigravityCli)
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
            if provider.kind == ProviderKind::AntigravityCli
                && provider.egress == ProviderEgress::Local
            {
                return Err(format!(
                    "provider {id} antigravity_cli cannot be declared local; use a local inference adapter"
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
            if reviewer.strategy == ReviewStrategy::Focused
                && config.providers[&reviewer.provider].kind != ProviderKind::OllamaNative
            {
                return Err(format!(
                    "reviewer {id} uses strategy focused, which requires an ollama_native provider"
                ));
            }
            if reviewer
                .samples
                .is_some_and(|samples| !(1..=sampling::MAX_REVIEWER_SAMPLES).contains(&samples))
            {
                return Err(format!(
                    "reviewer {id} samples must be 1..={}",
                    sampling::MAX_REVIEWER_SAMPLES
                ));
            }
            if reviewer.effort.is_some() && reviewer.samples.is_some() {
                return Err(format!("reviewer {id} sets both effort and samples"));
            }
            if let Some(quorum) = reviewer.sample_quorum {
                if reviewer.sample_count() <= 1 {
                    return Err(format!("reviewer {id} sets sample_quorum without samples"));
                }
                if !(1..=reviewer.sample_count()).contains(&quorum) {
                    return Err(format!(
                        "reviewer {id} sample_quorum must be 1..={}",
                        reviewer.sample_count()
                    ));
                }
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
            if profile.on_unreviewed != "block" && profile.on_unreviewed != "allow" {
                return Err(format!(
                    "policy profile {profile_id} on_unreviewed must be 'block' or 'allow'"
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
            validate_severity_floors(
                &format!("policy profile {profile_id}"),
                &profile.severity_floors,
            )?;
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
    /// Which run of a sampled reviewer this request is; absent for an unsampled reviewer.
    pub sample: Option<ProviderSample>,
    /// The snapshot tool server a CLI reviewer may start (ADR 0017); absent
    /// when exploration is off or the provider cannot use it.
    pub exploration: Option<ExplorationLaunch>,
}

/// How a reviewer CLI starts Vee's snapshot tool server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExplorationLaunch {
    pub program: String,
    pub args: Vec<String>,
    /// Identifies the tool contract and budgets, without per-run paths, so
    /// the review cache can key on it.
    pub descriptor: String,
}
/// Names of the snapshot tools, as the MCP server registers them.
pub const EXPLORATION_TOOLS: &[&str] = &["list_files", "read_file", "search"];
/// MCP server name reviewers see the snapshot tools under.
pub const EXPLORATION_SERVER_NAME: &str = "vee_snapshot";
/// One run of a reviewer that sends the same request several times.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ProviderSample {
    /// Zero-based run number.
    pub index: u32,
    /// How many runs the reviewer makes.
    pub count: u32,
}
impl ProviderUsage {
    /// Add another run's usage; a total is known only when both sides know it.
    pub fn accumulate(&mut self, other: &ProviderUsage) {
        fn add(left: Option<u64>, right: Option<u64>) -> Option<u64> {
            Some(left?.saturating_add(right?))
        }
        self.input_tokens = add(self.input_tokens, other.input_tokens);
        self.output_tokens = add(self.output_tokens, other.output_tokens);
        self.total_tokens = add(self.total_tokens, other.total_tokens);
    }
}

/// Matches a repository-relative path against a glob: `*` and `?` stay within
/// one path segment, `**` crosses segments.
pub fn glob_matches(pattern: &str, path: &str) -> bool {
    fn matches(
        pattern: &[u8],
        path: &[u8],
        pattern_index: usize,
        path_index: usize,
        memo: &mut std::collections::HashMap<(usize, usize), bool>,
    ) -> bool {
        if let Some(result) = memo.get(&(pattern_index, path_index)) {
            return *result;
        }
        let result = if pattern_index == pattern.len() {
            path_index == path.len()
        } else if pattern[pattern_index..].starts_with(b"**/") {
            matches(pattern, path, pattern_index + 3, path_index, memo)
                || path[path_index..]
                    .iter()
                    .enumerate()
                    .filter(|(_, byte)| **byte == b'/')
                    .any(|(offset, _)| {
                        matches(
                            pattern,
                            path,
                            pattern_index + 3,
                            path_index + offset + 1,
                            memo,
                        )
                    })
        } else if pattern[pattern_index..].starts_with(b"**") {
            matches(pattern, path, pattern_index + 2, path_index, memo)
                || (path_index < path.len()
                    && matches(pattern, path, pattern_index, path_index + 1, memo))
        } else if pattern[pattern_index] == b'*' {
            matches(pattern, path, pattern_index + 1, path_index, memo)
                || (path_index < path.len()
                    && path[path_index] != b'/'
                    && matches(pattern, path, pattern_index, path_index + 1, memo))
        } else if pattern[pattern_index] == b'?' {
            path_index < path.len()
                && path[path_index] != b'/'
                && matches(pattern, path, pattern_index + 1, path_index + 1, memo)
        } else {
            path_index < path.len()
                && pattern[pattern_index] == path[path_index]
                && matches(pattern, path, pattern_index + 1, path_index + 1, memo)
        };
        memo.insert((pattern_index, path_index), result);
        result
    }

    let pattern = pattern.replace('\\', "/");
    let path = path.replace('\\', "/");
    matches(
        pattern.as_bytes(),
        path.as_bytes(),
        0,
        0,
        &mut std::collections::HashMap::new(),
    )
}
