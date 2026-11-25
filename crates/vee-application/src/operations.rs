//! Transport-neutral Vee operations.
//!
//! The CLI and the MCP server are thin adapters over this module: each operation
//! validates its input once, runs the shared application services, and returns the
//! published result document. The CLI prints that document for `--output json` (or
//! renders it as text); the MCP server returns it as the tool result. Errors carry the
//! CLI's usage/configuration markers so both transports report the same message and
//! the CLI keeps its documented exit codes.

use crate::failure::{configuration_failure, usage_failure};
use crate::{GateCheckResult, ReviewResult};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use vee_core::ports::*;
use vee_core::{
    ActorName, Evidence, FindingFeedback, FindingFeedbackLabel, FindingRecord, FindingStatus,
    FindingStatusChange, Reason, RepositoryConfig, Severity, VerificationRun,
};

pub const DEFAULT_PAGE_SIZE: usize = 50;
pub const MAX_PAGE_SIZE: usize = 100;
pub const DEFAULT_CONTEXT_LINES: usize = 20;
/// Results returned by imported-history search when no limit is given.
pub const DEFAULT_SEARCH_LIMIT: usize = 20;
/// Reviewer that drafts tests and PR descriptions when none is named.
pub const DEFAULT_DRAFTING_REVIEWER: &str = "correctness";
const MAX_SCOPE_CHARS: usize = 1_024;
const MAX_INSTRUCTION_BYTES: usize = 20_000;
/// Upper bound on findings scanned when mining rule candidates.
const RULE_MINING_FINDING_LIMIT: usize = 10_000;

/// The repository a transport operates on, and its local Vee database.
#[derive(Clone)]
pub struct Workspace {
    root: PathBuf,
    stores: std::sync::Arc<dyn RepositoryStores + Send + Sync>,
}

impl std::fmt::Debug for Workspace {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Workspace")
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

impl Workspace {
    /// A workspace at `root` whose local state is opened through `stores`.
    pub fn new(root: PathBuf, stores: std::sync::Arc<dyn RepositoryStores + Send + Sync>) -> Self {
        Self { root, stores }
    }

    /// The Git checkout containing the current directory.
    pub fn discover(stores: std::sync::Arc<dyn RepositoryStores + Send + Sync>) -> Result<Self> {
        let cwd = std::env::current_dir()?;
        let root = vee_git::repository_root(&cwd).map_err(anyhow::Error::msg)?;
        Ok(Self::new(root, stores))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Open the review store, creating local state on first use.
    pub fn store(&self) -> Result<Box<dyn Repositories>> {
        self.stores.open(&self.root).map_err(anyhow::Error::msg)
    }

    /// Open the review store only if it already exists, so read-only operations do
    /// not create local state as a side effect.
    pub fn existing_store(&self) -> Result<Option<Box<dyn Repositories>>> {
        self.stores
            .open_existing(&self.root)
            .map_err(anyhow::Error::msg)
    }

    /// The configuration a saved review ran with: its policy profile and any
    /// effort override reapplied to the current repository configuration.
    pub fn saved_review_config(&self, review: &ReviewResult) -> Result<RepositoryConfig> {
        let mut config = self.effective_config(review.policy_profile.as_deref())?;
        if let Some(effort) = review.review_effort {
            config.override_review_effort(effort);
        }
        Ok(config)
    }

    /// Repository configuration with the named policy profile and protected local
    /// policy applied, exactly as reviews and gates evaluate it.
    pub fn effective_config(&self, policy_profile: Option<&str>) -> Result<RepositoryConfig> {
        let mut config =
            crate::load_repository_config(&self.root).map_err(configuration_failure)?;
        config
            .select_policy_profile(policy_profile)
            .map_err(configuration_failure)?;
        crate::apply_protected_policy(&self.root, &mut config).map_err(configuration_failure)?;
        Ok(config)
    }

    fn saved_review(&self, store: &dyn Repositories, review_id: &str) -> Result<ReviewResult> {
        let payload = store
            .get(review_id)
            .map_err(anyhow::Error::msg)?
            .ok_or_else(|| usage_failure(format!("review {review_id} was not found")))?;
        crate::deserialize_review_result(&payload)
            .map_err(|error| anyhow::anyhow!("stored review {review_id} is invalid: {error}"))
    }

    fn finding(&self, store: &dyn Repositories, finding_id: &str) -> Result<FindingRecord> {
        store
            .finding(finding_id)
            .map_err(anyhow::Error::msg)?
            .ok_or_else(|| usage_failure(format!("finding {finding_id} was not found")))
    }

    /// Recapture a saved review's scope and fail if the source no longer matches.
    fn current_snapshot_of(&self, review: &ReviewResult) -> Result<vee_core::ChangeSet> {
        let current = crate::capture_current_change_set(&self.root, &review.change_set)
            .map_err(anyhow::Error::msg)?;
        if current.digest != review.snapshot_id {
            return Err(usage_failure(format!(
                "review {} is stale because its source snapshot changed",
                review.review_id
            )));
        }
        Ok(current)
    }
}

fn require_text(field: &str, value: &str, max_chars: usize) -> Result<()> {
    let length = value.trim().chars().count();
    if length == 0 || value.chars().count() > max_chars {
        return Err(usage_failure(format!(
            "{field} must contain 1 to {max_chars} characters"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Change scope and review

/// The scope kinds a tool input names explicitly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScopeKind {
    WorkingTree,
    Staged,
    Base,
    Commit,
}

/// Which changes to capture.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScopeRequest {
    /// Working tree plus commits since the merge base with `base` (or HEAD).
    BaseAndWorktree {
        base: Option<String>,
    },
    WorkingTree,
    Staged,
    Commit(String),
}

impl ScopeRequest {
    /// Build a scope from the CLI's mutually exclusive scope flags.
    pub fn from_flags(
        base: Option<String>,
        commit: Option<String>,
        staged: bool,
        working_tree: bool,
    ) -> Result<Self> {
        let selected =
            usize::from(commit.is_some()) + usize::from(staged) + usize::from(working_tree);
        if selected > 1 {
            return Err(usage_failure(
                "--commit, --staged, and --working-tree are mutually exclusive",
            ));
        }
        if base.is_some() && selected > 0 {
            return Err(usage_failure(
                "--base cannot be combined with --commit, --staged, or --working-tree",
            ));
        }
        Ok(match (commit, staged, working_tree) {
            (Some(commit), _, _) => Self::Commit(commit),
            (None, true, _) => Self::Staged,
            (None, false, true) => Self::WorkingTree,
            (None, false, false) => Self::BaseAndWorktree { base },
        })
    }

    /// Build a scope from an explicit kind and its ref, as tool inputs give it.
    /// Unlike the CLI's default, `Base` requires a ref.
    pub fn from_kind(
        kind: ScopeKind,
        base: Option<String>,
        commit: Option<String>,
    ) -> Result<Self> {
        let invalid = |message: &str| usage_failure(message.to_owned());
        match kind {
            ScopeKind::Staged | ScopeKind::WorkingTree if base.is_some() || commit.is_some() => {
                Err(invalid(
                    "staged/working_tree scope cannot be combined with base or commit",
                ))
            }
            ScopeKind::Staged => Ok(Self::Staged),
            ScopeKind::WorkingTree => Ok(Self::WorkingTree),
            ScopeKind::Base if commit.is_some() => {
                Err(invalid("base scope cannot be combined with commit"))
            }
            ScopeKind::Base => base
                .map(|base| Self::BaseAndWorktree { base: Some(base) })
                .ok_or_else(|| invalid("base scope requires a base ref")),
            ScopeKind::Commit if base.is_some() => {
                Err(invalid("commit scope cannot be combined with base"))
            }
            ScopeKind::Commit => commit
                .map(Self::Commit)
                .ok_or_else(|| invalid("commit scope requires a commit ref")),
        }
    }

    pub fn resolve(&self, root: &Path) -> Result<vee_git::ChangeScope> {
        match self {
            Self::BaseAndWorktree { base } => Ok(vee_git::ChangeScope::BaseAndWorktree {
                base_oid: base
                    .as_deref()
                    .map(|base_ref| vee_git::merge_base(root, base_ref))
                    .transpose()
                    .map_err(usage_failure)?,
            }),
            Self::WorkingTree => Ok(vee_git::ChangeScope::WorkingTree),
            Self::Staged => Ok(vee_git::ChangeScope::Staged),
            Self::Commit(commit) => vee_git::commit_scope(commit).map_err(usage_failure),
        }
    }
}

pub struct ReviewRequest<'a> {
    pub scope: ScopeRequest,
    pub reviewer_ids: Option<&'a [String]>,
    pub policy_profile: Option<&'a str>,
    /// Effort for every reviewer in this review, replacing configured sampling.
    pub effort: Option<vee_core::ReviewEffort>,
    /// Work item to fetch as `OWNER/REPO#NUMBER`; requires online configuration.
    pub work_item: Option<&'a str>,
    /// Hosting settings for this review; unset values come from `.vee.yaml`.
    pub hosting: crate::work_items::HostingOverrides,
    /// Receives live reviewer progress while providers run.
    pub progress: Option<&'a dyn crate::ReviewProgressSink>,
}

/// Capture the requested scope, run the configured reviewers, and persist the review.
pub fn review(
    workspace: &Workspace,
    request: ReviewRequest<'_>,
    cancellation: Option<&tokio_util::sync::CancellationToken>,
) -> Result<ReviewResult> {
    if cancellation.is_some_and(tokio_util::sync::CancellationToken::is_cancelled) {
        anyhow::bail!("review cancelled before capture");
    }
    // Validate configuration before touching local state.
    let mut config = workspace.effective_config(request.policy_profile)?;
    if let Some(effort) = request.effort {
        config.override_review_effort(effort);
    }
    if request.work_item.is_some() && config.offline {
        return Err(configuration_failure(
            "offline mode prevents fetching work item context",
        ));
    }
    // Every transport records the credential variable, so a later gate check
    // re-fetches the work item the same way whichever transport started the review.
    let hosting = crate::work_items::resolve_hosting(request.hosting, &config.hosting);
    let work_item = request
        .work_item
        .map(|spec| crate::work_items::fetch_work_item(&hosting, spec))
        .transpose()?;
    let scope = request.scope.resolve(workspace.root())?;
    let change_set =
        crate::capture_change_set(workspace.root(), scope).map_err(anyhow::Error::msg)?;
    let mut store = workspace.store()?;
    crate::run_review_with_provider_and_selection_context(
        workspace.root(),
        change_set,
        &config,
        &mut *store,
        crate::ReviewRunOptions {
            provider_adapter: &crate::CliReviewProvider,
            requested_reviewers: request.reviewer_ids,
            cancellation,
            work_item,
            work_item_token_env: Some(hosting.token_env),
            progress: request.progress,
        },
    )
    .map_err(anyhow::Error::msg)
}

pub fn get_review(workspace: &Workspace, review_id: &str) -> Result<ReviewResult> {
    let store = workspace.store()?;
    workspace.saved_review(&*store, review_id)
}

/// Saved reviews, newest first.
/// `reviews-list-v1`
#[derive(Debug, Serialize, Deserialize)]
pub struct ReviewsList {
    pub schema_version: u32,
    pub reviews: Vec<vee_core::ReviewSummary>,
}

pub fn reviews_list(workspace: &Workspace) -> Result<ReviewsList> {
    Ok(ReviewsList {
        schema_version: 1,
        reviews: list_reviews(workspace)?,
    })
}

/// `verification-list-v1`: run metadata for one snapshot, without logs.
#[derive(Debug, Serialize, Deserialize)]
pub struct VerificationList {
    pub schema_version: u32,
    pub snapshot_id: String,
    pub runs: Vec<VerificationRunSummary>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerificationRunSummary {
    pub run_id: String,
    pub snapshot_id: String,
    pub profile_id: String,
    pub status: vee_core::VerificationStatus,
    pub targets: Vec<String>,
    pub has_stdout_artifact: bool,
    pub has_stderr_artifact: bool,
}

pub fn verification_list(workspace: &Workspace, snapshot_id: &str) -> Result<VerificationList> {
    let runs = workspace
        .store()?
        .verifications_for_snapshot(snapshot_id)
        .map_err(anyhow::Error::msg)?;
    Ok(VerificationList {
        schema_version: 1,
        snapshot_id: snapshot_id.to_owned(),
        runs: runs
            .into_iter()
            .map(|run| VerificationRunSummary {
                has_stdout_artifact: run.stdout_artifact.is_some(),
                has_stderr_artifact: run.stderr_artifact.is_some(),
                run_id: run.run_id,
                snapshot_id: run.snapshot_id,
                profile_id: run.profile_id,
                status: run.status,
                targets: run.targets,
            })
            .collect(),
    })
}

/// `finding-feedback-list-v1`
#[derive(Debug, Serialize, Deserialize)]
pub struct FindingFeedbackList {
    pub schema_version: u32,
    pub feedback: Vec<FindingFeedback>,
}

pub fn finding_feedback_list(
    workspace: &Workspace,
    finding_id: Option<&str>,
) -> Result<FindingFeedbackList> {
    let feedback = workspace
        .store()?
        .list_finding_feedback()
        .map_err(anyhow::Error::msg)?
        .into_iter()
        .filter(|item| finding_id.is_none_or(|id| item.finding_id == id))
        .collect();
    Ok(FindingFeedbackList {
        schema_version: 1,
        feedback,
    })
}

pub fn list_reviews(workspace: &Workspace) -> Result<Vec<vee_core::ReviewSummary>> {
    workspace
        .store()?
        .list_reviews()
        .map_err(anyhow::Error::msg)
}

/// A saved review as the dashboard shows it.
#[derive(Debug, Serialize)]
pub struct ReviewDetail {
    pub review: ReviewResult,
    pub findings: Vec<FindingRecord>,
    pub impact: crate::ImpactAssessment,
    /// Change risk, available while the checkout matches the reviewed snapshot.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk: Option<crate::ChangeRisk>,
    /// Whether the checkout still matches the reviewed snapshot; impact and
    /// risk are only computed while it does.
    pub snapshot_current: bool,
    /// The newest later complete review of the same scope and base, when one exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub superseded_by: Option<Supersession>,
}

/// A later complete review of the same scope and base commit that ran every
/// reviewer this review ran, and which of this
/// review's findings it no longer reported. Display only: it does not change
/// gates, dispositions or waivers.
#[derive(Debug, Serialize)]
pub struct Supersession {
    pub review_id: String,
    pub created_at: String,
    pub outdated_finding_ids: Vec<String>,
}

/// How many newer saved reviews are inspected when looking for a later review
/// of the same scope and base.
const MAX_SUPERSESSION_CANDIDATES: usize = 100;

fn later_review_of_same_base(
    workspace: &Workspace,
    store: &dyn Repositories,
    review: &ReviewResult,
) -> Result<Option<Supersession>> {
    let summaries = store.list_reviews().map_err(anyhow::Error::msg)?;
    let Some(position) = summaries
        .iter()
        .position(|summary| summary.review_id == review.review_id)
    else {
        return Ok(None);
    };
    let successful = |review: &ReviewResult| -> std::collections::BTreeSet<String> {
        review
            .reviewer_outcomes
            .iter()
            .filter(|outcome| outcome.succeeded())
            .map(|outcome| outcome.reviewer_id.clone())
            .collect()
    };
    let ran_here = successful(review);
    // Summaries are newest first, so everything before this review is later.
    for summary in summaries[..position]
        .iter()
        .take(MAX_SUPERSESSION_CANDIDATES)
    {
        let Ok(candidate) = workspace.saved_review(store, &summary.review_id) else {
            continue;
        };
        // An incomplete review may have missed findings, so its silence about
        // a finding says nothing.
        // It must also have run every reviewer that ran here: a review limited
        // to other reviewers could not have reported these findings again.
        if !candidate.analysis_complete
            || candidate.change_set.scope != review.change_set.scope
            || candidate.change_set.base_oid != review.change_set.base_oid
            || !ran_here.is_subset(&successful(&candidate))
        {
            continue;
        }
        let reported: std::collections::BTreeSet<&str> = candidate
            .findings
            .iter()
            .map(|finding| finding.fingerprint.as_str())
            .collect();
        return Ok(Some(Supersession {
            review_id: summary.review_id.clone(),
            created_at: summary.created_at.clone(),
            outdated_finding_ids: review
                .findings
                .iter()
                .filter(|finding| !reported.contains(finding.fingerprint.as_str()))
                .map(|finding| finding.id.clone())
                .collect(),
        }));
    }
    Ok(None)
}

/// A saved review with its latest gate decision applied, its findings, and an
/// impact assessment recomputed from the current checkout when the checkout
/// still matches the review's snapshot.
pub fn review_detail(workspace: &Workspace, review_id: &str) -> Result<ReviewDetail> {
    review_detail_and_currency(workspace, review_id).map(|(detail, _)| detail)
}

/// The review detail, and whether the checkout still matches its snapshot.
fn review_detail_and_currency(
    workspace: &Workspace,
    review_id: &str,
) -> Result<(ReviewDetail, bool)> {
    let store = workspace.store()?;
    let mut review = workspace.saved_review(&*store, review_id)?;
    if let Some(latest_gate) = store
        .gate_decisions_for_review(review_id)
        .map_err(anyhow::Error::msg)?
        .pop()
    {
        review.status = match latest_gate.status {
            vee_core::GateStatus::Pass => "pass",
            vee_core::GateStatus::Block => "block",
            vee_core::GateStatus::Incomplete => "incomplete",
        }
        .into();
        review.reasons = latest_gate.reasons.clone();
        review.gate = latest_gate;
    }
    let findings = store
        .list_findings(None, None, Some(review_id))
        .map_err(anyhow::Error::msg)?;
    let (impact, current) = current_impact(workspace.root(), &review);
    // Risk reads the snapshot's files, so it needs the same live checkout.
    let risk = current
        .then(|| crate::assess_change_risk(workspace.root(), &review.change_set, &impact).ok())
        .flatten();
    let superseded_by = later_review_of_same_base(workspace, &*store, &review)?;
    Ok((
        ReviewDetail {
            review,
            findings,
            impact,
            risk,
            snapshot_current: current,
            superseded_by,
        },
        current,
    ))
}

/// Impact for a saved review. Impact is computed from source, so it is only
/// available while the checkout still matches the reviewed snapshot; otherwise
/// the assessment is empty and says why.
/// The flag is true when the impact was computed from a checkout matching the snapshot.
fn current_impact(root: &Path, review: &ReviewResult) -> (crate::ImpactAssessment, bool) {
    let limitation = match crate::capture_current_change_set(root, &review.change_set) {
        Ok(current) if current.digest == review.snapshot_id => {
            match crate::analyze_impact(root, &review.change_set) {
                Ok(impact) => return (impact, true),
                Err(error) => {
                    format!("saved review is available, but impact analysis failed: {error}")
                }
            }
        }
        Ok(_) => "current checkout differs from saved review snapshot; impact is unavailable for this historical review".into(),
        Err(error) => format!("saved review is available, but impact could not be recomputed from the current checkout: {error}"),
    };
    let unavailable = crate::ImpactAssessment {
        schema_version: crate::impact::IMPACT_SCHEMA_VERSION,
        snapshot_id: review.snapshot_id.clone(),
        coverage_complete: false,
        analyzers: Vec::new(),
        changed_paths: review
            .change_set
            .files
            .iter()
            .map(|file| file.path.clone())
            .collect(),
        changed_symbols: Vec::new(),
        groups: Vec::new(),
        paths: Vec::new(),
        limitations: vec![limitation],
    };
    (unavailable, false)
}

/// `local-review-analytics-v10`
pub fn local_analytics(workspace: &Workspace) -> Result<crate::local_analytics::LocalAnalytics> {
    let store = workspace.store()?;
    let mut analytics =
        crate::local_analytics::build(workspace.root(), &*store).map_err(anyhow::Error::msg)?;
    annotate_analyzer_runs(workspace, &mut analytics.verification_runs);
    Ok(analytics)
}

/// SARIF analyzers exit non-zero whenever they report anything, so a run's
/// status reads "failed" even when nothing lands on the changed lines. Record
/// what the gate evaluates, so trends do not contradict the gate. Runs whose
/// output or configuration cannot be read keep only their process status.
fn annotate_analyzer_runs(
    workspace: &Workspace,
    runs: &mut [crate::local_analytics::AnalyticsVerificationRun],
) {
    // Analytics also serves repositories without a configuration; their runs
    // keep only their process status.
    let (Ok(config), Ok(store)) = (workspace.effective_config(None), workspace.store()) else {
        return;
    };
    for entry in runs.iter_mut().filter(|entry| entry.status == "failed") {
        let is_analyzer = config
            .verification
            .get(&entry.profile_id)
            .is_some_and(|profile| profile.sarif.is_some());
        if !is_analyzer {
            continue;
        }
        let Ok(Some(run)) = store.verification(&entry.run_id) else {
            continue;
        };
        if let Ok(report) = analyzer_report_for(workspace, &run) {
            if report.parsed {
                entry.analyzer_findings_on_changed_lines = Some(report.findings.len());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Repository configuration editor

/// Upper bound on a repository configuration submitted through an editor.
pub const MAX_REPOSITORY_CONFIG_BYTES: usize = 256 * 1024;

/// The repository-owned `.vee.yaml` and the provider and reviewer ids it can
/// reference once user-level defaults are merged in.
#[derive(Debug, Serialize)]
pub struct RepositoryConfigView {
    pub config: RepositoryConfig,
    pub provider_ids: Vec<String>,
    pub reviewer_ids: Vec<String>,
}

pub fn repository_config_view(workspace: &Workspace) -> Result<RepositoryConfigView> {
    let effective =
        crate::load_repository_config(workspace.root()).map_err(configuration_failure)?;
    // The editor shows repository-owned YAML only. User-level provider defaults may
    // satisfy references in this file, so do not validate this partial view alone.
    let path = workspace.root().join(".vee.yaml");
    let raw = std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let config: RepositoryConfig = serde_yaml::from_str(&raw)
        .map_err(|error| configuration_failure(format!("parse .vee.yaml: {error}")))?;
    Ok(RepositoryConfigView {
        provider_ids: effective.providers.keys().cloned().collect(),
        reviewer_ids: effective.reviewers.keys().cloned().collect(),
        config,
    })
}

/// Providers and verification profiles name programs Vee runs. The UI's
/// editor may change everything else; these are edited in `.vee.yaml` itself,
/// so a request to the UI cannot make Vee run a new program.
fn ensure_programs_unchanged(workspace: &Workspace, replacement: &str) -> Result<()> {
    let parse = |text: &str| -> Result<(serde_json::Value, serde_json::Value)> {
        let config: RepositoryConfig = serde_yaml::from_str(text)
            .map_err(|error| usage_failure(format!("invalid configuration: {error}")))?;
        Ok((
            serde_json::to_value(&config.providers)?,
            serde_json::to_value(&config.verification)?,
        ))
    };
    let path = workspace.root().join(".vee.yaml");
    let current = match std::fs::read_to_string(&path) {
        Ok(text) => parse(&text)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            (serde_json::json!({}), serde_json::json!({}))
        }
        Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
    };
    let (providers, verification) = parse(replacement)?;
    if providers != current.0 || verification != current.1 {
        return Err(usage_failure(
            "providers and verification profiles run programs, so they are edited in .vee.yaml, not here",
        ));
    }
    Ok(())
}

/// Validate a replacement repository configuration and atomically write it to
/// `.vee.yaml`. Nothing is written unless every cross-reference and protected
/// requirement holds.
pub fn replace_repository_config(
    workspace: &Workspace,
    config: &serde_json::Value,
) -> Result<RepositoryConfigView> {
    let body = serde_json::to_string(config)?;
    if body.len() > MAX_REPOSITORY_CONFIG_BYTES {
        return Err(usage_failure("configuration exceeds 256 KiB"));
    }
    ensure_programs_unchanged(workspace, &body)?;
    crate::validate_repository_config_yaml(workspace.root(), &body).map_err(usage_failure)?;
    let mut temporary = tempfile::NamedTempFile::new_in(workspace.root())?;
    std::io::Write::write_all(temporary.as_file_mut(), body.as_bytes())?;
    temporary.persist(workspace.root().join(".vee.yaml"))?;
    repository_config_view(workspace)
}

// ---------------------------------------------------------------------------
// Findings

#[derive(Clone, Debug, Default)]
pub struct FindingQuery {
    pub review_id: Option<String>,
    pub severity: Option<Severity>,
    pub status: Option<FindingStatus>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// `findings-list-v2`
#[derive(Debug, Serialize, Deserialize)]
pub struct FindingsPage {
    pub schema_version: u32,
    pub findings: Vec<FindingRecord>,
    pub limit: usize,
    pub offset: usize,
    pub total: usize,
}

pub fn list_findings(workspace: &Workspace, query: FindingQuery) -> Result<FindingsPage> {
    let limit = query.limit.unwrap_or(DEFAULT_PAGE_SIZE);
    if !(1..=MAX_PAGE_SIZE).contains(&limit) {
        return Err(usage_failure(format!(
            "limit must be between 1 and {MAX_PAGE_SIZE}"
        )));
    }
    let offset = query.offset.unwrap_or(0);
    let (findings, total) = workspace
        .store()?
        .list_findings_page(
            query.severity,
            query.status,
            query.review_id.as_deref(),
            limit,
            offset,
        )
        .map_err(anyhow::Error::msg)?;
    Ok(FindingsPage {
        schema_version: 2,
        findings,
        limit,
        offset,
        total,
    })
}

/// Every finding matching the filters, unpaged, as the dashboard lists them.
pub fn all_findings(
    workspace: &Workspace,
    severity: Option<Severity>,
    review_id: Option<&str>,
) -> Result<Vec<FindingRecord>> {
    workspace
        .store()?
        .list_findings(severity, None, review_id)
        .map_err(anyhow::Error::msg)
}

/// `finding-detail-v2`
#[derive(Debug, Serialize, Deserialize)]
pub struct FindingDetail {
    pub schema_version: u32,
    pub finding: FindingRecord,
    pub evidence: Vec<Evidence>,
    pub verification_runs: Vec<VerificationRun>,
}

pub fn finding_detail(workspace: &Workspace, finding_id: &str) -> Result<FindingDetail> {
    let store = workspace.store()?;
    let finding = workspace.finding(&*store, finding_id)?;
    let mut evidence: Vec<Evidence> = Vec::new();
    for occurrence in finding.occurrences.iter().rev() {
        for item in store
            .evidence_for_review(&occurrence.review_id)
            .map_err(anyhow::Error::msg)?
        {
            if finding.finding.evidence_ids.contains(&item.id)
                && !evidence.iter().any(|prior| prior.id == item.id)
            {
                evidence.push(item);
            }
        }
    }
    let verification_runs = store
        .verifications_for_finding(finding_id)
        .map_err(anyhow::Error::msg)?;
    Ok(FindingDetail {
        schema_version: 2,
        finding,
        evidence,
        verification_runs,
    })
}

pub fn finding_task(
    workspace: &Workspace,
    finding_id: &str,
    context_lines: usize,
) -> Result<crate::finding_task::FindingTask> {
    let store = workspace.store()?;
    let record = workspace.finding(&*store, finding_id)?;
    crate::finding_task::build(workspace.root(), &*store, record, context_lines)
        .map_err(anyhow::Error::msg)
}

pub fn finding_work_package(
    workspace: &Workspace,
    finding_ids: &[String],
    context_lines: usize,
) -> Result<crate::finding_task::FindingWorkPackage> {
    let store = workspace.store()?;
    crate::finding_task::build_package(workspace.root(), &*store, finding_ids, context_lines)
        .map_err(usage_failure)
}

/// `finding-status-update-v1`
#[derive(Debug, Serialize, Deserialize)]
pub struct FindingStatusUpdate {
    pub schema_version: u32,
    pub finding_id: String,
    pub status: FindingStatus,
    pub reason: String,
    pub note: String,
}

pub fn set_finding_status(
    workspace: &Workspace,
    finding_id: &str,
    status: FindingStatus,
    reason: &str,
) -> Result<FindingStatusUpdate> {
    let change = FindingStatusChange::new(status, Reason::new(reason).map_err(usage_failure)?)
        .map_err(usage_failure)?;
    workspace
        .store()?
        .set_finding_status(finding_id, &change)
        .map_err(anyhow::Error::msg)?;
    Ok(FindingStatusUpdate {
        schema_version: 1,
        finding_id: finding_id.to_owned(),
        status,
        reason: change.reason().as_str().to_owned(),
        note: "Lifecycle status is audit metadata. Use the waiver workflow for a scoped gate exception."
            .into(),
    })
}

pub struct FeedbackRequest<'a> {
    pub finding_id: &'a str,
    pub snapshot_id: &'a str,
    pub label: FindingFeedbackLabel,
    pub reason: &'a str,
    pub reviewer: &'a str,
}

pub fn record_finding_feedback(
    workspace: &Workspace,
    request: FeedbackRequest<'_>,
) -> Result<FindingFeedback> {
    let reason = Reason::new(request.reason).map_err(usage_failure)?;
    let reviewer = ActorName::new("reviewer", request.reviewer).map_err(usage_failure)?;
    workspace
        .store()?
        .add_finding_feedback(
            request.finding_id,
            request.snapshot_id,
            request.label,
            &reason,
            &reviewer,
        )
        .map_err(anyhow::Error::msg)
}

// ---------------------------------------------------------------------------
// Gate and verification

/// Recapture the reviewed scope and re-evaluate the deterministic gate.
///
/// The work-item token variable resolves as: explicit override, the variable saved
/// with the review, `hosting.token_env` in `.vee.yaml`, then `GH_TOKEN` (mapped to
/// the provider's conventional default).
/// The configuration a saved review would be evaluated under now.
pub struct CurrentReviewConfig {
    pub config: RepositoryConfig,
    /// Digest of the configuration, bound to the re-fetched work item.
    pub digest: String,
    /// The review's work item as it reads now, when the review used one.
    pub work_item: Option<vee_hosting::WorkItemSnapshot>,
}

/// A review that used a work item re-fetches it, because the configuration
/// digest binds the item's content.
pub fn current_review_config(
    workspace: &Workspace,
    store: &dyn Repositories,
    review: &ReviewResult,
    token_env_override: Option<&str>,
) -> Result<CurrentReviewConfig> {
    let config = workspace.saved_review_config(review)?;
    let current_work_item = match review.work_item.as_ref() {
        None => None,
        Some(_) if config.offline => {
            return Err(configuration_failure(
                "offline mode prevents revalidating the work item used by this review",
            ))
        }
        Some(item) => {
            let configured = token_env_override
                .or(review.work_item_token_env.as_deref())
                .or(config.hosting.token_env.as_deref())
                .unwrap_or("GH_TOKEN");
            let token_env =
                crate::work_items::effective_work_item_token_env(&item.provider, configured);
            let token = std::env::var(token_env).with_context(|| {
                format!("{token_env} is required to revalidate the external work item used by this review")
            })?;
            Some(crate::work_items::get_work_item(
                &item.provider,
                &item.api_base,
                token,
                &item.reference,
            )?)
        }
    };
    let active_approvals = crate::active_rule_approvals(store).map_err(anyhow::Error::msg)?;
    let digest = crate::effective_review_config_digest_with_work_item(
        &config,
        workspace.root(),
        &review.selected_reviewers,
        &active_approvals,
        current_work_item.as_ref(),
    )
    .map_err(anyhow::Error::msg)?;
    Ok(CurrentReviewConfig {
        config,
        digest,
        work_item: current_work_item,
    })
}

/// A saved review's gate, re-evaluated against the current source,
/// configuration and verification evidence, and persisted.
pub struct GateReevaluation {
    pub review: ReviewResult,
    pub current: vee_core::ChangeSet,
    pub decision: vee_core::GateDecision,
}

/// The gate for a saved review as of now (current snapshot, configuration,
/// and verification runs), without recording a decision.
fn current_gate(workspace: &Workspace, review: &ReviewResult) -> Result<vee_core::GateDecision> {
    let store = workspace.store()?;
    let current = crate::capture_current_change_set(workspace.root(), &review.change_set)
        .map_err(anyhow::Error::msg)?;
    let CurrentReviewConfig {
        config,
        digest: config_digest,
        ..
    } = current_review_config(workspace, &*store, review, None)?;
    let verification_runs = store
        .verifications_for_snapshot(&current.digest)
        .map_err(anyhow::Error::msg)?;
    crate::evaluate_gate(
        &*store,
        crate::GateEvaluation {
            review_id: &review.review_id,
            reviewed_snapshot_id: &review.snapshot_id,
            current: &current,
            repository_root: workspace.root(),
            reviewed_config_digest: &review.effective_config_digest,
            effective_config_digest: &config_digest,
            config: &config,
            findings: &review.findings,
            policy_findings: review.policy_findings.as_deref(),
            reviewer_outcomes: &review.reviewer_outcomes,
            analysis_complete: review.analysis_complete,
            verification_runs: &verification_runs,
        },
    )
    .map_err(anyhow::Error::msg)
}

pub fn reevaluate_gate(
    workspace: &Workspace,
    review_id: &str,
    token_env_override: Option<&str>,
) -> Result<GateReevaluation> {
    let mut store = workspace.store()?;
    let review = workspace.saved_review(&*store, review_id)?;
    let current = crate::capture_current_change_set(workspace.root(), &review.change_set)
        .map_err(anyhow::Error::msg)?;
    let CurrentReviewConfig {
        config,
        digest: config_digest,
        ..
    } = current_review_config(workspace, &*store, &review, token_env_override)?;
    let verification_runs = store
        .verifications_for_snapshot(&current.digest)
        .map_err(anyhow::Error::msg)?;
    let decision = crate::evaluate_and_persist_gate(
        &mut *store,
        crate::GateEvaluation {
            review_id,
            reviewed_snapshot_id: &review.snapshot_id,
            current: &current,
            repository_root: workspace.root(),
            reviewed_config_digest: &review.effective_config_digest,
            effective_config_digest: &config_digest,
            config: &config,
            findings: &review.findings,
            policy_findings: review.policy_findings.as_deref(),
            reviewer_outcomes: &review.reviewer_outcomes,
            analysis_complete: review.analysis_complete,
            verification_runs: &verification_runs,
        },
    )
    .map_err(anyhow::Error::msg)?;
    Ok(GateReevaluation {
        review,
        current,
        decision,
    })
}

pub fn gate_check(
    workspace: &Workspace,
    review_id: &str,
    token_env_override: Option<&str>,
) -> Result<GateCheckResult> {
    let reevaluated = reevaluate_gate(workspace, review_id, token_env_override)?;
    Ok(GateCheckResult::from_decision(
        review_id.to_owned(),
        reevaluated.review.snapshot_id,
        reevaluated.current.digest,
        reevaluated.decision,
    ))
}

pub enum VerifyTarget {
    /// The exact snapshot a finding was reported on; fails if the source changed.
    Finding(String),
    /// A freshly captured change scope.
    Scope(ScopeRequest),
}

pub struct VerifyRequest<'a> {
    pub target: VerifyTarget,
    pub profile_id: &'a str,
    /// Expand impacted-test placeholders in the profile (scope verification only).
    pub impacted_tests: bool,
}

/// A verification run with, for a SARIF analyzer profile, the report the
/// gate evaluates. It serializes as the run alone (`verification-run-v1`);
/// the report only informs the view, since an analyzer's non-zero exit is how
/// it reports results, not a failure of the check.
#[derive(Clone, Debug)]
pub struct VerificationResult {
    pub run: VerificationRun,
    pub analyzer: Option<vee_core::AnalyzerReport>,
}

impl serde::Serialize for VerificationResult {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        self.run.serialize(serializer)
    }
}

pub fn verify(workspace: &Workspace, request: VerifyRequest<'_>) -> Result<VerificationResult> {
    let config = workspace.effective_config(None)?;
    let run = run_verify(workspace, &config, request)?;
    let analyzer = if config
        .verification
        .get(&run.profile_id)
        .is_some_and(|profile| profile.sarif.is_some())
    {
        Some(analyzer_report_for(workspace, &run)?)
    } else {
        None
    };
    Ok(VerificationResult { run, analyzer })
}

fn run_verify(
    workspace: &Workspace,
    config: &RepositoryConfig,
    request: VerifyRequest<'_>,
) -> Result<VerificationRun> {
    let mut store = workspace.store()?;
    let root = workspace.root();
    match request.target {
        VerifyTarget::Finding(finding_id) => {
            if request.impacted_tests {
                return Err(usage_failure(
                    "impacted-test expansion applies to scope verification, not a finding",
                ));
            }
            let finding = workspace.finding(&*store, &finding_id)?;
            let occurrence = finding
                .occurrences
                .last()
                .context("finding has no review occurrence")?;
            let review = workspace.saved_review(&*store, &occurrence.review_id)?;
            let current = crate::capture_current_change_set(root, &review.change_set)
                .map_err(anyhow::Error::msg)?;
            if current.digest != occurrence.snapshot_id {
                return Err(usage_failure(format!(
                    "finding {finding_id} is stale because its source snapshot changed"
                )));
            }
            crate::run_finding_verification(
                root,
                &current,
                &finding_id,
                request.profile_id,
                config,
                &mut *store,
            )
        }
        VerifyTarget::Scope(scope) => {
            let scope = scope.resolve(root)?;
            let snapshot = crate::capture_change_set(root, scope).map_err(anyhow::Error::msg)?;
            if request.impacted_tests {
                crate::run_impacted_test_verification(
                    root,
                    &snapshot,
                    request.profile_id,
                    config,
                    &mut *store,
                )
            } else {
                crate::run_verification(root, &snapshot, request.profile_id, config, &mut *store)
            }
        }
    }
    .map_err(anyhow::Error::msg)
}

pub fn diagnose_verification(
    workspace: &Workspace,
    run_id: &str,
) -> Result<crate::verification_diagnosis::VerificationDiagnosis> {
    let store = workspace.store()?;
    let run = store
        .verification(run_id)
        .map_err(anyhow::Error::msg)?
        .ok_or_else(|| usage_failure(format!("verification run {run_id} was not found")))?;
    crate::verification_diagnosis::diagnose(workspace.root(), &*store, &run)
        .map_err(anyhow::Error::msg)
}

fn saved_verification(store: &dyn Repositories, run_id: &str) -> Result<VerificationRun> {
    store
        .verification(run_id)
        .map_err(anyhow::Error::msg)?
        .with_context(|| format!("verification run {run_id} was not found"))
}

/// `vee verification show`: one saved verification run.
pub fn verification_show(workspace: &Workspace, run_id: &str) -> Result<VerificationRun> {
    saved_verification(workspace.store()?.as_ref(), run_id)
}

/// `vee verification coverage`: changed-file coverage from a run's LCOV `stream`
/// (`stdout` or `stderr`).
pub fn verification_coverage(
    workspace: &Workspace,
    run_id: &str,
    stream: &str,
) -> Result<crate::coverage::CoverageReport> {
    let store = workspace.store()?;
    let run = saved_verification(store.as_ref(), run_id)?;
    crate::coverage::report(workspace.root(), store.as_ref(), &run, stream)
        .map_err(anyhow::Error::msg)
}

// ---------------------------------------------------------------------------
// Impact, acceptance, standards, analytics

/// The change an analysis runs on.
pub enum ChangeTarget {
    /// The immutable snapshot of a saved review; fails if the source changed.
    Review(String),
    /// A freshly captured change scope.
    Scope(ScopeRequest),
}

impl ChangeTarget {
    fn change_set(self, workspace: &Workspace) -> Result<vee_core::ChangeSet> {
        match self {
            Self::Review(review_id) => {
                let store = workspace.store()?;
                let review = workspace.saved_review(&*store, &review_id)?;
                workspace.current_snapshot_of(&review)
            }
            Self::Scope(scope) => {
                let scope = scope.resolve(workspace.root())?;
                crate::capture_change_set(workspace.root(), scope).map_err(anyhow::Error::msg)
            }
        }
    }
}

pub fn impact(workspace: &Workspace, target: ChangeTarget) -> Result<crate::ImpactAssessment> {
    let change_set = target.change_set(workspace)?;
    crate::analyze_impact(workspace.root(), &change_set).map_err(anyhow::Error::msg)
}

/// `approval-eligibility-v1`: whether a saved review's change may be approved
/// without a human, with every guard stage and its reason.
pub fn approval_eligibility(
    workspace: &Workspace,
    review_id: &str,
) -> Result<crate::ApprovalEligibility> {
    let config = crate::load_repository_config(workspace.root()).map_err(configuration_failure)?;
    let (mut detail, current) = review_detail_and_currency(workspace, review_id)?;
    if let Ok(gate) = current_gate(workspace, &detail.review) {
        detail.review.gate = gate;
    }
    Ok(crate::evaluate_approval(
        workspace.root(),
        &config.approval,
        &detail.review,
        current,
        detail.risk.as_ref(),
    ))
}

/// `review-session-v1`: several saved reviews read together, each with its
/// own gate, risk, open findings, and approval eligibility.
pub fn review_session(
    workspace: &Workspace,
    references: &[String],
    paths: RepositoryPaths,
) -> Result<crate::ReviewSession> {
    if references.is_empty() || references.len() > crate::MAX_SESSION_REVIEWS {
        return Err(usage_failure(format!(
            "a review session combines 1 to {} reviews",
            crate::MAX_SESSION_REVIEWS
        )));
    }
    // Resolve every reference before reading any review, so a bad path or a
    // repeat fails the whole request.
    let mut resolved = Vec::with_capacity(references.len());
    let mut seen = std::collections::HashSet::new();
    for reference in references {
        let (repository, review_id) = match reference.rsplit_once(':') {
            Some((repository, review_id)) => (Some(repository), review_id),
            None => (None, reference.as_str()),
        };
        if review_id.is_empty() {
            return Err(usage_failure(format!(
                "review reference `{reference}` has no review ID"
            )));
        }
        let root = match repository {
            Some(path) => resolve_repository_path(workspace.root(), path, paths)?,
            None => workspace.root().to_path_buf(),
        };
        // A repeated review would be counted twice in the session totals.
        let identity = (
            vee_core::paths::CanonicalPath::canonical(root.as_path())?,
            review_id.to_owned(),
        );
        if !seen.insert(identity) {
            return Err(usage_failure(format!(
                "review {reference} is listed more than once"
            )));
        }
        resolved.push((repository.map(str::to_owned), root, review_id.to_owned()));
    }
    let mut lines = Vec::with_capacity(resolved.len());
    for (repository, root, review_id) in resolved {
        // Each change is read from its own repository: its store, its
        // configuration, and its approval guards.
        let workspace = Workspace::new(root, workspace.stores.clone());
        let workspace = &workspace;
        let config =
            crate::load_repository_config(workspace.root()).map_err(configuration_failure)?;
        let (mut detail, current) = review_detail_and_currency(workspace, &review_id)?;
        // Without the inputs to re-evaluate (for example a work item whose
        // token is not set), the last recorded decision stands.
        if let Ok(gate) = current_gate(workspace, &detail.review) {
            detail.review.gate = gate;
        }
        let approval = crate::evaluate_approval(
            workspace.root(),
            &config.approval,
            &detail.review,
            current,
            detail.risk.as_ref(),
        );
        let mut line = crate::session_review(
            &detail.review,
            &detail.findings,
            detail.risk.as_ref(),
            &approval,
        );
        line.repository = repository;
        lines.push(line);
    }
    Ok(crate::review_session(lines))
}

/// How a transport may name another repository's checkout. Paths are always
/// relative to this repository's root; MCP keeps them beneath it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RepositoryPaths {
    /// Any checkout the local user names, such as a sibling `../api`.
    Relative,
    /// Only checkouts beneath this repository's root, without `.` or `..`.
    Confined,
}

/// Resolve a repository path to the root of a Git checkout.
fn resolve_repository_path(root: &Path, path: &str, paths: RepositoryPaths) -> Result<PathBuf> {
    match paths {
        RepositoryPaths::Confined => confine_repository_path(root, path, "repository"),
        RepositoryPaths::Relative => {
            use vee_core::paths::CanonicalPath as _;
            let relative = Path::new(path);
            if path.is_empty() || relative.is_absolute() {
                return Err(usage_failure(format!(
                    "repository path `{path}` must be relative to this repository's root"
                )));
            }
            let resolved = root.join(relative).canonical().map_err(|error| {
                usage_failure(format!("cannot resolve repository path `{path}`: {error}"))
            })?;
            ensure_checkout_root(&resolved, path, "repository")?;
            Ok(resolved)
        }
    }
}

/// Fails unless `resolved` is a directory at the root of a Git checkout.
fn ensure_checkout_root(resolved: &Path, path: &str, kind: &str) -> Result<()> {
    use vee_core::paths::CanonicalPath as _;
    if !resolved.is_dir() {
        return Err(usage_failure(format!(
            "{kind} path `{path}` is not a directory"
        )));
    }
    let git_root = vee_git::repository_root(resolved).map_err(anyhow::Error::msg)?;
    if git_root.canonical()? != resolved {
        return Err(usage_failure(format!(
            "{kind} path `{path}` must name a Git checkout root"
        )));
    }
    Ok(())
}

/// `change-risk-v1`: the change's risk tier with every measured factor.
pub fn change_risk(workspace: &Workspace, target: ChangeTarget) -> Result<crate::ChangeRisk> {
    let change_set = target.change_set(workspace)?;
    let impact =
        crate::analyze_impact(workspace.root(), &change_set).map_err(anyhow::Error::msg)?;
    crate::assess_change_risk(workspace.root(), &change_set, &impact).map_err(anyhow::Error::msg)
}

/// Trace saved work-item criteria to the review's changes. Impact candidates are
/// included only when the live source still matches the review; otherwise the report
/// records why they are missing.
pub fn acceptance_report(
    workspace: &Workspace,
    review_id: &str,
) -> Result<crate::acceptance::AcceptanceReport> {
    let store = workspace.store()?;
    let review = workspace.saved_review(&*store, review_id)?;
    let (impact, impact_problem) = crate::acceptance::matching_impact(
        &review.snapshot_id,
        crate::analyze_impact(workspace.root(), &review.change_set),
    );
    Ok(crate::acceptance::report_with_impact(
        &review,
        impact.as_ref(),
        impact_problem.as_deref(),
    ))
}

/// Largest acceptance mapping file `acceptance_validate` reads.
const MAX_ACCEPTANCE_MAPPING_BYTES: u64 = 1_048_576;

/// `vee acceptance validate`: check a human-authored acceptance mapping against
/// a saved review and the repository's acceptance policy.
pub fn acceptance_validate(
    workspace: &Workspace,
    review_id: &str,
    mapping: &Path,
) -> Result<crate::acceptance::AcceptanceValidation> {
    let store = workspace.store()?;
    let review = workspace.saved_review(&*store, review_id)?;
    let config = workspace.saved_review_config(&review)?;
    let metadata = std::fs::symlink_metadata(mapping)
        .map_err(|error| configuration_failure(format!("cannot read mapping file: {error}")))?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_ACCEPTANCE_MAPPING_BYTES {
        return Err(configuration_failure(
            "mapping must be a regular file no larger than 1 MiB",
        ));
    }
    let contents = std::fs::read(mapping)
        .map_err(|error| configuration_failure(format!("cannot read mapping file: {error}")))?;
    let mapping: crate::acceptance::AcceptanceMapping = serde_json::from_slice(&contents)
        .map_err(|error| configuration_failure(format!("invalid acceptance mapping: {error}")))?;
    crate::acceptance::validate_mapping(&review, &mapping, &config.policy.acceptance)
        .map_err(configuration_failure)
}

pub fn applicable_standards(
    workspace: &Workspace,
    path: Option<&Path>,
) -> Result<crate::standards::StandardsReport> {
    crate::standards::resolve(workspace.root(), path).map_err(configuration_failure)
}

pub fn quality_analytics(workspace: &Workspace) -> Result<crate::analytics::QualityAnalytics> {
    let store = workspace.store()?;
    crate::analytics::summarize(workspace.root(), &*store).map_err(anyhow::Error::msg)
}

// ---------------------------------------------------------------------------
// Repository context

/// Largest source read `repository_context` returns, and its default.
pub const MAX_REPOSITORY_CONTEXT_BYTES: usize = 32 * 1024;

/// A bounded source read from a saved review's immutable snapshot.
pub struct RepositoryContextRequest<'a> {
    pub review_id: &'a str,
    /// Repository-relative file path.
    pub path: &'a str,
    /// Report the line numbers containing this text.
    pub symbol: Option<&'a str>,
    /// Bytes to return, clamped to 1..=[`MAX_REPOSITORY_CONTEXT_BYTES`].
    pub max_bytes: Option<usize>,
}

/// Source text from a review snapshot, labeled as untrusted repository content.
#[derive(Debug, Serialize, Deserialize)]
pub struct RepositoryContext {
    pub schema_version: u32,
    pub path: String,
    pub snapshot_id: String,
    pub content_digest: String,
    pub returned_bytes: usize,
    pub total_bytes: usize,
    pub matching_line_count: usize,
    /// The returned bytes as text, or `None` when they are not valid UTF-8.
    pub content: Option<String>,
    /// One-based line numbers containing the requested symbol.
    pub matching_lines: Vec<usize>,
    pub truncated: bool,
    pub classification: String,
    pub note: Option<String>,
}

pub fn repository_context(
    workspace: &Workspace,
    request: RepositoryContextRequest<'_>,
) -> Result<RepositoryContext> {
    let review = get_review(workspace, request.review_id)?;
    let relative = PathBuf::from(request.path);
    if relative.components().any(|component| {
        matches!(component, std::path::Component::Normal(name) if name == ".git" || name == ".vee")
    }) {
        return Err(usage_failure(
            "repository metadata paths are not available through this tool",
        ));
    }
    let bytes = vee_git::read_snapshot_tree_file(workspace.root(), &review.change_set, &relative)
        .map_err(anyhow::Error::msg)?
        .ok_or_else(|| usage_failure(format!("repository path {} was not found", request.path)))?;
    let limit = request
        .max_bytes
        .unwrap_or(MAX_REPOSITORY_CONTEXT_BYTES)
        .clamp(1, MAX_REPOSITORY_CONTEXT_BYTES);
    let truncated = bytes.len() > limit;
    let visible = &bytes[..bytes.len().min(limit)];
    let (content, note, matching_lines) = match std::str::from_utf8(visible) {
        Ok(text) => {
            let matching_lines = request
                .symbol
                .map(|symbol| {
                    text.lines()
                        .enumerate()
                        .filter_map(|(index, line)| line.contains(symbol).then_some(index + 1))
                        .collect()
                })
                .unwrap_or_default();
            (Some(text.to_owned()), None, matching_lines)
        }
        Err(_) => (
            None,
            Some("file is binary or contains non-UTF8 bytes".into()),
            Vec::new(),
        ),
    };
    Ok(RepositoryContext {
        schema_version: 2,
        path: request.path.to_owned(),
        snapshot_id: review.snapshot_id,
        content_digest: vee_core::digest(&bytes),
        returned_bytes: visible.len(),
        total_bytes: bytes.len(),
        matching_line_count: matching_lines.len(),
        content,
        matching_lines,
        truncated,
        classification: "untrusted_repository_source".into(),
        note,
    })
}

// ---------------------------------------------------------------------------
// Review records

/// The formats `vee reviews export` writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReviewExportFormat {
    /// A SARIF 2.1.0 log of the review's findings.
    Sarif,
    /// The portable Vee review document (`review-output-v2`).
    VeeJson,
}

/// `vee reviews export`: a saved review as an exchange payload. Both formats are
/// JSON values with sorted keys, written exactly as returned.
pub fn export_review(
    workspace: &Workspace,
    review_id: &str,
    format: ReviewExportFormat,
) -> Result<serde_json::Value> {
    let payload = workspace
        .store()?
        .get(review_id)
        .map_err(anyhow::Error::msg)?
        .with_context(|| format!("review {review_id} was not found"))?;
    let review = crate::deserialize_review_result(&payload).map_err(anyhow::Error::msg)?;
    Ok(match format {
        ReviewExportFormat::Sarif => crate::sarif::review_log(&review),
        ReviewExportFormat::VeeJson => serde_json::to_value(&review)?,
    })
}

// ---------------------------------------------------------------------------
// Imported review history

pub fn search_imported_history(
    workspace: &Workspace,
    query: &str,
    limit: usize,
) -> Result<crate::imported_history::ImportedHistorySearch> {
    crate::imported_history::search(workspace.root(), query, limit).map_err(configuration_failure)
}

/// Envelope for a recorded human label on an imported provider comment.
#[derive(Debug, Serialize, Deserialize)]
pub struct ExternalFeedbackRecorded {
    pub schema_version: u32,
    pub feedback: crate::imported_history::ExternalReviewFeedback,
    pub trust: String,
    pub gate_eligible: bool,
}

pub struct ExternalFeedbackRequest<'a> {
    pub archive_digest: &'a str,
    pub external_id: &'a str,
    pub category: &'a str,
    pub label: FindingFeedbackLabel,
    pub reason: &'a str,
    pub reviewer: &'a str,
}

pub fn record_external_feedback(
    workspace: &Workspace,
    request: ExternalFeedbackRequest<'_>,
) -> Result<ExternalFeedbackRecorded> {
    Reason::new(request.reason).map_err(usage_failure)?;
    ActorName::new("reviewer", request.reviewer).map_err(usage_failure)?;
    let feedback = crate::imported_history::record_feedback(
        workspace.root(),
        crate::imported_history::FeedbackRecordInput {
            archive_digest: request.archive_digest,
            external_id: request.external_id,
            category: request.category,
            label: request.label,
            reason: request.reason,
            reviewer: request.reviewer,
            recorded_at_unix: crate::current_unix_time().map_err(anyhow::Error::msg)?,
        },
    )
    .map_err(configuration_failure)?;
    Ok(ExternalFeedbackRecorded {
        schema_version: 1,
        feedback,
        trust: "human_labeled_external_context".into(),
        gate_eligible: false,
    })
}

/// Envelope for listed human labels on imported provider comments.
#[derive(Debug, Serialize, Deserialize)]
pub struct ExternalFeedbackList {
    pub schema_version: u32,
    pub feedback: Vec<crate::imported_history::ExternalReviewFeedback>,
    pub gate_eligible: bool,
}

pub fn list_external_feedback(
    workspace: &Workspace,
    archive_digest: Option<&str>,
) -> Result<ExternalFeedbackList> {
    let feedback = crate::imported_history::list_feedback(workspace.root(), archive_digest)
        .map_err(configuration_failure)?;
    Ok(ExternalFeedbackList {
        schema_version: 1,
        feedback,
        gate_eligible: false,
    })
}

// ---------------------------------------------------------------------------
// Rule candidates and approvals

fn mine_candidates(
    workspace: &Workspace,
    store: Option<&dyn Repositories>,
) -> Result<crate::rule_candidates::CandidateReport> {
    let external_feedback = crate::imported_history::list_feedback(workspace.root(), None)
        .map_err(configuration_failure)?;
    let Some(store) = store else {
        return Ok(crate::rule_candidates::mine_with_external(
            &[],
            &[],
            &external_feedback,
            false,
        ));
    };
    let (records, total) = store
        .list_findings_page(None, None, None, RULE_MINING_FINDING_LIMIT, 0)
        .map_err(anyhow::Error::msg)?;
    let feedback = store.list_finding_feedback().map_err(anyhow::Error::msg)?;
    Ok(crate::rule_candidates::mine_with_external(
        &records,
        &feedback,
        &external_feedback,
        total > records.len(),
    ))
}

pub fn rule_candidates(workspace: &Workspace) -> Result<crate::rule_candidates::CandidateReport> {
    let store = workspace.existing_store()?;
    mine_candidates(workspace, store.as_deref())
}

pub struct ApproveRuleRequest {
    pub candidate_id: String,
    pub evidence_digest: String,
    pub scope: String,
    pub instruction: String,
    pub approver: String,
    pub reason: String,
    pub supersedes_approval_id: Option<String>,
    pub expires_in_days: Option<u32>,
}

pub fn approve_rule(
    workspace: &Workspace,
    request: ApproveRuleRequest,
) -> Result<vee_core::RuleApproval> {
    require_text("scope", &request.scope, MAX_SCOPE_CHARS)?;
    let approver = ActorName::new("approver", &request.approver).map_err(usage_failure)?;
    let reason = Reason::new(&request.reason).map_err(usage_failure)?;
    if request.instruction.trim().is_empty() || request.instruction.len() > MAX_INSTRUCTION_BYTES {
        return Err(usage_failure(format!(
            "instruction must contain 1 to {MAX_INSTRUCTION_BYTES} bytes"
        )));
    }
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
    let expires_at_unix = match request.expires_in_days {
        None => None,
        Some(days) if (1..=3650).contains(&days) => {
            Some(i64::try_from(now.as_secs())? + i64::from(days) * 86_400)
        }
        Some(_) => return Err(usage_failure("expires_in_days must be between 1 and 3650")),
    };
    let mut store = workspace.store()?;
    let report = mine_candidates(workspace, Some(&*store))?;
    if report.truncated {
        return Err(configuration_failure(
            "cannot approve candidates while feedback history is truncated",
        ));
    }
    let candidate = report
        .candidates
        .iter()
        .find(|candidate| candidate.candidate_id == request.candidate_id)
        .ok_or_else(|| {
            usage_failure(
                "candidate is missing, stale, disputed, or does not meet the evidence threshold",
            )
        })?;
    if candidate.evidence_digest != request.evidence_digest {
        return Err(usage_failure(
            "candidate evidence changed; retrieve the current candidates and approve their current evidence digest",
        ));
    }
    let approval_id = format!(
        "rule-approval:{}",
        vee_core::digest(
            format!(
                "{}\0{}\0{}\0{}",
                request.candidate_id,
                candidate.evidence_digest,
                approver.as_str(),
                now.as_nanos()
            )
            .as_bytes()
        )
    );
    let approval = vee_core::RuleApproval {
        schema_version: 2,
        approval_id,
        version: 1,
        candidate_id: request.candidate_id,
        evidence_digest: request.evidence_digest,
        source_feedback_ids: candidate.feedback_ids.clone(),
        activated_at_unix: None,
        category: candidate.category.clone(),
        feedback_label: candidate.feedback_label,
        scope: request.scope,
        instruction: request.instruction,
        approver: approver.as_str().to_owned(),
        approval_reason: reason.as_str().to_owned(),
        supersedes_approval_id: request.supersedes_approval_id,
        expires_at_unix,
        created_at: String::new(),
        status: vee_core::RuleApprovalStatus::Active,
        events: Vec::new(),
    };
    store
        .create_rule_approval(&approval)
        .map_err(anyhow::Error::msg)?;
    saved_approval(&*store, &approval.approval_id)
}

fn saved_approval(store: &dyn Repositories, approval_id: &str) -> Result<vee_core::RuleApproval> {
    store
        .list_rule_approvals()
        .map_err(anyhow::Error::msg)?
        .into_iter()
        .find(|item| item.approval_id == approval_id)
        .ok_or_else(|| anyhow::anyhow!("approval {approval_id} could not be read back"))
}

/// Every saved rule guidance approval, in creation order.
#[derive(Debug, Serialize, Deserialize)]
pub struct RuleApprovalList {
    pub schema_version: u32,
    pub approvals: Vec<vee_core::RuleApproval>,
}

pub fn list_rule_approvals(workspace: &Workspace) -> Result<RuleApprovalList> {
    let approvals = match workspace.existing_store()? {
        Some(store) => store.list_rule_approvals().map_err(anyhow::Error::msg)?,
        None => Vec::new(),
    };
    Ok(RuleApprovalList {
        schema_version: 1,
        approvals,
    })
}

pub fn revoke_rule(
    workspace: &Workspace,
    approval_id: &str,
    actor: &str,
    reason: &str,
) -> Result<vee_core::RuleApproval> {
    let actor = ActorName::new("actor", actor).map_err(usage_failure)?;
    let reason = Reason::new(reason).map_err(usage_failure)?;
    let mut store = workspace.store()?;
    store
        .revoke_rule_approval(approval_id, &actor, &reason)
        .map_err(anyhow::Error::msg)?;
    saved_approval(&*store, approval_id)
}

pub fn rule_effectiveness(
    workspace: &Workspace,
    approval_id: Option<&str>,
) -> Result<crate::rule_candidates::RuleEffectivenessReport> {
    let Some(store) = workspace.existing_store()? else {
        return Err(configuration_failure(
            "no saved rule approvals or finding feedback are available",
        ));
    };
    let external_feedback = crate::imported_history::list_feedback(workspace.root(), None)
        .map_err(configuration_failure)?;
    crate::rule_candidates::effectiveness(&*store, approval_id, &external_feedback)
        .map_err(anyhow::Error::msg)
}

// ---------------------------------------------------------------------------
// Setup: provider detection, init, doctor

fn user_config_location() -> Result<PathBuf> {
    crate::user_config_location().ok_or_else(|| {
        configuration_failure("cannot determine the user config location; set VEE_CONFIG")
    })
}

/// AI backends available on this machine, in preference order.
pub fn detect_providers() -> crate::setup::DetectionReport {
    crate::setup::detect(&crate::setup::LocalSystem)
}

/// Whether the repository's configured reviewers can run on this machine.
pub fn doctor(workspace: &Workspace) -> Result<crate::setup::DoctorReport> {
    let user_config = user_config_location().ok();
    Ok(crate::setup::doctor(
        &crate::setup::LocalSystem,
        workspace.root(),
        user_config.as_deref(),
    ))
}

/// Create a reviewer setup from the detected backends, or configure this machine
/// for a repository that already has one.
/// This machine's configured provider and review effort, for guided setup.
pub fn machine_setup() -> Result<crate::setup::MachineSetup> {
    crate::setup::machine_setup(&user_config_location()?).map_err(configuration_failure)
}

pub fn init(
    workspace: &Workspace,
    candidate_id: Option<&str>,
    model: Option<&str>,
    effort: Option<vee_core::ReviewEffort>,
) -> Result<crate::setup::InitReport> {
    let user_config = user_config_location()?;
    crate::setup::init(
        &crate::setup::LocalSystem,
        workspace.root(),
        &user_config,
        crate::setup::InitRequest {
            candidate_id,
            model,
            effort,
        },
    )
    .map_err(|error| match error {
        crate::setup::InitError::Usage(message) => usage_failure(message),
        crate::setup::InitError::Configuration(message) => configuration_failure(message),
    })
}

// ---------------------------------------------------------------------------
// Agent workflow: tests, PR drafts, ownership, waivers, gate history, patches

/// Recommend missing tests for a change, optionally informed by LCOV coverage
/// from a verification run on the same snapshot.
pub fn recommend_tests(
    workspace: &Workspace,
    target: ChangeTarget,
    coverage_run_id: Option<&str>,
) -> Result<crate::test_recommendations::TestRecommendationReport> {
    use crate::test_recommendations::{ExecutionCoverageFile, ExecutionCoverageSummary};
    let change_set = target.change_set(workspace)?;
    let impact =
        crate::analyze_impact(workspace.root(), &change_set).map_err(anyhow::Error::msg)?;
    let coverage = match coverage_run_id {
        None => None,
        Some(run_id) => {
            let store = workspace.store()?;
            let run = store
                .verification(run_id)
                .map_err(anyhow::Error::msg)?
                .ok_or_else(|| usage_failure(format!("verification run {run_id} was not found")))?;
            if run.snapshot_id != change_set.digest {
                return Err(usage_failure(
                    "coverage verification run belongs to a different change snapshot",
                ));
            }
            let report = crate::coverage::report(workspace.root(), &*store, &run, "stdout")
                .map_err(anyhow::Error::msg)?;
            let files = report
                .files
                .into_iter()
                .map(|file| {
                    let signal = if file.executable_lines == 0 {
                        "no_executable_lines"
                    } else if file.covered_lines == 0 {
                        "zero_covered_lines"
                    } else if file.covered_lines == file.executable_lines {
                        "all_reported_lines_covered"
                    } else {
                        "partial_file_coverage"
                    };
                    ExecutionCoverageFile {
                        path: file.path,
                        covered_lines: file.covered_lines,
                        executable_lines: file.executable_lines,
                        percent: file.percent,
                        changed_line_count: file.changed_line_count,
                        changed_executable_lines: file.changed_executable_lines,
                        changed_covered_lines: file.changed_covered_lines,
                        changed_percent: file.changed_percent,
                        signal: signal.to_owned(),
                    }
                })
                .collect();
            Some(ExecutionCoverageSummary {
                run_id: report.run_id,
                profile_id: report.profile_id,
                status: format!("{:?}", run.status).to_lowercase(),
                files,
                limitations: report.limitations,
            })
        }
    };
    Ok(crate::test_recommendations::recommend_with_coverage(
        &impact, coverage,
    ))
}

/// Draft a pull request title and body with a configured reviewer. The draft is
/// digest-bound to the snapshot and never used by a gate.
pub fn draft_pr_description(
    workspace: &Workspace,
    target: ChangeTarget,
    reviewer_id: &str,
) -> Result<crate::ProviderTaskResult> {
    let change_set = target.change_set(workspace)?;
    let config = workspace.effective_config(None)?;
    let context = crate::pr_description::snapshot_context(
        workspace.root(),
        &change_set,
        config.review.max_context_files,
        config.review.max_context_file_bytes,
        config.review.max_context_bytes,
    )?;
    crate::run_provider_task(
        crate::ProviderTaskRequest {
            root: workspace.root(),
            snapshot_id: &change_set.digest,
            config: &config,
            reviewer_id,
            task_instructions: crate::pr_description::INSTRUCTIONS,
            context,
            output_schema: crate::pr_description::output_schema(),
        },
        &crate::CliReviewProvider,
    )
    .map_err(anyhow::Error::msg)
}

pub fn owners(
    workspace: &Workspace,
    paths: &[PathBuf],
) -> Result<crate::ownership::OwnershipReport> {
    crate::ownership::analyze(workspace.root(), paths).map_err(usage_failure)
}

/// `gate-history-v1`
#[derive(Debug, Serialize, Deserialize)]
pub struct GateHistory {
    pub schema_version: u32,
    pub decisions: Vec<vee_core::GateDecision>,
}

pub fn gate_history(workspace: &Workspace, review_id: &str) -> Result<GateHistory> {
    let store = workspace.store()?;
    workspace.saved_review(&*store, review_id)?;
    let decisions = store
        .gate_decisions_for_review(review_id)
        .map_err(anyhow::Error::msg)?;
    Ok(GateHistory {
        schema_version: 1,
        decisions,
    })
}

/// `waivers-list-v1`
#[derive(Debug, Serialize, Deserialize)]
pub struct WaiverList {
    pub schema_version: u32,
    pub waivers: Vec<vee_core::Waiver>,
}

pub fn list_waivers(workspace: &Workspace, review_id: &str) -> Result<WaiverList> {
    let store = workspace.store()?;
    let review = workspace.saved_review(&*store, review_id)?;
    let waivers = store
        .waivers_for_snapshot(&review.snapshot_id)
        .map_err(anyhow::Error::msg)?;
    Ok(WaiverList {
        schema_version: 1,
        waivers,
    })
}

/// What a person supplies to waive one finding of a saved review.
pub struct WaiverRequest<'a> {
    pub review_id: &'a str,
    pub finding_id: &'a str,
    pub reason: &'a str,
    pub author: &'a str,
    pub expires_in_days: u32,
}

/// Record a waiver for one finding fingerprint in the review's immutable snapshot.
/// The finding may be a reviewer finding or one reported by a deterministic analyzer
/// that the review's gate evaluated. Waivers expire; they are never open-ended.
pub fn create_waiver(
    workspace: &Workspace,
    request: &WaiverRequest<'_>,
) -> Result<vee_core::Waiver> {
    if request.expires_in_days == 0 {
        return Err(usage_failure("--expires-in-days must be positive"));
    }
    let mut store = workspace.store()?;
    let review = workspace.saved_review(&*store, request.review_id)?;
    let fingerprint = match review
        .findings
        .iter()
        .find(|finding| finding.id == request.finding_id)
    {
        Some(finding) => finding.fingerprint.clone(),
        None => analyzer_finding_fingerprint(&*store, &review, request.finding_id)?.ok_or_else(
            || {
                usage_failure(format!(
                    "finding {} was not observed in review {}",
                    request.finding_id, request.review_id
                ))
            },
        )?,
    };
    let created_at_unix = crate::current_unix_time().map_err(anyhow::Error::msg)?;
    let expires_at_unix = created_at_unix
        .checked_add(i64::from(request.expires_in_days) * 86_400)
        .context("waiver expiry exceeds supported timestamp")?;
    record_waiver(
        &mut *store,
        RecordedWaiver {
            fingerprint,
            snapshot_id: review.snapshot_id,
            reason: request.reason,
            author: request.author,
            provenance: "local_cli",
            created_at_unix,
            expires_at_unix,
        },
    )
}

/// A waiver whose finding, snapshot and times are already settled.
pub(crate) struct RecordedWaiver<'a> {
    pub fingerprint: String,
    pub snapshot_id: String,
    pub reason: &'a str,
    pub author: &'a str,
    /// Where the waiver came from: `local_cli` or `pull_request_command`.
    pub provenance: &'a str,
    pub created_at_unix: i64,
    pub expires_at_unix: i64,
}

pub(crate) fn record_waiver(
    store: &mut dyn Repositories,
    recorded: RecordedWaiver<'_>,
) -> Result<vee_core::Waiver> {
    let reason = vee_core::Reason::new(recorded.reason).map_err(usage_failure)?;
    let author = vee_core::ActorName::new("author", recorded.author).map_err(usage_failure)?;
    let (created_at_unix, expires_at_unix) = (recorded.created_at_unix, recorded.expires_at_unix);
    let fingerprint = recorded.fingerprint;
    let id = format!(
        "waiver_{}",
        &vee_core::digest(&serde_json::to_vec(&(
            fingerprint.as_str(),
            recorded.snapshot_id.as_str(),
            reason.as_str(),
            author.as_str(),
            created_at_unix,
            expires_at_unix,
        ))?)[..20]
    );
    let waiver = vee_core::Waiver {
        schema_version: 1,
        id,
        finding_fingerprint: fingerprint,
        snapshot_id: recorded.snapshot_id,
        reason: reason.as_str().to_owned(),
        author: author.as_str().to_owned(),
        provenance: recorded.provenance.into(),
        created_at_unix,
        expires_at_unix,
    };
    // The ID covers every field, so an existing one is this same waiver, as
    // when a CI run on a reused checkout applies a pull request's waivers again.
    let recorded_before = store
        .waivers_for_snapshot(&waiver.snapshot_id)
        .map_err(anyhow::Error::msg)?
        .iter()
        .any(|existing| existing.id == waiver.id);
    if !recorded_before {
        store.create_waiver(&waiver).map_err(anyhow::Error::msg)?;
    }
    Ok(waiver)
}

/// The fingerprint of an analyzer finding the review's gate evaluated for its snapshot.
fn analyzer_finding_fingerprint(
    store: &dyn Repositories,
    review: &ReviewResult,
    finding_id: &str,
) -> Result<Option<String>> {
    let decisions = store
        .gate_decisions_for_review(&review.review_id)
        .map_err(anyhow::Error::msg)?;
    Ok(std::iter::once(&review.gate)
        .chain(decisions.iter())
        .filter(|decision| decision.snapshot_id == review.snapshot_id)
        .filter_map(|decision| decision.replay_inputs.as_ref())
        .flat_map(|inputs| &inputs.analyzer_reports)
        .flat_map(|report| &report.findings)
        .find(|finding| finding.id == finding_id)
        .map(|finding| finding.fingerprint.clone()))
}

pub const MAX_PATCH_BYTES: usize = 2 * 1024 * 1024;
const MAX_PROPOSAL_RECORD_BYTES: usize = 128 * 1024;

/// Validate an agent-authored unified diff against a saved, still-current review,
/// and save it as a digest-bound proposal (`patch-proposal-v1`). No repository file
/// is changed; applying requires explicit human approval of the digest through
/// `vee findings apply-patch`.
/// The result of applying a human-approved patch proposal: the follow-up review
/// of the changed working tree, and whether the target changed while applying.
#[derive(Debug, Serialize, Deserialize)]
pub struct PatchApplication {
    pub schema_version: u32,
    pub proposal_digest: String,
    pub approved: bool,
    pub application: String,
    pub concurrent_mutation_detected: bool,
    pub review: ReviewResult,
}

/// `patch-proposal-v1` for a newly validated, unapplied patch.
#[derive(Debug, Serialize, Deserialize)]
pub struct PatchProposal {
    pub schema_version: u32,
    pub review_id: String,
    pub snapshot_id: String,
    pub effective_config_digest: String,
    pub patch_digest: String,
    pub patch_bytes: usize,
    pub patch_inputs: Vec<vee_core::SnapshotFile>,
    pub patch_input_digest: String,
    pub patch_sandbox_result_digest: String,
    pub validated: bool,
    pub application: String,
    pub approval_instruction: String,
    pub patch_path: String,
}

pub fn propose_patch(
    workspace: &Workspace,
    review_id: &str,
    patch: &[u8],
) -> Result<PatchProposal> {
    use sha2::Digest as _;
    use std::io::Write as _;
    let root = workspace.root();
    let store = workspace.store()?;
    let saved = workspace.saved_review(&*store, review_id)?;
    if !matches!(
        saved.change_set.scope.as_str(),
        "staged" | "working_tree" | "base_and_worktree"
    ) {
        return Err(usage_failure(
            "patch proposals require a mutable staged or working-tree review scope",
        ));
    }
    let current = crate::capture_current_change_set(root, &saved.change_set)
        .is_ok_and(|snapshot| snapshot.digest == saved.snapshot_id);
    if !current {
        return Err(usage_failure(
            "saved review snapshot is stale; rerun review before proposing a patch",
        ));
    }
    if patch.is_empty() || patch.len() > MAX_PATCH_BYTES {
        return Err(usage_failure(format!(
            "patch must contain 1 to {MAX_PATCH_BYTES} bytes"
        )));
    }
    let text = std::str::from_utf8(patch)
        .map_err(|_| usage_failure("patch must be a UTF-8 unified diff"))?;
    if !(text.contains("diff --git ") || text.contains("--- ")) {
        return Err(usage_failure("patch does not look like a unified diff"));
    }
    let mut check_command = std::process::Command::new("git");
    check_command
        .arg("-C")
        .arg(root)
        .args(["apply", "--check"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped());
    if saved.change_set.scope == "staged" {
        check_command.arg("--index");
    }
    let mut child = check_command
        .spawn()
        .context("could not start git apply --check")?;
    child
        .stdin
        .take()
        .context("could not open git apply input")?
        .write_all(patch)?;
    let check = child
        .wait_with_output()
        .context("could not run git apply --check")?;
    if !check.status.success() {
        return Err(usage_failure(format!(
            "patch does not apply cleanly: {}",
            String::from_utf8_lossy(&check.stderr).trim()
        )));
    }
    let sandbox = crate::patch_sandbox::validate_bytes(root, patch).map_err(anyhow::Error::msg)?;
    let input_digest =
        crate::patch_sandbox::input_digest(&sandbox.input_files).map_err(anyhow::Error::msg)?;
    let digest = format!("sha256:{:x}", sha2::Sha256::digest(patch));
    let directory = crate::proposals::proposal_directory(root)?;
    let saved_patch = directory.join(format!("{}.patch", &digest[7..]));
    let record_path = directory.join(format!("{}.json", &digest[7..]));
    let proposal = PatchProposal {
        schema_version: 1,
        review_id: review_id.to_owned(),
        snapshot_id: saved.snapshot_id.clone(),
        effective_config_digest: saved.effective_config_digest.clone(),
        approval_instruction: format!(
            "Review the diff, then apply only with explicit approval of digest {digest}."
        ),
        patch_digest: digest,
        patch_bytes: patch.len(),
        patch_inputs: sandbox.input_files,
        patch_input_digest: input_digest,
        patch_sandbox_result_digest: sandbox.result_digest,
        validated: true,
        application: "not_applied".to_owned(),
        patch_path: saved_patch.to_string_lossy().into_owned(),
    };
    // Through a Value so the record keeps its sorted keys: apply-patch reads
    // and extends it as JSON.
    let record = serde_json::to_vec_pretty(&serde_json::to_value(&proposal)?)?;
    if record.len() > MAX_PROPOSAL_RECORD_BYTES {
        return Err(usage_failure(
            "patch proposal metadata exceeds the 128 KiB apply limit",
        ));
    }
    crate::proposals::write_immutable_proposal_file(&saved_patch, patch)?;
    crate::proposals::write_immutable_proposal_file(&record_path, &record)?;
    Ok(proposal)
}

// ---------------------------------------------------------------------------
// Trusted analyzers (SARIF)

/// Results of a SARIF analyzer verification run on changed lines of its snapshot
/// (`analyzer-report-v1`), exactly as the gate evaluates them.
pub fn analyzer_findings(workspace: &Workspace, run_id: &str) -> Result<vee_core::AnalyzerReport> {
    let store = workspace.store()?;
    let run = store
        .verification(run_id)
        .map_err(anyhow::Error::msg)?
        .ok_or_else(|| usage_failure(format!("verification run {run_id} was not found")))?;
    let config = workspace.effective_config(None)?;
    let is_analyzer = config
        .verification
        .get(&run.profile_id)
        .is_some_and(|profile| profile.sarif.is_some());
    if !is_analyzer {
        return Err(usage_failure(format!(
            "verification profile {} is not configured as a SARIF analyzer",
            run.profile_id
        )));
    }
    analyzer_report_for(workspace, &run)
}

fn analyzer_report_for(
    workspace: &Workspace,
    run: &VerificationRun,
) -> Result<vee_core::AnalyzerReport> {
    let store = workspace.store()?;
    let run_id = &run.run_id;
    let manifest = store
        .snapshot_manifest(&run.snapshot_id)
        .map_err(anyhow::Error::msg)?
        .ok_or_else(|| anyhow::anyhow!("snapshot manifest for run {run_id} is missing"))?;
    let change_set =
        crate::coverage::parse_manifest(&manifest, &run.snapshot_id).map_err(anyhow::Error::msg)?;
    Ok(crate::sarif::analyze_run(
        workspace.root(),
        &change_set,
        run,
    ))
}

pub const MAX_CROSS_REPOSITORY_CONSUMERS: usize = 128;
const MAX_BASE_REF_CHARS: usize = 256;

/// Analyze changed symbols of `producer` across local consumer checkouts.
/// Input bounds apply to every transport; callers that must confine consumer
/// paths (MCP) resolve them with [`confine_consumers`] first.
pub fn cross_repository_impact(
    producer: &Path,
    base_ref: &str,
    consumers: &[PathBuf],
) -> Result<crate::repository_map::CrossRepositoryImpact> {
    if base_ref.trim().is_empty() || base_ref.chars().count() > MAX_BASE_REF_CHARS {
        return Err(usage_failure(format!(
            "base_ref must contain 1 to {MAX_BASE_REF_CHARS} characters"
        )));
    }
    if consumers.is_empty() || consumers.len() > MAX_CROSS_REPOSITORY_CONSUMERS {
        return Err(usage_failure(format!(
            "consumer repositories must number between 1 and {MAX_CROSS_REPOSITORY_CONSUMERS}"
        )));
    }
    crate::repository_map::analyze_cross_impact(producer, base_ref, consumers)
        .map_err(anyhow::Error::msg)
}

/// Resolve consumer paths relative to the workspace root, rejecting any that
/// leave it or do not name a Git checkout root.
pub fn confine_consumers(workspace: &Workspace, supplied: &[String]) -> Result<Vec<PathBuf>> {
    if supplied.is_empty() || supplied.len() > MAX_CROSS_REPOSITORY_CONSUMERS {
        return Err(usage_failure(format!(
            "consumer_paths must contain between 1 and {MAX_CROSS_REPOSITORY_CONSUMERS} repository paths"
        )));
    }
    supplied
        .iter()
        .map(|path| confine_repository_path(workspace.root(), path, "consumer"))
        .collect()
}

/// Resolve `path` beneath `root` to a Git checkout root, rejecting absolute
/// paths, `.` and `..` components, and anything that leaves `root`.
fn confine_repository_path(root: &Path, path: &str, kind: &str) -> Result<PathBuf> {
    use vee_core::paths::CanonicalPath as _;
    let root = root.canonical()?;
    let relative = Path::new(path);
    if relative.is_absolute()
        || relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(usage_failure(format!(
            "{kind} path `{path}` must be a relative path without `.` or `..` components"
        )));
    }
    let resolved = root
        .join(relative)
        .canonical()
        .map_err(|error| usage_failure(format!("cannot resolve {kind} path `{path}`: {error}")))?;
    if !resolved.starts_with(&root) {
        return Err(usage_failure(format!(
            "{kind} path `{path}` escapes the configured repository root"
        )));
    }
    ensure_checkout_root(&resolved, path, kind)?;
    Ok(resolved)
}

/// What to capture in a cross-repository change package.
#[derive(Clone, Debug, Default)]
pub struct ChangePackageRequest<'a> {
    pub repositories: &'a [PathBuf],
    /// `REPOSITORY_ID=HOST/OWNER/REPO#NUMBER` links the caller named.
    pub pull_request_links: &'a [String],
    /// Also link pull requests discovered from each checkout's branch.
    pub discover_linked_prs: bool,
    /// Read each linked pull request's state from its hosting provider.
    pub refresh_pr_links: bool,
    pub base: Option<&'a str>,
}

/// Capture a deterministic local change package across related checkouts,
/// with their linked pull requests and, when asked, their provider state.
pub fn change_package(
    request: ChangePackageRequest<'_>,
    stores: &dyn RepositoryStores,
) -> Result<crate::repository_map::ChangePackage> {
    use crate::repository_map;
    use std::collections::BTreeMap;
    let mut explicit_links = BTreeMap::<String, Vec<vee_hosting::PullRequestRef>>::new();
    for value in request.pull_request_links {
        let (repository_id, reference) =
            repository_map::parse_pull_request_link(value).map_err(usage_failure)?;
        let entry = explicit_links.entry(repository_id).or_default();
        if entry.contains(&reference) {
            return Err(usage_failure("pull request link is repeated"));
        }
        entry.push(reference);
    }
    let mut links = explicit_links;
    let mut discovered_links = BTreeMap::<String, Vec<vee_hosting::PullRequestRef>>::new();
    if request.discover_linked_prs {
        discovered_links = repository_map::discover_linked_pull_requests(request.repositories)
            .map_err(anyhow::Error::msg)?;
        for (repository_id, references) in &discovered_links {
            let entry = links.entry(repository_id.clone()).or_default();
            for reference in references {
                if !entry.contains(reference) {
                    entry.push(reference.clone());
                }
            }
        }
    }
    if request.refresh_pr_links && links.is_empty() {
        return Err(usage_failure(
            "--refresh-pr-links requires at least one --link-pr",
        ));
    }
    let remote_states = if request.refresh_pr_links {
        let local = repository_map::build(request.repositories).map_err(anyhow::Error::msg)?;
        crate::hosting::refresh_linked_pull_requests(&local, &links)?
    } else {
        BTreeMap::new()
    };
    repository_map::change_package_with_pull_requests(
        request.repositories,
        request.base,
        &links,
        &discovered_links,
        &remote_states,
        stores,
    )
    .map_err(|error| {
        if error.starts_with("pull request link") {
            usage_failure(error)
        } else {
            anyhow::Error::msg(error)
        }
    })
}

/// The direct package dependencies between explicitly selected local checkouts.
pub fn repository_map(repositories: &[PathBuf]) -> Result<crate::repository_map::RepositoryMap> {
    crate::repository_map::build(repositories).map_err(anyhow::Error::msg)
}

#[cfg(test)]
mod repository_path_tests {
    use super::*;

    #[test]
    fn confined_repository_paths_stay_beneath_the_root_and_name_a_checkout() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("app");
        let init = |path: &Path| {
            std::fs::create_dir_all(path).unwrap();
            assert!(std::process::Command::new("git")
                .args(["init", "-q"])
                .arg(path)
                .status()
                .unwrap()
                .success());
        };
        init(&root);
        init(&root.join("api"));
        init(&directory.path().join("sibling"));
        std::fs::create_dir_all(root.join("docs")).unwrap();

        let confined = |path: &str| resolve_repository_path(&root, path, RepositoryPaths::Confined);
        assert!(confined("api").is_ok());
        for rejected in ["../sibling", "./api", "/tmp", "docs", ""] {
            assert!(confined(rejected).is_err(), "{rejected}");
        }
        // The CLI may name a sibling checkout, but still only a checkout root.
        let relative = |path: &str| resolve_repository_path(&root, path, RepositoryPaths::Relative);
        assert!(relative("../sibling").is_ok());
        assert!(relative("docs").is_err());
        assert!(relative("/tmp").is_err());
    }
}
