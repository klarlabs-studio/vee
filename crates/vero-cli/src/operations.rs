//! Transport-neutral Vero operations.
//!
//! The CLI and the MCP server are thin adapters over this module: each operation
//! validates its input once, runs the shared application services, and returns the
//! published result document. The CLI prints that document for `--output json` (or
//! renders it as text); the MCP server returns it as the tool result. Errors carry the
//! CLI's usage/configuration markers so both transports report the same message and
//! the CLI keeps its documented exit codes.

use crate::{configuration_failure, usage_failure};
use anyhow::{Context, Result};
use serde::Serialize;
use std::path::{Path, PathBuf};
use vero_application::{GateCheckResult, ReviewResult};
use vero_core::{
    Evidence, FindingFeedback, FindingFeedbackLabel, FindingRecord, FindingStatus,
    RepositoryConfig, ReviewStore, Severity, VerificationRun,
};

pub const DEFAULT_PAGE_SIZE: usize = 50;
pub const MAX_PAGE_SIZE: usize = 100;
pub const DEFAULT_CONTEXT_LINES: usize = 20;
const MAX_REASON_CHARS: usize = 4_000;
const MAX_NAME_CHARS: usize = 200;
const MAX_SCOPE_CHARS: usize = 1_024;
const MAX_INSTRUCTION_BYTES: usize = 20_000;
/// Upper bound on findings scanned when mining rule candidates.
const RULE_MINING_FINDING_LIMIT: usize = 10_000;

/// The repository a transport operates on, and its local Vero database.
#[derive(Clone, Debug)]
pub struct Workspace {
    root: PathBuf,
}

impl Workspace {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// The Git checkout containing the current directory.
    pub fn discover() -> Result<Self> {
        let cwd = std::env::current_dir()?;
        let root = vero_git::repository_root(&cwd).map_err(anyhow::Error::msg)?;
        Ok(Self::new(root))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn database_path(&self) -> PathBuf {
        self.root.join(".vero/vero.sqlite")
    }

    /// Open the review store, creating `.vero/` on first use.
    pub fn store(&self) -> Result<ReviewStore> {
        std::fs::create_dir_all(self.root.join(".vero"))?;
        ReviewStore::open(&self.database_path()).map_err(anyhow::Error::msg)
    }

    /// Open the review store only if it already exists, so read-only operations do
    /// not create local state as a side effect.
    pub fn existing_store(&self) -> Result<Option<ReviewStore>> {
        let path = self.database_path();
        if !path.exists() {
            return Ok(None);
        }
        ReviewStore::open(&path)
            .map(Some)
            .map_err(anyhow::Error::msg)
    }

    /// Repository configuration with the named policy profile and protected local
    /// policy applied, exactly as reviews and gates evaluate it.
    pub fn effective_config(&self, policy_profile: Option<&str>) -> Result<RepositoryConfig> {
        let mut config =
            vero_application::load_repository_config(&self.root).map_err(configuration_failure)?;
        config
            .select_policy_profile(policy_profile)
            .map_err(configuration_failure)?;
        vero_application::apply_protected_policy(&self.root, &mut config)
            .map_err(configuration_failure)?;
        Ok(config)
    }

    fn saved_review(&self, store: &ReviewStore, review_id: &str) -> Result<ReviewResult> {
        let payload = store
            .get(review_id)
            .map_err(anyhow::Error::msg)?
            .ok_or_else(|| usage_failure(format!("review {review_id} was not found")))?;
        vero_application::deserialize_review_result(&payload)
            .map_err(|error| anyhow::anyhow!("stored review {review_id} is invalid: {error}"))
    }

    fn finding(&self, store: &ReviewStore, finding_id: &str) -> Result<FindingRecord> {
        store
            .finding(finding_id)
            .map_err(anyhow::Error::msg)?
            .ok_or_else(|| usage_failure(format!("finding {finding_id} was not found")))
    }

    /// Recapture a saved review's scope and fail if the source no longer matches.
    fn current_snapshot_of(&self, review: &ReviewResult) -> Result<vero_core::ChangeSet> {
        let current = vero_application::capture_current_change_set(&self.root, &review.change_set)
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

    pub fn resolve(&self, root: &Path) -> Result<vero_git::ChangeScope> {
        match self {
            Self::BaseAndWorktree { base } => Ok(vero_git::ChangeScope::BaseAndWorktree {
                base_oid: base
                    .as_deref()
                    .map(|base_ref| vero_git::merge_base(root, base_ref))
                    .transpose()
                    .map_err(usage_failure)?,
            }),
            Self::WorkingTree => Ok(vero_git::ChangeScope::WorkingTree),
            Self::Staged => Ok(vero_git::ChangeScope::Staged),
            Self::Commit(commit) => vero_git::commit_scope(commit).map_err(usage_failure),
        }
    }
}

pub struct ReviewRequest<'a> {
    pub scope: ScopeRequest,
    pub reviewer_ids: Option<&'a [String]>,
    pub policy_profile: Option<&'a str>,
    /// Work item fetched by the caller; requires online configuration.
    pub work_item: Option<vero_hosting::WorkItemSnapshot>,
    pub work_item_token_env: Option<String>,
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
    let config = workspace.effective_config(request.policy_profile)?;
    if request.work_item.is_some() && config.offline {
        return Err(configuration_failure(
            "offline mode prevents fetching work item context",
        ));
    }
    let scope = request.scope.resolve(workspace.root())?;
    let change_set = vero_application::capture_change_set(workspace.root(), scope)
        .map_err(anyhow::Error::msg)?;
    let mut store = workspace.store()?;
    vero_application::run_review_with_provider_and_selection_context(
        workspace.root(),
        change_set,
        &config,
        &mut store,
        vero_application::ReviewRunOptions {
            provider_adapter: &vero_application::CliReviewProvider,
            requested_reviewers: request.reviewer_ids,
            cancellation,
            work_item: request.work_item,
            work_item_token_env: request.work_item_token_env,
        },
    )
    .map_err(anyhow::Error::msg)
}

pub fn get_review(workspace: &Workspace, review_id: &str) -> Result<ReviewResult> {
    let store = workspace.store()?;
    workspace.saved_review(&store, review_id)
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
#[derive(Debug, Serialize)]
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

/// `finding-detail-v2`
#[derive(Debug, Serialize)]
pub struct FindingDetail {
    pub schema_version: u32,
    pub finding: FindingRecord,
    pub evidence: Vec<Evidence>,
    pub verification_runs: Vec<VerificationRun>,
}

pub fn finding_detail(workspace: &Workspace, finding_id: &str) -> Result<FindingDetail> {
    let store = workspace.store()?;
    let finding = workspace.finding(&store, finding_id)?;
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
    let record = workspace.finding(&store, finding_id)?;
    crate::finding_task::build(workspace.root(), &store, record, context_lines)
        .map_err(anyhow::Error::msg)
}

pub fn finding_work_package(
    workspace: &Workspace,
    finding_ids: &[String],
    context_lines: usize,
) -> Result<crate::finding_task::FindingWorkPackage> {
    let store = workspace.store()?;
    crate::finding_task::build_package(workspace.root(), &store, finding_ids, context_lines)
        .map_err(usage_failure)
}

/// `finding-status-update-v1`
#[derive(Debug, Serialize)]
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
    require_text("reason", reason, MAX_REASON_CHARS)?;
    if status == FindingStatus::Waived {
        return Err(usage_failure(
            "waivers require a scoped snapshot, author, and expiry; use the waiver workflow (`vero waivers create`)",
        ));
    }
    let reason = reason.trim().to_owned();
    workspace
        .store()?
        .set_finding_status(finding_id, status, &reason)
        .map_err(anyhow::Error::msg)?;
    Ok(FindingStatusUpdate {
        schema_version: 1,
        finding_id: finding_id.to_owned(),
        status,
        reason,
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
    require_text("reason", request.reason, MAX_REASON_CHARS)?;
    require_text("reviewer", request.reviewer, MAX_NAME_CHARS)?;
    workspace
        .store()?
        .add_finding_feedback(
            request.finding_id,
            request.snapshot_id,
            request.label,
            request.reason,
            request.reviewer,
        )
        .map_err(anyhow::Error::msg)
}

// ---------------------------------------------------------------------------
// Gate and verification

/// Recapture the reviewed scope and re-evaluate the deterministic gate.
///
/// The work-item token variable resolves as: explicit override, the variable saved
/// with the review, `hosting.token_env` in `.vero.yaml`, then `GH_TOKEN` (mapped to
/// the provider's conventional default).
pub fn gate_check(
    workspace: &Workspace,
    review_id: &str,
    token_env_override: Option<&str>,
) -> Result<GateCheckResult> {
    let store = workspace.store()?;
    let review = workspace.saved_review(&store, review_id)?;
    let current =
        vero_application::capture_current_change_set(workspace.root(), &review.change_set)
            .map_err(anyhow::Error::msg)?;
    let config = workspace.effective_config(review.policy_profile.as_deref())?;
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
            let token_env = crate::effective_work_item_token_env(&item.provider, configured);
            let token = std::env::var(token_env).with_context(|| {
                format!("{token_env} is required to revalidate the external work item used by this review")
            })?;
            Some(crate::get_work_item(
                &item.provider,
                &item.api_base,
                token,
                &item.reference,
            )?)
        }
    };
    let config_digest = vero_application::effective_review_config_digest_with_work_item(
        &config,
        workspace.root(),
        &review.selected_reviewers,
        current_work_item.as_ref(),
    )
    .map_err(anyhow::Error::msg)?;
    let verification_runs = store
        .verifications_for_snapshot(&current.digest)
        .map_err(anyhow::Error::msg)?;
    let decision = vero_application::evaluate_and_persist_gate(
        &store,
        vero_application::GateEvaluation {
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
    Ok(GateCheckResult::from_decision(
        review_id.to_owned(),
        review.snapshot_id,
        current.digest,
        decision,
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

pub fn verify(workspace: &Workspace, request: VerifyRequest<'_>) -> Result<VerificationRun> {
    let config = workspace.effective_config(None)?;
    let mut store = workspace.store()?;
    let root = workspace.root();
    match request.target {
        VerifyTarget::Finding(finding_id) => {
            if request.impacted_tests {
                return Err(usage_failure(
                    "impacted-test expansion applies to scope verification, not a finding",
                ));
            }
            let finding = workspace.finding(&store, &finding_id)?;
            let occurrence = finding
                .occurrences
                .last()
                .context("finding has no review occurrence")?;
            let review = workspace.saved_review(&store, &occurrence.review_id)?;
            let current = vero_application::capture_current_change_set(root, &review.change_set)
                .map_err(anyhow::Error::msg)?;
            if current.digest != occurrence.snapshot_id {
                return Err(usage_failure(format!(
                    "finding {finding_id} is stale because its source snapshot changed"
                )));
            }
            vero_application::run_finding_verification(
                root,
                &current,
                &finding_id,
                request.profile_id,
                &config,
                &mut store,
            )
        }
        VerifyTarget::Scope(scope) => {
            let scope = scope.resolve(root)?;
            let snapshot =
                vero_application::capture_change_set(root, scope).map_err(anyhow::Error::msg)?;
            if request.impacted_tests {
                vero_application::run_impacted_test_verification(
                    root,
                    &snapshot,
                    request.profile_id,
                    &config,
                    &mut store,
                )
            } else {
                vero_application::run_verification(
                    root,
                    &snapshot,
                    request.profile_id,
                    &config,
                    &mut store,
                )
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
    crate::verification_diagnosis::diagnose(workspace.root(), &store, &run)
        .map_err(anyhow::Error::msg)
}

// ---------------------------------------------------------------------------
// Impact, acceptance, standards, analytics

pub enum ImpactTarget {
    /// The immutable snapshot of a saved review; fails if the source changed.
    Review(String),
    Scope(ScopeRequest),
}

pub fn impact(
    workspace: &Workspace,
    target: ImpactTarget,
) -> Result<vero_application::ImpactAssessment> {
    let change_set = match target {
        ImpactTarget::Review(review_id) => {
            let store = workspace.store()?;
            let review = workspace.saved_review(&store, &review_id)?;
            workspace.current_snapshot_of(&review)?
        }
        ImpactTarget::Scope(scope) => {
            let scope = scope.resolve(workspace.root())?;
            vero_application::capture_change_set(workspace.root(), scope)
                .map_err(anyhow::Error::msg)?
        }
    };
    vero_application::analyze_impact(workspace.root(), &change_set).map_err(anyhow::Error::msg)
}

/// Trace saved work-item criteria to the review's changes. Impact candidates are
/// included only when the live source still matches the review; otherwise the report
/// records why they are missing.
pub fn acceptance_report(
    workspace: &Workspace,
    review_id: &str,
) -> Result<crate::acceptance::AcceptanceReport> {
    let store = workspace.store()?;
    let review = workspace.saved_review(&store, review_id)?;
    let (impact, impact_problem) = crate::acceptance::matching_impact(
        &review.snapshot_id,
        vero_application::analyze_impact(workspace.root(), &review.change_set),
    );
    Ok(crate::acceptance::report_with_impact(
        &review,
        impact.as_ref(),
        impact_problem.as_deref(),
    ))
}

pub fn applicable_standards(
    workspace: &Workspace,
    path: Option<&Path>,
) -> Result<crate::standards::StandardsReport> {
    crate::standards::resolve(workspace.root(), path).map_err(configuration_failure)
}

pub fn quality_analytics(workspace: &Workspace) -> Result<crate::analytics::QualityAnalytics> {
    let store = workspace.store()?;
    crate::analytics::summarize(workspace.root(), &store).map_err(anyhow::Error::msg)
}

// ---------------------------------------------------------------------------
// Imported review history

pub fn search_imported_history(
    workspace: &Workspace,
    query: &str,
    limit: usize,
) -> Result<serde_json::Value> {
    crate::imported_history::search(workspace.root(), query, limit).map_err(configuration_failure)
}

/// Envelope for a recorded human label on an imported provider comment.
#[derive(Debug, Serialize)]
pub struct ExternalFeedbackRecorded {
    pub schema_version: u32,
    pub feedback: crate::imported_history::ExternalReviewFeedback,
    pub trust: &'static str,
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
    require_text("reason", request.reason, MAX_REASON_CHARS)?;
    require_text("reviewer", request.reviewer, MAX_NAME_CHARS)?;
    let feedback = crate::imported_history::record_feedback(
        workspace.root(),
        crate::imported_history::FeedbackRecordInput {
            archive_digest: request.archive_digest,
            external_id: request.external_id,
            category: request.category,
            label: request.label,
            reason: request.reason,
            reviewer: request.reviewer,
            recorded_at_unix: crate::current_unix_time()?,
        },
    )
    .map_err(configuration_failure)?;
    Ok(ExternalFeedbackRecorded {
        schema_version: 1,
        feedback,
        trust: "human_labeled_external_context",
        gate_eligible: false,
    })
}

/// Envelope for listed human labels on imported provider comments.
#[derive(Debug, Serialize)]
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
    store: Option<&ReviewStore>,
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
    mine_candidates(workspace, store.as_ref())
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
) -> Result<vero_core::RuleApproval> {
    require_text("scope", &request.scope, MAX_SCOPE_CHARS)?;
    require_text("approver", &request.approver, MAX_NAME_CHARS)?;
    require_text("reason", &request.reason, MAX_REASON_CHARS)?;
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
    let report = mine_candidates(workspace, Some(&store))?;
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
        vero_core::digest(
            format!(
                "{}\0{}\0{}\0{}",
                request.candidate_id,
                candidate.evidence_digest,
                request.approver,
                now.as_nanos()
            )
            .as_bytes()
        )
    );
    let approval = vero_core::RuleApproval {
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
        approver: request.approver,
        approval_reason: request.reason,
        supersedes_approval_id: request.supersedes_approval_id,
        expires_at_unix,
        created_at: String::new(),
        status: String::new(),
        events: Vec::new(),
    };
    store
        .create_rule_approval(&approval)
        .map_err(anyhow::Error::msg)?;
    saved_approval(&store, &approval.approval_id)
}

fn saved_approval(store: &ReviewStore, approval_id: &str) -> Result<vero_core::RuleApproval> {
    store
        .list_rule_approvals()
        .map_err(anyhow::Error::msg)?
        .into_iter()
        .find(|item| item.approval_id == approval_id)
        .ok_or_else(|| anyhow::anyhow!("approval {approval_id} could not be read back"))
}

pub fn list_rule_approvals(workspace: &Workspace) -> Result<Vec<vero_core::RuleApproval>> {
    match workspace.existing_store()? {
        Some(store) => store.list_rule_approvals().map_err(anyhow::Error::msg),
        None => Ok(Vec::new()),
    }
}

pub fn revoke_rule(
    workspace: &Workspace,
    approval_id: &str,
    actor: &str,
    reason: &str,
) -> Result<vero_core::RuleApproval> {
    require_text("actor", actor, MAX_NAME_CHARS)?;
    require_text("reason", reason, MAX_REASON_CHARS)?;
    let mut store = workspace.store()?;
    store
        .revoke_rule_approval(approval_id, actor, reason)
        .map_err(anyhow::Error::msg)?;
    saved_approval(&store, approval_id)
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
    crate::rule_candidates::effectiveness(&store, approval_id, &external_feedback)
        .map_err(anyhow::Error::msg)
}
