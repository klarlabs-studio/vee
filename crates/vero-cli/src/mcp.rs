use mcp_rs::{transport, Server, ToolError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{path::PathBuf, sync::Arc, time::Duration};
use vero_core::ChangeSet;
use vero_core::{Evidence, FindingFeedbackLabel, FindingStatus, ReviewStore, Severity};

const MAX_PAGE_SIZE: usize = 100;
const MAX_REPOSITORY_CONTEXT_BYTES: usize = 32 * 1024;

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct EmptyInput {}

#[derive(Clone)]
struct App {
    root: PathBuf,
    database: PathBuf,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ListFindingsInput {
    review_id: Option<String>,
    severity: Option<String>,
    status: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
}

#[derive(Serialize, JsonSchema)]
struct ListFindingsOutput {
    schema_version: u32,
    findings: Vec<Value>,
    limit: usize,
    offset: usize,
    total: usize,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct FindingInput {
    finding_id: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct FindingPackageInput {
    #[schemars(length(min = 1, max = 20))]
    finding_ids: Vec<String>,
    context_lines: Option<usize>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ImportedHistorySearchInput {
    query: String,
    limit: Option<usize>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ExternalReviewFeedbackInput {
    archive_digest: String,
    external_id: String,
    category: String,
    label: String,
    reason: String,
    reviewer: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ListExternalReviewFeedbackInput {
    archive_digest: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct SetFindingStatusInput {
    finding_id: String,
    status: String,
    reason: String,
}

#[derive(Serialize, JsonSchema)]
struct SetFindingStatusOutput {
    schema_version: u32,
    finding_id: String,
    status: String,
    reason: String,
    note: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct RecordFindingFeedbackInput {
    finding_id: String,
    snapshot_id: String,
    label: String,
    reason: String,
    reviewer: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ApproveRuleCandidateInput {
    candidate_id: String,
    evidence_digest: String,
    scope: String,
    instruction: String,
    approver: String,
    reason: String,
    #[serde(default)]
    supersedes_approval_id: Option<String>,
    #[serde(default)]
    expires_in_days: Option<u32>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct RevokeRuleApprovalInput {
    approval_id: String,
    actor: String,
    reason: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct RuleEffectivenessInput {
    approval_id: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct VerifyFindingInput {
    finding_id: String,
    profile_id: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct DiagnoseVerificationInput {
    run_id: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ImpactInput {
    review_id: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct CrossRepositoryImpactInput {
    base_ref: String,
    consumer_paths: Vec<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct RepositoryContextInput {
    review_id: String,
    path: String,
    symbol: Option<String>,
    max_bytes: Option<usize>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct StandardsInput {
    path: Option<String>,
}

#[derive(Serialize, JsonSchema)]
struct RepositoryContextOutput {
    schema_version: u32,
    path: String,
    snapshot_id: String,
    content_digest: String,
    returned_bytes: usize,
    total_bytes: usize,
    matching_line_count: usize,
    content: Option<String>,
    matching_lines: Vec<usize>,
    truncated: bool,
    classification: String,
    note: Option<String>,
}

#[derive(Serialize, JsonSchema)]
struct ImpactOutput {
    schema_version: u32,
    review_id: String,
    assessment: Value,
}

#[derive(Serialize, JsonSchema)]
struct AcceptanceOutput {
    schema_version: u32,
    review_id: String,
    snapshot_id: String,
    report: Value,
}

#[derive(Serialize, JsonSchema)]
struct VerifyFindingOutput {
    schema_version: u32,
    finding_id: String,
    snapshot_id: String,
    run: Value,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ReviewInput {
    review_id: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct StartReviewInput {
    scope: String,
    base: Option<String>,
    commit: Option<String>,
    reviewer_ids: Option<Vec<String>>,
    policy_profile: Option<String>,
}

#[derive(Serialize, JsonSchema)]
struct StartReviewOutput {
    schema_version: u32,
    review_id: String,
    snapshot_id: String,
    status: String,
    policy_profile: Option<String>,
}

#[derive(Serialize, JsonSchema)]
struct ReviewOutput {
    schema_version: u32,
    review_id: String,
    review: serde_json::Value,
}

#[derive(Serialize, JsonSchema)]
struct FindingOutput {
    schema_version: u32,
    finding: Value,
    evidence: Vec<Value>,
    verification_runs: Vec<Value>,
}

#[derive(Serialize, JsonSchema)]
struct FindingTaskOutput {
    schema_version: u32,
    task: Value,
}

#[derive(Serialize, JsonSchema)]
struct FindingPackageOutput {
    schema_version: u32,
    package: Value,
}

#[derive(Serialize, JsonSchema)]
struct ImportedHistorySearchOutput {
    schema_version: u32,
    report: Value,
}

#[derive(Serialize, JsonSchema)]
struct GateOutput {
    schema_version: u32,
    review_id: String,
    reviewed_snapshot_id: String,
    current_snapshot_id: String,
    effective_config_digest: String,
    status: String,
    decision_id: String,
    blocking_findings: Vec<String>,
    verification_run_ids: Vec<String>,
    evidence_digest: String,
    reasons: Vec<String>,
}

impl App {
    fn store(&self) -> Result<ReviewStore, String> {
        if let Some(parent) = self.database.parent() {
            std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        ReviewStore::open(&self.database)
    }
}

fn resolve_review_scope(
    root: &std::path::Path,
    input: &StartReviewInput,
) -> Result<vero_git::ChangeScope, String> {
    match input.scope.as_str() {
        "staged" if input.base.is_none() && input.commit.is_none() => {
            Ok(vero_git::ChangeScope::Staged)
        }
        "working_tree" if input.base.is_none() && input.commit.is_none() => {
            Ok(vero_git::ChangeScope::WorkingTree)
        }
        "base" if input.commit.is_none() => {
            let base_ref = input
                .base
                .as_deref()
                .ok_or("base scope requires a base ref")?;
            let base_oid = vero_git::merge_base(root, base_ref)?;
            Ok(vero_git::ChangeScope::BaseAndWorktree {
                base_oid: Some(base_oid),
            })
        }
        "commit" if input.base.is_none() => {
            let oid = input
                .commit
                .clone()
                .ok_or("commit scope requires a commit ref")?;
            vero_git::commit_scope(&oid)
        }
        "staged" | "working_tree" => {
            Err("staged/working_tree scope cannot be combined with base or commit".into())
        }
        "base" => Err("base scope cannot be combined with commit".into()),
        "commit" => Err("commit scope cannot be combined with base".into()),
        other => Err(format!("unknown review scope {other}")),
    }
}

fn run_review_task(
    app: &App,
    input: StartReviewInput,
    cancellation: &tokio_util::sync::CancellationToken,
) -> Result<vero_application::ReviewResult, String> {
    if cancellation.is_cancelled() {
        return Err("review cancelled before capture".into());
    }
    let scope = resolve_review_scope(&app.root, &input)?;
    let change_set = vero_application::capture_change_set(&app.root, scope)?;
    let mut config = vero_application::load_repository_config(&app.root)?;
    config.select_policy_profile(input.policy_profile.as_deref())?;
    vero_application::apply_protected_policy(&app.root, &mut config)?;
    if let Some(parent) = app.database.parent() {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let mut store = app.store()?;
    vero_application::run_review_with_provider_and_selection(
        &app.root,
        change_set,
        &config,
        &mut store,
        &vero_application::CliReviewProvider,
        input.reviewer_ids.as_deref(),
        Some(cancellation),
    )
}

fn build_server(app: App) -> Result<Server, mcp_rs::RegistrationError> {
    let app = Arc::new(app);
    let tasks = mcp_rs::protocol::task_manager::TaskManager::new();
    let mut server = Server::new("vero", env!("CARGO_PKG_VERSION")).with_task_manager(tasks);
    let state = app.clone();
    server.tool("start_review")
        .description("Start a review as a cancellable MCP task; poll it through the MCP tasks API")
        .task_handler(
            mcp_rs::protocol::task_manager::TaskOptions::new()
                .with_status_message("Preparing Vero review"),
            move |ctx, task, input: StartReviewInput| {
                let app = state.clone();
                async move {
                    let cancellation = ctx.ct.clone();
                    let task_cancel = task.clone();
                    let work = tokio::task::spawn_blocking(move || run_review_task(&app, input, &cancellation));
                    tokio::select! {
                        _ = task_cancel.cancelled() => {
                            ctx.ct.cancel();
                            Err(mcp_rs::protocol::task_manager::TaskExit::Cancelled)
                        }
                        result = work => {
                            let review = result
                                .map_err(|error| mcp_rs::protocol::ErrorData::internal_error(error.to_string(), None))?
                                .map_err(|error| mcp_rs::protocol::ErrorData::internal_error(error, None))?;
                            let output = StartReviewOutput {
                                schema_version: review.schema_version,
                                review_id: review.review_id,
                                snapshot_id: review.snapshot_id,
                                status: review.status,
                                policy_profile: review.policy_profile,
                            };
                            let mut result = mcp_rs::model::CallToolResult::default();
                            result.structured_content = Some(serde_json::to_value(output)
                                .map_err(|error| mcp_rs::protocol::ErrorData::internal_error(error.to_string(), None))?);
                            Ok(result)
                        }
                    }
                }
            },
        )?;
    let state = app.clone();
    server
        .tool("review_changes")
        .description("Capture the requested repository scope, run configured reviewers, and persist a review")
        .handler(move |_ctx, input: StartReviewInput| {
            let app = state.clone();
            async move {
                let scope = resolve_review_scope(&app.root, &input).map_err(ToolError::new)?;
                let change_set = vero_application::capture_change_set(&app.root, scope)
                    .map_err(ToolError::new)?;
                let mut config = vero_application::load_repository_config(&app.root)
                    .map_err(ToolError::new)?;
                config
                    .select_policy_profile(input.policy_profile.as_deref())
                    .map_err(ToolError::new)?;
                vero_application::apply_protected_policy(&app.root, &mut config).map_err(ToolError::new)?;
                if let Some(parent) = app.database.parent() {
                    std::fs::create_dir_all(parent).map_err(|error| ToolError::new(error.to_string()))?;
                }
                let mut store = app.store().map_err(ToolError::new)?;
                let review = vero_application::run_review_selecting_reviewers(
                    &app.root,
                    change_set,
                    &config,
                    &mut store,
                    input.reviewer_ids.as_deref(),
                )
                    .map_err(ToolError::new)?;
                Ok::<_, ToolError>(StartReviewOutput {
                    schema_version: review.schema_version,
                    review_id: review.review_id,
                    snapshot_id: review.snapshot_id,
                    status: review.status,
                    policy_profile: review.policy_profile,
                })
            }
        })?;
    let state = app.clone();
    server.tool("list_findings").description("List persisted findings in this repository with optional filters and bounded pagination")
        .handler(move |_ctx, input: ListFindingsInput| {
            let app = state.clone();
            async move {
                let limit = input.limit.unwrap_or(50).clamp(1, MAX_PAGE_SIZE);
                let offset = input.offset.unwrap_or(0);
                let severity = input.severity.as_deref().map(parse_severity).transpose().map_err(ToolError::new)?;
                let status = input.status.as_deref().map(parse_status).transpose().map_err(ToolError::new)?;
                let store = app.store().map_err(ToolError::new)?;
                let (findings, total) = store.list_findings_page(
                    severity,
                    status,
                    input.review_id.as_deref(),
                    limit,
                    offset,
                ).map_err(ToolError::new)?;
                let findings = findings.into_iter()
                    .map(serde_json::to_value).collect::<Result<Vec<_>, _>>()
                    .map_err(|error| ToolError::new(error.to_string()))?;
                Ok::<_, ToolError>(ListFindingsOutput { schema_version: 1, findings, limit, offset, total })
            }
        })?;
    let state = app.clone();
    server
        .tool("get_quality_analytics")
        .description("Summarize local saved reviews, latest gate decisions, finding lifecycle and severity counts, verification outcomes and recognized saved test-log events by profile, and explicit feedback labels")
        .handler(move |_ctx, _input: EmptyInput| {
            let app = state.clone();
            async move {
                let store = app.store().map_err(ToolError::new)?;
                crate::analytics::summarize(&app.root, &store).map_err(ToolError::new)
            }
        })?;
    let state = app.clone();
    server
        .tool("get_finding")
        .description("Get a persisted finding, lifecycle state, and occurrence history")
        .handler(move |_ctx, input: FindingInput| {
            let app = state.clone();
            async move {
                let store = app.store().map_err(ToolError::new)?;
                let record = store
                    .finding(&input.finding_id)
                    .map_err(ToolError::new)?
                    .ok_or_else(|| {
                        ToolError::new(format!("finding {} was not found", input.finding_id))
                    })?;
                let evidence_ids = &record.finding.evidence_ids;
                let mut evidence = Vec::new();
                for occurrence in record.occurrences.iter().rev() {
                    for item in store
                        .evidence_for_review(&occurrence.review_id)
                        .map_err(ToolError::new)?
                    {
                        if evidence_ids.contains(&item.id)
                            && !evidence.iter().any(|prior: &Evidence| prior.id == item.id)
                        {
                            evidence.push(item);
                        }
                    }
                }
                let finding = serde_json::to_value(record)
                    .map_err(|error| ToolError::new(error.to_string()))?;
                let evidence = evidence
                    .into_iter()
                    .map(serde_json::to_value)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|error| ToolError::new(error.to_string()))?;
                let verification_runs = store
                    .verifications_for_finding(&input.finding_id)
                    .map_err(ToolError::new)?
                    .into_iter()
                    .map(serde_json::to_value)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|error| ToolError::new(error.to_string()))?;
                Ok::<_, ToolError>(FindingOutput {
                    schema_version: 1,
                    finding,
                    evidence,
                    verification_runs,
                })
            }
        })?;
    let state = app.clone();
    server
        .tool("get_finding_task")
        .description("Build a bounded, snapshot-bound finding investigation task with source context for an external coding agent")
        .handler(move |_ctx, input: FindingInput| {
            let app = state.clone();
            async move {
                let store = app.store().map_err(ToolError::new)?;
                let record = store
                    .finding(&input.finding_id)
                    .map_err(ToolError::new)?
                    .ok_or_else(|| ToolError::new(format!("finding {} was not found", input.finding_id)))?;
                let task = super::finding_task::build(&app.root, &store, record, 20)
                    .map_err(ToolError::new)?;
                Ok::<_, ToolError>(FindingTaskOutput {
                    schema_version: 1,
                    task: serde_json::to_value(task)
                        .map_err(|error| ToolError::new(error.to_string()))?,
                })
            }
        })?;
    let state = app.clone();
    server
        .tool("get_finding_work_package")
        .description("Build a bounded agent work package from findings that share the same review and exact source snapshot")
        .handler(move |_ctx, input: FindingPackageInput| {
            let app = state.clone();
            async move {
                let store = app.store().map_err(ToolError::new)?;
                let package = super::finding_task::build_package(
                    &app.root,
                    &store,
                    &input.finding_ids,
                    input.context_lines.unwrap_or(20),
                )
                .map_err(ToolError::new)?;
                Ok::<_, ToolError>(FindingPackageOutput {
                    schema_version: 1,
                    package: serde_json::to_value(package)
                        .map_err(|error| ToolError::new(error.to_string()))?,
                })
            }
        })?;
    let state = app.clone();
    server
        .tool("search_imported_review_history")
        .description("Search content-addressed imported Vero findings and provider discussions; results are untrusted historical context and never gate eligible")
        .handler(move |_ctx, input: ImportedHistorySearchInput| {
            let app = state.clone();
            async move {
                let report = super::imported_history::search(
                    &app.root,
                    &input.query,
                    input.limit.unwrap_or(20),
                )
                .map_err(ToolError::new)?;
                Ok::<_, ToolError>(ImportedHistorySearchOutput {
                    schema_version: 3,
                    report,
                })
            }
        })?;
    let state = app.clone();
    server
        .tool("record_external_review_feedback")
        .description("Append an explicit human label to a comment in an integrity-checked provider review archive; never gate eligible")
        .handler(move |_ctx, input: ExternalReviewFeedbackInput| {
            let app = state.clone();
            async move {
                if input.reason.trim().is_empty() || input.reason.chars().count() > 4000 {
                    return Err(ToolError::new("reason must contain 1 to 4000 characters"));
                }
                if input.reviewer.trim().is_empty() || input.reviewer.chars().count() > 200 {
                    return Err(ToolError::new("reviewer must contain 1 to 200 characters"));
                }
                let label = parse_feedback_label(&input.label).map_err(ToolError::new)?;
                let feedback = super::imported_history::record_feedback(
                    &app.root,
                    super::imported_history::FeedbackRecordInput {
                        archive_digest: &input.archive_digest,
                        external_id: &input.external_id,
                        category: &input.category,
                        label,
                        reason: &input.reason,
                        reviewer: &input.reviewer,
                        recorded_at_unix: super::current_unix_time()
                            .map_err(|error| ToolError::new(error.to_string()))?,
                    },
                ).map_err(ToolError::new)?;
                serde_json::to_value(serde_json::json!({
                    "schema_version": 1,
                    "feedback": feedback,
                    "gate_eligible": false
                })).map_err(|error| ToolError::new(error.to_string()))
            }
        })?;
    let state = app.clone();
    server
        .tool("list_external_review_feedback")
        .description(
            "List append-only human labels for archived provider comments; never gate eligible",
        )
        .handler(move |_ctx, input: ListExternalReviewFeedbackInput| {
            let app = state.clone();
            async move {
                let feedback = super::imported_history::list_feedback(
                    &app.root,
                    input.archive_digest.as_deref(),
                )
                .map_err(ToolError::new)?;
                serde_json::to_value(serde_json::json!({
                    "schema_version": 1,
                    "feedback": feedback,
                    "gate_eligible": false
                }))
                .map_err(|error| ToolError::new(error.to_string()))
            }
        })?;
    let state = app.clone();
    server
        .tool("set_finding_status")
        .description("Record an auditable finding lifecycle disposition; this does not create a gate waiver")
        .handler(move |_ctx, input: SetFindingStatusInput| {
            let app = state.clone();
            async move {
                let reason = input.reason.trim().to_owned();
                if reason.is_empty() || reason.chars().count() > 4000 {
                    return Err(ToolError::new("reason must contain 1 to 4000 characters"));
                }
                let status = parse_status(&input.status).map_err(ToolError::new)?;
                if status == FindingStatus::Waived {
                    return Err(ToolError::new(
                        "waivers require a scoped snapshot, provenance, author, and expiry; use the waiver workflow",
                    ));
                }
                let mut store = app.store().map_err(ToolError::new)?;
                store
                    .set_finding_status(&input.finding_id, status, &reason)
                    .map_err(ToolError::new)?;
                Ok::<_, ToolError>(SetFindingStatusOutput {
                    schema_version: 1,
                    finding_id: input.finding_id,
                    status: input.status,
                    reason,
                    note: "Lifecycle status is audit metadata. Use the waiver workflow for a scoped gate exception.".into(),
                })
            }
        })?;
    let state = app.clone();
    server
        .tool("record_finding_feedback")
        .description("Record explicit human accuracy/actionability feedback for a finding on a snapshot where it occurred")
        .handler(move |_ctx, input: RecordFindingFeedbackInput| {
            let app = state.clone();
            async move {
                if input.reason.trim().is_empty() || input.reason.chars().count() > 4000 {
                    return Err(ToolError::new("reason must contain 1 to 4000 characters"));
                }
                if input.reviewer.trim().is_empty() || input.reviewer.chars().count() > 200 {
                    return Err(ToolError::new("reviewer must contain 1 to 200 characters"));
                }
                let label = parse_feedback_label(&input.label).map_err(ToolError::new)?;
                let mut store = app.store().map_err(ToolError::new)?;
                store.add_finding_feedback(
                    &input.finding_id,
                    &input.snapshot_id,
                    label,
                    &input.reason,
                    &input.reviewer,
                ).map_err(ToolError::new)
            }
        })?;
    let state = app.clone();
    server
        .tool("list_rule_candidates")
        .description("Mine repeated explicit feedback into candidate reviewer guidance without changing policy")
        .handler(move |_ctx, _input: EmptyInput| {
            let app = state.clone();
            async move {
                let store = app.store().map_err(ToolError::new)?;
                let (records, total) = store.list_findings_page(None, None, None, 10_000, 0).map_err(ToolError::new)?;
                let feedback = store.list_finding_feedback().map_err(ToolError::new)?;
                let external_feedback = super::imported_history::list_feedback(&app.root, None).map_err(ToolError::new)?;
                let report = super::rule_candidates::mine_with_external(&records, &feedback, &external_feedback, total > records.len());
                serde_json::to_value(report).map_err(|error| ToolError::new(error.to_string()))
            }
        })?;
    let state = app.clone();
    server
        .tool("approve_rule_candidate")
        .description("Approve explicit scoped reviewer guidance for a current feedback candidate and exact evidence digest")
        .handler(move |_ctx, input: ApproveRuleCandidateInput| {
            let app = state.clone();
            async move {
                if input.instruction.trim().is_empty() || input.instruction.len() > 20_000
                    || input.scope.trim().is_empty() || input.scope.len() > 1_024
                    || input.approver.trim().is_empty() || input.approver.len() > 200
                    || input.reason.trim().is_empty() || input.reason.len() > 4_000 {
                    return Err(ToolError::new("approval scope, instruction, approver, and reason must be non-empty and within their size limits"));
                }
                let mut store = app.store().map_err(ToolError::new)?;
                let (records, total) = store.list_findings_page(None, None, None, 10_000, 0).map_err(ToolError::new)?;
                let feedback = store.list_finding_feedback().map_err(ToolError::new)?;
                let external_feedback = super::imported_history::list_feedback(&app.root, None).map_err(ToolError::new)?;
                let report = super::rule_candidates::mine_with_external(&records, &feedback, &external_feedback, total > records.len());
                if report.truncated { return Err(ToolError::new("cannot approve a candidate while feedback history is truncated")); }
                let candidate = report.candidates.iter().find(|candidate| candidate.candidate_id == input.candidate_id)
                    .ok_or_else(|| ToolError::new("candidate is missing, disputed, or no longer meets the evidence threshold"))?;
                if candidate.evidence_digest != input.evidence_digest { return Err(ToolError::new("candidate evidence changed; retrieve the current candidates and digest")); }
                let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|error| ToolError::new(error.to_string()))?.as_nanos();
                let approval_id = format!("rule-approval:{}", vero_core::digest(format!("{}\0{}\0{}\0{now}", input.candidate_id, input.evidence_digest, input.approver).as_bytes()));
                let expires_at_unix = match input.expires_in_days {
                    Some(days) if (1..=3650).contains(&days) => Some(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|error| ToolError::new(error.to_string()))?.as_secs() as i64 + i64::from(days) * 86_400),
                    Some(_) => return Err(ToolError::new("expires_in_days must be between 1 and 3650")),
                    None => None,
                };
                let approval = vero_core::RuleApproval {
                    schema_version: 2, approval_id, version: 1, candidate_id: input.candidate_id,
                    evidence_digest: input.evidence_digest, category: candidate.category.clone(),
                    source_feedback_ids: candidate.feedback_ids.clone(), activated_at_unix: None,
                    feedback_label: candidate.feedback_label, scope: input.scope,
                    instruction: input.instruction, approver: input.approver,
                    approval_reason: input.reason, created_at: String::new(), status: String::new(), events: Vec::new(),
                    supersedes_approval_id: input.supersedes_approval_id,
                    expires_at_unix,
                };
                store.create_rule_approval(&approval).map_err(ToolError::new)?;
                let saved = store.list_rule_approvals().map_err(ToolError::new)?.into_iter().find(|item| item.approval_id == approval.approval_id).ok_or_else(|| ToolError::new("saved approval could not be read"))?;
                serde_json::to_value(saved).map_err(|error| ToolError::new(error.to_string()))
            }
        })?;
    let state = app.clone();
    server
        .tool("list_rule_approvals")
        .description("List active and revoked scoped reviewer guidance with audit events")
        .handler(move |_ctx, _input: EmptyInput| {
            let app = state.clone();
            async move {
                let approvals = app
                    .store()
                    .map_err(ToolError::new)?
                    .list_rule_approvals()
                    .map_err(ToolError::new)?;
                serde_json::to_value(approvals).map_err(|error| ToolError::new(error.to_string()))
            }
        })?;
    let state = app.clone();
    server
        .tool("revoke_rule_approval")
        .description("Revoke scoped reviewer guidance by appending an auditable event")
        .handler(move |_ctx, input: RevokeRuleApprovalInput| {
            let app = state.clone();
            async move {
                if input.actor.trim().is_empty() || input.actor.len() > 200 || input.reason.trim().is_empty() || input.reason.len() > 4_000 {
                    return Err(ToolError::new("revocation actor and reason must be non-empty and within their size limits"));
                }
                let mut store = app.store().map_err(ToolError::new)?;
                store.revoke_rule_approval(&input.approval_id, &input.actor, &input.reason).map_err(ToolError::new)?;
                let approval = store.list_rule_approvals().map_err(ToolError::new)?.into_iter().find(|item| item.approval_id == input.approval_id).ok_or_else(|| ToolError::new("approval could not be read after revocation"))?;
                serde_json::to_value(approval).map_err(|error| ToolError::new(error.to_string()))
            }
        })?;
    let state = app.clone();
    server
        .tool("rule_effectiveness")
        .description("Compare explicit category-matched feedback before and after approval activation; observational only")
        .handler(move |_ctx, input: RuleEffectivenessInput| {
            let app = state.clone();
            async move {
                let store = app.store().map_err(ToolError::new)?;
                let external_feedback = super::imported_history::list_feedback(&app.root, None).map_err(ToolError::new)?;
                let report = super::rule_candidates::effectiveness(&store, input.approval_id.as_deref(), &external_feedback).map_err(ToolError::new)?;
                serde_json::to_value(report).map_err(|error| ToolError::new(error.to_string()))
            }
        })?;
    let state = app.clone();
    server
        .tool("get_review")
        .description("Get the persisted review output by review ID")
        .handler(move |_ctx, input: ReviewInput| {
            let app = state.clone();
            async move {
                let payload = app
                    .store()
                    .map_err(ToolError::new)?
                    .get(&input.review_id)
                    .map_err(ToolError::new)?
                    .ok_or_else(|| {
                        ToolError::new(format!("review {} was not found", input.review_id))
                    })?;
                let review = serde_json::from_str(&payload)
                    .map_err(|e| ToolError::new(format!("stored review is invalid: {e}")))?;
                Ok::<_, ToolError>(ReviewOutput {
                    schema_version: 1,
                    review_id: input.review_id,
                    review,
                })
            }
        })?;
    let state = app.clone();
    server
        .tool("evaluate_gate")
        .description(
            "Recapture the current source and reevaluate the deterministic gate for a review",
        )
        .handler(move |_ctx, input: ReviewInput| {
            let app = state.clone();
            async move {
                let store = app.store().map_err(ToolError::new)?;
                if store
                    .get(&input.review_id)
                    .map_err(ToolError::new)?
                    .is_none()
                {
                    return Err(ToolError::new(format!(
                        "review {} was not found",
                        input.review_id
                    )));
                }
                let payload = store
                    .get(&input.review_id)
                    .map_err(ToolError::new)?
                    .unwrap();
                let review: ReviewOutputData = serde_json::from_str(&payload).map_err(|error| {
                    ToolError::new(format!("stored review is invalid: {error}"))
                })?;
                let current =
                    vero_application::capture_current_change_set(&app.root, &review.change_set)
                        .map_err(ToolError::new)?;
                let mut config =
                    vero_application::load_repository_config(&app.root).map_err(ToolError::new)?;
                config
                    .select_policy_profile(review.policy_profile.as_deref())
                    .map_err(ToolError::new)?;
                vero_application::apply_protected_policy(&app.root, &mut config)
                    .map_err(ToolError::new)?;
                let current_work_item = if let Some(item) = review.work_item.as_ref() {
                    if config.offline {
                        return Err(ToolError::new(
                            "offline mode prevents revalidating the work item used by this review",
                        ));
                    }
                    let token_env = review.work_item_token_env.as_deref().unwrap_or("GH_TOKEN");
                    let token_env = super::effective_work_item_token_env(&item.provider, token_env);
                    let token = std::env::var(token_env).map_err(|_| {
                        ToolError::new(format!(
                            "{token_env} is required to revalidate the external work item used by this review"
                        ))
                    })?;
                    Some(
                        super::get_work_item(
                            &item.provider,
                            &item.api_base,
                            token,
                            &item.reference,
                        )
                        .map_err(|error| ToolError::new(error.to_string()))?,
                    )
                } else {
                    None
                };
                let config_digest = vero_application::effective_review_config_digest_with_work_item(
                    &config,
                    &app.root,
                    &review.selected_reviewers,
                    current_work_item.as_ref(),
                )
                .map_err(ToolError::new)?;
                let verifications = store
                    .verifications_for_snapshot(&current.digest)
                    .map_err(ToolError::new)?;
                let decision = vero_application::evaluate_and_persist_gate(
                    &store,
                    vero_application::GateEvaluation {
                        review_id: &input.review_id,
                        reviewed_snapshot_id: &review.snapshot_id,
                        current: &current,
                        repository_root: &app.root,
                        reviewed_config_digest: &review.effective_config_digest,
                        effective_config_digest: &config_digest,
                        config: &config,
                        findings: &review.findings,
                        policy_findings: review.policy_findings.as_deref(),
                        reviewer_outcomes: &review.reviewer_outcomes,
                        analysis_complete: review.analysis_complete,
                        verification_runs: &verifications,
                    },
                )
                .map_err(ToolError::new)?;
                let result = vero_application::GateCheckResult::from_decision(
                    input.review_id.clone(),
                    review.snapshot_id,
                    current.digest,
                    decision,
                );
                Ok::<_, ToolError>(GateOutput {
                    schema_version: result.schema_version,
                    review_id: result.review_id,
                    reviewed_snapshot_id: result.reviewed_snapshot_id,
                    current_snapshot_id: result.current_snapshot_id,
                    effective_config_digest: result.effective_config_digest,
                    status: match result.status {
                        vero_core::GateStatus::Pass => "pass",
                        vero_core::GateStatus::Block => "block",
                        vero_core::GateStatus::Incomplete => "incomplete",
                    }
                    .into(),
                    decision_id: result.decision_id,
                    blocking_findings: result.blocking_findings,
                    verification_run_ids: result.verification_run_ids,
                    evidence_digest: result.evidence_digest,
                    reasons: result.reasons,
                })
            }
        })?;
    let state = app.clone();
    server
        .tool("verify_finding")
        .description("Run a configured verification profile for the exact current snapshot containing a finding")
        .handler(move |_ctx, input: VerifyFindingInput| {
            let app = state.clone();
            async move {
                let mut store = app.store().map_err(ToolError::new)?;
                let finding = store.finding(&input.finding_id).map_err(ToolError::new)?
                    .ok_or_else(|| ToolError::new(format!("finding {} was not found", input.finding_id)))?;
                let occurrence = finding.occurrences.last()
                    .ok_or_else(|| ToolError::new("finding has no review occurrence"))?;
                let payload = store.get(&occurrence.review_id).map_err(ToolError::new)?
                    .ok_or_else(|| ToolError::new("finding review was not found"))?;
                let review: ReviewOutputData = serde_json::from_str(&payload)
                    .map_err(|error| ToolError::new(format!("stored review is invalid: {error}")))?;
                let current = vero_application::capture_current_change_set(&app.root, &review.change_set)
                    .map_err(ToolError::new)?;
                if current.digest != occurrence.snapshot_id {
                    return Err(ToolError::new("finding is stale because its source snapshot changed"));
                }
                let mut config = vero_application::load_repository_config(&app.root).map_err(ToolError::new)?;
                vero_application::apply_protected_policy(&app.root, &mut config).map_err(ToolError::new)?;
                let run = vero_application::run_finding_verification(
                    &app.root,
                    &current,
                    &input.finding_id,
                    &input.profile_id,
                    &config,
                    &mut store,
                ).map_err(ToolError::new)?;
                Ok::<_, ToolError>(VerifyFindingOutput {
                    schema_version: 1,
                    finding_id: input.finding_id,
                    snapshot_id: current.digest,
                    run: serde_json::to_value(run).map_err(|error| ToolError::new(error.to_string()))?,
                })
            }
        })?;
    let state = app.clone();
    server
        .tool("diagnose_verification")
        .description("Parse integrity-checked verification logs into deterministic snapshot-linked compiler and test diagnostics")
        .handler(move |_ctx, input: DiagnoseVerificationInput| {
            let app = state.clone();
            async move {
                let store = app.store().map_err(ToolError::new)?;
                let run = store.verification(&input.run_id).map_err(ToolError::new)?
                    .ok_or_else(|| ToolError::new(format!("verification run {} was not found", input.run_id)))?;
                crate::verification_diagnosis::diagnose(&app.root, &store, &run).map_err(ToolError::new)
            }
        })?;
    let state = app.clone();
    server
        .tool("analyze_impact")
        .description("Analyze likely affected Go/Rust files with evidence paths and uncertainty")
        .handler(move |_ctx, input: ImpactInput| {
            let app = state.clone();
            async move {
                let store = app.store().map_err(ToolError::new)?;
                let payload = store
                    .get(&input.review_id)
                    .map_err(ToolError::new)?
                    .ok_or_else(|| {
                        ToolError::new(format!("review {} was not found", input.review_id))
                    })?;
                let review: ReviewOutputData = serde_json::from_str(&payload).map_err(|error| {
                    ToolError::new(format!("stored review is invalid: {error}"))
                })?;
                let current =
                    vero_application::capture_current_change_set(&app.root, &review.change_set)
                        .map_err(ToolError::new)?;
                if current.digest != review.snapshot_id {
                    return Err(ToolError::new(
                        "review is stale because its source snapshot changed",
                    ));
                }
                let assessment = vero_application::analyze_impact(&app.root, &current)
                    .map_err(ToolError::new)?;
                Ok::<_, ToolError>(ImpactOutput {
                    schema_version: assessment.schema_version,
                    review_id: input.review_id,
                    assessment: serde_json::to_value(assessment)
                        .map_err(|error| ToolError::new(error.to_string()))?,
                })
            }
        })?;
    let state = app.clone();
    server
        .tool("analyze_cross_repository_impact")
        .description("Analyze changed symbols across selected local consumer checkouts beneath this MCP server's repository root; consumer paths must be relative and stay within that root")
        .handler(move |_ctx, input: CrossRepositoryImpactInput| {
            let app = state.clone();
            async move {
                if input.base_ref.trim().is_empty() || input.base_ref.len() > 256 {
                    return Err(ToolError::new("base_ref must contain 1 to 256 characters"));
                }
                if input.consumer_paths.is_empty() || input.consumer_paths.len() > 128 {
                    return Err(ToolError::new("consumer_paths must contain between 1 and 128 repository paths"));
                }
                let root = app.root.canonicalize().map_err(|error| ToolError::new(error.to_string()))?;
                let mut consumers = Vec::with_capacity(input.consumer_paths.len());
                for supplied in input.consumer_paths {
                    let relative = std::path::Path::new(&supplied);
                    if relative.is_absolute() || relative.as_os_str().is_empty() || relative.components().any(|component| !matches!(component, std::path::Component::Normal(_))) {
                        return Err(ToolError::new(format!("consumer path `{supplied}` must be a relative path without `.` or `..` components")));
                    }
                    let candidate = root.join(relative);
                    let canonical = candidate.canonicalize().map_err(|error| ToolError::new(format!("cannot resolve consumer path `{supplied}`: {error}")))?;
                    if !canonical.starts_with(&root) {
                        return Err(ToolError::new(format!("consumer path `{supplied}` escapes the configured repository root")));
                    }
                    if !canonical.is_dir() {
                        return Err(ToolError::new(format!("consumer path `{supplied}` is not a directory")));
                    }
                    let git_root = vero_git::repository_root(&canonical).map_err(ToolError::new)?;
                    if git_root.canonicalize().map_err(|error| ToolError::new(error.to_string()))? != canonical {
                        return Err(ToolError::new(format!("consumer path `{supplied}` must name a Git checkout root")));
                    }
                    consumers.push(canonical);
                }
                let base = input.base_ref;
                let producer = root.clone();
                let report = tokio::task::spawn_blocking(move || crate::repository_map::analyze_cross_impact(&producer, &base, &consumers))
                    .await
                    .map_err(|error| ToolError::new(format!("cross-repository analysis task failed: {error}")))?
                    .map_err(ToolError::new)?;
                serde_json::to_value(report).map_err(|error| ToolError::new(error.to_string()))
            }
        })?;
    let state = app.clone();
    server
        .tool("acceptance_traceability")
        .description("Extract saved work-item criteria and return same-snapshot changed-to-test impact candidates with provenance and uncertainty")
        .handler(move |_ctx, input: ReviewInput| {
            let app = state.clone();
            async move {
                let payload = app.store().map_err(ToolError::new)?
                    .get(&input.review_id).map_err(ToolError::new)?
                    .ok_or_else(|| ToolError::new(format!("review {} was not found", input.review_id)))?;
                let review = vero_application::deserialize_review_result(&payload)
                    .map_err(|error| ToolError::new(format!("stored review is invalid: {error}")))?;
                let current = vero_application::capture_current_change_set(&app.root, &review.change_set)
                    .map_err(ToolError::new)?;
                if current.digest != review.snapshot_id {
                    return Err(ToolError::new("review is stale because its source snapshot changed"));
                }
                let (impact, impact_problem) = super::acceptance::matching_impact(
                    &review.snapshot_id,
                    vero_application::analyze_impact(&app.root, &current),
                );
                let report = super::acceptance::report_with_impact(
                    &review,
                    impact.as_ref(),
                    impact_problem.as_deref(),
                );
                Ok::<_, ToolError>(AcceptanceOutput {
                    schema_version: 1,
                    review_id: input.review_id,
                    snapshot_id: current.digest,
                    report: serde_json::to_value(report)
                        .map_err(|error| ToolError::new(error.to_string()))?,
                })
            }
        })?;
    let state = app.clone();
    server
        .tool("get_repository_context")
        .description("Read bounded source from an immutable review snapshot by path and optionally find lines matching a symbol query")
        .handler(move |_ctx, input: RepositoryContextInput| {
            let app = state.clone();
            async move {
                let payload = app.store().map_err(ToolError::new)?
                    .get(&input.review_id).map_err(ToolError::new)?
                    .ok_or_else(|| ToolError::new(format!("review {} was not found", input.review_id)))?;
                let review: ReviewOutputData = serde_json::from_str(&payload)
                    .map_err(|error| ToolError::new(format!("stored review is invalid: {error}")))?;
                let relative = PathBuf::from(&input.path);
                if relative.components().any(|component| {
                    matches!(component, std::path::Component::Normal(name) if name == ".git" || name == ".vero")
                }) {
                    return Err(ToolError::new("repository metadata paths are not available through this tool"));
                }
                let bytes = vero_git::read_snapshot_tree_file(&app.root, &review.change_set, &relative)
                    .map_err(ToolError::new)?;
                let Some(bytes) = bytes else {
                    return Err(ToolError::new(format!("repository path {} was not found", input.path)));
                };
                let limit = input.max_bytes.unwrap_or(MAX_REPOSITORY_CONTEXT_BYTES)
                    .clamp(1, MAX_REPOSITORY_CONTEXT_BYTES);
                let truncated = bytes.len() > limit;
                let visible = &bytes[..bytes.len().min(limit)];
                let (content, note, matching_lines) = match std::str::from_utf8(visible) {
                    Ok(text) => {
                        let matching_lines = input.symbol.as_deref().map(|symbol| {
                            text.lines().enumerate()
                                .filter_map(|(index, line)| line.contains(symbol).then_some(index + 1))
                                .collect()
                        }).unwrap_or_default();
                        (Some(text.to_owned()), None, matching_lines)
                    }
                    Err(_) => (None, Some("file is binary or contains non-UTF8 bytes".into()), Vec::new()),
                };
                Ok::<_, ToolError>(RepositoryContextOutput {
                    schema_version: 2,
                    path: input.path,
                    snapshot_id: review.snapshot_id,
                    content_digest: vero_core::digest(&bytes),
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
        })?;
    let state = app.clone();
    server
        .tool("get_applicable_standards")
        .description("Resolve bounded repository standards with source provenance, precedence, scope, and potential-conflict disclosures")
        .handler(move |_ctx, input: StandardsInput| {
            let app = state.clone();
            async move {
                let path = input.path.map(PathBuf::from);
                super::standards::resolve(&app.root, path.as_deref())
                    .map_err(ToolError::new)
            }
        })?;
    Ok(server)
}

#[derive(Deserialize)]
struct ReviewOutputData {
    snapshot_id: String,
    effective_config_digest: String,
    findings: Vec<vero_core::Finding>,
    #[serde(default)]
    policy_findings: Option<Vec<vero_core::Finding>>,
    #[serde(default)]
    reviewer_outcomes: Vec<vero_application::ReviewerOutcome>,
    #[serde(default)]
    selected_reviewers: Vec<String>,
    #[serde(default)]
    policy_profile: Option<String>,
    #[serde(default)]
    work_item: Option<vero_hosting::WorkItemSnapshot>,
    #[serde(default)]
    work_item_token_env: Option<String>,
    analysis_complete: bool,
    change_set: ChangeSet,
}

fn parse_severity(value: &str) -> Result<Severity, String> {
    match value {
        "critical" => Ok(Severity::Critical),
        "high" => Ok(Severity::High),
        "medium" => Ok(Severity::Medium),
        "low" => Ok(Severity::Low),
        "info" => Ok(Severity::Info),
        _ => Err(format!("unknown severity {value}")),
    }
}

fn parse_status(value: &str) -> Result<FindingStatus, String> {
    match value {
        "open" => Ok(FindingStatus::Open),
        "verified" => Ok(FindingStatus::Verified),
        "refuted" => Ok(FindingStatus::Refuted),
        "resolved" => Ok(FindingStatus::Resolved),
        "waived" => Ok(FindingStatus::Waived),
        _ => Err(format!("unknown finding status {value}")),
    }
}

fn parse_feedback_label(value: &str) -> Result<FindingFeedbackLabel, String> {
    match value {
        "confirmed" => Ok(FindingFeedbackLabel::Confirmed),
        "false_positive" => Ok(FindingFeedbackLabel::FalsePositive),
        "actionable" => Ok(FindingFeedbackLabel::Actionable),
        "not_actionable" => Ok(FindingFeedbackLabel::NotActionable),
        _ => Err(
            "feedback label must be confirmed, false_positive, actionable, or not_actionable"
                .into(),
        ),
    }
}

pub fn serve_stdio() -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let root = vero_git::repository_root(&cwd).map_err(anyhow::Error::msg)?;
    let database = root.join(".vero/vero.sqlite");
    let server = build_server(App { root, database })?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let shutdown = tokio_util::sync::CancellationToken::new();
    let result = runtime.block_on(transport::serve_stdio_compatible(server, shutdown));
    runtime.shutdown_timeout(Duration::from_secs(1));
    result?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn validates_mcp_filter_enums_and_page_bound() {
        assert_eq!(parse_severity("high").unwrap(), Severity::High);
        assert!(parse_severity("urgent").is_err());
        assert_eq!(parse_status("open").unwrap(), FindingStatus::Open);
        assert!(parse_status("closed").is_err());
        assert_eq!(usize::MAX.clamp(1, MAX_PAGE_SIZE), MAX_PAGE_SIZE);
    }

    #[test]
    fn legacy_mcp_review_keeps_missing_policy_findings_absent() {
        let change_set = ChangeSet::from_entries(None, None, "working_tree", vec![]);
        let payload = serde_json::json!({
            "snapshot_id": "snapshot",
            "effective_config_digest": "config",
            "findings": [{
                "id": "legacy-blocker",
                "fingerprint": "legacy-fingerprint",
                "category": "correctness",
                "severity": "high",
                "confidence": 99,
                "rationale": "legacy finding",
                "path": "src/lib.rs",
                "line": 1,
                "provenance": "model_inference",
                "evidence_ids": []
            }],
            "reviewer_outcomes": [],
            "selected_reviewers": [],
            "policy_profile": null,
            "analysis_complete": true,
            "change_set": change_set
        });

        let review: ReviewOutputData = serde_json::from_value(payload).unwrap();

        assert!(review.policy_findings.is_none());
        assert_eq!(review.findings.len(), 1);
    }

    #[test]
    fn mcp_review_task_rejects_network_provider_when_repository_is_offline() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        assert!(Command::new("git")
            .args(["init", "-q"])
            .arg(root)
            .status()
            .unwrap()
            .success());
        std::fs::write(root.join("src.rs"), "fn value() -> i32 { 1 }\n").unwrap();
        assert!(Command::new("git")
            .args(["-C"])
            .arg(root)
            .args(["add", "src.rs"])
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args(["-C"])
            .arg(root)
            .args([
                "-c",
                "user.name=Vero Test",
                "-c",
                "user.email=vero-test@example.invalid",
                "commit",
                "-qm",
                "baseline",
            ])
            .status()
            .unwrap()
            .success());
        std::fs::write(root.join("src.rs"), "fn value() -> i32 { 2 }\n").unwrap();
        std::fs::write(root.join("reviewer.md"), "Review correctness.").unwrap();
        std::fs::write(
            root.join(".vero.yaml"),
            "version: 1\noffline: true\nproviders:\n  hosted:\n    kind: cli\n    executable: /vero-test-provider-must-not-run\n    egress: network\nreviewers:\n  correctness:\n    provider: hosted\n    instructions_file: reviewer.md\npolicy:\n  required_reviewers: [correctness]\n  on_incomplete: block\n",
        )
        .unwrap();

        let error = run_review_task(
            &App {
                root: root.to_path_buf(),
                database: root.join(".vero/vero.sqlite"),
            },
            StartReviewInput {
                scope: "working_tree".into(),
                base: None,
                commit: None,
                policy_profile: None,
                reviewer_ids: None,
            },
            &tokio_util::sync::CancellationToken::new(),
        )
        .unwrap_err();

        assert!(
            error.contains("offline mode rejects network provider hosted"),
            "unexpected MCP task result: {error}"
        );
        assert!(!root.join(".vero/vero.sqlite").exists());
    }
}
