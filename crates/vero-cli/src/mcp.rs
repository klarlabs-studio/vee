use mcp_rs::{transport, Server, ToolError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{path::PathBuf, sync::Arc, time::Duration};
use vero_core::ChangeSet;
use vero_core::{Evidence, FindingStatus, ReviewStore, Severity};

const MAX_PAGE_SIZE: usize = 100;
const MAX_REPOSITORY_CONTEXT_BYTES: usize = 32 * 1024;

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
struct VerifyFindingInput {
    finding_id: String,
    profile_id: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ImpactInput {
    review_id: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct RepositoryContextInput {
    review_id: String,
    path: String,
    symbol: Option<String>,
    max_bytes: Option<usize>,
}

#[derive(Serialize, JsonSchema)]
struct RepositoryContextOutput {
    schema_version: u32,
    path: String,
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
                Ok::<_, ToolError>(FindingOutput {
                    schema_version: 1,
                    finding,
                    evidence,
                })
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
                let config_digest = vero_application::effective_review_config_digest(
                    &config,
                    &app.root,
                    &review.selected_reviewers,
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
                        reviewed_config_digest: &review.effective_config_digest,
                        effective_config_digest: &config_digest,
                        config: &config,
                        findings: &review.findings,
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
                    schema_version: 1,
                    path: input.path,
                    content,
                    matching_lines,
                    truncated,
                    classification: "untrusted_repository_source".into(),
                    note,
                })
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
    reviewer_outcomes: Vec<vero_application::ReviewerOutcome>,
    #[serde(default)]
    selected_reviewers: Vec<String>,
    #[serde(default)]
    policy_profile: Option<String>,
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

pub fn serve_stdio() -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let root = vero_git::repository_root(&cwd).map_err(anyhow::Error::msg)?;
    let database = root.join(".vero/vero.sqlite");
    let server = build_server(App { root, database })?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let shutdown = tokio_util::sync::CancellationToken::new();
    let result = runtime.block_on(transport::serve_stdio(server, shutdown));
    runtime.shutdown_timeout(Duration::from_secs(1));
    result?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_mcp_filter_enums_and_page_bound() {
        assert_eq!(parse_severity("high").unwrap(), Severity::High);
        assert!(parse_severity("urgent").is_err());
        assert_eq!(parse_status("open").unwrap(), FindingStatus::Open);
        assert!(parse_status("closed").is_err());
        assert_eq!(usize::MAX.clamp(1, MAX_PAGE_SIZE), MAX_PAGE_SIZE);
    }
}
