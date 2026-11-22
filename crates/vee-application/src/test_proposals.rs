//! Generated-test proposals: plan, generate, refine, apply, run, and assess
//! them against seeded mutants.
//!
//! Every operation returns the published result document; transports only
//! parse their input and present the document.

use crate::failure::usage_failure;
use crate::operations::{ScopeRequest, Workspace};
use crate::proposals::{
    acquire_proposal_apply_lock, capture_recorded_scope, proposal_directory, read_proposal_file,
    write_new_proposal_file, write_proposal_file,
};
use crate::test_effectiveness::{CorpusEffectivenessReport, EffectivenessReport};
use crate::{patch_sandbox, test_effectiveness, test_generation};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::io::Write as _;
use std::path::Path;
use vee_core::ports::Repositories;
use vee_core::{ChangeSet, RepositoryConfig, VerificationRun, VerificationStatus};

const MAX_TEST_PATCH_BYTES: usize = 2 * 1024 * 1024;
const MAX_PROPOSAL_RECORD_BYTES: u64 = 2 * 1024 * 1024;
const MAX_APPLY_RECORD_BYTES: u64 = 256 * 1024;

/// A generated or refined test patch proposal (`test-patch-proposal-v2`), as
/// returned when it is created. The saved record grows application and run
/// fields later; those are not part of this document.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TestPatchProposal {
    pub schema_version: u32,
    pub proposal_id: String,
    pub snapshot_id: String,
    pub source_scope: String,
    pub base_oid: Option<String>,
    pub reviewer_id: String,
    pub provider_id: String,
    pub provider_kind: vee_core::ProviderKind,
    pub model: Option<String>,
    pub provider_output_digest: String,
    pub context_summary: serde_json::Value,
    pub patch_digest: String,
    pub patch_path: String,
    pub validated_in_isolated_sandbox: bool,
    pub sandbox_input_digest: String,
    pub sandbox_result_digest: String,
    pub application: String,
    pub tests_executed: bool,
    pub verification_runs: Vec<ProposalVerificationRun>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refinement: Option<ProposalRefinement>,
    pub approval_instruction: String,
}

/// A trusted verification run recorded against a proposal.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProposalVerificationRun {
    pub run_id: String,
    pub snapshot_id: String,
    pub profile_id: String,
    pub status: VerificationStatus,
}

/// Where a refined proposal came from.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProposalRefinement {
    pub parent_proposal_id: String,
    pub failed_run_id: String,
    pub attempt: u64,
}

/// The result of applying an approved test proposal (`test-proposal-application-v1`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TestProposalApplication {
    pub schema_version: u32,
    pub proposal_id: String,
    pub application: String,
    /// The snapshot after the patch was applied; trusted runs bind to it.
    pub snapshot_id: String,
    pub concurrent_mutation_detected: bool,
}

/// A trusted verification run of an applied test proposal (`test-verification-v1`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TestProposalVerification {
    pub schema_version: u32,
    pub proposal_id: String,
    pub verification_run: VerificationRun,
}

/// An effectiveness report and the digest-addressed artifact it was saved to.
/// The report alone is the published JSON document; the artifact location is
/// reported beside it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PersistedAssessment<R> {
    pub report: R,
    pub artifact_path: String,
    pub artifact_digest: String,
}

pub fn is_sha256_digest(value: &str) -> bool {
    value.starts_with("sha256:")
        && value.len() == 71
        && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn require_proposal_id(proposal_id: &str) -> Result<()> {
    if is_sha256_digest(proposal_id) {
        Ok(())
    } else {
        Err(usage_failure(
            "test proposal ID must be a full sha256:<hex> digest",
        ))
    }
}

/// The proposal ID binds the source snapshot to the exact patch bytes.
pub fn test_proposal_id(snapshot_id: &str, patch_digest: &str) -> Result<String> {
    Ok(vee_core::digest(&serde_json::to_vec(&(
        "vee-test-patch-proposal-v2",
        snapshot_id,
        patch_digest,
    ))?))
}

fn record_path(directory: &Path, proposal_id: &str) -> std::path::PathBuf {
    directory.join(format!("test-{}.json", &proposal_id[7..]))
}

fn patch_path(directory: &Path, proposal_id: &str) -> std::path::PathBuf {
    directory.join(format!("test-{}.patch", &proposal_id[7..]))
}

fn read_record(directory: &Path, proposal_id: &str, max_bytes: u64) -> Result<serde_json::Value> {
    let record: serde_json::Value = serde_json::from_slice(
        &read_proposal_file(&record_path(directory, proposal_id), max_bytes)
            .with_context(|| format!("test proposal {proposal_id} was not found"))?,
    )?;
    anyhow::ensure!(
        record["schema_version"] == 2,
        "unsupported test proposal schema"
    );
    anyhow::ensure!(
        record["proposal_id"].as_str() == Some(proposal_id),
        "test proposal ID does not match its record"
    );
    Ok(record)
}

/// Saved records keep sorted keys: they are read and extended as JSON.
fn write_record(path: &Path, record: &serde_json::Value) -> Result<()> {
    write_proposal_file(path, &serde_json::to_vec_pretty(record)?)
}

fn recorded_scope(record: &serde_json::Value) -> Result<&str> {
    record["source_scope"]
        .as_str()
        .context("test proposal has no source scope")
}

/// Fail unless the provider's test-generation context fits its token budget.
fn ensure_within_budget(context: &serde_json::Value) -> Result<()> {
    anyhow::ensure!(
        context["context_budget"]["within_budget"] == true,
        "test-generation context estimate {} exceeds budget {}; raise test_generation.max_context_tokens or reduce the change scope",
        context["context_budget"]["estimated_prompt_tokens"],
        context["context_budget"]["max_context_tokens"]
    );
    Ok(())
}

fn generation_context(
    root: &Path,
    change_set: &ChangeSet,
    config: &RepositoryConfig,
) -> Result<serde_json::Value> {
    let impact = crate::analyze_impact(root, change_set).map_err(anyhow::Error::msg)?;
    let context = test_generation::context(
        root,
        change_set,
        &impact,
        config.review.max_context_files,
        config.review.max_context_file_bytes,
        config.review.max_context_bytes,
        config.test_generation.max_context_tokens,
    )?;
    ensure_within_budget(&context)?;
    Ok(context)
}

/// A provider's test patch after it passed the isolated sandbox check.
struct ValidatedTestPatch {
    text: String,
    digest: String,
    sandbox_input_digest: String,
    sandbox_result_digest: String,
}

fn validate_test_patch(
    root: &Path,
    patch_text: String,
    outside_tests: &str,
) -> Result<ValidatedTestPatch> {
    let sandbox =
        patch_sandbox::validate_bytes(root, patch_text.as_bytes()).map_err(anyhow::Error::msg)?;
    anyhow::ensure!(
        !sandbox.result_files.is_empty()
            && sandbox
                .result_files
                .iter()
                .all(|file| test_generation::is_test_path(&file.path)),
        "{outside_tests}"
    );
    Ok(ValidatedTestPatch {
        digest: vee_core::digest(patch_text.as_bytes()),
        sandbox_input_digest: patch_sandbox::input_digest(&sandbox.input_files)
            .map_err(anyhow::Error::msg)?,
        sandbox_result_digest: sandbox.result_digest,
        text: patch_text,
    })
}

/// Save a validated patch and its proposal record under `.vee/proposals`.
fn save_proposal(
    directory: &Path,
    proposal_id: &str,
    patch: &ValidatedTestPatch,
    build: impl FnOnce(String) -> TestPatchProposal,
) -> Result<TestPatchProposal> {
    let saved_patch = patch_path(directory, proposal_id);
    write_new_proposal_file(&saved_patch, patch.text.as_bytes())?;
    let proposal = build(saved_patch.to_string_lossy().into_owned());
    write_new_proposal_file(
        &record_path(directory, proposal_id),
        &serde_json::to_vec_pretty(&serde_json::to_value(&proposal)?)?,
    )?;
    Ok(proposal)
}

/// Preview the impact-selected trusted test commands for a change without running them.
pub fn plan(
    workspace: &Workspace,
    scope: ScopeRequest,
    profile_id: &str,
) -> Result<crate::ImpactedTestPlan> {
    let root = workspace.root();
    let config = workspace.effective_config(None)?;
    let snapshot =
        crate::capture_change_set(root, scope.resolve(root)?).map_err(anyhow::Error::msg)?;
    crate::plan_impacted_test_verification(root, &snapshot, profile_id, &config)
        .map_err(anyhow::Error::msg)
}

/// Ask a reviewer for a test-only patch for the change, validate it in an
/// isolated copy, and save it as a proposal. Never applies or runs it.
pub fn generate(
    workspace: &Workspace,
    scope: ScopeRequest,
    reviewer_id: &str,
) -> Result<TestPatchProposal> {
    let root = workspace.root();
    let change_set =
        crate::capture_change_set(root, scope.resolve(root)?).map_err(anyhow::Error::msg)?;
    anyhow::ensure!(
        !change_set.files.is_empty(),
        "test generation requires a non-empty change snapshot"
    );
    let config = workspace.effective_config(None)?;
    let context = generation_context(root, &change_set, &config)?;
    let context_summary = test_generation::context_summary(&context)?;
    let report = crate::run_provider_task(
        crate::ProviderTaskRequest {
            root,
            snapshot_id: &change_set.digest,
            config: &config,
            reviewer_id,
            task_instructions: test_generation::INSTRUCTIONS,
            context,
            output_schema: test_generation::output_schema(),
        },
        &crate::CliReviewProvider,
    )
    .map_err(anyhow::Error::msg)?;
    let snapshot_still_current = crate::capture_current_change_set(root, &change_set)
        .map(|current| current.digest == change_set.digest)
        .unwrap_or(false);
    anyhow::ensure!(
        snapshot_still_current,
        "change snapshot became stale during test generation; rerun against current changes"
    );
    let patch_text = test_generation::extract_patch(report.output["patch"].as_str().unwrap_or(""));
    anyhow::ensure!(
        !patch_text.trim().is_empty(),
        "provider returned an empty test patch"
    );
    anyhow::ensure!(
        patch_text.len() <= MAX_TEST_PATCH_BYTES,
        "generated patch exceeds 2 MiB"
    );
    let patch = validate_test_patch(
        root,
        patch_text,
        "generated patch touches paths outside recognized test files",
    )?;
    let proposal_id = test_proposal_id(&change_set.digest, &patch.digest)?;
    let directory = proposal_directory(root)?;
    save_proposal(&directory, &proposal_id, &patch, |patch_path| {
        TestPatchProposal {
            schema_version: 2,
            approval_instruction: format!(
                "Inspect the generated diff, then run `vee tests apply {proposal_id} --approve {proposal_id}`. Vee has not modified the worktree or run repository tests."
            ),
            proposal_id: proposal_id.clone(),
            snapshot_id: report.snapshot_id,
            source_scope: change_set.scope,
            base_oid: change_set.base_oid,
            reviewer_id: report.reviewer_id,
            provider_id: report.provider_id,
            provider_kind: report.provider_kind,
            model: report.model,
            provider_output_digest: report.output_digest,
            context_summary,
            patch_digest: patch.digest.clone(),
            patch_path,
            validated_in_isolated_sandbox: true,
            sandbox_input_digest: patch.sandbox_input_digest.clone(),
            sandbox_result_digest: patch.sandbox_result_digest.clone(),
            application: "not_applied".to_owned(),
            tests_executed: false,
            verification_runs: Vec::new(),
            refinement: None,
        }
    })
}

/// Ask a reviewer to refine an applied proposal from one of its failed trusted
/// runs. The result is a new proposal that needs its own approval.
pub fn refine(
    workspace: &Workspace,
    proposal_id: &str,
    run_id: &str,
    reviewer_id: &str,
) -> Result<TestPatchProposal> {
    require_proposal_id(proposal_id)?;
    let root = workspace.root();
    let directory = proposal_directory(root)?;
    let parent = read_record(&directory, proposal_id, MAX_PROPOSAL_RECORD_BYTES)?;
    anyhow::ensure!(
        parent["application"] == "applied",
        "test proposal must be applied before it can be refined"
    );
    anyhow::ensure!(
        parent["approval_digest"].as_str() == Some(proposal_id),
        "test proposal has no matching explicit approval record"
    );
    anyhow::ensure!(
        parent["concurrent_mutation_detected"] == false,
        "proposal application had concurrent mutations"
    );
    let linked_run = parent["verification_runs"]
        .as_array()
        .context("proposal has no verification run history")?
        .iter()
        .any(|entry| entry["run_id"].as_str() == Some(run_id));
    anyhow::ensure!(
        linked_run,
        "verification run is not linked to this test proposal"
    );

    let store = workspace.store()?;
    let verification = store
        .verification(run_id)
        .map_err(anyhow::Error::msg)?
        .with_context(|| format!("verification run {run_id} was not found"))?;
    anyhow::ensure!(
        verification.status == VerificationStatus::Failed,
        "only failed verification runs can guide refinement"
    );
    anyhow::ensure!(
        Some(verification.snapshot_id.as_str()) == parent["post_application_snapshot_id"].as_str(),
        "failed verification run is not from this proposal's applied snapshot"
    );
    let scope = parent["source_scope"]
        .as_str()
        .context("proposal has no source scope")?;
    anyhow::ensure!(
        !matches!(scope, "commit" | "commit_range"),
        "immutable commit proposals cannot be refined for application"
    );
    let current = capture_recorded_scope(root, parent["base_oid"].as_str(), scope)?;
    anyhow::ensure!(
        current.digest == verification.snapshot_id,
        "worktree changed after the failed verification; capture a new review before refining"
    );
    let diagnosis = crate::verification_diagnosis::diagnose(root, &*store, &verification)
        .map_err(anyhow::Error::msg)?;
    let parent_patch = read_proposal_file(
        &patch_path(&directory, proposal_id),
        MAX_TEST_PATCH_BYTES as u64,
    )?;
    anyhow::ensure!(
        vee_core::digest(&parent_patch) == parent["patch_digest"].as_str().unwrap_or_default(),
        "parent test patch content has changed"
    );
    let parent_patch =
        std::str::from_utf8(&parent_patch).context("parent test patch is not UTF-8")?;

    let config = workspace.effective_config(None)?;
    let context = test_generation::refinement_context(
        generation_context(root, &current, &config)?,
        parent_patch,
        &diagnosis,
        proposal_id,
        run_id,
    );
    let context_summary = test_generation::context_summary(&context)?;
    let report = crate::run_provider_task(
        crate::ProviderTaskRequest {
            root,
            snapshot_id: &current.digest,
            config: &config,
            reviewer_id,
            task_instructions: test_generation::REFINEMENT_INSTRUCTIONS,
            context,
            output_schema: test_generation::output_schema(),
        },
        &crate::CliReviewProvider,
    )
    .map_err(anyhow::Error::msg)?;
    anyhow::ensure!(
        crate::capture_current_change_set(root, &current)
            .map(|captured| captured.digest == current.digest)
            .unwrap_or(false),
        "change snapshot became stale during test refinement; rerun against current changes"
    );
    let patch_text = test_generation::extract_patch(report.output["patch"].as_str().unwrap_or(""));
    anyhow::ensure!(
        !patch_text.trim().is_empty() && patch_text.len() <= MAX_TEST_PATCH_BYTES,
        "provider returned an empty or oversized test patch"
    );
    let patch = validate_test_patch(
        root,
        patch_text,
        "refined patch touches paths outside recognized test files",
    )?;
    let refined_id = test_proposal_id(&current.digest, &patch.digest)?;
    let attempt = parent["refinement"]["attempt"].as_u64().unwrap_or(0) + 1;
    save_proposal(&directory, &refined_id, &patch, |patch_path| {
        TestPatchProposal {
            schema_version: 2,
            approval_instruction: format!(
                "Inspect the refined diff, then run `vee tests apply {refined_id} --approve {refined_id}`. This is a new proposal; Vee has not applied it or run tests."
            ),
            proposal_id: refined_id.clone(),
            snapshot_id: report.snapshot_id,
            source_scope: current.scope,
            base_oid: current.base_oid,
            reviewer_id: report.reviewer_id,
            provider_id: report.provider_id,
            provider_kind: report.provider_kind,
            model: report.model,
            provider_output_digest: report.output_digest,
            context_summary,
            patch_digest: patch.digest.clone(),
            patch_path,
            validated_in_isolated_sandbox: true,
            sandbox_input_digest: patch.sandbox_input_digest.clone(),
            sandbox_result_digest: patch.sandbox_result_digest.clone(),
            application: "not_applied".to_owned(),
            tests_executed: false,
            verification_runs: Vec::new(),
            refinement: Some(ProposalRefinement {
                parent_proposal_id: proposal_id.to_owned(),
                failed_run_id: run_id.to_owned(),
                attempt,
            }),
        }
    })
}

/// Apply a saved test proposal after explicit approval of its exact ID,
/// re-validating its snapshot, targets and sandbox result first.
pub fn apply(
    workspace: &Workspace,
    proposal_id: &str,
    approval: &str,
) -> Result<TestProposalApplication> {
    require_proposal_id(proposal_id)?;
    if approval != proposal_id {
        return Err(usage_failure(
            "explicit approval must exactly match the generated test proposal ID",
        ));
    }
    let root = workspace.root();
    let directory = proposal_directory(root)?;
    let apply_lock = acquire_proposal_apply_lock(&directory)?;
    let record_file = record_path(&directory, proposal_id);
    let mut proposal = read_record(&directory, proposal_id, MAX_APPLY_RECORD_BYTES)?;
    anyhow::ensure!(
        proposal["application"].as_str() == Some("not_applied"),
        "test proposal was already applied or is not applicable"
    );
    let patch_digest = proposal["patch_digest"]
        .as_str()
        .context("test proposal has no patch digest")?;
    anyhow::ensure!(
        is_sha256_digest(patch_digest),
        "test proposal patch digest is invalid"
    );
    let patch_bytes = read_proposal_file(
        &patch_path(&directory, proposal_id),
        MAX_TEST_PATCH_BYTES as u64,
    )
    .context("saved test proposal patch is missing or invalid")?;
    anyhow::ensure!(
        vee_core::digest(&patch_bytes) == patch_digest,
        "saved test patch content has changed"
    );
    let source_snapshot_id = proposal["snapshot_id"]
        .as_str()
        .context("test proposal has no source snapshot")?;
    anyhow::ensure!(
        test_proposal_id(source_snapshot_id, patch_digest)? == proposal_id,
        "test proposal record does not match its approved content"
    );
    std::str::from_utf8(&patch_bytes).context("saved test patch is not UTF-8")?;
    let scope = recorded_scope(&proposal)?.to_owned();
    anyhow::ensure!(
        matches!(
            scope.as_str(),
            "staged" | "working_tree" | "base_and_worktree"
        ),
        "test proposals from immutable commit scopes cannot be applied"
    );
    let base_oid = proposal["base_oid"].as_str().map(str::to_owned);
    let source_snapshot = capture_recorded_scope(root, base_oid.as_deref(), &scope)?;
    anyhow::ensure!(
        proposal["snapshot_id"].as_str() == Some(source_snapshot.digest.as_str()),
        "source snapshot is stale; test patch was not applied"
    );
    let sandbox = patch_sandbox::validate_bytes(root, &patch_bytes).map_err(anyhow::Error::msg)?;
    anyhow::ensure!(
        !sandbox.result_files.is_empty()
            && sandbox
                .result_files
                .iter()
                .all(|file| test_generation::is_test_path(&file.path)),
        "saved proposal no longer contains test-only paths"
    );
    let input_digest =
        patch_sandbox::input_digest(&sandbox.input_files).map_err(anyhow::Error::msg)?;
    anyhow::ensure!(
        proposal["sandbox_input_digest"].as_str() == Some(input_digest.as_str()),
        "a test patch target changed since proposal validation"
    );
    anyhow::ensure!(
        proposal["sandbox_result_digest"].as_str() == Some(sandbox.result_digest.as_str()),
        "isolated test patch result differs from the approved proposal"
    );
    let index_flag = (scope == "staged").then_some("--index");
    let check_args: Vec<&str> = ["apply", "--check"].into_iter().chain(index_flag).collect();
    patch_sandbox::apply_bytes(root, &check_args, &patch_bytes).map_err(anyhow::Error::msg)?;
    let current = capture_recorded_scope(root, base_oid.as_deref(), &scope)?;
    anyhow::ensure!(
        current.digest == source_snapshot.digest,
        "source snapshot changed during test patch validation"
    );
    let final_inputs = vee_git::snapshot_files(root, &snapshot_paths(&sandbox.input_files))
        .map_err(anyhow::Error::msg)?;
    anyhow::ensure!(
        patch_sandbox::input_digest(&final_inputs).map_err(anyhow::Error::msg)? == input_digest,
        "a test patch target changed during validation"
    );
    let apply_args: Vec<&str> = ["apply"].into_iter().chain(index_flag).collect();
    patch_sandbox::apply_bytes(root, &apply_args, &patch_bytes).map_err(anyhow::Error::msg)?;
    let observed_outputs = vee_git::snapshot_files(root, &snapshot_paths(&sandbox.result_files))
        .map_err(anyhow::Error::msg)?;
    let post_snapshot =
        crate::capture_current_change_set(root, &source_snapshot).map_err(anyhow::Error::msg)?;
    let patch_paths = sandbox
        .result_files
        .iter()
        .map(|file| file.path.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let concurrent_mutation = observed_outputs != sandbox.result_files
        || unpatched_files(&source_snapshot, &patch_paths)
            != unpatched_files(&post_snapshot, &patch_paths);
    proposal["application"] = serde_json::Value::String("applied".into());
    proposal["approval_digest"] = serde_json::Value::String(approval.to_owned());
    proposal["applied_at_unix"] =
        serde_json::json!(crate::current_unix_time().map_err(anyhow::Error::msg)?);
    proposal["concurrent_mutation_detected"] = serde_json::Value::Bool(concurrent_mutation);
    proposal["post_application_snapshot_id"] =
        serde_json::Value::String(post_snapshot.digest.clone());
    write_record(&record_file, &proposal)?;
    drop(apply_lock);
    Ok(TestProposalApplication {
        schema_version: 1,
        proposal_id: proposal_id.to_owned(),
        application: "applied".to_owned(),
        snapshot_id: post_snapshot.digest,
        concurrent_mutation_detected: concurrent_mutation,
    })
}

fn snapshot_paths(files: &[vee_core::SnapshotFile]) -> Vec<std::path::PathBuf> {
    files
        .iter()
        .map(|file| std::path::PathBuf::from(&file.path))
        .collect()
}

/// Mode and content of every snapshot file the patch does not touch.
fn unpatched_files<'a>(
    snapshot: &'a ChangeSet,
    patch_paths: &std::collections::BTreeSet<&str>,
) -> std::collections::BTreeMap<&'a str, (u32, &'a str)> {
    snapshot
        .files
        .iter()
        .filter(|file| !patch_paths.contains(file.path.as_str()))
        .map(|file| {
            (
                file.path.as_str(),
                (file.mode, file.content_digest.as_str()),
            )
        })
        .collect()
}

/// Run a trusted verification profile on the snapshot an applied proposal
/// produced, and record the run against the proposal.
pub fn run(
    workspace: &Workspace,
    proposal_id: &str,
    profile_id: &str,
) -> Result<TestProposalVerification> {
    require_proposal_id(proposal_id)?;
    let root = workspace.root();
    let directory = proposal_directory(root)?;
    let apply_lock = acquire_proposal_apply_lock(&directory)?;
    let record_file = record_path(&directory, proposal_id);
    let mut proposal = read_record(&directory, proposal_id, MAX_APPLY_RECORD_BYTES)?;
    anyhow::ensure!(
        proposal["application"].as_str() == Some("applied"),
        "test proposal must be explicitly applied before it can run"
    );
    anyhow::ensure!(
        proposal["approval_digest"].as_str() == Some(proposal_id),
        "test proposal has no matching explicit approval record"
    );
    anyhow::ensure!(
        proposal["concurrent_mutation_detected"] == false,
        "test proposal application had a concurrent mutation; review the worktree and generate a new proposal"
    );
    let patch_digest = proposal["patch_digest"]
        .as_str()
        .context("test proposal has no patch digest")?;
    let patch_bytes = read_proposal_file(
        &patch_path(&directory, proposal_id),
        MAX_TEST_PATCH_BYTES as u64,
    )
    .context("saved test proposal patch is missing or invalid")?;
    anyhow::ensure!(
        vee_core::digest(&patch_bytes) == patch_digest,
        "saved test patch content has changed"
    );
    let source_snapshot_id = proposal["snapshot_id"]
        .as_str()
        .context("test proposal has no source snapshot")?;
    anyhow::ensure!(
        test_proposal_id(source_snapshot_id, patch_digest)? == proposal_id,
        "test proposal record does not match its approved content"
    );
    let snapshot = capture_recorded_scope(
        root,
        proposal["base_oid"].as_str(),
        recorded_scope(&proposal)?,
    )?;
    anyhow::ensure!(
        proposal["post_application_snapshot_id"].as_str() == Some(snapshot.digest.as_str()),
        "worktree no longer matches the snapshot produced by this test proposal"
    );
    let config = workspace.effective_config(None)?;
    anyhow::ensure!(
        config.verification.contains_key(profile_id),
        "unknown trusted verification profile {profile_id}"
    );
    let mut store = workspace.store()?;
    let run = crate::run_verification(root, &snapshot, profile_id, &config, &mut *store)
        .map_err(anyhow::Error::msg)?;
    let mut verification_runs = proposal["verification_runs"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    verification_runs.push(serde_json::to_value(ProposalVerificationRun {
        run_id: run.run_id.clone(),
        snapshot_id: run.snapshot_id.clone(),
        profile_id: run.profile_id.clone(),
        status: run.status,
    })?);
    proposal["verification_runs"] = serde_json::Value::Array(verification_runs);
    proposal["tests_executed"] = serde_json::Value::Bool(true);
    proposal["last_verification_run_id"] = serde_json::Value::String(run.run_id.clone());
    write_record(&record_file, &proposal)?;
    drop(apply_lock);
    Ok(TestProposalVerification {
        schema_version: 1,
        proposal_id: proposal_id.to_owned(),
        verification_run: run,
    })
}

/// An applied, approved proposal whose exact post-application snapshot has a
/// passing run of the trusted profile: the baseline for mutation testing.
struct EffectivenessBaseline {
    store: Box<dyn Repositories>,
    snapshot: ChangeSet,
    profile: vee_core::VerificationProfile,
    run_id: String,
}

fn effectiveness_baseline(
    workspace: &Workspace,
    proposal_id: &str,
    profile_id: &str,
) -> Result<EffectivenessBaseline> {
    anyhow::ensure!(
        is_sha256_digest(proposal_id),
        "test proposal ID must be a full sha256:<hex> digest"
    );
    let root = workspace.root();
    let directory = proposal_directory(root)?;
    let proposal = read_record(&directory, proposal_id, MAX_PROPOSAL_RECORD_BYTES)?;
    anyhow::ensure!(
        proposal["application"] == "applied"
            && proposal["approval_digest"].as_str() == Some(proposal_id),
        "test proposal must be explicitly approved and applied before effectiveness assessment"
    );
    anyhow::ensure!(
        proposal["concurrent_mutation_detected"] == false,
        "proposal application had concurrent mutations"
    );
    let scope = proposal["source_scope"]
        .as_str()
        .context("proposal has no source scope")?;
    let snapshot = capture_recorded_scope(root, proposal["base_oid"].as_str(), scope)?;
    anyhow::ensure!(
        proposal["post_application_snapshot_id"].as_str() == Some(snapshot.digest.as_str()),
        "worktree no longer matches the proposal's applied snapshot"
    );
    let saved_patch = read_proposal_file(
        &patch_path(&directory, proposal_id),
        MAX_TEST_PATCH_BYTES as u64,
    )?;
    let patch_digest = vee_core::digest(&saved_patch);
    anyhow::ensure!(
        proposal["patch_digest"].as_str() == Some(patch_digest.as_str())
            && test_proposal_id(
                proposal["snapshot_id"].as_str().unwrap_or_default(),
                &patch_digest
            )? == proposal_id,
        "test proposal integrity check failed"
    );
    let config = workspace.effective_config(None)?;
    let profile = config
        .verification
        .get(profile_id)
        .context("unknown trusted verification profile")?;
    let expected_command_digest =
        vee_process::verification_command_digest(profile, root).map_err(anyhow::Error::msg)?;
    let store = workspace.store()?;
    let run_id = proposal["verification_runs"]
        .as_array()
        .context("proposal has no verification history")?
        .iter()
        .filter(|entry| {
            entry["profile_id"].as_str() == Some(profile_id)
                && entry["snapshot_id"].as_str() == Some(snapshot.digest.as_str())
                && entry["status"] == "passed"
        })
        .filter_map(|entry| entry["run_id"].as_str())
        .find(|run_id| {
            store
                .verification(run_id)
                .ok()
                .flatten()
                .is_some_and(|run| {
                    run.status == VerificationStatus::Passed
                        && run.snapshot_id == snapshot.digest
                        && run.profile_id == profile_id
                        && run.command_digest == expected_command_digest
                })
        })
        .context("effectiveness assessment requires a passing run for this trusted profile and exact proposal snapshot")?
        .to_owned();
    Ok(EffectivenessBaseline {
        store,
        snapshot,
        profile: profile.clone(),
        run_id,
    })
}

/// Changed-line coverage from the baseline run's LCOV output, or the reason it
/// could not be attached.
fn baseline_coverage(
    root: &Path,
    baseline: &EffectivenessBaseline,
) -> (Option<crate::coverage::CoverageReport>, String) {
    let result = (|| -> Result<crate::coverage::CoverageReport> {
        let run = baseline
            .store
            .verification(&baseline.run_id)
            .map_err(anyhow::Error::msg)?
            .context("passing verification run was not found")?;
        crate::coverage::report_for_change_set(root, &run, "stdout", &baseline.snapshot)
            .or_else(|_| {
                crate::coverage::report_for_change_set(root, &run, "stderr", &baseline.snapshot)
            })
            .map_err(anyhow::Error::msg)
    })();
    match result {
        Ok(report) => (Some(report), String::new()),
        Err(error) => (
            None,
            format!("Changed-line coverage could not be attached: {error}"),
        ),
    }
}

/// Save a report under `.vee/effectiveness/<prefix>-<digest>.json`; an existing
/// artifact with the same digest must hold the same bytes.
fn persist_assessment<R: Serialize>(
    root: &Path,
    prefix: &str,
    report: R,
    max_existing_bytes: u64,
    mismatch: &str,
) -> Result<PersistedAssessment<R>> {
    let directory = root.join(".vee/effectiveness");
    std::fs::create_dir_all(&directory)?;
    anyhow::ensure!(
        std::fs::symlink_metadata(&directory)?.file_type().is_dir(),
        "effectiveness artifact directory must be a real directory"
    );
    let bytes = serde_json::to_vec_pretty(&report)?;
    let digest = vee_core::digest(&bytes);
    let path = directory.join(format!("{prefix}-{}.json", &digest[7..]));
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(mut file) => file.write_all(&bytes)?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            anyhow::ensure!(
                read_proposal_file(&path, max_existing_bytes)? == bytes,
                "{mismatch}"
            );
        }
        Err(error) => return Err(error.into()),
    }
    Ok(PersistedAssessment {
        report,
        artifact_path: path.to_string_lossy().into_owned(),
        artifact_digest: digest,
    })
}

/// Check whether the trusted profile kills one source mutant supplied as a
/// patch outside the repository; the worktree is left unchanged.
pub fn assess_effectiveness(
    workspace: &Workspace,
    proposal_id: &str,
    profile_id: &str,
    mutant_patch: &Path,
) -> Result<PersistedAssessment<EffectivenessReport>> {
    let baseline = effectiveness_baseline(workspace, proposal_id, profile_id)?;
    let root = workspace.root();
    let root_canonical = vee_core::paths::canonicalize(root)?;
    let patch_canonical = vee_core::paths::canonicalize(mutant_patch)?;
    anyhow::ensure!(
        !patch_canonical.starts_with(&root_canonical),
        "mutant patch must be outside the repository so it cannot change the reviewed snapshot"
    );
    let mutant_meta = std::fs::symlink_metadata(&patch_canonical)?;
    anyhow::ensure!(
        mutant_meta.file_type().is_file() && mutant_meta.len() <= MAX_TEST_PATCH_BYTES as u64,
        "mutant patch must be a regular file no larger than 2 MiB"
    );
    let mutant_bytes = std::fs::read(&patch_canonical)?;
    let mut assessment = test_effectiveness::assess(
        root,
        &baseline.snapshot,
        proposal_id,
        profile_id,
        &baseline.run_id,
        &baseline.profile,
        &mutant_bytes,
    )
    .map_err(anyhow::Error::msg)?;
    let (coverage, coverage_limitation) = baseline_coverage(root, &baseline);
    test_effectiveness::attach_coverage(&mut assessment, coverage.as_ref());
    if !coverage_limitation.is_empty() {
        assessment.limitations.push(coverage_limitation);
    }
    persist_assessment(
        root,
        "assessment",
        assessment,
        MAX_PROPOSAL_RECORD_BYTES,
        "existing effectiveness artifact has different content",
    )
}

/// Assess the trusted profile against every mutant of a digest-pinned corpus.
pub fn assess_effectiveness_corpus(
    workspace: &Workspace,
    proposal_id: &str,
    profile_id: &str,
    manifest: &Path,
) -> Result<PersistedAssessment<CorpusEffectivenessReport>> {
    let baseline = effectiveness_baseline(workspace, proposal_id, profile_id)?;
    let root = workspace.root();
    let mut assessment = test_effectiveness::assess_corpus(
        root,
        &baseline.snapshot,
        proposal_id,
        profile_id,
        &baseline.run_id,
        &baseline.profile,
        manifest,
    )
    .map_err(anyhow::Error::msg)?;
    let (coverage, coverage_limitation) = baseline_coverage(root, &baseline);
    test_effectiveness::attach_corpus_coverage(&mut assessment, coverage.as_ref());
    if !coverage_limitation.is_empty() {
        assessment.limitations.push(coverage_limitation);
    }
    persist_assessment(
        root,
        "corpus",
        assessment,
        8 * 1024 * 1024,
        "existing corpus assessment artifact has different content",
    )
}
