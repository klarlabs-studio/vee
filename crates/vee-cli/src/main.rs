use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    process::ExitCode,
};
use vee_core::ports::*;
use vee_core::{
    ChangeSet, GateStatus, RepositoryConfig, Severity, VerificationRun, VerificationStatus,
};
use vee_store_sqlite::ReviewStore;

use vee_application::acceptance;
use vee_application::attestation;
mod contracts;
use vee_application::coverage;
use vee_application::failure::{
    configuration_failure, usage_failure, ConfigurationFailure, UsageFailure,
};
use vee_application::imported_history::{
    imported_reviews_dir, parse_portable_review, store_imported_history, MAX_IMPORTED_REVIEW_BYTES,
};
use vee_application::proposals::{proposal_directory, read_proposal_file};
use vee_application::work_items::{
    effective_work_item_host, effective_work_item_token_env, get_work_item, work_item_api_base,
};
mod mcp;
use vee_application::operations;
use vee_application::packs;
use vee_application::patch_sandbox;
use vee_application::repository_map;
use vee_application::standards;
use vee_application::test_effectiveness;
use vee_application::test_generation;
use vee_application::verification_diagnosis;

/// The local SQLite stores that the CLI and MCP server hand to application services.
fn local_stores() -> std::sync::Arc<dyn vee_core::ports::RepositoryStores + Send + Sync> {
    std::sync::Arc::new(vee_store_sqlite::SqliteRepositoryStores)
}

fn current_unix_time() -> Result<i64> {
    vee_application::current_unix_time().map_err(anyhow::Error::msg)
}

fn load_repository_config(root: &std::path::Path) -> Result<RepositoryConfig> {
    vee_application::load_repository_config(root).map_err(configuration_failure)
}

fn is_sha256_digest(value: &str) -> bool {
    value.starts_with("sha256:")
        && value.len() == 71
        && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

struct PreparedEffectiveness {
    root: std::path::PathBuf,
    snapshot: ChangeSet,
    profile: vee_core::VerificationProfile,
    baseline_run_id: String,
}

fn prepare_effectiveness(proposal_id: &str, profile_id: &str) -> Result<PreparedEffectiveness> {
    anyhow::ensure!(
        is_sha256_digest(proposal_id),
        "test proposal ID must be a full sha256:<hex> digest"
    );
    let cwd = std::env::current_dir()?;
    let root = vee_git::repository_root(&cwd).map_err(anyhow::Error::msg)?;
    let proposal_dir = proposal_directory(&root)?;
    let record_path = proposal_dir.join(format!("test-{}.json", &proposal_id[7..]));
    let proposal: serde_json::Value = serde_json::from_slice(
        &read_proposal_file(&record_path, 2 * 1024 * 1024)
            .with_context(|| format!("test proposal {proposal_id} was not found"))?,
    )?;
    anyhow::ensure!(
        proposal["schema_version"] == 2,
        "unsupported test proposal schema"
    );
    anyhow::ensure!(
        proposal["proposal_id"].as_str() == Some(proposal_id),
        "test proposal ID does not match its record"
    );
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
    let base_oid = proposal["base_oid"].as_str();
    let root_string = root.to_string_lossy().to_string();
    let snapshot = current_change_set(&root_string, base_oid, scope)?;
    anyhow::ensure!(
        proposal["post_application_snapshot_id"].as_str() == Some(snapshot.digest.as_str()),
        "worktree no longer matches the proposal's applied snapshot"
    );
    let saved_patch = read_proposal_file(
        &proposal_dir.join(format!("test-{}.patch", &proposal_id[7..])),
        2 * 1024 * 1024,
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
    let mut config = load_repository_config(&root)?;
    apply_protected_policy(&root, &mut config)?;
    let profile = config
        .verification
        .get(profile_id)
        .context("unknown trusted verification profile")?;
    let expected_command_digest =
        vee_process::verification_command_digest(profile, &root).map_err(anyhow::Error::msg)?;
    let store = ReviewStore::open(&root.join(".vee/vee.sqlite")).map_err(anyhow::Error::msg)?;
    let baseline_run_id = proposal["verification_runs"]
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
    Ok(PreparedEffectiveness {
        root,
        snapshot,
        profile: profile.clone(),
        baseline_run_id,
    })
}

fn effectiveness_coverage(
    root: &std::path::Path,
    run_id: &str,
    snapshot: &ChangeSet,
) -> (Option<coverage::CoverageReport>, String) {
    let result = (|| -> Result<coverage::CoverageReport> {
        let store = ReviewStore::open(&root.join(".vee/vee.sqlite")).map_err(anyhow::Error::msg)?;
        let run = store
            .verification(run_id)
            .map_err(anyhow::Error::msg)?
            .context("passing verification run was not found")?;
        coverage::report_for_change_set(root, &run, "stdout", snapshot)
            .or_else(|_| coverage::report_for_change_set(root, &run, "stderr", snapshot))
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

fn test_proposal_id(snapshot_id: &str, patch_digest: &str) -> Result<String> {
    Ok(vee_core::digest(&serde_json::to_vec(&(
        "vee-test-patch-proposal-v2",
        snapshot_id,
        patch_digest,
    ))?))
}

fn write_proposal_file(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            anyhow::ensure!(
                metadata.file_type().is_file(),
                "proposal artifact must be a regular file"
            );
            std::fs::write(path, bytes)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)?;
            file.write_all(bytes)?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn write_new_proposal_file(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| {
            format!(
                "refusing to overwrite existing proposal artifact {}",
                path.display()
            )
        })?;
    file.write_all(bytes)?;
    Ok(())
}

struct ProposalApplyLock(std::path::PathBuf);

impl Drop for ProposalApplyLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn acquire_proposal_apply_lock(directory: &std::path::Path) -> Result<ProposalApplyLock> {
    let path = directory.join("apply.lock");
    let mut file = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            anyhow::bail!(
                "another Vee patch application is in progress ({}); if this lock is stale, verify no apply-patch process is running before removing it",
                path.display()
            )
        }
        Err(error) => return Err(error.into()),
    };
    writeln!(
        file,
        "pid={} started_unix={}",
        std::process::id(),
        current_unix_time()?
    )?;
    file.sync_all()?;
    Ok(ProposalApplyLock(path))
}

fn resolve_hosting_setting(
    command_line: Option<String>,
    repository: Option<String>,
    fallback: &str,
) -> String {
    command_line
        .or(repository)
        .unwrap_or_else(|| fallback.to_owned())
}

fn load_hosting_config(root: &std::path::Path) -> Result<(bool, vee_core::HostingConfig)> {
    if !root.join(".vee.yaml").exists() {
        return Ok((false, vee_core::HostingConfig::default()));
    }
    let config = load_repository_config(root)?;
    Ok((config.offline, config.hosting))
}

fn apply_protected_policy(root: &std::path::Path, config: &mut RepositoryConfig) -> Result<()> {
    vee_application::apply_protected_policy(root, config).map_err(configuration_failure)
}

fn classify_error(error: &anyhow::Error) -> (&'static str, u8) {
    if error
        .chain()
        .any(|cause| cause.is::<clap::Error>() || cause.is::<UsageFailure>())
    {
        ("usage_error", 3)
    } else if error
        .chain()
        .any(|cause| cause.is::<ConfigurationFailure>())
    {
        ("configuration_error", 3)
    } else {
        ("execution_failed", 2)
    }
}

#[derive(Parser)]
#[command(name = "vee", version, about = "Local-first code change assurance")]
struct Cli {
    /// When to color text output: auto (a terminal, unless NO_COLOR is set), always, or never.
    #[arg(long, global = true, value_enum, default_value_t = ColorArg::Auto)]
    color: ColorArg,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum ColorArg {
    Auto,
    Always,
    Never,
}

/// Whether text output is colored, decided once from `--color` and the environment.
static COLOR: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

fn set_color(choice: ColorArg) {
    let enabled = match choice {
        ColorArg::Always => true,
        ColorArg::Never => false,
        // Honors NO_COLOR, CLICOLOR, CLICOLOR_FORCE and whether stdout is a terminal.
        ColorArg::Auto => !matches!(
            anstream::AutoStream::choice(&std::io::stdout()),
            anstream::ColorChoice::Never
        ),
    };
    let _ = COLOR.set(enabled);
}

/// Prints the shared view of a result document: the same view MCP returns as Markdown.
fn print_view(document: &impl vee_present::ToView) -> Result<()> {
    let text = vee_present::ansi::render(&document.to_view(), *COLOR.get().unwrap_or(&false));
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(text.as_bytes())?;
    Ok(())
}
#[derive(Subcommand)]
enum Command {
    /// Set up Vee: create .vee.yaml and reviewer instructions, and configure this
    /// machine's AI provider from the backends detected (local model first). In a
    /// repository that already has .vee.yaml, configures only this machine.
    Init {
        /// Backend to use instead of the recommended one (see `vee providers detect`).
        #[arg(long, value_name = "CANDIDATE")]
        provider: Option<String>,
        /// Model for the chosen backend; required for API keys, optional for Ollama.
        #[arg(long)]
        model: Option<String>,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Check whether this repository's reviewers can run on this machine (exit 0 when ready, 2 when not).
    Doctor {
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Discover the AI backends available on this machine.
    Providers {
        #[command(subcommand)]
        command: ProvidersCommand,
    },
    /// Share policy across repositories as digest-pinned policy packs.
    Packs {
        #[command(subcommand)]
        command: PacksCommand,
    },
    /// Print a shell completion script to stdout (for example: `vee completions zsh > ~/.zfunc/_vee`).
    Completions {
        /// Shell to generate completions for.
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
    /// List or install bundled agent workflow skills.
    Skills {
        #[command(subcommand)]
        command: SkillsCommand,
    },
    /// Resolve repository guidance that applies to a target path.
    Standards {
        /// Repository-relative path whose applicable standards should be resolved.
        #[arg(long, value_name = "PATH")]
        path: Option<std::path::PathBuf>,
        /// Explicitly fetch one HTTPS standards document into the local cache.
        #[arg(long, value_name = "HTTPS_URL")]
        sync_url: Option<String>,
        /// Identifier for the remote standards source being synced or removed.
        #[arg(long, value_name = "ID")]
        source_id: Option<String>,
        /// Repository path glob the remote standards source applies to.
        #[arg(long, value_name = "SCOPE")]
        source_scope: Option<String>,
        /// Optional expected digest in sha256:<hex> form.
        #[arg(long, value_name = "DIGEST")]
        expected_digest: Option<String>,
        /// Remove a previously synced source and its cached content.
        #[arg(long, value_name = "ID")]
        remove_source: Option<String>,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Resolve advisory CODEOWNERS for repository paths.
    Owners {
        /// Repository-relative path to resolve owners for (repeatable).
        #[arg(long = "path", required = true, value_name = "PATH")]
        paths: Vec<std::path::PathBuf>,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Mine repeated human feedback into reviewable rule suggestions.
    Rules {
        #[command(subcommand)]
        command: RulesCommand,
    },
    /// Review a change scope with the configured reviewers and save the result.
    Review {
        /// Use changes since the merge base with this Git ref.
        #[arg(long)]
        base: Option<String>,
        /// Use the changes introduced by this commit.
        #[arg(long, conflicts_with_all = ["base", "staged", "working_tree"])]
        commit: Option<String>,
        /// Use only staged changes.
        #[arg(long)]
        staged: bool,
        /// Use staged and unstaged working-tree changes.
        #[arg(long)]
        working_tree: bool,
        /// Evaluate the deterministic gate after the review and exit 1 on block, 2 on incomplete.
        #[arg(long)]
        gate: bool,
        /// Named policy profile from .vee.yaml to apply.
        #[arg(long, value_name = "NAME")]
        policy_profile: Option<String>,
        /// Run only these configured reviewer IDs (repeatable).
        #[arg(long = "reviewer")]
        reviewer_ids: Vec<String>,
        /// Review effort for every reviewer, replacing configured sampling: low runs each
        /// reviewer once, medium three times, high five times. Findings most runs agree on can block.
        #[arg(long, value_enum)]
        effort: Option<EffortArg>,
        /// Attach hosting issue context as untrusted, digest-bound reviewer input (OWNER/REPO#NUMBER).
        #[arg(long, value_name = "OWNER/REPO#NUMBER")]
        work_item: Option<String>,
        /// Git hosting provider for --work-item context.
        #[arg(long, value_parser = ["github", "gitlab", "azure-devops"])]
        hosting_provider: Option<String>,
        /// Hosting server host name for --work-item (self-hosted instances).
        #[arg(long)]
        hosting_host: Option<String>,
        /// Hosting API base URL for --work-item (defaults per provider).
        #[arg(long, value_name = "URL")]
        hosting_api_base: Option<String>,
        /// Environment variable holding the hosting token for --work-item.
        #[arg(long, value_name = "ENV_VAR")]
        hosting_token_env: Option<String>,
        /// Also write a Markdown report to this path.
        #[arg(long, value_name = "PATH")]
        markdown: Option<std::path::PathBuf>,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Analyze which files and tests a change is likely to affect.
    Impact {
        /// Analyze a saved review's exact snapshot instead of capturing a scope; fails if the source changed.
        #[arg(long, value_name = "REVIEW_ID", conflicts_with_all = ["base", "commit", "staged", "working_tree"])]
        review: Option<String>,
        /// Use changes since the merge base with this Git ref.
        #[arg(long, conflicts_with_all = ["staged", "working_tree"])]
        base: Option<String>,
        /// Use the changes introduced by this commit.
        #[arg(long, conflicts_with_all = ["base", "staged", "working_tree"])]
        commit: Option<String>,
        /// Use only staged changes.
        #[arg(long, conflicts_with = "working_tree")]
        staged: bool,
        /// Use staged and unstaged working-tree changes.
        #[arg(long)]
        working_tree: bool,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Produce deterministic, evidence-limited test gap recommendations.
    Tests {
        #[command(subcommand)]
        command: TestsCommand,
    },
    /// Draft a pull request title and description from an exact local change snapshot.
    Pr {
        #[command(subcommand)]
        command: PrCommand,
    },
    /// Trace explicit work-item acceptance criteria against one saved review.
    Acceptance {
        #[command(subcommand)]
        command: AcceptanceCommand,
    },
    /// Evaluate or inspect deterministic gate decisions for saved reviews.
    Gate {
        #[command(subcommand)]
        command: GateCommand,
    },
    /// Inspect, resolve, and give feedback on review findings.
    Findings {
        #[command(subcommand)]
        command: FindingsCommand,
    },
    /// Create or list snapshot-scoped finding waivers.
    Waivers {
        #[command(subcommand)]
        command: WaiversCommand,
    },
    /// Run a trusted verification profile against the current snapshot.
    Verify {
        /// Finding to verify; omit to verify the current snapshot as a whole.
        finding_id: Option<String>,
        /// Verification profile ID from .vee.yaml.
        #[arg(long)]
        profile: String,
        /// Expand `{impacted_test_packages}` (Go) or `{impacted_rust_test_filters}` (Rust) in profile argv.
        #[arg(long, conflicts_with = "finding_id")]
        impacted_tests: bool,
        /// Use the changes introduced by this commit.
        #[arg(long, conflicts_with_all = ["base", "staged", "working_tree"])]
        commit: Option<String>,
        /// Use changes since the merge base with this Git ref.
        #[arg(long, conflicts_with_all = ["staged", "working_tree"])]
        base: Option<String>,
        /// Use only staged changes.
        #[arg(long, conflicts_with = "working_tree")]
        staged: bool,
        /// Use staged and unstaged working-tree changes.
        #[arg(long)]
        working_tree: bool,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Inspect saved verification runs and their diagnostics.
    Verification {
        #[command(subcommand)]
        command: VerificationCommand,
    },
    /// List, export, bundle, sign, and import saved reviews.
    Reviews {
        #[command(subcommand)]
        command: ReviewsCommand,
    },
    /// Summarize local review, gate, and finding lifecycle outcomes.
    Analytics {
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Inspect direct package dependencies across explicitly selected local repositories.
    Repos {
        #[command(subcommand)]
        command: ReposCommand,
    },
    /// Publish a saved local review to a Git hosting pull request.
    Hosting {
        #[command(subcommand)]
        command: HostingCommand,
    },
    /// Run Vee as a Model Context Protocol server for coding agents.
    Mcp {
        #[command(subcommand)]
        command: McpCommand,
    },
    /// Serve the local web dashboard on a loopback address.
    Ui {
        /// Loopback address to listen on (127.0.0.1 or ::1).
        #[arg(long, default_value = "127.0.0.1")]
        host: std::net::IpAddr,
        /// Loopback port to listen on.
        #[arg(long, default_value_t = 7878)]
        port: u16,
        /// Reserved; direct network access requires native TLS support.
        #[arg(long, default_value_t = false)]
        allow_network: bool,
    },
}
#[derive(Subcommand)]
enum McpCommand {
    /// Serve MCP tools over stdio for the current repository.
    Serve {
        /// MCP transport (stdio is the only supported transport).
        #[arg(long, default_value = "stdio", value_parser = ["stdio"])]
        transport: String,
    },
}
#[derive(Subcommand)]
enum SkillsCommand {
    /// List the bundled agent skills.
    List,
    /// Install the bundled agent skills into this repository.
    Install {
        /// Replace existing Vee skill files.
        #[arg(long)]
        force: bool,
    },
}
#[derive(Subcommand)]
enum ReposCommand {
    /// Build a deterministic local manifest dependency map.
    Map {
        /// Local repository checkouts to include.
        #[arg(required = true, value_name = "REPOSITORY_PATH")]
        repositories: Vec<std::path::PathBuf>,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Capture a digest-bound working-tree change package across related checkouts.
    Package {
        /// Local repository checkouts to include in the change package.
        #[arg(required = true, value_name = "REPOSITORY_PATH")]
        repositories: Vec<std::path::PathBuf>,
        /// Bind a selected local repository to a provider PR: REPO_ID=HOST/OWNER/REPO#NUMBER.
        /// Repeat to include multiple linked changes in the same checkout.
        #[arg(long = "link-pr", value_name = "REPOSITORY_ID=HOST/OWNER/REPO#NUMBER")]
        pull_requests: Vec<String>,
        /// Discover linked PRs only from provider-specific local refs exactly matching HEAD.
        #[arg(long)]
        discover_linked_prs: bool,
        /// Fetch current provider state for linked PRs using each repository's configured hosting adapter.
        #[arg(long)]
        refresh_pr_links: bool,
        /// Resolve this ref to a merge-base independently in every checkout.
        #[arg(long)]
        base: Option<String>,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Find potential Rust symbol references in selected consumer checkouts.
    Impact {
        /// Repository whose changes are the source of impact.
        #[arg(value_name = "PRODUCER_REPOSITORY")]
        producer: std::path::PathBuf,
        /// Local consumer repository checkouts to analyze.
        #[arg(required = true, value_name = "CONSUMER_REPOSITORY")]
        consumers: Vec<std::path::PathBuf>,
        /// Use changes since the merge base with this Git ref.
        #[arg(long, required = true, value_name = "GIT_REF")]
        base: String,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
}
#[derive(Subcommand)]
enum RulesCommand {
    /// List rule candidates mined from repeated human feedback.
    Candidates {
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Approve explicitly written reviewer guidance for a current candidate.
    Approve {
        /// Candidate ID from `vee rules candidates`.
        candidate_id: String,
        /// Evidence digest reported for the candidate; approval fails if evidence changed.
        #[arg(long)]
        evidence_digest: String,
        /// Repository-relative file or directory the approved guidance applies to (no globs or `..`).
        #[arg(long)]
        scope: String,
        /// Reviewer guidance text to activate.
        #[arg(long)]
        instruction: String,
        /// Name of the person approving the guidance.
        #[arg(long)]
        approver: String,
        /// Why the guidance is being approved.
        #[arg(long)]
        reason: String,
        /// Replace this prior approval with a new immutable version.
        #[arg(long)]
        supersedes: Option<String>,
        /// Expire the approval after this many days (1 to 3650).
        #[arg(long)]
        expires_in_days: Option<u32>,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// List guidance approvals and their audit events.
    List {
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Revoke an approval without deleting its audit history.
    Revoke {
        /// Approval ID to revoke.
        approval_id: String,
        /// Name of the person revoking the approval.
        #[arg(long)]
        actor: String,
        /// Why the approval is being revoked.
        #[arg(long)]
        reason: String,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Report later human feedback for occurrences in an approved rule category.
    Effectiveness {
        /// Limit the report to one approval ID.
        #[arg(long)]
        approval_id: Option<String>,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
}
#[derive(Subcommand)]
enum TestsCommand {
    /// Show impact-selected trusted test commands without executing them.
    Plan {
        /// Use changes since the merge base with this Git ref.
        #[arg(long, conflicts_with_all = ["staged", "working_tree"])]
        base: Option<String>,
        /// Use only staged changes.
        #[arg(long, conflicts_with = "working_tree")]
        staged: bool,
        /// Use staged and unstaged working-tree changes.
        #[arg(long)]
        working_tree: bool,
        /// Verification profile whose test selection is planned.
        #[arg(long, required = true)]
        profile: String,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Recommend missing tests for the current change.
    Recommend {
        /// Analyze a saved review's exact snapshot instead of capturing a scope; fails if the source changed.
        #[arg(long, value_name = "REVIEW_ID", conflicts_with_all = ["base", "commit", "staged", "working_tree"])]
        review: Option<String>,
        /// Use changes since the merge base with this Git ref.
        #[arg(long, conflicts_with_all = ["staged", "working_tree"])]
        base: Option<String>,
        /// Use the changes introduced by this commit.
        #[arg(long, conflicts_with_all = ["base", "staged", "working_tree"])]
        commit: Option<String>,
        /// Use only staged changes.
        #[arg(long, conflicts_with = "working_tree")]
        staged: bool,
        /// Use staged and unstaged working-tree changes.
        #[arg(long)]
        working_tree: bool,
        /// Include a persisted LCOV verification run for this exact change snapshot.
        #[arg(long)]
        coverage_run: Option<String>,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Generate a snapshot-bound test patch proposal; never applies or runs it.
    Generate {
        /// Use changes since the merge base with this Git ref.
        #[arg(long, conflicts_with_all = ["staged", "working_tree", "commit"])]
        base: Option<String>,
        /// Use only staged changes.
        #[arg(long, conflicts_with_all = ["base", "working_tree", "commit"])]
        staged: bool,
        /// Use staged and unstaged working-tree changes.
        #[arg(long, conflicts_with_all = ["base", "staged", "commit"])]
        working_tree: bool,
        /// Use the changes introduced by this commit.
        #[arg(long, conflicts_with_all = ["base", "staged", "working_tree"])]
        commit: Option<String>,
        /// Configured reviewer that drafts the test patch.
        #[arg(long, default_value = "correctness")]
        reviewer: String,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Create a new test-only proposal from a failed run linked to an applied proposal.
    Refine {
        /// Applied test proposal to refine.
        proposal_id: String,
        /// Failed verification run ID that guides the refinement.
        #[arg(long, required = true)]
        run: String,
        /// Configured reviewer that drafts the refined test patch.
        #[arg(long, default_value = "correctness")]
        reviewer: String,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Measure whether the selected trusted profile kills a supplied source mutant.
    Effectiveness {
        /// Applied test proposal to assess.
        proposal_id: String,
        /// Trusted verification profile used to run the tests.
        #[arg(long, required = true)]
        profile: String,
        /// Unified diff that introduces the mutant.
        #[arg(long = "mutant-patch", required = true)]
        mutant_patch: std::path::PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Measure generated-test effectiveness across a digest-pinned mutant corpus.
    EffectivenessCorpus {
        /// Applied test proposal to assess.
        proposal_id: String,
        /// Trusted verification profile used to run the tests.
        #[arg(long, required = true)]
        profile: String,
        /// Digest-pinned mutant corpus manifest (JSON).
        #[arg(long = "manifest", required = true)]
        manifest: std::path::PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Apply a previously generated test patch after exact-digest approval.
    Apply {
        /// Test proposal ID to apply.
        proposal_id: String,
        /// Exact proposal digest, confirming you reviewed this patch.
        #[arg(long, required = true)]
        approve: String,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Run a trusted verification profile against an applied generated-test proposal.
    Run {
        /// Applied test proposal whose tests should run.
        proposal_id: String,
        /// Trusted verification profile used to run the tests.
        #[arg(long, required = true)]
        profile: String,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
}
#[derive(Subcommand)]
enum PrCommand {
    /// Draft a pull request title and body with a configured reviewer.
    Draft {
        /// Analyze a saved review's exact snapshot instead of capturing a scope; fails if the source changed.
        #[arg(long, value_name = "REVIEW_ID", conflicts_with_all = ["base", "commit", "staged", "working_tree"])]
        review: Option<String>,
        /// Use changes since the merge base with this Git ref.
        #[arg(long, conflicts_with_all = ["staged", "working_tree", "commit"])]
        base: Option<String>,
        /// Use only staged changes.
        #[arg(long, conflicts_with_all = ["base", "working_tree", "commit"])]
        staged: bool,
        /// Use staged and unstaged working-tree changes.
        #[arg(long, conflicts_with_all = ["base", "staged", "commit"])]
        working_tree: bool,
        /// Use the changes introduced by this commit.
        #[arg(long, conflicts_with_all = ["base", "staged", "working_tree"])]
        commit: Option<String>,
        /// Configured reviewer whose provider and instruction file draft the artifact.
        #[arg(long, default_value = "correctness")]
        reviewer: String,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
}
#[derive(Subcommand)]
enum AcceptanceCommand {
    /// Report candidate changed files and snapshot-bound verification for criteria.
    Report {
        /// Saved review ID.
        #[arg(long, value_name = "REVIEW_ID")]
        review: String,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Validate a human traceability mapping against a saved review and snapshot.
    Validate {
        /// Saved review ID.
        #[arg(long, value_name = "REVIEW_ID")]
        review: String,
        /// Path to the acceptance mapping file (JSON or YAML).
        #[arg(long, value_name = "PATH")]
        mapping: std::path::PathBuf,
        /// Enforce the attestation result: 0 met, 1 not met, 2 incomplete.
        /// This evaluates human traceability attestations, not behavioral proof.
        #[arg(long)]
        gate: bool,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
}

const AGENT_SKILLS: &[(&str, &str)] = &[
    (
        "vee-codebase-context",
        include_str!("../skills/vee-codebase-context/SKILL.md"),
    ),
    (
        "vee-standards",
        include_str!("../skills/vee-standards/SKILL.md"),
    ),
    (
        "vee-local-review",
        include_str!("../skills/vee-local-review/SKILL.md"),
    ),
    (
        "vee-investigate-findings",
        include_str!("../skills/vee-investigate-findings/SKILL.md"),
    ),
    (
        "vee-resolve-findings",
        include_str!("../skills/vee-resolve-findings/SKILL.md"),
    ),
    (
        "vee-requirement-traceability",
        include_str!("../skills/vee-requirement-traceability/SKILL.md"),
    ),
];
static SKILL_TEMP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
#[derive(Subcommand)]
enum VerificationCommand {
    /// List verification runs for an exact immutable snapshot.
    List {
        /// Snapshot ID whose verification runs should be listed.
        #[arg(long, required = true)]
        snapshot: String,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Show a verification run with its captured output references.
    Show {
        /// Verification run ID.
        run_id: String,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Parse a saved verification run into bounded, snapshot-linked diagnostics.
    Diagnose {
        /// Verification run ID.
        run_id: String,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Summarize snapshot-bound LCOV data for changed files.
    Coverage {
        /// Verification run ID.
        run_id: String,
        /// Which captured stream contains the LCOV data.
        #[arg(long, value_enum, default_value = "stdout")]
        stream: CoverageStream,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Show a SARIF analyzer run's results on changed lines, as the gate evaluates them.
    Findings {
        /// Verification run ID of a profile configured with `sarif`.
        run_id: String,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum EffortArg {
    Low,
    Medium,
    High,
}

impl From<EffortArg> for vee_core::ReviewEffort {
    fn from(effort: EffortArg) -> Self {
        match effort {
            EffortArg::Low => Self::Low,
            EffortArg::Medium => Self::Medium,
            EffortArg::High => Self::High,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum AttestationFormat {
    Dsse,
    Statement,
}
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum CoverageStream {
    Stdout,
    Stderr,
}
#[derive(Subcommand)]
enum ReviewsCommand {
    /// List saved reviews.
    List {
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Show a saved review.
    Show {
        /// Saved review ID.
        id: String,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Export a saved review as SARIF or Vee JSON.
    Export {
        /// Saved review ID.
        id: String,
        /// Export format.
        #[arg(long, value_enum, default_value = "sarif")]
        format: ReportFormat,
    },
    /// Export a self-contained, digest-verified gate evidence bundle.
    Bundle {
        /// Saved review ID.
        id: String,
        /// Export a particular persisted gate decision; defaults to the latest decision.
        #[arg(long)]
        decision_id: Option<String>,
    },
    /// Export a gate decision as an in-toto attestation (DSSE-signed by default) for supply-chain tooling.
    Attest {
        /// Saved review ID.
        id: String,
        /// Attest a particular persisted gate decision; defaults to the latest decision.
        #[arg(long)]
        decision_id: Option<String>,
        /// `dsse`: an Ed25519-signed DSSE envelope; `statement`: the unsigned in-toto Statement, for signing with external tools.
        #[arg(long, value_enum, default_value = "dsse")]
        format: AttestationFormat,
        /// Ed25519 PKCS#8 private key (from `vee reviews keygen`); required for `dsse`.
        #[arg(long, required_if_eq("format", "dsse"))]
        private_key: Option<std::path::PathBuf>,
        /// Key identifier recorded in the signature; required for `dsse`.
        #[arg(long, required_if_eq("format", "dsse"))]
        key_id: Option<String>,
    },
    /// Verify a DSSE-signed Vee attestation with an Ed25519 public key.
    VerifyAttestation {
        /// Path to the DSSE envelope.
        path: std::path::PathBuf,
        /// Ed25519 public key in raw 32-byte form (from `vee reviews keygen`).
        #[arg(long)]
        public_key: std::path::PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Verify the integrity and internal bindings of an exported evidence bundle.
    VerifyBundle {
        /// Path to the evidence bundle.
        path: std::path::PathBuf,
        /// Ed25519 public key in raw 32-byte form; required to verify signed bundles.
        #[arg(long)]
        public_key: Option<std::path::PathBuf>,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Sign a bundle with an Ed25519 PKCS#8 private key.
    SignBundle {
        /// Path to the evidence bundle.
        path: std::path::PathBuf,
        /// Ed25519 PKCS#8 private key file.
        #[arg(long)]
        private_key: std::path::PathBuf,
        /// Key identifier recorded with the signature.
        #[arg(long)]
        key_id: String,
    },
    /// Generate a local Ed25519 key pair for bundle signing.
    Keygen {
        /// Where to write the PKCS#8 private key.
        #[arg(long)]
        private_key: std::path::PathBuf,
        /// Where to write the public key.
        #[arg(long)]
        public_key: std::path::PathBuf,
    },
    /// Import a portable review as untrusted external history. It is never used by gate evaluation.
    Import {
        /// Path to the portable review file to import.
        path: std::path::PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// List or inspect imported, untrusted external review history.
    Imported {
        #[command(subcommand)]
        command: ImportedCommand,
    },
}
#[derive(Subcommand)]
enum HostingCommand {
    /// Retrieve live PR review comments as untrusted remediation context.
    PrIssues {
        /// Repository identifier on the hosting provider.
        #[arg(long, value_name = "OWNER/REPO")]
        repository: String,
        /// Pull or merge request number.
        #[arg(long)]
        number: u64,
        /// Git hosting provider (defaults to .vee.yaml).
        #[arg(long, value_parser = ["github", "gitlab", "bitbucket", "azure-devops", "gerrit"])]
        provider: Option<String>,
        /// Hosting server host name (for self-hosted instances).
        #[arg(long)]
        host: Option<String>,
        /// Hosting API base URL (defaults per provider).
        #[arg(long, value_name = "URL")]
        api_base: Option<String>,
        /// Credential variable (default: GH_TOKEN; can be set in .vee.yaml).
        #[arg(long, value_name = "ENV_VAR")]
        token_env: Option<String>,
        /// Gerrit HTTP username for Basic authentication; omit for bearer token auth.
        #[arg(long)]
        username: Option<String>,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
        /// Save the returned discussion as content-addressed, untrusted history.
        #[arg(long, default_value_t = false)]
        archive: bool,
    },
    /// Retrieve Azure DevOps pull request metadata and changed-file context.
    PrContext {
        /// Repository identifier on the hosting provider.
        #[arg(long, value_name = "ORGANIZATION/PROJECT/REPOSITORY")]
        repository: String,
        /// Pull or merge request number.
        #[arg(long)]
        number: u64,
        /// Git hosting provider (defaults to .vee.yaml).
        #[arg(long, value_parser = ["github", "gitlab", "bitbucket", "azure-devops", "gerrit"])]
        provider: Option<String>,
        /// Hosting server host name (for self-hosted instances).
        #[arg(long)]
        host: Option<String>,
        /// Hosting API base URL (defaults per provider).
        #[arg(long, value_name = "URL")]
        api_base: Option<String>,
        /// Credential variable (default: AZURE_DEVOPS_EXT_PAT; can be set in .vee.yaml).
        #[arg(long, value_name = "ENV_VAR")]
        token_env: Option<String>,
        /// Gerrit HTTP username for Basic authentication; omit for bearer token auth.
        #[arg(long)]
        username: Option<String>,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Retrieve issue/specification context with a content digest.
    IssueContext {
        /// Repository identifier on the hosting provider.
        #[arg(long, value_name = "OWNER/REPO")]
        repository: String,
        /// Issue or work-item number.
        #[arg(long)]
        number: u64,
        /// Git hosting provider (defaults to .vee.yaml).
        #[arg(long, value_parser = ["github", "gitlab", "azure-devops"])]
        provider: Option<String>,
        /// Hosting server host name (for self-hosted instances).
        #[arg(long)]
        host: Option<String>,
        /// Hosting API base URL (defaults per provider).
        #[arg(long, value_name = "URL")]
        api_base: Option<String>,
        /// Credential variable (defaults by provider; can be set in .vee.yaml).
        #[arg(long, value_name = "ENV_VAR")]
        token_env: Option<String>,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Publish a saved review's gate result and findings to a pull request.
    Publish {
        /// Saved review ID to publish.
        #[arg(long, value_name = "REVIEW_ID")]
        review: String,
        /// Repository identifier on the hosting provider.
        #[arg(long, value_name = "OWNER/REPO")]
        repository: String,
        /// Pull or merge request number.
        #[arg(long)]
        number: u64,
        /// Git hosting provider (defaults to .vee.yaml).
        #[arg(long, value_parser = ["github", "gitlab", "bitbucket", "azure-devops", "gerrit"])]
        provider: Option<String>,
        /// Hosting server host name (for self-hosted instances).
        #[arg(long)]
        host: Option<String>,
        /// Hosting API base URL (defaults per provider).
        #[arg(long, value_name = "URL")]
        api_base: Option<String>,
        /// Credential variable (defaults by provider; can be set in .vee.yaml).
        #[arg(long, value_name = "ENV_VAR")]
        token_env: Option<String>,
        /// Gerrit HTTP username for Basic authentication; omit for bearer token auth.
        #[arg(long)]
        username: Option<String>,
        /// Environment variable holding the webhook secret.
        #[arg(long, value_name = "ENV_VAR")]
        webhook_secret_env: Option<String>,
        /// Hosting account that owns Vee's published threads.
        #[arg(long, value_name = "LOGIN")]
        actor_login: Option<String>,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Listen for authenticated pull request events from supported Git hosts.
    WebhookServe {
        /// Local repository checkout that webhook reviews run in.
        #[arg(long, value_name = "PATH")]
        repository: String,
        /// Git hosting provider (defaults to .vee.yaml).
        #[arg(long, value_parser = ["github", "gitlab", "bitbucket", "azure-devops", "gerrit"])]
        provider: Option<String>,
        /// Hosting server host name (for self-hosted instances).
        #[arg(long)]
        host: Option<String>,
        /// Address to bind the webhook listener to.
        #[arg(long, default_value = "127.0.0.1")]
        bind: std::net::IpAddr,
        /// Port for the webhook listener.
        #[arg(long, default_value_t = 8787)]
        port: u16,
        /// Hosting API base URL (defaults per provider).
        #[arg(long, value_name = "URL")]
        api_base: Option<String>,
        /// Credential variable (defaults by provider; can be set in .vee.yaml).
        #[arg(long, value_name = "ENV_VAR")]
        token_env: Option<String>,
        /// Gerrit HTTP username for Basic authentication; omit for bearer token auth.
        #[arg(long)]
        username: Option<String>,
        /// Environment variable holding the webhook secret.
        #[arg(long, value_name = "ENV_VAR")]
        webhook_secret_env: Option<String>,
        /// Hosting account that owns Vee's published threads.
        #[arg(long, value_name = "LOGIN")]
        actor_login: Option<String>,
        /// Reserved; non-loopback binding requires native TLS support.
        #[arg(long, default_value_t = false)]
        allow_network: bool,
    },
    /// Preview or delete completed webhook receipts older than the selected retention period.
    PruneWebhooks {
        /// Keep receipts newer than this many days (1..=36500).
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=36500))]
        older_than_days: u32,
        /// Apply deletion. Without this flag, only report the number of eligible receipts.
        #[arg(long, default_value_t = false)]
        apply: bool,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
}
#[derive(Subcommand)]
enum ImportedCommand {
    /// List imported review archives.
    List {
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Show one imported review archive.
    Show {
        /// Content digest of the imported archive.
        digest: String,
    },
    /// Search imported review findings as untrusted, non-gating history.
    Search {
        /// Search text.
        query: String,
        /// Maximum number of results.
        #[arg(long, default_value_t = 20)]
        limit: usize,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Record or inspect explicit human labels for archived provider comments.
    Feedback {
        #[command(subcommand)]
        command: ImportedFeedbackCommand,
    },
}
#[derive(Subcommand)]
enum ImportedFeedbackCommand {
    /// Label one provider comment after human review.
    Set {
        /// Content digest of the imported archive.
        archive_digest: String,
        /// Provider comment ID within the archive.
        external_id: String,
        /// Human-assigned normalized defect category used only for candidate grouping.
        #[arg(long)]
        category: String,
        /// Feedback label.
        #[arg(long, value_enum)]
        label: FeedbackLabelArg,
        /// Why this label applies.
        #[arg(long)]
        reason: String,
        /// Name of the person labeling the comment.
        #[arg(long)]
        reviewer: String,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// List labels attached to archived provider comments.
    List {
        /// Limit to one imported archive.
        #[arg(long)]
        archive_digest: Option<String>,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
}
#[derive(Clone, Copy, clap::ValueEnum)]
enum ReportFormat {
    Sarif,
    VeeJson,
}

/// A saved review with its `gate` replaced by the selected persisted decision
/// (default: the latest), checked to belong to the same snapshot, configuration,
/// and replay inputs. Shared by evidence bundles and attestations.
fn review_with_decision(
    root: &std::path::Path,
    id: &str,
    decision_id: Option<&str>,
) -> Result<vee_application::ReviewResult> {
    let store = ReviewStore::open(&root.join(".vee/vee.sqlite")).map_err(anyhow::Error::msg)?;
    let payload = store
        .get(id)
        .map_err(anyhow::Error::msg)?
        .with_context(|| format!("review {id} was not found"))?;
    let mut review = vee_application::deserialize_review_result(&payload)
        .map_err(|error| anyhow::anyhow!(error))?;
    let decisions = store
        .gate_decisions_for_review(id)
        .map_err(anyhow::Error::msg)?;
    let selected = match decision_id {
        Some(wanted) => decisions
            .into_iter()
            .find(|decision| decision.decision_id == wanted)
            .ok_or_else(|| {
                usage_failure("requested gate decision was not found for this review")
            })?,
        None => decisions
            .into_iter()
            .last()
            .unwrap_or_else(|| review.gate.clone()),
    };
    if selected.snapshot_id != review.snapshot_id {
        return Err(configuration_failure("selected gate decision belongs to a different snapshot and cannot be exported with this review"));
    }
    if selected.effective_config_digest != review.effective_config_digest
        || selected.replay_inputs != review.gate.replay_inputs
    {
        return Err(configuration_failure("selected gate decision uses configuration or replay inputs not retained by the original review; export the original review decision or create a new review"));
    }
    review.effective_config_digest = selected.effective_config_digest.clone();
    review.status = match selected.status {
        GateStatus::Pass => "pass",
        GateStatus::Block => "block",
        GateStatus::Incomplete => "incomplete",
    }
    .into();
    review.gate = selected;
    Ok(review)
}

/// The commit an attestation can name as its subject: only when the reviewed
/// snapshot is exactly that commit's change, so a verifier binding the
/// attestation to a revision attests what was actually reviewed.
fn attested_commit(root: &std::path::Path, change_set: &ChangeSet) -> Result<Option<String>> {
    Ok(match change_set.scope.as_str() {
        scope if scope.starts_with("commit:") || scope.starts_with("commit_range:") => {
            change_set.head_oid.clone()
        }
        "base_and_worktree" => committed_snapshot_matches_review(root, change_set)
            .map_err(anyhow::Error::msg)?
            .then(|| change_set.head_oid.clone())
            .flatten(),
        _ => None,
    })
}

fn evidence_bundle(review: &vee_application::ReviewResult) -> Result<serde_json::Value> {
    let review_value = serde_json::to_value(review)?;
    let review_bytes = serde_json::to_vec(&review_value)?;
    let review_digest = vee_core::digest(&review_bytes);
    let manifest = serde_json::json!({
        "schema_version": 1,
        "review_id": review.review_id,
        "snapshot_id": review.snapshot_id,
        "effective_config_digest": review.gate.effective_config_digest,
        "policy_digest": review.gate.policy_digest,
        "decision_id": review.gate.decision_id,
        "gate_status": review.gate.status,
        "review_digest": review_digest,
        "finding_count": review.findings.len(),
        "evidence_count": review.evidence.len(),
        "verification_count": review.verification_runs.len(),
    });
    let manifest_digest = vee_core::digest(&serde_json::to_vec(&manifest)?);
    Ok(serde_json::json!({
        "schema_version": 1,
        "manifest": manifest,
        "manifest_digest": manifest_digest,
        "review": review_value,
        "limitations": [
            "The bundle proves integrity and internal consistency, not that the source or provider output is correct.",
            "Unsigned bundles do not provide cryptographic tamper protection; use sign-bundle and verify-bundle with a trusted key for authenticity.",
            "Gate replay checks deterministic policy evaluation against retained inputs; it does not rerun providers or verification commands."
        ]
    }))
}

fn verify_evidence_bundle(
    bundle: &serde_json::Value,
    public_key_path: Option<&std::path::Path>,
) -> serde_json::Value {
    let invalid = |message: &str| serde_json::json!({ "schema_version": 1, "valid": false, "message": message });
    if bundle["schema_version"] != 1 {
        return invalid("unsupported evidence bundle schema version");
    }
    let Some(manifest) = bundle.get("manifest") else {
        return invalid("bundle manifest is missing");
    };
    let Some(review) = bundle.get("review") else {
        return invalid("bundled review is missing");
    };
    if !manifest.is_object() || !review.is_object() {
        return invalid("bundle manifest and review must be JSON objects");
    }
    for key in [
        "review_id",
        "snapshot_id",
        "effective_config_digest",
        "policy_digest",
        "decision_id",
        "gate_status",
        "review_digest",
    ] {
        if manifest
            .get(key)
            .and_then(serde_json::Value::as_str)
            .is_none()
        {
            return invalid("bundle manifest is missing a required identity or digest field");
        }
    }
    for key in ["finding_count", "evidence_count", "verification_count"] {
        if manifest
            .get(key)
            .and_then(serde_json::Value::as_u64)
            .is_none()
        {
            return invalid("bundle manifest is missing a required record count");
        }
    }
    if serde_json::from_value::<vee_application::ReviewResult>(review.clone()).is_err() {
        return invalid("bundled review does not match the Vee review contract");
    }
    let review_snapshot = review["snapshot_id"].as_str();
    if review_snapshot.is_none()
        || review["change_set"]["digest"].as_str() != review_snapshot
        || review["gate"]["snapshot_id"].as_str() != review_snapshot
    {
        return invalid("review, change set, and gate must reference the same snapshot");
    }
    let Ok(manifest_bytes) = serde_json::to_vec(manifest) else {
        return invalid("manifest could not be canonicalized");
    };
    if bundle["manifest_digest"].as_str() != Some(vee_core::digest(&manifest_bytes).as_str()) {
        return invalid("manifest digest does not match");
    }
    let Ok(review_bytes) = serde_json::to_vec(review) else {
        return invalid("review could not be canonicalized");
    };
    if manifest["review_digest"].as_str() != Some(vee_core::digest(&review_bytes).as_str()) {
        return invalid("review digest does not match");
    }
    for (manifest_key, review_value) in [
        ("review_id", review["review_id"].clone()),
        ("snapshot_id", review["snapshot_id"].clone()),
        (
            "effective_config_digest",
            review["effective_config_digest"].clone(),
        ),
        ("policy_digest", review["gate"]["policy_digest"].clone()),
        ("decision_id", review["gate"]["decision_id"].clone()),
        ("gate_status", review["gate"]["status"].clone()),
    ] {
        if manifest[manifest_key] != review_value {
            return invalid("manifest and review identity fields do not agree");
        }
    }
    for (manifest_key, review_key) in [
        ("finding_count", "findings"),
        ("evidence_count", "evidence"),
        ("verification_count", "verification_runs"),
    ] {
        if manifest[manifest_key].as_u64()
            != review[review_key]
                .as_array()
                .map(|values| values.len() as u64)
        {
            return invalid("manifest record counts do not agree with bundled review");
        }
    }
    let signature = bundle.get("signature");
    let signature_valid = match (signature, public_key_path) {
        (Some(signature), Some(path)) => {
            let key = match std::fs::read(path) {
                Ok(value) if value.len() == 32 => value,
                _ => return invalid("Ed25519 public key must be a readable raw 32-byte key"),
            };
            let encoded = match signature["signature"].as_str() {
                Some(value) => value,
                None => return invalid("bundle signature is malformed"),
            };
            let signature_bytes =
                match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded) {
                    Ok(value) => value,
                    Err(_) => return invalid("bundle signature is not valid base64"),
                };
            let message = match bundle["manifest_digest"].as_str() {
                Some(value) => value.as_bytes(),
                None => return invalid("manifest digest is missing"),
            };
            if signature["algorithm"] != "ed25519" {
                return invalid("unsupported bundle signature algorithm");
            }
            if ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key)
                .verify(message, &signature_bytes)
                .is_err()
            {
                return invalid("bundle signature verification failed");
            }
            true
        }
        (Some(_), None) => {
            return invalid("bundle is signed; provide --public-key to verify its signer")
        }
        (None, Some(_)) => return invalid("bundle has no signature"),
        (None, None) => false,
    };
    let replay_status = replay_gate(review);
    serde_json::json!({ "schema_version": 1, "valid": true, "signature_valid": signature_valid, "replay_status": replay_status["status"], "replay_matches": replay_status["matches"], "replay_message": replay_status["message"], "message": if signature_valid { "bundle digests and signature are valid; signer trust is determined by the supplied public key" } else { "bundle internal bindings are consistent but it is unsigned; this is not cryptographic tamper protection" }, "review_id": manifest["review_id"], "snapshot_id": manifest["snapshot_id"], "gate_status": manifest["gate_status"], "manifest_digest": bundle["manifest_digest"] })
}

fn committed_snapshot_matches_review(
    root: &std::path::Path,
    reviewed: &ChangeSet,
) -> Result<bool, String> {
    let base_oid = reviewed
        .base_oid
        .as_deref()
        .ok_or("base-and-worktree review is missing its captured base OID")?;
    let head_oid = reviewed
        .head_oid
        .as_deref()
        .ok_or("base-and-worktree review is missing its captured head OID")?;
    let committed = vee_application::capture_change_set(
        root,
        vee_git::ChangeScope::CommitRange {
            from: base_oid.to_owned(),
            to: head_oid.to_owned(),
        },
    )?;
    let normalize_mode = |mode: u32| {
        if mode & 0o170000 == 0o100000 {
            mode & 0o777
        } else {
            mode
        }
    };
    Ok(reviewed.files.len() == committed.files.len()
        && reviewed
            .files
            .iter()
            .zip(&committed.files)
            .all(|(left, right)| {
                left.path == right.path
                    && normalize_mode(left.mode) == normalize_mode(right.mode)
                    && left.content_digest == right.content_digest
                    && left.status == right.status
            }))
}

fn replay_gate(review_value: &serde_json::Value) -> serde_json::Value {
    let review: vee_application::ReviewResult = match serde_json::from_value(review_value.clone()) {
        Ok(review) => review,
        Err(error) => {
            return serde_json::json!({"status":"unavailable","matches":null,"message":format!("review cannot be decoded for replay: {error}")})
        }
    };
    let Some(inputs) = review.gate.replay_inputs.as_ref() else {
        return serde_json::json!({"status":"unavailable","matches":null,"message":"bundle does not contain retained deterministic gate inputs"});
    };
    if inputs.schema_version != 1 {
        return serde_json::json!({"status":"unavailable","matches":null,"message":"unsupported retained gate replay schema"});
    }
    let findings = review
        .policy_findings
        .as_deref()
        .unwrap_or(&review.findings);
    let mut replayed = vee_core::evaluate_gate_with_waivers_and_reviewer_policies(
        &review.snapshot_id,
        vee_core::GateDigests {
            effective_config_digest: &review.effective_config_digest,
            policy_digest: &review.gate.policy_digest,
        },
        findings,
        &inputs.policy,
        inputs.complete,
        vee_core::GateEvidence {
            verification_runs: &inputs.verification_runs,
            source_evidence: &inputs.evidence,
            analyzer_reports: &inputs.analyzer_reports,
        },
        vee_core::GateEvaluationOptions {
            waiver_evaluation: vee_core::WaiverEvaluation {
                records: &inputs.waivers,
                evaluation_time_unix: inputs.evaluation_time_unix,
            },
            reviewer_policies: &inputs.reviewer_policies,
        },
    );
    replayed.blocking_findings = vee_application::visible_blocking_findings(
        &replayed.blocking_findings,
        findings,
        &review.findings,
    );
    let matches = replayed == review.gate;
    serde_json::json!({"status":"replayed","matches":matches,"message":if matches {"deterministic gate replay matches the stored decision"} else {"replayed gate decision differs from the stored decision"},"replayed_decision":replayed})
}

fn write_private_key(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("creating private key {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn diff_contains_added_line(patch: Option<&str>, wanted: u32) -> bool {
    let Some(patch) = patch else {
        return false;
    };
    let mut new_line = 0u32;
    let mut in_hunk = false;
    for row in patch.lines() {
        if row.starts_with("@@") {
            let Some(range) = row.split_whitespace().find(|part| part.starts_with('+')) else {
                in_hunk = false;
                continue;
            };
            new_line = range
                .trim_start_matches('+')
                .split(',')
                .next()
                .and_then(|n| n.parse().ok())
                .unwrap_or(0);
            in_hunk = new_line > 0;
            continue;
        }
        if !in_hunk {
            continue;
        }
        if row.starts_with('+') {
            if new_line == wanted {
                return true;
            }
            new_line = new_line.saturating_add(1);
        } else if row.starts_with(' ') {
            new_line = new_line.saturating_add(1);
        }
    }
    false
}

fn build_hosting_threads(
    findings: &[vee_core::Finding],
    pull_request: &vee_hosting::PullRequestRef,
    changed_files: &[vee_hosting::PullRequestFile],
    _review_id: &str,
    snapshot_id: &str,
    delivery_key: &str,
) -> Vec<vee_hosting::ReviewThread> {
    findings
        .iter()
        .filter_map(|finding| {
            if matches!(finding.severity, Severity::Info) {
                return None;
            }
            let (Some(path), Some(line)) = (&finding.path, finding.line) else {
                return None;
            };
            if !changed_files.iter().any(|file| {
                file.path == *path && diff_contains_added_line(file.patch.as_deref(), line)
            }) {
                return None;
            }
            Some(vee_hosting::ReviewThread {
                pull_request: pull_request.clone(),
                fingerprint: finding.fingerprint.clone(),
                path: path.clone(),
                line: u64::from(line),
                side: vee_hosting::DiffSide::New,
                body: format!(
                    "**{:?} · {}** (confidence: {}%)\n\n{}\n\nVee finding `{}` · snapshot `{}`",
                    finding.severity,
                    finding.category,
                    finding.confidence.unwrap_or(0),
                    finding.rationale,
                    finding.id,
                    snapshot_id
                ),
                resolution: vee_hosting::ThreadResolution::Open,
                snapshot_id: snapshot_id.to_owned(),
                idempotency_key: format!("{delivery_key}:{}", finding.fingerprint),
            })
        })
        .collect()
}

fn build_resolved_hosting_threads(
    records: &[vee_core::FindingRecord],
    active_fingerprints: &std::collections::BTreeSet<String>,
    previously_published_fingerprints: &std::collections::BTreeSet<String>,
    pull_request: &vee_hosting::PullRequestRef,
    review_id: &str,
    snapshot_id: &str,
) -> Vec<vee_hosting::ReviewThread> {
    records
        .iter()
        .filter_map(|record| {
            let finding = &record.finding;
            if record.status != vee_core::FindingStatus::Resolved
                || active_fingerprints.contains(&finding.fingerprint)
                || !previously_published_fingerprints.contains(&finding.fingerprint)
                || matches!(finding.severity, Severity::Info)
            {
                return None;
            }
            let (Some(path), Some(line)) = (&finding.path, finding.line) else {
                return None;
            };
            Some(vee_hosting::ReviewThread {
                pull_request: pull_request.clone(),
                fingerprint: finding.fingerprint.clone(),
                path: path.clone(),
                line: u64::from(line),
                side: vee_hosting::DiffSide::New,
                body: format!(
                    "**Resolved finding**\n\n{}\n\nVee finding `{}` · previously reviewed snapshot `{}`",
                    record.status_reason.as_deref().unwrap_or("Marked resolved locally"),
                    finding.id,
                    snapshot_id
                ),
                resolution: vee_hosting::ThreadResolution::Resolved,
                snapshot_id: snapshot_id.to_owned(),
                idempotency_key: format!("{review_id}:{}:resolved", finding.fingerprint),
            })
        })
        .collect()
}

fn hosting_thread_target_key(
    provider_id: &str,
    pull_request: &vee_hosting::PullRequestRef,
) -> Result<String, String> {
    let identity = serde_json::to_string(pull_request).map_err(|error| error.to_string())?;
    Ok(format!("{provider_id}:{identity}"))
}

fn updated_hosted_finding_fingerprints(
    previously_published: &std::collections::BTreeSet<String>,
    desired_threads: &[vee_hosting::ReviewThread],
) -> std::collections::BTreeSet<String> {
    let mut retained = previously_published.clone();
    for thread in desired_threads {
        match thread.resolution {
            vee_hosting::ThreadResolution::Open => {
                retained.insert(thread.fingerprint.clone());
            }
            vee_hosting::ThreadResolution::Resolved => {
                retained.remove(&thread.fingerprint);
            }
        }
    }
    retained
}

/// Persist a recoverable superset before publishing. A provider may accept a
/// thread update while its response is lost, so the next run must still know
/// every fingerprint that could exist remotely until publication completes.
fn hosting_thread_intent_fingerprints(
    previously_published: &std::collections::BTreeSet<String>,
    desired_threads: &[vee_hosting::ReviewThread],
) -> std::collections::BTreeSet<String> {
    previously_published
        .iter()
        .cloned()
        .chain(
            desired_threads
                .iter()
                .map(|thread| thread.fingerprint.clone()),
        )
        .collect()
}

fn add_resolved_hosting_threads(
    threads: &mut Vec<vee_hosting::ReviewThread>,
    records: &[vee_core::FindingRecord],
    active_fingerprints: &std::collections::BTreeSet<String>,
    previously_published_fingerprints: &std::collections::BTreeSet<String>,
    pull_request: &vee_hosting::PullRequestRef,
    review_id: &str,
    snapshot_id: &str,
) {
    threads.extend(build_resolved_hosting_threads(
        records,
        active_fingerprints,
        previously_published_fingerprints,
        pull_request,
        review_id,
        snapshot_id,
    ));
}

enum ImportedArchive {
    Review(Box<vee_application::ReviewResult>),
    Discussions(vee_hosting::PullRequestReviewIssues),
}

fn parse_imported_archive(bytes: &[u8]) -> Result<ImportedArchive> {
    let payload: serde_json::Value =
        serde_json::from_slice(bytes).context("imported archive is not valid JSON")?;
    match payload
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
    {
        Some(2) => Ok(ImportedArchive::Review(Box::new(parse_portable_review(
            bytes,
        )?))),
        Some(1) => {
            let discussion: vee_hosting::PullRequestReviewIssues =
                serde_json::from_slice(bytes).context("invalid provider discussion archive")?;
            anyhow::ensure!(
                !discussion.gate_eligible,
                "provider discussion archive must remain gate-ineligible"
            );
            discussion
                .pull_request
                .validate()
                .map_err(anyhow::Error::msg)?;
            anyhow::ensure!(
                discussion
                    .issues
                    .iter()
                    .all(|issue| issue.classification == "untrusted_external_review"),
                "provider discussion archive contains an unsupported issue classification"
            );
            Ok(ImportedArchive::Discussions(discussion))
        }
        _ => anyhow::bail!("unsupported imported archive schema"),
    }
}

fn import_review_archive(
    root: &std::path::Path,
    source: &std::path::Path,
) -> Result<(String, vee_application::ReviewResult)> {
    let source_metadata = std::fs::symlink_metadata(source)
        .with_context(|| format!("could not inspect import file {}", source.display()))?;
    anyhow::ensure!(
        source_metadata.file_type().is_file(),
        "import path must be a regular, non-symlink file"
    );
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(source)
    };
    #[cfg(not(unix))]
    let file = std::fs::File::open(source);
    let file =
        file.with_context(|| format!("could not inspect import file {}", source.display()))?;
    let metadata = file
        .metadata()
        .context("could not inspect opened import file")?;
    anyhow::ensure!(metadata.is_file(), "import path must be a regular file");
    anyhow::ensure!(
        metadata.len() <= MAX_IMPORTED_REVIEW_BYTES,
        "import file exceeds 10 MiB limit"
    );
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_IMPORTED_REVIEW_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("could not read import file")?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_IMPORTED_REVIEW_BYTES,
        "import file exceeds 10 MiB limit"
    );
    let review = parse_portable_review(&bytes)?;
    let digest = store_imported_history(root, &bytes)?;
    Ok((digest, review))
}

fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Subcommand)]
enum GateCommand {
    /// Re-evaluate the gate for a saved review against the current source.
    Check {
        /// Saved review ID.
        #[arg(long)]
        review: String,
        /// Environment variable holding the token used to revalidate the review's work item.
        #[arg(long, value_name = "ENV_VAR")]
        token_env: Option<String>,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// List persisted gate decisions for a saved review.
    History {
        /// Saved review ID.
        #[arg(long)]
        review: String,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
}
#[derive(Subcommand)]
enum ProvidersCommand {
    /// List local models, agent CLIs, and API keys Vee can use, in preference order.
    Detect {
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
}

#[derive(Subcommand)]
enum PacksCommand {
    /// Export this repository's reviewers, policy, policy profiles, and approved rules as a pack directory.
    Export {
        /// Directory to create (must not exist or be empty).
        directory: std::path::PathBuf,
        /// Pack name: lowercase letters, digits, '.', '_', or '-'.
        #[arg(long)]
        name: String,
        /// Pack version label, for example 1.2.0.
        #[arg(long)]
        version: String,
        /// One-line description.
        #[arg(long)]
        description: Option<String>,
        /// Reviewer to include; repeat for several. Defaults to all reviewers.
        #[arg(long = "reviewer", value_name = "REVIEWER_ID")]
        reviewers: Vec<String>,
        /// Verification profile to include; repeat for several. Commands are repository-specific, so none are exported by default.
        #[arg(long = "verification", value_name = "PROFILE_ID")]
        verification: Vec<String>,
        /// Leave the repository policy out of the pack.
        #[arg(long)]
        no_policy: bool,
        /// Leave approved rules out of the pack.
        #[arg(long)]
        no_rules: bool,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Install a pack into .vee/packs/<name>/ and pin its digest in .vee.yaml.
    Add {
        /// Pack directory containing pack.yaml.
        directory: std::path::PathBuf,
        /// Provider that runs the pack's reviewers (default: `default`, configured by `vee init`).
        #[arg(long)]
        provider: Option<String>,
        /// Upgrade an installed pack whose content differs.
        #[arg(long)]
        replace: bool,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// List pinned packs and whether their content still matches the pin.
    List {
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Print the content digest of a pack directory.
    Digest {
        /// Pack directory containing pack.yaml.
        directory: std::path::PathBuf,
    },
}

#[derive(Subcommand)]
enum FindingsCommand {
    /// List findings with optional filters.
    List {
        /// Only findings with this severity.
        #[arg(long, value_enum)]
        severity: Option<SeverityArg>,
        /// Only findings with this lifecycle status.
        #[arg(long, value_enum)]
        status: Option<StatusArg>,
        /// Only findings from this review ID.
        #[arg(long)]
        review: Option<String>,
        /// Page size, 1 to 100.
        #[arg(long, default_value_t = operations::DEFAULT_PAGE_SIZE)]
        limit: usize,
        /// Number of matching findings to skip.
        #[arg(long, default_value_t = 0)]
        offset: usize,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Show a finding with its occurrences, evidence, and verification runs.
    Show {
        /// Finding ID.
        id: String,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Build a bounded, snapshot-bound task bundle for an agent or reviewer.
    Task {
        /// Finding ID.
        id: String,
        /// Source lines of context around the finding.
        #[arg(long, default_value_t = 20)]
        context_lines: usize,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Assemble same-review findings into one bounded agent work package.
    Package {
        /// Finding IDs from one review (1 to 20).
        #[arg(required = true, num_args = 1..=20)]
        ids: Vec<String>,
        /// Source lines of context around each finding.
        #[arg(long, default_value_t = 20)]
        context_lines: usize,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Validate and save an agent-proposed patch against an exact saved review.
    ProposePatch {
        /// Saved review ID the patch targets.
        #[arg(long, value_name = "REVIEW_ID")]
        review: String,
        /// Unified diff file proposed by the agent.
        patch: std::path::PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Apply a saved patch only when its exact digest is explicitly approved, then rerun review.
    ApplyPatch {
        /// Proposal digest to apply.
        digest: String,
        /// Repeat the proposal digest to confirm you reviewed the patch.
        #[arg(long, value_name = "SHA256_DIGEST")]
        approve: String,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Record an audited lifecycle status for a finding (not a waiver).
    SetStatus {
        /// Finding ID.
        id: String,
        /// New lifecycle status.
        #[arg(long, value_enum)]
        status: StatusArg,
        /// Why the status changed (kept in the audit log).
        #[arg(long)]
        reason: String,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Record and inspect explicit review feedback labels.
    Feedback {
        #[command(subcommand)]
        command: FindingFeedbackCommand,
    },
}
#[derive(Subcommand)]
enum FindingFeedbackCommand {
    /// Record a reasoned human review label for a finding occurrence.
    Set {
        /// Finding ID.
        id: String,
        /// Snapshot ID the finding occurred on.
        #[arg(long)]
        snapshot: String,
        /// Feedback label.
        #[arg(long, value_enum)]
        label: FeedbackLabelArg,
        /// Why this label applies.
        #[arg(long)]
        reason: String,
        /// Name of the person giving feedback.
        #[arg(long)]
        reviewer: String,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// List saved feedback, optionally for one finding.
    List {
        /// Limit to one finding ID.
        #[arg(long)]
        finding: Option<String>,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
}
#[derive(Subcommand)]
enum WaiversCommand {
    /// Waive a finding for one exact snapshot until it expires.
    Create {
        /// Finding ID to waive.
        finding_id: String,
        /// Saved review ID whose snapshot the waiver is scoped to.
        #[arg(long)]
        review: String,
        /// Why the finding is waived.
        #[arg(long)]
        reason: String,
        /// Name of the person granting the waiver.
        #[arg(long)]
        author: String,
        /// Days until the waiver expires.
        #[arg(long, default_value_t = 30)]
        expires_in_days: u32,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// List waivers recorded for a saved review.
    List {
        /// Saved review ID.
        #[arg(long)]
        review: String,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
}
#[derive(Clone, Copy, clap::ValueEnum)]
enum SeverityArg {
    Critical,
    High,
    Medium,
    Low,
    Info,
}
impl From<SeverityArg> for Severity {
    fn from(value: SeverityArg) -> Self {
        match value {
            SeverityArg::Critical => Self::Critical,
            SeverityArg::High => Self::High,
            SeverityArg::Medium => Self::Medium,
            SeverityArg::Low => Self::Low,
            SeverityArg::Info => Self::Info,
        }
    }
}
#[derive(Clone, Copy, clap::ValueEnum)]
enum StatusArg {
    Open,
    Verified,
    Refuted,
    Resolved,
}
#[derive(Clone, Copy, clap::ValueEnum)]
enum FeedbackLabelArg {
    Confirmed,
    FalsePositive,
    Actionable,
    NotActionable,
}
fn feedback_label_text(label: vee_core::FindingFeedbackLabel) -> &'static str {
    match label {
        vee_core::FindingFeedbackLabel::Confirmed => "confirmed",
        vee_core::FindingFeedbackLabel::FalsePositive => "false_positive",
        vee_core::FindingFeedbackLabel::Actionable => "actionable",
        vee_core::FindingFeedbackLabel::NotActionable => "not_actionable",
    }
}
impl From<FeedbackLabelArg> for vee_core::FindingFeedbackLabel {
    fn from(value: FeedbackLabelArg) -> Self {
        match value {
            FeedbackLabelArg::Confirmed => Self::Confirmed,
            FeedbackLabelArg::FalsePositive => Self::FalsePositive,
            FeedbackLabelArg::Actionable => Self::Actionable,
            FeedbackLabelArg::NotActionable => Self::NotActionable,
        }
    }
}
impl From<StatusArg> for vee_core::FindingStatus {
    fn from(value: StatusArg) -> Self {
        match value {
            StatusArg::Open => Self::Open,
            StatusArg::Verified => Self::Verified,
            StatusArg::Refuted => Self::Refuted,
            StatusArg::Resolved => Self::Resolved,
        }
    }
}
#[derive(Clone, clap::ValueEnum, PartialEq, Eq)]
enum Output {
    Text,
    Json,
}
fn current_change_set(root: &str, base_oid: Option<&str>, scope: &str) -> Result<ChangeSet> {
    let capture_scope = match scope {
        "staged" => vee_git::ChangeScope::Staged,
        "working_tree" => vee_git::ChangeScope::WorkingTree,
        value if value.starts_with("commit:") => {
            vee_git::commit_scope(value.trim_start_matches("commit:"))
                .map_err(anyhow::Error::msg)?
        }
        value if value.starts_with("commit_range:") => {
            vee_git::commit_scope(value.trim_start_matches("commit_range:"))
                .map_err(anyhow::Error::msg)?
        }
        _ => vee_git::ChangeScope::BaseAndWorktree {
            base_oid: base_oid.map(str::to_string),
        },
    };
    vee_application::capture_change_set(std::path::Path::new(root), capture_scope)
        .map_err(anyhow::Error::msg)
}

struct HostingWebhookReviewer {
    root: std::path::PathBuf,
    repository: vee_hosting::RepositoryRef,
    provider: std::sync::Arc<dyn vee_hosting::GitHostingProvider>,
    lock: std::sync::Mutex<()>,
}

impl vee_http::WebhookEventHandler for HostingWebhookReviewer {
    fn handle(&self, event: &vee_hosting::WebhookEnvelope) -> std::result::Result<(), String> {
        if event.event_type != "pull_request"
            || !matches!(
                event.action.as_deref(),
                Some("opened" | "reopened" | "synchronize")
            )
        {
            return Ok(());
        }
        let _guard = self
            .lock
            .lock()
            .map_err(|_| "webhook review lock is poisoned")?;
        let pull_request = event
            .pull_request
            .as_ref()
            .ok_or("pull request event is missing its pull request identity")?;
        if pull_request.repository != self.repository {
            return Err("webhook repository does not match the configured repository".into());
        }
        let head_oid = event
            .head_oid
            .as_deref()
            .ok_or("pull request event is missing head commit OID")?;
        let remote = self
            .provider
            .get_pull_request(pull_request)
            .map_err(|error| error.to_string())?;
        let base_oid = remote.base_oid.as_str();
        if remote.state != vee_hosting::PullRequestState::Open
            || event
                .base_oid
                .as_deref()
                .is_some_and(|event_base| !remote.base_oid.eq_ignore_ascii_case(event_base))
            || !remote.head_oid.eq_ignore_ascii_case(head_oid)
        {
            // A delayed delivery for an older revision can never become current
            // again. Acknowledge it instead of asking GitHub to retry forever.
            return Ok(());
        }

        let range = format!("{base_oid}..{head_oid}");
        let change_set =
            vee_application::capture_change_set(&self.root, vee_git::commit_scope(&range)?)?;
        if !change_set
            .base_oid
            .as_deref()
            .is_some_and(|value| value.eq_ignore_ascii_case(base_oid))
            || !change_set
                .head_oid
                .as_deref()
                .is_some_and(|value| value.eq_ignore_ascii_case(head_oid))
        {
            return Err("captured snapshot does not match webhook commit range".into());
        }
        let mut config = vee_application::load_repository_config(&self.root)?;
        vee_application::apply_protected_policy(&self.root, &mut config)?;
        let storage = self.root.join(".vee/vee.sqlite");
        if let Some(parent) = storage.parent() {
            std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let mut store = ReviewStore::open(&storage)?;
        let review = vee_application::run_review_selecting_reviewers(
            &self.root, change_set, &config, &mut store, None,
        )?;
        if review.change_set.base_oid.as_deref() != Some(base_oid)
            || review.change_set.head_oid.as_deref() != Some(head_oid)
        {
            return Err("review result does not match webhook commit range".into());
        }
        let (conclusion, title) = match review.gate.status {
            GateStatus::Pass => (vee_hosting::CheckConclusion::Success, "Vee passed"),
            GateStatus::Block => (vee_hosting::CheckConclusion::Failure, "Vee blocked"),
            GateStatus::Incomplete => (
                vee_hosting::CheckConclusion::ActionRequired,
                "Vee incomplete",
            ),
        };
        let summary = if review.gate.reasons.is_empty() {
            format!("Gate status: {:?}", review.gate.status)
        } else {
            review
                .gate
                .reasons
                .iter()
                .map(|reason| format!("- {reason}"))
                .collect::<Vec<_>>()
                .join("\n")
        };
        let changed = self
            .provider
            .list_changed_files(pull_request, &remote.revision)
            .map_err(|error| error.to_string())?;
        let delivery_key = vee_core::digest(event.event_id.as_bytes());
        let mut threads = build_hosting_threads(
            &review.findings,
            pull_request,
            &changed,
            &review.review_id,
            &review.snapshot_id,
            &delivery_key,
        );
        let active_fingerprints = review
            .findings
            .iter()
            .map(|finding| finding.fingerprint.clone())
            .collect();
        let resolved_findings =
            store.list_findings(None, Some(vee_core::FindingStatus::Resolved), None)?;
        let thread_target = hosting_thread_target_key(self.provider.provider_id(), pull_request)?;
        let previously_published = store.hosted_finding_threads(&thread_target)?;
        add_resolved_hosting_threads(
            &mut threads,
            &resolved_findings,
            &active_fingerprints,
            &previously_published,
            pull_request,
            &review.review_id,
            &review.snapshot_id,
        );
        let published_fingerprints =
            updated_hosted_finding_fingerprints(&previously_published, &threads);
        let intent_fingerprints =
            hosting_thread_intent_fingerprints(&previously_published, &threads);
        store.replace_hosted_finding_threads(&thread_target, &intent_fingerprints)?;
        self.provider
            .publish_review(vee_hosting::ReviewPublication {
                pull_request: pull_request.clone(),
                expected_revision: remote.revision,
                check: vee_hosting::CheckRun {
                    pull_request: pull_request.clone(),
                    external_id: format!("webhook:{delivery_key}"),
                    name: "Vee".into(),
                    status: vee_hosting::CheckStatus::Completed,
                    conclusion: Some(conclusion),
                    title: title.into(),
                    summary,
                    snapshot_id: review.snapshot_id,
                    idempotency_key: format!("webhook:{delivery_key}"),
                },
                threads,
            })
            .map_err(|error| error.to_string())?;
        store.replace_hosted_finding_threads(&thread_target, &published_fingerprints)?;
        Ok(())
    }
}

fn sarif_uri_reference(path: &str) -> String {
    let mut encoded = String::with_capacity(path.len());
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'.'
                    | b'_'
                    | b'~'
                    | b'/'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b':'
                    | b'@'
            )
        {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write;
            write!(encoded, "%{byte:02X}").expect("writing into String cannot fail");
        }
    }
    encoded
}

fn review_to_sarif(review: &vee_application::ReviewResult) -> Result<serde_json::Value> {
    let mut rules = std::collections::BTreeMap::<String, serde_json::Value>::new();
    let mut findings: Vec<_> = review.findings.iter().collect();
    findings.sort_by(|left, right| {
        left.fingerprint
            .cmp(&right.fingerprint)
            .then_with(|| left.id.cmp(&right.id))
    });
    let results = findings
        .into_iter()
        .map(|finding| {
            rules.entry(finding.category.clone()).or_insert_with(|| {
                serde_json::json!({
                    "id": finding.category,
                    "name": finding.category,
                    "shortDescription": {"text": finding.category}
                })
            });
            let level = match finding.severity {
                Severity::Critical | Severity::High => "error",
                Severity::Medium => "warning",
                Severity::Low | Severity::Info => "note",
            };
            let locations = match (finding.path.as_deref(), finding.line) {
                (Some(path), Some(line)) => serde_json::json!([{
                    "physicalLocation": {
                        "artifactLocation": {"uri": sarif_uri_reference(path)},
                        "region": {"startLine": line}
                    }
                }]),
                (Some(path), None) => serde_json::json!([{
                    "physicalLocation": {"artifactLocation": {"uri": sarif_uri_reference(path)}}
                }]),
                _ => serde_json::Value::Array(Vec::new()),
            };
            serde_json::json!({
                "ruleId": finding.category,
                "level": level,
                "message": {"text": finding.rationale},
                "partialFingerprints": {"vee/v1": finding.fingerprint},
                "locations": locations,
                "properties": {
                    "veeFindingId": finding.id,
                    "confidence": finding.confidence,
                    "provenance": finding.provenance,
                    "evidenceIds": finding.evidence_ids
                }
            })
        })
        .collect::<Vec<_>>();
    let rules = rules.into_values().collect::<Vec<_>>();
    Ok(serde_json::json!({
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Vee",
                "semanticVersion": env!("CARGO_PKG_VERSION"),
                "rules": rules
            }},
            "results": results,
            "invocations": [{
                "executionSuccessful": review.analysis_complete,
                "properties": {
                    "veeReviewId": review.review_id,
                    "veeSnapshotId": review.snapshot_id,
                    "veeGateStatus": review.status
                }
            }]
        }]
    }))
}

/// Fingerprint of an analyzer finding recorded in one of the review's gate
/// decisions (at review time or a later `gate check`) on the review's snapshot.
fn analyzer_finding_fingerprint(
    store: &dyn Repositories,
    review: &vee_application::ReviewResult,
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

fn run_packs(command: PacksCommand) -> Result<u8> {
    match command {
        PacksCommand::Export {
            directory,
            name,
            version,
            description,
            reviewers,
            verification,
            no_policy,
            no_rules,
            output,
        } => {
            let summary = packs::export(
                &operations::Workspace::discover(crate::local_stores())?,
                packs::ExportRequest {
                    destination: &directory,
                    name: &name,
                    version: &version,
                    description: description.as_deref(),
                    reviewers: &reviewers,
                    verification: &verification,
                    include_policy: !no_policy,
                    include_rules: !no_rules,
                },
            )?;
            match output {
                Output::Json => emit_json(&summary)?,
                Output::Text => print_pack_summary("Exported", &summary),
            }
            Ok(0)
        }
        PacksCommand::Add {
            directory,
            provider,
            replace,
            output,
        } => {
            let summary = packs::add(
                &operations::Workspace::discover(crate::local_stores())?,
                &directory,
                provider.as_deref(),
                replace,
            )?;
            match output {
                Output::Json => emit_json(&summary)?,
                Output::Text => print_pack_summary("Pinned", &summary),
            }
            Ok(0)
        }
        PacksCommand::List { output } => {
            let list = packs::list(&operations::Workspace::discover(crate::local_stores())?)?;
            match output {
                Output::Json => emit_json(&list)?,
                Output::Text => print_view(&list)?,
            }
            Ok(if list.packs.iter().all(|pack| pack.status == "ok") {
                0
            } else {
                2
            })
        }
        PacksCommand::Digest { directory } => {
            println!(
                "{}",
                vee_core::packs::pack_digest(&directory).map_err(usage_failure)?
            );
            Ok(0)
        }
    }
}

fn print_pack_summary(action: &str, summary: &packs::PackSummary) {
    println!(
        "{action} pack {} {} at {}",
        summary.name, summary.version, summary.path
    );
    println!("Digest: {}", summary.digest);
    println!(
        "Reviewers: {}",
        if summary.reviewers.is_empty() {
            "none".into()
        } else {
            summary.reviewers.join(", ")
        }
    );
    if !summary.verification_profiles.is_empty() {
        println!(
            "Verification profiles: {}",
            summary.verification_profiles.join(", ")
        );
    }
    if !summary.policy_profiles.is_empty() {
        println!("Policy profiles: {}", summary.policy_profiles.join(", "));
    }
    println!(
        "Policy: {}  Approved rules: {}",
        if summary.includes_policy {
            "included"
        } else {
            "not included"
        },
        summary.rules
    );
    for warning in &summary.warnings {
        println!("Warning: {warning}");
    }
}

/// Resolve the CLI's `--review` / scope flags into the change an operation runs on.
fn change_target(
    review: Option<String>,
    base: Option<String>,
    commit: Option<String>,
    staged: bool,
    working_tree: bool,
) -> Result<operations::ChangeTarget> {
    Ok(match review {
        Some(review_id) => operations::ChangeTarget::Review(review_id),
        None => operations::ChangeTarget::Scope(operations::ScopeRequest::from_flags(
            base,
            commit,
            staged,
            working_tree,
        )?),
    })
}

/// Print one machine-readable document for `--output json`: compact JSON and a newline.
/// The same document is returned by the matching MCP tool.
fn emit_json(document: &impl serde::Serialize) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, document)?;
    writeln!(stdout)?;
    Ok(())
}

fn write_completions(shell: clap_complete::Shell, output: &mut dyn std::io::Write) {
    use clap::CommandFactory;
    let mut command = Cli::command();
    clap_complete::generate(shell, &mut command, "vee", output);
}

/// Stack for the thread that runs the command. Windows gives the main thread
/// 1 MiB, which an unoptimized build overflows while parsing and dispatching
/// commands; Linux and macOS default to 8 MiB. Use 8 MiB everywhere.
const COMMAND_STACK_BYTES: usize = 8 * 1024 * 1024;

fn main() -> ExitCode {
    let json_output = json_output_requested(&std::env::args_os().collect::<Vec<_>>());
    let outcome = std::thread::Builder::new()
        .name("vee".into())
        .stack_size(COMMAND_STACK_BYTES)
        .spawn(run)
        .map_err(anyhow::Error::from)
        .and_then(|command| {
            command
                .join()
                .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
        });
    match outcome {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            let (error_code, exit_code) = classify_error(&err);
            if json_output {
                let document = serde_json::json!({
                    "schema_version": 1,
                    "error": {
                        "code": error_code,
                        "message": format!("{err:#}"),
                    },
                });
                let mut stdout = std::io::stdout().lock();
                if serde_json::to_writer(&mut stdout, &document).is_ok() {
                    let _ = writeln!(stdout);
                    let _ = stdout.flush();
                }
            } else {
                eprintln!("vee: {err:#}");
            }
            ExitCode::from(exit_code)
        }
    }
}

fn json_output_requested(args: &[std::ffi::OsString]) -> bool {
    if let Some(value) = args
        .iter()
        .find_map(|argument| argument.to_str()?.strip_prefix("--output="))
        .or_else(|| {
            args.windows(2)
                .find(|pair| pair[0] == "--output")
                .and_then(|pair| pair[1].to_str())
        })
    {
        return value == "json";
    }

    let command = args
        .iter()
        .filter_map(|argument| argument.to_str())
        .collect::<Vec<_>>();
    command.windows(2).any(|pair| {
        matches!(
            pair,
            ["rules", "effectiveness"]
                | ["reviews", "bundle"]
                | ["reviews", "verify-bundle"]
                | ["hosting", "pr-issues"]
                | ["hosting", "pr-context"]
                | ["hosting", "issue-context"]
                | ["findings", "task"]
                | ["findings", "package"]
                | ["findings", "propose-patch"]
                | ["findings", "apply-patch"]
        )
    }) || command
        .windows(3)
        .any(|triple| matches!(triple, ["reviews", "imported", "show"]))
}

fn write_markdown_report(path: &std::path::Path, contents: &[u8]) -> Result<()> {
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        anyhow::ensure!(
            metadata.file_type().is_file(),
            "refusing to overwrite non-regular Markdown report path {}",
            path.display()
        );
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent).with_context(|| {
        format!(
            "creating temporary Markdown report beside {}",
            path.display()
        )
    })?;
    temporary.write_all(contents)?;
    temporary
        .persist(path)
        .with_context(|| format!("writing Markdown report {}", path.display()))?;
    Ok(())
}

fn run() -> Result<u8> {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) =>
        {
            error.print()?;
            return Ok(0);
        }
        Err(error) => return Err(anyhow::Error::new(error)),
    };
    set_color(cli.color);
    match cli.command {
        Command::Init {
            provider,
            model,
            output,
        } => {
            let workspace = operations::Workspace::discover(crate::local_stores())?;
            let report = operations::init(&workspace, provider.as_deref(), model.as_deref())?;
            match output {
                Output::Json => emit_json(&report)?,
                Output::Text => {
                    if report.repository_config_status == "written" {
                        println!("Created {}", report.repository_config);
                    }
                    if report.reviewer_instructions_created {
                        println!("Created {}", report.reviewer_instructions);
                    }
                    match (report.provider_status, report.candidate_id) {
                        ("written", Some(candidate)) => println!(
                            "Configured provider `{}` ({candidate}, {} egress) in {}",
                            report.provider_id, report.egress, report.user_config
                        ),
                        _ => println!(
                            "Using existing provider `{}` from {}",
                            report.provider_id, report.user_config
                        ),
                    }
                    println!("Next: run `vee doctor`, then `vee review`.");
                }
            }
            Ok(0)
        }
        Command::Doctor { output } => {
            let workspace = operations::Workspace::discover(crate::local_stores())?;
            let report = operations::doctor(&workspace)?;
            match output {
                Output::Json => emit_json(&report)?,
                Output::Text => print_view(&report)?,
            }
            Ok(if report.ready { 0 } else { 2 })
        }
        Command::Providers {
            command: ProvidersCommand::Detect { output },
        } => {
            let report = operations::detect_providers();
            match output {
                Output::Json => emit_json(&report)?,
                Output::Text => print_view(&report)?,
            }
            Ok(0)
        }
        Command::Packs { command } => run_packs(command),
        Command::Completions { shell } => {
            let mut script = Vec::new();
            write_completions(shell, &mut script);
            match std::io::stdout().lock().write_all(&script) {
                Err(error) if error.kind() != std::io::ErrorKind::BrokenPipe => Err(error.into()),
                _ => Ok(0),
            }
        }
        Command::Skills { command } => match command {
            SkillsCommand::List => {
                for (id, _) in AGENT_SKILLS {
                    println!("{id}");
                }
                Ok(0)
            }
            SkillsCommand::Install { force } => {
                let cwd = std::env::current_dir()?;
                let root = vee_git::repository_root(&cwd).map_err(anyhow::Error::msg)?;
                install_agent_skills(&root, force)?;
                Ok(0)
            }
        },
        Command::Standards {
            path,
            sync_url,
            source_id,
            source_scope,
            expected_digest,
            remove_source,
            output,
        } => {
            let cwd = std::env::current_dir()?;
            let root = vee_git::repository_root(&cwd).map_err(anyhow::Error::msg)?;
            if remove_source.is_some()
                && (sync_url.is_some()
                    || source_id.is_some()
                    || source_scope.is_some()
                    || expected_digest.is_some())
            {
                return Err(usage_failure(
                    "--remove-source cannot be combined with remote sync options",
                ));
            }
            if let Some(id) = remove_source {
                standards::remove_remote(&root, &id).map_err(configuration_failure)?;
                if output == Output::Text {
                    eprintln!("Removed remote standards {id}");
                }
            } else {
                match (sync_url, source_id, source_scope) {
                (Some(url), Some(id), Some(scope)) => {
                    if load_repository_config(&root)?.offline {
                        return Err(configuration_failure(
                            "remote standards sync is disabled by offline: true",
                        ));
                    }
                    let digest = standards::sync_remote(
                        &root,
                        &id,
                        &url,
                        &scope,
                        expected_digest.as_deref(),
                    )
                    .map_err(configuration_failure)?;
                    if output == Output::Text {
                        eprintln!("Cached remote standards {id} ({digest})");
                    }
                }
                (None, None, None) if expected_digest.is_none() => {}
                _ => {
                    return Err(usage_failure(
                        "remote sync requires --sync-url, --source-id, and --source-scope together; --expected-digest is valid only with them",
                    ))
                }
            }
            }
            let report = operations::applicable_standards(
                &operations::Workspace::new(root.clone(), crate::local_stores()),
                path.as_deref(),
            )?;
            match output {
                Output::Json => emit_json(&report)?,
                Output::Text => print_view(&report)?,
            }
            Ok(0)
        }
        Command::Owners { paths, output } => {
            let report = operations::owners(
                &operations::Workspace::discover(crate::local_stores())?,
                &paths,
            )?;
            match output {
                Output::Json => println!("{}", serde_json::to_string(&report)?),
                Output::Text => print_view(&report)?,
            }
            Ok(0)
        }
        Command::Rules { command } => match command {
            RulesCommand::Candidates { output } => {
                let report = operations::rule_candidates(&operations::Workspace::discover(
                    crate::local_stores(),
                )?)?;
                match output {
                    Output::Json => emit_json(&report)?,
                    Output::Text => print_view(&report)?,
                }
                Ok(0)
            }
            RulesCommand::Approve {
                candidate_id,
                evidence_digest,
                scope,
                instruction,
                approver,
                reason,
                supersedes,
                expires_in_days,
                output,
            } => {
                let result = operations::approve_rule(
                    &operations::Workspace::discover(crate::local_stores())?,
                    operations::ApproveRuleRequest {
                        candidate_id,
                        evidence_digest,
                        scope,
                        instruction,
                        approver,
                        reason,
                        supersedes_approval_id: supersedes,
                        expires_in_days,
                    },
                )?;
                match output { Output::Json => emit_json(&result)?, Output::Text => println!("Approved {} ({}) for scope {}. Guidance is recorded and does not alter gate policy.", result.approval_id, result.candidate_id, result.scope) }
                Ok(0)
            }
            RulesCommand::List { output } => {
                let approvals = operations::list_rule_approvals(&operations::Workspace::discover(
                    crate::local_stores(),
                )?)?;
                match output {
                    Output::Json => emit_json(&approvals)?,
                    Output::Text => {
                        if approvals.is_empty() {
                            println!("No rule guidance approvals.");
                        }
                        for approval in approvals {
                            println!(
                                "{}  {}  {}  {}",
                                approval.approval_id,
                                approval.status.as_str(),
                                approval.category,
                                approval.scope
                            );
                        }
                    }
                }
                Ok(0)
            }
            RulesCommand::Revoke {
                approval_id,
                actor,
                reason,
                output,
            } => {
                let result = operations::revoke_rule(
                    &operations::Workspace::discover(crate::local_stores())?,
                    &approval_id,
                    &actor,
                    &reason,
                )?;
                match output {
                    Output::Json => emit_json(&result)?,
                    Output::Text => {
                        println!("Revoked {}. Audit history retained.", result.approval_id)
                    }
                }
                Ok(0)
            }
            RulesCommand::Effectiveness {
                approval_id,
                output,
            } => {
                let report = operations::rule_effectiveness(
                    &operations::Workspace::discover(crate::local_stores())?,
                    approval_id.as_deref(),
                )?;
                match output {
                    Output::Json => emit_json(&report)?,
                    Output::Text => print_view(&report)?,
                }
                Ok(0)
            }
        },
        Command::Mcp { command } => match command {
            McpCommand::Serve { transport: _ } => {
                mcp::serve_stdio()?;
                Ok(0)
            }
        },
        Command::Ui {
            host,
            port,
            allow_network,
        } => {
            if host.is_unspecified() {
                return Err(configuration_failure(
                    "wildcard UI binding cannot enforce the Host/Origin guard; bind to a specific interface address",
                ));
            }
            if !host.is_loopback() {
                return Err(configuration_failure(
                    "non-loopback UI binding is disabled until Vee can serve TLS directly; use a secure local tunnel",
                ));
            }
            let cwd = std::env::current_dir()?;
            let root = vee_git::repository_root(&cwd).map_err(anyhow::Error::msg)?;
            let address = std::net::SocketAddr::new(host, port);
            let auth_token = None;
            eprintln!("Vee UI: http://{address}");
            if let Some(token) = auth_token.as_deref() {
                eprintln!("Vee network UI access token (enter it in the browser prompt): {token}");
            }
            tokio::runtime::Runtime::new()?.block_on(vee_http::serve(
                root,
                address,
                allow_network,
                auth_token,
            ))?;
            Ok(0)
        }
        Command::Review {
            base,
            commit,
            staged,
            working_tree,
            gate,
            policy_profile,
            reviewer_ids,
            effort,
            work_item,
            hosting_provider,
            hosting_host,
            hosting_api_base,
            hosting_token_env,
            markdown,
            output,
        } => {
            let workspace = operations::Workspace::discover(crate::local_stores())?;
            let scope = operations::ScopeRequest::from_flags(base, commit, staged, working_tree)?;
            let out = operations::review(
                &workspace,
                operations::ReviewRequest {
                    scope,
                    reviewer_ids: (!reviewer_ids.is_empty()).then_some(reviewer_ids.as_slice()),
                    policy_profile: policy_profile.as_deref(),
                    effort: effort.map(Into::into),
                    work_item: work_item.as_deref(),
                    hosting: vee_application::work_items::HostingOverrides {
                        provider: hosting_provider,
                        host: hosting_host,
                        api_base: hosting_api_base,
                        token_env: hosting_token_env,
                    },
                },
                None,
            )?;
            if let Some(path) = markdown {
                let report = vee_present::markdown::render(&vee_present::review_report(&out));
                write_markdown_report(&path, report.as_bytes())?;
            }
            match output {
                Output::Json => {
                    emit_json(&out)?;
                    eprintln!("Review {}", out.review_id);
                    eprintln!("Status: {}", out.status);
                    eprintln!("Snapshot: {}", out.snapshot_id);
                    if !out.unreviewed_paths.is_empty() {
                        eprintln!("Not reviewed: {}", out.unreviewed_paths.join(", "));
                    }
                }
                Output::Text => print_view(&out)?,
            }
            std::io::stdout().flush()?;
            Ok(if gate {
                match out.gate.status {
                    GateStatus::Pass => 0,
                    GateStatus::Block => 1,
                    GateStatus::Incomplete => 2,
                }
            } else {
                0
            })
        }
        Command::Impact {
            review,
            base,
            commit,
            staged,
            working_tree,
            output,
        } => {
            let workspace = operations::Workspace::discover(crate::local_stores())?;
            let target = change_target(review, base, commit, staged, working_tree)?;
            let impact = operations::impact(&workspace, target)?;
            match output {
                Output::Json => emit_json(&impact)?,
                Output::Text => print_view(&impact)?,
            }
            Ok(0)
        }
        Command::Tests { command } => match command {
            TestsCommand::Plan {
                base,
                staged,
                working_tree,
                profile,
                output,
            } => {
                let cwd = std::env::current_dir()?;
                let root = vee_git::repository_root(&cwd).map_err(anyhow::Error::msg)?;
                let mut config = load_repository_config(&root)?;
                apply_protected_policy(&root, &mut config)?;
                let scope = operations::ScopeRequest::from_flags(base, None, staged, working_tree)?
                    .resolve(&root)?;
                let snapshot = vee_application::capture_change_set(&root, scope)
                    .map_err(anyhow::Error::msg)?;
                let plan = vee_application::plan_impacted_test_verification(
                    &root, &snapshot, &profile, &config,
                )
                .map_err(anyhow::Error::msg)?;
                match output {
                    Output::Json => {
                        serde_json::to_writer(std::io::stdout().lock(), &plan)?;
                        println!();
                    }
                    Output::Text => {
                        println!("Verification plan for snapshot: {}", plan.snapshot_id);
                        println!(
                            "Profile: {} ({}); no commands were executed",
                            plan.profile_id, plan.executable
                        );
                        for (index, args) in plan.invocations.iter().enumerate() {
                            println!(
                                "{}: {} {}",
                                index + 1,
                                plan.executable,
                                args.iter()
                                    .map(|arg| format!("{:?}", arg))
                                    .collect::<Vec<_>>()
                                    .join(" ")
                            );
                        }
                        println!("Targets: {}", plan.targets.join(", "));
                        for limitation in &plan.limitations {
                            println!("Limitation: {limitation}");
                        }
                    }
                }
                Ok(0)
            }
            TestsCommand::Recommend {
                review,
                base,
                commit,
                staged,
                working_tree,
                coverage_run,
                output,
            } => {
                let target = change_target(review, base, commit, staged, working_tree)?;
                let report = operations::recommend_tests(
                    &operations::Workspace::discover(crate::local_stores())?,
                    target,
                    coverage_run.as_deref(),
                )?;
                match output {
                    Output::Json => {
                        serde_json::to_writer(std::io::stdout().lock(), &report)?;
                        println!();
                    }
                    Output::Text => print_view(&report)?,
                }
                Ok(0)
            }
            TestsCommand::Generate {
                base,
                staged,
                working_tree,
                commit,
                reviewer,
                output,
            } => {
                let cwd = std::env::current_dir()?;
                let root = vee_git::repository_root(&cwd).map_err(anyhow::Error::msg)?;
                let scope =
                    operations::ScopeRequest::from_flags(base, commit, staged, working_tree)?
                        .resolve(&root)?;
                let change_set = vee_application::capture_change_set(&root, scope)
                    .map_err(anyhow::Error::msg)?;
                anyhow::ensure!(
                    !change_set.files.is_empty(),
                    "test generation requires a non-empty change snapshot"
                );
                let mut config = load_repository_config(&root)?;
                apply_protected_policy(&root, &mut config)?;
                let impact = vee_application::analyze_impact(&root, &change_set)
                    .map_err(anyhow::Error::msg)?;
                let context = test_generation::context(
                    &root,
                    &change_set,
                    &impact,
                    config.review.max_context_files,
                    config.review.max_context_file_bytes,
                    config.review.max_context_bytes,
                    config.test_generation.max_context_tokens,
                )?;
                anyhow::ensure!(
                    context["context_budget"]["within_budget"] == true,
                    "test-generation context estimate {} exceeds budget {}; raise test_generation.max_context_tokens or reduce the change scope",
                    context["context_budget"]["estimated_prompt_tokens"],
                    context["context_budget"]["max_context_tokens"]
                );
                let context_summary = test_generation::context_summary(&context)?;
                let report = vee_application::run_provider_task(
                    vee_application::ProviderTaskRequest {
                        root: &root,
                        snapshot_id: &change_set.digest,
                        config: &config,
                        reviewer_id: &reviewer,
                        task_instructions: test_generation::INSTRUCTIONS,
                        context,
                        output_schema: test_generation::output_schema(),
                    },
                    &vee_application::CliReviewProvider,
                )
                .map_err(anyhow::Error::msg)?;
                let snapshot_still_current =
                    vee_application::capture_current_change_set(&root, &change_set)
                        .map(|current| current.digest == change_set.digest)
                        .unwrap_or(false);
                anyhow::ensure!(
                    snapshot_still_current,
                    "change snapshot became stale during test generation; rerun against current changes"
                );
                let patch_text =
                    test_generation::extract_patch(report.output["patch"].as_str().unwrap_or(""));
                anyhow::ensure!(
                    !patch_text.trim().is_empty(),
                    "provider returned an empty test patch"
                );
                anyhow::ensure!(
                    patch_text.len() <= 2 * 1024 * 1024,
                    "generated patch exceeds 2 MiB"
                );
                let temp = tempfile::NamedTempFile::new()?;
                std::fs::write(temp.path(), patch_text.as_bytes())?;
                let sandbox_result =
                    patch_sandbox::validate(&root, temp.path()).map_err(anyhow::Error::msg)?;
                anyhow::ensure!(
                    !sandbox_result.result_files.is_empty()
                        && sandbox_result
                            .result_files
                            .iter()
                            .all(|file| test_generation::is_test_path(&file.path)),
                    "generated patch touches paths outside recognized test files"
                );
                let patch_digest = vee_core::digest(patch_text.as_bytes());
                let proposal_id = test_proposal_id(&change_set.digest, &patch_digest)?;
                let proposal_dir = proposal_directory(&root)?;
                let patch_path = proposal_dir.join(format!("test-{}.patch", &proposal_id[7..]));
                let metadata_path = proposal_dir.join(format!("test-{}.json", &proposal_id[7..]));
                write_new_proposal_file(&patch_path, patch_text.as_bytes())?;
                let proposal = serde_json::json!({
                    "schema_version": 2,
                    "proposal_id": proposal_id,
                    "snapshot_id": report.snapshot_id,
                    "source_scope": change_set.scope,
                    "base_oid": change_set.base_oid,
                    "reviewer_id": report.reviewer_id,
                    "provider_id": report.provider_id,
                    "provider_kind": report.provider_kind,
                    "model": report.model,
                    "provider_output_digest": report.output_digest,
                    "context_summary": context_summary,
                    "patch_digest": patch_digest,
                    "patch_path": patch_path,
                    "validated_in_isolated_sandbox": true,
                    "sandbox_input_digest": patch_sandbox::input_digest(&sandbox_result.input_files).map_err(anyhow::Error::msg)?,
                    "sandbox_result_digest": sandbox_result.result_digest,
                    "application": "not_applied",
                    "tests_executed": false,
                    "verification_runs": [],
                    "approval_instruction": format!("Inspect the generated diff, then run `vee tests apply {proposal_id} --approve {proposal_id}`. Vee has not modified the worktree or run repository tests.")
                });
                write_new_proposal_file(&metadata_path, &serde_json::to_vec_pretty(&proposal)?)?;
                match output {
                    Output::Json => {
                        serde_json::to_writer(std::io::stdout().lock(), &proposal)?;
                        println!();
                    }
                    Output::Text => {
                        println!("Generated test proposal: {proposal_id}");
                        println!("Patch digest: {patch_digest}");
                        println!("Snapshot: {}", report.snapshot_id);
                        println!("Validated in isolated sandbox: yes");
                        println!("Saved: {}", patch_path.display());
                        println!("Not applied; tests were not run.");
                    }
                }
                Ok(0)
            }
            TestsCommand::Refine {
                proposal_id,
                run,
                reviewer,
                output,
            } => {
                if !is_sha256_digest(&proposal_id) {
                    return Err(usage_failure(
                        "test proposal ID must be a full sha256:<hex> digest",
                    ));
                }
                let cwd = std::env::current_dir()?;
                let root = vee_git::repository_root(&cwd).map_err(anyhow::Error::msg)?;
                let proposal_dir = proposal_directory(&root)?;
                let record_path = proposal_dir.join(format!("test-{}.json", &proposal_id[7..]));
                let parent: serde_json::Value = serde_json::from_slice(
                    &read_proposal_file(&record_path, 2 * 1024 * 1024)
                        .with_context(|| format!("test proposal {proposal_id} was not found"))?,
                )?;
                anyhow::ensure!(
                    parent["schema_version"] == 2,
                    "unsupported test proposal schema"
                );
                anyhow::ensure!(
                    parent["proposal_id"].as_str() == Some(proposal_id.as_str()),
                    "test proposal ID does not match its record"
                );
                anyhow::ensure!(
                    parent["application"] == "applied",
                    "test proposal must be applied before it can be refined"
                );
                anyhow::ensure!(
                    parent["approval_digest"].as_str() == Some(proposal_id.as_str()),
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
                    .any(|entry| entry["run_id"].as_str() == Some(run.as_str()));
                anyhow::ensure!(
                    linked_run,
                    "verification run is not linked to this test proposal"
                );

                let db_dir = root.join(".vee");
                let store =
                    ReviewStore::open(&db_dir.join("vee.sqlite")).map_err(anyhow::Error::msg)?;
                let verification = store
                    .verification(&run)
                    .map_err(anyhow::Error::msg)?
                    .with_context(|| format!("verification run {run} was not found"))?;
                anyhow::ensure!(
                    verification.status == vee_core::VerificationStatus::Failed,
                    "only failed verification runs can guide refinement"
                );
                anyhow::ensure!(
                    Some(verification.snapshot_id.as_str())
                        == parent["post_application_snapshot_id"].as_str(),
                    "failed verification run is not from this proposal's applied snapshot"
                );
                let scope = parent["source_scope"]
                    .as_str()
                    .context("proposal has no source scope")?;
                anyhow::ensure!(
                    !matches!(scope, "commit" | "commit_range"),
                    "immutable commit proposals cannot be refined for application"
                );
                let base_oid = parent["base_oid"].as_str();
                let root_string = root.to_string_lossy().to_string();
                let current = current_change_set(&root_string, base_oid, scope)?;
                anyhow::ensure!(current.digest == verification.snapshot_id, "worktree changed after the failed verification; capture a new review before refining");
                let diagnosis = verification_diagnosis::diagnose(&root, &store, &verification)
                    .map_err(anyhow::Error::msg)?;
                let parent_patch_path =
                    proposal_dir.join(format!("test-{}.patch", &proposal_id[7..]));
                let parent_patch = read_proposal_file(&parent_patch_path, 2 * 1024 * 1024)?;
                anyhow::ensure!(
                    vee_core::digest(&parent_patch)
                        == parent["patch_digest"].as_str().unwrap_or_default(),
                    "parent test patch content has changed"
                );
                let parent_patch =
                    std::str::from_utf8(&parent_patch).context("parent test patch is not UTF-8")?;

                let mut config = load_repository_config(&root)?;
                apply_protected_policy(&root, &mut config)?;
                let impact =
                    vee_application::analyze_impact(&root, &current).map_err(anyhow::Error::msg)?;
                let context = test_generation::context(
                    &root,
                    &current,
                    &impact,
                    config.review.max_context_files,
                    config.review.max_context_file_bytes,
                    config.review.max_context_bytes,
                    config.test_generation.max_context_tokens,
                )?;
                anyhow::ensure!(
                    context["context_budget"]["within_budget"] == true,
                    "test-generation context estimate {} exceeds budget {}; raise test_generation.max_context_tokens or reduce the change scope",
                    context["context_budget"]["estimated_prompt_tokens"],
                    context["context_budget"]["max_context_tokens"]
                );
                let context = test_generation::refinement_context(
                    context,
                    parent_patch,
                    &diagnosis,
                    &proposal_id,
                    &run,
                );
                let context_summary = test_generation::context_summary(&context)?;
                let report = vee_application::run_provider_task(
                    vee_application::ProviderTaskRequest {
                        root: &root,
                        snapshot_id: &current.digest,
                        config: &config,
                        reviewer_id: &reviewer,
                        task_instructions: test_generation::REFINEMENT_INSTRUCTIONS,
                        context,
                        output_schema: test_generation::output_schema(),
                    },
                    &vee_application::CliReviewProvider,
                )
                .map_err(anyhow::Error::msg)?;
                anyhow::ensure!(vee_application::capture_current_change_set(&root, &current)
                    .map(|captured| captured.digest == current.digest).unwrap_or(false), "change snapshot became stale during test refinement; rerun against current changes");
                let patch_text =
                    test_generation::extract_patch(report.output["patch"].as_str().unwrap_or(""));
                anyhow::ensure!(
                    !patch_text.trim().is_empty() && patch_text.len() <= 2 * 1024 * 1024,
                    "provider returned an empty or oversized test patch"
                );
                let temp = tempfile::NamedTempFile::new()?;
                std::fs::write(temp.path(), patch_text.as_bytes())?;
                let sandbox_result =
                    patch_sandbox::validate(&root, temp.path()).map_err(anyhow::Error::msg)?;
                anyhow::ensure!(
                    !sandbox_result.result_files.is_empty()
                        && sandbox_result
                            .result_files
                            .iter()
                            .all(|file| test_generation::is_test_path(&file.path)),
                    "refined patch touches paths outside recognized test files"
                );
                let patch_digest = vee_core::digest(patch_text.as_bytes());
                let refined_id = test_proposal_id(&current.digest, &patch_digest)?;
                let patch_path = proposal_dir.join(format!("test-{}.patch", &refined_id[7..]));
                let metadata_path = proposal_dir.join(format!("test-{}.json", &refined_id[7..]));
                write_new_proposal_file(&patch_path, patch_text.as_bytes())?;
                let attempt = parent["refinement"]["attempt"].as_u64().unwrap_or(0) + 1;
                let proposal = serde_json::json!({
                    "schema_version": 2,
                    "proposal_id": refined_id,
                    "snapshot_id": report.snapshot_id,
                    "source_scope": current.scope,
                    "base_oid": current.base_oid,
                    "reviewer_id": report.reviewer_id,
                    "provider_id": report.provider_id,
                    "provider_kind": report.provider_kind,
                    "model": report.model,
                    "provider_output_digest": report.output_digest,
                    "context_summary": context_summary,
                    "patch_digest": patch_digest,
                    "patch_path": patch_path,
                    "validated_in_isolated_sandbox": true,
                    "sandbox_input_digest": patch_sandbox::input_digest(&sandbox_result.input_files).map_err(anyhow::Error::msg)?,
                    "sandbox_result_digest": sandbox_result.result_digest,
                    "application": "not_applied",
                    "tests_executed": false,
                    "verification_runs": [],
                    "refinement": {"parent_proposal_id": proposal_id, "failed_run_id": run, "attempt": attempt},
                    "approval_instruction": format!("Inspect the refined diff, then run `vee tests apply {refined_id} --approve {refined_id}`. This is a new proposal; Vee has not applied it or run tests.")
                });
                write_new_proposal_file(&metadata_path, &serde_json::to_vec_pretty(&proposal)?)?;
                match output {
                    Output::Json => {
                        serde_json::to_writer(std::io::stdout().lock(), &proposal)?;
                        println!();
                    }
                    Output::Text => {
                        println!("Generated refined test proposal: {refined_id}");
                        println!("Based on failed verification: {run}");
                        println!("Patch digest: {patch_digest}");
                        println!("Validated in isolated sandbox: yes");
                        println!(
                            "Not applied; inspect and explicitly approve before running tests."
                        );
                    }
                }
                Ok(0)
            }
            TestsCommand::Effectiveness {
                proposal_id,
                profile,
                mutant_patch,
                output,
            } => {
                let prepared = prepare_effectiveness(&proposal_id, &profile)?;
                let root_canonical = vee_core::paths::canonicalize(&prepared.root)?;
                let patch_canonical = vee_core::paths::canonicalize(&mutant_patch)?;
                anyhow::ensure!(!patch_canonical.starts_with(&root_canonical), "mutant patch must be outside the repository so it cannot change the reviewed snapshot");
                let mutant_meta = std::fs::symlink_metadata(&patch_canonical)?;
                anyhow::ensure!(
                    mutant_meta.file_type().is_file() && mutant_meta.len() <= 2 * 1024 * 1024,
                    "mutant patch must be a regular file no larger than 2 MiB"
                );
                let mutant_bytes = std::fs::read(&patch_canonical)?;
                let mut assessment = test_effectiveness::assess(
                    &prepared.root,
                    &prepared.snapshot,
                    &proposal_id,
                    &profile,
                    &prepared.baseline_run_id,
                    &prepared.profile,
                    &mutant_bytes,
                )
                .map_err(anyhow::Error::msg)?;
                let (coverage_report, coverage_limitation) = effectiveness_coverage(
                    &prepared.root,
                    &prepared.baseline_run_id,
                    &prepared.snapshot,
                );
                test_effectiveness::attach_coverage(&mut assessment, coverage_report.as_ref());
                if !coverage_limitation.is_empty() {
                    assessment.limitations.push(coverage_limitation);
                }
                let effectiveness_dir = prepared.root.join(".vee/effectiveness");
                std::fs::create_dir_all(&effectiveness_dir)?;
                anyhow::ensure!(
                    std::fs::symlink_metadata(&effectiveness_dir)?
                        .file_type()
                        .is_dir(),
                    "effectiveness artifact directory must be a real directory"
                );
                let assessment_bytes = serde_json::to_vec_pretty(&assessment)?;
                let assessment_digest = vee_core::digest(&assessment_bytes);
                let assessment_path =
                    effectiveness_dir.join(format!("assessment-{}.json", &assessment_digest[7..]));
                match std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&assessment_path)
                {
                    Ok(mut file) => file.write_all(&assessment_bytes)?,
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        anyhow::ensure!(
                            read_proposal_file(&assessment_path, 2 * 1024 * 1024)?
                                == assessment_bytes,
                            "existing effectiveness artifact has different content"
                        );
                    }
                    Err(error) => return Err(error.into()),
                }
                match output {
                    Output::Json => {
                        serde_json::to_writer(std::io::stdout().lock(), &assessment)?;
                        println!();
                        eprintln!(
                            "Effectiveness artifact: {} ({assessment_digest})",
                            assessment_path.display()
                        );
                    }
                    Output::Text => {
                        println!("Mutation outcome: {}", assessment.outcome);
                        println!(
                            "Baseline: {}; mutant: {}",
                            assessment.baseline_status, assessment.mutated_status
                        );
                        println!(
                            "Profile: {}; snapshot: {}",
                            assessment.profile_id, assessment.snapshot_id
                        );
                        println!(
                            "Persisted: {} ({assessment_digest})",
                            assessment_path.display()
                        );
                        for limitation in &assessment.limitations {
                            println!("Limitation: {limitation}");
                        }
                    }
                }
                Ok(0)
            }
            TestsCommand::EffectivenessCorpus {
                proposal_id,
                profile,
                manifest,
                output,
            } => {
                let prepared = prepare_effectiveness(&proposal_id, &profile)?;
                let mut assessment = test_effectiveness::assess_corpus(
                    &prepared.root,
                    &prepared.snapshot,
                    &proposal_id,
                    &profile,
                    &prepared.baseline_run_id,
                    &prepared.profile,
                    &manifest,
                )
                .map_err(anyhow::Error::msg)?;
                let (coverage_report, coverage_limitation) = effectiveness_coverage(
                    &prepared.root,
                    &prepared.baseline_run_id,
                    &prepared.snapshot,
                );
                test_effectiveness::attach_corpus_coverage(
                    &mut assessment,
                    coverage_report.as_ref(),
                );
                if !coverage_limitation.is_empty() {
                    assessment.limitations.push(coverage_limitation);
                }
                let effectiveness_dir = prepared.root.join(".vee/effectiveness");
                std::fs::create_dir_all(&effectiveness_dir)?;
                anyhow::ensure!(
                    std::fs::symlink_metadata(&effectiveness_dir)?
                        .file_type()
                        .is_dir(),
                    "effectiveness artifact directory must be a real directory"
                );
                let assessment_bytes = serde_json::to_vec_pretty(&assessment)?;
                let assessment_digest = vee_core::digest(&assessment_bytes);
                let assessment_path =
                    effectiveness_dir.join(format!("corpus-{}.json", &assessment_digest[7..]));
                match std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&assessment_path)
                {
                    Ok(mut file) => file.write_all(&assessment_bytes)?,
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        anyhow::ensure!(
                            read_proposal_file(&assessment_path, 8 * 1024 * 1024)?
                                == assessment_bytes,
                            "existing corpus assessment artifact has different content"
                        );
                    }
                    Err(error) => return Err(error.into()),
                }
                match output {
                    Output::Json => {
                        serde_json::to_writer(std::io::stdout().lock(), &assessment)?;
                        println!();
                        eprintln!(
                            "Effectiveness corpus artifact: {} ({assessment_digest})",
                            assessment_path.display()
                        );
                    }
                    Output::Text => {
                        println!(
                            "Mutant corpus {}: {} killed, {} survived, {} inconclusive of {}",
                            assessment.corpus_id,
                            assessment.killed,
                            assessment.survived,
                            assessment.inconclusive,
                            assessment.sample_size
                        );
                        println!(
                            "Profile: {}; snapshot: {}; corpus digest: {}",
                            assessment.profile_id, assessment.snapshot_id, assessment.corpus_digest
                        );
                        println!(
                            "Persisted: {} ({assessment_digest})",
                            assessment_path.display()
                        );
                        for limitation in &assessment.limitations {
                            println!("Limitation: {limitation}");
                        }
                    }
                }
                Ok(0)
            }
            TestsCommand::Apply {
                proposal_id,
                approve,
                output,
            } => {
                if !is_sha256_digest(&proposal_id) {
                    return Err(usage_failure(
                        "test proposal ID must be a full sha256:<hex> digest",
                    ));
                }
                if approve != proposal_id {
                    return Err(usage_failure(
                        "explicit approval must exactly match the generated test proposal ID",
                    ));
                }
                let cwd = std::env::current_dir()?;
                let root = vee_git::repository_root(&cwd).map_err(usage_failure)?;
                let proposal_dir = proposal_directory(&root)?;
                let apply_lock = acquire_proposal_apply_lock(&proposal_dir)?;
                let record_path = proposal_dir.join(format!("test-{}.json", &proposal_id[7..]));
                let patch_path = proposal_dir.join(format!("test-{}.patch", &proposal_id[7..]));
                let mut proposal: serde_json::Value = serde_json::from_slice(
                    &read_proposal_file(&record_path, 256 * 1024)
                        .with_context(|| format!("test proposal {proposal_id} was not found"))?,
                )?;
                anyhow::ensure!(
                    proposal["schema_version"] == 2,
                    "unsupported test proposal schema"
                );
                anyhow::ensure!(
                    proposal["proposal_id"].as_str() == Some(proposal_id.as_str()),
                    "test proposal ID does not match its record"
                );
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
                let patch_bytes = read_proposal_file(&patch_path, 2 * 1024 * 1024)
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
                let scope = proposal["source_scope"]
                    .as_str()
                    .context("test proposal has no source scope")?;
                anyhow::ensure!(
                    matches!(scope, "staged" | "working_tree" | "base_and_worktree"),
                    "test proposals from immutable commit scopes cannot be applied"
                );
                let base_oid = proposal["base_oid"].as_str();
                let root_string = root.to_string_lossy().to_string();
                let source_snapshot = current_change_set(&root_string, base_oid, scope)?;
                anyhow::ensure!(
                    proposal["snapshot_id"].as_str() == Some(source_snapshot.digest.as_str()),
                    "source snapshot is stale; test patch was not applied"
                );
                let sandbox_result = patch_sandbox::validate_bytes(&root, &patch_bytes)
                    .map_err(anyhow::Error::msg)?;
                anyhow::ensure!(
                    !sandbox_result.result_files.is_empty()
                        && sandbox_result
                            .result_files
                            .iter()
                            .all(|file| test_generation::is_test_path(&file.path)),
                    "saved proposal no longer contains test-only paths"
                );
                let input_digest = patch_sandbox::input_digest(&sandbox_result.input_files)
                    .map_err(anyhow::Error::msg)?;
                anyhow::ensure!(
                    proposal["sandbox_input_digest"].as_str() == Some(input_digest.as_str()),
                    "a test patch target changed since proposal validation"
                );
                anyhow::ensure!(
                    proposal["sandbox_result_digest"].as_str()
                        == Some(sandbox_result.result_digest.as_str()),
                    "isolated test patch result differs from the approved proposal"
                );
                let mut check_args = vec!["apply", "--check"];
                if scope == "staged" {
                    check_args.push("--index");
                }
                patch_sandbox::apply_bytes(&root, &check_args, &patch_bytes)
                    .map_err(anyhow::Error::msg)?;
                let current = current_change_set(&root_string, base_oid, scope)?;
                anyhow::ensure!(
                    current.digest == source_snapshot.digest,
                    "source snapshot changed during test patch validation"
                );
                let final_inputs = vee_git::snapshot_files(
                    &root,
                    &sandbox_result
                        .input_files
                        .iter()
                        .map(|file| std::path::PathBuf::from(&file.path))
                        .collect::<Vec<_>>(),
                )
                .map_err(anyhow::Error::msg)?;
                anyhow::ensure!(
                    patch_sandbox::input_digest(&final_inputs).map_err(anyhow::Error::msg)?
                        == input_digest,
                    "a test patch target changed during validation"
                );
                let mut apply_args = vec!["apply"];
                if scope == "staged" {
                    apply_args.push("--index");
                }
                patch_sandbox::apply_bytes(&root, &apply_args, &patch_bytes)
                    .map_err(anyhow::Error::msg)?;
                let observed_outputs = vee_git::snapshot_files(
                    &root,
                    &sandbox_result
                        .result_files
                        .iter()
                        .map(|file| std::path::PathBuf::from(&file.path))
                        .collect::<Vec<_>>(),
                )
                .map_err(anyhow::Error::msg)?;
                let patch_paths = sandbox_result
                    .result_files
                    .iter()
                    .map(|file| file.path.as_str())
                    .collect::<std::collections::BTreeSet<_>>();
                let post_snapshot =
                    vee_application::capture_current_change_set(&root, &source_snapshot)
                        .map_err(anyhow::Error::msg)?;
                let source_files = source_snapshot
                    .files
                    .iter()
                    .filter(|file| !patch_paths.contains(file.path.as_str()))
                    .map(|file| {
                        (
                            file.path.as_str(),
                            (file.mode, file.content_digest.as_str()),
                        )
                    })
                    .collect::<std::collections::BTreeMap<_, _>>();
                let post_files = post_snapshot
                    .files
                    .iter()
                    .filter(|file| !patch_paths.contains(file.path.as_str()))
                    .map(|file| {
                        (
                            file.path.as_str(),
                            (file.mode, file.content_digest.as_str()),
                        )
                    })
                    .collect::<std::collections::BTreeMap<_, _>>();
                let concurrent_mutation =
                    observed_outputs != sandbox_result.result_files || source_files != post_files;
                proposal["application"] = serde_json::Value::String("applied".into());
                proposal["approval_digest"] = serde_json::Value::String(approve);
                proposal["applied_at_unix"] = serde_json::json!(current_unix_time()?);
                proposal["concurrent_mutation_detected"] =
                    serde_json::Value::Bool(concurrent_mutation);
                proposal["post_application_snapshot_id"] =
                    serde_json::Value::String(post_snapshot.digest.clone());
                write_proposal_file(&record_path, &serde_json::to_vec_pretty(&proposal)?)?;
                drop(apply_lock);
                match output {
                    Output::Json => {
                        serde_json::to_writer(
                            std::io::stdout().lock(),
                            &serde_json::json!({"schema_version": 1, "proposal_id": proposal_id, "application": "applied", "snapshot_id": post_snapshot.digest, "concurrent_mutation_detected": concurrent_mutation}),
                        )?;
                        println!();
                    }
                    Output::Text => {
                        println!("Applied approved test proposal {proposal_id}");
                        println!("Current snapshot: {}", post_snapshot.digest);
                        println!("Concurrent mutation detected: {concurrent_mutation}");
                        println!("Run a trusted test profile with `vee tests run {proposal_id} --profile <profile>`.");
                    }
                }
                Ok(if concurrent_mutation { 2 } else { 0 })
            }
            TestsCommand::Run {
                proposal_id,
                profile,
                output,
            } => {
                if !is_sha256_digest(&proposal_id) {
                    return Err(usage_failure(
                        "test proposal ID must be a full sha256:<hex> digest",
                    ));
                }
                let cwd = std::env::current_dir()?;
                let root = vee_git::repository_root(&cwd).map_err(usage_failure)?;
                let proposal_dir = proposal_directory(&root)?;
                let apply_lock = acquire_proposal_apply_lock(&proposal_dir)?;
                let record_path = proposal_dir.join(format!("test-{}.json", &proposal_id[7..]));
                let mut proposal: serde_json::Value = serde_json::from_slice(
                    &read_proposal_file(&record_path, 256 * 1024)
                        .with_context(|| format!("test proposal {proposal_id} was not found"))?,
                )?;
                anyhow::ensure!(
                    proposal["schema_version"] == 2,
                    "unsupported test proposal schema"
                );
                anyhow::ensure!(
                    proposal["proposal_id"].as_str() == Some(proposal_id.as_str()),
                    "test proposal ID does not match its record"
                );
                anyhow::ensure!(
                    proposal["application"].as_str() == Some("applied"),
                    "test proposal must be explicitly applied before it can run"
                );
                anyhow::ensure!(
                    proposal["approval_digest"].as_str() == Some(proposal_id.as_str()),
                    "test proposal has no matching explicit approval record"
                );
                anyhow::ensure!(proposal["concurrent_mutation_detected"] == false, "test proposal application had a concurrent mutation; review the worktree and generate a new proposal");
                let patch_digest = proposal["patch_digest"]
                    .as_str()
                    .context("test proposal has no patch digest")?;
                let patch_path = proposal_dir.join(format!("test-{}.patch", &proposal_id[7..]));
                let patch_bytes = read_proposal_file(&patch_path, 2 * 1024 * 1024)
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
                let scope = proposal["source_scope"]
                    .as_str()
                    .context("test proposal has no source scope")?;
                let base_oid = proposal["base_oid"].as_str();
                let root_string = root.to_string_lossy().to_string();
                let snapshot = current_change_set(&root_string, base_oid, scope)?;
                anyhow::ensure!(
                    proposal["post_application_snapshot_id"].as_str()
                        == Some(snapshot.digest.as_str()),
                    "worktree no longer matches the snapshot produced by this test proposal"
                );
                let mut config = load_repository_config(&root)?;
                apply_protected_policy(&root, &mut config)?;
                anyhow::ensure!(
                    config.verification.contains_key(&profile),
                    "unknown trusted verification profile {profile}"
                );
                let db_dir = root.join(".vee");
                std::fs::create_dir_all(&db_dir)?;
                let mut store =
                    ReviewStore::open(&db_dir.join("vee.sqlite")).map_err(anyhow::Error::msg)?;
                let run = vee_application::run_verification(
                    &root, &snapshot, &profile, &config, &mut store,
                )
                .map_err(anyhow::Error::msg)?;
                let mut verification_runs = proposal["verification_runs"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default();
                verification_runs.push(serde_json::json!({"run_id": &run.run_id, "snapshot_id": &run.snapshot_id, "profile_id": &run.profile_id, "status": run.status}));
                proposal["verification_runs"] = serde_json::Value::Array(verification_runs);
                proposal["tests_executed"] = serde_json::Value::Bool(true);
                proposal["last_verification_run_id"] =
                    serde_json::Value::String(run.run_id.clone());
                write_proposal_file(&record_path, &serde_json::to_vec_pretty(&proposal)?)?;
                drop(apply_lock);
                let exit_code = match run.status {
                    VerificationStatus::Passed => 0,
                    VerificationStatus::Failed => 1,
                    VerificationStatus::TimedOut => 2,
                    VerificationStatus::Incomplete => 2,
                };
                match output {
                    Output::Json => {
                        serde_json::to_writer(
                            std::io::stdout().lock(),
                            &serde_json::json!({"schema_version": 1, "proposal_id": proposal_id, "verification_run": &run}),
                        )?;
                        println!();
                    }
                    Output::Text => {
                        println!(
                            "Verification {}: {:?} ({})",
                            profile, run.status, run.run_id
                        );
                        println!("Snapshot: {}", run.snapshot_id);
                        print_verification_artifacts(&run);
                    }
                }
                Ok(exit_code)
            }
        },
        Command::Pr { command } => match command {
            PrCommand::Draft {
                review,
                base,
                staged,
                working_tree,
                commit,
                reviewer,
                output,
            } => {
                let target = change_target(review, base, commit, staged, working_tree)?;
                let report = operations::draft_pr_description(
                    &operations::Workspace::discover(crate::local_stores())?,
                    target,
                    &reviewer,
                )?;
                match output {
                    Output::Json => {
                        serde_json::to_writer(std::io::stdout().lock(), &report)?;
                        println!();
                        eprintln!("Draft generated for snapshot {}", report.snapshot_id);
                        eprintln!("Provider output digest: {}", report.output_digest);
                    }
                    Output::Text => print_view(&report)?,
                }
                std::io::stdout().flush()?;
                Ok(0)
            }
        },
        Command::Acceptance { command } => match command {
            AcceptanceCommand::Report { review, output } => {
                let workspace = operations::Workspace::discover(crate::local_stores())?;
                let report = operations::acceptance_report(&workspace, &review)?;
                match output {
                    Output::Json => emit_json(&report)?,
                    Output::Text => print_view(&report)?,
                }
                Ok(0)
            }
            AcceptanceCommand::Validate {
                review,
                mapping,
                gate,
                output,
            } => {
                let cwd = std::env::current_dir()?;
                let root = vee_git::repository_root(&cwd).map_err(anyhow::Error::msg)?;
                let store =
                    ReviewStore::open(&root.join(".vee/vee.sqlite")).map_err(anyhow::Error::msg)?;
                let payload = store
                    .get(&review)
                    .map_err(anyhow::Error::msg)?
                    .ok_or_else(|| usage_failure(format!("review {review} was not found")))?;
                let review_result = vee_application::deserialize_review_result(&payload)
                    .map_err(anyhow::Error::msg)?;
                let mut repository_config = load_repository_config(&root)?;
                repository_config
                    .select_policy_profile(review_result.policy_profile.as_deref())
                    .map_err(configuration_failure)?;
                apply_protected_policy(&root, &mut repository_config)?;
                let metadata = std::fs::symlink_metadata(&mapping).map_err(|error| {
                    configuration_failure(format!("cannot read mapping file: {error}"))
                })?;
                if !metadata.file_type().is_file() || metadata.len() > 1_048_576 {
                    return Err(configuration_failure(
                        "mapping must be a regular file no larger than 1 MiB",
                    ));
                }
                let contents = std::fs::read(&mapping).map_err(|error| {
                    configuration_failure(format!("cannot read mapping file: {error}"))
                })?;
                let mapping: acceptance::AcceptanceMapping = serde_json::from_slice(&contents)
                    .map_err(|error| {
                        configuration_failure(format!("invalid acceptance mapping: {error}"))
                    })?;
                let report = acceptance::validate_mapping(
                    &review_result,
                    &mapping,
                    &repository_config.policy.acceptance,
                )
                .map_err(configuration_failure)?;
                match output {
                    Output::Json => {
                        serde_json::to_writer(std::io::stdout().lock(), &report)?;
                        println!();
                    }
                    Output::Text => acceptance::render_validation_text(&report),
                }
                if !gate {
                    Ok(0)
                } else {
                    Ok(match report.gate_status.as_str() {
                        "pass" => 0,
                        "block" => 1,
                        _ => 2,
                    })
                }
            }
        },
        Command::Gate { command } => match command {
            GateCommand::Check {
                review,
                token_env,
                output,
            } => {
                let workspace = operations::Workspace::discover(crate::local_stores())?;
                let response = operations::gate_check(&workspace, &review, token_env.as_deref())?;
                match output {
                    Output::Json => emit_json(&response)?,
                    Output::Text => print_view(&response)?,
                }
                Ok(response.exit_code())
            }
            GateCommand::History { review, output } => {
                let history = operations::gate_history(
                    &operations::Workspace::discover(crate::local_stores())?,
                    &review,
                )?;
                match output {
                    Output::Json => emit_json(&history)?,
                    Output::Text => print_view(&history)?,
                }
                Ok(0)
            }
        },
        Command::Verify {
            finding_id,
            profile,
            impacted_tests,
            commit,
            base,
            staged,
            working_tree,
            output,
        } => {
            let workspace = operations::Workspace::discover(crate::local_stores())?;
            let target = match finding_id {
                Some(finding_id) => {
                    if commit.is_some() || base.is_some() || staged || working_tree {
                        return Err(usage_failure("finding-scoped verification uses the finding's reviewed snapshot; scope flags cannot be combined"));
                    }
                    operations::VerifyTarget::Finding(finding_id)
                }
                None => operations::VerifyTarget::Scope(operations::ScopeRequest::from_flags(
                    base,
                    commit,
                    staged,
                    working_tree,
                )?),
            };
            let run = operations::verify(
                &workspace,
                operations::VerifyRequest {
                    target,
                    profile_id: &profile,
                    impacted_tests,
                },
            )?;
            match output {
                Output::Json => emit_json(&run)?,
                Output::Text => print_view(&run)?,
            }
            Ok(match run.status {
                VerificationStatus::Passed => 0,
                VerificationStatus::Failed => 1,
                VerificationStatus::TimedOut => 2,
                VerificationStatus::Incomplete => 2,
            })
        }
        Command::Verification { command } => match command {
            VerificationCommand::List { snapshot, output } => {
                let cwd = std::env::current_dir()?;
                let root = vee_git::repository_root(&cwd).map_err(anyhow::Error::msg)?;
                let store =
                    ReviewStore::open(&root.join(".vee/vee.sqlite")).map_err(anyhow::Error::msg)?;
                let runs = store
                    .verifications_for_snapshot(&snapshot)
                    .map_err(anyhow::Error::msg)?;
                match output {
                    Output::Json => {
                        let records: Vec<_> = runs
                            .iter()
                            .map(|run| {
                                serde_json::json!({
                                    "run_id": run.run_id,
                                    "snapshot_id": run.snapshot_id,
                                    "profile_id": run.profile_id,
                                    "status": run.status,
                                    "targets": run.targets,
                                    "has_stdout_artifact": run.stdout_artifact.is_some(),
                                    "has_stderr_artifact": run.stderr_artifact.is_some(),
                                })
                            })
                            .collect();
                        serde_json::to_writer(
                            std::io::stdout().lock(),
                            &serde_json::json!({ "schema_version": 1, "snapshot_id": snapshot, "runs": records }),
                        )?;
                        println!();
                    }
                    Output::Text => {
                        println!("Verification runs for snapshot {snapshot}:");
                        for run in runs {
                            println!("{}  {}  {:?}", run.run_id, run.profile_id, run.status);
                        }
                    }
                }
                Ok(0)
            }
            VerificationCommand::Show { run_id, output } => {
                let cwd = std::env::current_dir()?;
                let top = vee_git::repository_root(&cwd)
                    .map_err(anyhow::Error::msg)?
                    .to_string_lossy()
                    .to_string();
                let db_path = std::path::Path::new(&top).join(".vee/vee.sqlite");
                let store = ReviewStore::open(&db_path).map_err(anyhow::Error::msg)?;
                let run = store
                    .verification(&run_id)
                    .map_err(anyhow::Error::msg)?
                    .with_context(|| format!("verification run {run_id} was not found"))?;
                match output {
                    Output::Json => {
                        serde_json::to_writer(std::io::stdout().lock(), &run)?;
                        println!();
                    }
                    Output::Text => {
                        println!(
                            "Verification {}: {:?} on {}",
                            run.profile_id, run.status, run.snapshot_id
                        );
                        print_verification_artifacts(&run);
                    }
                }
                Ok(0)
            }
            VerificationCommand::Diagnose { run_id, output } => {
                let workspace = operations::Workspace::discover(crate::local_stores())?;
                let diagnosis = operations::diagnose_verification(&workspace, &run_id)?;
                match output {
                    Output::Json => emit_json(&diagnosis)?,
                    Output::Text => print_view(&diagnosis)?,
                }
                Ok(0)
            }
            VerificationCommand::Findings { run_id, output } => {
                let report = operations::analyzer_findings(
                    &operations::Workspace::discover(crate::local_stores())?,
                    &run_id,
                )?;
                match output {
                    Output::Json => emit_json(&report)?,
                    Output::Text => print_view(&report)?,
                }
                Ok(if report.parsed { 0 } else { 2 })
            }
            VerificationCommand::Coverage {
                run_id,
                stream,
                output,
            } => {
                let cwd = std::env::current_dir()?;
                let top = vee_git::repository_root(&cwd)
                    .map_err(anyhow::Error::msg)?
                    .to_string_lossy()
                    .to_string();
                let root = std::path::Path::new(&top);
                let store =
                    ReviewStore::open(&root.join(".vee/vee.sqlite")).map_err(anyhow::Error::msg)?;
                let run = store
                    .verification(&run_id)
                    .map_err(anyhow::Error::msg)?
                    .with_context(|| format!("verification run {run_id} was not found"))?;
                let report = coverage::report(
                    root,
                    &store,
                    &run,
                    match stream {
                        CoverageStream::Stdout => "stdout",
                        CoverageStream::Stderr => "stderr",
                    },
                )
                .map_err(anyhow::Error::msg)?;
                match output {
                    Output::Json => {
                        serde_json::to_writer(std::io::stdout().lock(), &report)?;
                        println!();
                    }
                    Output::Text => {
                        println!(
                            "Coverage for changed files: {} ({})",
                            report.profile_id, report.snapshot_id
                        );
                        for file in &report.files {
                            match file.percent {
                                Some(percent) => println!(
                                    "{}: {:.1}% ({}/{})",
                                    file.path, percent, file.covered_lines, file.executable_lines
                                ),
                                None => println!("{}: no executable lines", file.path),
                            }
                        }
                        for limitation in &report.limitations {
                            println!("Note: {limitation}");
                        }
                    }
                }
                Ok(0)
            }
        },
        Command::Reviews { command } => {
            let cwd = std::env::current_dir()?;
            let top = if matches!(
                &command,
                ReviewsCommand::VerifyBundle { .. }
                    | ReviewsCommand::SignBundle { .. }
                    | ReviewsCommand::Keygen { .. }
            ) {
                cwd.to_string_lossy().to_string()
            } else {
                vee_git::repository_root(&cwd)
                    .map_err(anyhow::Error::msg)?
                    .to_string_lossy()
                    .to_string()
            };
            match command {
                ReviewsCommand::List { output } => {
                    let store =
                        ReviewStore::open(&std::path::Path::new(&top).join(".vee/vee.sqlite"))
                            .map_err(anyhow::Error::msg)?;
                    let records = store.list_reviews().map_err(anyhow::Error::msg)?;
                    match output {
                        Output::Json => {
                            serde_json::to_writer(
                                std::io::stdout().lock(),
                                &serde_json::json!({
                                    "schema_version": 1,
                                    "reviews": records,
                                }),
                            )?;
                            println!();
                        }
                        Output::Text => {
                            if records.is_empty() {
                                println!("No reviews");
                            }
                            for record in records {
                                println!(
                                    "{}  {}  {}  {}",
                                    record.review_id,
                                    record.status,
                                    record.snapshot_id,
                                    record.created_at
                                );
                            }
                        }
                    }
                    Ok(0)
                }
                ReviewsCommand::Show { id, output } => {
                    let workspace = operations::Workspace::new(
                        std::path::PathBuf::from(&top),
                        crate::local_stores(),
                    );
                    let review = operations::get_review(&workspace, &id)?;
                    match output {
                        // Through a Value, as before: keys stay sorted, as MCP emits them.
                        Output::Json => emit_json(&serde_json::to_value(&review)?)?,
                        Output::Text => print_view(&review)?,
                    }
                    Ok(0)
                }
                ReviewsCommand::Export { id, format } => {
                    let store =
                        ReviewStore::open(&std::path::Path::new(&top).join(".vee/vee.sqlite"))
                            .map_err(anyhow::Error::msg)?;
                    let payload = store
                        .get(&id)
                        .map_err(anyhow::Error::msg)?
                        .with_context(|| format!("review {id} was not found"))?;
                    let review = vee_application::deserialize_review_result(&payload)
                        .map_err(anyhow::Error::msg)?;
                    let report = match format {
                        ReportFormat::Sarif => review_to_sarif(&review)?,
                        ReportFormat::VeeJson => serde_json::to_value(&review)?,
                    };
                    serde_json::to_writer(std::io::stdout().lock(), &report)?;
                    println!();
                    Ok(0)
                }
                ReviewsCommand::Bundle { id, decision_id } => {
                    let review = review_with_decision(
                        std::path::Path::new(&top),
                        &id,
                        decision_id.as_deref(),
                    )?;
                    let bundle = evidence_bundle(&review)?;
                    let bytes = serde_json::to_vec(&bundle)?;
                    anyhow::ensure!(
                        bytes.len() as u64 <= MAX_IMPORTED_REVIEW_BYTES,
                        "evidence bundle exceeds 10 MiB and cannot be verified by Vee"
                    );
                    let mut stdout = std::io::stdout().lock();
                    stdout.write_all(&bytes)?;
                    stdout.write_all(b"\n")?;
                    Ok(0)
                }
                ReviewsCommand::Attest {
                    id,
                    decision_id,
                    format,
                    private_key,
                    key_id,
                } => {
                    let root = std::path::Path::new(&top);
                    let review = review_with_decision(root, &id, decision_id.as_deref())?;
                    let bundle = evidence_bundle(&review)?;
                    let manifest_digest = bundle["manifest_digest"].as_str().unwrap_or_default();
                    let commit = attested_commit(root, &review.change_set)?;
                    let statement =
                        attestation::statement(&review, manifest_digest, commit.as_deref())?;
                    let document = match format {
                        AttestationFormat::Statement => statement,
                        AttestationFormat::Dsse => {
                            let key_id = key_id.unwrap_or_default();
                            if key_id.trim().is_empty() {
                                return Err(usage_failure("--key-id cannot be empty"));
                            }
                            let private_key = private_key.unwrap_or_default();
                            let key_bytes = std::fs::read(&private_key).with_context(|| {
                                format!("reading private key {}", private_key.display())
                            })?;
                            let key = ring::signature::Ed25519KeyPair::from_pkcs8(&key_bytes)
                                .map_err(|_| {
                                    configuration_failure(
                                        "private key must be a valid Ed25519 PKCS#8 DER file",
                                    )
                                })?;
                            attestation::sign(&statement, &key, &key_id)?
                        }
                    };
                    emit_json(&document)?;
                    Ok(0)
                }
                ReviewsCommand::VerifyAttestation {
                    path,
                    public_key,
                    output,
                } => {
                    let file = std::fs::File::open(&path)
                        .with_context(|| format!("opening attestation {}", path.display()))?;
                    let mut bytes = Vec::new();
                    file.take(MAX_IMPORTED_REVIEW_BYTES + 1)
                        .read_to_end(&mut bytes)
                        .with_context(|| format!("reading attestation {}", path.display()))?;
                    anyhow::ensure!(
                        bytes.len() as u64 <= MAX_IMPORTED_REVIEW_BYTES,
                        "attestation exceeds 10 MiB"
                    );
                    let envelope: serde_json::Value = serde_json::from_slice(&bytes)
                        .map_err(|_| usage_failure("attestation is not valid JSON"))?;
                    let key = std::fs::read(&public_key)
                        .with_context(|| format!("reading public key {}", public_key.display()))?;
                    let report = attestation::verify(&envelope, &key);
                    match output {
                        Output::Json => emit_json(&report)?,
                        Output::Text => {
                            if report["valid"] == true {
                                println!(
                                    "Valid: gate {} (decision {}) signed by {}",
                                    report["gate_status"].as_str().unwrap_or("?"),
                                    report["decision_id"].as_str().unwrap_or("?"),
                                    report["key_id"].as_str().unwrap_or("?")
                                );
                                for subject in report["subjects"].as_array().into_iter().flatten() {
                                    println!(
                                        "Subject: {}",
                                        subject["name"].as_str().unwrap_or("?")
                                    );
                                }
                            } else {
                                println!(
                                    "Invalid: {}",
                                    report["message"].as_str().unwrap_or("verification failed")
                                );
                            }
                        }
                    }
                    Ok(if report["valid"] == true { 0 } else { 2 })
                }
                ReviewsCommand::VerifyBundle {
                    path,
                    public_key,
                    output,
                } => {
                    let file = std::fs::File::open(&path)
                        .with_context(|| format!("opening evidence bundle {}", path.display()))?;
                    let mut bytes = Vec::new();
                    file.take(MAX_IMPORTED_REVIEW_BYTES + 1)
                        .read_to_end(&mut bytes)
                        .with_context(|| format!("reading evidence bundle {}", path.display()))?;
                    anyhow::ensure!(
                        bytes.len() as u64 <= MAX_IMPORTED_REVIEW_BYTES,
                        "evidence bundle exceeds 10 MiB"
                    );
                    let bundle: serde_json::Value = serde_json::from_slice(&bytes)
                        .context("evidence bundle is not valid JSON")?;
                    let report = verify_evidence_bundle(&bundle, public_key.as_deref());
                    match output {
                        Output::Json => {
                            serde_json::to_writer(std::io::stdout().lock(), &report)?;
                            println!();
                        }
                        Output::Text => println!(
                            "{}: {}",
                            if report["valid"] == true && report["replay_matches"] != false {
                                "Valid"
                            } else {
                                "Invalid"
                            },
                            report["message"]
                                .as_str()
                                .unwrap_or("bundle verification failed")
                        ),
                    }
                    if report["valid"] == true && report["replay_matches"] != false {
                        Ok(0)
                    } else {
                        Ok(2)
                    }
                }
                ReviewsCommand::SignBundle {
                    path,
                    private_key,
                    key_id,
                } => {
                    if key_id.trim().is_empty() {
                        return Err(usage_failure("--key-id cannot be empty"));
                    }
                    let file = std::fs::File::open(&path)
                        .with_context(|| format!("reading evidence bundle {}", path.display()))?;
                    anyhow::ensure!(
                        file.metadata()?.len() <= MAX_IMPORTED_REVIEW_BYTES,
                        "evidence bundle exceeds 10 MiB"
                    );
                    let mut bytes = Vec::new();
                    file.take(MAX_IMPORTED_REVIEW_BYTES + 1)
                        .read_to_end(&mut bytes)
                        .context("reading evidence bundle")?;
                    anyhow::ensure!(
                        bytes.len() as u64 <= MAX_IMPORTED_REVIEW_BYTES,
                        "evidence bundle exceeds 10 MiB"
                    );
                    let mut bundle: serde_json::Value = serde_json::from_slice(&bytes)
                        .context("evidence bundle is not valid JSON")?;
                    let integrity = verify_evidence_bundle(&bundle, None);
                    if integrity["valid"] != true || integrity["replay_matches"] == false {
                        return Err(configuration_failure(
                            "cannot sign an invalid evidence bundle",
                        ));
                    }
                    if bundle.get("signature").is_some() {
                        return Err(usage_failure("bundle is already signed; export a fresh bundle to create another signature"));
                    }
                    let key_bytes = std::fs::read(&private_key).with_context(|| {
                        format!("reading private key {}", private_key.display())
                    })?;
                    let key =
                        ring::signature::Ed25519KeyPair::from_pkcs8(&key_bytes).map_err(|_| {
                            configuration_failure(
                                "private key must be a valid Ed25519 PKCS#8 DER file",
                            )
                        })?;
                    let digest = bundle["manifest_digest"].as_str().ok_or_else(|| {
                        configuration_failure("bundle manifest digest is missing")
                    })?;
                    let signature = key.sign(digest.as_bytes());
                    bundle["signature"] = serde_json::json!({ "algorithm": "ed25519", "key_id": key_id, "signature": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, signature.as_ref()) });
                    let mut output = serde_json::to_vec_pretty(&bundle)?;
                    output.push(b'\n');
                    anyhow::ensure!(
                        output.len() as u64 <= MAX_IMPORTED_REVIEW_BYTES,
                        "signed evidence bundle exceeds 10 MiB and cannot be verified by Vee"
                    );
                    std::fs::write(&path, output).with_context(|| {
                        format!("writing signed evidence bundle {}", path.display())
                    })?;
                    println!("Signed evidence bundle with Ed25519 key {key_id}.");
                    Ok(0)
                }
                ReviewsCommand::Keygen {
                    private_key,
                    public_key,
                } => {
                    let resolve_target = |path: &std::path::Path| -> Result<std::path::PathBuf> {
                        let name = path
                            .file_name()
                            .context("key output path must name a file")?;
                        let parent = path
                            .parent()
                            .filter(|parent| !parent.as_os_str().is_empty())
                            .unwrap_or(std::path::Path::new("."));
                        std::fs::create_dir_all(parent)?;
                        Ok(vee_core::paths::canonicalize(parent)?.join(name))
                    };
                    let private_target = resolve_target(&private_key)?;
                    let public_target = resolve_target(&public_key)?;
                    if private_target == public_target {
                        return Err(usage_failure(
                            "private and public key output paths must differ",
                        ));
                    }
                    if private_target.exists() || public_target.exists() {
                        return Err(usage_failure("key output paths must not already exist"));
                    }
                    let rng = ring::rand::SystemRandom::new();
                    let document =
                        ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).map_err(|_| {
                            configuration_failure("could not generate Ed25519 key pair")
                        })?;
                    let pair = ring::signature::Ed25519KeyPair::from_pkcs8(document.as_ref())
                        .map_err(|_| {
                            configuration_failure("generated Ed25519 key pair could not be loaded")
                        })?;
                    write_private_key(&private_target, document.as_ref())?;
                    std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&public_target)?
                        .write_all(ring::signature::KeyPair::public_key(&pair).as_ref())?;
                    println!("Generated Ed25519 key pair; keep {} private and distribute {} to verifiers.", private_key.display(), public_key.display());
                    Ok(0)
                }
                ReviewsCommand::Import { path, output } => {
                    let (digest, review) =
                        import_review_archive(std::path::Path::new(&top), &path)?;
                    match output {
                        Output::Json => {
                            serde_json::to_writer(std::io::stdout().lock(), &serde_json::json!({
                                "schema_version": 1,
                                "archive_digest": digest,
                                "review_id": review.review_id,
                                "snapshot_id": review.snapshot_id,
                                "status": review.status,
                                "trust": "untrusted_external",
                                "gate_eligible": false
                            }))?;
                            println!();
                        }
                        Output::Text => println!("Imported {} ({}) as untrusted external history; excluded from gate evaluation.", review.review_id, digest),
                    }
                    Ok(0)
                }
                ReviewsCommand::Imported { command } => match command {
                    ImportedCommand::List { output } => {
                        let archive = imported_reviews_dir(std::path::Path::new(&top), true)?;
                        let mut records = Vec::new();
                        if archive.exists() {
                            for entry in std::fs::read_dir(&archive)? {
                                let entry = entry?;
                                if entry.path().extension().and_then(|ext| ext.to_str())
                                    != Some("json")
                                {
                                    continue;
                                }
                                let metadata = entry.metadata()?;
                                if !metadata.is_file() || metadata.len() > MAX_IMPORTED_REVIEW_BYTES
                                {
                                    continue;
                                }
                                let bytes = std::fs::read(entry.path())?;
                                let imported = match parse_imported_archive(&bytes) {
                                    Ok(imported) => imported,
                                    Err(_) => continue,
                                };
                                let hash = hex_digest(&Sha256::digest(&bytes));
                                if entry.file_name().to_string_lossy() != format!("{hash}.json") {
                                    continue;
                                }
                                records.push(match imported {
                                    ImportedArchive::Review(review) => serde_json::json!({
                                        "archive_digest": format!("sha256:{hash}"),
                                        "archive_type": "review",
                                        "review_id": review.review_id,
                                        "snapshot_id": review.snapshot_id,
                                        "status": review.status,
                                        "trust": "untrusted_external",
                                        "gate_eligible": false
                                    }),
                                    ImportedArchive::Discussions(discussion) => serde_json::json!({
                                        "archive_digest": format!("sha256:{hash}"),
                                        "archive_type": "provider_discussions",
                                        "provider": discussion.provider,
                                        "pull_request": discussion.pull_request,
                                        "revision": discussion.revision,
                                        "complete": discussion.complete,
                                        "issue_count": discussion.issues.len(),
                                        "trust": "untrusted_external",
                                        "gate_eligible": false
                                    }),
                                });
                            }
                        }
                        records.sort_by(|a, b| {
                            a["archive_digest"]
                                .as_str()
                                .cmp(&b["archive_digest"].as_str())
                        });
                        match output {
                            Output::Json => {
                                serde_json::to_writer(
                                    std::io::stdout().lock(),
                                    &serde_json::json!({"schema_version": 1, "reviews": records}),
                                )?;
                                println!();
                            }
                            Output::Text => {
                                for record in records {
                                    if record["archive_type"] == "provider_discussions" {
                                        println!("{}  {}  {} issues  untrusted_external (not gate eligible)", record["archive_digest"], record["pull_request"]["number"], record["issue_count"]);
                                    } else {
                                        println!(
                                            "{}  {}  {}  untrusted_external",
                                            record["archive_digest"],
                                            record["review_id"],
                                            record["status"]
                                        );
                                    }
                                }
                            }
                        }
                        Ok(0)
                    }
                    ImportedCommand::Show { digest } => {
                        let archive = imported_reviews_dir(std::path::Path::new(&top), false)?;
                        let raw_digest = digest.strip_prefix("sha256:").unwrap_or(&digest);
                        anyhow::ensure!(
                            raw_digest.len() == 64
                                && raw_digest.bytes().all(|b| b.is_ascii_hexdigit()),
                            "digest must be a SHA-256 hex digest"
                        );
                        let normalized_digest = raw_digest.to_ascii_lowercase();
                        let path = archive.join(format!("{normalized_digest}.json"));
                        let metadata =
                            std::fs::metadata(&path).context("imported review not found")?;
                        anyhow::ensure!(
                            metadata.is_file() && metadata.len() <= MAX_IMPORTED_REVIEW_BYTES,
                            "invalid imported review archive entry"
                        );
                        let bytes = std::fs::read(&path)?;
                        anyhow::ensure!(
                            format!("sha256:{}", hex_digest(&Sha256::digest(&bytes)))
                                == format!("sha256:{normalized_digest}"),
                            "imported archive entry failed integrity check"
                        );
                        let (mut value, archive_type) = match parse_imported_archive(&bytes)? {
                            ImportedArchive::Review(review) => {
                                (serde_json::to_value(review)?, "review")
                            }
                            ImportedArchive::Discussions(discussion) => {
                                (serde_json::to_value(discussion)?, "provider_discussions")
                            }
                        };
                        value["archive_type"] = serde_json::json!(archive_type);
                        value["trust"] = serde_json::json!("untrusted_external");
                        value["gate_eligible"] = serde_json::json!(false);
                        serde_json::to_writer(std::io::stdout().lock(), &value)?;
                        println!();
                        Ok(0)
                    }
                    ImportedCommand::Search {
                        query,
                        limit,
                        output,
                    } => {
                        let workspace = operations::Workspace::new(
                            std::path::PathBuf::from(&top),
                            crate::local_stores(),
                        );
                        let report =
                            operations::search_imported_history(&workspace, &query, limit)?;
                        match output {
                            Output::Json => emit_json(&report)?,
                            Output::Text => {
                                for item in report["matches"].as_array().into_iter().flatten() {
                                    println!(
                                        "{}  {}  {}  {}:{}  untrusted_external (not gate eligible)",
                                        item["archive_digest"],
                                        item["review_id"],
                                        item["finding"]["severity"],
                                        item["finding"]["path"].as_str().unwrap_or("<unknown>"),
                                        item["finding"]["line"].as_u64().unwrap_or(0)
                                    );
                                    println!(
                                        "  {}",
                                        item["finding"]["rationale"].as_str().unwrap_or("")
                                    );
                                }
                            }
                        }
                        Ok(0)
                    }
                    ImportedCommand::Feedback { command } => match command {
                        ImportedFeedbackCommand::Set {
                            archive_digest,
                            external_id,
                            category,
                            label,
                            reason,
                            reviewer,
                            output,
                        } => {
                            let workspace = operations::Workspace::new(
                                std::path::PathBuf::from(&top),
                                crate::local_stores(),
                            );
                            let recorded = operations::record_external_feedback(
                                &workspace,
                                operations::ExternalFeedbackRequest {
                                    archive_digest: &archive_digest,
                                    external_id: &external_id,
                                    category: &category,
                                    label: label.into(),
                                    reason: &reason,
                                    reviewer: &reviewer,
                                },
                            )?;
                            let feedback = &recorded.feedback;
                            match output {
                                Output::Json => emit_json(&recorded)?,
                                Output::Text => println!("Recorded {} feedback for external comment {} in {} (human label; never gate eligible).", feedback.label_text(), feedback.external_id, feedback.archive_digest),
                            }
                            Ok(0)
                        }
                        ImportedFeedbackCommand::List {
                            archive_digest,
                            output,
                        } => {
                            let workspace = operations::Workspace::new(
                                std::path::PathBuf::from(&top),
                                crate::local_stores(),
                            );
                            let listed = operations::list_external_feedback(
                                &workspace,
                                archive_digest.as_deref(),
                            )?;
                            let feedback = &listed.feedback;
                            match output {
                                Output::Json => emit_json(&listed)?,
                                Output::Text => {
                                    for item in feedback {
                                        println!(
                                            "{} {} {} {} — {}",
                                            item.archive_digest,
                                            item.external_id,
                                            item.label_text(),
                                            item.reviewer,
                                            item.reason
                                        );
                                    }
                                }
                            }
                            Ok(0)
                        }
                    },
                },
            }
        }
        Command::Analytics { output } => {
            let workspace = operations::Workspace::discover(crate::local_stores())?;
            let analytics = operations::quality_analytics(&workspace)?;
            match output {
                Output::Json => emit_json(&analytics)?,
                Output::Text => print_view(&analytics)?,
            }
            Ok(0)
        }
        Command::Repos { command } => match command {
            ReposCommand::Map {
                repositories,
                output,
            } => {
                let result = repository_map::build(&repositories).map_err(anyhow::Error::msg)?;
                match output {
                    Output::Json => {
                        serde_json::to_writer(std::io::stdout().lock(), &result)?;
                        println!();
                    }
                    Output::Text => {
                        println!(
                            "Local repository dependency map ({} repositories, {} direct edges)",
                            result.repositories.len(),
                            result.dependencies.len()
                        );
                        for repo in &result.repositories {
                            println!("  {} [{}] {}", repo.id, repo.ecosystem, repo.root);
                        }
                        for edge in &result.dependencies {
                            println!(
                                "  {} -> {} ({}, {}) [{}]",
                                edge.from, edge.to, edge.package, edge.kind, edge.evidence_digest
                            );
                        }
                        for limitation in &result.limitations {
                            println!("Limitation: {limitation}");
                        }
                        println!("Map digest: {}", result.digest);
                    }
                }
                Ok(0)
            }
            ReposCommand::Package {
                repositories,
                pull_requests,
                discover_linked_prs,
                refresh_pr_links,
                base,
                output,
            } => {
                let mut explicit_links =
                    std::collections::BTreeMap::<String, Vec<vee_hosting::PullRequestRef>>::new();
                for value in pull_requests {
                    let (repository_id, reference) =
                        repository_map::parse_pull_request_link(&value).map_err(usage_failure)?;
                    let entry = explicit_links.entry(repository_id).or_default();
                    if entry.contains(&reference) {
                        return Err(usage_failure("pull request link is repeated"));
                    }
                    entry.push(reference);
                }
                let mut links = explicit_links.clone();
                let mut discovered_links =
                    std::collections::BTreeMap::<String, Vec<vee_hosting::PullRequestRef>>::new();
                if discover_linked_prs {
                    discovered_links = repository_map::discover_linked_pull_requests(&repositories)
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
                if refresh_pr_links && links.is_empty() {
                    return Err(usage_failure(
                        "--refresh-pr-links requires at least one --link-pr",
                    ));
                }
                let mut remote_states = std::collections::BTreeMap::new();
                if refresh_pr_links {
                    let local = repository_map::build(&repositories).map_err(anyhow::Error::msg)?;
                    for entry in &local.repositories {
                        let Some(references) = links.get(&entry.id) else {
                            continue;
                        };
                        let root = std::path::Path::new(&entry.root);
                        let local_head_oid = repository_map::repository_head_oid(root)
                            .map_err(anyhow::Error::msg)?;
                        let (offline, hosting) = load_hosting_config(root)?;
                        if offline {
                            return Err(configuration_failure(format!(
                                "offline mode prevents refreshing linked pull requests in {}",
                                root.display()
                            )));
                        }
                        let provider_id =
                            hosting.provider.clone().unwrap_or_else(|| "github".into());
                        let host = hosting.host.clone().unwrap_or_else(|| "github.com".into());
                        let api_base = hosting.api_base.clone().unwrap_or_default();
                        let token_env = hosting.token_env.clone().unwrap_or_else(|| {
                            match provider_id.as_str() {
                                "gitlab" => "GL_TOKEN",
                                "bitbucket" => "BB_TOKEN",
                                "azure-devops" => "AZURE_DEVOPS_EXT_PAT",
                                "gerrit" => "GERRIT_TOKEN",
                                _ => "GH_TOKEN",
                            }
                            .into()
                        });
                        let token = std::env::var(&token_env).with_context(|| {
                            format!(
                                "required credential environment variable {token_env} is not set"
                            )
                        })?;
                        let host = effective_work_item_host(&provider_id, &host)?;
                        let api_base = work_item_api_base(&provider_id, &host, &api_base)?;
                        let username = hosting.username.unwrap_or_default();
                        let adapter: Box<dyn vee_hosting::PullRequestContextProvider> =
                            match provider_id.as_str() {
                                "github" => Box::new(
                                    vee_hosting::github::GitHubAdapter::new(
                                        vee_hosting::github::GitHubConfig::new(
                                            &api_base,
                                            token,
                                            String::new(),
                                        )
                                        .map_err(configuration_failure)?,
                                    )
                                    .map_err(configuration_failure)?,
                                ),
                                "gitlab" => Box::new(
                                    vee_hosting::gitlab::GitLabAdapter::new(
                                        vee_hosting::gitlab::GitLabConfig::new(&api_base, token)
                                            .map_err(configuration_failure)?,
                                    )
                                    .map_err(configuration_failure)?,
                                ),
                                "bitbucket" => Box::new(
                                    vee_hosting::bitbucket::BitbucketAdapter::new(
                                        vee_hosting::bitbucket::BitbucketConfig::new(
                                            &api_base, token,
                                        )
                                        .map_err(configuration_failure)?,
                                    )
                                    .map_err(configuration_failure)?,
                                ),
                                "azure-devops" => Box::new(
                                    vee_hosting::azure_devops::AzureDevOpsAdapter::new(
                                        vee_hosting::azure_devops::AzureDevOpsConfig::new(
                                            &api_base, token,
                                        )
                                        .map_err(configuration_failure)?,
                                    )
                                    .map_err(configuration_failure)?,
                                ),
                                "gerrit" => {
                                    let mut config =
                                        vee_hosting::gerrit::GerritConfig::new(&api_base, token)
                                            .map_err(configuration_failure)?;
                                    if !username.is_empty() {
                                        config = config.with_username(username);
                                    }
                                    Box::new(
                                        vee_hosting::gerrit::GerritAdapter::new(config)
                                            .map_err(configuration_failure)?,
                                    )
                                }
                                _ => {
                                    return Err(configuration_failure(format!(
                                        "unsupported hosting provider `{provider_id}`"
                                    )))
                                }
                            };
                        let mut states = Vec::new();
                        for reference in references {
                            let snapshot = adapter
                                .get_pull_request_context(reference)
                                .map_err(anyhow::Error::msg)?;
                            states.push(repository_map::RemotePullRequestState {
                                pull_request: reference.clone(),
                                provider: provider_id.clone(),
                                state: format!("{:?}", snapshot.state).to_ascii_lowercase(),
                                base_oid: snapshot.base_oid,
                                local_head_matches: snapshot.head_oid == local_head_oid,
                                head_oid: snapshot.head_oid,
                                revision: snapshot.revision,
                            });
                        }
                        remote_states.insert(entry.id.clone(), states);
                    }
                }
                let package = repository_map::change_package_with_pull_requests(
                    &repositories,
                    base.as_deref(),
                    &links,
                    &discovered_links,
                    &remote_states,
                    &vee_store_sqlite::SqliteRepositoryStores,
                )
                .map_err(|error| {
                    if error.starts_with("pull request link") {
                        usage_failure(error)
                    } else {
                        anyhow::Error::msg(error)
                    }
                })?;
                match output {
                    Output::Json => {
                        serde_json::to_writer(std::io::stdout().lock(), &package)?;
                        println!();
                    }
                    Output::Text => {
                        println!(
                            "Change package {} ({} repositories)",
                            package.package_id,
                            package.repositories.len()
                        );
                        for repository in &package.repositories {
                            println!(
                                "  {} [{}] {} — {} changed files — gate: {}",
                                repository.repository_id,
                                repository.branch.as_deref().unwrap_or("detached"),
                                repository.root,
                                repository.changed_files.len(),
                                repository.saved_gate_status
                            );
                            for file in &repository.changed_files {
                                println!("    {} ({})", file.path, file.status);
                            }
                            for remote in &repository.remote_pull_requests {
                                println!(
                                    "    PR {}#{}: {} — provider revision {} — local head match: {}",
                                    remote.pull_request.repository.full_name,
                                    remote.pull_request.number,
                                    remote.state,
                                    remote.revision,
                                    remote.local_head_matches
                                );
                            }
                        }
                        println!("Local dependency edges: {}", package.dependency_edges.len());
                        for limitation in &package.limitations {
                            println!("Limitation: {limitation}");
                        }
                    }
                }
                Ok(0)
            }
            ReposCommand::Impact {
                producer,
                consumers,
                base,
                output,
            } => {
                let result = repository_map::analyze_cross_impact(&producer, &base, &consumers)
                    .map_err(anyhow::Error::msg)?;
                match output {
                    Output::Json => {
                        serde_json::to_writer(std::io::stdout().lock(), &result)?;
                        println!();
                    }
                    Output::Text => {
                        println!(
                            "Cross-repository impact for producer snapshot: {}",
                            result.producer_snapshot_id
                        );
                        println!("Changed symbols: {}", result.changed_symbols.join(", "));
                        for path in &result.dependency_paths {
                            println!("  package path: {}", path.packages.join(" -> "));
                            println!("    manifest digests: {}", path.manifest_digests.join(", "));
                        }
                        for reference in &result.references {
                            println!(
                                "  {}:{}:{} may reference {} ({})",
                                reference.consumer_repository,
                                reference.path,
                                reference.line,
                                reference.symbol,
                                reference.certainty
                            );
                        }
                        println!("Coverage complete: {}", result.coverage_complete);
                        for limitation in &result.limitations {
                            println!("Limitation: {limitation}");
                        }
                        println!("Impact digest: {}", result.digest);
                    }
                }
                Ok(0)
            }
        },
        Command::Hosting { command } => match command {
            HostingCommand::PrIssues {
                repository,
                number,
                provider,
                host,
                api_base,
                token_env,
                username,
                output,
                archive,
            } => {
                let cwd = std::env::current_dir()?;
                let config_root = vee_git::repository_root(&cwd).unwrap_or(cwd);
                let (offline, hosting) = load_hosting_config(&config_root)?;
                if offline {
                    return Err(configuration_failure(
                        "offline mode prevents fetching pull request review issues",
                    ));
                }
                let provider_id = resolve_hosting_setting(provider, hosting.provider, "github");
                if !matches!(
                    provider_id.as_str(),
                    "github" | "gitlab" | "bitbucket" | "azure-devops" | "gerrit"
                ) {
                    return Err(configuration_failure(format!(
                        "unsupported hosting provider `{provider_id}`"
                    )));
                }
                let host = resolve_hosting_setting(host, hosting.host, "github.com");
                let api_base = resolve_hosting_setting(api_base, hosting.api_base, "");
                let token_env = resolve_hosting_setting(token_env, hosting.token_env, "GH_TOKEN");
                let username = resolve_hosting_setting(username, hosting.username, "");
                let token_env = effective_work_item_token_env(&provider_id, &token_env);
                let token = std::env::var(token_env).with_context(|| {
                    format!("required credential environment variable {token_env} is not set")
                })?;
                let host = effective_work_item_host(&provider_id, &host)?;
                let api_base = work_item_api_base(&provider_id, &host, &api_base)?;
                let reference = vee_hosting::PullRequestRef {
                    repository: vee_hosting::RepositoryRef {
                        host,
                        full_name: repository,
                    },
                    number,
                };
                reference.validate().map_err(configuration_failure)?;
                if provider_id != "gerrit" && !username.is_empty() {
                    return Err(configuration_failure(
                        "--username is only supported with the Gerrit provider",
                    ));
                }
                let adapter: Box<dyn vee_hosting::PullRequestReviewIssuesProvider> =
                    match provider_id.as_str() {
                        "github" => Box::new(
                            vee_hosting::github::GitHubAdapter::new(
                                vee_hosting::github::GitHubConfig::new(
                                    &api_base,
                                    token,
                                    String::new(),
                                )
                                .map_err(configuration_failure)?,
                            )
                            .map_err(configuration_failure)?,
                        ),
                        "gitlab" => Box::new(
                            vee_hosting::gitlab::GitLabAdapter::new(
                                vee_hosting::gitlab::GitLabConfig::new(&api_base, token)
                                    .map_err(configuration_failure)?,
                            )
                            .map_err(configuration_failure)?,
                        ),
                        "bitbucket" => Box::new(
                            vee_hosting::bitbucket::BitbucketAdapter::new(
                                vee_hosting::bitbucket::BitbucketConfig::new(&api_base, token)
                                    .map_err(configuration_failure)?,
                            )
                            .map_err(configuration_failure)?,
                        ),
                        "azure-devops" => Box::new(
                            vee_hosting::azure_devops::AzureDevOpsAdapter::new(
                                vee_hosting::azure_devops::AzureDevOpsConfig::new(&api_base, token)
                                    .map_err(configuration_failure)?,
                            )
                            .map_err(configuration_failure)?,
                        ),
                        "gerrit" => {
                            let mut config =
                                vee_hosting::gerrit::GerritConfig::new(&api_base, token)
                                    .map_err(configuration_failure)?;
                            if !username.is_empty() {
                                config = config.with_username(username);
                            }
                            Box::new(
                                vee_hosting::gerrit::GerritAdapter::new(config)
                                    .map_err(configuration_failure)?,
                            )
                        }
                        _ => {
                            return Err(configuration_failure(format!(
                                "unsupported hosting provider `{provider_id}`"
                            )))
                        }
                    };
                let report = adapter
                    .list_pull_request_review_issues(&reference)
                    .map_err(anyhow::Error::msg)?;
                let archive_digest = if archive {
                    anyhow::ensure!(
                        !report.gate_eligible,
                        "provider review discussions must remain non-gating"
                    );
                    let bytes = serde_json::to_vec(&report)?;
                    Some(store_imported_history(&config_root, &bytes)?)
                } else {
                    None
                };
                match output {
                    Output::Json => {
                        let mut value = serde_json::to_value(&report)?;
                        if let Some(digest) = &archive_digest {
                            value["archive_digest"] = serde_json::Value::String(digest.clone());
                        }
                        serde_json::to_writer(std::io::stdout().lock(), &value)?;
                        println!();
                    }
                    Output::Text => {
                        println!(
                            "{} #{} — {} external review issue(s){}",
                            report.pull_request.repository.full_name,
                            report.pull_request.number,
                            report.issues.len(),
                            if report.complete {
                                ""
                            } else {
                                " (incomplete pagination)"
                            }
                        );
                        if let Some(digest) = &archive_digest {
                            println!("Archived as {digest}");
                        }
                        for issue in &report.issues {
                            println!(
                                "- {} {}:{} — {}",
                                issue.external_id,
                                issue.path.as_deref().unwrap_or("(general comment)"),
                                issue
                                    .line
                                    .map(|line| line.to_string())
                                    .unwrap_or_else(|| "?".into()),
                                issue.body.lines().next().unwrap_or_default()
                            );
                        }
                    }
                }
                Ok(if report.complete { 0 } else { 2 })
            }
            HostingCommand::PrContext {
                repository,
                number,
                provider,
                host,
                api_base,
                token_env,
                username,
                output,
            } => {
                let cwd = std::env::current_dir()?;
                let config_root = vee_git::repository_root(&cwd).unwrap_or(cwd);
                let (offline, hosting) = load_hosting_config(&config_root)?;
                if offline {
                    return Err(configuration_failure(
                        "offline mode prevents fetching pull request context",
                    ));
                }
                let provider_id =
                    resolve_hosting_setting(provider, hosting.provider, "azure-devops");
                let host = resolve_hosting_setting(host, hosting.host, "github.com");
                let api_base = resolve_hosting_setting(api_base, hosting.api_base, "");
                let token_env =
                    resolve_hosting_setting(token_env, hosting.token_env, "AZURE_DEVOPS_EXT_PAT");
                let username = resolve_hosting_setting(username, hosting.username, "");
                let token_env = match provider_id.as_str() {
                    "github" if token_env == "AZURE_DEVOPS_EXT_PAT" => "GH_TOKEN",
                    "gitlab" if token_env == "AZURE_DEVOPS_EXT_PAT" => "GL_TOKEN",
                    "bitbucket" if token_env == "AZURE_DEVOPS_EXT_PAT" => "BB_TOKEN",
                    "gerrit" if token_env == "AZURE_DEVOPS_EXT_PAT" => "GERRIT_TOKEN",
                    _ => &token_env,
                };
                let token = std::env::var(token_env).with_context(|| {
                    format!("required credential environment variable {token_env} is not set")
                })?;
                let host = effective_work_item_host(&provider_id, &host)?;
                let api_base = work_item_api_base(&provider_id, &host, &api_base)?;
                let reference = vee_hosting::PullRequestRef {
                    repository: vee_hosting::RepositoryRef {
                        host: host.clone(),
                        full_name: repository,
                    },
                    number,
                };
                reference.validate().map_err(configuration_failure)?;
                let provider: Box<dyn vee_hosting::PullRequestContextProvider> = match provider_id
                    .as_str()
                {
                    "github" => Box::new(
                        vee_hosting::github::GitHubAdapter::new(
                            vee_hosting::github::GitHubConfig::new(&api_base, token, String::new())
                                .map_err(configuration_failure)?,
                        )
                        .map_err(configuration_failure)?,
                    ),
                    "gitlab" => Box::new(
                        vee_hosting::gitlab::GitLabAdapter::new(
                            vee_hosting::gitlab::GitLabConfig::new(&api_base, token)
                                .map_err(configuration_failure)?,
                        )
                        .map_err(configuration_failure)?,
                    ),
                    "bitbucket" => Box::new(
                        vee_hosting::bitbucket::BitbucketAdapter::new(
                            vee_hosting::bitbucket::BitbucketConfig::new(&api_base, token)
                                .map_err(configuration_failure)?,
                        )
                        .map_err(configuration_failure)?,
                    ),
                    "azure-devops" => Box::new(
                        vee_hosting::azure_devops::AzureDevOpsAdapter::new(
                            vee_hosting::azure_devops::AzureDevOpsConfig::new(&api_base, token)
                                .map_err(configuration_failure)?,
                        )
                        .map_err(configuration_failure)?,
                    ),
                    "gerrit" => {
                        let mut config = vee_hosting::gerrit::GerritConfig::new(&api_base, token)
                            .map_err(configuration_failure)?;
                        if !username.is_empty() {
                            config = config.with_username(username);
                        }
                        Box::new(
                            vee_hosting::gerrit::GerritAdapter::new(config)
                                .map_err(configuration_failure)?,
                        )
                    }
                    _ => {
                        return Err(configuration_failure(format!(
                            "unsupported pull request provider `{provider_id}`"
                        )))
                    }
                };
                let snapshot = provider
                    .get_pull_request_context(&reference)
                    .map_err(anyhow::Error::msg)?;
                let changed_files = provider
                    .list_pull_request_context_files(&reference, &snapshot.revision)
                    .map_err(anyhow::Error::msg)?;
                let report = vee_hosting::PullRequestContextReport {
                    schema_version: 1,
                    provider: provider_id.clone(),
                    snapshot,
                    changed_files,
                    limitations: match provider_id.as_str() {
                        "azure-devops" => vec!["Azure DevOps diff metadata does not include line-level patches; file records are context only, not line evidence.".into()],
                        "bitbucket" => vec!["Bitbucket unified diffs are bounded to 5 MiB; quoted or unsupported paths may lack line-level patch evidence.".into()],
                        _ => vec![],
                    },
                };
                match output {
                    Output::Json => {
                        serde_json::to_writer(std::io::stdout().lock(), &report)?;
                        println!();
                    }
                    Output::Text => {
                        println!(
                            "{} #{} — {} ({:?})\nRevision: {}",
                            report.snapshot.pull_request.repository.full_name,
                            report.snapshot.pull_request.number,
                            report.snapshot.title,
                            report.snapshot.state,
                            report.snapshot.revision
                        );
                        for file in &report.changed_files {
                            println!("{:?} {}", file.change, file.path);
                        }
                        for limitation in &report.limitations {
                            println!("Limit: {limitation}");
                        }
                    }
                }
                Ok(0)
            }
            HostingCommand::IssueContext {
                repository,
                number,
                provider,
                host,
                api_base,
                token_env,
                output,
            } => {
                let cwd = std::env::current_dir()?;
                let config_root = vee_git::repository_root(&cwd).unwrap_or(cwd);
                let (offline, hosting) = load_hosting_config(&config_root)?;
                if offline {
                    return Err(configuration_failure(
                        "offline mode prevents fetching work item context",
                    ));
                }
                let provider = resolve_hosting_setting(provider, hosting.provider, "github");
                let host = resolve_hosting_setting(host, hosting.host, "github.com");
                let api_base = resolve_hosting_setting(api_base, hosting.api_base, "");
                let token_env = resolve_hosting_setting(token_env, hosting.token_env, "");
                let token_env = if token_env.is_empty() {
                    match provider.as_str() {
                        "gitlab" => "GL_TOKEN",
                        "azure-devops" => "AZURE_DEVOPS_EXT_PAT",
                        "gerrit" => "GERRIT_TOKEN",
                        _ => "GH_TOKEN",
                    }
                } else {
                    &token_env
                };
                let token = std::env::var(token_env).with_context(|| {
                    format!("required credential environment variable {token_env} is not set")
                })?;
                let host = effective_work_item_host(&provider, &host)?;
                let api_base = work_item_api_base(&provider, &host, &api_base)?;
                let reference = vee_hosting::WorkItemRef {
                    repository: vee_hosting::RepositoryRef {
                        host: host.clone(),
                        full_name: repository,
                    },
                    number,
                };
                reference.validate().map_err(configuration_failure)?;
                let item = get_work_item(&provider, &api_base, token, &reference)?;
                match output {
                    Output::Json => {
                        serde_json::to_writer(std::io::stdout().lock(), &item)?;
                        println!();
                    }
                    Output::Text => println!(
                        "{} #{} — {} ({})\n{}\nContent digest: {}",
                        reference.repository.full_name,
                        reference.number,
                        item.title,
                        item.state,
                        item.url,
                        item.content_digest
                    ),
                }
                Ok(0)
            }
            HostingCommand::Publish {
                review: review_id,
                repository,
                number,
                provider,
                host,
                api_base,
                token_env,
                username,
                webhook_secret_env,
                actor_login,
                output,
            } => {
                let cwd = std::env::current_dir()?;
                let top = vee_git::repository_root(&cwd)
                    .map_err(anyhow::Error::msg)?
                    .to_string_lossy()
                    .to_string();
                let (offline, hosting) = load_hosting_config(std::path::Path::new(&top))?;
                anyhow::ensure!(
                    !offline,
                    "offline mode prevents publishing to a Git hosting provider"
                );
                let provider_id = resolve_hosting_setting(provider, hosting.provider, "github");
                let host = resolve_hosting_setting(host, hosting.host, "github.com");
                let api_base = resolve_hosting_setting(api_base, hosting.api_base, "");
                let token_env = resolve_hosting_setting(token_env, hosting.token_env, "");
                let username = resolve_hosting_setting(username, hosting.username, "");
                let webhook_secret_env = resolve_hosting_setting(
                    webhook_secret_env,
                    hosting.webhook_secret_env,
                    "VEE_GITHUB_WEBHOOK_SECRET",
                );
                let actor_login = resolve_hosting_setting(actor_login, hosting.actor_login, "");
                // The same re-evaluation as `vee gate check`, so a published
                // decision is the one the gate would make now.
                let reevaluated = operations::reevaluate_gate(
                    &operations::Workspace::new(
                        std::path::PathBuf::from(&top),
                        crate::local_stores(),
                    ),
                    &review_id,
                    None,
                )?;
                let mut reviewed = reevaluated.review;
                reviewed.gate = reevaluated.decision;
                let mut store =
                    ReviewStore::open(&std::path::Path::new(&top).join(".vee/vee.sqlite"))
                        .map_err(anyhow::Error::msg)?;
                anyhow::ensure!(
                    reviewed.analysis_complete,
                    "cannot publish an incomplete review"
                );
                anyhow::ensure!(
                    reviewed.snapshot_id == reviewed.change_set.digest,
                    "review snapshot digest is invalid"
                );
                anyhow::ensure!(
                    !matches!(
                        reviewed.change_set.scope.as_str(),
                        "staged" | "working_tree"
                    ),
                    "cannot publish a staged-only or working-tree-only snapshot to a pull request"
                );
                if reviewed.change_set.scope == "base_and_worktree" {
                    anyhow::ensure!(
                        committed_snapshot_matches_review(
                            std::path::Path::new(&top),
                            &reviewed.change_set,
                        )
                        .map_err(anyhow::Error::msg)?,
                        "cannot publish a review whose captured worktree content differs from the committed PR diff"
                    );
                    let status = std::process::Command::new("git")
                        .args(["status", "--porcelain", "--untracked-files=all"])
                        .current_dir(&top)
                        .output()?;
                    anyhow::ensure!(
                        status.status.success(),
                        "could not verify the local worktree state"
                    );
                    anyhow::ensure!(status.stdout.is_empty(), "cannot publish a snapshot while the local worktree or index has uncommitted changes");
                }
                let token_env = if token_env.is_empty() {
                    match provider_id.as_str() {
                        "gitlab" => "GL_TOKEN",
                        "bitbucket" => "BB_TOKEN",
                        "azure-devops" => "AZURE_DEVOPS_EXT_PAT",
                        "gerrit" => "GERRIT_TOKEN",
                        _ => "GH_TOKEN",
                    }
                } else {
                    &token_env
                };
                let token = std::env::var(token_env).with_context(|| {
                    format!("required credential environment variable {token_env} is not set")
                })?;
                let secret_env = if webhook_secret_env == "VEE_GITHUB_WEBHOOK_SECRET"
                    && provider_id == "bitbucket"
                {
                    "VEE_BITBUCKET_WEBHOOK_SECRET"
                } else {
                    &webhook_secret_env
                };
                let webhook_secret = std::env::var(secret_env).unwrap_or_default();
                let host = effective_work_item_host(&provider_id, &host)?;
                let api_base = work_item_api_base(&provider_id, &host, &api_base)?;
                if provider_id == "azure-devops" {
                    let provider = vee_hosting::azure_devops::AzureDevOpsAdapter::new(
                        vee_hosting::azure_devops::AzureDevOpsConfig::new(&api_base, token)
                            .map_err(anyhow::Error::msg)?,
                    )
                    .map_err(anyhow::Error::msg)?;
                    let pull_request = vee_hosting::PullRequestRef {
                        repository: vee_hosting::RepositoryRef {
                            host: host.clone(),
                            full_name: repository.clone(),
                        },
                        number,
                    };
                    let remote = vee_hosting::PullRequestContextProvider::get_pull_request_context(
                        &provider,
                        &pull_request,
                    )
                    .map_err(anyhow::Error::msg)?;
                    anyhow::ensure!(
                        remote.state == vee_hosting::PullRequestState::Open,
                        "pull request is not open"
                    );
                    anyhow::ensure!(reviewed.change_set.head_oid.as_deref() == Some(remote.head_oid.as_str()), "reviewed head does not match the current pull request head; rerun Vee against the PR head");
                    anyhow::ensure!(reviewed.change_set.base_oid.as_deref() == Some(remote.base_oid.as_str()), "reviewed base does not match the current pull request base; rerun Vee against the current PR diff");
                    // Equal to the provider's commits (checked above), but captured
                    // from local Git, so these are what reach git as arguments.
                    let reviewed_base = reviewed.change_set.base_oid.clone().unwrap_or_default();
                    let reviewed_head = reviewed.change_set.head_oid.clone().unwrap_or_default();
                    let (conclusion, title) = match reviewed.gate.status {
                        vee_core::GateStatus::Pass => {
                            (vee_hosting::CheckConclusion::Success, "Vee passed")
                        }
                        vee_core::GateStatus::Block => {
                            (vee_hosting::CheckConclusion::Failure, "Vee blocked")
                        }
                        vee_core::GateStatus::Incomplete => (
                            vee_hosting::CheckConclusion::ActionRequired,
                            "Vee incomplete",
                        ),
                    };
                    let summary = if reviewed.gate.reasons.is_empty() {
                        format!("Gate status: {:?}", reviewed.gate.status)
                    } else {
                        reviewed
                            .gate
                            .reasons
                            .iter()
                            .map(|reason| format!("- {reason}"))
                            .collect::<Vec<_>>()
                            .join("\n")
                    };
                    let mut threads = Vec::new();
                    for finding in &reviewed.findings {
                        if matches!(finding.severity, Severity::Info) {
                            continue;
                        }
                        let (Some(path), Some(line)) = (&finding.path, finding.line) else {
                            continue;
                        };
                        let relative = std::path::Path::new(path);
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
                            continue;
                        }
                        let diff = std::process::Command::new("git")
                            .args([
                                "--literal-pathspecs",
                                "diff",
                                "--no-ext-diff",
                                "--unified=0",
                            ])
                            .arg(&reviewed_base)
                            .arg(&reviewed_head)
                            .arg("--")
                            .arg(path)
                            .current_dir(&top)
                            .output()?;
                        anyhow::ensure!(diff.status.success(), "could not verify Azure DevOps finding locations against the local PR diff");
                        if !diff_contains_added_line(Some(std::str::from_utf8(&diff.stdout)?), line)
                        {
                            continue;
                        }
                        threads.push(vee_hosting::ReviewThread {
                            pull_request: pull_request.clone(),
                            fingerprint: finding.fingerprint.clone(),
                            path: path.clone(),
                            line: u64::from(line),
                            side: vee_hosting::DiffSide::New,
                            body: format!("**{:?} · {}** (confidence: {}%)\n\n{}\n\nVee finding `{}` · snapshot `{}`", finding.severity, finding.category, finding.confidence.unwrap_or(0), finding.rationale, finding.id, reviewed.snapshot_id),
                            resolution: vee_hosting::ThreadResolution::Open,
                            snapshot_id: reviewed.snapshot_id.clone(),
                            idempotency_key: format!("{}:{}", reviewed.review_id, finding.fingerprint),
                        });
                    }
                    let active_fingerprints = reviewed
                        .findings
                        .iter()
                        .map(|finding| finding.fingerprint.clone())
                        .collect();
                    let resolved_findings = store
                        .list_findings(None, Some(vee_core::FindingStatus::Resolved), None)
                        .map_err(anyhow::Error::msg)?;
                    let thread_target = hosting_thread_target_key(&provider_id, &pull_request)
                        .map_err(anyhow::Error::msg)?;
                    let previously_published = store
                        .hosted_finding_threads(&thread_target)
                        .map_err(anyhow::Error::msg)?;
                    add_resolved_hosting_threads(
                        &mut threads,
                        &resolved_findings,
                        &active_fingerprints,
                        &previously_published,
                        &pull_request,
                        &reviewed.review_id,
                        &reviewed.snapshot_id,
                    );
                    let published_fingerprints =
                        updated_hosted_finding_fingerprints(&previously_published, &threads);
                    let intent_fingerprints =
                        hosting_thread_intent_fingerprints(&previously_published, &threads);
                    store
                        .replace_hosted_finding_threads(&thread_target, &intent_fingerprints)
                        .map_err(anyhow::Error::msg)?;
                    let thread_ids = if threads.is_empty() {
                        std::collections::BTreeMap::new()
                    } else {
                        provider
                            .publish_threads(&pull_request, &remote.revision, &threads)
                            .map_err(anyhow::Error::msg)?
                    };
                    let check = vee_hosting::CheckRun {
                        pull_request: pull_request.clone(),
                        external_id: reviewed.review_id.clone(),
                        name: "Vee".into(),
                        status: vee_hosting::CheckStatus::Completed,
                        conclusion: Some(conclusion),
                        title: title.into(),
                        summary,
                        snapshot_id: reviewed.snapshot_id.clone(),
                        idempotency_key: reviewed.review_id.clone(),
                    };
                    let check_id = provider
                        .publish_check(&pull_request, &remote.revision, &check)
                        .map_err(anyhow::Error::msg)?;
                    store
                        .replace_hosted_finding_threads(&thread_target, &published_fingerprints)
                        .map_err(anyhow::Error::msg)?;
                    match output {
                        Output::Json => { serde_json::to_writer(std::io::stdout().lock(), &serde_json::json!({"schema_version":1,"review_id":reviewed.review_id,"snapshot_id":reviewed.snapshot_id,"provider_check_id":check_id,"thread_ids":thread_ids,"revision":remote.revision}))?; println!(); }
                        Output::Text => println!("Published Vee review for {} to {}/{}#{} on Azure DevOps (status {}, {} finding threads)", reviewed.review_id, host, repository, number, check_id, thread_ids.len()),
                    }
                    return Ok(0);
                }
                let provider: Box<dyn vee_hosting::GitHostingProvider> = match provider_id.as_str()
                {
                    "github" => Box::new(
                        vee_hosting::github::GitHubAdapter::new(
                            vee_hosting::github::GitHubConfig::new(
                                &api_base,
                                token,
                                webhook_secret,
                            )
                            .map_err(anyhow::Error::msg)?
                            .with_actor_login(actor_login),
                        )
                        .map_err(anyhow::Error::msg)?,
                    ),
                    "gitlab" => {
                        let secret_env = if webhook_secret_env == "VEE_GITHUB_WEBHOOK_SECRET" {
                            "VEE_GITLAB_WEBHOOK_SECRET"
                        } else {
                            &webhook_secret_env
                        };
                        let webhook_secret = std::env::var(secret_env).unwrap_or_default();
                        Box::new(
                            vee_hosting::gitlab::GitLabAdapter::new(
                                vee_hosting::gitlab::GitLabConfig::new(&api_base, token)
                                    .map_err(anyhow::Error::msg)?
                                    .with_webhook_secret(webhook_secret)
                                    .with_actor_login(actor_login),
                            )
                            .map_err(anyhow::Error::msg)?,
                        )
                    }
                    "bitbucket" => Box::new(
                        vee_hosting::bitbucket::BitbucketAdapter::new(
                            vee_hosting::bitbucket::BitbucketConfig::new(&api_base, token)
                                .map_err(anyhow::Error::msg)?
                                .with_webhook_secret(webhook_secret),
                        )
                        .map_err(anyhow::Error::msg)?,
                    ),
                    "gerrit" => {
                        let mut config = vee_hosting::gerrit::GerritConfig::new(&api_base, token)
                            .map_err(anyhow::Error::msg)?;
                        if !username.is_empty() {
                            config = config.with_username(username);
                        }
                        Box::new(
                            vee_hosting::gerrit::GerritAdapter::new(config)
                                .map_err(anyhow::Error::msg)?,
                        )
                    }
                    _ => {
                        return Err(configuration_failure(format!(
                            "unsupported hosting provider `{provider_id}`"
                        )))
                    }
                };
                let pull_request = vee_hosting::PullRequestRef {
                    repository: vee_hosting::RepositoryRef {
                        host: host.clone(),
                        full_name: repository.clone(),
                    },
                    number,
                };
                let remote = provider
                    .get_pull_request(&pull_request)
                    .map_err(anyhow::Error::msg)?;
                anyhow::ensure!(
                    remote.state == vee_hosting::PullRequestState::Open,
                    "pull request is not open"
                );
                anyhow::ensure!(reviewed.change_set.head_oid.as_deref() == Some(remote.head_oid.as_str()), "reviewed head does not match the current pull request head; rerun Vee against the PR head");
                anyhow::ensure!(reviewed.change_set.base_oid.as_deref() == Some(remote.base_oid.as_str()), "reviewed base does not match the current pull request base; rerun Vee against the current PR diff");
                // Equal to the provider's commits (checked above), but captured
                // from local Git, so these are what reach git as arguments.
                let reviewed_base = reviewed.change_set.base_oid.clone().unwrap_or_default();
                let reviewed_head = reviewed.change_set.head_oid.clone().unwrap_or_default();
                let changed = provider
                    .list_changed_files(&pull_request, &remote.revision)
                    .map_err(anyhow::Error::msg)?;
                let changed_paths: std::collections::BTreeSet<_> =
                    changed.iter().map(|file| file.path.as_str()).collect();
                let mut threads = Vec::new();
                for finding in &reviewed.findings {
                    if matches!(finding.severity, vee_core::Severity::Info) {
                        continue;
                    }
                    let (Some(path), Some(line)) = (&finding.path, finding.line) else {
                        continue;
                    };
                    anyhow::ensure!(
                        changed_paths.contains(path.as_str()),
                        "finding {} is outside the current pull request diff",
                        finding.id
                    );
                    let on_added_line = if provider_id == "gerrit" {
                        let diff = std::process::Command::new("git")
                            .args([
                                "--literal-pathspecs",
                                "diff",
                                "--no-ext-diff",
                                "--unified=0",
                            ])
                            .arg(&reviewed_base)
                            .arg(&reviewed_head)
                            .arg("--")
                            .arg(path)
                            .current_dir(&top)
                            .output()?;
                        anyhow::ensure!(diff.status.success(), "could not verify Gerrit finding locations against the local base-to-head Git diff");
                        diff_contains_added_line(Some(std::str::from_utf8(&diff.stdout)?), line)
                    } else {
                        changed.iter().any(|file| {
                            file.path == *path
                                && diff_contains_added_line(file.patch.as_deref(), line)
                        })
                    };
                    if !on_added_line {
                        continue;
                    }
                    let resolution = vee_hosting::ThreadResolution::Open;
                    let body = format!(
                        "**{:?} · {}** (confidence: {}%)\n\n{}\n\nVee finding `{}` · snapshot `{}`",
                        finding.severity,
                        finding.category,
                        finding.confidence.unwrap_or(0),
                        finding.rationale,
                        finding.id,
                        reviewed.snapshot_id
                    );
                    threads.push(vee_hosting::ReviewThread {
                        pull_request: pull_request.clone(),
                        fingerprint: finding.fingerprint.clone(),
                        path: path.clone(),
                        line: u64::from(line),
                        side: vee_hosting::DiffSide::New,
                        body,
                        resolution,
                        snapshot_id: reviewed.snapshot_id.clone(),
                        idempotency_key: format!("{}:{}", reviewed.review_id, finding.fingerprint),
                    });
                }
                let active_fingerprints = reviewed
                    .findings
                    .iter()
                    .map(|finding| finding.fingerprint.clone())
                    .collect();
                let resolved_findings = store
                    .list_findings(None, Some(vee_core::FindingStatus::Resolved), None)
                    .map_err(anyhow::Error::msg)?;
                let thread_target = hosting_thread_target_key(&provider_id, &pull_request)
                    .map_err(anyhow::Error::msg)?;
                let previously_published = store
                    .hosted_finding_threads(&thread_target)
                    .map_err(anyhow::Error::msg)?;
                add_resolved_hosting_threads(
                    &mut threads,
                    &resolved_findings,
                    &active_fingerprints,
                    &previously_published,
                    &pull_request,
                    &reviewed.review_id,
                    &reviewed.snapshot_id,
                );
                let (conclusion, title) = match reviewed.gate.status {
                    vee_core::GateStatus::Pass => {
                        (vee_hosting::CheckConclusion::Success, "Vee passed")
                    }
                    vee_core::GateStatus::Block => {
                        (vee_hosting::CheckConclusion::Failure, "Vee blocked")
                    }
                    vee_core::GateStatus::Incomplete => (
                        vee_hosting::CheckConclusion::ActionRequired,
                        "Vee incomplete",
                    ),
                };
                let summary = reviewed
                    .gate
                    .reasons
                    .iter()
                    .map(|reason| format!("- {reason}"))
                    .collect::<Vec<_>>()
                    .join("\n");
                let published_fingerprints =
                    updated_hosted_finding_fingerprints(&previously_published, &threads);
                let intent_fingerprints =
                    hosting_thread_intent_fingerprints(&previously_published, &threads);
                store
                    .replace_hosted_finding_threads(&thread_target, &intent_fingerprints)
                    .map_err(anyhow::Error::msg)?;
                let publication = vee_hosting::ReviewPublication {
                    pull_request: pull_request.clone(),
                    expected_revision: remote.revision.clone(),
                    check: vee_hosting::CheckRun {
                        pull_request,
                        external_id: reviewed.review_id.clone(),
                        name: "Vee".into(),
                        status: vee_hosting::CheckStatus::Completed,
                        conclusion: Some(conclusion),
                        title: title.into(),
                        summary: if summary.is_empty() {
                            format!("Gate status: {:?}", reviewed.gate.status)
                        } else {
                            summary
                        },
                        snapshot_id: reviewed.snapshot_id.clone(),
                        idempotency_key: reviewed.review_id.clone(),
                    },
                    threads,
                };
                let receipt = provider
                    .publish_review(publication)
                    .map_err(anyhow::Error::msg)?;
                store
                    .replace_hosted_finding_threads(&thread_target, &published_fingerprints)
                    .map_err(anyhow::Error::msg)?;
                match output {
                    Output::Json => {
                        serde_json::to_writer(
                            std::io::stdout().lock(),
                            &serde_json::json!({"schema_version":1,"review_id":reviewed.review_id,"snapshot_id":reviewed.snapshot_id,"provider_check_id":receipt.provider_check_id,"thread_ids":receipt.thread_ids,"revision":receipt.resulting_revision}),
                        )?;
                        println!();
                    }
                    Output::Text => println!(
                        "Published review {} to {}/{}#{} on {} (check {})",
                        reviewed.review_id,
                        host,
                        repository,
                        number,
                        provider_id,
                        receipt.provider_check_id
                    ),
                }
                Ok(0)
            }
            HostingCommand::WebhookServe {
                repository,
                provider,
                host,
                bind,
                port,
                api_base,
                token_env,
                username,
                webhook_secret_env,
                actor_login,
                allow_network,
            } => {
                if bind.is_unspecified() {
                    return Err(configuration_failure(
                        "wildcard webhook binding is not supported; bind to a specific interface",
                    ));
                }
                if !bind.is_loopback() {
                    return Err(configuration_failure(
                        "non-loopback webhook binding is disabled until Vee can serve TLS directly; use a secure local tunnel",
                    ));
                }
                let cwd = std::env::current_dir()?;
                let root = vee_git::repository_root(&cwd).map_err(anyhow::Error::msg)?;
                let (offline, hosting) = load_hosting_config(&root)?;
                anyhow::ensure!(!offline, "offline mode prevents serving hosting webhooks");
                let provider_id = resolve_hosting_setting(provider, hosting.provider, "github");
                let host = resolve_hosting_setting(host, hosting.host, "github.com");
                let api_base = resolve_hosting_setting(api_base, hosting.api_base, "");
                let token_env = resolve_hosting_setting(token_env, hosting.token_env, "");
                let username = resolve_hosting_setting(username, hosting.username, "");
                let webhook_secret_env = resolve_hosting_setting(
                    webhook_secret_env,
                    hosting.webhook_secret_env,
                    "VEE_GITHUB_WEBHOOK_SECRET",
                );
                let actor_login = resolve_hosting_setting(actor_login, hosting.actor_login, "");
                if matches!(provider_id.as_str(), "github" | "gitlab")
                    && actor_login.trim().is_empty()
                {
                    return Err(configuration_failure(
                        "--actor-login is required for GitHub and GitLab webhook reviews",
                    ));
                }
                let host = effective_work_item_host(&provider_id, &host)?;
                let api_base = work_item_api_base(&provider_id, &host, &api_base)?;
                let token_env = if token_env.is_empty() {
                    match provider_id.as_str() {
                        "gitlab" => "GL_TOKEN",
                        "bitbucket" => "BB_TOKEN",
                        "azure-devops" => "AZURE_DEVOPS_EXT_PAT",
                        "gerrit" => "GERRIT_TOKEN",
                        _ => "GH_TOKEN",
                    }
                } else {
                    &token_env
                };
                let token = std::env::var(token_env).with_context(|| {
                    format!("required credential environment variable {token_env} is not set")
                })?;
                let secret_env = if webhook_secret_env == "VEE_GITHUB_WEBHOOK_SECRET"
                    && provider_id == "gitlab"
                {
                    "VEE_GITLAB_WEBHOOK_SECRET"
                } else if webhook_secret_env == "VEE_GITHUB_WEBHOOK_SECRET"
                    && provider_id == "azure-devops"
                {
                    "VEE_AZURE_DEVOPS_WEBHOOK_SECRET"
                } else if webhook_secret_env == "VEE_GITHUB_WEBHOOK_SECRET"
                    && provider_id == "bitbucket"
                {
                    "VEE_BITBUCKET_WEBHOOK_SECRET"
                } else if webhook_secret_env == "VEE_GITHUB_WEBHOOK_SECRET"
                    && provider_id == "gerrit"
                {
                    "VEE_GERRIT_WEBHOOK_SECRET"
                } else {
                    &webhook_secret_env
                };
                let secret = std::env::var(secret_env).with_context(|| {
                    format!("required webhook secret environment variable {secret_env} is not set")
                })?;
                anyhow::ensure!(!secret.is_empty(), "webhook signing secret cannot be empty");
                let provider: std::sync::Arc<dyn vee_hosting::GitHostingProvider> =
                    match provider_id.as_str() {
                        "github" => std::sync::Arc::new(
                            vee_hosting::github::GitHubAdapter::new(
                                vee_hosting::github::GitHubConfig::new(&api_base, token, secret)
                                    .map_err(anyhow::Error::msg)?
                                    .with_actor_login(actor_login),
                            )
                            .map_err(anyhow::Error::msg)?,
                        ),
                        "gitlab" => std::sync::Arc::new(
                            vee_hosting::gitlab::GitLabAdapter::new(
                                vee_hosting::gitlab::GitLabConfig::new(&api_base, token)
                                    .map_err(anyhow::Error::msg)?
                                    .with_webhook_secret(secret)
                                    .with_actor_login(actor_login),
                            )
                            .map_err(anyhow::Error::msg)?,
                        ),
                        "azure-devops" => std::sync::Arc::new(
                            vee_hosting::azure_devops::AzureDevOpsAdapter::new(
                                vee_hosting::azure_devops::AzureDevOpsConfig::new(&api_base, token)
                                    .map_err(anyhow::Error::msg)?
                                    .with_webhook_secret(secret),
                            )
                            .map_err(anyhow::Error::msg)?,
                        ),
                        "bitbucket" => std::sync::Arc::new(
                            vee_hosting::bitbucket::BitbucketAdapter::new(
                                vee_hosting::bitbucket::BitbucketConfig::new(&api_base, token)
                                    .map_err(anyhow::Error::msg)?
                                    .with_webhook_secret(secret),
                            )
                            .map_err(anyhow::Error::msg)?,
                        ),
                        "gerrit" => {
                            let mut config =
                                vee_hosting::gerrit::GerritConfig::new(&api_base, token)
                                    .map_err(anyhow::Error::msg)?
                                    .with_webhook_secret(secret);
                            if !username.is_empty() {
                                config = config.with_username(username);
                            }
                            std::sync::Arc::new(
                                vee_hosting::gerrit::GerritAdapter::new(config)
                                    .map_err(anyhow::Error::msg)?,
                            )
                        }
                        _ => {
                            return Err(configuration_failure(format!(
                                "unsupported hosting provider `{provider_id}`"
                            )))
                        }
                    };
                let repository_ref = vee_hosting::RepositoryRef {
                    host,
                    full_name: repository,
                };
                repository_ref.validate().map_err(configuration_failure)?;
                let handler = std::sync::Arc::new(HostingWebhookReviewer {
                    root: root.clone(),
                    repository: repository_ref,
                    provider: provider.clone(),
                    lock: std::sync::Mutex::new(()),
                });
                let address = std::net::SocketAddr::new(bind, port);
                let auth_token = None;
                eprintln!("Vee {provider_id} webhook listener: http://{address}/api/webhooks/{provider_id}");
                if let Some(token) = auth_token.as_deref() {
                    eprintln!(
                        "Vee dashboard access token (enter it in the browser prompt): {token}"
                    );
                }
                tokio::runtime::Runtime::new()?.block_on(vee_http::serve_with_webhooks(
                    root,
                    address,
                    allow_network,
                    provider,
                    handler,
                    auth_token,
                ))?;
                Ok(0)
            }
            HostingCommand::PruneWebhooks {
                older_than_days,
                apply,
                output,
            } => {
                let cwd = std::env::current_dir()?;
                let root = vee_git::repository_root(&cwd).map_err(anyhow::Error::msg)?;
                let database = root.join(".vee/vee.sqlite");
                let mut store = ReviewStore::open(&database).map_err(anyhow::Error::msg)?;
                let now = current_unix_time()?;
                let retention_seconds = i64::from(older_than_days)
                    .checked_mul(86_400)
                    .context("webhook retention period exceeds supported timestamp")?;
                let cutoff = now
                    .checked_sub(retention_seconds)
                    .context("webhook retention cutoff is outside the supported range")?;
                let eligible = store
                    .prune_processed_webhook_deliveries_before(cutoff, apply)
                    .map_err(anyhow::Error::msg)?;
                match output {
                    Output::Json => {
                        serde_json::to_writer(
                            std::io::stdout().lock(),
                            &serde_json::json!({
                                "schema_version": 1,
                                "retention_days": older_than_days,
                                "eligible_receipts": eligible,
                                "deleted_receipts": if apply { eligible } else { 0 },
                                "dry_run": !apply
                            }),
                        )?;
                        println!();
                    }
                    Output::Text if apply => println!("Deleted {eligible} completed webhook receipts older than {older_than_days} days."),
                    Output::Text => println!("{eligible} completed webhook receipts are eligible for deletion; rerun with --apply to remove them."),
                }
                Ok(0)
            }
        },
        Command::Waivers { command } => {
            let cwd = std::env::current_dir()?;
            let top = vee_git::repository_root(&cwd).map_err(anyhow::Error::msg)?;
            let database = top.join(".vee/vee.sqlite");
            let mut store = ReviewStore::open(&database).map_err(anyhow::Error::msg)?;
            match command {
                WaiversCommand::Create {
                    finding_id,
                    review,
                    reason,
                    author,
                    expires_in_days,
                    output,
                } => {
                    if expires_in_days == 0 {
                        anyhow::bail!("--expires-in-days must be positive");
                    }
                    let payload = store
                        .get(&review)
                        .map_err(anyhow::Error::msg)?
                        .with_context(|| format!("review {review} was not found"))?;
                    let reviewed = vee_application::deserialize_review_result(&payload)
                        .map_err(anyhow::Error::msg)?;
                    let fingerprint = match reviewed
                        .findings
                        .iter()
                        .find(|finding| finding.id == finding_id)
                    {
                        Some(finding) => finding.fingerprint.clone(),
                        None => analyzer_finding_fingerprint(&store, &reviewed, &finding_id)?
                            .with_context(|| {
                                format!("finding {finding_id} was not observed in review {review}")
                            })?,
                    };
                    let reason = vee_core::Reason::new(&reason).map_err(usage_failure)?;
                    let author =
                        vee_core::ActorName::new("author", &author).map_err(usage_failure)?;
                    let created_at_unix = current_unix_time()?;
                    let expires_at_unix = created_at_unix
                        .checked_add(i64::from(expires_in_days) * 86_400)
                        .context("waiver expiry exceeds supported timestamp")?;
                    let id = format!(
                        "waiver_{}",
                        &vee_core::digest(&serde_json::to_vec(&(
                            fingerprint.as_str(),
                            reviewed.snapshot_id.as_str(),
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
                        snapshot_id: reviewed.snapshot_id,
                        reason: reason.as_str().to_owned(),
                        author: author.as_str().to_owned(),
                        provenance: "local_cli".into(),
                        created_at_unix,
                        expires_at_unix,
                    };
                    store.create_waiver(&waiver).map_err(anyhow::Error::msg)?;
                    match output {
                        Output::Json => {
                            serde_json::to_writer(std::io::stdout().lock(), &waiver)?;
                            println!();
                        }
                        Output::Text => println!(
                            "Created {} for {} through {}",
                            waiver.id, finding_id, waiver.expires_at_unix
                        ),
                    }
                    Ok(0)
                }
                WaiversCommand::List { review, output } => {
                    let listed = operations::list_waivers(
                        &operations::Workspace::new(top.clone(), crate::local_stores()),
                        &review,
                    )?;
                    match output {
                        Output::Json => emit_json(&listed)?,
                        Output::Text => print_view(&listed)?,
                    }
                    Ok(0)
                }
            }
        }
        Command::Findings { command } => {
            let workspace = operations::Workspace::discover(crate::local_stores())?;
            let cwd = std::env::current_dir()?;
            let top = vee_git::repository_root(&cwd)
                .map_err(anyhow::Error::msg)?
                .to_string_lossy()
                .to_string();
            let db_path = std::path::Path::new(&top).join(".vee/vee.sqlite");
            let mut store = ReviewStore::open(&db_path).map_err(anyhow::Error::msg)?;
            match command {
                FindingsCommand::List {
                    severity,
                    status,
                    review,
                    limit,
                    offset,
                    output,
                } => {
                    let page = operations::list_findings(
                        &workspace,
                        operations::FindingQuery {
                            review_id: review,
                            severity: severity.map(Into::into),
                            status: status.map(Into::into),
                            limit: Some(limit),
                            offset: Some(offset),
                        },
                    )?;
                    match output {
                        Output::Json => emit_json(&page)?,
                        Output::Text => print_view(&page)?,
                    }
                    Ok(0)
                }
                FindingsCommand::Show { id, output } => {
                    let detail = operations::finding_detail(&workspace, &id)?;
                    match output {
                        Output::Json => emit_json(&detail)?,
                        Output::Text => print_view(&detail)?,
                    }
                    Ok(0)
                }
                FindingsCommand::Task {
                    id,
                    context_lines,
                    output,
                } => {
                    let task = operations::finding_task(&workspace, &id, context_lines)?;
                    match output {
                        Output::Json => emit_json(&task)?,
                        Output::Text => print_view(&task)?,
                    }
                    Ok(0)
                }
                FindingsCommand::Package {
                    ids,
                    context_lines,
                    output,
                } => {
                    let package =
                        operations::finding_work_package(&workspace, &ids, context_lines)?;
                    match output {
                        Output::Json => emit_json(&package)?,
                        Output::Text => print_view(&package)?,
                    }
                    Ok(0)
                }
                FindingsCommand::ProposePatch {
                    review,
                    patch,
                    output,
                } => {
                    let bytes = read_proposal_file(&patch, operations::MAX_PATCH_BYTES as u64)
                        .context(
                            "patch must be a regular, non-symlink file no larger than 2 MiB",
                        )?;
                    let proposal = operations::propose_patch(&workspace, &review, &bytes)?;
                    let digest = proposal["patch_digest"].as_str().unwrap_or_default();
                    match output {
                        Output::Json => {
                            serde_json::to_writer(std::io::stdout().lock(), &proposal)?;
                            println!();
                        }
                        Output::Text => {
                            println!("Patch validated: {digest}");
                            println!(
                                "Review: {}  Snapshot: {}",
                                proposal["review_id"].as_str().unwrap_or_default(),
                                proposal["snapshot_id"].as_str().unwrap_or_default()
                            );
                            println!(
                                "Saved patch: {}",
                                proposal["patch_path"].as_str().unwrap_or_default()
                            );
                            println!("No repository files were changed.");
                        }
                    }
                    Ok(0)
                }
                FindingsCommand::ApplyPatch {
                    digest,
                    approve,
                    output,
                } => {
                    if !digest.starts_with("sha256:")
                        || digest.len() != 71
                        || !digest[7..].bytes().all(|b| b.is_ascii_hexdigit())
                    {
                        return Err(usage_failure(
                            "proposal ID must be a full sha256:<hex> digest",
                        ));
                    }
                    if approve != digest {
                        return Err(usage_failure(
                            "explicit approval digest must exactly match the proposal digest",
                        ));
                    }
                    let proposal_dir = proposal_directory(std::path::Path::new(&top))?;
                    let apply_lock = acquire_proposal_apply_lock(&proposal_dir)?;
                    let record_path = proposal_dir.join(format!("{}.json", &digest[7..]));
                    let patch_path = proposal_dir.join(format!("{}.patch", &digest[7..]));
                    let mut proposal: serde_json::Value = serde_json::from_slice(
                        &read_proposal_file(&record_path, 128 * 1024)
                            .with_context(|| format!("proposal {digest} was not found"))?,
                    )?;
                    anyhow::ensure!(
                        proposal["schema_version"] == 1,
                        "unsupported patch proposal schema"
                    );
                    anyhow::ensure!(
                        proposal["patch_digest"].as_str() == Some(digest.as_str()),
                        "proposal record digest does not match requested ID"
                    );
                    anyhow::ensure!(
                        proposal["application"].as_str() == Some("not_applied"),
                        "proposal was already applied or is not applicable"
                    );
                    let review_id = proposal["review_id"]
                        .as_str()
                        .context("proposal has no review ID")?
                        .to_owned();
                    let payload = store
                        .get(&review_id)
                        .map_err(anyhow::Error::msg)?
                        .with_context(|| format!("source review {review_id} was not found"))?;
                    let saved: vee_application::ReviewResult =
                        vee_application::deserialize_review_result(&payload)
                            .map_err(anyhow::Error::msg)?;
                    anyhow::ensure!(
                        proposal["snapshot_id"].as_str() == Some(saved.snapshot_id.as_str()),
                        "proposal snapshot does not match its saved review"
                    );
                    anyhow::ensure!(
                        matches!(
                            saved.change_set.scope.as_str(),
                            "staged" | "working_tree" | "base_and_worktree"
                        ),
                        "patch proposals require a mutable staged or working-tree review scope"
                    );
                    anyhow::ensure!(
                        proposal["effective_config_digest"].as_str()
                            == Some(saved.effective_config_digest.as_str()),
                        "proposal configuration digest does not match its saved review"
                    );
                    let operations::CurrentReviewConfig {
                        config,
                        digest: current_config_digest,
                        work_item: current_work_item,
                    } = operations::current_review_config(
                        &operations::Workspace::new(
                            std::path::PathBuf::from(&top),
                            crate::local_stores(),
                        ),
                        &store,
                        &saved,
                        None,
                    )?;
                    anyhow::ensure!(
                        current_config_digest == saved.effective_config_digest,
                        "effective review configuration changed; patch was not applied"
                    );
                    let current = vee_application::capture_current_change_set(
                        std::path::Path::new(&top),
                        &saved.change_set,
                    )
                    .map(|snapshot| snapshot.digest == saved.snapshot_id)
                    .unwrap_or(false);
                    anyhow::ensure!(current, "source snapshot is stale; patch was not applied");
                    let patch_bytes = read_proposal_file(&patch_path, 2 * 1024 * 1024)
                        .context("saved proposal patch is missing or invalid")?;
                    let mut hasher = Sha256::new();
                    hasher.update(&patch_bytes);
                    let actual_digest = format!("sha256:{:x}", hasher.finalize());
                    anyhow::ensure!(
                        actual_digest == digest,
                        "saved patch content has changed; patch was not applied"
                    );
                    let sandbox_result =
                        patch_sandbox::validate_bytes(std::path::Path::new(&top), &patch_bytes)
                            .map_err(anyhow::Error::msg)?;
                    let patch_input_digest =
                        patch_sandbox::input_digest(&sandbox_result.input_files)
                            .map_err(anyhow::Error::msg)?;
                    anyhow::ensure!(
                        proposal["patch_input_digest"].as_str()
                            == Some(patch_input_digest.as_str()),
                        "a patch target changed since proposal validation; patch was not applied"
                    );
                    anyhow::ensure!(
                        proposal["patch_sandbox_result_digest"].as_str()
                            == Some(sandbox_result.result_digest.as_str()),
                        "isolated patch result differs from the approved proposal"
                    );
                    let mut check_args = vec!["apply", "--check"];
                    if saved.change_set.scope == "staged" {
                        check_args.push("--index");
                    }
                    patch_sandbox::apply_bytes(
                        std::path::Path::new(&top),
                        &check_args,
                        &patch_bytes,
                    )
                    .map_err(anyhow::Error::msg)?;
                    let current = vee_application::capture_current_change_set(
                        std::path::Path::new(&top),
                        &saved.change_set,
                    )
                    .map(|snapshot| snapshot.digest == saved.snapshot_id)
                    .unwrap_or(false);
                    anyhow::ensure!(
                        current,
                        "source snapshot changed during patch validation; patch was not applied"
                    );
                    let final_inputs = vee_git::snapshot_files(
                        std::path::Path::new(&top),
                        &sandbox_result
                            .input_files
                            .iter()
                            .map(|file| std::path::PathBuf::from(&file.path))
                            .collect::<Vec<_>>(),
                    )
                    .map_err(anyhow::Error::msg)?;
                    anyhow::ensure!(
                        patch_sandbox::input_digest(&final_inputs).map_err(anyhow::Error::msg)?
                            == patch_input_digest,
                        "a patch target changed during application checks; patch was not applied"
                    );
                    let mut apply_args = vec!["apply"];
                    if saved.change_set.scope == "staged" {
                        apply_args.push("--index");
                    }
                    patch_sandbox::apply_bytes(
                        std::path::Path::new(&top),
                        &apply_args,
                        &patch_bytes,
                    )
                    .map_err(anyhow::Error::msg)?;
                    let observed_outputs = vee_git::snapshot_files(
                        std::path::Path::new(&top),
                        &sandbox_result
                            .result_files
                            .iter()
                            .map(|file| std::path::PathBuf::from(&file.path))
                            .collect::<Vec<_>>(),
                    )
                    .map_err(anyhow::Error::msg)?;
                    let concurrent_mutation_detected =
                        observed_outputs != sandbox_result.result_files;
                    proposal["application"] = serde_json::Value::String("applied".into());
                    proposal["concurrent_mutation_detected"] =
                        serde_json::Value::Bool(concurrent_mutation_detected);
                    proposal["approval_digest"] = serde_json::Value::String(approve);
                    proposal["applied_at_unix"] = serde_json::json!(current_unix_time()?);
                    write_proposal_file(&record_path, &serde_json::to_vec_pretty(&proposal)?)?;
                    drop(apply_lock);
                    let updated_scope = vee_application::capture_current_change_set(
                        std::path::Path::new(&top),
                        &saved.change_set,
                    )
                    .map_err(anyhow::Error::msg)?;
                    let review = vee_application::run_review_selecting_reviewers_with_work_item_and_token_env(
                        std::path::Path::new(&top),
                        updated_scope,
                        &config,
                        &mut store,
                        (!saved.selected_reviewers.is_empty())
                            .then_some(saved.selected_reviewers.as_slice()),
                        current_work_item,
                        saved.work_item_token_env.clone(),
                    )
                    .map_err(anyhow::Error::msg)?;
                    proposal["follow_up_review_id"] =
                        serde_json::Value::String(review.review_id.clone());
                    proposal["follow_up_snapshot_id"] =
                        serde_json::Value::String(review.snapshot_id.clone());
                    write_proposal_file(&record_path, &serde_json::to_vec_pretty(&proposal)?)?;
                    match output {
                        Output::Json => {
                            serde_json::to_writer(
                                std::io::stdout().lock(),
                                &serde_json::json!({"schema_version":1,"proposal_digest":digest,"approved":true,"application":"applied","concurrent_mutation_detected":concurrent_mutation_detected,"review":review}),
                            )?;
                            println!();
                        }
                        Output::Text => {
                            println!("Applied approved patch {digest}");
                            if concurrent_mutation_detected {
                                println!("Warning: patch target changed concurrently; inspect the re-reviewed result.");
                            }
                            println!("Follow-up review: {}", review.review_id);
                            println!(
                                "Snapshot: {}  Gate: {:?}",
                                review.snapshot_id, review.gate.status
                            );
                        }
                    }
                    Ok(if concurrent_mutation_detected {
                        2
                    } else {
                        match review.gate.status {
                            GateStatus::Pass => 0,
                            GateStatus::Block => 1,
                            GateStatus::Incomplete => 2,
                        }
                    })
                }
                FindingsCommand::SetStatus {
                    id,
                    status,
                    reason,
                    output,
                } => {
                    let update =
                        operations::set_finding_status(&workspace, &id, status.into(), &reason)?;
                    match output {
                        Output::Json => emit_json(&update)?,
                        Output::Text => print_view(&update)?,
                    }
                    Ok(0)
                }
                FindingsCommand::Feedback { command } => match command {
                    FindingFeedbackCommand::Set {
                        id,
                        snapshot,
                        label,
                        reason,
                        reviewer,
                        output,
                    } => {
                        let feedback = operations::record_finding_feedback(
                            &workspace,
                            operations::FeedbackRequest {
                                finding_id: &id,
                                snapshot_id: &snapshot,
                                label: label.into(),
                                reason: &reason,
                                reviewer: &reviewer,
                            },
                        )?;
                        match output {
                            Output::Json => emit_json(&feedback)?,
                            Output::Text => print_view(&feedback)?,
                        }
                        Ok(0)
                    }
                    FindingFeedbackCommand::List { finding, output } => {
                        let feedback = store.list_finding_feedback().map_err(anyhow::Error::msg)?;
                        let feedback: Vec<_> = feedback
                            .into_iter()
                            .filter(|item| {
                                finding.as_deref().is_none_or(|id| item.finding_id == id)
                            })
                            .collect();
                        match output {
                            Output::Json => {
                                serde_json::to_writer(
                                    std::io::stdout().lock(),
                                    &serde_json::json!({"schema_version": 1, "feedback": feedback}),
                                )?;
                                println!();
                            }
                            Output::Text => {
                                if feedback.is_empty() {
                                    println!("No reviewed feedback");
                                }
                                for item in feedback {
                                    println!(
                                        "{}  {}  {}  {}  {}",
                                        item.finding_id,
                                        item.snapshot_id,
                                        feedback_label_text(item.label),
                                        item.reviewer,
                                        item.reason
                                    );
                                }
                            }
                        }
                        Ok(0)
                    }
                },
            }
        }
    }
}

fn install_agent_skills(root: &std::path::Path, force: bool) -> Result<()> {
    let root = vee_core::paths::canonicalize(root).context("resolve checkout root")?;
    let agents = root.join(".agents");
    let skills = agents.join("skills");
    for directory in [&agents, &skills] {
        if directory.exists() {
            let metadata = std::fs::symlink_metadata(directory)
                .with_context(|| format!("inspect {}", directory.display()))?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(configuration_failure(format!(
                    "refusing to install through non-directory or symlink {}",
                    directory.display()
                )));
            }
        } else {
            std::fs::create_dir(directory)
                .with_context(|| format!("create {}", directory.display()))?;
        }
    }
    for (id, _) in AGENT_SKILLS {
        let directory = skills.join(id);
        if directory.exists() {
            let metadata = std::fs::symlink_metadata(&directory)
                .with_context(|| format!("inspect {}", directory.display()))?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(configuration_failure(format!(
                    "refusing to install through non-directory or symlink {}",
                    directory.display()
                )));
            }
        }
        let target = directory.join("SKILL.md");
        if target.exists() {
            let metadata = std::fs::symlink_metadata(&target)
                .with_context(|| format!("inspect {}", target.display()))?;
            if metadata.file_type().is_symlink() {
                return Err(configuration_failure(format!(
                    "refusing to replace symlink {}",
                    target.display()
                )));
            }
            if !force {
                return Err(configuration_failure(format!(
                    "{} already exists; use --force to replace it",
                    target.display()
                )));
            }
        }
    }
    for (id, contents) in AGENT_SKILLS {
        let directory = skills.join(id);
        if directory.exists() {
            let metadata = std::fs::symlink_metadata(&directory)
                .with_context(|| format!("inspect {}", directory.display()))?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(configuration_failure(format!(
                    "refusing to install through non-directory or symlink {}",
                    directory.display()
                )));
            }
        } else {
            std::fs::create_dir(&directory)
                .with_context(|| format!("create {}", directory.display()))?;
        }
        let target = directory.join("SKILL.md");
        if target.exists() && std::fs::symlink_metadata(&target)?.file_type().is_symlink() {
            return Err(configuration_failure(format!(
                "refusing to replace symlink {}",
                target.display()
            )));
        }
        let mut temporary = None;
        for _ in 0..16 {
            let nonce = SKILL_TEMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let candidate =
                directory.join(format!(".SKILL.md.vee-{}-{nonce}.tmp", std::process::id()));
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&candidate)
            {
                Ok(mut file) => {
                    if let Err(error) = file.write_all(contents.as_bytes()) {
                        let _ = std::fs::remove_file(&candidate);
                        return Err(error)
                            .with_context(|| format!("write {}", candidate.display()));
                    }
                    file.sync_all()
                        .with_context(|| format!("sync {}", candidate.display()))?;
                    temporary = Some(candidate);
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(error).with_context(|| format!("create {}", candidate.display()))
                }
            }
        }
        let temporary = temporary.ok_or_else(|| {
            anyhow::anyhow!(
                "could not allocate a unique temporary file in {}",
                directory.display()
            )
        })?;
        if force {
            if target.exists() {
                std::fs::remove_file(&target)
                    .with_context(|| format!("replace {}", target.display()))?;
            }
            std::fs::rename(&temporary, &target)
                .with_context(|| format!("install {}", target.display()))?;
        } else {
            std::fs::hard_link(&temporary, &target).with_context(|| {
                format!(
                    "install {} without replacing existing files",
                    target.display()
                )
            })?;
            std::fs::remove_file(&temporary)
                .with_context(|| format!("remove temporary file {}", temporary.display()))?;
        }
        println!("Installed {}", target.strip_prefix(&root)?.display());
    }
    Ok(())
}

fn print_verification_artifacts(run: &VerificationRun) {
    if let Some(artifact) = &run.stdout_artifact {
        println!("stdout artifact: {} ({})", artifact.path, artifact.digest);
    }
    if let Some(artifact) = &run.stderr_artifact {
        println!("stderr artifact: {} ({})", artifact.path, artifact.digest);
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::install_agent_skills;
    use super::{
        build_hosting_threads, committed_snapshot_matches_review, diff_contains_added_line,
        json_output_requested, read_proposal_file, sarif_uri_reference, work_item_api_base,
        write_markdown_report, Cli, Command, HostingCommand, Output,
    };
    use clap::Parser;
    use std::collections::BTreeSet;
    use vee_core::ports::HostedDeliveryRepository;
    use vee_core::Severity;

    fn undocumented_cli_items(command: &clap::Command, path: &str, problems: &mut Vec<String>) {
        if command.get_about().is_none() && !path.is_empty() {
            problems.push(format!("{path}: missing about"));
        }
        for argument in command.get_arguments() {
            let id = argument.get_id().as_str();
            if matches!(id, "help" | "version") || argument.is_hide_set() {
                continue;
            }
            if argument.get_help().is_none() {
                problems.push(format!("{path} --{id}: missing help"));
            }
        }
        for subcommand in command.get_subcommands() {
            if subcommand.get_name() == "help" {
                continue;
            }
            let child = format!("{path} {}", subcommand.get_name())
                .trim()
                .to_owned();
            undocumented_cli_items(subcommand, &child, problems);
        }
    }

    #[test]
    fn every_cli_command_and_argument_has_help_text() {
        use clap::CommandFactory;
        let command = Cli::command();
        command.clone().debug_assert();
        let mut problems = Vec::new();
        undocumented_cli_items(&command, "", &mut problems);
        assert!(
            problems.is_empty(),
            "{} undocumented CLI items:\n{}",
            problems.len(),
            problems.join("\n")
        );
    }

    #[test]
    fn completions_command_emits_a_script_for_supported_shells() {
        for shell in ["bash", "zsh", "fish"] {
            let parsed = Cli::try_parse_from(["vee", "completions", shell]);
            assert!(parsed.is_ok(), "completions {shell} should parse");
        }
        let mut script = Vec::new();
        super::write_completions(clap_complete::Shell::Zsh, &mut script);
        let script = String::from_utf8(script).unwrap();
        assert!(
            script.contains("#compdef vee"),
            "unexpected script: {script}"
        );
    }

    #[test]
    fn markdown_report_writer_replaces_regular_files_and_rejects_symlinks() {
        let directory = tempfile::tempdir().unwrap();
        let report = directory.path().join("review.md");
        std::fs::write(&report, "old report").unwrap();
        write_markdown_report(&report, b"new report").unwrap();
        assert_eq!(std::fs::read(&report).unwrap(), b"new report");

        #[cfg(unix)]
        {
            let protected = directory.path().join("protected.txt");
            let link = directory.path().join("linked-review.md");
            std::fs::write(&protected, "keep me").unwrap();
            std::os::unix::fs::symlink(&protected, &link).unwrap();

            let error = write_markdown_report(&link, b"replace me").unwrap_err();
            assert!(error
                .to_string()
                .contains("non-regular Markdown report path"));
            assert_eq!(std::fs::read(&protected).unwrap(), b"keep me");
            assert!(std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink());
        }
    }

    #[test]
    fn json_error_mode_respects_effective_output_defaults_and_overrides() {
        let args = |values: &[&str]| {
            values
                .iter()
                .map(std::ffi::OsString::from)
                .collect::<Vec<_>>()
        };
        assert!(json_output_requested(&args(&["vee", "findings", "task"])));
        assert!(json_output_requested(&args(&[
            "vee",
            "hosting",
            "pr-issues"
        ])));
        assert!(json_output_requested(&args(&[
            "vee",
            "hosting",
            "pr-context"
        ])));
        assert!(json_output_requested(&args(&[
            "vee",
            "reviews",
            "verify-bundle"
        ])));
        assert!(json_output_requested(&args(&[
            "vee", "reviews", "bundle", "rev-1"
        ])));
        assert!(json_output_requested(&args(&[
            "vee",
            "reviews",
            "imported",
            "show",
            "sha256:digest"
        ])));
        assert!(json_output_requested(&args(&[
            "vee",
            "rules",
            "effectiveness"
        ])));
        assert!(!json_output_requested(&args(&[
            "vee", "findings", "task", "--output", "text"
        ])));
        assert!(json_output_requested(&args(&[
            "vee",
            "reviews",
            "list",
            "--output=json"
        ])));
    }

    fn output_defaults(command: &clap::Command, path: &str, found: &mut Vec<(String, String)>) {
        for argument in command.get_arguments() {
            if argument.get_id() == "output" {
                let default = argument
                    .get_default_values()
                    .iter()
                    .map(|value| value.to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join(",");
                found.push((path.to_owned(), default));
            }
        }
        for subcommand in command.get_subcommands() {
            output_defaults(
                subcommand,
                &format!("{path} {}", subcommand.get_name()),
                found,
            );
        }
    }

    #[test]
    fn every_output_flag_defaults_to_human_readable_text() {
        use clap::CommandFactory;
        let mut found = Vec::new();
        output_defaults(&Cli::command(), "vee", &mut found);
        assert!(
            found.len() > 40,
            "expected many --output flags, found {}",
            found.len()
        );
        let inconsistent: Vec<_> = found
            .iter()
            .filter(|(_, default)| default != "text")
            .collect();
        assert!(
            inconsistent.is_empty(),
            "--output must default to text everywhere; use --output json for machine output: {inconsistent:#?}"
        );
        let parsed = Cli::try_parse_from([
            "vee",
            "hosting",
            "pr-context",
            "--repository",
            "org/project/repo",
            "--number",
            "7",
            "--output",
            "json",
        ])
        .unwrap();
        let Command::Hosting {
            command: HostingCommand::PrContext { output, .. },
        } = parsed.command
        else {
            panic!("expected hosting pr-context");
        };
        assert!(matches!(output, Output::Json));
    }

    #[test]
    fn proposal_artifact_reader_enforces_bound_and_rejects_symlinks() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("bounded.patch");
        std::fs::write(&file, b"12345").unwrap();
        assert_eq!(read_proposal_file(&file, 5).unwrap(), b"12345");
        assert!(read_proposal_file(&file, 4)
            .unwrap_err()
            .to_string()
            .contains("size limit"));

        #[cfg(unix)]
        {
            let link = directory.path().join("linked.patch");
            std::os::unix::fs::symlink(&file, &link).unwrap();
            assert!(read_proposal_file(&link, 5).is_err());
        }
    }

    #[test]
    fn github_enterprise_uses_enterprise_api_unless_overridden() {
        assert_eq!(
            work_item_api_base("github", "github.com", "").unwrap(),
            "https://api.github.com/"
        );
        assert_eq!(
            work_item_api_base("github", "github.enterprise.example", "").unwrap(),
            "https://github.enterprise.example/api/v3/"
        );
        assert_eq!(
            work_item_api_base(
                "github",
                "github.enterprise.example",
                "https://proxy.example/api/"
            )
            .unwrap(),
            "https://proxy.example/api/"
        );
    }

    #[test]
    fn sarif_uri_encodes_spaces_and_uri_delimiters() {
        assert_eq!(
            sarif_uri_reference("src/my file#1?.rs"),
            "src/my%20file%231%3F.rs"
        );
        assert_eq!(sarif_uri_reference("src/naïve.rs"), "src/na%C3%AFve.rs");
    }

    #[test]
    fn azure_review_location_must_be_on_an_added_line() {
        let patch = "diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -2,2 +2,3 @@\n context\n+added line\n more context\n";
        assert!(diff_contains_added_line(Some(patch), 3));
        let plus_prefixed_addition = "@@ -1,0 +1,1 @@\n+++ valid added source\n";
        assert!(diff_contains_added_line(Some(plus_prefixed_addition), 1));
        assert!(!diff_contains_added_line(Some(patch), 4));
        assert!(!diff_contains_added_line(Some(patch), 2));
        assert!(!diff_contains_added_line(None, 3));
    }

    #[test]
    fn publish_snapshot_rejects_uncommitted_content_in_base_and_worktree_review() {
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
        std::fs::write(root.join("src.rs"), "base\n").unwrap();
        git(&["add", "."]);
        git(&["commit", "-qm", "base"]);
        let base = String::from_utf8(
            std::process::Command::new("git")
                .arg("-C")
                .arg(root)
                .args(["rev-parse", "HEAD"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_owned();
        std::fs::write(root.join("src.rs"), "committed change\n").unwrap();
        git(&["add", "."]);
        git(&["commit", "-qm", "change"]);
        let head = String::from_utf8(
            std::process::Command::new("git")
                .arg("-C")
                .arg(root)
                .args(["rev-parse", "HEAD"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_owned();
        std::fs::write(root.join("src.rs"), "uncommitted content\n").unwrap();
        let scope = vee_git::ChangeScope::BaseAndWorktree {
            base_oid: Some(base),
        };
        let reviewed = vee_application::capture_change_set(root, scope.clone()).unwrap();
        assert!(!committed_snapshot_matches_review(root, &reviewed).unwrap());

        std::fs::write(root.join("src.rs"), "committed change\n").unwrap();
        let clean_review = vee_application::capture_change_set(root, scope).unwrap();
        assert_eq!(clean_review.head_oid.as_deref(), Some(head.as_str()));
        let committed = vee_application::capture_change_set(
            root,
            vee_git::ChangeScope::CommitRange {
                from: clean_review.base_oid.clone().unwrap(),
                to: head,
            },
        )
        .unwrap();
        assert_eq!(
            clean_review.files[0].content_digest,
            committed.files[0].content_digest
        );
        assert!(
            committed_snapshot_matches_review(root, &clean_review).unwrap(),
            "review files: {:?}",
            clean_review.files
        );
    }

    #[test]
    fn hosting_threads_only_target_findings_on_added_diff_lines() {
        let pull_request = vee_hosting::PullRequestRef {
            repository: vee_hosting::RepositoryRef {
                host: "github.com".into(),
                full_name: "example/repo".into(),
            },
            number: 12,
        };
        let finding = |id: &str, line: u32, severity| vee_core::Finding {
            id: id.into(),
            fingerprint: format!("sha256:{id}"),
            category: "correctness".into(),
            severity,
            confidence: Some(90),
            rationale: "A concrete issue".into(),
            path: Some("src/lib.rs".into()),
            line: Some(line),
            provenance: "model_inference".into(),
            reviewer_ids: Vec::new(),
            evidence_ids: Vec::new(),
            rule_attributions: Vec::new(),
            sample_agreement: None,
            advisory: false,
        };
        let findings = vec![
            finding("added", 3, vee_core::Severity::High),
            finding("context", 4, vee_core::Severity::High),
            finding("informational", 3, vee_core::Severity::Info),
        ];
        let changed_files = vec![vee_hosting::PullRequestFile {
            path: "src/lib.rs".into(),
            change: vee_hosting::FileChange::Modified,
            previous_path: None,
            patch: Some("@@ -2,2 +2,3 @@\n context\n+added\n more context\n".into()),
            additions: 1,
            deletions: 0,
        }];

        let threads = build_hosting_threads(
            &findings,
            &pull_request,
            &changed_files,
            "review-1",
            "sha256:snapshot",
            "sha256:delivery",
        );

        assert_eq!(threads.len(), 1);
        assert_eq!(threads[0].fingerprint, "sha256:added");
        assert_eq!(threads[0].line, 3);
        assert_eq!(threads[0].side, vee_hosting::DiffSide::New);
        assert_eq!(threads[0].snapshot_id, "sha256:snapshot");
        assert_eq!(threads[0].idempotency_key, "sha256:delivery:sha256:added");
    }

    #[test]
    fn hosted_finding_ledger_retains_unmentioned_threads_until_resolved() {
        let pull_request = vee_hosting::PullRequestRef {
            repository: vee_hosting::RepositoryRef {
                host: "github.com".into(),
                full_name: "example/repo".into(),
            },
            number: 12,
        };
        let thread = |fingerprint: &str, resolution| vee_hosting::ReviewThread {
            pull_request: pull_request.clone(),
            fingerprint: fingerprint.into(),
            path: "src/lib.rs".into(),
            line: 10,
            side: vee_hosting::DiffSide::New,
            body: "finding".into(),
            resolution,
            snapshot_id: "sha256:snapshot".into(),
            idempotency_key: format!("key:{fingerprint}"),
        };
        let previous = BTreeSet::from(["sha256:stale".into(), "sha256:resolved".into()]);
        let updated = super::updated_hosted_finding_fingerprints(
            &previous,
            &[
                thread("sha256:new", vee_hosting::ThreadResolution::Open),
                thread("sha256:resolved", vee_hosting::ThreadResolution::Resolved),
            ],
        );
        assert_eq!(
            updated,
            BTreeSet::from(["sha256:new".into(), "sha256:stale".into()])
        );
        let intent = super::hosting_thread_intent_fingerprints(
            &previous,
            &[
                thread("sha256:new", vee_hosting::ThreadResolution::Open),
                thread("sha256:resolved", vee_hosting::ThreadResolution::Resolved),
            ],
        );
        assert_eq!(
            intent,
            BTreeSet::from([
                "sha256:new".into(),
                "sha256:resolved".into(),
                "sha256:stale".into(),
            ]),
            "pending publication must retain prior and all possibly written fingerprints"
        );

        // Model a provider accepting the write while Vee exits before it can
        // store the final publication receipt. The prewritten intent survives
        // restart and still allows the next review to resolve that thread.
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("hosted-threads.sqlite");
        let target = "github:example/repo#12";
        let mut store = vee_store_sqlite::ReviewStore::open(&database).unwrap();
        store
            .replace_hosted_finding_threads(target, &intent)
            .unwrap();
        drop(store);

        let reopened = vee_store_sqlite::ReviewStore::open(&database).unwrap();
        let recovered = reopened.hosted_finding_threads(target).unwrap();
        assert_eq!(recovered, intent);

        let records = vec![vee_core::FindingRecord {
            assessments: Vec::new(),
            finding: vee_core::Finding {
                id: "recovered".into(),
                fingerprint: "sha256:new".into(),
                category: "correctness".into(),
                severity: Severity::High,
                confidence: Some(90),
                rationale: "Concrete issue".into(),
                path: Some("src/lib.rs".into()),
                line: Some(10),
                provenance: "model_inference".into(),
                reviewer_ids: Vec::new(),
                evidence_ids: Vec::new(),
                rule_attributions: Vec::new(),
                sample_agreement: None,
                advisory: false,
            },
            status: vee_core::FindingStatus::Resolved,
            status_reason: Some("fixed and verified".into()),
            occurrence_count: 1,
            first_seen: "2026-11-14T00:00:00Z".into(),
            last_seen: "2026-11-14T00:00:00Z".into(),
            occurrences: Vec::new(),
        }];
        let resolved = super::build_resolved_hosting_threads(
            &records,
            &BTreeSet::new(),
            &recovered,
            &pull_request,
            "review-after-restart",
            "sha256:next-snapshot",
        );
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].fingerprint, "sha256:new");
        assert_eq!(
            resolved[0].resolution,
            vee_hosting::ThreadResolution::Resolved
        );
    }

    #[test]
    fn resolved_hosting_threads_exclude_active_and_non_resolved_findings() {
        let pull_request = vee_hosting::PullRequestRef {
            repository: vee_hosting::RepositoryRef {
                host: "github.com".into(),
                full_name: "example/repo".into(),
            },
            number: 12,
        };
        let record = |id: &str, status| vee_core::FindingRecord {
            assessments: Vec::new(),
            finding: vee_core::Finding {
                id: id.into(),
                fingerprint: format!("sha256:{id}"),
                category: "correctness".into(),
                severity: Severity::High,
                confidence: Some(90),
                rationale: "Concrete issue".into(),
                path: Some("src/lib.rs".into()),
                line: Some(10),
                provenance: "model_inference".into(),
                reviewer_ids: Vec::new(),
                evidence_ids: Vec::new(),
                rule_attributions: Vec::new(),
                sample_agreement: None,
                advisory: false,
            },
            status,
            status_reason: Some("fixed and verified".into()),
            occurrence_count: 1,
            first_seen: "2026-11-14T00:00:00Z".into(),
            last_seen: "2026-11-14T00:00:00Z".into(),
            occurrences: Vec::new(),
        };
        let records = vec![
            record("resolved", vee_core::FindingStatus::Resolved),
            record("active", vee_core::FindingStatus::Resolved),
            record("refuted", vee_core::FindingStatus::Refuted),
        ];
        let active = BTreeSet::from(["sha256:active".to_owned()]);
        let threads = super::build_resolved_hosting_threads(
            &records,
            &active,
            &BTreeSet::from(["sha256:resolved".to_owned()]),
            &pull_request,
            "review-2",
            "sha256:snapshot",
        );
        assert_eq!(threads.len(), 1);
        assert_eq!(threads[0].fingerprint, "sha256:resolved");
        assert_eq!(
            threads[0].resolution,
            vee_hosting::ThreadResolution::Resolved
        );
        assert_eq!(
            threads[0].idempotency_key,
            "review-2:sha256:resolved:resolved"
        );

        let mut publication = vec![vee_hosting::ReviewThread {
            pull_request: pull_request.clone(),
            fingerprint: "sha256:active".into(),
            path: "src/lib.rs".into(),
            line: 10,
            side: vee_hosting::DiffSide::New,
            body: "still present".into(),
            resolution: vee_hosting::ThreadResolution::Open,
            snapshot_id: "sha256:snapshot".into(),
            idempotency_key: "review-2:sha256:active".into(),
        }];
        super::add_resolved_hosting_threads(
            &mut publication,
            &records,
            &BTreeSet::from(["sha256:active".to_owned(), "sha256:resolved".to_owned()]),
            &BTreeSet::from(["sha256:resolved".to_owned()]),
            &pull_request,
            "review-2",
            "sha256:snapshot",
        );
        assert_eq!(publication.len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn skill_install_never_follows_a_precreated_temporary_symlink() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(outside.path(), "keep this content\n").unwrap();
        let skill_dir = root.path().join(".agents/skills/vee-codebase-context");
        std::fs::create_dir_all(&skill_dir).unwrap();
        let guessed_temporary =
            skill_dir.join(format!(".SKILL.md.vee-{}-0.tmp", std::process::id()));
        symlink(outside.path(), guessed_temporary).unwrap();

        install_agent_skills(root.path(), false).unwrap();

        assert_eq!(
            std::fs::read_to_string(outside.path()).unwrap(),
            "keep this content\n"
        );
        assert!(skill_dir.join("SKILL.md").is_file());
    }
}
