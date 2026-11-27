use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use std::{io::Write, process::ExitCode};
use vee_core::ports::*;
use vee_core::{GateStatus, RepositoryConfig, Severity, VerificationStatus};
use vee_store_sqlite::ReviewStore;

use vee_application::attestation;
mod contracts;
mod init_wizard;
use vee_application::evidence_bundle;
use vee_application::failure::{
    configuration_failure, usage_failure, ConfigurationFailure, UsageFailure,
};
use vee_application::hosting::{load_hosting_config, resolve_hosting_setting};
use vee_application::imported_history;
use vee_application::proposals::{
    acquire_proposal_apply_lock, proposal_directory, read_proposal_file, write_proposal_file,
};
use vee_application::work_items::{effective_work_item_host, work_item_api_base};
mod mcp;
mod snapshot_mcp;
use vee_application::operations;
use vee_application::packs;
use vee_application::patch_sandbox;
use vee_application::signing;
use vee_application::standards;
use vee_application::test_proposals;

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

/// The workspace for commands that change the worktree: outside a Git
/// repository is a usage error.
fn proposal_workspace() -> Result<operations::Workspace> {
    let cwd = std::env::current_dir()?;
    let root = vee_git::repository_root(&cwd).map_err(usage_failure)?;
    Ok(operations::Workspace::new(root, crate::local_stores()))
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

/// The current repository's root, or the current directory outside a checkout.
fn hosting_config_root() -> Result<std::path::PathBuf> {
    let cwd = std::env::current_dir()?;
    Ok(vee_git::repository_root(&cwd).unwrap_or(cwd))
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
        /// Model for the chosen backend; required for API keys, optional otherwise.
        #[arg(long)]
        model: Option<String>,
        /// Review effort on this machine: low runs each reviewer once, medium three
        /// times and high five times, keeping findings the runs agree on.
        #[arg(long, value_enum)]
        effort: Option<EffortArg>,
        /// Do not ask questions in a terminal; use the recommended choices.
        #[arg(long)]
        no_input: bool,
        /// Instead of configuring this machine, write a CI pipeline that reviews
        /// each pull request with an API-key provider (`--provider` and
        /// `--model` required).
        #[arg(long, value_enum)]
        ci: Option<CiTargetArg>,
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
    /// Assess a change's risk tier from measured factors, each with its research basis.
    Risk {
        /// Assess a saved review's exact snapshot instead of capturing a scope; fails if the source changed.
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
        #[command(subcommand)]
        command: Option<AnalyticsCommand>,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Inspect direct package dependencies across explicitly selected local repositories.
    Repos {
        #[command(subcommand)]
        command: ReposCommand,
    },
    /// Review the pull request a CI job runs for and publish the result to it.
    Ci {
        #[command(subcommand)]
        command: CiCommand,
    },
    /// Review at hand-off points: a Git pre-push hook, and the hooks the
    /// agent plugins run before a coding agent finishes.
    Hooks {
        #[command(subcommand)]
        command: HooksCommand,
    },
    /// Fix what keeps the current branch from passing its gate: a merge
    /// conflict with the base, failing required verifications and blocking
    /// findings. The configured reviewer's model proposes each fix; Vee
    /// commits it and keeps it only when a new review is complete, adds no
    /// blocking finding, breaks no verification that passed, and solves the
    /// problem. Kept fixes stay on the branch, unpushed, each with how to
    /// undo it. Exit 0 when the gate passes at the end, 1 when it blocks, 2
    /// when it is incomplete.
    Steward {
        /// The branch or commit the change is reviewed and merged against.
        #[arg(long, value_name = "REF")]
        base: String,
        /// The most fixes to attempt, 1 to 10 (default `steward.max_fixes`, or 5).
        #[arg(long, value_name = "N", value_parser = clap::value_parser!(u32).range(1..=10))]
        max_fixes: Option<u32>,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
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
    /// Internal: serve read-only snapshot tools to a reviewer during a review.
    #[command(hide = true)]
    Snapshot {
        /// Exploration spec written by the review.
        #[arg(long)]
        spec: std::path::PathBuf,
        /// File each tool call is appended to, one JSON line per call.
        #[arg(long)]
        log: std::path::PathBuf,
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
/// Read pull requests for weak labels (ADR 0031).
#[derive(clap::Args, Clone, Debug)]
struct PullRequestFeedbackArgs {
    /// Also read the closed pull requests of this repository (OWNER/REPO, or
    /// a GitLab project path) for dismissals, fixes and reactions.
    #[arg(long = "pull-requests", value_name = "OWNER/REPO")]
    repository: Option<String>,
    /// Hosting provider of --pull-requests: `github` or `gitlab`.
    #[arg(long = "pull-requests-provider", default_value = "github", value_parser = ["github", "gitlab"])]
    provider: String,
    /// API base URL, for example https://gitlab.example.com/api/v4/.
    #[arg(
        long = "pull-requests-api-base",
        default_value = "https://api.github.com/"
    )]
    api_base: String,
    /// Environment variable holding the hosting token.
    #[arg(long = "pull-requests-token-env", default_value = "GH_TOKEN")]
    token_env: String,
    /// The account Vee publishes as (default: github-actions[bot], or the
    /// GitLab token's user).
    #[arg(long = "pull-requests-actor-login")]
    actor_login: Option<String>,
    /// Closed pull requests to read, newest first.
    #[arg(long = "pull-requests-limit", default_value_t = 100, value_parser = clap::value_parser!(u16).range(1..=1000))]
    limit: u16,
}

impl PullRequestFeedbackArgs {
    fn source(&self) -> Option<operations::PullRequestSource> {
        self.repository
            .clone()
            .map(|repository| operations::PullRequestSource {
                provider: self.provider.clone(),
                repository,
                api_base: self.api_base.clone(),
                token_env: self.token_env.clone(),
                actor_login: self.actor_login.clone(),
                limit: usize::from(self.limit),
            })
    }
}

#[derive(Subcommand)]
enum RulesCommand {
    /// List rule candidates mined from repeated human feedback, and with
    /// --pull-requests, weak candidates from what people did on pull requests.
    Candidates {
        #[command(flatten)]
        pull_requests: PullRequestFeedbackArgs,
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
        /// For a weak candidate: the pull requests it was mined from.
        #[command(flatten)]
        pull_requests: PullRequestFeedbackArgs,
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
    /// Put a rule Vee suspended back in effect.
    Restore {
        /// Approval ID to restore.
        approval_id: String,
        /// Name of the person restoring the approval.
        #[arg(long)]
        actor: String,
        /// Why the rule should apply again.
        #[arg(long)]
        reason: String,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Print the approved rules as a Markdown section, or write them into a
    /// standards file such as REVIEW.md or AGENTS.md.
    Export {
        /// Repository Markdown file whose rules section to replace or add.
        #[arg(long, value_name = "FILE")]
        write: Option<String>,
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
        #[arg(long, default_value = operations::DEFAULT_DRAFTING_REVIEWER)]
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
        #[arg(long, default_value = operations::DEFAULT_DRAFTING_REVIEWER)]
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
        #[arg(long, default_value = operations::DEFAULT_DRAFTING_REVIEWER)]
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
    /// Read several saved reviews together, such as one agent session's changes: each change's gate, risk, open findings, and approval eligibility, and one verdict.
    Session {
        /// Saved reviews (1 to 20), in the order to show them: a review ID in
        /// this repository, or `REPO:REVIEW_ID` for a review saved in another
        /// checkout, with REPO relative to this repository's root (such as
        /// `../api`).
        #[arg(long = "review", value_name = "[REPO:]REVIEW_ID", required = true)]
        reviews: Vec<String>,
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
    /// Sign a saved review of committed changes and store it as a Git note
    /// on its head, so CI can reuse it instead of reviewing again. CI reuses
    /// it only when the base branch's `review_signers` lists the key and the
    /// configuration and file contents are the same; push the note with
    /// `git push origin refs/notes/vee-reviews`.
    Share {
        /// Saved review ID.
        id: String,
        /// Ed25519 PKCS#8 private key (from `vee reviews keygen`).
        #[arg(long)]
        private_key: std::path::PathBuf,
        /// Key identifier recorded in the signature.
        #[arg(long)]
        key_id: String,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum CiTargetArg {
    Github,
    Gitlab,
}

#[derive(Subcommand)]
enum AnalyticsCommand {
    /// Combine analytics documents collected across repositories and CI runs
    /// into one report: gate outcomes, approval override rate, cost and rule
    /// effectiveness, each with its denominator. Reads the JSON of
    /// `vee analytics`, `vee ci approvals` and `vee rules effectiveness`. No
    /// server, and no person is named.
    Aggregate {
        /// Documents or directories of `.json` documents; `NAME=PATH` labels one.
        #[arg(required = true, value_name = "PATH")]
        inputs: Vec<String>,
        /// Also write the report as one self-contained HTML page.
        #[arg(long, value_name = "FILE")]
        html: Option<std::path::PathBuf>,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
}

#[derive(Subcommand)]
enum HooksCommand {
    /// Install a pre-push hook that reviews the commits each push sends and
    /// stops the push when the gate blocks (`git push --no-verify` skips it).
    Install {
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Remove Vee's pre-push hook; another tool's hook is left alone.
    Uninstall {
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Show whether Vee's pre-push hook is installed.
    Status {
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Run a hook. Git and the agent plugins call these; they read the
    /// hook's input from stdin.
    Run {
        #[command(subcommand)]
        hook: HookRun,
    },
}

#[derive(Subcommand)]
enum HookRun {
    /// Git's pre-push hook: review each pushed ref; exit 1 when a review blocks.
    #[command(name = "pre-push")]
    PrePush {
        /// The remote's name, as Git passes it.
        remote: String,
        /// The remote's URL, as Git passes it.
        url: Option<String>,
    },
    /// An agent's session start: remember `HEAD`, so the Stop hook also
    /// reviews the commits the agent makes.
    AgentSessionStart,
    /// An agent's Stop: review its changes and, when the gate blocks, keep
    /// it working with the findings. Set VEE_AGENT_REVIEW=off to turn it off.
    AgentStop,
}

#[derive(Subcommand)]
enum CiCommand {
    /// Detect the pull request from GitHub Actions or GitLab CI, review it from
    /// its base, publish the check and finding threads, and exit with the gate:
    /// 0 pass, 1 block, 2 incomplete.
    Run {
        /// Also publish the approval verdict as a separate check.
        #[arg(long)]
        approval: bool,
        /// Review effort for this run, replacing configured sampling.
        #[arg(long, value_enum)]
        effort: Option<EffortArg>,
        /// Named policy profile from .vee.yaml to apply.
        #[arg(long, value_name = "NAME")]
        policy_profile: Option<String>,
        /// Account Vee publishes as, when the CI system does not determine it.
        #[arg(long)]
        actor_login: Option<String>,
        /// Review the whole change. Otherwise, on GitHub, files whose change
        /// the last review covered are not sent to reviewers again and their
        /// findings are carried over.
        #[arg(long)]
        full: bool,
        /// Add a walkthrough to Vee's summary: the risk tier, a graph of what
        /// the change reaches, and a drafted description (one more model call).
        #[arg(long)]
        describe: bool,
        /// Keep `vee:gate:*` and `vee:risk:*` labels on the pull request (GitHub, GitLab).
        #[arg(long)]
        labels: bool,
        /// Approve the pull request when the change is eligible for approval
        /// without a person, and withdraw Vee's approvals that no longer hold (GitHub, GitLab).
        #[arg(long)]
        approve: bool,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Compare Vee's approval verdicts on recently closed GitHub pull requests
    /// with what people did: merged as eligible, changed, sent back or closed.
    Approvals {
        /// The repository, as OWNER/REPO (on GitLab, the project path).
        #[arg(long, value_name = "OWNER/REPO")]
        repository: String,
        /// Hosting provider: `github` or `gitlab`.
        #[arg(long, default_value = "github", value_parser = ["github", "gitlab"])]
        provider: String,
        /// Closed pull requests to read, newest first.
        #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u16).range(1..=1000))]
        limit: u16,
        /// API base URL, for example https://gitlab.example.com/api/v4/.
        #[arg(long, default_value = "https://api.github.com/")]
        api_base: String,
        /// Environment variable holding the hosting token.
        #[arg(long, default_value = "GH_TOKEN")]
        token_env: String,
        /// The account Vee published as; on GitLab, the token's user when omitted.
        #[arg(long, default_value = "github-actions[bot]")]
        actor_login: String,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Handle the pull request comment that started a GitHub Actions job, or
    /// the merge request comment a GitLab Comments webhook triggered a pipeline for:
    /// `@vee review`, `status`, `explain`, `dismiss`, `waive` or `help`.
    /// Exits 0 when the comment was handled or held no command.
    Command {
        /// Also publish the approval verdict when the command reviews.
        #[arg(long)]
        approval: bool,
        /// Review effort when the command reviews.
        #[arg(long, value_enum)]
        effort: Option<EffortArg>,
        /// Named policy profile from .vee.yaml to apply.
        #[arg(long, value_name = "NAME")]
        policy_profile: Option<String>,
        /// Account Vee posts as.
        #[arg(long)]
        actor_login: Option<String>,
        /// Add a walkthrough to Vee's summary: the risk tier, a graph of what
        /// the change reaches, and a drafted description (one more model call).
        #[arg(long)]
        describe: bool,
        /// Keep `vee:gate:*` and `vee:risk:*` labels on the pull request (GitHub, GitLab).
        #[arg(long)]
        labels: bool,
        /// Approve the pull request when the change is eligible for approval
        /// without a person, and withdraw Vee's approvals that no longer hold (GitHub, GitLab).
        #[arg(long)]
        approve: bool,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
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
        /// Also publish the approval verdict (`vee gate approval`) as a separate
        /// "Vee approval" check: success when eligible, neutral when a person is
        /// needed. On Bitbucket, Azure DevOps and Gerrit, with
        /// `approval.mode: enforce`, Vee also approves an eligible change (a
        /// Gerrit Code-Review vote instead of a check) and withdraws its
        /// approval from one that is not.
        #[arg(long)]
        approval: bool,
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
        /// Allow binding beyond loopback; requires --tls-cert and --tls-key.
        #[arg(long, default_value_t = false)]
        allow_network: bool,
        /// PEM certificate chain; serves HTTPS.
        #[arg(long, value_name = "PATH", requires = "tls_key")]
        tls_cert: Option<std::path::PathBuf>,
        /// PEM private key for --tls-cert, readable only by its owner.
        #[arg(long, value_name = "PATH", requires = "tls_cert")]
        tls_key: Option<std::path::PathBuf>,
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
        #[arg(long, default_value_t = operations::DEFAULT_SEARCH_LIMIT)]
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
    /// Check whether a saved review's change may be approved without a human: snapshot, protected paths, authors, risk, and gate, each with its reason.
    Approval {
        /// Saved review ID.
        #[arg(long)]
        review: String,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    /// Classify a saved review's change against `approval.conditions` with a
    /// reviewer's model, or show the stored classification. Conditions only
    /// decide whether a person approves; they never change the gate.
    Conditions {
        /// Saved review ID.
        #[arg(long)]
        review: String,
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
        #[arg(long, default_value_t = operations::DEFAULT_CONTEXT_LINES)]
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
        #[arg(long, default_value_t = operations::DEFAULT_CONTEXT_LINES)]
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
        let changed = self
            .provider
            .list_changed_files(pull_request, &remote.revision)
            .map_err(|error| error.to_string())?;
        let delivery_key = vee_core::digest(event.event_id.as_bytes());
        let findings =
            vee_application::publication::findings_for_publication(&review.findings, &review.gate);
        let threads = vee_application::publication::build_hosting_threads(
            &findings,
            pull_request,
            &changed,
            &review.snapshot_id,
            &delivery_key,
        );
        let check = vee_application::publication::gate_check_run(
            &review.gate,
            pull_request,
            format!("webhook:{delivery_key}"),
            &review.snapshot_id,
        );
        vee_application::publication::publish_with_thread_ledger(
            &mut store,
            self.provider.provider_id(),
            pull_request,
            &vee_application::publication::PublishedReview {
                review_id: &review.review_id,
                snapshot_id: &review.snapshot_id,
                findings: &review.findings,
                pull_request_threads: &[],
            },
            threads,
            |threads| {
                self.provider
                    .publish_review(vee_hosting::ReviewPublication {
                        pull_request: pull_request.clone(),
                        expected_revision: remote.revision,
                        check,
                        threads,
                    })
                    .map_err(|error| error.to_string())
            },
        )?;
        Ok(())
    }
}

/// Fingerprint of an analyzer finding recorded in one of the review's gate
/// decisions (at review time or a later `gate check`) on the review's snapshot.
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
                Output::Text => print_view(&summary)?,
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
                Output::Text => print_view(&summary)?,
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
fn run_hooks(command: HooksCommand) -> Result<u8> {
    use vee_application::hooks;
    let (status, output) = match command {
        HooksCommand::Install { output } => {
            let workspace = operations::Workspace::discover(crate::local_stores())?;
            (hooks::install_git_hook(workspace.root())?, output)
        }
        HooksCommand::Uninstall { output } => {
            let workspace = operations::Workspace::discover(crate::local_stores())?;
            (hooks::uninstall_git_hook(workspace.root())?, output)
        }
        HooksCommand::Status { output } => {
            let workspace = operations::Workspace::discover(crate::local_stores())?;
            (hooks::git_hook_status(workspace.root())?, output)
        }
        HooksCommand::Run { hook } => return run_hook(hook),
    };
    match output {
        Output::Json => emit_json(&status)?,
        Output::Text => print_view(&status)?,
    }
    Ok(0)
}

fn run_hook(hook: HookRun) -> Result<u8> {
    use std::io::Read;
    use vee_application::hooks;
    let mut input = Vec::new();
    std::io::stdin()
        .take((1 << 20) + 1)
        .read_to_end(&mut input)?;
    match hook {
        HookRun::PrePush { remote, url: _ } => {
            let workspace = operations::Workspace::discover(crate::local_stores())?;
            let updates = hooks::parse_push_updates(&String::from_utf8_lossy(&input))?;
            let outcome = hooks::pre_push(&workspace, &remote, &updates)?;
            for skipped in &outcome.skipped {
                eprintln!("vee: not reviewed: {skipped}");
            }
            for review in &outcome.reviews {
                eprintln!(
                    "vee: {} ({}): {} (review {})",
                    review.remote_ref,
                    review.range,
                    gate_word(review.gate),
                    review.review_id
                );
                for reason in &review.reasons {
                    eprintln!("vee:   {reason}");
                }
            }
            if outcome.blocks() {
                eprintln!(
                    "vee: push stopped. See `vee findings list --review <id>`; \
                     `git push --no-verify` pushes without the review."
                );
                return Ok(1);
            }
            Ok(0)
        }
        // Agent hooks never fail the agent's hook call: problems are messages.
        HookRun::AgentSessionStart => {
            let started = hooks::parse_agent_hook_input(&input)
                .and_then(|input| hooks::agent_session_start(&input));
            if let Err(error) = started {
                eprintln!("vee: {error:#}");
            }
            Ok(0)
        }
        HookRun::AgentStop => {
            let response = match hooks::parse_agent_hook_input(&input) {
                Ok(input) => hooks::agent_stop(&input, crate::local_stores()),
                Err(error) => hooks::AgentHookResponse {
                    system_message: Some(format!("Vee could not review: {error:#}")),
                    ..Default::default()
                },
            };
            if !response.is_empty() {
                emit_json(&response)?;
            }
            Ok(0)
        }
    }
}

fn gate_word(status: GateStatus) -> &'static str {
    match status {
        GateStatus::Pass => "passed",
        GateStatus::Block => "blocked",
        GateStatus::Incomplete => "incomplete, not gated",
    }
}

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
            effort,
            no_input,
            ci: Some(target),
            output,
        } => {
            let _ = no_input;
            let (Some(provider), Some(model)) = (provider, model) else {
                return Err(usage_failure(
                    "`vee init --ci` needs --provider and --model, for example --provider anthropic-api --model <model>",
                ));
            };
            let workflow = vee_application::setup::ci_workflow(
                match target {
                    CiTargetArg::Github => vee_application::setup::CiTarget::Github,
                    CiTargetArg::Gitlab => vee_application::setup::CiTarget::Gitlab,
                },
                &provider,
                &model,
                effort.map_or(vee_core::ReviewEffort::Medium, Into::into),
            )
            .map_err(usage_failure)?;
            let workspace = operations::Workspace::discover(crate::local_stores())?;
            vee_application::setup::write_ci_workflow(workspace.root(), &workflow)
                .map_err(configuration_failure)?;
            match output {
                Output::Json => emit_json(&serde_json::json!({
                    "schema_version": 1,
                    "path": workflow.path,
                    "secrets": workflow.secrets,
                }))?,
                Output::Text => {
                    println!("Wrote {}.", workflow.path);
                    println!(
                        "Define these CI secrets before it runs: {}.",
                        workflow.secrets.join(", ")
                    );
                    println!("Commit the file; the next pull request is reviewed in CI.");
                }
            }
            Ok(0)
        }
        Command::Init {
            provider,
            model,
            effort,
            no_input,
            ci: None,
            output,
        } => {
            let workspace = operations::Workspace::discover(crate::local_stores())?;
            let mut provider = provider;
            let mut model = model;
            let mut effort = effort.map(vee_core::ReviewEffort::from);
            let guided = !no_input
                && output == Output::Text
                && provider.is_none()
                && model.is_none()
                && effort.is_none()
                && std::io::IsTerminal::is_terminal(&std::io::stdin())
                && std::io::IsTerminal::is_terminal(&std::io::stdout());
            if guided {
                let choices = init_wizard::ask(
                    &operations::detect_providers(),
                    &operations::machine_setup()?,
                    &mut std::io::stdin().lock(),
                    &mut std::io::stdout().lock(),
                )?;
                provider = choices.provider;
                model = choices.model;
                effort = choices.effort;
            }
            let report =
                operations::init(&workspace, provider.as_deref(), model.as_deref(), effort)?;
            match output {
                Output::Json => emit_json(&report)?,
                Output::Text => print_view(&report)?,
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
            RulesCommand::Candidates {
                pull_requests,
                output,
            } => {
                let report = operations::rule_candidates_from(
                    &operations::Workspace::discover(crate::local_stores())?,
                    pull_requests.source().as_ref(),
                )?;
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
                pull_requests,
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
                        pull_requests: pull_requests.source(),
                    },
                )?;
                match output {
                    Output::Json => emit_json(&result)?,
                    Output::Text => print_view(&result)?,
                }
                Ok(0)
            }
            RulesCommand::List { output } => {
                let approvals = operations::list_rule_approvals(&operations::Workspace::discover(
                    crate::local_stores(),
                )?)?;
                match output {
                    Output::Json => emit_json(&approvals)?,
                    Output::Text => print_view(&approvals)?,
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
                    Output::Text => print_view(&result)?,
                }
                Ok(0)
            }
            RulesCommand::Restore {
                approval_id,
                actor,
                reason,
                output,
            } => {
                let result = operations::restore_rule(
                    &operations::Workspace::discover(crate::local_stores())?,
                    &approval_id,
                    &actor,
                    &reason,
                )?;
                match output {
                    Output::Json => emit_json(&result)?,
                    Output::Text => print_view(&result)?,
                }
                Ok(0)
            }
            RulesCommand::Export { write, output } => {
                let result = operations::export_rules(
                    &operations::Workspace::discover(crate::local_stores())?,
                    write.as_deref(),
                )?;
                match output {
                    Output::Json => emit_json(&result)?,
                    Output::Text if result.path.is_none() => print!("{}", result.content),
                    Output::Text => println!(
                        "Wrote {} approved rule(s) to {}. Commit it to share them.",
                        result.rules,
                        result.path.as_deref().unwrap_or_default()
                    ),
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
            McpCommand::Snapshot { spec, log } => {
                snapshot_mcp::serve(&spec, &log)?;
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
            // A token for this process only. It travels in the URL fragment,
            // which the browser keeps to itself; the page then sends it with
            // every API request.
            let auth_token = vee_http::new_access_token()?;
            eprintln!("Vee UI: http://{address}/#token={auth_token}");
            eprintln!("Open this address; the token in it keeps other users and programs out.");
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
            // A progress line on an interactive terminal only, so pipes, logs
            // and JSON output stay clean.
            let terminal_progress = (matches!(output, Output::Text)
                && std::io::IsTerminal::is_terminal(&std::io::stderr()))
            .then_some(TerminalProgress);
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
                    progress: terminal_progress
                        .as_ref()
                        .map(|sink| sink as &dyn vee_application::ReviewProgressSink),
                    carried: None,
                },
                None,
            );
            if terminal_progress.is_some() {
                TerminalProgress::clear();
            }
            let out = out?;
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
        Command::Risk {
            review,
            base,
            commit,
            staged,
            working_tree,
            output,
        } => {
            let workspace = operations::Workspace::discover(crate::local_stores())?;
            let target = change_target(review, base, commit, staged, working_tree)?;
            let risk = operations::change_risk(&workspace, target)?;
            match output {
                Output::Json => emit_json(&risk)?,
                Output::Text => print_view(&risk)?,
            }
            Ok(0)
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
                let plan = test_proposals::plan(
                    &operations::Workspace::discover(crate::local_stores())?,
                    operations::ScopeRequest::from_flags(base, None, staged, working_tree)?,
                    &profile,
                )?;
                match output {
                    Output::Json => emit_json(&plan)?,
                    Output::Text => print_view(&plan)?,
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
                let proposal = test_proposals::generate(
                    &operations::Workspace::discover(crate::local_stores())?,
                    operations::ScopeRequest::from_flags(base, commit, staged, working_tree)?,
                    &reviewer,
                )?;
                match output {
                    // Through a Value, as before: keys stay sorted, as the saved record has them.
                    Output::Json => emit_json(&serde_json::to_value(&proposal)?)?,
                    Output::Text => print_view(&proposal)?,
                }
                Ok(0)
            }
            TestsCommand::Refine {
                proposal_id,
                run,
                reviewer,
                output,
            } => {
                let proposal = test_proposals::refine(
                    &operations::Workspace::discover(crate::local_stores())?,
                    &proposal_id,
                    &run,
                    &reviewer,
                )?;
                match output {
                    // Through a Value, as before: keys stay sorted, as the saved record has them.
                    Output::Json => emit_json(&serde_json::to_value(&proposal)?)?,
                    Output::Text => print_view(&proposal)?,
                }
                Ok(0)
            }
            TestsCommand::Effectiveness {
                proposal_id,
                profile,
                mutant_patch,
                output,
            } => {
                let assessment = test_proposals::assess_effectiveness(
                    &operations::Workspace::discover(crate::local_stores())?,
                    &proposal_id,
                    &profile,
                    &mutant_patch,
                )?;
                match output {
                    Output::Json => {
                        emit_json(&assessment.report)?;
                        eprintln!(
                            "Effectiveness artifact: {} ({})",
                            assessment.artifact_path, assessment.artifact_digest
                        );
                    }
                    Output::Text => print_view(&assessment)?,
                }
                Ok(0)
            }
            TestsCommand::EffectivenessCorpus {
                proposal_id,
                profile,
                manifest,
                output,
            } => {
                let assessment = test_proposals::assess_effectiveness_corpus(
                    &operations::Workspace::discover(crate::local_stores())?,
                    &proposal_id,
                    &profile,
                    &manifest,
                )?;
                match output {
                    Output::Json => {
                        emit_json(&assessment.report)?;
                        eprintln!(
                            "Effectiveness corpus artifact: {} ({})",
                            assessment.artifact_path, assessment.artifact_digest
                        );
                    }
                    Output::Text => print_view(&assessment)?,
                }
                Ok(0)
            }
            TestsCommand::Apply {
                proposal_id,
                approve,
                output,
            } => {
                let workspace = proposal_workspace()?;
                confirm_patch_application(
                    "test proposal",
                    &proposal_id,
                    &workspace.root().join(".vee/proposals").join(format!(
                        "test-{}.patch",
                        proposal_id.strip_prefix("sha256:").unwrap_or(&proposal_id)
                    )),
                )?;
                let application = test_proposals::apply(&workspace, &proposal_id, &approve)?;
                match output {
                    // Through a Value, as before: keys stay sorted.
                    Output::Json => emit_json(&serde_json::to_value(&application)?)?,
                    Output::Text => print_view(&application)?,
                }
                Ok(if application.concurrent_mutation_detected {
                    2
                } else {
                    0
                })
            }
            TestsCommand::Run {
                proposal_id,
                profile,
                output,
            } => {
                let verification =
                    test_proposals::run(&proposal_workspace()?, &proposal_id, &profile)?;
                match output {
                    // Through a Value, as before: keys stay sorted.
                    Output::Json => emit_json(&serde_json::to_value(&verification)?)?,
                    Output::Text => print_view(&verification)?,
                }
                Ok(match verification.verification_run.status {
                    VerificationStatus::Passed => 0,
                    VerificationStatus::Failed => 1,
                    VerificationStatus::TimedOut | VerificationStatus::Incomplete => 2,
                })
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
                let workspace = operations::Workspace::discover(crate::local_stores())?;
                let report = operations::acceptance_validate(&workspace, &review, &mapping)?;
                match output {
                    Output::Json => emit_json(&report)?,
                    Output::Text => print_view(&report)?,
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
            GateCommand::Approval { review, output } => {
                let approval = operations::approval_eligibility(
                    &operations::Workspace::discover(crate::local_stores())?,
                    &review,
                )?;
                match output {
                    Output::Json => emit_json(&approval)?,
                    Output::Text => print_view(&approval)?,
                }
                // Like `gate check`, a non-zero exit lets scripts branch on it.
                Ok(if approval.eligible { 0 } else { 1 })
            }
            GateCommand::Conditions { review, output } => {
                let classification = operations::classify_conditions(
                    &operations::Workspace::discover(crate::local_stores())?,
                    &review,
                )?;
                match output {
                    Output::Json => emit_json(&classification)?,
                    Output::Text => {
                        for result in &classification.results {
                            println!(
                                "{} {}: {}",
                                if result.holds { "holds" } else { "clear" },
                                result.id,
                                result.evidence
                            );
                        }
                        println!(
                            "Classified by {}{}; output {}.",
                            classification.reviewer_id,
                            classification
                                .model
                                .as_deref()
                                .map(|model| format!(" on {model}"))
                                .unwrap_or_default(),
                            classification.output_digest
                        );
                    }
                }
                // Like `gate approval`: non-zero when a person must approve.
                Ok(
                    if classification.results.iter().any(|result| result.holds) {
                        1
                    } else {
                        0
                    },
                )
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
            let result = operations::verify(
                &workspace,
                operations::VerifyRequest {
                    target,
                    profile_id: &profile,
                    impacted_tests,
                },
            )?;
            match output {
                Output::Json => emit_json(&result)?,
                Output::Text => print_view(&result)?,
            }
            Ok(match result.run.status {
                VerificationStatus::Passed => 0,
                VerificationStatus::Failed => 1,
                VerificationStatus::TimedOut => 2,
                VerificationStatus::Incomplete => 2,
            })
        }
        Command::Verification { command } => match command {
            VerificationCommand::List { snapshot, output } => {
                let list = operations::verification_list(
                    &operations::Workspace::discover(crate::local_stores())?,
                    &snapshot,
                )?;
                match output {
                    Output::Json => emit_json(&list)?,
                    Output::Text => print_view(&list)?,
                }
                Ok(0)
            }
            VerificationCommand::Show { run_id, output } => {
                let workspace = operations::Workspace::discover(crate::local_stores())?;
                let run = operations::verification_show(&workspace, &run_id)?;
                match output {
                    Output::Json => emit_json(&run)?,
                    Output::Text => print_view(&run)?,
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
                let workspace = operations::Workspace::discover(crate::local_stores())?;
                let stream = match stream {
                    CoverageStream::Stdout => "stdout",
                    CoverageStream::Stderr => "stderr",
                };
                let report = operations::verification_coverage(&workspace, &run_id, stream)?;
                match output {
                    Output::Json => emit_json(&report)?,
                    Output::Text => print_view(&report)?,
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
                    let list = operations::reviews_list(&operations::Workspace::new(
                        std::path::PathBuf::from(&top),
                        crate::local_stores(),
                    ))?;
                    match output {
                        Output::Json => emit_json(&list)?,
                        Output::Text => print_view(&list)?,
                    }
                    Ok(0)
                }
                ReviewsCommand::Session { reviews, output } => {
                    let workspace = operations::Workspace::new(
                        std::path::PathBuf::from(&top),
                        crate::local_stores(),
                    );
                    let session = operations::review_session(
                        &workspace,
                        &reviews,
                        operations::RepositoryPaths::Relative,
                    )?;
                    match output {
                        Output::Json => emit_json(&session)?,
                        Output::Text => print_view(&session)?,
                    }
                    // Like `gate check`: 0 pass, 1 block, 2 incomplete.
                    Ok(session.exit_code())
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
                    let workspace = operations::Workspace::new(
                        std::path::PathBuf::from(&top),
                        crate::local_stores(),
                    );
                    let format = match format {
                        ReportFormat::Sarif => operations::ReviewExportFormat::Sarif,
                        ReportFormat::VeeJson => operations::ReviewExportFormat::VeeJson,
                    };
                    emit_json(&operations::export_review(&workspace, &id, format)?)?;
                    Ok(0)
                }
                ReviewsCommand::Bundle { id, decision_id } => {
                    let workspace = operations::Workspace::new(
                        std::path::PathBuf::from(&top),
                        crate::local_stores(),
                    );
                    let bundle =
                        evidence_bundle::export_bundle(&workspace, &id, decision_id.as_deref())?;
                    // Through a Value: the manifest digests cover the sorted-key form.
                    emit_json(&serde_json::to_value(&bundle)?)?;
                    Ok(0)
                }
                ReviewsCommand::Attest {
                    id,
                    decision_id,
                    format,
                    private_key,
                    key_id,
                } => {
                    let workspace = operations::Workspace::new(
                        std::path::PathBuf::from(&top),
                        crate::local_stores(),
                    );
                    let format = match format {
                        AttestationFormat::Statement => attestation::AttestationFormat::Statement,
                        AttestationFormat::Dsse => attestation::AttestationFormat::Dsse {
                            private_key: private_key.as_deref().unwrap_or(std::path::Path::new("")),
                            key_id: key_id.as_deref().unwrap_or_default(),
                        },
                    };
                    let document =
                        attestation::attest(&workspace, &id, decision_id.as_deref(), format)?;
                    emit_json(&document)?;
                    Ok(0)
                }
                ReviewsCommand::Share {
                    id,
                    private_key,
                    key_id,
                    output,
                } => {
                    let workspace = operations::Workspace::new(
                        std::path::PathBuf::from(&top),
                        crate::local_stores(),
                    );
                    let shared = vee_application::shared_review::share(
                        &workspace,
                        &id,
                        &private_key,
                        &key_id,
                    )?;
                    match output {
                        Output::Json => emit_json(&shared)?,
                        Output::Text => print_view(&shared)?,
                    }
                    Ok(0)
                }
                ReviewsCommand::VerifyAttestation {
                    path,
                    public_key,
                    output,
                } => {
                    let report = attestation::verify_file(&path, &public_key)?;
                    match output {
                        // Through a Value, as before: keys stay sorted.
                        Output::Json => emit_json(&serde_json::to_value(&report)?)?,
                        Output::Text => print_view(&report)?,
                    }
                    Ok(if report.valid { 0 } else { 2 })
                }
                ReviewsCommand::VerifyBundle {
                    path,
                    public_key,
                    output,
                } => {
                    let report = evidence_bundle::verify_file(&path, public_key.as_deref())?;
                    match output {
                        // Through a Value, as before: keys stay sorted.
                        Output::Json => emit_json(&serde_json::to_value(&report)?)?,
                        Output::Text => print_view(&report)?,
                    }
                    Ok(if report.passed() { 0 } else { 2 })
                }
                ReviewsCommand::SignBundle {
                    path,
                    private_key,
                    key_id,
                } => {
                    print_view(&evidence_bundle::sign_file(&path, &private_key, &key_id)?)?;
                    Ok(0)
                }
                ReviewsCommand::Keygen {
                    private_key,
                    public_key,
                } => {
                    print_view(&signing::generate_key_pair(&private_key, &public_key)?)?;
                    Ok(0)
                }
                ReviewsCommand::Import { path, output } => {
                    let imported =
                        imported_history::import_review_archive(std::path::Path::new(&top), &path)?;
                    match output {
                        // Through a Value, as before: keys stay sorted.
                        Output::Json => emit_json(&serde_json::to_value(&imported)?)?,
                        Output::Text => print_view(&imported)?,
                    }
                    Ok(0)
                }
                ReviewsCommand::Imported { command } => match command {
                    ImportedCommand::List { output } => {
                        let list =
                            imported_history::list_imported_archives(std::path::Path::new(&top))?;
                        match output {
                            // Through a Value, as before: keys stay sorted.
                            Output::Json => emit_json(&serde_json::to_value(&list)?)?,
                            Output::Text => print_view(&list)?,
                        }
                        Ok(0)
                    }
                    ImportedCommand::Show { digest } => {
                        emit_json(&imported_history::show_imported_archive(
                            std::path::Path::new(&top),
                            &digest,
                        )?)?;
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
                            // Through a Value, as before: keys stay sorted, as MCP emits them.
                            Output::Json => emit_json(&serde_json::to_value(&report)?)?,
                            Output::Text => print_view(&report)?,
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
                            match output {
                                Output::Json => emit_json(&recorded)?,
                                Output::Text => print_view(&recorded)?,
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
                            match output {
                                Output::Json => emit_json(&listed)?,
                                Output::Text => print_view(&listed)?,
                            }
                            Ok(0)
                        }
                    },
                },
            }
        }
        Command::Analytics {
            command:
                Some(AnalyticsCommand::Aggregate {
                    inputs,
                    html,
                    output,
                }),
            ..
        } => {
            let report = vee_application::team_analytics::aggregate(&inputs)?;
            if let Some(path) = html {
                let page = vee_present::html::render(
                    &vee_present::ToView::to_view(&report),
                    "Vee team analytics",
                );
                std::fs::write(&path, page)
                    .with_context(|| format!("writing {}", path.display()))?;
            }
            match output {
                Output::Json => emit_json(&report)?,
                Output::Text => print_view(&report)?,
            }
            Ok(0)
        }
        Command::Analytics {
            command: None,
            output,
        } => {
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
                let result = operations::repository_map(&repositories)?;
                match output {
                    Output::Json => emit_json(&result)?,
                    Output::Text => print_view(&result)?,
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
                let package = operations::change_package(
                    operations::ChangePackageRequest {
                        repositories: &repositories,
                        pull_request_links: &pull_requests,
                        discover_linked_prs,
                        refresh_pr_links,
                        base: base.as_deref(),
                    },
                    &vee_store_sqlite::SqliteRepositoryStores,
                )?;
                match output {
                    Output::Json => emit_json(&package)?,
                    Output::Text => print_view(&package)?,
                }
                Ok(0)
            }
            ReposCommand::Impact {
                producer,
                consumers,
                base,
                output,
            } => {
                let result = operations::cross_repository_impact(&producer, &base, &consumers)?;
                match output {
                    Output::Json => emit_json(&result)?,
                    Output::Text => print_view(&result)?,
                }
                Ok(0)
            }
        },
        Command::Hooks { command } => run_hooks(command),
        Command::Steward {
            base,
            max_fixes,
            output,
        } => {
            let workspace = operations::Workspace::discover(crate::local_stores())?;
            let report = operations::steward(
                &workspace,
                vee_application::steward::StewardRequest {
                    base: &base,
                    max_fixes,
                    by_agent: false,
                },
            )?;
            match output {
                Output::Json => emit_json(&report)?,
                Output::Text => print_view(&report)?,
            }
            Ok(match report.gate {
                GateStatus::Pass => 0,
                GateStatus::Block => 1,
                GateStatus::Incomplete => 2,
            })
        }
        Command::Ci {
            command:
                CiCommand::Approvals {
                    repository,
                    provider: provider_id,
                    limit,
                    api_base,
                    token_env,
                    actor_login,
                    output,
                },
        } => {
            let api_base = if api_base.ends_with('/') {
                api_base
            } else {
                format!("{api_base}/")
            };
            let api = url::Url::parse(&api_base)
                .map_err(|_| anyhow::anyhow!("--api-base is not a URL: {api_base}"))?;
            let host = match api.host_str() {
                Some("api.github.com") => "github.com".to_owned(),
                Some(host) => host.to_owned(),
                None => anyhow::bail!("--api-base has no host: {api_base}"),
            };
            let actor_login = if provider_id == "gitlab" && actor_login == "github-actions[bot]" {
                vee_application::hosting::token_login(&provider_id, &api_base, &token_env)?
                    .unwrap_or_default()
            } else {
                actor_login
            };
            let provider = vee_application::hosting::conversation_provider(
                &provider_id,
                &api_base,
                &token_env,
                &actor_login,
            )?;
            let report = vee_application::approval_report::report(
                &*provider,
                &vee_hosting::RepositoryRef {
                    host,
                    full_name: repository,
                },
                &actor_login,
                usize::from(limit),
                &local_revert_commits(),
            )?;
            match output {
                Output::Json => emit_json(&report)?,
                Output::Text => print_view(&report)?,
            }
            Ok(0)
        }
        Command::Ci {
            command:
                CiCommand::Run {
                    approval,
                    effort,
                    policy_profile,
                    actor_login,
                    full,
                    labels,
                    approve,
                    describe,
                    output,
                },
        } => {
            let pull_request = vee_application::ci::detect(&|name| std::env::var(name).ok())?;
            let cwd = std::env::current_dir()?;
            let top = vee_git::repository_root(&cwd).map_err(anyhow::Error::msg)?;
            let run = vee_application::ci::run(
                &operations::Workspace::new(top, crate::local_stores()),
                pull_request,
                vee_application::ci::CiRunOptions {
                    describe,
                    approval,
                    effort: effort.map(Into::into),
                    policy_profile,
                    actor_login,
                    full,
                    labels,
                    approve,
                },
            )?;
            match output {
                Output::Json => emit_json(&serde_json::to_value(&run)?)?,
                Output::Text => print_view(&run)?,
            }
            Ok(match run.gate {
                GateStatus::Pass => 0,
                GateStatus::Block => 1,
                GateStatus::Incomplete => 2,
            })
        }
        Command::Ci {
            command:
                CiCommand::Command {
                    approval,
                    effort,
                    policy_profile,
                    actor_login,
                    labels,
                    approve,
                    describe,
                    output,
                },
        } => {
            let Some(event) =
                vee_application::pr_commands::detect_comment(&|name| std::env::var(name).ok())?
            else {
                return Ok(0);
            };
            let mut actor = actor_login
                .clone()
                .unwrap_or_else(|| event.actor_login.clone());
            if actor.is_empty() {
                // GitLab: the token's user is Vee.
                actor = vee_application::hosting::token_login(
                    &event.provider,
                    &event.api_base,
                    &event.token_env,
                )?
                .unwrap_or_default();
            }
            let actor_login = actor_login.or_else(|| Some(actor.clone()));
            let host = vee_application::hosting::conversation_provider(
                &event.provider,
                &event.api_base,
                &event.token_env,
                &actor,
            )?;
            let cwd = std::env::current_dir()?;
            let top = vee_git::repository_root(&cwd).map_err(anyhow::Error::msg)?;
            let handled = vee_application::pr_commands::handle(
                &operations::Workspace::new(top, crate::local_stores()),
                &*host,
                event,
                vee_application::pr_commands::CommandOptions {
                    run: vee_application::ci::CiRunOptions {
                        describe,
                        approval,
                        effort: effort.map(Into::into),
                        policy_profile,
                        actor_login: None,
                        full: false,
                        labels,
                        approve,
                    },
                    actor_login,
                },
            )?;
            match output {
                Output::Json => emit_json(&serde_json::to_value(&handled)?)?,
                Output::Text => print_view(&handled)?,
            }
            Ok(0)
        }
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
                let issues = vee_application::hosting::pull_request_issues(
                    &hosting_config_root()?,
                    vee_application::hosting::HostingFlags {
                        provider,
                        host,
                        api_base,
                        token_env,
                        username,
                    },
                    vee_application::hosting::PullRequestTarget { repository, number },
                    archive,
                )?;
                match output {
                    // Sorted keys, as the document has always been printed.
                    Output::Json => emit_json(&serde_json::to_value(&issues)?)?,
                    Output::Text => print_view(&issues)?,
                }
                Ok(if issues.report.complete { 0 } else { 2 })
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
                let report = vee_application::hosting::pull_request_context(
                    &hosting_config_root()?,
                    vee_application::hosting::HostingFlags {
                        provider,
                        host,
                        api_base,
                        token_env,
                        username,
                    },
                    vee_application::hosting::PullRequestTarget { repository, number },
                )?;
                match output {
                    Output::Json => emit_json(&report)?,
                    Output::Text => print_view(&report)?,
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
                let item = vee_application::hosting::issue_context(
                    &hosting_config_root()?,
                    vee_application::hosting::HostingFlags {
                        provider,
                        host,
                        api_base,
                        token_env,
                        username: None,
                    },
                    repository,
                    number,
                )?;
                match output {
                    Output::Json => emit_json(&item)?,
                    Output::Text => print_view(&item)?,
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
                approval,
                output,
            } => {
                let cwd = std::env::current_dir()?;
                let top = vee_git::repository_root(&cwd).map_err(anyhow::Error::msg)?;
                let publication = vee_application::hosting::publish_review(
                    &operations::Workspace::new(top, crate::local_stores()),
                    vee_application::hosting::PublishRequest {
                        dismissed_fingerprints: Default::default(),
                        review_id: &review_id,
                        repository: &repository,
                        number,
                        flags: vee_application::hosting::PublishFlags {
                            hosting: vee_application::hosting::HostingFlags {
                                provider,
                                host,
                                api_base,
                                token_env,
                                username,
                            },
                            webhook_secret_env,
                            actor_login,
                        },
                        approval,
                        pull_request_threads: Vec::new(),
                    },
                )?;
                match output {
                    // Sorted keys, as the document has always been printed.
                    Output::Json => emit_json(&serde_json::to_value(&publication)?)?,
                    Output::Text => print_view(&publication)?,
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
                tls_cert,
                tls_key,
            } => {
                let tls = match (tls_cert, tls_key) {
                    (Some(certificate), Some(private_key)) => Some(
                        vee_http::tls::server_config(&vee_http::tls::TlsFiles {
                            certificate,
                            private_key,
                        })
                        .map_err(|error| configuration_failure(format!("{error:#}")))?,
                    ),
                    _ => None,
                };
                let listen = vee_http::WebhookListen {
                    address: std::net::SocketAddr::new(bind, port),
                    allow_network,
                    tls,
                };
                if let Some(refusal) = vee_http::webhook_listen_refusal(&listen) {
                    return Err(configuration_failure(refusal));
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
                let scheme = if listen.tls.is_some() {
                    "https"
                } else {
                    "http"
                };
                eprintln!(
                    "Vee {provider_id} webhook listener: {scheme}://{}/api/webhooks/{provider_id}",
                    listen.address
                );
                tokio::runtime::Runtime::new()?.block_on(vee_http::serve_with_webhooks(
                    root, listen, provider, handler,
                ))?;
                Ok(0)
            }
            HostingCommand::PruneWebhooks {
                older_than_days,
                apply,
                output,
            } => {
                let workspace = operations::Workspace::discover(crate::local_stores())?;
                let retention = vee_application::hosting::prune_webhook_deliveries(
                    &workspace,
                    older_than_days,
                    apply,
                )?;
                match output {
                    // Sorted keys, as the document has always been printed.
                    Output::Json => emit_json(&serde_json::to_value(&retention)?)?,
                    Output::Text => print_view(&retention)?,
                }
                Ok(0)
            }
        },
        Command::Waivers { command } => {
            let cwd = std::env::current_dir()?;
            let top = vee_git::repository_root(&cwd).map_err(anyhow::Error::msg)?;
            match command {
                WaiversCommand::Create {
                    finding_id,
                    review,
                    reason,
                    author,
                    expires_in_days,
                    output,
                } => {
                    let waiver = operations::create_waiver(
                        &operations::Workspace::new(top.clone(), crate::local_stores()),
                        &operations::WaiverRequest {
                            review_id: &review,
                            finding_id: &finding_id,
                            reason: &reason,
                            author: &author,
                            expires_in_days,
                        },
                    )?;
                    match output {
                        Output::Json => emit_json(&waiver)?,
                        Output::Text => print_view(&waiver)?,
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
                    match output {
                        // Through a Value, as before: keys stay sorted, as MCP emits them.
                        Output::Json => emit_json(&serde_json::to_value(&proposal)?)?,
                        Output::Text => print_view(&proposal)?,
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
                    confirm_patch_application(
                        "patch",
                        &digest,
                        &proposal_dir.join(format!("{}.patch", &digest[7..])),
                    )?;
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
                    let applied = operations::PatchApplication {
                        schema_version: 1,
                        proposal_digest: digest,
                        approved: true,
                        application: "applied".into(),
                        concurrent_mutation_detected,
                        review,
                    };
                    match output {
                        // Sorted keys, as this command has always emitted.
                        Output::Json => emit_json(&serde_json::to_value(&applied)?)?,
                        Output::Text => print_view(&applied)?,
                    }
                    Ok(if applied.concurrent_mutation_detected {
                        2
                    } else {
                        match applied.review.gate.status {
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
                        let list =
                            operations::finding_feedback_list(&workspace, finding.as_deref())?;
                        match output {
                            Output::Json => emit_json(&list)?,
                            Output::Text => print_view(&list)?,
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

/// Redraws one stderr line with the review's progress as reviewer runs finish.
struct TerminalProgress;

impl TerminalProgress {
    fn clear() {
        use std::io::Write;
        let mut stderr = std::io::stderr().lock();
        let _ = write!(stderr, "\r\x1b[2K");
        let _ = stderr.flush();
    }
}

impl vee_application::ReviewProgressSink for TerminalProgress {
    fn report(&self, progress: &vee_application::ReviewProgress) {
        use std::io::Write;
        // Reviewer IDs come from repository configuration; keep the line inert.
        let line: String = progress
            .summary()
            .chars()
            .filter(|character| !character.is_control())
            .collect();
        let mut stderr = std::io::stderr().lock();
        let _ = write!(stderr, "\r\x1b[2KReviewing: {line}");
        let _ = stderr.flush();
    }
}

/// A person confirms each patch application at a terminal. Without one, as in
/// an agent's shell, applying needs `patches.allow_noninteractive_apply` in
/// this machine's user configuration, which lives outside the repository.
fn confirm_patch_application(
    kind: &str,
    id: &str,
    location: &std::path::Path,
) -> anyhow::Result<()> {
    use std::io::{BufRead, IsTerminal, Write};
    let interactive = std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
    if !interactive {
        if vee_application::noninteractive_patch_apply_allowed().map_err(configuration_failure)? {
            return Ok(());
        }
        return Err(usage_failure(
            "applying a patch needs a person to confirm it at a terminal; to allow it without one on this machine, set `patches: { allow_noninteractive_apply: true }` in your Vee user config",
        ));
    }
    let mut stderr = std::io::stderr();
    write!(
        stderr,
        "Apply {kind} {id}?\nReview it first: {}\nType `apply` to continue: ",
        location.display()
    )?;
    stderr.flush()?;
    let mut answer = String::new();
    std::io::stdin().lock().read_line(&mut answer)?;
    if answer.trim() != "apply" {
        return Err(usage_failure(format!("{kind} {id} was not applied")));
    }
    Ok(())
}

/// Revert commits on the checked-out branch, when `vee ci approvals` runs in
/// a clone; none otherwise.
fn local_revert_commits() -> Vec<vee_git::RevertCommit> {
    std::env::current_dir()
        .ok()
        .and_then(|directory| vee_git::repository_root(&directory).ok())
        .and_then(|root| {
            vee_git::revert_commits(
                &root,
                "HEAD",
                vee_application::approval_report::LOCAL_REVERT_LIMIT,
            )
            .ok()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::install_agent_skills;
    use super::{
        json_output_requested, read_proposal_file, work_item_api_base, write_markdown_report, Cli,
        Command, HostingCommand, Output,
    };
    use clap::Parser;
    use vee_application::attestation::committed_snapshot_matches_review;

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
