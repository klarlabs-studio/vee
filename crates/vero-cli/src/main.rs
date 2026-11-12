use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::{io::Write, process::ExitCode};
use vero_core::{
    ChangeSet, GateStatus, RepositoryConfig, ReviewStore, Severity, VerificationRun,
    VerificationStatus,
};

mod mcp;

#[derive(Debug)]
struct ConfigurationFailure(String);

impl std::fmt::Display for ConfigurationFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ConfigurationFailure {}

#[derive(Debug)]
struct UsageFailure(String);

impl std::fmt::Display for UsageFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for UsageFailure {}

fn configuration_failure(message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(ConfigurationFailure(message.into()))
}

fn usage_failure(message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(UsageFailure(message.into()))
}

fn load_repository_config(root: &std::path::Path) -> Result<RepositoryConfig> {
    vero_application::load_repository_config(root).map_err(configuration_failure)
}

fn apply_protected_policy(root: &std::path::Path, config: &mut RepositoryConfig) -> Result<()> {
    vero_application::apply_protected_policy(root, config).map_err(configuration_failure)
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
#[command(name = "vero", version, about = "Local-first code change assurance")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Init,
    Review {
        #[arg(long)]
        base: Option<String>,
        #[arg(long, conflicts_with_all = ["base", "staged", "working_tree"])]
        commit: Option<String>,
        #[arg(long)]
        staged: bool,
        #[arg(long)]
        working_tree: bool,
        #[arg(long)]
        gate: bool,
        #[arg(long, value_name = "NAME")]
        policy_profile: Option<String>,
        #[arg(long = "reviewer")]
        reviewer_ids: Vec<String>,
        #[arg(long, value_name = "PATH")]
        markdown: Option<std::path::PathBuf>,
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    Impact {
        #[arg(long, conflicts_with_all = ["staged", "working_tree"])]
        base: Option<String>,
        #[arg(long, conflicts_with_all = ["base", "staged", "working_tree"])]
        commit: Option<String>,
        #[arg(long, conflicts_with = "working_tree")]
        staged: bool,
        #[arg(long)]
        working_tree: bool,
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    Gate {
        #[command(subcommand)]
        command: GateCommand,
    },
    Findings {
        #[command(subcommand)]
        command: FindingsCommand,
    },
    Waivers {
        #[command(subcommand)]
        command: WaiversCommand,
    },
    Verify {
        finding_id: Option<String>,
        #[arg(long)]
        profile: String,
        #[arg(long, conflicts_with_all = ["staged", "working_tree"])]
        base: Option<String>,
        #[arg(long, conflicts_with = "working_tree")]
        staged: bool,
        #[arg(long)]
        working_tree: bool,
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    Verification {
        #[command(subcommand)]
        command: VerificationCommand,
    },
    Reviews {
        #[command(subcommand)]
        command: ReviewsCommand,
    },
    Mcp {
        #[command(subcommand)]
        command: McpCommand,
    },
}
#[derive(Subcommand)]
enum McpCommand {
    Serve {
        #[arg(long, default_value = "stdio", value_parser = ["stdio"])]
        transport: String,
    },
}
#[derive(Subcommand)]
enum VerificationCommand {
    Show {
        run_id: String,
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
}
#[derive(Subcommand)]
enum ReviewsCommand {
    List {
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    Show {
        id: String,
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    Export {
        id: String,
        #[arg(long, value_enum, default_value = "sarif")]
        format: ReportFormat,
    },
}
#[derive(Clone, Copy, clap::ValueEnum)]
enum ReportFormat {
    Sarif,
}
#[derive(Subcommand)]
enum GateCommand {
    Check {
        #[arg(long)]
        review: String,
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    History {
        #[arg(long)]
        review: String,
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
}
#[derive(Subcommand)]
enum FindingsCommand {
    List {
        #[arg(long, value_enum)]
        severity: Option<SeverityArg>,
        #[arg(long, value_enum)]
        status: Option<StatusArg>,
        #[arg(long)]
        review: Option<String>,
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    Show {
        id: String,
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    SetStatus {
        id: String,
        #[arg(long, value_enum)]
        status: StatusArg,
        #[arg(long)]
        reason: String,
    },
}
#[derive(Subcommand)]
enum WaiversCommand {
    Create {
        finding_id: String,
        #[arg(long)]
        review: String,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        author: String,
        #[arg(long, default_value_t = 30)]
        expires_in_days: u32,
        #[arg(long, value_enum, default_value = "text")]
        output: Output,
    },
    List {
        #[arg(long)]
        review: String,
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
impl From<StatusArg> for vero_core::FindingStatus {
    fn from(value: StatusArg) -> Self {
        match value {
            StatusArg::Open => Self::Open,
            StatusArg::Verified => Self::Verified,
            StatusArg::Refuted => Self::Refuted,
            StatusArg::Resolved => Self::Resolved,
        }
    }
}
#[derive(Clone, clap::ValueEnum)]
enum Output {
    Text,
    Json,
}
fn current_change_set(root: &str, base_oid: Option<&str>, scope: &str) -> Result<ChangeSet> {
    let capture_scope = match scope {
        "staged" => vero_git::ChangeScope::Staged,
        "working_tree" => vero_git::ChangeScope::WorkingTree,
        value if value.starts_with("commit:") => {
            vero_git::commit_scope(value.trim_start_matches("commit:"))
                .map_err(anyhow::Error::msg)?
        }
        value if value.starts_with("commit_range:") => {
            vero_git::commit_scope(value.trim_start_matches("commit_range:"))
                .map_err(anyhow::Error::msg)?
        }
        _ => vero_git::ChangeScope::BaseAndWorktree {
            base_oid: base_oid.map(str::to_string),
        },
    };
    vero_application::capture_change_set(std::path::Path::new(root), capture_scope)
        .map_err(anyhow::Error::msg)
}

fn current_unix_time() -> Result<i64> {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    i64::try_from(seconds).context("system clock exceeds supported timestamp")
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

fn review_to_sarif(review: &vero_application::ReviewResult) -> Result<serde_json::Value> {
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
                "partialFingerprints": {"vero/v1": finding.fingerprint},
                "locations": locations,
                "properties": {
                    "veroFindingId": finding.id,
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
                "name": "Vero",
                "semanticVersion": env!("CARGO_PKG_VERSION"),
                "rules": rules
            }},
            "results": results,
            "invocations": [{
                "executionSuccessful": review.analysis_complete,
                "properties": {
                    "veroReviewId": review.review_id,
                    "veroSnapshotId": review.snapshot_id,
                    "veroGateStatus": review.status
                }
            }]
        }]
    }))
}

fn main() -> ExitCode {
    let json_output = json_output_requested(&std::env::args_os().collect::<Vec<_>>());
    match run() {
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
                eprintln!("vero: {err:#}");
            }
            ExitCode::from(exit_code)
        }
    }
}

fn json_output_requested(args: &[std::ffi::OsString]) -> bool {
    args.iter().any(|arg| arg == "--output=json")
        || args
            .windows(2)
            .any(|pair| pair[0] == "--output" && pair[1] == "json")
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
    match cli.command {
        Command::Init => {
            let path = std::path::Path::new(".vero.yaml");
            if path.exists() {
                return Err(configuration_failure(".vero.yaml already exists"));
            }
            std::fs::write(path, "version: 1\nreview:\n  include: [\"**/*.rs\", \"**/*.go\"]\n  exclude: [\"**/generated/**\"]\nproviders: {}\nreviewers: {}\nverification: {}\npolicy:\n  required_reviewers: []\n  required_verifications: []\n  block_severities: [critical, high]\n  minimum_confidence: 80\n  on_incomplete: block\n")?;
            println!("Created .vero.yaml");
            Ok(0)
        }
        Command::Mcp { command } => match command {
            McpCommand::Serve { transport: _ } => {
                mcp::serve_stdio()?;
                Ok(0)
            }
        },
        Command::Review {
            base,
            commit,
            staged,
            working_tree,
            gate,
            policy_profile,
            reviewer_ids,
            markdown,
            output,
        } => {
            let root = std::env::current_dir()?;
            let top = vero_git::repository_root(&root).map_err(anyhow::Error::msg)?;
            if staged && working_tree {
                return Err(usage_failure(
                    "--staged and --working-tree are mutually exclusive",
                ));
            }
            if staged && base.is_some() {
                return Err(usage_failure("--base cannot be combined with --staged"));
            }
            let capture_scope = if let Some(oid) = commit {
                vero_git::commit_scope(&oid).map_err(usage_failure)?
            } else if staged {
                vero_git::ChangeScope::Staged
            } else if working_tree {
                vero_git::ChangeScope::WorkingTree
            } else {
                vero_git::ChangeScope::BaseAndWorktree {
                    base_oid: base
                        .as_deref()
                        .map(|base_ref| vero_git::merge_base(&top, base_ref))
                        .transpose()
                        .map_err(usage_failure)?,
                }
            };
            let change_set = vero_application::capture_change_set(&top, capture_scope)
                .map_err(anyhow::Error::msg)?;
            let mut config = load_repository_config(std::path::Path::new(&top))?;
            config
                .select_policy_profile(policy_profile.as_deref())
                .map_err(configuration_failure)?;
            apply_protected_policy(std::path::Path::new(&top), &mut config)?;
            let db_dir = std::path::Path::new(&top).join(".vero");
            std::fs::create_dir_all(&db_dir)?;
            let mut store =
                ReviewStore::open(&db_dir.join("vero.sqlite")).map_err(anyhow::Error::msg)?;
            let out = vero_application::run_review_selecting_reviewers(
                &top,
                change_set,
                &config,
                &mut store,
                (!reviewer_ids.is_empty()).then_some(reviewer_ids.as_slice()),
            )
            .map_err(anyhow::Error::msg)?;
            if let Some(path) = markdown {
                let report = vero_application::render_review_markdown(&out);
                std::fs::write(&path, report)
                    .with_context(|| format!("writing Markdown report {}", path.display()))?;
            }
            match output {
                Output::Json => {
                    serde_json::to_writer(std::io::stdout().lock(), &out)?;
                    println!();
                    eprintln!("Review {}", out.review_id);
                    eprintln!("Status: {}", out.status);
                    eprintln!("Snapshot: {}", out.snapshot_id);
                }
                Output::Text => {
                    println!("Review snapshot: {}", out.snapshot_id);
                    println!("Status: {}", out.status);
                    for reason in &out.reasons {
                        println!("- {reason}");
                    }
                }
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
            base,
            commit,
            staged,
            working_tree,
            output,
        } => {
            let cwd = std::env::current_dir()?;
            let root = vero_git::repository_root(&cwd).map_err(anyhow::Error::msg)?;
            let scope = if let Some(oid) = commit {
                vero_git::commit_scope(&oid).map_err(usage_failure)?
            } else if staged {
                vero_git::ChangeScope::Staged
            } else if working_tree {
                vero_git::ChangeScope::WorkingTree
            } else {
                vero_git::ChangeScope::BaseAndWorktree {
                    base_oid: base
                        .as_deref()
                        .map(|base_ref| vero_git::merge_base(&root, base_ref))
                        .transpose()
                        .map_err(usage_failure)?,
                }
            };
            let change_set =
                vero_application::capture_change_set(&root, scope).map_err(anyhow::Error::msg)?;
            let impact =
                vero_application::analyze_impact(&root, &change_set).map_err(anyhow::Error::msg)?;
            match output {
                Output::Json => {
                    serde_json::to_writer(std::io::stdout().lock(), &impact)?;
                    println!();
                }
                Output::Text => {
                    println!("Impact for snapshot: {}", impact.snapshot_id);
                    println!("Changed paths: {}", impact.changed_paths.len());
                    println!("Changed symbols: {}", impact.changed_symbols.join(", "));
                    for edge in &impact.paths {
                        println!(
                            "{}:{} -> {} via {} ({})",
                            edge.affected_path,
                            edge.evidence_line,
                            edge.source_path,
                            edge.symbol,
                            edge.certainty
                        );
                    }
                    for limitation in &impact.limitations {
                        println!("Limitation: {limitation}");
                    }
                }
            }
            Ok(0)
        }
        Command::Gate { command } => match command {
            GateCommand::Check { review, output } => {
                let root = std::env::current_dir()?;
                let top = vero_git::repository_root(&root)
                    .map_err(anyhow::Error::msg)?
                    .to_string_lossy()
                    .to_string();
                let db_path = std::path::Path::new(&top).join(".vero/vero.sqlite");
                let store = ReviewStore::open(&db_path).map_err(anyhow::Error::msg)?;
                let payload = store
                    .get(&review)
                    .map_err(anyhow::Error::msg)?
                    .ok_or_else(|| usage_failure(format!("review ID {review} was not found")))?;
                let stored = vero_application::deserialize_review_result(&payload)
                    .map_err(anyhow::Error::msg)?;
                let current = current_change_set(
                    &top,
                    stored.change_set.base_oid.as_deref(),
                    &stored.change_set.scope,
                )?;
                let mut config = load_repository_config(std::path::Path::new(&top))?;
                config
                    .select_policy_profile(stored.policy_profile.as_deref())
                    .map_err(configuration_failure)?;
                apply_protected_policy(std::path::Path::new(&top), &mut config)?;
                let config_digest = vero_application::effective_review_config_digest(
                    &config,
                    std::path::Path::new(&top),
                    &stored.selected_reviewers,
                )
                .map_err(anyhow::Error::msg)?;
                let verification_runs = store
                    .verifications_for_snapshot(&current.digest)
                    .map_err(anyhow::Error::msg)?;
                let decision = vero_application::evaluate_and_persist_gate(
                    &store,
                    vero_application::GateEvaluation {
                        review_id: &review,
                        reviewed_snapshot_id: &stored.snapshot_id,
                        current: &current,
                        reviewed_config_digest: &stored.effective_config_digest,
                        effective_config_digest: &config_digest,
                        config: &config,
                        findings: &stored.findings,
                        reviewer_outcomes: &stored.reviewer_outcomes,
                        analysis_complete: stored.analysis_complete,
                        verification_runs: &verification_runs,
                    },
                )
                .map_err(anyhow::Error::msg)?;
                let response = vero_application::GateCheckResult::from_decision(
                    review,
                    stored.snapshot_id,
                    current.digest,
                    decision,
                );
                match output {
                    Output::Json => {
                        serde_json::to_writer(std::io::stdout().lock(), &response)?;
                        println!();
                    }
                    Output::Text => {
                        println!("Gate status: {:?}", response.status);
                        for reason in &response.reasons {
                            println!("- {reason}");
                        }
                    }
                }
                Ok(response.exit_code())
            }
            GateCommand::History { review, output } => {
                let cwd = std::env::current_dir()?;
                let top = vero_git::repository_root(&cwd)
                    .map_err(anyhow::Error::msg)?
                    .to_string_lossy()
                    .to_string();
                let store =
                    ReviewStore::open(&std::path::Path::new(&top).join(".vero/vero.sqlite"))
                        .map_err(anyhow::Error::msg)?;
                let decisions = store
                    .gate_decisions_for_review(&review)
                    .map_err(anyhow::Error::msg)?;
                match output {
                    Output::Json => {
                        serde_json::to_writer(
                            std::io::stdout().lock(),
                            &serde_json::json!({"schema_version": 1, "decisions": decisions}),
                        )?;
                        println!();
                    }
                    Output::Text => {
                        for decision in &decisions {
                            println!(
                                "{} {:?} snapshot={} evidence={}",
                                decision.decision_id,
                                decision.status,
                                decision.snapshot_id,
                                decision.evidence_digest
                            );
                        }
                    }
                }
                Ok(0)
            }
        },
        Command::Verify {
            finding_id,
            profile,
            base,
            staged,
            working_tree,
            output,
        } => {
            let cwd = std::env::current_dir()?;
            let top = vero_git::repository_root(&cwd)
                .map_err(anyhow::Error::msg)?
                .to_string_lossy()
                .to_string();
            let mut config = load_repository_config(std::path::Path::new(&top))?;
            apply_protected_policy(std::path::Path::new(&top), &mut config)?;
            let base_oid = base
                .as_deref()
                .map(|base_ref| vero_git::merge_base(std::path::Path::new(&top), base_ref))
                .transpose()
                .map_err(usage_failure)?;
            if finding_id.is_some() && (base.is_some() || staged || working_tree) {
                return Err(usage_failure("finding-scoped verification uses the finding's reviewed snapshot; scope flags cannot be combined"));
            }
            let scope = if staged {
                "staged"
            } else if working_tree {
                "working_tree"
            } else {
                "base_and_worktree"
            };
            let snapshot = current_change_set(&top, base_oid.as_deref(), scope)?;
            let db_dir = std::path::Path::new(&top).join(".vero");
            std::fs::create_dir_all(&db_dir)?;
            let mut store =
                ReviewStore::open(&db_dir.join("vero.sqlite")).map_err(anyhow::Error::msg)?;
            let snapshot = if let Some(finding_id) = finding_id.as_deref() {
                let finding = store
                    .finding(finding_id)
                    .map_err(anyhow::Error::msg)?
                    .with_context(|| format!("finding {finding_id} was not found"))?;
                let occurrence = finding
                    .occurrences
                    .last()
                    .context("finding has no review occurrence")?;
                let payload = store
                    .get(&occurrence.review_id)
                    .map_err(anyhow::Error::msg)?
                    .context("finding review was not found")?;
                let review: serde_json::Value = serde_json::from_str(&payload)?;
                let change_set: vero_core::ChangeSet = serde_json::from_value(
                    review
                        .get("change_set")
                        .cloned()
                        .context("stored review has no change set")?,
                )?;
                let current = vero_application::capture_current_change_set(
                    std::path::Path::new(&top),
                    &change_set,
                )
                .map_err(anyhow::Error::msg)?;
                if current.digest != occurrence.snapshot_id {
                    anyhow::bail!("finding is stale because its source snapshot changed");
                }
                current
            } else {
                snapshot
            };
            let run = if let Some(finding_id) = finding_id.as_deref() {
                vero_application::run_finding_verification(
                    std::path::Path::new(&top),
                    &snapshot,
                    finding_id,
                    &profile,
                    &config,
                    &mut store,
                )
            } else {
                vero_application::run_verification(
                    std::path::Path::new(&top),
                    &snapshot,
                    &profile,
                    &config,
                    &mut store,
                )
            }
            .map_err(anyhow::Error::msg)?;
            match output {
                Output::Json => {
                    serde_json::to_writer(std::io::stdout().lock(), &run)?;
                    println!();
                }
                Output::Text => {
                    println!(
                        "Verification {}: {:?} ({})",
                        profile, run.status, run.run_id
                    );
                    print_verification_artifacts(&run);
                }
            }
            Ok(match run.status {
                VerificationStatus::Passed => 0,
                VerificationStatus::Failed => 1,
                VerificationStatus::TimedOut => 2,
            })
        }
        Command::Verification { command } => match command {
            VerificationCommand::Show { run_id, output } => {
                let cwd = std::env::current_dir()?;
                let top = vero_git::repository_root(&cwd)
                    .map_err(anyhow::Error::msg)?
                    .to_string_lossy()
                    .to_string();
                let db_path = std::path::Path::new(&top).join(".vero/vero.sqlite");
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
        },
        Command::Reviews { command } => {
            let cwd = std::env::current_dir()?;
            let top = vero_git::repository_root(&cwd)
                .map_err(anyhow::Error::msg)?
                .to_string_lossy()
                .to_string();
            let store = ReviewStore::open(&std::path::Path::new(&top).join(".vero/vero.sqlite"))
                .map_err(anyhow::Error::msg)?;
            match command {
                ReviewsCommand::List { output } => {
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
                    let payload = store
                        .get(&id)
                        .map_err(anyhow::Error::msg)?
                        .with_context(|| format!("review {id} was not found"))?;
                    let review = vero_application::deserialize_review_result(&payload)
                        .map_err(anyhow::Error::msg)?;
                    let review = serde_json::to_value(review)?;
                    match output {
                        Output::Json => {
                            serde_json::to_writer(std::io::stdout().lock(), &review)?;
                            println!();
                        }
                        Output::Text => {
                            println!("Review {}", review["review_id"].as_str().unwrap_or(&id));
                            println!("Snapshot: {}", review["snapshot_id"]);
                            println!("Status: {}", review["status"]);
                            println!(
                                "Findings: {}",
                                review["findings"].as_array().map_or(0, Vec::len)
                            );
                            println!("Gate: {}", review["gate"]["status"]);
                        }
                    }
                    Ok(0)
                }
                ReviewsCommand::Export { id, format } => {
                    let payload = store
                        .get(&id)
                        .map_err(anyhow::Error::msg)?
                        .with_context(|| format!("review {id} was not found"))?;
                    let review = vero_application::deserialize_review_result(&payload)
                        .map_err(anyhow::Error::msg)?;
                    let report = match format {
                        ReportFormat::Sarif => review_to_sarif(&review)?,
                    };
                    serde_json::to_writer(std::io::stdout().lock(), &report)?;
                    println!();
                    Ok(0)
                }
            }
        }
        Command::Waivers { command } => {
            let cwd = std::env::current_dir()?;
            let top = vero_git::repository_root(&cwd).map_err(anyhow::Error::msg)?;
            let database = top.join(".vero/vero.sqlite");
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
                    let reviewed = vero_application::deserialize_review_result(&payload)
                        .map_err(anyhow::Error::msg)?;
                    let finding = reviewed
                        .findings
                        .iter()
                        .find(|finding| finding.id == finding_id)
                        .with_context(|| {
                            format!("finding {finding_id} was not observed in review {review}")
                        })?;
                    if reason.trim().is_empty() || author.trim().is_empty() {
                        anyhow::bail!("--reason and --author must not be empty");
                    }
                    let created_at_unix = current_unix_time()?;
                    let expires_at_unix = created_at_unix
                        .checked_add(i64::from(expires_in_days) * 86_400)
                        .context("waiver expiry exceeds supported timestamp")?;
                    let fingerprint = finding.fingerprint.clone();
                    let id = format!(
                        "waiver_{}",
                        &vero_core::digest(&serde_json::to_vec(&(
                            fingerprint.as_str(),
                            reviewed.snapshot_id.as_str(),
                            reason.as_str(),
                            author.as_str(),
                            created_at_unix,
                            expires_at_unix,
                        ))?)[..20]
                    );
                    let waiver = vero_core::Waiver {
                        schema_version: 1,
                        id,
                        finding_fingerprint: fingerprint,
                        snapshot_id: reviewed.snapshot_id,
                        reason,
                        author,
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
                    let payload = store
                        .get(&review)
                        .map_err(anyhow::Error::msg)?
                        .with_context(|| format!("review {review} was not found"))?;
                    let reviewed = vero_application::deserialize_review_result(&payload)
                        .map_err(anyhow::Error::msg)?;
                    let waivers = store
                        .waivers_for_snapshot(&reviewed.snapshot_id)
                        .map_err(anyhow::Error::msg)?;
                    match output {
                        Output::Json => {
                            serde_json::to_writer(
                                std::io::stdout().lock(),
                                &serde_json::json!({"schema_version": 1, "waivers": waivers}),
                            )?;
                            println!();
                        }
                        Output::Text => {
                            for waiver in waivers {
                                println!(
                                    "{}  {}  expires {}  by {}  {}",
                                    waiver.id,
                                    waiver.finding_fingerprint,
                                    waiver.expires_at_unix,
                                    waiver.author,
                                    waiver.reason
                                );
                            }
                        }
                    }
                    Ok(0)
                }
            }
        }
        Command::Findings { command } => {
            let cwd = std::env::current_dir()?;
            let top = vero_git::repository_root(&cwd)
                .map_err(anyhow::Error::msg)?
                .to_string_lossy()
                .to_string();
            let db_path = std::path::Path::new(&top).join(".vero/vero.sqlite");
            let mut store = ReviewStore::open(&db_path).map_err(anyhow::Error::msg)?;
            match command {
                FindingsCommand::List {
                    severity,
                    status,
                    review,
                    output,
                } => {
                    let records = store
                        .list_findings(
                            severity.map(Into::into),
                            status.map(Into::into),
                            review.as_deref(),
                        )
                        .map_err(anyhow::Error::msg)?;
                    match output {
                        Output::Json => {
                            serde_json::to_writer(
                                std::io::stdout().lock(),
                                &serde_json::json!({"schema_version": 1, "findings": records}),
                            )?;
                            println!();
                        }
                        Output::Text => {
                            if records.is_empty() {
                                println!("No findings");
                            }
                            for record in records {
                                println!(
                                    "{}  {:?}  {:?}  {}",
                                    record.finding.id,
                                    record.finding.severity,
                                    record.status,
                                    record.finding.path.as_deref().unwrap_or("<no path>")
                                );
                            }
                        }
                    }
                    Ok(0)
                }
                FindingsCommand::Show { id, output } => {
                    let record = store
                        .finding(&id)
                        .map_err(anyhow::Error::msg)?
                        .with_context(|| format!("finding {id} was not found"))?;
                    match output {
                        Output::Json => {
                            println!(
                                "{}",
                                serde_json::to_string_pretty(
                                    &serde_json::json!({"schema_version": 1, "finding": record})
                                )?
                            );
                        }
                        Output::Text => {
                            println!(
                                "{} {:?} ({:?})",
                                record.finding.id, record.finding.severity, record.status
                            );
                            if let Some(path) = &record.finding.path {
                                println!("Location: {}:{}", path, record.finding.line.unwrap_or(0));
                            }
                            println!(
                                "Confidence: {}",
                                record
                                    .finding
                                    .confidence
                                    .map_or_else(|| "unknown".into(), |v| format!("{v}%"))
                            );
                            println!("{}", record.finding.rationale);
                            println!("Occurrences: {}", record.occurrence_count);
                            if let Some(reason) = &record.status_reason {
                                println!("Status reason: {reason}");
                            }
                        }
                    }
                    Ok(0)
                }
                FindingsCommand::SetStatus { id, status, reason } => {
                    store
                        .set_finding_status(&id, status.into(), &reason)
                        .map_err(anyhow::Error::msg)?;
                    println!("Updated finding {id}");
                    Ok(0)
                }
            }
        }
    }
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
    use super::sarif_uri_reference;

    #[test]
    fn sarif_uri_encodes_spaces_and_uri_delimiters() {
        assert_eq!(
            sarif_uri_reference("src/my file#1?.rs"),
            "src/my%20file%231%3F.rs"
        );
        assert_eq!(sarif_uri_reference("src/naïve.rs"), "src/na%C3%AFve.rs");
    }
}
