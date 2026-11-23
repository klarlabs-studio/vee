//! Read-only hosting operations and the documents they return: pull request
//! review issues and context, work item context, webhook receipt retention,
//! and the receipt of a review published to a pull request.
//!
//! Text fetched from a hosting provider (titles, bodies, comments) is
//! untrusted context; these documents carry it verbatim and never make it
//! gate evidence.

use crate::failure::{configuration_failure, usage_failure};
use crate::operations::Workspace;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

/// Hosting settings named on the command line for one hosting command; unset
/// values fall back to the repository's `hosting` configuration, then to the
/// command's own defaults.
#[derive(Clone, Debug, Default)]
pub struct HostingFlags {
    pub provider: Option<String>,
    pub host: Option<String>,
    pub api_base: Option<String>,
    pub token_env: Option<String>,
    pub username: Option<String>,
}

/// The repository's offline flag and `hosting` configuration; defaults when the
/// checkout has no `.vee.yaml`.
pub fn load_hosting_config(root: &Path) -> Result<(bool, vee_core::HostingConfig)> {
    if !root.join(".vee.yaml").exists() {
        return Ok((false, vee_core::HostingConfig::default()));
    }
    let config = crate::load_repository_config(root).map_err(configuration_failure)?;
    Ok((config.offline, config.hosting))
}

/// The command-line value, else the configured one, else `fallback`.
pub fn resolve_hosting_setting(
    command_line: Option<String>,
    repository: Option<String>,
    fallback: &str,
) -> String {
    command_line
        .or(repository)
        .unwrap_or_else(|| fallback.to_owned())
}

fn read_token(token_env: &str) -> Result<String> {
    std::env::var(token_env)
        .with_context(|| format!("required credential environment variable {token_env} is not set"))
}

/// A pull request context adapter for `provider_id`. `kind` names the provider
/// role in the error for an unsupported provider (e.g. "hosting provider").
pub fn pull_request_context_provider(
    provider_id: &str,
    api_base: &str,
    token: String,
    username: String,
    kind: &str,
) -> Result<Box<dyn vee_hosting::PullRequestContextProvider>> {
    Ok(match provider_id {
        "github" => Box::new(
            vee_hosting::github::GitHubAdapter::new(
                vee_hosting::github::GitHubConfig::new(api_base, token, String::new())
                    .map_err(configuration_failure)?,
            )
            .map_err(configuration_failure)?,
        ),
        "gitlab" => Box::new(
            vee_hosting::gitlab::GitLabAdapter::new(
                vee_hosting::gitlab::GitLabConfig::new(api_base, token)
                    .map_err(configuration_failure)?,
            )
            .map_err(configuration_failure)?,
        ),
        "bitbucket" => Box::new(
            vee_hosting::bitbucket::BitbucketAdapter::new(
                vee_hosting::bitbucket::BitbucketConfig::new(api_base, token)
                    .map_err(configuration_failure)?,
            )
            .map_err(configuration_failure)?,
        ),
        "azure-devops" => Box::new(
            vee_hosting::azure_devops::AzureDevOpsAdapter::new(
                vee_hosting::azure_devops::AzureDevOpsConfig::new(api_base, token)
                    .map_err(configuration_failure)?,
            )
            .map_err(configuration_failure)?,
        ),
        "gerrit" => {
            let mut config = vee_hosting::gerrit::GerritConfig::new(api_base, token)
                .map_err(configuration_failure)?;
            if !username.is_empty() {
                config = config.with_username(username);
            }
            Box::new(
                vee_hosting::gerrit::GerritAdapter::new(config).map_err(configuration_failure)?,
            )
        }
        _ => {
            return Err(configuration_failure(format!(
                "unsupported {kind} `{provider_id}`"
            )))
        }
    })
}

fn review_issues_provider(
    provider_id: &str,
    api_base: &str,
    token: String,
    username: String,
) -> Result<Box<dyn vee_hosting::PullRequestReviewIssuesProvider>> {
    Ok(match provider_id {
        "github" => Box::new(
            vee_hosting::github::GitHubAdapter::new(
                vee_hosting::github::GitHubConfig::new(api_base, token, String::new())
                    .map_err(configuration_failure)?,
            )
            .map_err(configuration_failure)?,
        ),
        "gitlab" => Box::new(
            vee_hosting::gitlab::GitLabAdapter::new(
                vee_hosting::gitlab::GitLabConfig::new(api_base, token)
                    .map_err(configuration_failure)?,
            )
            .map_err(configuration_failure)?,
        ),
        "bitbucket" => Box::new(
            vee_hosting::bitbucket::BitbucketAdapter::new(
                vee_hosting::bitbucket::BitbucketConfig::new(api_base, token)
                    .map_err(configuration_failure)?,
            )
            .map_err(configuration_failure)?,
        ),
        "azure-devops" => Box::new(
            vee_hosting::azure_devops::AzureDevOpsAdapter::new(
                vee_hosting::azure_devops::AzureDevOpsConfig::new(api_base, token)
                    .map_err(configuration_failure)?,
            )
            .map_err(configuration_failure)?,
        ),
        "gerrit" => {
            let mut config = vee_hosting::gerrit::GerritConfig::new(api_base, token)
                .map_err(configuration_failure)?;
            if !username.is_empty() {
                config = config.with_username(username);
            }
            Box::new(
                vee_hosting::gerrit::GerritAdapter::new(config).map_err(configuration_failure)?,
            )
        }
        _ => {
            return Err(configuration_failure(format!(
                "unsupported hosting provider `{provider_id}`"
            )))
        }
    })
}

/// A pull request on a hosting provider, named by repository and number.
#[derive(Clone, Debug)]
pub struct PullRequestTarget {
    pub repository: String,
    pub number: u64,
}

/// Untrusted provider review discussions for one pull request, and the
/// digest of the local archive they were stored under when archiving was
/// requested. Never gate eligible.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PullRequestIssues {
    #[serde(flatten)]
    pub report: vee_hosting::PullRequestReviewIssues,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive_digest: Option<String>,
}

/// Fetch the review discussions of a pull request, archiving them as
/// untrusted imported history under `config_root` when `archive` is set.
pub fn pull_request_issues(
    config_root: &Path,
    flags: HostingFlags,
    target: PullRequestTarget,
    archive: bool,
) -> Result<PullRequestIssues> {
    let (offline, hosting) = load_hosting_config(config_root)?;
    if offline {
        return Err(configuration_failure(
            "offline mode prevents fetching pull request review issues",
        ));
    }
    let provider_id = resolve_hosting_setting(flags.provider, hosting.provider, "github");
    if !matches!(
        provider_id.as_str(),
        "github" | "gitlab" | "bitbucket" | "azure-devops" | "gerrit"
    ) {
        return Err(configuration_failure(format!(
            "unsupported hosting provider `{provider_id}`"
        )));
    }
    let host = resolve_hosting_setting(flags.host, hosting.host, "github.com");
    let api_base = resolve_hosting_setting(flags.api_base, hosting.api_base, "");
    let token_env = resolve_hosting_setting(flags.token_env, hosting.token_env, "GH_TOKEN");
    let username = resolve_hosting_setting(flags.username, hosting.username, "");
    let token_env = crate::work_items::effective_work_item_token_env(&provider_id, &token_env);
    let token = read_token(token_env)?;
    let host = crate::work_items::effective_work_item_host(&provider_id, &host)?;
    let api_base = crate::work_items::work_item_api_base(&provider_id, &host, &api_base)?;
    let reference = vee_hosting::PullRequestRef {
        repository: vee_hosting::RepositoryRef {
            host,
            full_name: target.repository,
        },
        number: target.number,
    };
    reference.validate().map_err(configuration_failure)?;
    if provider_id != "gerrit" && !username.is_empty() {
        return Err(configuration_failure(
            "--username is only supported with the Gerrit provider",
        ));
    }
    let adapter = review_issues_provider(&provider_id, &api_base, token, username)?;
    let report = adapter
        .list_pull_request_review_issues(&reference)
        .map_err(anyhow::Error::msg)?;
    let archive_digest = if archive {
        anyhow::ensure!(
            !report.gate_eligible,
            "provider review discussions must remain non-gating"
        );
        let bytes = serde_json::to_vec(&report)?;
        Some(crate::imported_history::store_imported_history(
            config_root,
            &bytes,
        )?)
    } else {
        None
    };
    Ok(PullRequestIssues {
        report,
        archive_digest,
    })
}

/// Fetch a pull request's metadata and changed files as untrusted context.
pub fn pull_request_context(
    config_root: &Path,
    flags: HostingFlags,
    target: PullRequestTarget,
) -> Result<vee_hosting::PullRequestContextReport> {
    let (offline, hosting) = load_hosting_config(config_root)?;
    if offline {
        return Err(configuration_failure(
            "offline mode prevents fetching pull request context",
        ));
    }
    let provider_id = resolve_hosting_setting(flags.provider, hosting.provider, "azure-devops");
    let host = resolve_hosting_setting(flags.host, hosting.host, "github.com");
    let api_base = resolve_hosting_setting(flags.api_base, hosting.api_base, "");
    let token_env =
        resolve_hosting_setting(flags.token_env, hosting.token_env, "AZURE_DEVOPS_EXT_PAT");
    let username = resolve_hosting_setting(flags.username, hosting.username, "");
    let token_env = match provider_id.as_str() {
        "github" if token_env == "AZURE_DEVOPS_EXT_PAT" => "GH_TOKEN",
        "gitlab" if token_env == "AZURE_DEVOPS_EXT_PAT" => "GL_TOKEN",
        "bitbucket" if token_env == "AZURE_DEVOPS_EXT_PAT" => "BB_TOKEN",
        "gerrit" if token_env == "AZURE_DEVOPS_EXT_PAT" => "GERRIT_TOKEN",
        _ => &token_env,
    };
    let token = read_token(token_env)?;
    let host = crate::work_items::effective_work_item_host(&provider_id, &host)?;
    let api_base = crate::work_items::work_item_api_base(&provider_id, &host, &api_base)?;
    let reference = vee_hosting::PullRequestRef {
        repository: vee_hosting::RepositoryRef {
            host,
            full_name: target.repository,
        },
        number: target.number,
    };
    reference.validate().map_err(configuration_failure)?;
    let provider = pull_request_context_provider(
        &provider_id,
        &api_base,
        token,
        username,
        "pull request provider",
    )?;
    let snapshot = provider
        .get_pull_request_context(&reference)
        .map_err(anyhow::Error::msg)?;
    let changed_files = provider
        .list_pull_request_context_files(&reference, &snapshot.revision)
        .map_err(anyhow::Error::msg)?;
    let limitations = match provider_id.as_str() {
        "azure-devops" => vec!["Azure DevOps diff metadata does not include line-level patches; file records are context only, not line evidence.".into()],
        "bitbucket" => vec!["Bitbucket unified diffs are bounded to 5 MiB; quoted or unsupported paths may lack line-level patch evidence.".into()],
        _ => vec![],
    };
    Ok(vee_hosting::PullRequestContextReport {
        schema_version: 1,
        provider: provider_id,
        snapshot,
        changed_files,
        limitations,
    })
}

/// Fetch an issue (work item) as untrusted, source-attributed context.
pub fn issue_context(
    config_root: &Path,
    flags: HostingFlags,
    repository: String,
    number: u64,
) -> Result<vee_hosting::WorkItemSnapshot> {
    let (offline, hosting) = load_hosting_config(config_root)?;
    if offline {
        return Err(configuration_failure(
            "offline mode prevents fetching work item context",
        ));
    }
    let provider = resolve_hosting_setting(flags.provider, hosting.provider, "github");
    let host = resolve_hosting_setting(flags.host, hosting.host, "github.com");
    let api_base = resolve_hosting_setting(flags.api_base, hosting.api_base, "");
    let token_env = resolve_hosting_setting(flags.token_env, hosting.token_env, "");
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
    let token = read_token(token_env)?;
    let host = crate::work_items::effective_work_item_host(&provider, &host)?;
    let api_base = crate::work_items::work_item_api_base(&provider, &host, &api_base)?;
    let reference = vee_hosting::WorkItemRef {
        repository: vee_hosting::RepositoryRef {
            host,
            full_name: repository,
        },
        number,
    };
    reference.validate().map_err(configuration_failure)?;
    crate::work_items::get_work_item(&provider, &api_base, token, &reference)
}

pub const WEBHOOK_RETENTION_SCHEMA_VERSION: u32 = 1;

/// How many completed webhook receipts are past the retention period, and
/// how many were deleted (none on a dry run).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebhookRetention {
    pub schema_version: u32,
    pub retention_days: u32,
    pub eligible_receipts: u64,
    pub deleted_receipts: u64,
    pub dry_run: bool,
}

/// Count, and with `apply` delete, completed webhook receipts older than
/// `older_than_days`. In-flight and retryable deliveries are never eligible.
pub fn prune_webhook_deliveries(
    workspace: &Workspace,
    older_than_days: u32,
    apply: bool,
) -> Result<WebhookRetention> {
    let mut store = workspace.store()?;
    let now = crate::current_unix_time().map_err(anyhow::Error::msg)?;
    let retention_seconds = i64::from(older_than_days)
        .checked_mul(86_400)
        .context("webhook retention period exceeds supported timestamp")?;
    let cutoff = now
        .checked_sub(retention_seconds)
        .context("webhook retention cutoff is outside the supported range")?;
    let eligible = store
        .prune_processed_webhook_deliveries_before(cutoff, apply)
        .map_err(anyhow::Error::msg)?;
    Ok(WebhookRetention {
        schema_version: WEBHOOK_RETENTION_SCHEMA_VERSION,
        retention_days: older_than_days,
        eligible_receipts: eligible,
        deleted_receipts: if apply { eligible } else { 0 },
        dry_run: !apply,
    })
}

pub const REVIEW_PUBLICATION_SCHEMA_VERSION: u32 = 1;

/// Where a review was published. Shown to the reader, but not part of the
/// published JSON document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicationDestination {
    pub provider: String,
    pub pull_request: vee_hosting::PullRequestRef,
}

/// The receipt of a review published to a pull request: the provider's
/// check (or status) and one thread per published finding fingerprint.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReviewPublication {
    pub schema_version: u32,
    pub review_id: String,
    pub snapshot_id: String,
    pub provider_check_id: String,
    /// Vee finding fingerprint to provider-native thread ID.
    pub thread_ids: BTreeMap<String, String>,
    /// The provider's ID of the separate "Vee approval" check, when the
    /// approval verdict was published too.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_check_id: Option<String>,
    /// The pull request revision after publication.
    pub revision: String,
    #[serde(skip)]
    pub destination: Option<PublicationDestination>,
}

/// The provider state of each linked pull request, keyed by repository ID,
/// read through each linked checkout's own hosting configuration.
pub fn refresh_linked_pull_requests(
    local: &crate::repository_map::RepositoryMap,
    links: &BTreeMap<String, Vec<vee_hosting::PullRequestRef>>,
) -> Result<BTreeMap<String, Vec<crate::repository_map::RemotePullRequestState>>> {
    let mut remote_states = BTreeMap::new();
    for entry in &local.repositories {
        let Some(references) = links.get(&entry.id) else {
            continue;
        };
        let root = Path::new(&entry.root);
        let local_head_oid =
            crate::repository_map::repository_head_oid(root).map_err(anyhow::Error::msg)?;
        let (offline, hosting) = load_hosting_config(root)?;
        if offline {
            return Err(configuration_failure(format!(
                "offline mode prevents refreshing linked pull requests in {}",
                root.display()
            )));
        }
        let provider_id = hosting.provider.clone().unwrap_or_else(|| "github".into());
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
        let token = read_token(&token_env)?;
        let host = crate::work_items::effective_work_item_host(&provider_id, &host)?;
        let api_base = crate::work_items::work_item_api_base(&provider_id, &host, &api_base)?;
        let username = hosting.username.unwrap_or_default();
        let adapter = pull_request_context_provider(
            &provider_id,
            &api_base,
            token,
            username,
            "hosting provider",
        )?;
        let mut states = Vec::new();
        for reference in references {
            let snapshot = adapter
                .get_pull_request_context(reference)
                .map_err(anyhow::Error::msg)?;
            states.push(crate::repository_map::RemotePullRequestState {
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
    Ok(remote_states)
}

/// Hosting settings for `vee hosting publish`: the shared flags plus the
/// webhook secret variable and the actor login some adapters need.
#[derive(Clone, Debug, Default)]
pub struct PublishFlags {
    pub hosting: HostingFlags,
    pub webhook_secret_env: Option<String>,
    pub actor_login: Option<String>,
}

/// One saved review to publish to one pull request.
pub struct PublishRequest<'a> {
    pub review_id: &'a str,
    pub repository: &'a str,
    pub number: u64,
    pub flags: PublishFlags,
    /// Also publish the approval verdict as a separate "Vee approval" check.
    pub approval: bool,
}

/// Settings resolved from flags, the repository's `hosting` block and defaults.
struct PublishSettings {
    provider_id: String,
    host: String,
    api_base: String,
    token: String,
    username: String,
    webhook_secret_env: String,
    actor_login: String,
}

const DEFAULT_WEBHOOK_SECRET_ENV: &str = "VEE_GITHUB_WEBHOOK_SECRET";

/// The default credential variable of each provider.
fn default_publish_token_env(provider_id: &str) -> &'static str {
    match provider_id {
        "gitlab" => "GL_TOKEN",
        "bitbucket" => "BB_TOKEN",
        "azure-devops" => "AZURE_DEVOPS_EXT_PAT",
        "gerrit" => "GERRIT_TOKEN",
        _ => "GH_TOKEN",
    }
}

/// The webhook secret, read from the provider's variable when the default
/// GitHub variable was not overridden.
fn webhook_secret(provider_id: &str, configured_env: &str) -> String {
    let env = match (configured_env, provider_id) {
        (DEFAULT_WEBHOOK_SECRET_ENV, "bitbucket") => "VEE_BITBUCKET_WEBHOOK_SECRET",
        (DEFAULT_WEBHOOK_SECRET_ENV, "gitlab") => "VEE_GITLAB_WEBHOOK_SECRET",
        (env, _) => env,
    };
    std::env::var(env).unwrap_or_default()
}

/// Re-evaluate a saved review's gate and publish it to a pull request: one
/// check with the decision, a thread per finding on an added line of the pull
/// request diff, and resolutions for previously published findings that are
/// resolved since. The review must be complete and capture exactly the pull
/// request's committed base and head.
pub fn publish_review(
    workspace: &Workspace,
    request: PublishRequest<'_>,
) -> Result<ReviewPublication> {
    let root = workspace.root();
    let (offline, hosting) = load_hosting_config(root)?;
    anyhow::ensure!(
        !offline,
        "offline mode prevents publishing to a Git hosting provider"
    );
    let flags = request.flags;
    let provider_id = resolve_hosting_setting(flags.hosting.provider, hosting.provider, "github");
    let host = resolve_hosting_setting(flags.hosting.host, hosting.host, "github.com");
    let api_base = resolve_hosting_setting(flags.hosting.api_base, hosting.api_base, "");
    let token_env = resolve_hosting_setting(flags.hosting.token_env, hosting.token_env, "");
    let username = resolve_hosting_setting(flags.hosting.username, hosting.username, "");
    let webhook_secret_env = resolve_hosting_setting(
        flags.webhook_secret_env,
        hosting.webhook_secret_env,
        DEFAULT_WEBHOOK_SECRET_ENV,
    );
    let actor_login = resolve_hosting_setting(flags.actor_login, hosting.actor_login, "");

    anyhow::ensure!(
        !(request.approval && provider_id == "gerrit"),
        usage_failure(
            "Gerrit has no separate check to carry an approval verdict; publish without --approval"
        )
    );
    // The same re-evaluation as `vee gate check`, so a published decision is the
    // one the gate would make now.
    let reevaluated = crate::operations::reevaluate_gate(workspace, request.review_id, None)?;
    let mut reviewed = reevaluated.review;
    reviewed.gate = reevaluated.decision;
    ensure_publishable(root, &reviewed)?;
    // Evaluated before anything is written, so a failure publishes nothing.
    let approval = if request.approval {
        Some(crate::operations::approval_eligibility(
            workspace,
            request.review_id,
        )?)
    } else {
        None
    };

    let token_env = if token_env.is_empty() {
        default_publish_token_env(&provider_id).to_owned()
    } else {
        token_env
    };
    let token = read_token(&token_env)?;
    let host = crate::work_items::effective_work_item_host(&provider_id, &host)?;
    let api_base = crate::work_items::work_item_api_base(&provider_id, &host, &api_base)?;
    let settings = PublishSettings {
        provider_id,
        host,
        api_base,
        token,
        username,
        webhook_secret_env,
        actor_login,
    };
    let pull_request = vee_hosting::PullRequestRef {
        repository: vee_hosting::RepositoryRef {
            host: settings.host.clone(),
            full_name: request.repository.to_owned(),
        },
        number: request.number,
    };
    pull_request
        .validate()
        .map_err(|error| usage_failure(format!("invalid pull request: {error}")))?;
    let mut store = workspace.store()?;
    let (provider_check_id, thread_ids, revision) = if settings.provider_id == "azure-devops" {
        publish_to_azure_devops(root, &mut *store, &settings, &pull_request, &reviewed)?
    } else {
        publish_to_provider(
            root,
            &mut *store,
            settings_provider(&settings)?,
            &settings,
            &pull_request,
            &reviewed,
        )?
    };
    let approval_check_id = approval
        .map(|eligibility| {
            let check = crate::publication::approval_check_run(
                &eligibility,
                &pull_request,
                &reviewed.snapshot_id,
            );
            publish_approval_check(&settings, &pull_request, &revision, check)
        })
        .transpose()?;
    Ok(ReviewPublication {
        schema_version: REVIEW_PUBLICATION_SCHEMA_VERSION,
        review_id: reviewed.review_id,
        snapshot_id: reviewed.snapshot_id,
        provider_check_id,
        thread_ids,
        approval_check_id,
        revision,
        destination: Some(PublicationDestination {
            provider: settings.provider_id,
            pull_request,
        }),
    })
}

/// A review is publishable when it is complete, its snapshot digest is intact,
/// and it captures committed content: never a staged-only or working-tree-only
/// snapshot, and a base-and-worktree snapshot only of a clean checkout whose
/// content equals the commits.
fn ensure_publishable(root: &Path, reviewed: &crate::ReviewResult) -> Result<()> {
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
            crate::attestation::committed_snapshot_matches_review(root, &reviewed.change_set)
                .map_err(anyhow::Error::msg)?,
            "cannot publish a review whose captured worktree content differs from the committed PR diff"
        );
        let status = std::process::Command::new("git")
            .args(["status", "--porcelain", "--untracked-files=all"])
            .current_dir(root)
            .output()?;
        anyhow::ensure!(
            status.status.success(),
            "could not verify the local worktree state"
        );
        anyhow::ensure!(
            status.stdout.is_empty(),
            "cannot publish a snapshot while the local worktree or index has uncommitted changes"
        );
    }
    Ok(())
}

/// The remote pull request must be open and at exactly the reviewed commits.
/// Returns the reviewed base and head, captured from local Git, which are the
/// values that reach `git` as arguments.
fn ensure_reviewed_commits(
    reviewed: &crate::ReviewResult,
    state: vee_hosting::PullRequestState,
    base_oid: &str,
    head_oid: &str,
) -> Result<(String, String)> {
    anyhow::ensure!(
        state == vee_hosting::PullRequestState::Open,
        "pull request is not open"
    );
    anyhow::ensure!(
        reviewed.change_set.head_oid.as_deref() == Some(head_oid),
        "reviewed head does not match the current pull request head; rerun Vee against the PR head"
    );
    anyhow::ensure!(
        reviewed.change_set.base_oid.as_deref() == Some(base_oid),
        "reviewed base does not match the current pull request base; rerun Vee against the current PR diff"
    );
    Ok((
        reviewed.change_set.base_oid.clone().unwrap_or_default(),
        reviewed.change_set.head_oid.clone().unwrap_or_default(),
    ))
}

/// Whether `line` of `path` is added in the local `base..head` Git diff.
fn locally_added_line(
    root: &Path,
    (base, head): (&str, &str),
    path: &str,
    line: u32,
    failure: &str,
) -> Result<bool> {
    let diff = std::process::Command::new("git")
        .args([
            "--literal-pathspecs",
            "diff",
            "--no-ext-diff",
            "--unified=0",
        ])
        .arg(base)
        .arg(head)
        .arg("--")
        .arg(path)
        .current_dir(root)
        .output()?;
    anyhow::ensure!(diff.status.success(), "{failure}");
    Ok(crate::publication::diff_contains_added_line(
        Some(std::str::from_utf8(&diff.stdout)?),
        line,
    ))
}

/// A relative path without parent, root or prefix components.
fn is_confined_relative_path(path: &str) -> bool {
    let path = Path::new(path);
    !path.is_absolute()
        && !path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        })
}

type PublicationReceipt = (String, BTreeMap<String, String>, String);

/// Azure DevOps publishes threads and the status separately. Its diff metadata
/// has no line patches, so finding locations are checked against local Git.
fn publish_to_azure_devops(
    root: &Path,
    store: &mut dyn vee_core::ports::Repositories,
    settings: &PublishSettings,
    pull_request: &vee_hosting::PullRequestRef,
    reviewed: &crate::ReviewResult,
) -> Result<PublicationReceipt> {
    let provider = azure_devops_adapter(settings)?;
    let remote =
        vee_hosting::PullRequestContextProvider::get_pull_request_context(&provider, pull_request)
            .map_err(anyhow::Error::msg)?;
    let (base, head) =
        ensure_reviewed_commits(reviewed, remote.state, &remote.base_oid, &remote.head_oid)?;
    let mut threads = Vec::new();
    for finding in &reviewed.findings {
        let Some((path, line)) = crate::publication::thread_location(finding) else {
            continue;
        };
        if !is_confined_relative_path(path)
            || !locally_added_line(
                root,
                (&base, &head),
                path,
                line,
                "could not verify Azure DevOps finding locations against the local PR diff",
            )?
        {
            continue;
        }
        threads.push(crate::publication::finding_thread(
            finding,
            path,
            line,
            pull_request,
            &reviewed.snapshot_id,
            &reviewed.review_id,
        ));
    }
    let check = crate::publication::gate_check_run(
        &reviewed.gate,
        pull_request,
        reviewed.review_id.clone(),
        &reviewed.snapshot_id,
    );
    let (check_id, thread_ids) = crate::publication::publish_with_thread_ledger(
        store,
        &settings.provider_id,
        pull_request,
        &published_review(reviewed),
        threads,
        |threads| {
            let thread_ids = if threads.is_empty() {
                BTreeMap::new()
            } else {
                provider
                    .publish_threads(pull_request, &remote.revision, &threads)
                    .map_err(|error| error.to_string())?
            };
            let check_id = provider
                .publish_check(pull_request, &remote.revision, &check)
                .map_err(|error| error.to_string())?;
            Ok((check_id, thread_ids))
        },
    )
    .map_err(anyhow::Error::msg)?;
    Ok((check_id, thread_ids, remote.revision))
}

fn azure_devops_adapter(
    settings: &PublishSettings,
) -> Result<vee_hosting::azure_devops::AzureDevOpsAdapter> {
    vee_hosting::azure_devops::AzureDevOpsAdapter::new(
        vee_hosting::azure_devops::AzureDevOpsConfig::new(
            &settings.api_base,
            settings.token.clone(),
        )
        .map_err(anyhow::Error::msg)?,
    )
    .map_err(anyhow::Error::msg)
}

/// Publish the approval verdict as its own check at the revision the gate
/// was just published to. It carries no threads; omitting threads never
/// resolves the ones the gate publication owns.
fn publish_approval_check(
    settings: &PublishSettings,
    pull_request: &vee_hosting::PullRequestRef,
    revision: &str,
    check: vee_hosting::CheckRun,
) -> Result<String> {
    if settings.provider_id == "azure-devops" {
        return azure_devops_adapter(settings)?
            .publish_check(pull_request, revision, &check)
            .map_err(anyhow::Error::msg);
    }
    let receipt = settings_provider(settings)?
        .publish_review(vee_hosting::ReviewPublication {
            pull_request: pull_request.clone(),
            expected_revision: revision.to_owned(),
            check,
            threads: Vec::new(),
        })
        .map_err(anyhow::Error::msg)?;
    Ok(receipt.provider_check_id)
}

/// The adapter for a provider that publishes a check and its threads together.
fn settings_provider(
    settings: &PublishSettings,
) -> Result<Box<dyn vee_hosting::GitHostingProvider>> {
    let webhook_secret = webhook_secret(&settings.provider_id, &settings.webhook_secret_env);
    let token = settings.token.clone();
    Ok(match settings.provider_id.as_str() {
        "github" => Box::new(
            vee_hosting::github::GitHubAdapter::new(
                vee_hosting::github::GitHubConfig::new(&settings.api_base, token, webhook_secret)
                    .map_err(anyhow::Error::msg)?
                    .with_actor_login(settings.actor_login.clone()),
            )
            .map_err(anyhow::Error::msg)?,
        ),
        "gitlab" => Box::new(
            vee_hosting::gitlab::GitLabAdapter::new(
                vee_hosting::gitlab::GitLabConfig::new(&settings.api_base, token)
                    .map_err(anyhow::Error::msg)?
                    .with_webhook_secret(webhook_secret)
                    .with_actor_login(settings.actor_login.clone()),
            )
            .map_err(anyhow::Error::msg)?,
        ),
        "bitbucket" => Box::new(
            vee_hosting::bitbucket::BitbucketAdapter::new(
                vee_hosting::bitbucket::BitbucketConfig::new(&settings.api_base, token)
                    .map_err(anyhow::Error::msg)?
                    .with_webhook_secret(webhook_secret),
            )
            .map_err(anyhow::Error::msg)?,
        ),
        "gerrit" => {
            let mut config = vee_hosting::gerrit::GerritConfig::new(&settings.api_base, token)
                .map_err(anyhow::Error::msg)?;
            if !settings.username.is_empty() {
                config = config.with_username(settings.username.clone());
            }
            Box::new(vee_hosting::gerrit::GerritAdapter::new(config).map_err(anyhow::Error::msg)?)
        }
        other => {
            return Err(configuration_failure(format!(
                "unsupported hosting provider `{other}`"
            )))
        }
    })
}

/// Publish through a provider's combined review publication. Inline threads
/// go only on lines the pull request adds: Gerrit's are checked against local
/// Git, the others against the provider's patches.
fn publish_to_provider(
    root: &Path,
    store: &mut dyn vee_core::ports::Repositories,
    provider: Box<dyn vee_hosting::GitHostingProvider>,
    settings: &PublishSettings,
    pull_request: &vee_hosting::PullRequestRef,
    reviewed: &crate::ReviewResult,
) -> Result<PublicationReceipt> {
    let remote = provider
        .get_pull_request(pull_request)
        .map_err(anyhow::Error::msg)?;
    let (base, head) =
        ensure_reviewed_commits(reviewed, remote.state, &remote.base_oid, &remote.head_oid)?;
    let changed = provider
        .list_changed_files(pull_request, &remote.revision)
        .map_err(anyhow::Error::msg)?;
    // A finding gets an inline thread only on a line the pull request adds;
    // the rest, including findings outside the diff, are carried by the gate
    // check, as for Azure DevOps and the webhook.
    let threads = if settings.provider_id == "gerrit" {
        let changed_paths: std::collections::BTreeSet<_> =
            changed.iter().map(|file| file.path.as_str()).collect();
        let mut threads = Vec::new();
        for finding in &reviewed.findings {
            let Some((path, line)) = crate::publication::thread_location(finding) else {
                continue;
            };
            if changed_paths.contains(path)
                && locally_added_line(
                    root,
                    (&base, &head),
                    path,
                    line,
                    "could not verify Gerrit finding locations against the local base-to-head Git diff",
                )?
            {
                threads.push(crate::publication::finding_thread(
                    finding,
                    path,
                    line,
                    pull_request,
                    &reviewed.snapshot_id,
                    &reviewed.review_id,
                ));
            }
        }
        threads
    } else {
        crate::publication::build_hosting_threads(
            &reviewed.findings,
            pull_request,
            &changed,
            &reviewed.snapshot_id,
            &reviewed.review_id,
        )
    };
    let check = crate::publication::gate_check_run(
        &reviewed.gate,
        pull_request,
        reviewed.review_id.clone(),
        &reviewed.snapshot_id,
    );
    let receipt = crate::publication::publish_with_thread_ledger(
        store,
        &settings.provider_id,
        pull_request,
        &published_review(reviewed),
        threads,
        |threads| {
            provider
                .publish_review(vee_hosting::ReviewPublication {
                    pull_request: pull_request.clone(),
                    expected_revision: remote.revision.clone(),
                    check,
                    threads,
                })
                .map_err(|error| error.to_string())
        },
    )
    .map_err(anyhow::Error::msg)?;
    Ok((
        receipt.provider_check_id,
        receipt.thread_ids,
        receipt.resulting_revision,
    ))
}

fn published_review(reviewed: &crate::ReviewResult) -> crate::publication::PublishedReview<'_> {
    crate::publication::PublishedReview {
        review_id: &reviewed.review_id,
        snapshot_id: &reviewed.snapshot_id,
        findings: &reviewed.findings,
    }
}
