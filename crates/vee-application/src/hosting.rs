//! Read-only hosting operations and the documents they return: pull request
//! review issues and context, work item context, webhook receipt retention,
//! and the receipt of a review published to a pull request.
//!
//! Text fetched from a hosting provider (titles, bodies, comments) is
//! untrusted context; these documents carry it verbatim and never make it
//! gate evidence.

use crate::failure::configuration_failure;
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
