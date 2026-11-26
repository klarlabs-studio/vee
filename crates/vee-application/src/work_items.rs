//! Fetching external work items (issues) from the configured hosting provider.

use crate::failure::{configuration_failure, usage_failure};
use anyhow::Context;

/// Hosting settings a caller chose for one command; unset values fall back to
/// the repository's `hosting` configuration, then to GitHub defaults.
#[derive(Clone, Debug, Default)]
pub struct HostingOverrides {
    pub provider: Option<String>,
    pub host: Option<String>,
    pub api_base: Option<String>,
    pub token_env: Option<String>,
}

/// Resolved hosting settings. `token_env` is already the provider-specific
/// default when the configured value is the generic `GH_TOKEN`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostingSettings {
    pub provider: String,
    pub host: String,
    pub api_base: String,
    pub token_env: String,
    /// Whether the host or API base came from the caller rather than the
    /// repository configuration; see `ensure_credential_destination`.
    pub named_by_user: bool,
}

pub fn resolve_hosting(
    overrides: HostingOverrides,
    configured: &vee_core::HostingConfig,
) -> HostingSettings {
    let pick = |chosen: Option<String>, configured: &Option<String>, fallback: &str| {
        chosen
            .or_else(|| configured.clone())
            .unwrap_or_else(|| fallback.to_owned())
    };
    let provider = pick(overrides.provider, &configured.provider, "github");
    let token_env = pick(overrides.token_env, &configured.token_env, "GH_TOKEN");
    let named_by_user = overrides.host.is_some() || overrides.api_base.is_some();
    HostingSettings {
        named_by_user,
        host: pick(overrides.host, &configured.host, "github.com"),
        api_base: pick(overrides.api_base, &configured.api_base, ""),
        token_env: effective_work_item_token_env(&provider, &token_env).to_owned(),
        provider,
    }
}

pub fn effective_work_item_host(provider: &str, host: &str) -> anyhow::Result<String> {
    match provider {
        "github" if host == "github.com" => Ok("github.com".into()),
        "gitlab" if host == "github.com" => Ok("gitlab.com".into()),
        "azure-devops" if host == "github.com" => Ok("dev.azure.com".into()),
        "bitbucket" if host == "github.com" => Ok("bitbucket.org".into()),
        "gerrit" if host == "github.com" => {
            Err(configuration_failure("Gerrit requires an explicit --host"))
        }
        "github" | "gitlab" | "azure-devops" | "bitbucket" | "gerrit" => Ok(host.into()),
        _ => Err(configuration_failure(format!(
            "unsupported work item provider `{provider}`"
        ))),
    }
}

pub fn work_item_api_base(provider: &str, host: &str, configured: &str) -> anyhow::Result<String> {
    if !configured.trim().is_empty() {
        return Ok(configured.to_owned());
    }
    match provider {
        "github" if host == "github.com" => Ok("https://api.github.com/".into()),
        "github" => Ok(format!("https://{host}/api/v3/")),
        "gitlab" => Ok(format!("https://{host}/api/v4/")),
        "azure-devops" => Ok(format!("https://{host}/")),
        "bitbucket" => Ok("https://api.bitbucket.org/2.0/".into()),
        "gerrit" => Ok(format!("https://{host}/")),
        _ => Err(configuration_failure(format!(
            "unsupported work item provider `{provider}`"
        ))),
    }
}

/// Environment variable listing hosting hosts the user trusts with credentials,
/// comma-separated, for self-hosted servers named in a repository's `.vee.yaml`.
pub const TRUSTED_HOSTS_ENV: &str = "VEE_HOSTING_HOSTS";

/// Hosts each provider's public service uses for its web and API endpoints.
fn public_hosts(provider: &str) -> &'static [&'static str] {
    match provider {
        "github" => &["github.com", "api.github.com"],
        "gitlab" => &["gitlab.com"],
        "azure-devops" => &["dev.azure.com"],
        "bitbucket" => &["bitbucket.org", "api.bitbucket.org"],
        "linear" => &["linear.app", "api.linear.app"],
        _ => &[],
    }
}

pub fn parse_trusted_hosts(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|host| host.trim().to_ascii_lowercase())
        .filter(|host| !host.is_empty())
        .collect()
}

pub fn trusted_hosts_from_env() -> Vec<String> {
    std::env::var(TRUSTED_HOSTS_ENV)
        .map(|value| parse_trusted_hosts(&value))
        .unwrap_or_default()
}

/// Credentials go to the provider's public service, or to a host the person
/// running Vee named: on the command line (`named_by_user`) or in
/// `VEE_HOSTING_HOSTS`. A host chosen only by the shared repository
/// configuration is refused, so a branch cannot redirect a token.
pub fn ensure_credential_destination(
    provider: &str,
    host: &str,
    api_base: &str,
    named_by_user: bool,
    trusted: &[String],
) -> anyhow::Result<()> {
    if named_by_user {
        return Ok(());
    }
    let api_host = url::Url::parse(api_base)
        .ok()
        .and_then(|url| url.host_str().map(str::to_ascii_lowercase))
        .ok_or_else(|| configuration_failure(format!("hosting API base {api_base} has no host")))?;
    // `host` may carry a port (Azure DevOps Server); compare host names only.
    let host = url::Url::parse(&format!("https://{host}/"))
        .ok()
        .and_then(|url| url.host_str().map(str::to_ascii_lowercase))
        .ok_or_else(|| configuration_failure(format!("hosting host {host} is not a host name")))?;
    for destination in [host, api_host] {
        let allowed = public_hosts(provider).contains(&destination.as_str())
            || trusted.contains(&destination);
        if !allowed {
            return Err(configuration_failure(format!(
                "the repository configuration would send hosting credentials to {destination}; confirm that host with --host or --api-base, or add it to {TRUSTED_HOSTS_ENV}"
            )));
        }
    }
    Ok(())
}

/// Fetches `OWNER/REPO#NUMBER` from the hosting provider, reading the
/// credential from the settings' token environment variable.
pub fn fetch_work_item(
    settings: &HostingSettings,
    specification: &str,
) -> anyhow::Result<vee_hosting::WorkItemSnapshot> {
    let (repository, number) = specification
        .rsplit_once('#')
        .ok_or_else(|| usage_failure("--work-item must use OWNER/REPO#NUMBER"))?;
    let number = number
        .parse::<u64>()
        .map_err(|_| usage_failure("--work-item number must be a positive integer"))?;
    let token = std::env::var(&settings.token_env).with_context(|| {
        format!(
            "required credential environment variable {} is not set",
            settings.token_env
        )
    })?;
    let host = effective_work_item_host(&settings.provider, &settings.host)?;
    let reference = vee_hosting::WorkItemRef {
        repository: vee_hosting::RepositoryRef {
            host: host.clone(),
            full_name: repository.to_owned(),
        },
        number,
    };
    reference.validate().map_err(configuration_failure)?;
    let api_base = work_item_api_base(&settings.provider, &host, &settings.api_base)?;
    ensure_credential_destination(
        &settings.provider,
        &host,
        &api_base,
        settings.named_by_user,
        &trusted_hosts_from_env(),
    )?;
    get_work_item(&settings.provider, &api_base, token, &reference)
}

/// The settings for an issue tracker named in `work_items` (ADR 0033).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrackerSettings {
    pub provider: String,
    pub host: String,
    pub api_base: String,
    pub token_env: String,
    /// Jira Cloud's email variable; unset or empty selects a Data Center
    /// personal access token.
    pub user_env: Option<String>,
    pub acceptance_field: Option<String>,
}

pub fn tracker_settings(tracker: &vee_core::WorkItemsConfig) -> anyhow::Result<TrackerSettings> {
    let (default_token, default_user) = match tracker.provider.as_str() {
        "jira" => ("JIRA_API_TOKEN", Some("JIRA_EMAIL")),
        "linear" => ("LINEAR_API_KEY", None),
        other => {
            return Err(configuration_failure(format!(
                "unsupported work item tracker `{other}`"
            )))
        }
    };
    let host = match (&tracker.host, tracker.provider.as_str()) {
        (Some(host), _) => host.clone(),
        (None, "linear") => "linear.app".to_owned(),
        (None, _) => tracker
            .api_base
            .as_deref()
            .and_then(|api_base| url::Url::parse(api_base).ok())
            .and_then(|url| url.host_str().map(str::to_owned))
            .ok_or_else(|| configuration_failure("work_items.host is required for Jira"))?,
    };
    let api_base = match (&tracker.api_base, tracker.provider.as_str()) {
        (Some(api_base), _) => api_base.clone(),
        (None, "linear") => "https://api.linear.app/graphql".to_owned(),
        (None, _) => format!("https://{host}/"),
    };
    Ok(TrackerSettings {
        provider: tracker.provider.clone(),
        host,
        api_base,
        token_env: tracker
            .token_env
            .clone()
            .unwrap_or_else(|| default_token.to_owned()),
        user_env: tracker
            .user_env
            .clone()
            .or_else(|| default_user.map(str::to_owned)),
        acceptance_field: tracker.acceptance_field.clone(),
    })
}

/// Fetch `PROJ-123` from the tracker. Linear's public API may receive the
/// token; a Jira site must be in `VEE_HOSTING_HOSTS`, because the shared
/// repository configuration names it.
pub fn fetch_tracker_item(
    settings: &TrackerSettings,
    specification: &str,
) -> anyhow::Result<vee_hosting::WorkItemSnapshot> {
    let (project, number) =
        vee_hosting::trackers::parse_tracker_key(specification).ok_or_else(|| {
            usage_failure(format!(
                "--work-item must be a {} key such as PROJ-123",
                settings.provider
            ))
        })?;
    ensure_credential_destination(
        &settings.provider,
        &settings.host,
        &settings.api_base,
        false,
        &trusted_hosts_from_env(),
    )?;
    let reference = vee_hosting::WorkItemRef {
        repository: vee_hosting::RepositoryRef {
            host: settings.host.clone(),
            full_name: project,
        },
        number,
    };
    reference.validate().map_err(configuration_failure)?;
    get_tracker_item(settings, &reference)
}

/// Read a tracker item with the settings' credentials.
pub fn get_tracker_item(
    settings: &TrackerSettings,
    reference: &vee_hosting::WorkItemRef,
) -> anyhow::Result<vee_hosting::WorkItemSnapshot> {
    let token = std::env::var(&settings.token_env).with_context(|| {
        format!(
            "required credential environment variable {} is not set",
            settings.token_env
        )
    })?;
    let item = match settings.provider.as_str() {
        "jira" => {
            let email = settings
                .user_env
                .as_deref()
                .and_then(|name| std::env::var(name).ok())
                .filter(|email| !email.trim().is_empty());
            let adapter = vee_hosting::trackers::JiraAdapter::new(
                &settings.api_base,
                &token,
                email.as_deref(),
                settings.acceptance_field.clone(),
            )
            .map_err(configuration_failure)?;
            vee_hosting::WorkItemProvider::get_work_item(&adapter, reference)
        }
        "linear" => {
            let adapter = vee_hosting::trackers::LinearAdapter::new(&settings.api_base, &token)
                .map_err(configuration_failure)?;
            vee_hosting::WorkItemProvider::get_work_item(&adapter, reference)
        }
        other => {
            return Err(configuration_failure(format!(
                "unsupported work item tracker `{other}`"
            )))
        }
    };
    item.map_err(anyhow::Error::msg)
}

pub fn effective_work_item_token_env<'a>(provider: &str, configured: &'a str) -> &'a str {
    if configured != "GH_TOKEN" {
        return configured;
    }
    match provider {
        "gitlab" => "GL_TOKEN",
        "azure-devops" => "AZURE_DEVOPS_EXT_PAT",
        "bitbucket" => "BB_TOKEN",
        "gerrit" => "GERRIT_TOKEN",
        _ => configured,
    }
}

pub fn get_work_item(
    provider_id: &str,
    api_base: &str,
    token: String,
    reference: &vee_hosting::WorkItemRef,
) -> anyhow::Result<vee_hosting::WorkItemSnapshot> {
    match provider_id {
        "github" => {
            let provider = vee_hosting::github::GitHubAdapter::new(
                vee_hosting::github::GitHubConfig::new(api_base, token, String::new())
                    .map_err(configuration_failure)?,
            )
            .map_err(configuration_failure)?;
            vee_hosting::WorkItemProvider::get_work_item(&provider, reference)
                .map_err(anyhow::Error::msg)
        }
        "gitlab" => {
            let provider = vee_hosting::gitlab::GitLabAdapter::new(
                vee_hosting::gitlab::GitLabConfig::new(api_base, token)
                    .map_err(configuration_failure)?,
            )
            .map_err(configuration_failure)?;
            vee_hosting::WorkItemProvider::get_work_item(&provider, reference)
                .map_err(anyhow::Error::msg)
        }
        "azure-devops" => {
            let provider = vee_hosting::azure_devops::AzureDevOpsAdapter::new(
                vee_hosting::azure_devops::AzureDevOpsConfig::new(api_base, token)
                    .map_err(configuration_failure)?,
            )
            .map_err(configuration_failure)?;
            vee_hosting::WorkItemProvider::get_work_item(&provider, reference)
                .map_err(anyhow::Error::msg)
        }
        _ => Err(configuration_failure(format!(
            "unsupported work item provider `{provider_id}`"
        ))),
    }
}

#[cfg(test)]
mod credential_destination_tests {
    use super::*;

    #[test]
    fn credentials_go_to_public_apis_or_hosts_the_user_named() {
        assert!(ensure_credential_destination(
            "github",
            "github.com",
            "https://api.github.com/",
            false,
            &[]
        )
        .is_ok());
        assert!(ensure_credential_destination(
            "gitlab",
            "gitlab.com",
            "https://gitlab.com/api/v4/",
            false,
            &[]
        )
        .is_ok());
        assert!(ensure_credential_destination(
            "bitbucket",
            "bitbucket.org",
            "https://api.bitbucket.org/2.0/",
            false,
            &[]
        )
        .is_ok());

        // A host chosen only by the repository configuration is refused...
        let error = ensure_credential_destination(
            "github",
            "evil.example",
            "https://evil.example/api/v3/",
            false,
            &[],
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("evil.example") && error.contains("VEE_HOSTING_HOSTS"),
            "{error}"
        );
        // ...including an API base that points away from a public host.
        assert!(ensure_credential_destination(
            "github",
            "github.com",
            "https://evil.example/",
            false,
            &[]
        )
        .is_err());

        // A host the user named on the command line or in VEE_HOSTING_HOSTS is used.
        assert!(ensure_credential_destination(
            "gitlab",
            "git.corp.example",
            "https://git.corp.example/api/v4/",
            true,
            &[]
        )
        .is_ok());
        let trusted = ["git.corp.example".to_string()];
        assert!(ensure_credential_destination(
            "gitlab",
            "git.corp.example",
            "https://git.corp.example/api/v4/",
            false,
            &trusted
        )
        .is_ok());
        assert!(ensure_credential_destination(
            "gitlab",
            "git.corp.example",
            "https://other.example/api/v4/",
            false,
            &trusted
        )
        .is_err());
    }

    #[test]
    fn a_port_on_the_host_does_not_change_which_host_is_trusted() {
        let local = ["127.0.0.1".to_string()];
        assert!(ensure_credential_destination(
            "azure-devops",
            "127.0.0.1:8443",
            "http://127.0.0.1:8443/",
            false,
            &local
        )
        .is_ok());
    }

    #[test]
    fn trusted_hosting_hosts_are_read_from_a_comma_separated_list() {
        assert_eq!(
            parse_trusted_hosts(" git.corp.example , Gerrit.Corp.Example,,"),
            vec![
                "git.corp.example".to_string(),
                "gerrit.corp.example".to_string()
            ]
        );
    }
}
