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
    HostingSettings {
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
    get_work_item(&settings.provider, &api_base, token, &reference)
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
