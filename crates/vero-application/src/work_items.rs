//! Fetching external work items (issues) from the configured hosting provider.

use crate::failure::configuration_failure;

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
    reference: &vero_hosting::WorkItemRef,
) -> anyhow::Result<vero_hosting::WorkItemSnapshot> {
    match provider_id {
        "github" => {
            let provider = vero_hosting::github::GitHubAdapter::new(
                vero_hosting::github::GitHubConfig::new(api_base, token, String::new())
                    .map_err(configuration_failure)?,
            )
            .map_err(configuration_failure)?;
            vero_hosting::WorkItemProvider::get_work_item(&provider, reference)
                .map_err(anyhow::Error::msg)
        }
        "gitlab" => {
            let provider = vero_hosting::gitlab::GitLabAdapter::new(
                vero_hosting::gitlab::GitLabConfig::new(api_base, token)
                    .map_err(configuration_failure)?,
            )
            .map_err(configuration_failure)?;
            vero_hosting::WorkItemProvider::get_work_item(&provider, reference)
                .map_err(anyhow::Error::msg)
        }
        "azure-devops" => {
            let provider = vero_hosting::azure_devops::AzureDevOpsAdapter::new(
                vero_hosting::azure_devops::AzureDevOpsConfig::new(api_base, token)
                    .map_err(configuration_failure)?,
            )
            .map_err(configuration_failure)?;
            vero_hosting::WorkItemProvider::get_work_item(&provider, reference)
                .map_err(anyhow::Error::msg)
        }
        _ => Err(configuration_failure(format!(
            "unsupported work item provider `{provider_id}`"
        ))),
    }
}
