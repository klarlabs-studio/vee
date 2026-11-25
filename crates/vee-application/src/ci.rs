//! Running Vee on a pull request from CI (ADR 0019): detect the pull request
//! from the CI environment, review it from its base, and publish the result.
//!
//! The pull request is the record. CI keeps no Vee state between runs, so
//! everything a later run needs is read back from the pull request.

use crate::failure::{configuration_failure, usage_failure};
use crate::operations::Workspace;
use anyhow::{Context, Result};
use serde::Serialize;
use std::path::Path;

/// The CI system Vee is running in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CiSystem {
    GithubActions,
    GitlabCi,
}

/// A pull request as the CI environment describes it. Every value comes from
/// the CI runner, not from the repository, so its host is trusted with the
/// hosting credential.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CiPullRequest {
    pub system: CiSystem,
    /// Hosting provider ID: `github` or `gitlab`.
    pub provider: String,
    pub host: String,
    pub api_base: String,
    pub repository: String,
    pub number: u64,
    pub base_oid: String,
    pub head_oid: String,
    /// Environment variable holding the hosting token.
    pub token_env: String,
    /// The account Vee publishes as, when the CI system determines it.
    pub actor_login: Option<String>,
}

/// Detect the pull request this CI job runs for. `env` reads one environment
/// variable; it is a parameter so that detection is testable.
pub fn detect(env: &dyn Fn(&str) -> Option<String>) -> Result<CiPullRequest> {
    let set = |name: &str| env(name).filter(|value| !value.trim().is_empty());
    if set("GITHUB_ACTIONS").as_deref() == Some("true") {
        return detect_github(&set);
    }
    if set("GITLAB_CI").as_deref() == Some("true") {
        return detect_gitlab(&set);
    }
    Err(usage_failure(
        "no supported CI environment found; `vee ci run` runs in GitHub Actions or GitLab CI",
    ))
}

fn required(set: &dyn Fn(&str) -> Option<String>, name: &str) -> Result<String> {
    set(name).ok_or_else(|| configuration_failure(format!("{name} is not set")))
}

fn with_trailing_slash(url: String) -> String {
    if url.ends_with('/') {
        url
    } else {
        format!("{url}/")
    }
}

fn host_of(url: &str, name: &str) -> Result<String> {
    let parsed = url::Url::parse(url)
        .map_err(|_| configuration_failure(format!("{name} is not a URL: {url}")))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| configuration_failure(format!("{name} has no host: {url}")))?;
    Ok(match parsed.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    })
}

fn detect_github(set: &dyn Fn(&str) -> Option<String>) -> Result<CiPullRequest> {
    let event_name = required(set, "GITHUB_EVENT_NAME")?;
    if !matches!(event_name.as_str(), "pull_request" | "pull_request_target") {
        return Err(usage_failure(format!(
            "`vee ci run` reviews pull requests; this workflow runs for `{event_name}`. Trigger it on `pull_request`"
        )));
    }
    let event_path = required(set, "GITHUB_EVENT_PATH")?;
    let event: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&event_path).with_context(|| format!("reading {event_path}"))?,
    )
    .with_context(|| format!("parsing {event_path}"))?;
    let field = |pointer: &str| {
        event
            .pointer(pointer)
            .ok_or_else(|| configuration_failure(format!("the event payload has no {pointer}")))
    };
    let number = field("/pull_request/number")?
        .as_u64()
        .ok_or_else(|| configuration_failure("the pull request number is not a number"))?;
    let sha = |pointer: &str| -> Result<String> {
        field(pointer)?
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| configuration_failure(format!("{pointer} is not a commit ID")))
    };
    let server = set("GITHUB_SERVER_URL").unwrap_or_else(|| "https://github.com".into());
    let api_base = set("GITHUB_API_URL").unwrap_or_else(|| "https://api.github.com".into());
    Ok(CiPullRequest {
        system: CiSystem::GithubActions,
        provider: "github".into(),
        host: host_of(&server, "GITHUB_SERVER_URL")?,
        api_base: with_trailing_slash(api_base),
        repository: required(set, "GITHUB_REPOSITORY")?,
        number,
        base_oid: sha("/pull_request/base/sha")?,
        head_oid: sha("/pull_request/head/sha")?,
        token_env: if set("GH_TOKEN").is_some() {
            "GH_TOKEN".into()
        } else {
            "GITHUB_TOKEN".into()
        },
        // The workflow's GITHUB_TOKEN acts as this bot account.
        actor_login: Some("github-actions[bot]".into()),
    })
}

fn detect_gitlab(set: &dyn Fn(&str) -> Option<String>) -> Result<CiPullRequest> {
    let number = set("CI_MERGE_REQUEST_IID").ok_or_else(|| {
        usage_failure(
            "`vee ci run` reviews merge requests; run it in a merge request pipeline (`rules: - if: $CI_PIPELINE_SOURCE == \"merge_request_event\"`)",
        )
    })?;
    let number = number
        .parse()
        .map_err(|_| configuration_failure("CI_MERGE_REQUEST_IID is not a number"))?;
    let server = required(set, "CI_SERVER_URL")?;
    // In a merged-results pipeline CI_COMMIT_SHA is the merge commit; the
    // source branch's head is what the merge request shows.
    let head_oid = set("CI_MERGE_REQUEST_SOURCE_BRANCH_SHA")
        .map_or_else(|| required(set, "CI_COMMIT_SHA"), Ok)?;
    Ok(CiPullRequest {
        system: CiSystem::GitlabCi,
        provider: "gitlab".into(),
        host: host_of(&server, "CI_SERVER_URL")?,
        api_base: with_trailing_slash(required(set, "CI_API_V4_URL")?),
        repository: set("CI_MERGE_REQUEST_PROJECT_PATH")
            .map_or_else(|| required(set, "CI_PROJECT_PATH"), Ok)?,
        number,
        base_oid: required(set, "CI_MERGE_REQUEST_DIFF_BASE_SHA")?,
        head_oid,
        token_env: "GL_TOKEN".into(),
        actor_login: None,
    })
}

/// Options for one CI run.
#[derive(Clone, Debug, Default)]
pub struct CiRunOptions {
    /// Also publish the approval verdict as a separate check.
    pub approval: bool,
    pub effort: Option<vee_core::ReviewEffort>,
    pub policy_profile: Option<String>,
    /// Overrides the account Vee publishes as.
    pub actor_login: Option<String>,
}

/// The outcome of `vee ci run`.
#[derive(Clone, Debug, Serialize)]
pub struct CiRun {
    pub schema_version: u32,
    pub pull_request: CiPullRequest,
    pub review_id: String,
    pub gate: vee_core::GateStatus,
    pub publication: crate::hosting::ReviewPublication,
}

/// Review the pull request CI runs for and publish the result to it.
pub fn run(
    workspace: &Workspace,
    pull_request: CiPullRequest,
    options: CiRunOptions,
) -> Result<CiRun> {
    let root = workspace.root();
    ensure_checkout_is_head(root, &pull_request)?;
    exclude_vee_runtime_files(root)?;
    let review = crate::operations::review(
        workspace,
        crate::operations::ReviewRequest {
            scope: crate::operations::ScopeRequest::BaseAndWorktree {
                base: Some(pull_request.base_oid.clone()),
            },
            reviewer_ids: None,
            policy_profile: options.policy_profile.as_deref(),
            effort: options.effort,
            work_item: None,
            hosting: Default::default(),
            progress: None,
        },
        None,
    )?;
    let hosting_flags = crate::hosting::HostingFlags {
        provider: Some(pull_request.provider.clone()),
        host: Some(pull_request.host.clone()),
        api_base: Some(pull_request.api_base.clone()),
        token_env: Some(pull_request.token_env.clone()),
        username: None,
    };
    let actor_login = options
        .actor_login
        .clone()
        .or_else(|| pull_request.actor_login.clone());
    // CI keeps no ledger: Vee's earlier threads are read back from the pull
    // request, so threads of findings fixed since are resolved.
    let earlier = crate::hosting::pull_request_issues(
        root,
        hosting_flags.clone(),
        crate::hosting::PullRequestTarget {
            repository: pull_request.repository.clone(),
            number: pull_request.number,
        },
        false,
    )?;
    let pull_request_threads = crate::publication::vee_threads_on_pull_request(
        &earlier.report.issues,
        actor_login.as_deref().unwrap_or_default(),
    );
    let publication = crate::hosting::publish_review(
        workspace,
        crate::hosting::PublishRequest {
            review_id: &review.review_id,
            repository: &pull_request.repository,
            number: pull_request.number,
            flags: crate::hosting::PublishFlags {
                hosting: hosting_flags,
                webhook_secret_env: None,
                actor_login,
            },
            approval: options.approval,
            pull_request_threads,
        },
    )?;
    Ok(CiRun {
        schema_version: 1,
        gate: review.gate.status,
        review_id: review.review_id,
        pull_request,
        publication,
    })
}

/// CI checks out a merge commit by default; Vee reviews and publishes the
/// pull request's own head.
fn ensure_checkout_is_head(root: &Path, pull_request: &CiPullRequest) -> Result<()> {
    let head = crate::repository_map::repository_head_oid(root).map_err(|error| {
        configuration_failure(format!("cannot read the checked-out commit: {error}"))
    })?;
    if head == pull_request.head_oid {
        return Ok(());
    }
    let hint = match pull_request.system {
        CiSystem::GithubActions => {
            "check out the head with `actions/checkout` and `ref: ${{ github.event.pull_request.head.sha }}`"
        }
        CiSystem::GitlabCi => "run in a merge request pipeline, not a merged-results pipeline",
    };
    Err(configuration_failure(format!(
        "the checkout is at {head}, not the pull request head {}; {hint}",
        pull_request.head_oid
    )))
}

/// Vee writes its store under `.vee/`. On a fresh CI checkout those files are
/// untracked and would make the worktree look changed, which publication
/// refuses. The local exclude file hides only untracked files, so committed
/// reviewer instructions and policy still count.
fn exclude_vee_runtime_files(root: &Path) -> Result<()> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--git-path", "info/exclude"])
        .current_dir(root)
        .output()?;
    anyhow::ensure!(
        output.status.success(),
        "cannot locate the Git exclude file"
    );
    let path = root.join(String::from_utf8(output.stdout)?.trim());
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    if existing.lines().any(|line| line.trim() == "/.vee/") {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let separator = if existing.is_empty() || existing.ends_with('\n') {
        ""
    } else {
        "\n"
    };
    std::fs::write(&path, format!("{existing}{separator}/.vee/\n"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn environment(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: BTreeMap<String, String> = pairs
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect();
        move |name| map.get(name).cloned()
    }

    #[test]
    fn github_actions_pull_requests_are_read_from_the_event_payload() {
        let directory = tempfile::tempdir().unwrap();
        let event = directory.path().join("event.json");
        std::fs::write(
            &event,
            serde_json::json!({"pull_request": {"number": 42, "base": {"sha": "a".repeat(40)}, "head": {"sha": "b".repeat(40)}}}).to_string(),
        )
        .unwrap();
        let event = event.to_string_lossy().into_owned();
        let pull_request = detect(&environment(&[
            ("GITHUB_ACTIONS", "true"),
            ("GITHUB_EVENT_NAME", "pull_request"),
            ("GITHUB_EVENT_PATH", &event),
            ("GITHUB_REPOSITORY", "octo/repo"),
            ("GITHUB_SERVER_URL", "https://git.example.com"),
            ("GITHUB_API_URL", "https://git.example.com/api/v3"),
            ("GH_TOKEN", "token"),
        ]))
        .unwrap();
        assert_eq!(
            pull_request,
            CiPullRequest {
                system: CiSystem::GithubActions,
                provider: "github".into(),
                host: "git.example.com".into(),
                api_base: "https://git.example.com/api/v3/".into(),
                repository: "octo/repo".into(),
                number: 42,
                base_oid: "a".repeat(40),
                head_oid: "b".repeat(40),
                token_env: "GH_TOKEN".into(),
                actor_login: Some("github-actions[bot]".into()),
            }
        );

        let push = detect(&environment(&[
            ("GITHUB_ACTIONS", "true"),
            ("GITHUB_EVENT_NAME", "push"),
        ]))
        .unwrap_err()
        .to_string();
        assert!(push.contains("pull_request"), "{push}");
    }

    #[test]
    fn gitlab_merge_request_pipelines_are_read_from_predefined_variables() {
        let pull_request = detect(&environment(&[
            ("GITLAB_CI", "true"),
            ("CI_MERGE_REQUEST_IID", "7"),
            ("CI_SERVER_URL", "https://gitlab.example.com:8443"),
            ("CI_API_V4_URL", "https://gitlab.example.com:8443/api/v4"),
            ("CI_PROJECT_PATH", "group/project"),
            ("CI_MERGE_REQUEST_DIFF_BASE_SHA", &"a".repeat(40)),
            ("CI_COMMIT_SHA", &"c".repeat(40)),
            ("CI_MERGE_REQUEST_SOURCE_BRANCH_SHA", &"b".repeat(40)),
        ]))
        .unwrap();
        assert_eq!(pull_request.system, CiSystem::GitlabCi);
        assert_eq!(pull_request.host, "gitlab.example.com:8443");
        assert_eq!(
            pull_request.api_base,
            "https://gitlab.example.com:8443/api/v4/"
        );
        assert_eq!(pull_request.repository, "group/project");
        assert_eq!(pull_request.number, 7);
        assert_eq!(pull_request.head_oid, "b".repeat(40));
        assert_eq!(pull_request.token_env, "GL_TOKEN");

        let branch = detect(&environment(&[("GITLAB_CI", "true")]))
            .unwrap_err()
            .to_string();
        assert!(branch.contains("merge request pipeline"), "{branch}");
        assert!(detect(&environment(&[])).is_err());
    }

    #[test]
    fn vee_runtime_files_are_excluded_once_without_hiding_tracked_files() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        assert!(std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(root)
            .status()
            .unwrap()
            .success());
        exclude_vee_runtime_files(root).unwrap();
        exclude_vee_runtime_files(root).unwrap();
        let exclude = std::fs::read_to_string(root.join(".git/info/exclude")).unwrap();
        assert_eq!(exclude.matches("/.vee/").count(), 1, "{exclude}");
    }
}
