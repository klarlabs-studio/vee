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
    /// Review the whole change, ignoring the earlier review's record.
    pub full: bool,
    /// Keep `vee:gate:*` and `vee:risk:*` labels on the pull request.
    pub labels: bool,
    /// Approve the pull request when the change is eligible, and withdraw
    /// Vee's approvals that no longer hold (ADR 0024).
    pub approve: bool,
    /// Add a walkthrough to the summary: the risk tier, a graph of what the
    /// change reaches, and a drafted description (ADR 0032).
    pub describe: bool,
}

/// What a summary's walkthrough is made of.
struct WalkthroughInputs {
    draft: Option<serde_json::Value>,
    risk: Option<crate::ChangeRisk>,
    impact: crate::ImpactAssessment,
}

/// The walkthrough's parts for `review`. A description that cannot be
/// drafted is left out; the rest needs only local analysis.
fn walkthrough_inputs(
    workspace: &Workspace,
    review: &crate::ReviewResult,
) -> Result<WalkthroughInputs> {
    let detail = crate::operations::review_detail(workspace, &review.review_id)?;
    let draft = review.selected_reviewers.first().and_then(|reviewer| {
        crate::operations::draft_pr_description(
            workspace,
            crate::operations::ChangeTarget::Review(review.review_id.clone()),
            reviewer,
        )
        .map(|result| result.output)
        .map_err(|error| eprintln!("warning: the description was not drafted: {error:#}"))
        .ok()
    });
    Ok(WalkthroughInputs {
        draft,
        risk: detail.risk,
        impact: detail.impact,
    })
}

/// Hosts take comments up to 65,536 characters; the walkthrough gets what
/// the rest of the summary leaves.
const MAX_SUMMARY_CHARS: usize = 65_000;

/// The outcome of `vee ci run`.
#[derive(Clone, Debug, Serialize)]
pub struct CiRun {
    pub schema_version: u32,
    pub pull_request: CiPullRequest,
    pub review_id: String,
    pub gate: vee_core::GateStatus,
    pub publication: crate::hosting::ReviewPublication,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_review_id: Option<String>,
}

/// Review the pull request CI runs for and publish the result to it.
pub fn run(
    workspace: &Workspace,
    pull_request: CiPullRequest,
    options: CiRunOptions,
) -> Result<CiRun> {
    let reviewed = review(workspace, &pull_request, &options)?;
    publish(workspace, pull_request, &options, reviewed)
}

/// A review of a pull request's head, not yet published.
pub(crate) struct Reviewed {
    pub(crate) review: crate::ReviewResult,
    /// The record of the review before this one, from Vee's summary comment.
    pub(crate) earlier: Option<crate::incremental::ReviewRecord>,
    conversation: Option<Conversation>,
    summary: Option<vee_hosting::ConversationComment>,
    actor_login: Option<String>,
}

/// Review the checked-out head of `pull_request`, building on the last
/// review's record unless `options.full`.
pub(crate) fn review(
    workspace: &Workspace,
    pull_request: &CiPullRequest,
    options: &CiRunOptions,
) -> Result<Reviewed> {
    let root = workspace.root();
    ensure_checkout_is_head(root, pull_request)?;
    exclude_vee_runtime_files(root)?;
    let actor_login = match options
        .actor_login
        .clone()
        .or_else(|| pull_request.actor_login.clone())
    {
        Some(login) => Some(login),
        // GitLab CI does not name the account; the token's user is Vee.
        None => crate::hosting::token_login(
            &pull_request.provider,
            &pull_request.api_base,
            &pull_request.token_env,
        )
        .unwrap_or_else(|error| {
            eprintln!("warning: {error:#}; Vee's earlier comments are not recognized");
            None
        }),
    };
    // The conversation holds commands and Vee's summary with its record of
    // the last review.
    let conversation = if matches!(pull_request.provider.as_str(), "github" | "gitlab") {
        read_conversation(pull_request, actor_login.as_deref().unwrap_or_default())
            .map_err(|error| {
                eprintln!(
                    "warning: the pull request's comments could not be read, so dismissals and waivers are not applied and the whole change is reviewed: {error:#}"
                );
            })
            .ok()
    } else {
        None
    };
    let summary = conversation.as_ref().and_then(|(_, comments)| {
        summary_comment(comments, actor_login.as_deref().unwrap_or_default())
    });
    let earlier = summary
        .as_ref()
        .and_then(|comment| crate::incremental::decode(&comment.body))
        .filter(|record| {
            record.repository == pull_request.repository && record.number == pull_request.number
        });
    let carried = earlier
        .clone()
        .filter(|_| !options.full)
        .map(|record| crate::incremental::CarriedReview { record });
    run_required_verifications(workspace, pull_request, options.policy_profile.as_deref())?;
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
            carried,
        },
        None,
    )?;
    Ok(Reviewed {
        review,
        earlier,
        conversation,
        summary,
        actor_login,
    })
}

/// Run the verification profiles the policy requires on the change, so
/// the gate has their runs: CI keeps no earlier ones. A profile that cannot
/// run leaves the gate incomplete; the error is reported and the review
/// goes on.
fn run_required_verifications(
    workspace: &Workspace,
    pull_request: &CiPullRequest,
    policy_profile: Option<&str>,
) -> Result<()> {
    let config = workspace.effective_config(policy_profile)?;
    for profile_id in &config.policy.required_verifications {
        let result = crate::operations::verify(
            workspace,
            crate::operations::VerifyRequest {
                target: crate::operations::VerifyTarget::Scope(
                    crate::operations::ScopeRequest::BaseAndWorktree {
                        base: Some(pull_request.base_oid.clone()),
                    },
                ),
                profile_id,
                impacted_tests: false,
            },
        );
        match result {
            Ok(result) => eprintln!("vee: verification {profile_id}: {:?}", result.run.status),
            Err(error) => eprintln!("warning: verification {profile_id} could not run: {error:#}"),
        }
    }
    Ok(())
}

/// Publish a review of `pull_request`'s head: the check, threads, the
/// dismissals and waivers people gave, and Vee's summary.
pub(crate) fn publish(
    workspace: &Workspace,
    pull_request: CiPullRequest,
    options: &CiRunOptions,
    reviewed: Reviewed,
) -> Result<CiRun> {
    let root = workspace.root();
    let Reviewed {
        review,
        earlier: earlier_record,
        conversation,
        summary,
        actor_login,
    } = reviewed;
    let hosting_flags = crate::hosting::HostingFlags {
        provider: Some(pull_request.provider.clone()),
        host: Some(pull_request.host.clone()),
        api_base: Some(pull_request.api_base.clone()),
        token_env: Some(pull_request.token_env.clone()),
        username: None,
    };
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
    let decisions = match &conversation {
        Some((host, comments)) => decisions_on_pull_request(
            root,
            &pull_request,
            &**host,
            comments,
            actor_login.as_deref().unwrap_or_default(),
        )
        .unwrap_or_else(|error| {
            // Without them the gate can only be stricter.
            eprintln!(
                "warning: dismissals and waivers on the pull request are not applied: {error:#}"
            );
            Default::default()
        }),
        None => Default::default(),
    };
    apply_waivers(workspace, &review, &pull_request, &decisions)?;
    let publication = crate::hosting::publish_review(
        workspace,
        crate::hosting::PublishRequest {
            review_id: &review.review_id,
            repository: &pull_request.repository,
            number: pull_request.number,
            flags: crate::hosting::PublishFlags {
                hosting: hosting_flags,
                webhook_secret_env: None,
                actor_login: actor_login.clone(),
            },
            approval: options.approval,
            pull_request_threads,
            dismissed_fingerprints: decisions.dismissed_fingerprints(),
        },
    )?;
    let gate = publication.gate.unwrap_or(review.gate.status);
    let mut labels = Vec::new();
    let mut approval_review_id = None;
    let mut verdict = None;
    if let Some((host, _)) = &conversation {
        let reference = pull_request_ref(&pull_request);
        if options.labels {
            match apply_labels(
                workspace,
                host.as_ref(),
                &reference,
                &review.review_id,
                gate,
            ) {
                Ok(applied) => labels = applied,
                Err(error) => eprintln!("warning: Vee's labels were not updated: {error:#}"),
            }
        }
        if options.approve {
            match apply_approval(
                workspace,
                host.as_ref(),
                &reference,
                &review.review_id,
                &pull_request.head_oid,
                actor_login.as_deref().unwrap_or_default(),
            ) {
                Ok((approved, given)) => {
                    approval_review_id = given;
                    verdict = Some(approved);
                }
                Err(error) => eprintln!("warning: Vee's approval was not updated: {error:#}"),
            }
        }
        let approvals = match verdict {
            Some(verdict) => crate::incremental::append_verdict(
                earlier_record
                    .map(|record| record.approvals)
                    .unwrap_or_default(),
                verdict,
            ),
            None => earlier_record
                .map(|record| record.approvals)
                .unwrap_or_default(),
        };
        let walkthrough = if options.describe {
            walkthrough_inputs(workspace, &review)
                .map_err(|error| eprintln!("warning: the walkthrough was left out: {error:#}"))
                .ok()
        } else {
            None
        };
        if let Err(error) = publish_summary(
            root,
            host.as_ref(),
            &pull_request,
            &review,
            SummaryUpdate {
                gate,
                approvals,
                existing: summary.as_ref(),
                walkthrough: walkthrough.as_ref(),
            },
        ) {
            // The next review is then a full one.
            eprintln!("warning: Vee's summary comment was not updated: {error:#}");
        }
    } else if options.labels || options.approve {
        eprintln!(
            "warning: labels and approvals need the pull request's comments, which could not be read; {} gets the check",
            pull_request.provider
        );
    }
    Ok(CiRun {
        schema_version: 1,
        gate,
        review_id: review.review_id,
        pull_request,
        publication,
        labels,
        approval_review_id,
    })
}

/// Labels name the gate and the risk tier, so teams can filter and route
/// pull requests by them.
const GATE_LABEL: &str = "vee:gate:";
const RISK_LABEL: &str = "vee:risk:";

fn apply_labels(
    workspace: &Workspace,
    host: &dyn vee_hosting::PullRequestConversationProvider,
    reference: &vee_hosting::PullRequestRef,
    review_id: &str,
    gate: vee_core::GateStatus,
) -> Result<Vec<String>> {
    let gate = format!(
        "{GATE_LABEL}{}",
        match gate {
            vee_core::GateStatus::Pass => "pass",
            vee_core::GateStatus::Block => "block",
            vee_core::GateStatus::Incomplete => "incomplete",
        }
    );
    let risk = crate::operations::review_detail(workspace, review_id)?
        .risk
        .map(|risk| format!("{RISK_LABEL}{}", risk.tier.as_str()));
    let host_error = |error: vee_hosting::HostingError| anyhow::anyhow!("{error}");
    host.set_labels(reference, GATE_LABEL, std::slice::from_ref(&gate))
        .map_err(host_error)?;
    let risk: Vec<String> = risk.into_iter().collect();
    host.set_labels(reference, RISK_LABEL, &risk)
        .map_err(host_error)?;
    Ok(std::iter::once(gate).chain(risk).collect())
}

/// Decide whether `head_oid` may be approved without a person. In
/// `approval.mode: enforce`, approve it when it may, and withdraw Vee's
/// approvals of other heads, or of this one when it may not. In observe
/// mode, approve nothing and withdraw every approval Vee gave.
fn apply_approval(
    workspace: &Workspace,
    host: &dyn vee_hosting::PullRequestConversationProvider,
    reference: &vee_hosting::PullRequestRef,
    review_id: &str,
    head_oid: &str,
    actor_login: &str,
) -> Result<(crate::incremental::ApprovalVerdict, Option<String>)> {
    let eligibility = crate::operations::approval_eligibility(workspace, review_id)?;
    let guards = workspace.effective_config(None)?.approval;
    let enforce = guards.enforces();
    let mut verdict = crate::incremental::ApprovalVerdict {
        head_oid: head_oid.to_owned(),
        review_id: review_id.to_owned(),
        eligible: eligibility.eligible,
        approved: false,
        rate_limited: false,
        failed_stages: eligibility
            .stages
            .iter()
            .filter(|stage| !stage.passed)
            .map(|stage| stage.id.clone())
            .collect(),
    };
    let host_error = |error: vee_hosting::HostingError| anyhow::anyhow!("{error}");
    let standing = host.approvals(reference, actor_login).map_err(host_error)?;
    let mut current = None;
    for approval in standing {
        if enforce && eligibility.eligible && approval.commit_id == head_oid {
            current = Some(approval.id);
            continue;
        }
        let why = if !enforce {
            "Vee withdrew its approval: approval.mode is observe, so Vee approves nothing."
        } else if approval.commit_id == head_oid {
            "Vee withdrew its approval: the change no longer qualifies for approval without a person."
        } else {
            "Vee withdrew its approval: the pull request changed since Vee approved it."
        };
        host.dismiss_approval(reference, &approval.id, why)
            .map_err(host_error)?;
    }
    if !enforce || !eligibility.eligible || current.is_some() {
        verdict.approved = current.is_some();
        return Ok((verdict, current));
    }
    if let Some(limit) = guards.max_per_day {
        let now = crate::current_unix_time().map_err(anyhow::Error::msg)?;
        let given = approvals_in_last_day(host, &reference.repository, actor_login, now)?;
        if given >= limit as usize {
            verdict.rate_limited = true;
            return Ok((verdict, None));
        }
    }
    let stages = eligibility
        .stages
        .iter()
        .map(|stage| format!("- {}: {}", stage.id, stage.detail))
        .collect::<Vec<_>>()
        .join("\n");
    let body = format!(
        "Vee approves this change without a person: every approval stage passed for `{}` (review `{review_id}`).\n\n{stages}\n\nA new push withdraws this approval until Vee reviews again.",
        head_oid.chars().take(12).collect::<String>()
    );
    let given = host
        .approve(reference, head_oid, &body)
        .map_err(host_error)?;
    verdict.approved = true;
    Ok((verdict, Some(given)))
}

/// Approvals Vee gave in the 24 hours before `now`, read from the 100 most
/// recently updated pull requests. Withdrawn approvals count: they were given.
fn approvals_in_last_day(
    host: &dyn vee_hosting::PullRequestConversationProvider,
    repository: &vee_hosting::RepositoryRef,
    actor_login: &str,
    now: i64,
) -> Result<usize> {
    let since = now - 24 * 60 * 60;
    let host_error = |error: vee_hosting::HostingError| anyhow::anyhow!("{error}");
    let recent = |time: Option<&str>| {
        time.and_then(crate::pr_commands::unix_time)
            .is_some_and(|time| time >= since)
    };
    let mut given = 0;
    for pull in host
        .recent_pull_requests(repository, 100)
        .map_err(host_error)?
        .iter()
        .filter(|pull| recent(pull.updated_at.as_deref()))
    {
        let reference = vee_hosting::PullRequestRef {
            repository: repository.clone(),
            number: pull.number,
        };
        given += host
            .reviews(&reference)
            .map_err(host_error)?
            .iter()
            .filter(|review| {
                review.author.eq_ignore_ascii_case(actor_login)
                    && matches!(review.state.as_str(), "APPROVED" | "DISMISSED")
                    && recent(review.submitted_at.as_deref())
            })
            .count();
    }
    Ok(given)
}

type Conversation = (
    Box<dyn vee_hosting::PullRequestConversationProvider>,
    Vec<vee_hosting::ConversationComment>,
);

fn pull_request_ref(pull_request: &CiPullRequest) -> vee_hosting::PullRequestRef {
    vee_hosting::PullRequestRef {
        repository: vee_hosting::RepositoryRef {
            host: pull_request.host.clone(),
            full_name: pull_request.repository.clone(),
        },
        number: pull_request.number,
    }
}

/// The pull request's comments, and the host to answer through.
fn read_conversation(pull_request: &CiPullRequest, actor_login: &str) -> Result<Conversation> {
    let host = crate::hosting::conversation_provider(
        &pull_request.provider,
        &pull_request.api_base,
        &pull_request.token_env,
        actor_login,
    )?;
    let comments = host
        .list_conversation(&pull_request_ref(pull_request))
        .map_err(|error| anyhow::anyhow!("reading the pull request's comments: {error}"))?;
    Ok((host, comments))
}

/// Marks Vee's summary comment, which it edits on every review.
const SUMMARY_MARKER: &str = "<!-- vee:summary -->";

/// Vee's summary comment: the newest conversation comment by Vee's own
/// account that carries the marker. Anyone else's copy is ignored.
fn summary_comment(
    comments: &[vee_hosting::ConversationComment],
    actor_login: &str,
) -> Option<vee_hosting::ConversationComment> {
    comments
        .iter()
        .filter(|comment| {
            comment.kind == vee_hosting::ConversationKind::Conversation
                && !actor_login.is_empty()
                && comment.author.eq_ignore_ascii_case(actor_login)
                && comment.body.contains(SUMMARY_MARKER)
        })
        .max_by(|a, b| a.created_at.cmp(&b.created_at))
        .cloned()
}

/// The record in Vee's summary comment among `comments`.
pub(crate) fn summary_record(
    comments: &[vee_hosting::ConversationComment],
    actor_login: &str,
) -> Option<crate::incremental::ReviewRecord> {
    summary_comment(comments, actor_login)
        .and_then(|comment| crate::incremental::decode(&comment.body))
}

/// Post or update Vee's summary of `review`, with the record the next
/// review builds on.
/// What Vee's summary comment says, and the comment it replaces.
struct SummaryUpdate<'a> {
    gate: vee_core::GateStatus,
    approvals: Vec<crate::incremental::ApprovalVerdict>,
    existing: Option<&'a vee_hosting::ConversationComment>,
    walkthrough: Option<&'a WalkthroughInputs>,
}

fn publish_summary(
    root: &Path,
    host: &dyn vee_hosting::PullRequestConversationProvider,
    pull_request: &CiPullRequest,
    review: &crate::ReviewResult,
    update: SummaryUpdate<'_>,
) -> Result<()> {
    let SummaryUpdate {
        gate,
        approvals,
        existing,
        walkthrough,
    } = update;
    let record = crate::incremental::ReviewRecord {
        schema_version: 1,
        repository: pull_request.repository.clone(),
        number: pull_request.number,
        head_oid: pull_request.head_oid.clone(),
        review_id: review.review_id.clone(),
        config_digest: review.effective_config_digest.clone(),
        standards_digest: review.standards_digest.clone(),
        files: crate::incremental::reviewed_files(root, &review.change_set)
            .map_err(anyhow::Error::msg)?,
        findings: review
            .policy_findings
            .clone()
            .unwrap_or_else(|| review.findings.clone()),
        approvals,
    };
    let approval = record
        .approvals
        .last()
        .filter(|verdict| verdict.head_oid == pull_request.head_oid);
    let encoded = crate::incremental::encode(&record);
    let without = summary_text(
        review,
        gate,
        &pull_request.head_oid,
        approval,
        encoded.clone(),
        None,
    );
    let walkthrough = walkthrough.and_then(|inputs| {
        let budget = MAX_SUMMARY_CHARS.saturating_sub(without.chars().count() + 4);
        let section = crate::walkthrough::section(
            inputs.draft.as_ref(),
            inputs.risk.as_ref(),
            &inputs.impact,
            budget,
        );
        if section.is_none() {
            eprintln!("warning: the walkthrough did not fit in the summary comment");
        }
        section
    });
    let body = match walkthrough {
        Some(section) => summary_text(
            review,
            gate,
            &pull_request.head_oid,
            approval,
            encoded,
            Some(&section),
        ),
        None => without,
    };
    let reference = pull_request_ref(pull_request);
    match existing {
        Some(comment) => host
            .edit_comment(&reference, &comment.id, &body)
            .map_err(|error| anyhow::anyhow!("editing the summary: {error}")),
        None => host
            .reply(&reference, &vee_hosting::ReplyTarget::Conversation, &body)
            .map(|_| ())
            .map_err(|error| anyhow::anyhow!("posting the summary: {error}")),
    }
}

fn summary_text(
    review: &crate::ReviewResult,
    gate: vee_core::GateStatus,
    head_oid: &str,
    approval: Option<&crate::incremental::ApprovalVerdict>,
    record: Option<String>,
    walkthrough: Option<&str>,
) -> String {
    let short = |oid: &str| oid.chars().take(7).collect::<String>();
    let verdict = match gate {
        vee_core::GateStatus::Pass => "passed",
        vee_core::GateStatus::Block => "blocked",
        vee_core::GateStatus::Incomplete => "incomplete",
    };
    let mut text = format!(
        "**Vee** reviewed `{}`: **{verdict}**, with {} finding(s), {} blocking.",
        short(head_oid),
        review.findings.len(),
        review.gate.blocking_findings.len()
    );
    if let Some(carried) = &review.carried {
        let changed = review.change_set.files.len();
        text.push_str(&format!(
            "\n\nOnly the changes since `{}` were reviewed again: {} of {changed} changed file(s) were the same as then, and their {} finding(s) are carried over.",
            short(&carried.from_head),
            carried.paths.len(),
            carried.findings
        ));
    }
    if let Some(verdict) = approval {
        text.push_str(&match (verdict.eligible, verdict.approved) {
            (true, true) => "\n\nVee approved this head: it is eligible for approval without a person.".to_owned(),
            (true, false) if verdict.rate_limited => "\n\nThis head is eligible for approval without a person, but Vee reached `approval.max_per_day` and leaves it to a person.".to_owned(),
            (true, false) => "\n\nVee would approve this head without a person. It approves nothing while `approval.mode` is `observe`.".to_owned(),
            (false, _) => format!(
                "\n\nThis head needs a person to approve it (failed: {}).",
                verdict.failed_stages.join(", ")
            ),
        });
    }
    if let Some(walkthrough) = walkthrough {
        text.push_str("\n\n");
        text.push_str(walkthrough);
    }
    text.push_str(
        "\n\n<sub>Vee updates this comment after each review. Comment `@vee review` to review the whole change again.</sub>\n\n",
    );
    text.push_str(SUMMARY_MARKER);
    match record {
        Some(record) => {
            text.push('\n');
            text.push_str(&record);
        }
        None => text.push_str(
            "\n<!-- vee: the review record is too large for a comment; the next review is a full one -->",
        ),
    }
    text
}

/// The dismissals and waivers people gave in comments that still stand.
fn decisions_on_pull_request(
    root: &Path,
    pull_request: &CiPullRequest,
    host: &dyn vee_hosting::PullRequestConversationProvider,
    comments: &[vee_hosting::ConversationComment],
    actor_login: &str,
) -> Result<crate::pr_commands::PullRequestDecisions> {
    let reference = pull_request_ref(pull_request);
    let waived = comments.iter().any(|comment| {
        comment.body.contains("<!-- vee:ack:") && comment.body.contains("\"waive\"")
    });
    let codeowners = if waived {
        crate::pr_commands::base_codeowners(root, &pull_request.base_oid)?
    } else {
        None
    };
    let mut authorizer = crate::pr_commands::Authorizer::new(host, &reference, codeowners);
    crate::pr_commands::pull_request_decisions(comments, actor_login, &mut authorizer)
}

/// Record the waivers given on this head, so the published gate applies them.
fn apply_waivers(
    workspace: &Workspace,
    review: &crate::ReviewResult,
    pull_request: &CiPullRequest,
    decisions: &crate::pr_commands::PullRequestDecisions,
) -> Result<()> {
    let now = crate::current_unix_time().map_err(anyhow::Error::msg)?;
    let mut store = workspace.store()?;
    for waiver in decisions
        .waivers
        .iter()
        .filter(|waiver| waiver.head_oid == pull_request.head_oid && waiver.expires_at_unix > now)
    {
        crate::operations::record_waiver(
            &mut *store,
            crate::operations::RecordedWaiver {
                fingerprint: waiver.fingerprint.clone(),
                snapshot_id: review.snapshot_id.clone(),
                reason: &waiver.reason,
                author: &waiver.author,
                provenance: "pull_request_command",
                created_at_unix: waiver.created_at_unix,
                expires_at_unix: waiver.expires_at_unix,
            },
        )?;
    }
    Ok(())
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
