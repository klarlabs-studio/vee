//! How Vee's approval verdicts compared with what people did (ADR 0025).
//!
//! The pull requests are the record: each one's Vee summary holds the
//! verdicts Vee gave with `--approve`, and the host holds what happened next.

use crate::incremental::ApprovalVerdict;
use anyhow::Result;
use serde::Serialize;
use std::collections::BTreeMap;

/// What happened to a pull request after Vee's verdicts on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalOutcome {
    /// Merged at a head Vee called eligible: people agreed.
    MergedAsEligible,
    /// Merged at a head Vee called eligible, and reverted later.
    RevertedAfterEligible,
    /// Merged at another head, after Vee called an earlier one eligible.
    ChangedAfterEligible,
    /// A person requested changes on a head Vee called eligible.
    ChangesRequestedOnEligible,
    /// Closed without merging after Vee called a head eligible.
    ClosedAfterEligible,
    /// Vee never called a head eligible: a person had to approve.
    NeverEligible,
}

impl ApprovalOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MergedAsEligible => "merged_as_eligible",
            Self::RevertedAfterEligible => "reverted_after_eligible",
            Self::ChangedAfterEligible => "changed_after_eligible",
            Self::ChangesRequestedOnEligible => "changes_requested_on_eligible",
            Self::ClosedAfterEligible => "closed_after_eligible",
            Self::NeverEligible => "never_eligible",
        }
    }
}

/// One pull request's verdicts and outcome.
#[derive(Clone, Debug, Serialize)]
pub struct ApprovalCase {
    pub number: u64,
    pub outcome: ApprovalOutcome,
    /// Heads Vee called eligible.
    pub eligible_heads: Vec<String>,
    /// Heads Vee approved on the host (`approval.mode: enforce`).
    pub approved_heads: Vec<String>,
    /// The merged pull request that reverted this one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reverted_by_pull_request: Option<u64>,
    /// The commit on the checked-out branch that reverted this one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reverted_by_commit: Option<String>,
}

/// Revert commits read from the checked-out branch.
pub const LOCAL_REVERT_LIMIT: usize = 1000;

/// What reverted a pull request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RevertedBy {
    PullRequest(u64),
    Commit(String),
}

/// What a revert message names.
#[derive(Clone, Debug, PartialEq, Eq)]
enum RevertTarget {
    Number(u64),
    Commit(String),
}

/// The pull requests and commits `text` says it reverts, in the words the
/// hosts' revert buttons and `git revert` use:
///
/// - `Reverts owner/repo#12` (GitHub's revert button);
/// - `This reverts merge request !12` (GitLab's);
/// - `This reverts commit <sha>` (`git revert`).
fn revert_targets(text: &str, full_name: &str) -> Vec<RevertTarget> {
    let token = |rest: &str| {
        rest.split_whitespace()
            .next()
            .unwrap_or_default()
            .trim_end_matches(['.', ',', ';', ')'])
            .to_owned()
    };
    let number = |token: &str, sigil: char| {
        let (repository, number) = token.rsplit_once(sigil)?;
        (repository.is_empty() || repository.eq_ignore_ascii_case(full_name))
            .then(|| number.parse::<u64>().ok())
            .flatten()
    };
    let mut targets = Vec::new();
    for (phrase, kind) in [
        ("Reverts ", '#'),
        ("This reverts merge request ", '!'),
        ("This reverts commit ", 'c'),
    ] {
        for (index, _) in text.match_indices(phrase) {
            let token = token(&text[index + phrase.len()..]);
            match kind {
                'c' => {
                    let commit = token.to_ascii_lowercase();
                    if (7..=64).contains(&commit.len())
                        && commit.bytes().all(|byte| byte.is_ascii_hexdigit())
                    {
                        targets.push(RevertTarget::Commit(commit));
                    }
                }
                sigil => targets.extend(number(&token, sigil).map(RevertTarget::Number)),
            }
        }
    }
    targets
}

/// The pull requests among `pulls` that were reverted, and by what: a merged
/// pull request among `pulls`, or a commit in `local`. A revert that was
/// itself reverted does not count.
pub fn reverted(
    pulls: &[vee_hosting::PullRequestSummary],
    local: &[vee_git::RevertCommit],
    full_name: &str,
) -> BTreeMap<u64, RevertedBy> {
    let merged_by_commit = |commit: &str| {
        pulls.iter().find(|pull| {
            pull.merge_commit.as_deref().is_some_and(|merge| {
                let merge = merge.to_ascii_lowercase();
                merge.starts_with(commit) || commit.starts_with(&merge)
            })
        })
    };
    let mut reverted = BTreeMap::new();
    let mut record = |target: RevertTarget, by: RevertedBy| {
        let number = match target {
            RevertTarget::Number(number) => Some(number),
            RevertTarget::Commit(commit) => merged_by_commit(&commit).map(|pull| pull.number),
        };
        if let Some(number) = number {
            if by != RevertedBy::PullRequest(number) {
                reverted.entry(number).or_insert(by);
            }
        }
    };
    for pull in pulls.iter().filter(|pull| pull.merged) {
        let text = format!("{}\n{}", pull.title, pull.description);
        for target in revert_targets(&text, full_name) {
            record(target, RevertedBy::PullRequest(pull.number));
        }
    }
    for commit in local {
        for target in revert_targets(&commit.message, full_name) {
            record(target, RevertedBy::Commit(commit.oid.clone()));
        }
    }
    let undone: Vec<u64> = reverted
        .values()
        .filter_map(|by| match by {
            RevertedBy::PullRequest(number) if reverted.contains_key(number) => Some(*number),
            _ => None,
        })
        .collect();
    reverted
        .retain(|_, by| !matches!(by, RevertedBy::PullRequest(number) if undone.contains(number)));
    reverted
}

/// `approval-report-v1`.
#[derive(Clone, Debug, Serialize)]
pub struct ApprovalReport {
    pub schema_version: u32,
    pub repository: String,
    /// Closed pull requests read.
    pub pull_requests_read: usize,
    /// Of those, the ones with Vee approval verdicts.
    pub with_verdicts: usize,
    /// Pull requests with at least one eligible head: the denominator of
    /// both rates.
    pub eligible: usize,
    pub outcomes: BTreeMap<ApprovalOutcome, usize>,
    /// Share of `eligible` merged at a head Vee called eligible.
    pub agreement_rate: Option<f64>,
    /// Share of `eligible` that people changed, sent back or closed.
    pub override_rate: Option<f64>,
    pub cases: Vec<ApprovalCase>,
    pub limitations: Vec<String>,
}

/// Classify one closed pull request from Vee's verdicts and the reviews
/// people gave. `None` when Vee gave no verdict on it.
pub fn classify(
    merged: bool,
    final_head: &str,
    verdicts: &[ApprovalVerdict],
    human_changes_requested_on: &[String],
    reverted: bool,
) -> Option<ApprovalOutcome> {
    if verdicts.is_empty() {
        return None;
    }
    let eligible: Vec<&str> = verdicts
        .iter()
        .filter(|verdict| verdict.eligible)
        .map(|verdict| verdict.head_oid.as_str())
        .collect();
    Some(if eligible.is_empty() {
        ApprovalOutcome::NeverEligible
    } else if human_changes_requested_on
        .iter()
        .any(|head| eligible.contains(&head.as_str()))
    {
        ApprovalOutcome::ChangesRequestedOnEligible
    } else if !merged {
        ApprovalOutcome::ClosedAfterEligible
    } else if eligible.contains(&final_head) && reverted {
        ApprovalOutcome::RevertedAfterEligible
    } else if eligible.contains(&final_head) {
        ApprovalOutcome::MergedAsEligible
    } else {
        ApprovalOutcome::ChangedAfterEligible
    })
}

/// Read the `limit` most recently closed pull requests of `repository` and
/// compare Vee's verdicts with their outcomes. `local_reverts` are revert
/// commits from a checkout of the repository, if there is one.
pub fn report(
    host: &dyn vee_hosting::PullRequestConversationProvider,
    repository: &vee_hosting::RepositoryRef,
    actor_login: &str,
    limit: usize,
    local_reverts: &[vee_git::RevertCommit],
) -> Result<ApprovalReport> {
    let host_error = |error: vee_hosting::HostingError| anyhow::anyhow!("{error}");
    let closed = host
        .closed_pull_requests(repository, limit)
        .map_err(host_error)?;
    let reverts = reverted(&closed, local_reverts, &repository.full_name);
    let mut cases = Vec::new();
    for pull in &closed {
        let reference = vee_hosting::PullRequestRef {
            repository: repository.clone(),
            number: pull.number,
        };
        let comments = host.list_conversation(&reference).map_err(host_error)?;
        let Some(record) = comments
            .iter()
            .filter(|comment| {
                comment.kind == vee_hosting::ConversationKind::Conversation
                    && !actor_login.is_empty()
                    && comment.author.eq_ignore_ascii_case(actor_login)
            })
            .filter_map(|comment| crate::incremental::decode(&comment.body))
            .find(|record| {
                record.repository == repository.full_name && record.number == pull.number
            })
        else {
            continue;
        };
        if record.approvals.is_empty() {
            continue;
        }
        let changes_requested: Vec<String> = host
            .reviews(&reference)
            .map_err(host_error)?
            .into_iter()
            .filter(|review| {
                review.state == "CHANGES_REQUESTED"
                    && !review.author_is_bot
                    && !review.author.eq_ignore_ascii_case(actor_login)
            })
            .map(|review| review.commit_id)
            .collect();
        let Some(outcome) = classify(
            pull.merged,
            &pull.head_oid,
            &record.approvals,
            &changes_requested,
            reverts.contains_key(&pull.number),
        ) else {
            continue;
        };
        let heads = |keep: fn(&ApprovalVerdict) -> bool| {
            record
                .approvals
                .iter()
                .filter(|verdict| keep(verdict))
                .map(|verdict| verdict.head_oid.clone())
                .collect::<Vec<_>>()
        };
        cases.push(ApprovalCase {
            number: pull.number,
            outcome,
            eligible_heads: heads(|verdict| verdict.eligible),
            approved_heads: heads(|verdict| verdict.approved),
            reverted_by_pull_request: match reverts.get(&pull.number) {
                Some(RevertedBy::PullRequest(number)) => Some(*number),
                _ => None,
            },
            reverted_by_commit: match reverts.get(&pull.number) {
                Some(RevertedBy::Commit(commit)) => Some(commit.clone()),
                _ => None,
            },
        });
    }
    Ok(summarize(repository, closed.len(), cases))
}

fn summarize(
    repository: &vee_hosting::RepositoryRef,
    read: usize,
    cases: Vec<ApprovalCase>,
) -> ApprovalReport {
    let mut outcomes = BTreeMap::new();
    for case in &cases {
        *outcomes.entry(case.outcome).or_insert(0) += 1;
    }
    let count = |outcome| outcomes.get(&outcome).copied().unwrap_or(0);
    let eligible = cases.len() - count(ApprovalOutcome::NeverEligible);
    let rate = |numerator: usize| (eligible > 0).then(|| numerator as f64 / eligible as f64);
    let agreement = count(ApprovalOutcome::MergedAsEligible);
    ApprovalReport {
        schema_version: 1,
        repository: repository.full_name.clone(),
        pull_requests_read: read,
        with_verdicts: cases.len(),
        eligible,
        agreement_rate: rate(agreement),
        override_rate: rate(eligible - agreement),
        outcomes,
        cases,
        limitations: vec![
            "Only pull requests reviewed with `--approve`, whose Vee summary comment holds a record, count.".into(),
            "Reverts are found in merged revert pull requests among those read and, when run in a clone, in the last 1,000 revert commits of the checked-out branch. A revert without `This reverts` or `Reverts` in its message, or one outside a shallow clone, goes unnoticed.".into(),
            "A change made after an eligible verdict counts as an override, even when it only answered an unrelated request.".into(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verdict(head: &str, eligible: bool) -> ApprovalVerdict {
        ApprovalVerdict {
            conditions: None,
            head_oid: head.into(),
            review_id: "r".into(),
            eligible,
            approved: false,
            rate_limited: false,
            failed_stages: vec![],
        }
    }

    #[test]
    fn outcomes_follow_what_people_did_with_an_eligible_head() {
        let eligible_h2 = [verdict("h1", false), verdict("h2", true)];
        assert_eq!(classify(true, "h2", &[], &[], false), None);
        assert_eq!(
            classify(true, "h2", &eligible_h2, &[], false),
            Some(ApprovalOutcome::MergedAsEligible)
        );
        assert_eq!(
            classify(true, "h3", &eligible_h2, &[], false),
            Some(ApprovalOutcome::ChangedAfterEligible)
        );
        assert_eq!(
            classify(true, "h3", &eligible_h2, &["h2".into()], false),
            Some(ApprovalOutcome::ChangesRequestedOnEligible)
        );
        assert_eq!(
            classify(false, "h2", &eligible_h2, &[], false),
            Some(ApprovalOutcome::ClosedAfterEligible)
        );
        assert_eq!(
            classify(true, "h1", &[verdict("h1", false)], &["h1".into()], false),
            Some(ApprovalOutcome::NeverEligible)
        );
        assert_eq!(
            classify(true, "h2", &eligible_h2, &[], true),
            Some(ApprovalOutcome::RevertedAfterEligible)
        );
        // A later head that was reverted was already an override.
        assert_eq!(
            classify(true, "h3", &eligible_h2, &[], true),
            Some(ApprovalOutcome::ChangedAfterEligible)
        );
    }

    fn pull(
        number: u64,
        title: &str,
        description: &str,
        merge: Option<&str>,
    ) -> vee_hosting::PullRequestSummary {
        vee_hosting::PullRequestSummary {
            number,
            merged: merge.is_some(),
            head_oid: format!("h{number}"),
            updated_at: None,
            title: title.into(),
            description: description.into(),
            merge_commit: merge.map(str::to_owned),
        }
    }

    #[test]
    fn reverts_are_found_in_revert_pull_requests_and_commits() {
        let pulls = [
            pull(10, "Add cache", "", Some("aaaaaaa1111")),
            pull(11, "Add login", "", Some("bbbbbbb2222")),
            pull(12, "Add queue", "", Some("ccccccc3333")),
            pull(13, "Add search", "", Some("ddddddd4444")),
            // GitHub's revert button.
            pull(
                20,
                "Revert \"Add cache\"",
                "Reverts acme/app#10",
                Some("e1"),
            ),
            // Another repository's pull request is not this one.
            pull(21, "Revert", "Reverts other/app#11", Some("e2")),
            // GitLab's.
            pull(
                22,
                "Revert \"Add queue\"",
                "This reverts merge request !12",
                Some("e3"),
            ),
            // A revert pull request that was not merged reverted nothing.
            pull(23, "Revert", "Reverts acme/app#11", None),
            // A revert that was itself reverted does not count.
            pull(24, "Revert", "Reverts #13", Some("e4")),
            pull(25, "Revert \"Revert\"", "Reverts #24", Some("e5")),
        ];
        let local = [vee_git::RevertCommit {
            oid: "f00d".into(),
            message: "Revert \"Add login\"\n\nThis reverts commit BBBBBBB2222.\n".into(),
        }];
        let reverted = reverted(&pulls, &local, "acme/app");
        assert_eq!(reverted.get(&10), Some(&RevertedBy::PullRequest(20)));
        assert_eq!(reverted.get(&11), Some(&RevertedBy::Commit("f00d".into())));
        assert_eq!(reverted.get(&12), Some(&RevertedBy::PullRequest(22)));
        assert_eq!(reverted.get(&13), None);
        assert_eq!(reverted.get(&24), Some(&RevertedBy::PullRequest(25)));
    }

    #[test]
    fn rates_are_shares_of_pull_requests_with_an_eligible_head() {
        let case = |outcome| ApprovalCase {
            number: 1,
            outcome,
            eligible_heads: vec![],
            approved_heads: vec![],
            reverted_by_pull_request: None,
            reverted_by_commit: None,
        };
        let repository = vee_hosting::RepositoryRef {
            host: "github.com".into(),
            full_name: "acme/app".into(),
        };
        let report = summarize(
            &repository,
            10,
            vec![
                case(ApprovalOutcome::MergedAsEligible),
                case(ApprovalOutcome::MergedAsEligible),
                case(ApprovalOutcome::MergedAsEligible),
                case(ApprovalOutcome::RevertedAfterEligible),
                case(ApprovalOutcome::NeverEligible),
            ],
        );
        assert_eq!(report.with_verdicts, 5);
        assert_eq!(report.eligible, 4);
        // A reverted merge is not agreement.
        assert_eq!(report.agreement_rate, Some(0.75));
        assert_eq!(report.override_rate, Some(0.25));
        let empty = summarize(&repository, 3, vec![case(ApprovalOutcome::NeverEligible)]);
        assert_eq!(empty.agreement_rate, None);
    }
}
