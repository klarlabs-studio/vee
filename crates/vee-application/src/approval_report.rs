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
    } else if eligible.contains(&final_head) {
        ApprovalOutcome::MergedAsEligible
    } else {
        ApprovalOutcome::ChangedAfterEligible
    })
}

/// Read the `limit` most recently closed pull requests of `repository` and
/// compare Vee's verdicts with their outcomes.
pub fn report(
    host: &dyn vee_hosting::PullRequestConversationProvider,
    repository: &vee_hosting::RepositoryRef,
    actor_login: &str,
    limit: usize,
) -> Result<ApprovalReport> {
    let host_error = |error: vee_hosting::HostingError| anyhow::anyhow!("{error}");
    let closed = host
        .closed_pull_requests(repository, limit)
        .map_err(host_error)?;
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
            "A merge that was reverted later counts as agreement; reverts are not detected.".into(),
            "A change made after an eligible verdict counts as an override, even when it only answered an unrelated request.".into(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verdict(head: &str, eligible: bool) -> ApprovalVerdict {
        ApprovalVerdict {
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
        assert_eq!(classify(true, "h2", &[], &[]), None);
        assert_eq!(
            classify(true, "h2", &eligible_h2, &[]),
            Some(ApprovalOutcome::MergedAsEligible)
        );
        assert_eq!(
            classify(true, "h3", &eligible_h2, &[]),
            Some(ApprovalOutcome::ChangedAfterEligible)
        );
        assert_eq!(
            classify(true, "h3", &eligible_h2, &["h2".into()]),
            Some(ApprovalOutcome::ChangesRequestedOnEligible)
        );
        assert_eq!(
            classify(false, "h2", &eligible_h2, &[]),
            Some(ApprovalOutcome::ClosedAfterEligible)
        );
        assert_eq!(
            classify(true, "h1", &[verdict("h1", false)], &["h1".into()]),
            Some(ApprovalOutcome::NeverEligible)
        );
    }

    #[test]
    fn rates_are_shares_of_pull_requests_with_an_eligible_head() {
        let case = |outcome| ApprovalCase {
            number: 1,
            outcome,
            eligible_heads: vec![],
            approved_heads: vec![],
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
                case(ApprovalOutcome::ChangedAfterEligible),
                case(ApprovalOutcome::NeverEligible),
            ],
        );
        assert_eq!(report.with_verdicts, 5);
        assert_eq!(report.eligible, 4);
        assert_eq!(report.agreement_rate, Some(0.75));
        assert_eq!(report.override_rate, Some(0.25));
        let empty = summarize(&repository, 3, vec![case(ApprovalOutcome::NeverEligible)]);
        assert_eq!(empty.agreement_rate, None);
    }
}
