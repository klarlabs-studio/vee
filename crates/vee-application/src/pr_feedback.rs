//! What people did with Vee's findings on pull requests, as weak labels
//! (ADR 0031).
//!
//! The pull requests are the record: Vee's finding threads, the dismissals
//! people gave, the reactions on the threads, and the summary's record of
//! what the last review still reported. Weak labels are kept apart from
//! explicit feedback, only suggest rule candidates, and never reach the
//! gate.

use crate::pr_commands::{finding_threads, pull_request_decisions, Authorizer, FindingThread};
use crate::rule_candidates::{FeedbackExample, RuleCandidate};
use anyhow::Result;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use vee_core::FindingFeedbackLabel;
use vee_hosting::{PullRequestConversationProvider, PullRequestRef, RepositoryRef};

/// Distinct findings a weak candidate needs: more than explicit feedback,
/// because each signal says less.
const MIN_DISTINCT_FINDINGS: usize = 5;
const MAX_EXAMPLES: usize = 5;
const MAX_REASON_CHARS: usize = 500;

/// What a person did with a finding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Signal {
    /// `@vee dismiss <reason>` by someone allowed to.
    Dismissed,
    /// The finding was no longer reported when the pull request merged.
    Fixed,
    /// A thumbs-up on the finding's thread.
    ThumbsUp,
    /// A thumbs-down on the finding's thread.
    ThumbsDown,
}

impl Signal {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dismissed => "dismissed",
            Self::Fixed => "fixed",
            Self::ThumbsUp => "thumbs_up",
            Self::ThumbsDown => "thumbs_down",
        }
    }

    /// The feedback label the signal suggests.
    pub fn label(self) -> FindingFeedbackLabel {
        match self {
            Self::Dismissed | Self::ThumbsDown => FindingFeedbackLabel::FalsePositive,
            Self::Fixed => FindingFeedbackLabel::Confirmed,
            Self::ThumbsUp => FindingFeedbackLabel::Actionable,
        }
    }

    fn negative(self) -> bool {
        matches!(self, Self::Dismissed | Self::ThumbsDown)
    }
}

/// One weak label, with where it came from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WeakLabel {
    pub label_id: String,
    pub signal: Signal,
    pub label: FindingFeedbackLabel,
    pub category: String,
    pub fingerprint: String,
    pub finding_id: String,
    pub snapshot_id: String,
    pub pull_request: PullRequestRef,
    /// The finding thread's first comment.
    pub thread_comment_id: String,
    /// Who gave the signal; none for `fixed`.
    pub author: Option<String>,
    pub reason: String,
}

/// The weak labels read from a repository's pull requests.
#[derive(Clone, Debug, Default, Serialize)]
pub struct PullRequestFeedback {
    pub pull_requests_read: usize,
    pub labels: Vec<WeakLabel>,
}

impl PullRequestFeedback {
    /// Labels by signal, for the report.
    pub fn counts(&self) -> BTreeMap<Signal, usize> {
        let mut counts = BTreeMap::new();
        for label in &self.labels {
            *counts.entry(label.signal).or_insert(0) += 1;
        }
        counts
    }
}

fn between<'a>(text: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let from = text.find(start)? + start.len();
    let to = text[from..].find(end)? + from;
    Some(&text[from..to])
}

/// The category a Vee thread names in its heading `**High · category**`.
fn thread_category(thread: &FindingThread) -> Option<String> {
    let heading = between(&thread.body, "**", "**")?;
    let (_, category) = heading.split_once(" · ")?;
    let category = category.trim();
    (!category.is_empty()).then(|| category.to_owned())
}

fn label_id(pull_request: &PullRequestRef, thread: &str, signal: Signal, author: &str) -> String {
    let identity = format!(
        "{}\0{}\0{}\0{thread}\0{}\0{author}",
        pull_request.repository.host,
        pull_request.repository.full_name,
        pull_request.number,
        signal.as_str()
    );
    format!(
        "weak-label:{}",
        &vee_core::digest(identity.as_bytes())[7..31]
    )
}

/// Read the weak labels on the `limit` most recently closed pull requests.
pub fn collect(
    host: &dyn PullRequestConversationProvider,
    repository: &RepositoryRef,
    actor_login: &str,
    limit: usize,
) -> Result<PullRequestFeedback> {
    let host_error = |error: vee_hosting::HostingError| anyhow::anyhow!("{error}");
    let closed = host
        .closed_pull_requests(repository, limit)
        .map_err(host_error)?;
    let mut feedback = PullRequestFeedback {
        pull_requests_read: closed.len(),
        labels: Vec::new(),
    };
    for pull in &closed {
        let reference = PullRequestRef {
            repository: repository.clone(),
            number: pull.number,
        };
        let comments = host.list_conversation(&reference).map_err(host_error)?;
        let threads = finding_threads(&comments, actor_login);
        if threads.is_empty() {
            continue;
        }
        // Who may dismiss is checked as the commands check it now.
        let mut authorizer = Authorizer::new(host, &reference, None);
        let decisions = pull_request_decisions(&comments, actor_login, &mut authorizer)?;
        let reported_at_close: Option<BTreeSet<String>> = comments
            .iter()
            .filter(|comment| {
                comment.kind == vee_hosting::ConversationKind::Conversation
                    && comment.author.eq_ignore_ascii_case(actor_login)
            })
            .filter_map(|comment| crate::incremental::decode(&comment.body))
            .find(|record| {
                record.repository == repository.full_name && record.number == pull.number
            })
            .map(|record| {
                record
                    .findings
                    .iter()
                    .map(|finding| finding.fingerprint.clone())
                    .collect()
            });
        for thread in &threads {
            let Some(category) = thread_category(thread) else {
                continue;
            };
            let snapshot_id = between(&thread.body, "snapshot `", "`")
                .unwrap_or_default()
                .to_owned();
            let mut push = |signal: Signal, author: Option<&str>, reason: &str| {
                feedback.labels.push(WeakLabel {
                    label_id: label_id(
                        &reference,
                        &thread.comment_id,
                        signal,
                        author.unwrap_or_default(),
                    ),
                    signal,
                    label: signal.label(),
                    category: category.clone(),
                    fingerprint: thread.fingerprint.clone(),
                    finding_id: thread.finding_id.clone(),
                    snapshot_id: snapshot_id.clone(),
                    pull_request: reference.clone(),
                    thread_comment_id: thread.comment_id.clone(),
                    author: author.map(str::to_owned),
                    reason: reason.chars().take(MAX_REASON_CHARS).collect(),
                });
            };
            let dismissal = decisions
                .dismissals
                .iter()
                .find(|dismissal| dismissal.fingerprint == thread.fingerprint);
            if let Some(dismissal) = dismissal {
                push(
                    Signal::Dismissed,
                    Some(&dismissal.author),
                    &dismissal.reason,
                );
            } else if pull.merged
                && reported_at_close
                    .as_ref()
                    .is_some_and(|reported| !reported.contains(&thread.fingerprint))
            {
                push(Signal::Fixed, None, "");
            }
            // One vote per person; Vee's own account and bots do not vote.
            let mut votes = BTreeMap::new();
            for reaction in host
                .reactions(&reference, &thread.comment_id)
                .map_err(host_error)?
            {
                if !reaction.author_is_bot && !reaction.author.eq_ignore_ascii_case(actor_login) {
                    votes.insert(reaction.author.to_ascii_lowercase(), reaction.positive);
                }
            }
            for (author, positive) in votes {
                let signal = if positive {
                    Signal::ThumbsUp
                } else {
                    Signal::ThumbsDown
                };
                push(signal, Some(&author), "");
            }
        }
    }
    Ok(feedback)
}

/// Rule candidates from weak labels: categories whose findings people
/// pushed back on, on at least [`MIN_DISTINCT_FINDINGS`] distinct findings,
/// leaving out findings that got both kinds of signal.
pub fn candidates(feedback: &PullRequestFeedback) -> (Vec<RuleCandidate>, usize) {
    let mut by_fingerprint = BTreeMap::<&str, Vec<&WeakLabel>>::new();
    for label in &feedback.labels {
        by_fingerprint
            .entry(label.fingerprint.as_str())
            .or_default()
            .push(label);
    }
    let disputed: BTreeSet<&str> = by_fingerprint
        .iter()
        .filter(|(_, labels)| {
            labels.iter().any(|label| label.signal.negative())
                && labels.iter().any(|label| !label.signal.negative())
        })
        .map(|(fingerprint, _)| *fingerprint)
        .collect();
    let mut groups = BTreeMap::<(String, FindingFeedbackLabel), Vec<&WeakLabel>>::new();
    for label in &feedback.labels {
        if label.signal.negative() && !disputed.contains(label.fingerprint.as_str()) {
            groups
                .entry((label.category.trim().to_lowercase(), label.label))
                .or_default()
                .push(label);
        }
    }
    let candidates = groups
        .into_iter()
        .filter_map(|((category_key, label), mut evidence)| {
            evidence.sort_by(|a, b| {
                (&a.fingerprint, &a.label_id).cmp(&(&b.fingerprint, &b.label_id))
            });
            let distinct: BTreeSet<&str> = evidence
                .iter()
                .map(|label| label.fingerprint.as_str())
                .collect();
            if distinct.len() < MIN_DISTINCT_FINDINGS {
                return None;
            }
            let mut identity = b"pull_request_feedback\0".to_vec();
            identity.extend_from_slice(category_key.as_bytes());
            identity.push(0);
            identity.extend_from_slice(label.as_str().as_bytes());
            for fingerprint in &distinct {
                identity.push(0);
                identity.extend_from_slice(fingerprint.as_bytes());
            }
            let candidate_id = format!(
                "rule-candidate:{}",
                &vee_core::digest(&identity)[7..39]
            );
            let feedback_ids: Vec<String> =
                evidence.iter().map(|label| label.label_id.clone()).collect();
            let evidence_digest = vee_core::digest(feedback_ids.join("\0").as_bytes());
            let category = evidence[0].category.trim().to_owned();
            Some(RuleCandidate {
                candidate_id,
                source_kind: "pull_request_feedback".into(),
                category: category.clone(),
                feedback_label: label,
                feedback_count: distinct.len(),
                feedback_event_count: evidence.len(),
                evidence_digest,
                feedback_ids,
                suggestion: format!(
                    "People pushed back on {} findings in category '{category}' on pull requests (dismissals and thumbs-down). These are weak signals: read the examples, and if a specific pattern is behind them, propose a narrowly scoped rule; do not suppress the whole category.",
                    distinct.len()
                ),
                feedback: evidence
                    .iter()
                    .take(MAX_EXAMPLES)
                    .map(|label| FeedbackExample {
                        source_kind: label.signal.as_str().into(),
                        finding_id: Some(label.finding_id.clone()),
                        external_comment_id: Some(label.thread_comment_id.clone()),
                        archive_digest: None,
                        provider: None,
                        pull_request: Some(label.pull_request.clone()),
                        snapshot_id: label.snapshot_id.clone(),
                        reviewer: label.author.clone().unwrap_or_default(),
                        reason: label.reason.clone(),
                    })
                    .collect(),
                approval_status: "requires_human_review".into(),
            })
        })
        .collect();
    (candidates, disputed.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn weak(fingerprint: &str, signal: Signal, category: &str) -> WeakLabel {
        let pull_request = PullRequestRef {
            repository: RepositoryRef {
                host: "github.com".into(),
                full_name: "acme/app".into(),
            },
            number: 3,
        };
        WeakLabel {
            label_id: label_id(&pull_request, fingerprint, signal, "dev"),
            signal,
            label: signal.label(),
            category: category.into(),
            fingerprint: fingerprint.into(),
            finding_id: format!("F{fingerprint}"),
            snapshot_id: "s".into(),
            pull_request,
            thread_comment_id: fingerprint.into(),
            author: Some("dev".into()),
            reason: "not how we do it".into(),
        }
    }

    #[test]
    fn weak_candidates_need_five_undisputed_findings() {
        let mut labels: Vec<WeakLabel> = (0..4)
            .map(|index| weak(&format!("f{index}"), Signal::Dismissed, "Style"))
            .collect();
        let feedback = PullRequestFeedback {
            pull_requests_read: 2,
            labels: labels.clone(),
        };
        assert!(candidates(&feedback).0.is_empty());

        labels.push(weak("f4", Signal::ThumbsDown, "style"));
        // A finding someone also liked is disputed and does not count.
        labels.push(weak("f5", Signal::ThumbsDown, "style"));
        labels.push(weak("f5", Signal::ThumbsUp, "style"));
        let (found, disputed) = candidates(&PullRequestFeedback {
            pull_requests_read: 2,
            labels,
        });
        assert_eq!(disputed, 1);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].feedback_count, 5);
        assert_eq!(found[0].source_kind, "pull_request_feedback");
        assert_eq!(found[0].feedback_label, FindingFeedbackLabel::FalsePositive);
        assert!(found[0].feedback[0].pull_request.is_some());
    }

    /// Two closed pull requests: #1 merged with three Vee threads, one
    /// dismissed, one reacted to and one gone by merge time; #2 closed
    /// unmerged.
    struct Host;

    fn comment(
        id: &str,
        author: &str,
        body: &str,
        review: bool,
        reply_to: Option<&str>,
    ) -> vee_hosting::ConversationComment {
        vee_hosting::ConversationComment {
            id: id.into(),
            kind: if review {
                vee_hosting::ConversationKind::Review
            } else {
                vee_hosting::ConversationKind::Conversation
            },
            author: author.into(),
            author_is_bot: author == "vee-bot",
            body: body.into(),
            created_at: "2026-11-26T10:00:00Z".into(),
            in_reply_to: reply_to.map(str::to_owned),
            path: review.then(|| "src/lib.rs".into()),
            line: review.then_some(1),
        }
    }

    fn thread(id: &str, finding: &str, category: &str) -> vee_hosting::ConversationComment {
        comment(
            id,
            "vee-bot",
            &format!("**High · {category}** (confidence: 90%)\n\nwhy\n\nVee finding `{finding}` · snapshot `s1`\n<!-- vee:fingerprint:sha256:{finding} -->"),
            true,
            None,
        )
    }

    impl PullRequestConversationProvider for Host {
        fn list_conversation(
            &self,
            pull_request: &PullRequestRef,
        ) -> Result<Vec<vee_hosting::ConversationComment>, vee_hosting::HostingError> {
            if pull_request.number != 1 {
                return Ok(vec![thread("20", "find_000000000020", "style")]);
            }
            let acknowledgement = crate::pr_commands::Acknowledgement {
                command_id: "11".into(),
                command: "dismiss".into(),
                fingerprint: "sha256:find_000000000001".into(),
                head_oid: None,
                created_at_unix: crate::pr_commands::unix_time("2026-11-26T10:00:00Z").unwrap(),
                expires_at_unix: None,
            };
            let record = crate::incremental::ReviewRecord {
                schema_version: 1,
                repository: "acme/app".into(),
                number: 1,
                head_oid: "h".into(),
                review_id: "r".into(),
                config_digest: "c".into(),
                standards_digest: None,
                files: Default::default(),
                findings: vec![],
                approvals: vec![],
            };
            Ok(vec![
                thread("1", "find_000000000001", "style"),
                comment(
                    "11",
                    "dev",
                    "@vee dismiss we allow this here",
                    true,
                    Some("1"),
                ),
                comment(
                    "12",
                    "vee-bot",
                    &format!("Dismissed.\n{}", acknowledgement.marker()),
                    true,
                    Some("1"),
                ),
                thread("2", "find_000000000002", "style"),
                thread("3", "find_000000000003", "naming"),
                comment(
                    "30",
                    "vee-bot",
                    &format!(
                        "<!-- vee:summary -->\n{}",
                        crate::incremental::encode(&record).unwrap()
                    ),
                    false,
                    None,
                ),
            ])
        }
        fn permission(
            &self,
            _: &PullRequestRef,
            login: &str,
        ) -> Result<vee_hosting::RepositoryPermission, vee_hosting::HostingError> {
            Ok(if login == "dev" {
                vee_hosting::RepositoryPermission::Write
            } else {
                vee_hosting::RepositoryPermission::Read
            })
        }
        fn is_team_member(
            &self,
            _: &PullRequestRef,
            _: &str,
            _: &str,
        ) -> Result<bool, vee_hosting::HostingError> {
            Ok(false)
        }
        fn pull_request_origin(
            &self,
            _: &PullRequestRef,
        ) -> Result<vee_hosting::PullRequestOrigin, vee_hosting::HostingError> {
            unimplemented!()
        }
        fn reply(
            &self,
            _: &PullRequestRef,
            _: &vee_hosting::ReplyTarget,
            _: &str,
        ) -> Result<String, vee_hosting::HostingError> {
            unimplemented!()
        }
        fn set_labels(
            &self,
            _: &PullRequestRef,
            _: &str,
            _: &[String],
        ) -> Result<(), vee_hosting::HostingError> {
            unimplemented!()
        }
        fn closed_pull_requests(
            &self,
            _: &RepositoryRef,
            _: usize,
        ) -> Result<Vec<vee_hosting::PullRequestSummary>, vee_hosting::HostingError> {
            Ok(vec![
                vee_hosting::PullRequestSummary {
                    number: 1,
                    merged: true,
                    head_oid: "h".into(),
                    updated_at: None,
                    title: String::new(),
                    description: String::new(),
                    merge_commit: None,
                },
                vee_hosting::PullRequestSummary {
                    number: 2,
                    merged: false,
                    head_oid: "h2".into(),
                    updated_at: None,
                    title: String::new(),
                    description: String::new(),
                    merge_commit: None,
                },
            ])
        }
        fn recent_pull_requests(
            &self,
            _: &RepositoryRef,
            _: usize,
        ) -> Result<Vec<vee_hosting::PullRequestSummary>, vee_hosting::HostingError> {
            unimplemented!()
        }
        fn reviews(
            &self,
            _: &PullRequestRef,
        ) -> Result<Vec<vee_hosting::PullRequestReview>, vee_hosting::HostingError> {
            unimplemented!()
        }
        fn approvals(
            &self,
            _: &PullRequestRef,
            _: &str,
        ) -> Result<Vec<vee_hosting::Approval>, vee_hosting::HostingError> {
            unimplemented!()
        }
        fn approve(
            &self,
            _: &PullRequestRef,
            _: &str,
            _: &str,
        ) -> Result<String, vee_hosting::HostingError> {
            unimplemented!()
        }
        fn dismiss_approval(
            &self,
            _: &PullRequestRef,
            _: &str,
            _: &str,
        ) -> Result<(), vee_hosting::HostingError> {
            unimplemented!()
        }
        fn edit_comment(
            &self,
            _: &PullRequestRef,
            _: &str,
            _: &str,
        ) -> Result<(), vee_hosting::HostingError> {
            unimplemented!()
        }
        fn set_thread_resolved(
            &self,
            _: &PullRequestRef,
            _: &str,
            _: bool,
        ) -> Result<(), vee_hosting::HostingError> {
            unimplemented!()
        }
        fn reactions(
            &self,
            pull_request: &PullRequestRef,
            comment_id: &str,
        ) -> Result<Vec<vee_hosting::Reaction>, vee_hosting::HostingError> {
            let reaction =
                |author: &str, author_is_bot: bool, positive: bool| vee_hosting::Reaction {
                    author: author.into(),
                    author_is_bot,
                    positive,
                };
            Ok(if pull_request.number == 1 && comment_id == "3" {
                vec![
                    reaction("dev", false, false),
                    reaction("DEV", false, false),
                    reaction("renovate", true, true),
                    reaction("vee-bot", false, true),
                ]
            } else {
                vec![]
            })
        }
    }

    #[test]
    fn pull_requests_yield_dismissals_fixes_and_reactions() {
        let repository = RepositoryRef {
            host: "github.com".into(),
            full_name: "acme/app".into(),
        };
        let feedback = collect(&Host, &repository, "vee-bot", 10).unwrap();
        assert_eq!(feedback.pull_requests_read, 2);
        let signals: Vec<(&str, Signal, Option<&str>)> = feedback
            .labels
            .iter()
            .map(|label| {
                (
                    label.finding_id.as_str(),
                    label.signal,
                    label.author.as_deref(),
                )
            })
            .collect();
        assert_eq!(
            signals,
            [
                ("find_000000000001", Signal::Dismissed, Some("dev")),
                ("find_000000000002", Signal::Fixed, None),
                // One vote per person; bots and Vee itself do not vote.
                ("find_000000000003", Signal::Fixed, None),
                ("find_000000000003", Signal::ThumbsDown, Some("dev")),
            ]
        );
        assert_eq!(feedback.labels[0].reason, "we allow this here");
        assert_eq!(feedback.labels[0].category, "style");
        // The unmerged pull request's thread is not called fixed.
        assert!(feedback
            .labels
            .iter()
            .all(|label| label.pull_request.number == 1));
    }

    #[test]
    fn a_thread_heading_names_its_category() {
        let thread = FindingThread {
            comment_id: "1".into(),
            finding_id: "F1".into(),
            fingerprint: "sha256:x".into(),
            path: None,
            line: None,
            body: "**High · error-handling** (confidence: 90%)\n\nwhy\n\nVee finding `F1` · snapshot `s1`".into(),
        };
        assert_eq!(thread_category(&thread).as_deref(), Some("error-handling"));
    }
}
