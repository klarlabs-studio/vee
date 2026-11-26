//! The conversation on a pull request, for commands in comments (ADR 0020):
//! who wrote what, what they may do, and replies from Vee.

use crate::{HostingError, PullRequestRef};
use serde::{Deserialize, Serialize};

/// Where on the pull request a comment was written.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConversationKind {
    /// The pull request's main conversation.
    Conversation,
    /// An inline comment on the diff, in a thread.
    Review,
}

/// One comment on a pull request, as the host reports it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConversationComment {
    pub id: String,
    pub kind: ConversationKind,
    pub author: String,
    /// Whether the host marks the author as a bot or app account.
    pub author_is_bot: bool,
    pub body: String,
    /// RFC 3339 time the comment was created.
    pub created_at: String,
    /// For a reply in a review thread, the thread's first comment.
    pub in_reply_to: Option<String>,
    pub path: Option<String>,
    pub line: Option<u64>,
}

/// A person's access to the repository, from least to most.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryPermission {
    None,
    Read,
    Triage,
    Write,
    Maintain,
    Admin,
}

impl RepositoryPermission {
    pub fn can_write(self) -> bool {
        self >= Self::Write
    }
}

/// A pull request in a listing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PullRequestSummary {
    pub number: u64,
    pub merged: bool,
    /// The head, or the head when it was closed.
    pub head_oid: String,
    /// RFC 3339 time of the last update.
    pub updated_at: Option<String>,
}

/// A review on a pull request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PullRequestReview {
    pub author: String,
    pub author_is_bot: bool,
    /// `APPROVED`, `CHANGES_REQUESTED`, `COMMENTED` or `DISMISSED`.
    pub state: String,
    pub commit_id: String,
    /// RFC 3339 time the review was submitted.
    pub submitted_at: Option<String>,
}

/// An approving review that still stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Approval {
    pub id: String,
    /// The commit the approval was given on.
    pub commit_id: String,
}

/// Whether `label` is a label name Vee writes: lowercase letters, digits,
/// `:` and `-`, at most 50 characters.
pub fn valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 50
        && label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b":-".contains(&byte))
}

/// Where the pull request's commits come from.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PullRequestOrigin {
    pub head_oid: String,
    pub base_oid: String,
    pub base_repository: String,
    /// `None` when the head repository was deleted.
    pub head_repository: Option<String>,
    /// The head branch's name in the head repository.
    pub head_ref: Option<String>,
    pub open: bool,
}

impl PullRequestOrigin {
    /// Whether the head lives outside the base repository; such heads are
    /// never checked out by commands (ADR 0020).
    pub fn is_fork(&self) -> bool {
        self.head_repository
            .as_deref()
            .is_none_or(|head| !head.eq_ignore_ascii_case(&self.base_repository))
    }
}

/// Where Vee answers a command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplyTarget {
    /// The pull request's main conversation.
    Conversation,
    /// The review thread that starts with this comment.
    Thread { comment_id: String },
}

pub trait PullRequestConversationProvider: Send + Sync {
    /// Every comment on the pull request, in the main conversation and in
    /// review threads. Fails rather than return a partial list.
    fn list_conversation(
        &self,
        pull_request: &PullRequestRef,
    ) -> Result<Vec<ConversationComment>, HostingError>;
    /// The access `login` has to the pull request's repository.
    fn permission(
        &self,
        pull_request: &PullRequestRef,
        login: &str,
    ) -> Result<RepositoryPermission, HostingError>;
    /// Whether `login` is an active member of `team` (`org/team`). An error
    /// means the host could not say, which callers treat as no.
    fn is_team_member(
        &self,
        pull_request: &PullRequestRef,
        team: &str,
        login: &str,
    ) -> Result<bool, HostingError>;
    fn pull_request_origin(
        &self,
        pull_request: &PullRequestRef,
    ) -> Result<PullRequestOrigin, HostingError>;
    /// Post `body` and return the new comment's ID.
    fn reply(
        &self,
        pull_request: &PullRequestRef,
        target: &ReplyTarget,
        body: &str,
    ) -> Result<String, HostingError>;
    /// Make the pull request's labels that start with `prefix` exactly
    /// `wanted`, leaving every other label alone.
    fn set_labels(
        &self,
        pull_request: &PullRequestRef,
        prefix: &str,
        wanted: &[String],
    ) -> Result<(), HostingError>;
    /// The repository's most recently updated closed pull requests, newest
    /// first, at most `limit`.
    fn closed_pull_requests(
        &self,
        repository: &crate::RepositoryRef,
        limit: usize,
    ) -> Result<Vec<PullRequestSummary>, HostingError>;
    /// The repository's most recently updated pull requests, open or closed,
    /// newest first, at most `limit`.
    fn recent_pull_requests(
        &self,
        repository: &crate::RepositoryRef,
        limit: usize,
    ) -> Result<Vec<PullRequestSummary>, HostingError>;
    /// Every review on the pull request, oldest first.
    fn reviews(
        &self,
        pull_request: &PullRequestRef,
    ) -> Result<Vec<PullRequestReview>, HostingError>;
    /// The approving reviews `login` gave on the pull request that still stand.
    fn approvals(
        &self,
        pull_request: &PullRequestRef,
        login: &str,
    ) -> Result<Vec<Approval>, HostingError>;
    /// Approve the pull request at `commit_id`, and return the review's ID.
    fn approve(
        &self,
        pull_request: &PullRequestRef,
        commit_id: &str,
        body: &str,
    ) -> Result<String, HostingError>;
    /// Withdraw an approving review.
    fn dismiss_approval(
        &self,
        pull_request: &PullRequestRef,
        review_id: &str,
        message: &str,
    ) -> Result<(), HostingError>;
    /// Replace the body of a comment in the main conversation.
    fn edit_comment(
        &self,
        pull_request: &PullRequestRef,
        comment_id: &str,
        body: &str,
    ) -> Result<(), HostingError>;
    /// Resolve or reopen the review thread that starts with `comment_id`.
    fn set_thread_resolved(
        &self,
        pull_request: &PullRequestRef,
        comment_id: &str,
        resolved: bool,
    ) -> Result<(), HostingError>;
}

/// A host login safe to put in an API path.
pub fn valid_login(login: &str) -> bool {
    !login.is_empty()
        && login.len() <= 64
        && login
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// An `org/team` name safe to put in an API path.
pub fn valid_team(team: &str) -> bool {
    match team.split_once('/') {
        Some((org, slug)) => {
            valid_login(org)
                && !slug.is_empty()
                && slug.len() <= 100
                && slug
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_plain_logins_and_teams_reach_an_api_path() {
        assert!(valid_login("octo-cat") && valid_login("a_b"));
        for bad in ["", "a/b", "../x", "a b", "a%2f", "x?y"] {
            assert!(!valid_login(bad), "{bad}");
        }
        assert!(valid_team("acme/platform-team") && valid_team("acme/a.b"));
        for bad in ["acme", "acme/", "acme/a/b", "../x/y", "acme/a?b"] {
            assert!(!valid_team(bad), "{bad}");
        }
    }

    #[test]
    fn a_head_in_another_or_a_deleted_repository_is_a_fork() {
        let origin = |head: Option<&str>| PullRequestOrigin {
            head_oid: "h".into(),
            base_oid: "b".into(),
            base_repository: "team/repo".into(),
            head_repository: head.map(str::to_owned),
            head_ref: Some("feature".into()),
            open: true,
        };
        assert!(!origin(Some("Team/Repo")).is_fork());
        assert!(origin(Some("someone/repo")).is_fork());
        assert!(origin(None).is_fork());
        assert!(RepositoryPermission::Maintain.can_write());
        assert!(!RepositoryPermission::Triage.can_write());
    }
}
