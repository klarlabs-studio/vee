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

/// Where the pull request's commits come from.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PullRequestOrigin {
    pub head_oid: String,
    pub base_oid: String,
    pub base_repository: String,
    /// `None` when the head repository was deleted.
    pub head_repository: Option<String>,
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
            open: true,
        };
        assert!(!origin(Some("Team/Repo")).is_fork());
        assert!(origin(Some("someone/repo")).is_fork());
        assert!(origin(None).is_fork());
        assert!(RepositoryPermission::Maintain.can_write());
        assert!(!RepositoryPermission::Triage.can_write());
    }
}
