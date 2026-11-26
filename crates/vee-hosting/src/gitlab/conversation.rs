//! The conversation on a GitLab merge request (ADR 0030): discussions and
//! notes, members' access, labels, approvals and their history.
//!
//! A comment's ID is `<discussion ID>:<note ID>`, so a reply, an edit or a
//! resolution can always find its discussion.

use super::{GitLabAdapter, MAX_API_RESPONSE_BYTES};
use crate::conversation::{
    Approval, ConversationComment, ConversationKind, PullRequestConversationProvider,
    PullRequestOrigin, PullRequestReview, PullRequestSummary, ReplyTarget, RepositoryPermission,
};
use crate::{HostingError, PullRequestRef, RepositoryRef};
use reqwest::{Method, Url};
use serde_json::Value;

const PAGE_SIZE: usize = 100;
/// Pages read from one listing: 3,000 items.
const MAX_PAGES: usize = 30;
/// The ID `approve` returns: GitLab keeps one approval per person.
const APPROVAL_ID: &str = "approval";

/// A GitLab username: letters, digits, `_`, `-` and `.`.
fn valid_username(login: &str) -> bool {
    !login.is_empty()
        && login.len() <= 255
        && login
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-.".contains(&byte))
}

/// A GitLab group path such as `org/team` or `org/sub/team`.
fn valid_group(group: &str) -> bool {
    group.contains('/') && group.split('/').all(valid_username)
}

fn comment_id(discussion: &str, note: u64) -> String {
    format!("{discussion}:{note}")
}

fn split_comment_id(id: &str) -> Result<(&str, u64), HostingError> {
    id.split_once(':')
        .filter(|(discussion, _)| {
            !discussion.is_empty() && discussion.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
        .and_then(|(discussion, note)| Some((discussion, note.parse().ok()?)))
        .ok_or_else(|| HostingError::InvalidResponse(format!("`{id}` is not a GitLab comment ID")))
}

fn text<'a>(value: &'a Value, pointer: &str) -> Option<&'a str> {
    value.pointer(pointer).and_then(Value::as_str)
}

/// What a system note about approval says, as a review state.
fn system_review_state(body: &str) -> Option<&'static str> {
    let body = body.trim();
    if body.starts_with("unapproved this merge request") {
        Some("DISMISSED")
    } else if body.starts_with("approved this merge request") {
        Some("APPROVED")
    } else if body.starts_with("requested changes") {
        Some("CHANGES_REQUESTED")
    } else {
        None
    }
}

/// Whether GitLab marks the user as a bot: a bot account, or a project or
/// group access token's user.
fn is_bot(author: &Value) -> bool {
    author.get("bot").and_then(Value::as_bool) == Some(true)
        || text(author, "/username").is_some_and(|name| {
            (name.starts_with("project_") || name.starts_with("group_")) && name.contains("_bot")
        })
}

impl GitLabAdapter {
    fn send_json(
        &self,
        method: Method,
        url: Url,
        body: Option<Value>,
        what: &str,
    ) -> Result<Value, HostingError> {
        let mut request = self.request_method(method, url)?;
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request
            .send()
            .map_err(|error| HostingError::Transport(format!("{what}: {error}")))?;
        let response = Self::checked(response)?;
        if response.content_length() == Some(0) {
            return Ok(Value::Null);
        }
        Self::bounded_json(response, MAX_API_RESPONSE_BYTES)
    }

    fn get_value(&self, url: Url, what: &str) -> Result<Value, HostingError> {
        self.send_json(Method::GET, url, None, what)
    }

    /// Every item of a paginated listing, at most `limit`.
    fn pages(&self, url: Url, limit: usize, what: &str) -> Result<Vec<Value>, HostingError> {
        let mut items = Vec::new();
        for page in 1..=MAX_PAGES {
            let mut page_url = url.clone();
            page_url
                .query_pairs_mut()
                .append_pair("per_page", &PAGE_SIZE.to_string())
                .append_pair("page", &page.to_string());
            let response = self
                .request(page_url)?
                .send()
                .map_err(|error| HostingError::Transport(format!("{what}: {error}")))?;
            let response = Self::checked(response)?;
            let next = response
                .headers()
                .get("x-next-page")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| !value.trim().is_empty());
            let batch: Vec<Value> = Self::bounded_json(response, MAX_API_RESPONSE_BYTES)?;
            let full = batch.len() >= PAGE_SIZE;
            items.extend(batch);
            if items.len() >= limit {
                items.truncate(limit);
                return Ok(items);
            }
            if !next && !full {
                return Ok(items);
            }
        }
        Err(HostingError::InvalidResponse(format!(
            "{what}: more than {} items",
            PAGE_SIZE * MAX_PAGES
        )))
    }

    fn repository_url(
        &self,
        repository: &RepositoryRef,
        suffix: &str,
    ) -> Result<Url, HostingError> {
        // Any positive number: only the project part of the path is used.
        self.project_url(
            &PullRequestRef {
                repository: repository.clone(),
                number: 1,
            },
            suffix,
        )
    }

    fn api_url(&self, path: &str) -> Url {
        let prefix = self.config.api_base.path().trim_end_matches('/').to_owned();
        let mut url = self.config.api_base.clone();
        url.set_path(&format!("{prefix}{path}"));
        url
    }

    /// The username the token acts as.
    pub fn current_login(&self) -> Result<String, HostingError> {
        let user = self.get_value(self.api_url("/user"), "reading the GitLab user")?;
        text(&user, "/username")
            .map(str::to_owned)
            .ok_or_else(|| HostingError::InvalidResponse("GitLab user has no username".into()))
    }

    /// The ID of the user named `login`, or `None` when there is none.
    fn user_id(&self, login: &str) -> Result<Option<u64>, HostingError> {
        if !valid_username(login) {
            return Ok(None);
        }
        let mut url = self.api_url("/users");
        url.query_pairs_mut().append_pair("username", login);
        let users = self.get_value(url, "looking up a GitLab user")?;
        Ok(users
            .as_array()
            .into_iter()
            .flatten()
            .find(|user| {
                text(user, "/username").is_some_and(|name| name.eq_ignore_ascii_case(login))
            })
            .and_then(|user| user.get("id").and_then(Value::as_u64)))
    }

    fn merge_request(&self, pull_request: &PullRequestRef) -> Result<Value, HostingError> {
        self.get_value(
            self.project_path(pull_request, "")?,
            "reading the merge request",
        )
    }

    /// The merge request's versions as (created at, head commit), oldest first.
    fn versions(
        &self,
        pull_request: &PullRequestRef,
    ) -> Result<Vec<(String, String)>, HostingError> {
        let versions = self.pages(
            self.project_path(pull_request, "/versions")?,
            PAGE_SIZE * MAX_PAGES,
            "listing merge request versions",
        )?;
        let mut versions: Vec<(String, String)> = versions
            .iter()
            .filter_map(|version| {
                Some((
                    text(version, "/created_at")?.to_owned(),
                    text(version, "/head_commit_sha")?.to_owned(),
                ))
            })
            .collect();
        versions.sort();
        Ok(versions)
    }

    fn post_note(&self, pull_request: &PullRequestRef, body: &str) -> Result<String, HostingError> {
        let created = self.send_json(
            Method::POST,
            self.project_path(pull_request, "/discussions")?,
            Some(serde_json::json!({ "body": body })),
            "posting a GitLab comment",
        )?;
        let discussion = text(&created, "/id");
        let note = created.pointer("/notes/0/id").and_then(Value::as_u64);
        match (discussion, note) {
            (Some(discussion), Some(note)) => Ok(comment_id(discussion, note)),
            _ => Err(HostingError::InvalidResponse(
                "the created GitLab discussion has no ID".into(),
            )),
        }
    }

    fn summaries(
        &self,
        repository: &RepositoryRef,
        limit: usize,
        closed_only: bool,
    ) -> Result<Vec<PullRequestSummary>, HostingError> {
        let mut url = self.repository_url(repository, "/merge_requests")?;
        url.query_pairs_mut()
            .append_pair("state", "all")
            .append_pair("order_by", "updated_at")
            .append_pair("sort", "desc");
        let mut summaries = Vec::new();
        for request in self.pages(url, PAGE_SIZE * MAX_PAGES, "listing merge requests")? {
            let state = text(&request, "/state").unwrap_or_default();
            if closed_only && !matches!(state, "merged" | "closed") {
                continue;
            }
            let (Some(number), Some(head)) = (
                request.get("iid").and_then(Value::as_u64),
                text(&request, "/sha"),
            ) else {
                continue;
            };
            summaries.push(PullRequestSummary {
                number,
                merged: state == "merged",
                head_oid: head.to_owned(),
                updated_at: text(&request, "/updated_at").map(str::to_owned),
            });
            if summaries.len() >= limit {
                break;
            }
        }
        Ok(summaries)
    }
}

impl PullRequestConversationProvider for GitLabAdapter {
    fn list_conversation(
        &self,
        pull_request: &PullRequestRef,
    ) -> Result<Vec<ConversationComment>, HostingError> {
        let discussions = self.pages(
            self.project_path(pull_request, "/discussions")?,
            PAGE_SIZE * MAX_PAGES,
            "listing GitLab discussions",
        )?;
        let mut comments = Vec::new();
        for discussion in &discussions {
            let Some(discussion_id) = text(discussion, "/id") else {
                continue;
            };
            let notes = discussion
                .get("notes")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or_default();
            let Some(first) = notes.first() else {
                continue;
            };
            if first.get("system").and_then(Value::as_bool) == Some(true) {
                continue;
            }
            let position = first.get("position").filter(|position| !position.is_null());
            let kind = if position.is_some() {
                ConversationKind::Review
            } else {
                ConversationKind::Conversation
            };
            let first_id = first.get("id").and_then(Value::as_u64);
            let path = position.and_then(|position| {
                text(position, "/new_path")
                    .or_else(|| text(position, "/old_path"))
                    .map(str::to_owned)
            });
            let line = position.and_then(|position| {
                position
                    .get("new_line")
                    .and_then(Value::as_u64)
                    .or_else(|| position.get("old_line").and_then(Value::as_u64))
            });
            for note in notes {
                let (Some(id), Some(author), Some(created_at)) = (
                    note.get("id").and_then(Value::as_u64),
                    text(note, "/author/username"),
                    text(note, "/created_at"),
                ) else {
                    return Err(HostingError::InvalidResponse(
                        "a GitLab note lacks its ID, author or time".into(),
                    ));
                };
                let reply = kind == ConversationKind::Review && Some(id) != first_id;
                comments.push(ConversationComment {
                    id: comment_id(discussion_id, id),
                    kind,
                    author: author.to_owned(),
                    author_is_bot: note.get("author").is_some_and(is_bot),
                    body: text(note, "/body").unwrap_or_default().to_owned(),
                    created_at: created_at.to_owned(),
                    in_reply_to: reply
                        .then(|| first_id.map(|first| comment_id(discussion_id, first)))
                        .flatten(),
                    path: path.clone(),
                    line,
                });
            }
        }
        Ok(comments)
    }

    fn permission(
        &self,
        pull_request: &PullRequestRef,
        login: &str,
    ) -> Result<RepositoryPermission, HostingError> {
        let Some(user) = self.user_id(login)? else {
            return Ok(RepositoryPermission::None);
        };
        let member = match self.get_value(
            self.project_url(pull_request, &format!("/members/all/{user}"))?,
            "reading project membership",
        ) {
            Ok(member) => member,
            Err(HostingError::NotFound) => return Ok(RepositoryPermission::None),
            Err(error) => return Err(error),
        };
        if text(&member, "/state").is_some_and(|state| state != "active") {
            return Ok(RepositoryPermission::None);
        }
        // Owner, Maintainer, Developer, Reporter, Planner and Guest.
        Ok(match member.get("access_level").and_then(Value::as_u64) {
            Some(50..) => RepositoryPermission::Admin,
            Some(40..=49) => RepositoryPermission::Maintain,
            Some(30..=39) => RepositoryPermission::Write,
            Some(20..=29) => RepositoryPermission::Triage,
            Some(5..=19) => RepositoryPermission::Read,
            _ => RepositoryPermission::None,
        })
    }

    fn is_team_member(
        &self,
        _pull_request: &PullRequestRef,
        team: &str,
        login: &str,
    ) -> Result<bool, HostingError> {
        if !valid_group(team) {
            return Ok(false);
        }
        let Some(user) = self.user_id(login)? else {
            return Ok(false);
        };
        let group = team.replace('/', "%2F");
        match self.get_value(
            self.api_url(&format!("/groups/{group}/members/all/{user}")),
            "reading group membership",
        ) {
            Ok(member) => Ok(text(&member, "/state").is_none_or(|state| state == "active")),
            Err(HostingError::NotFound) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn pull_request_origin(
        &self,
        pull_request: &PullRequestRef,
    ) -> Result<PullRequestOrigin, HostingError> {
        let request = self.merge_request(pull_request)?;
        let field = |pointer: &str| {
            text(&request, pointer).map(str::to_owned).ok_or_else(|| {
                HostingError::InvalidResponse(format!("the merge request has no {pointer}"))
            })
        };
        let source = request.get("source_project_id").and_then(Value::as_u64);
        let target = request.get("target_project_id").and_then(Value::as_u64);
        let head_repository = if source.is_some() && source == target {
            Some(pull_request.repository.full_name.clone())
        } else if let Some(source) = source {
            match self.get_value(
                self.api_url(&format!("/projects/{source}")),
                "reading the source project",
            ) {
                Ok(project) => text(&project, "/path_with_namespace").map(str::to_owned),
                Err(HostingError::NotFound) => None,
                Err(error) => return Err(error),
            }
        } else {
            None
        };
        Ok(PullRequestOrigin {
            head_oid: field("/sha")?,
            base_oid: field("/diff_refs/base_sha")?,
            base_repository: pull_request.repository.full_name.clone(),
            head_repository,
            head_ref: text(&request, "/source_branch").map(str::to_owned),
            open: text(&request, "/state") == Some("opened"),
        })
    }

    fn reply(
        &self,
        pull_request: &PullRequestRef,
        target: &ReplyTarget,
        body: &str,
    ) -> Result<String, HostingError> {
        match target {
            ReplyTarget::Conversation => self.post_note(pull_request, body),
            ReplyTarget::Thread { comment_id: thread } => {
                let (discussion, _) = split_comment_id(thread)?;
                let note = self.send_json(
                    Method::POST,
                    self.project_path(pull_request, &format!("/discussions/{discussion}/notes"))?,
                    Some(serde_json::json!({ "body": body })),
                    "replying in a GitLab discussion",
                )?;
                note.get("id")
                    .and_then(Value::as_u64)
                    .map(|note| comment_id(discussion, note))
                    .ok_or_else(|| {
                        HostingError::InvalidResponse("the created GitLab note has no ID".into())
                    })
            }
        }
    }

    fn set_labels(
        &self,
        pull_request: &PullRequestRef,
        prefix: &str,
        wanted: &[String],
    ) -> Result<(), HostingError> {
        if let Some(label) = wanted
            .iter()
            .find(|label| !crate::conversation::valid_label(label) || !label.starts_with(prefix))
        {
            return Err(HostingError::InvalidResponse(format!(
                "`{label}` is not a label Vee writes under `{prefix}`"
            )));
        }
        let request = self.merge_request(pull_request)?;
        let current: Vec<&str> = request
            .get("labels")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        let remove: Vec<&str> = current
            .iter()
            .copied()
            .filter(|label| label.starts_with(prefix) && !wanted.iter().any(|w| w == label))
            .collect();
        let add: Vec<&str> = wanted
            .iter()
            .map(String::as_str)
            .filter(|label| !current.contains(label))
            .collect();
        if add.is_empty() && remove.is_empty() {
            return Ok(());
        }
        self.send_json(
            Method::PUT,
            self.project_path(pull_request, "")?,
            Some(serde_json::json!({
                "add_labels": add.join(","),
                "remove_labels": remove.join(","),
            })),
            "updating merge request labels",
        )?;
        Ok(())
    }

    fn closed_pull_requests(
        &self,
        repository: &RepositoryRef,
        limit: usize,
    ) -> Result<Vec<PullRequestSummary>, HostingError> {
        self.summaries(repository, limit, true)
    }

    fn recent_pull_requests(
        &self,
        repository: &RepositoryRef,
        limit: usize,
    ) -> Result<Vec<PullRequestSummary>, HostingError> {
        self.summaries(repository, limit, false)
    }

    /// GitLab keeps no review objects; its system notes record each
    /// approval, withdrawal and request for changes. Each is tied to the
    /// head of the newest merge request version created before it.
    fn reviews(
        &self,
        pull_request: &PullRequestRef,
    ) -> Result<Vec<PullRequestReview>, HostingError> {
        let mut url = self.project_path(pull_request, "/notes")?;
        url.query_pairs_mut()
            .append_pair("sort", "asc")
            .append_pair("order_by", "created_at");
        let notes = self.pages(url, PAGE_SIZE * MAX_PAGES, "listing merge request notes")?;
        let versions = self.versions(pull_request)?;
        let mut reviews = Vec::new();
        for note in &notes {
            if note.get("system").and_then(Value::as_bool) != Some(true) {
                continue;
            }
            let Some(state) = system_review_state(text(note, "/body").unwrap_or_default()) else {
                continue;
            };
            let submitted_at = text(note, "/created_at").map(str::to_owned);
            let commit_id = versions
                .iter()
                .rev()
                .find(|(created, _)| {
                    submitted_at
                        .as_deref()
                        .is_some_and(|at| created.as_str() <= at)
                })
                .map(|(_, head)| head.clone())
                .unwrap_or_default();
            reviews.push(PullRequestReview {
                author: text(note, "/author/username")
                    .unwrap_or_default()
                    .to_owned(),
                author_is_bot: note.get("author").is_some_and(is_bot),
                state: state.to_owned(),
                commit_id,
                submitted_at,
            });
        }
        Ok(reviews)
    }

    fn approvals(
        &self,
        pull_request: &PullRequestRef,
        login: &str,
    ) -> Result<Vec<Approval>, HostingError> {
        let state = self.get_value(
            self.project_path(pull_request, "/approvals")?,
            "reading merge request approvals",
        )?;
        let approved = state
            .get("approved_by")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .any(|entry| {
                text(entry, "/user/username").is_some_and(|name| name.eq_ignore_ascii_case(login))
            });
        if !approved {
            return Ok(Vec::new());
        }
        // The head it was given on: the last approval by `login` in the
        // history, else the current head.
        let commit_id = self
            .reviews(pull_request)?
            .into_iter()
            .rev()
            .find(|review| review.author.eq_ignore_ascii_case(login) && review.state == "APPROVED")
            .map(|review| review.commit_id)
            .filter(|commit| !commit.is_empty());
        let commit_id = match commit_id {
            Some(commit) => commit,
            None => text(&self.merge_request(pull_request)?, "/sha")
                .unwrap_or_default()
                .to_owned(),
        };
        Ok(vec![Approval {
            id: APPROVAL_ID.into(),
            commit_id,
        }])
    }

    fn approve(
        &self,
        pull_request: &PullRequestRef,
        commit_id: &str,
        body: &str,
    ) -> Result<String, HostingError> {
        // `sha` makes GitLab refuse the approval if the head moved.
        self.send_json(
            Method::POST,
            self.project_path(pull_request, "/approve")?,
            Some(serde_json::json!({ "sha": commit_id })),
            "approving the merge request",
        )?;
        self.post_note(pull_request, body)?;
        Ok(APPROVAL_ID.into())
    }

    fn dismiss_approval(
        &self,
        pull_request: &PullRequestRef,
        _review_id: &str,
        message: &str,
    ) -> Result<(), HostingError> {
        self.send_json(
            Method::POST,
            self.project_path(pull_request, "/unapprove")?,
            None,
            "withdrawing the approval",
        )?;
        self.post_note(pull_request, message)?;
        Ok(())
    }

    fn edit_comment(
        &self,
        pull_request: &PullRequestRef,
        comment_id: &str,
        body: &str,
    ) -> Result<(), HostingError> {
        let (discussion, note) = split_comment_id(comment_id)?;
        self.put_note(pull_request, discussion, note, body)
    }

    fn set_thread_resolved(
        &self,
        pull_request: &PullRequestRef,
        comment_id: &str,
        resolved: bool,
    ) -> Result<(), HostingError> {
        let (discussion, _) = split_comment_id(comment_id)?;
        self.set_discussion_resolved(pull_request, discussion, resolved)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gitlab::{GitLabAdapter, GitLabConfig};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    /// A fake GitLab that answers by method and path, and records requests.
    fn fake(
        routes: Vec<(&'static str, &'static str, String)>,
    ) -> (GitLabAdapter, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = requests.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut buffer = vec![0u8; 65536];
                let count = stream.read(&mut buffer).unwrap_or(0);
                let request = String::from_utf8_lossy(&buffer[..count]).to_string();
                let line = request.lines().next().unwrap_or_default().to_owned();
                seen.lock().unwrap().push(request.clone());
                let mut parts = line.split_whitespace();
                let (method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
                let path = target.split('?').next().unwrap_or("");
                let body = routes
                    .iter()
                    .find(|(m, p, _)| *m == method && path.ends_with(p))
                    .map(|(_, _, body)| body.clone());
                let response = match body {
                    Some(body) => format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    ),
                    None => {
                        "HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"
                            .into()
                    }
                };
                let _ = stream.write_all(response.as_bytes());
            }
        });
        let adapter = GitLabAdapter::new(
            GitLabConfig::new(&format!("http://{address}/api/v4/"), "token".into()).unwrap(),
        )
        .unwrap();
        (adapter, requests)
    }

    fn merge_request() -> PullRequestRef {
        PullRequestRef {
            repository: RepositoryRef {
                host: "127.0.0.1".into(),
                full_name: "group/app".into(),
            },
            number: 7,
        }
    }

    #[test]
    fn discussions_become_comments_with_discussion_scoped_ids() {
        let discussions = serde_json::json!([
            {"id": "d1", "notes": [{"id": 1, "system": false, "body": "@vee status", "created_at": "2026-11-26T10:00:00Z", "author": {"username": "dev"}}]},
            {"id": "d2", "notes": [
                {"id": 2, "system": false, "body": "Vee finding `F1`", "created_at": "2026-11-26T10:01:00Z", "author": {"username": "project_9_bot_x", "bot": true}, "position": {"new_path": "src/lib.rs", "new_line": 4}},
                {"id": 3, "system": false, "body": "@vee dismiss false positive", "created_at": "2026-11-26T10:02:00Z", "author": {"username": "dev"}}
            ]},
            {"id": "d3", "notes": [{"id": 4, "system": true, "body": "added 1 commit", "created_at": "2026-11-26T10:03:00Z", "author": {"username": "dev"}}]}
        ]);
        let (adapter, _) = fake(vec![(
            "GET",
            "/merge_requests/7/discussions",
            discussions.to_string(),
        )]);
        let comments = adapter.list_conversation(&merge_request()).unwrap();
        assert_eq!(comments.len(), 3);
        assert_eq!(comments[0].id, "d1:1");
        assert_eq!(comments[0].kind, ConversationKind::Conversation);
        assert_eq!(comments[1].id, "d2:2");
        assert!(comments[1].author_is_bot);
        assert_eq!(comments[1].path.as_deref(), Some("src/lib.rs"));
        assert_eq!(comments[1].line, Some(4));
        assert_eq!(comments[2].in_reply_to.as_deref(), Some("d2:2"));
        assert_eq!(comments[2].kind, ConversationKind::Review);
    }

    #[test]
    fn access_levels_map_to_permissions_and_strangers_have_none() {
        let (adapter, _) = fake(vec![
            ("GET", "/users", r#"[{"id": 42, "username": "dev"}]"#.into()),
            (
                "GET",
                "/members/all/42",
                r#"{"access_level": 30, "state": "active"}"#.into(),
            ),
        ]);
        assert_eq!(
            adapter.permission(&merge_request(), "dev").unwrap(),
            RepositoryPermission::Write
        );
        let (adapter, _) = fake(vec![("GET", "/users", "[]".into())]);
        assert_eq!(
            adapter.permission(&merge_request(), "nobody").unwrap(),
            RepositoryPermission::None
        );
        assert_eq!(
            adapter.permission(&merge_request(), "bad/name").unwrap(),
            RepositoryPermission::None
        );
    }

    #[test]
    fn labels_change_only_under_the_prefix() {
        let (adapter, requests) = fake(vec![
            (
                "GET",
                "/merge_requests/7",
                r#"{"labels": ["vee:gate:block", "team:core"]}"#.into(),
            ),
            ("PUT", "/merge_requests/7", "{}".into()),
        ]);
        adapter
            .set_labels(&merge_request(), "vee:gate:", &["vee:gate:pass".into()])
            .unwrap();
        let requests = requests.lock().unwrap();
        let put = requests.iter().find(|r| r.starts_with("PUT")).unwrap();
        assert!(put.contains(r#""add_labels":"vee:gate:pass""#), "{put}");
        assert!(put.contains(r#""remove_labels":"vee:gate:block""#), "{put}");
        assert!(!put.contains("team:core"));
    }

    #[test]
    fn reviews_come_from_system_notes_at_the_version_they_followed() {
        let notes = serde_json::json!([
            {"id": 1, "system": true, "body": "approved this merge request", "created_at": "2026-11-26T10:05:00Z", "author": {"username": "vee-bot", "bot": true}},
            {"id": 2, "system": true, "body": "added 1 commit", "created_at": "2026-11-26T10:06:00Z", "author": {"username": "dev"}},
            {"id": 3, "system": true, "body": "unapproved this merge request", "created_at": "2026-11-26T10:08:00Z", "author": {"username": "vee-bot", "bot": true}},
            {"id": 4, "system": false, "body": "approved this merge request", "created_at": "2026-11-26T10:09:00Z", "author": {"username": "dev"}}
        ]);
        let versions = serde_json::json!([
            {"created_at": "2026-11-26T10:07:00Z", "head_commit_sha": "h2"},
            {"created_at": "2026-11-26T10:00:00Z", "head_commit_sha": "h1"}
        ]);
        let (adapter, _) = fake(vec![
            ("GET", "/merge_requests/7/notes", notes.to_string()),
            ("GET", "/merge_requests/7/versions", versions.to_string()),
        ]);
        let reviews = adapter.reviews(&merge_request()).unwrap();
        let summary: Vec<(&str, &str)> = reviews
            .iter()
            .map(|review| (review.state.as_str(), review.commit_id.as_str()))
            .collect();
        assert_eq!(summary, [("APPROVED", "h1"), ("DISMISSED", "h2")]);
    }

    #[test]
    fn approval_names_the_head_and_replies_keep_their_discussion() {
        let (adapter, requests) = fake(vec![
            ("POST", "/merge_requests/7/approve", "{}".into()),
            (
                "POST",
                "/merge_requests/7/discussions",
                r#"{"id": "d9", "notes": [{"id": 90}]}"#.into(),
            ),
            ("POST", "/discussions/d2/notes", r#"{"id": 91}"#.into()),
        ]);
        assert_eq!(
            adapter.approve(&merge_request(), "h2", "why").unwrap(),
            "approval"
        );
        let reply = adapter
            .reply(
                &merge_request(),
                &ReplyTarget::Thread {
                    comment_id: "d2:2".into(),
                },
                "ok",
            )
            .unwrap();
        assert_eq!(reply, "d2:91");
        let requests = requests.lock().unwrap();
        assert!(requests.iter().any(|r| r.starts_with("POST")
            && r.contains("/approve")
            && r.contains(r#""sha":"h2""#)));
        assert!(split_comment_id("not-an-id").is_err());
        assert!(split_comment_id("d/2:1").is_err());
    }
}
