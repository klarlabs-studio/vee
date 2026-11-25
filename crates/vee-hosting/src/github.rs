//! GitHub REST adapter for the provider-neutral hosting port.
//!
//! Check-run creation is available only to GitHub Apps. Configure `token` as
//! an app user or installation access token with Checks write and Pull requests
//! write permissions. This module never logs or serializes credentials.

use crate::*;
use hmac::{Hmac, Mac};
use reqwest::{blocking::Client, header, Method, StatusCode, Url};
use serde::Deserialize;
use sha2::Sha256;
use std::{collections::BTreeMap, io::Read, time::Duration};

type HmacSha256 = Hmac<Sha256>;

const MAX_WORK_ITEM_RESPONSE_BYTES: u64 = 1_048_576;
const MAX_REVIEW_ISSUES_RESPONSE_BYTES: u64 = 5_242_880;
const MAX_GITHUB_JSON_RESPONSE_BYTES: u64 = 8_388_608;
const MAX_GITHUB_ERROR_RESPONSE_BYTES: u64 = 16_384;
// A single 100-item publication page can contain large comment/check bodies.
// Bound it independently from page counts so a hostile host cannot force an
// unbounded allocation during reconciliation.
const MAX_PUBLICATION_PAGE_RESPONSE_BYTES: u64 = 8_388_608;
const MAX_CHECK_RUN_PAGES: u32 = 30;
const CHECK_RUN_PAGE_SIZE: usize = 100;
const MAX_REVIEW_THREAD_PAGES: u32 = 30;

#[derive(Clone)]
pub struct GitHubConfig {
    pub api_base: Url,
    pub token: String,
    pub webhook_secret: String,
    /// Login that owns Vee's comments; prevents editing another user's comment.
    pub actor_login: String,
    pub timeout: Duration,
}

impl GitHubConfig {
    pub fn new(api_base: &str, token: String, webhook_secret: String) -> Result<Self, String> {
        let api_base = Url::parse(api_base).map_err(|error| error.to_string())?;
        if !matches!(api_base.scheme(), "https" | "http")
            || api_base.host_str().is_none()
            || !api_base.username().is_empty()
            || api_base.password().is_some()
            || api_base.query().is_some()
            || api_base.fragment().is_some()
            || token.trim().is_empty()
        {
            return Err("GitHub API URL and token are required".into());
        }
        if api_base.scheme() == "http"
            && !matches!(api_base.host_str(), Some("127.0.0.1" | "localhost" | "::1"))
        {
            return Err("GitHub API URLs must use HTTPS except for loopback test servers".into());
        }
        Ok(Self {
            api_base,
            token,
            webhook_secret,
            actor_login: String::new(),
            timeout: Duration::from_secs(20),
        })
    }

    pub fn with_actor_login(mut self, actor_login: impl Into<String>) -> Self {
        self.actor_login = actor_login.into();
        self
    }
}

pub struct GitHubAdapter {
    config: GitHubConfig,
    client: Client,
}

impl GitHubAdapter {
    pub fn new(config: GitHubConfig) -> Result<Self, String> {
        let client = Client::builder()
            .timeout(config.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| format!("building GitHub client: {error}"))?;
        Ok(Self { config, client })
    }

    fn path(&self, reference: &PullRequestRef, suffix: &str) -> Result<Url, HostingError> {
        reference
            .validate()
            .map_err(HostingError::InvalidResponse)?;
        if !reference
            .repository
            .host
            .eq_ignore_ascii_case(self.config.api_base.host_str().unwrap_or_default())
            && !(reference.repository.host == "github.com"
                && self.config.api_base.host_str() == Some("api.github.com"))
        {
            return Err(HostingError::InvalidResponse(
                "repository host does not match configured GitHub API".into(),
            ));
        }
        let mut url = self.config.api_base.clone();
        let prefix = url.path().trim_end_matches('/');
        let path = format!(
            "{prefix}/repos/{}/pulls/{}{suffix}",
            reference.repository.full_name, reference.number
        );
        url.set_path(&path);
        Ok(url)
    }

    fn request(
        &self,
        method: Method,
        url: Url,
    ) -> Result<reqwest::blocking::RequestBuilder, HostingError> {
        Ok(self
            .client
            .request(method, url)
            .bearer_auth(&self.config.token)
            .header(header::ACCEPT, "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28"))
    }

    fn send(
        &self,
        response: reqwest::blocking::Response,
    ) -> Result<reqwest::blocking::Response, HostingError> {
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }
        let retry_after_seconds = response
            .headers()
            .get(header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse().ok());
        let exhausted_rate_limit = response
            .headers()
            .get("X-RateLimit-Remaining")
            .and_then(|value| value.to_str().ok())
            == Some("0");
        let accepted_permissions = response
            .headers()
            .get("X-Accepted-GitHub-Permissions")
            .and_then(|value| value.to_str().ok())
            .map(clean_diagnostic)
            .filter(|value| !value.is_empty());
        match status {
            StatusCode::NOT_FOUND => Err(HostingError::NotFound),
            StatusCode::UNAUTHORIZED => {
                Err(github_authorization_error(response, accepted_permissions))
            }
            StatusCode::FORBIDDEN if retry_after_seconds.is_some() || exhausted_rate_limit => {
                Err(HostingError::RateLimited {
                    retry_after_seconds,
                })
            }
            StatusCode::FORBIDDEN => {
                Err(github_authorization_error(response, accepted_permissions))
            }
            StatusCode::TOO_MANY_REQUESTS => Err(HostingError::RateLimited {
                retry_after_seconds,
            }),
            StatusCode::CONFLICT | StatusCode::PRECONDITION_FAILED => {
                Err(HostingError::StaleRevision {
                    expected: "requested revision".into(),
                    actual: "provider rejected stale update".into(),
                })
            }
            _ => Err(HostingError::Transport(format!(
                "GitHub returned HTTP {status}"
            ))),
        }
    }

    fn json<T: for<'de> Deserialize<'de>>(
        response: reqwest::blocking::Response,
    ) -> Result<T, HostingError> {
        Self::json_limited(response, MAX_GITHUB_JSON_RESPONSE_BYTES)
    }

    fn json_limited<T: for<'de> Deserialize<'de>>(
        response: reqwest::blocking::Response,
        max_bytes: u64,
    ) -> Result<T, HostingError> {
        if response
            .content_length()
            .is_some_and(|length| length > max_bytes)
        {
            return Err(HostingError::InvalidResponse(format!(
                "GitHub response exceeds the {max_bytes}-byte limit"
            )));
        }
        let mut bytes = Vec::new();
        response
            .take(max_bytes + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                HostingError::InvalidResponse(format!("reading GitHub response body: {error}"))
            })?;
        if bytes.len() as u64 > max_bytes {
            return Err(HostingError::InvalidResponse(format!(
                "GitHub response exceeds the {max_bytes}-byte limit"
            )));
        }
        serde_json::from_slice(&bytes)
            .map_err(|error| HostingError::InvalidResponse(format!("invalid GitHub JSON: {error}")))
    }

    fn verify_signature(
        &self,
        headers: &BTreeMap<String, String>,
        body: &[u8],
    ) -> Result<(), HostingError> {
        if self.config.webhook_secret.is_empty() {
            return Err(HostingError::InvalidResponse(
                "webhook verification is unavailable until a webhook secret is configured".into(),
            ));
        }
        let signature = headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case("x-hub-signature-256"))
            .map(|(_, value)| value.as_str())
            .ok_or_else(|| {
                HostingError::InvalidResponse("missing GitHub webhook signature".into())
            })?;
        let signature = signature.strip_prefix("sha256=").ok_or_else(|| {
            HostingError::InvalidResponse("invalid GitHub webhook signature format".into())
        })?;
        let mut mac = HmacSha256::new_from_slice(self.config.webhook_secret.as_bytes())
            .map_err(|_| HostingError::InvalidResponse("invalid webhook secret".into()))?;
        mac.update(body);
        let expected = decode_hex(signature).ok_or_else(|| {
            HostingError::InvalidResponse("invalid GitHub webhook signature encoding".into())
        })?;
        mac.verify_slice(&expected).map_err(|_| {
            HostingError::InvalidResponse("GitHub webhook signature verification failed".into())
        })
    }

    fn graphql_url(&self) -> Result<Url, HostingError> {
        let mut url = self.config.api_base.clone();
        if url.host_str() == Some("api.github.com") {
            url.set_path("/graphql");
        } else {
            let base = url.path().trim_end_matches('/');
            let root = base.strip_suffix("/api/v3").unwrap_or(base);
            url.set_path(&format!("{root}/api/graphql"));
        }
        Ok(url)
    }

    fn graphql(
        &self,
        query: &str,
        variables: serde_json::Value,
    ) -> Result<serde_json::Value, HostingError> {
        let response = self
            .request(Method::POST, self.graphql_url()?)?
            .json(&serde_json::json!({"query": query, "variables": variables}))
            .send()
            .map_err(|error| HostingError::Transport(format!("calling GitHub GraphQL: {error}")))?;
        let response = self.send(response)?;
        let value: serde_json::Value =
            Self::json_limited(response, MAX_PUBLICATION_PAGE_RESPONSE_BYTES)?;
        if let Some(errors) = value
            .get("errors")
            .and_then(|errors| errors.as_array())
            .filter(|errors| !errors.is_empty())
        {
            return Err(HostingError::InvalidResponse(format!(
                "GitHub GraphQL returned {} error(s)",
                errors.len()
            )));
        }
        Ok(value)
    }

    fn sync_review_thread(
        &self,
        snapshot: &PullRequestSnapshot,
        thread: &ReviewThread,
    ) -> Result<Option<String>, HostingError> {
        if self.config.actor_login.trim().is_empty() {
            return Err(HostingError::InvalidResponse(
                "GitHub actor_login must be configured before publishing review threads".into(),
            ));
        }
        let marker = format!("<!-- vee:fingerprint:{} -->", thread.fingerprint);
        let sanitized_body = thread
            .body_with_suggestion(SuggestionStyle::GitHub)
            .replace("<!-- vee:fingerprint:", "&lt;!-- vee:fingerprint:");
        let body = format!(
            "{}\n\n{}\n<!-- vee:idempotency:{} -->",
            sanitized_body, marker, thread.idempotency_key
        );
        if body.len() > 65_535 {
            return Err(HostingError::InvalidResponse(
                "review thread body exceeds GitHub's comment limit".into(),
            ));
        }
        // (id, path, first line, last line, side) of Vee's comment for this finding.
        let mut existing_comment: Option<(u64, String, u64, u64, String)> = None;
        let mut comment_pages_exhausted = true;
        for page in 1..=30 {
            let mut url = self.path(&thread.pull_request, "/comments")?;
            url.query_pairs_mut()
                .append_pair("per_page", "100")
                .append_pair("page", &page.to_string());
            let response = self.request(Method::GET, url)?.send().map_err(|error| {
                HostingError::Transport(format!("listing review comments: {error}"))
            })?;
            let response = self.send(response)?;
            let comments: Vec<serde_json::Value> =
                Self::json_limited(response, MAX_PUBLICATION_PAGE_RESPONSE_BYTES)?;
            let count = comments.len();
            for comment in comments {
                let owned = comment
                    .get("user")
                    .and_then(|user| user.get("login"))
                    .and_then(|login| login.as_str())
                    .is_some_and(|login| login.eq_ignore_ascii_case(&self.config.actor_login));
                let matches = comment
                    .get("body")
                    .and_then(|value| value.as_str())
                    .is_some_and(|value| value.contains(&marker));
                if owned && matches {
                    let id = comment
                        .get("id")
                        .and_then(|value| value.as_u64())
                        .ok_or_else(|| {
                            HostingError::InvalidResponse("GitHub review comment has no ID".into())
                        })?;
                    let path = comment
                        .get("path")
                        .and_then(|value| value.as_str())
                        .unwrap_or_default()
                        .to_owned();
                    let line = comment
                        .get("line")
                        .filter(|value| !value.is_null())
                        .or_else(|| comment.get("original_line"))
                        .and_then(|value| value.as_u64())
                        .unwrap_or(0);
                    let start_line = comment
                        .get("start_line")
                        .filter(|value| !value.is_null())
                        .or_else(|| comment.get("original_start_line"))
                        .and_then(|value| value.as_u64())
                        .unwrap_or(line);
                    let side = comment
                        .get("side")
                        .and_then(|value| value.as_str())
                        .unwrap_or("RIGHT")
                        .to_owned();
                    existing_comment = Some((id, path, start_line, line, side));
                    break;
                }
            }
            if existing_comment.is_some() || count < 100 {
                comment_pages_exhausted = false;
                break;
            }
        }
        if comment_pages_exhausted {
            return Err(HostingError::InvalidResponse(
                "GitHub review-comment pagination exceeded its 3000-comment reconciliation bound"
                    .into(),
            ));
        }
        let side = match thread.side {
            DiffSide::Old => "LEFT",
            DiffSide::New => "RIGHT",
        };
        // (comment, whether its body is refreshed). A finding that moved keeps
        // no thread: the old one is marked as moved and resolved, and a new
        // comment opens at the new line.
        let reused = match existing_comment {
            Some((id, old_path, old_start, old_end, old_side)) => {
                // A suggestion replaces exactly the lines its comment covers,
                // so a comment over other lines cannot carry it.
                let range_matches = old_start == thread.line
                    && (thread.suggestion.is_none() || old_end == thread.end_line());
                let location_matches = old_path == thread.path && range_matches && old_side == side;
                if location_matches {
                    Some((id, true))
                } else if thread.resolution == ThreadResolution::Resolved {
                    Some((id, false))
                } else {
                    self.retire_moved_comment(thread, id)?;
                    None
                }
            }
            None if thread.resolution == ThreadResolution::Resolved => return Ok(None),
            None => None,
        };
        let comment_id = match reused {
            Some((id, false)) => id,
            Some((id, true)) => self.update_comment_body(&thread.pull_request, id, &body)?,
            None => {
                let url = self.path(&thread.pull_request, "/comments")?;
                let mut comment = serde_json::json!({
                    "body": body, "commit_id": snapshot.head_oid, "path": thread.path,
                    "line": thread.end_line(), "side": side
                });
                if thread.end_line() > thread.line {
                    comment["start_line"] = thread.line.into();
                    comment["start_side"] = side.into();
                }
                let response = self
                    .request(Method::POST, url)?
                    .json(&comment)
                    .send()
                    .map_err(|error| {
                        HostingError::Transport(format!("creating review comment: {error}"))
                    })?;
                let response = self.send(response)?;
                let created: serde_json::Value = Self::json(response)?;
                created
                    .get("id")
                    .and_then(|value| value.as_u64())
                    .ok_or_else(|| {
                        HostingError::InvalidResponse("created GitHub comment has no ID".into())
                    })?
            }
        };
        let should_resolve = thread.resolution == ThreadResolution::Resolved;
        let thread_id =
            self.reconcile_resolution(&thread.pull_request, comment_id, should_resolve)?;
        Ok(Some(thread_id))
    }

    /// Replace the body of one of Vee's review comments.
    fn update_comment_body(
        &self,
        pull_request: &PullRequestRef,
        id: u64,
        body: &str,
    ) -> Result<u64, HostingError> {
        let url = self
            .config
            .api_base
            .join(&format!(
                "repos/{}/pulls/comments/{id}",
                pull_request.repository.full_name
            ))
            .map_err(|error| HostingError::InvalidResponse(error.to_string()))?;
        let response = self
            .request(Method::PATCH, url)?
            .json(&serde_json::json!({"body": body}))
            .send()
            .map_err(|error| {
                HostingError::Transport(format!("updating review comment: {error}"))
            })?;
        let response = self.send(response)?;
        let updated: serde_json::Value = Self::json(response)?;
        updated
            .get("id")
            .and_then(|value| value.as_u64())
            .ok_or_else(|| HostingError::InvalidResponse("updated GitHub comment has no ID".into()))
    }

    /// GitHub cannot move a review comment. The old one says where the finding
    /// went and loses its fingerprint marker, so later publications no longer
    /// match it, and its thread is resolved.
    fn retire_moved_comment(&self, thread: &ReviewThread, id: u64) -> Result<(), HostingError> {
        let body = format!(
            "Vee now reports this finding at `{}` line {}; see the thread there.\n<!-- vee:moved:{} -->",
            thread.path, thread.line, thread.fingerprint
        );
        self.update_comment_body(&thread.pull_request, id, &body)?;
        self.reconcile_resolution(&thread.pull_request, id, true)?;
        Ok(())
    }

    /// Resolve or reopen the review thread holding Vee's comment `comment_id`,
    /// returning the thread's node ID.
    fn reconcile_resolution(
        &self,
        pull_request: &PullRequestRef,
        comment_id: u64,
        should_resolve: bool,
    ) -> Result<String, HostingError> {
        let owner = pull_request
            .repository
            .full_name
            .split('/')
            .next()
            .unwrap_or_default();
        let name = pull_request
            .repository
            .full_name
            .split('/')
            .nth(1)
            .unwrap_or_default();
        let query = "query($owner:String!,$name:String!,$number:Int!,$after:String){repository(owner:$owner,name:$name){pullRequest(number:$number){reviewThreads(first:100,after:$after){nodes{id isResolved comments(first:100){nodes{databaseId body author{login}}}} pageInfo{hasNextPage endCursor}}}}}";
        let mut after: Option<String> = None;
        let mut page_count = 0;
        let target = loop {
            page_count += 1;
            if page_count > MAX_REVIEW_THREAD_PAGES {
                return Err(HostingError::InvalidResponse(
                    "GitHub review-thread pagination exceeded its 3000-thread reconciliation bound"
                        .into(),
                ));
            }
            let data = self.graphql(
                query,
                serde_json::json!({"owner":owner,"name":name,"number":pull_request.number,"after":after}),
            )?;
            let connection = data
                .pointer("/data/repository/pullRequest/reviewThreads")
                .ok_or_else(|| {
                    HostingError::InvalidResponse(
                        "GitHub GraphQL response omitted review threads".into(),
                    )
                })?;
            let nodes = connection
                .get("nodes")
                .and_then(|nodes| nodes.as_array())
                .ok_or_else(|| {
                    HostingError::InvalidResponse(
                        "GitHub GraphQL response contained invalid review threads".into(),
                    )
                })?;
            if let Some(target) = nodes.iter().find(|node| {
                node.get("comments")
                    .and_then(|v| v.get("nodes"))
                    .and_then(|v| v.as_array())
                    .is_some_and(|comments| {
                        comments.iter().any(|comment| {
                            comment.get("databaseId").and_then(|v| v.as_u64()) == Some(comment_id)
                                && comment
                                    .get("author")
                                    .and_then(|v| v.get("login"))
                                    .and_then(|v| v.as_str())
                                    .is_some_and(|login| {
                                        login.eq_ignore_ascii_case(&self.config.actor_login)
                                    })
                        })
                    })
            }) {
                break target.clone();
            }
            let page_info = connection.get("pageInfo").ok_or_else(|| {
                HostingError::InvalidResponse(
                    "GitHub GraphQL response omitted review thread pagination".into(),
                )
            })?;
            if !page_info
                .get("hasNextPage")
                .and_then(|value| value.as_bool())
                .unwrap_or(false)
            {
                return Err(HostingError::InvalidResponse(
                    "GitHub did not return the published review thread".into(),
                ));
            }
            after = Some(
                page_info
                    .get("endCursor")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| {
                        HostingError::InvalidResponse(
                            "GitHub review thread page omitted its cursor".into(),
                        )
                    })?
                    .to_owned(),
            );
        };
        let thread_id = target
            .get("id")
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                HostingError::InvalidResponse("GitHub review thread has no node ID".into())
            })?
            .to_owned();
        let is_resolved = target
            .get("isResolved")
            .and_then(|value| value.as_bool())
            .unwrap_or(false);
        if is_resolved != should_resolve {
            let (mutation, operation) = if should_resolve {
                ("resolveReviewThread", "resolveReviewThread")
            } else {
                ("unresolveReviewThread", "unresolveReviewThread")
            };
            let query = format!("mutation($threadId:ID!){{{mutation}(input:{{threadId:$threadId}}){{thread{{id isResolved}}}}}}");
            let result = self.graphql(&query, serde_json::json!({"threadId":thread_id}))?;
            if result
                .pointer(&format!("/data/{operation}/thread/isResolved"))
                .and_then(|value| value.as_bool())
                != Some(should_resolve)
            {
                return Err(HostingError::InvalidResponse(
                    "GitHub did not apply requested thread resolution".into(),
                ));
            }
        }
        Ok(thread_id)
    }
}

fn github_authorization_error(
    response: reqwest::blocking::Response,
    required_permissions: Option<String>,
) -> HostingError {
    let detail = (|| {
        let mut bytes = Vec::new();
        response
            .take(MAX_GITHUB_ERROR_RESPONSE_BYTES + 1)
            .read_to_end(&mut bytes)
            .ok()?;
        if bytes.len() as u64 > MAX_GITHUB_ERROR_RESPONSE_BYTES {
            return None;
        }
        let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
        value
            .get("message")
            .and_then(serde_json::Value::as_str)
            .map(clean_diagnostic)
            .filter(|message| !message.is_empty())
    })();
    HostingError::AuthorizationDenied {
        provider: "GitHub".into(),
        detail,
        required_permissions,
    }
}

fn clean_diagnostic(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(240)
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

impl GitHostingProvider for GitHubAdapter {
    fn provider_id(&self) -> &'static str {
        "github"
    }

    fn get_pull_request(
        &self,
        reference: &PullRequestRef,
    ) -> Result<PullRequestSnapshot, HostingError> {
        #[derive(Deserialize)]
        struct ApiPr {
            number: u64,
            title: String,
            body: Option<String>,
            state: String,
            merged: bool,
            base: ApiBranch,
            head: ApiBranch,
        }
        #[derive(Deserialize)]
        struct ApiBranch {
            sha: String,
        }
        let url = self.path(reference, "")?;
        let response = self.request(Method::GET, url)?.send().map_err(|error| {
            HostingError::Transport(format!("requesting pull request: {error}"))
        })?;
        let response = self.send(response)?;
        let revision = response
            .headers()
            .get(header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let revision = revision.unwrap_or_else(|| "".into());
        let api: ApiPr = Self::json(response)?;
        if api.number != reference.number {
            return Err(HostingError::InvalidResponse(
                "GitHub returned a different pull request".into(),
            ));
        }
        let state = if api.merged {
            PullRequestState::Merged
        } else if api.state == "open" {
            PullRequestState::Open
        } else {
            PullRequestState::Closed
        };
        let computed_revision = format!("{}:{}", api.base.sha, api.head.sha);
        Ok(PullRequestSnapshot {
            pull_request: reference.clone(),
            base_oid: api.base.sha,
            head_oid: api.head.sha,
            title: api.title,
            body: api.body,
            state,
            revision: if revision.is_empty() {
                computed_revision
            } else {
                format!("{revision}:{}", computed_revision)
            },
        })
    }

    fn list_changed_files(
        &self,
        reference: &PullRequestRef,
        expected_revision: &str,
    ) -> Result<Vec<PullRequestFile>, HostingError> {
        #[derive(Deserialize)]
        struct ApiFile {
            filename: String,
            status: String,
            previous_filename: Option<String>,
            patch: Option<String>,
            additions: u64,
            deletions: u64,
        }
        let snapshot = GitHostingProvider::get_pull_request(self, reference)?;
        if snapshot.revision != expected_revision {
            return Err(HostingError::StaleRevision {
                expected: expected_revision.into(),
                actual: snapshot.revision,
            });
        }
        let mut files = Vec::new();
        for page in 1..=30 {
            let mut url = self.path(reference, "/files")?;
            url.query_pairs_mut()
                .append_pair("per_page", "100")
                .append_pair("page", &page.to_string());
            let response = self.request(Method::GET, url)?.send().map_err(|error| {
                HostingError::Transport(format!("listing pull request files: {error}"))
            })?;
            let response = self.send(response)?;
            let batch: Vec<ApiFile> = Self::json(response)?;
            let count = batch.len();
            files.extend(batch.into_iter().map(|file| PullRequestFile {
                path: file.filename,
                change: match file.status.as_str() {
                    "added" => FileChange::Added,
                    "removed" => FileChange::Deleted,
                    "renamed" => FileChange::Renamed,
                    "copied" => FileChange::Copied,
                    _ => FileChange::Modified,
                },
                previous_path: file.previous_filename,
                patch: file.patch,
                additions: file.additions,
                deletions: file.deletions,
            }));
            if count < 100 {
                return Ok(files);
            }
        }
        Err(HostingError::InvalidResponse(
            "pull request exceeds the 3000-file API limit".into(),
        ))
    }

    fn publish_review(
        &self,
        publication: ReviewPublication,
    ) -> Result<PublicationReceipt, HostingError> {
        publication
            .validate()
            .map_err(HostingError::InvalidResponse)?;
        let snapshot = GitHostingProvider::get_pull_request(self, &publication.pull_request)?;
        if snapshot.revision != publication.expected_revision {
            return Err(HostingError::StaleRevision {
                expected: publication.expected_revision,
                actual: snapshot.revision,
            });
        }
        let url = self
            .config
            .api_base
            .join(&format!(
                "repos/{}/check-runs",
                publication.pull_request.repository.full_name
            ))
            .map_err(|error| HostingError::InvalidResponse(error.to_string()))?;
        let head_sha = snapshot.head_oid.clone();
        let conclusion = publication.check.conclusion.map(|value| match value {
            CheckConclusion::Success => "success",
            CheckConclusion::Failure => "failure",
            CheckConclusion::Neutral => "neutral",
            CheckConclusion::Cancelled => "cancelled",
            CheckConclusion::TimedOut => "timed_out",
            CheckConclusion::ActionRequired => "action_required",
        });
        let status = match publication.check.status {
            CheckStatus::Queued => "queued",
            CheckStatus::InProgress => "in_progress",
            CheckStatus::Completed => "completed",
        };
        let mut body = serde_json::json!({
            "name": publication.check.name,
            "head_sha": head_sha,
            "external_id": publication.check.idempotency_key,
            "status": status,
            "output": { "title": publication.check.title, "summary": publication.check.summary }
        });
        if let Some(conclusion) = conclusion {
            body["conclusion"] = serde_json::json!(conclusion);
        }
        #[derive(Deserialize)]
        struct ApiCheck {
            id: u64,
        }
        let existing_url = self
            .config
            .api_base
            .join(&format!(
                "repos/{}/commits/{head_sha}/check-runs",
                publication.pull_request.repository.full_name
            ))
            .map_err(|error| HostingError::InvalidResponse(error.to_string()))?;
        let mut existing_id = None;
        let mut check_pages_exhausted = true;
        for page in 1..=MAX_CHECK_RUN_PAGES {
            let mut page_url = existing_url.clone();
            page_url
                .query_pairs_mut()
                .append_pair("filter", "all")
                .append_pair("per_page", &CHECK_RUN_PAGE_SIZE.to_string())
                .append_pair("page", &page.to_string());
            let response = self
                .request(Method::GET, page_url)?
                .send()
                .map_err(|error| {
                    HostingError::Transport(format!("looking up check run: {error}"))
                })?;
            let response = self.send(response)?;
            let checks: serde_json::Value =
                Self::json_limited(response, MAX_PUBLICATION_PAGE_RESPONSE_BYTES)?;
            let check_runs = checks
                .get("check_runs")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| {
                    HostingError::InvalidResponse(
                        "GitHub check-run listing omitted check_runs".into(),
                    )
                })?;
            existing_id = check_runs
                .iter()
                .find(|check| {
                    check.get("external_id").and_then(|value| value.as_str())
                        == Some(publication.check.idempotency_key.as_str())
                })
                .and_then(|check| check.get("id"))
                .and_then(serde_json::Value::as_u64);
            if existing_id.is_some() {
                check_pages_exhausted = false;
                break;
            }
            if check_runs.len() < CHECK_RUN_PAGE_SIZE {
                check_pages_exhausted = false;
                break;
            }
        }
        if check_pages_exhausted {
            return Err(HostingError::InvalidResponse(
                "GitHub check-run pagination exceeded its 3000-run search bound".into(),
            ));
        }
        let (request_url, method) = if let Some(id) = existing_id {
            (
                self.config
                    .api_base
                    .join(&format!(
                        "repos/{}/check-runs/{id}",
                        publication.pull_request.repository.full_name
                    ))
                    .map_err(|error| HostingError::InvalidResponse(error.to_string()))?,
                Method::PATCH,
            )
        } else {
            (url, Method::POST)
        };
        let response = self
            .request(method, request_url)?
            .json(&body)
            .send()
            .map_err(|error| HostingError::Transport(format!("publishing check run: {error}")))?;
        let response = self.send(response)?;
        let check: ApiCheck = Self::json(response)?;
        let mut thread_ids = BTreeMap::new();
        if !publication.threads.is_empty() {
            let before_threads =
                GitHostingProvider::get_pull_request(self, &publication.pull_request)?;
            if before_threads.revision != publication.expected_revision {
                return Err(HostingError::StaleRevision {
                    expected: publication.expected_revision,
                    actual: before_threads.revision,
                });
            }
        }
        for thread in &publication.threads {
            if let Some(thread_id) = self.sync_review_thread(&snapshot, thread)? {
                thread_ids.insert(thread.fingerprint.clone(), thread_id);
            }
        }
        let resulting_snapshot =
            GitHostingProvider::get_pull_request(self, &publication.pull_request)?;
        if resulting_snapshot.revision != publication.expected_revision {
            return Err(HostingError::StaleRevision {
                expected: publication.expected_revision,
                actual: resulting_snapshot.revision,
            });
        }
        Ok(PublicationReceipt {
            provider_check_id: check.id.to_string(),
            thread_ids,
            resulting_revision: publication.expected_revision,
        })
    }

    fn verify_webhook(
        &self,
        headers: &BTreeMap<String, String>,
        body: &[u8],
    ) -> Result<WebhookEnvelope, HostingError> {
        self.verify_signature(headers, body)?;
        #[derive(Deserialize)]
        struct HookPr {
            number: u64,
            base: HookBranch,
            head: HookHead,
        }
        #[derive(Deserialize)]
        struct HookBranch {
            sha: String,
            repo: HookRepo,
        }
        #[derive(Deserialize)]
        struct HookHead {
            sha: String,
        }
        #[derive(Deserialize)]
        struct HookRepo {
            full_name: String,
            html_url: String,
        }
        let payload: serde_json::Value = serde_json::from_slice(body).map_err(|error| {
            HostingError::InvalidResponse(format!("invalid webhook JSON: {error}"))
        })?;
        let event_id = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("x-github-delivery"))
            .map(|(_, v)| v.clone())
            .ok_or_else(|| HostingError::InvalidResponse("missing GitHub delivery ID".into()))?;
        let event_type = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("x-github-event"))
            .map(|(_, v)| v.clone())
            .ok_or_else(|| HostingError::InvalidResponse("missing GitHub event type".into()))?;
        let hook_pr = serde_json::from_value::<HookPr>(
            payload
                .get("pull_request")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        )
        .ok();
        let action = payload
            .get("action")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        let (pull_request, base_oid, head_oid) = hook_pr
            .map(|pr| {
                let html_url = pr.base.repo.html_url;
                let host = Url::parse(&html_url)
                    .ok()
                    .and_then(|url| url.host_str().map(str::to_owned))
                    .unwrap_or_else(|| "github.com".into());
                let full_name = pr.base.repo.full_name;
                (
                    PullRequestRef {
                        repository: RepositoryRef { host, full_name },
                        number: pr.number,
                    },
                    Some(pr.base.sha),
                    Some(pr.head.sha),
                )
            })
            .map_or((None, None, None), |(reference, base, head)| {
                (Some(reference), base, head)
            });
        let envelope = WebhookEnvelope {
            provider: "github".into(),
            event_id,
            event_type,
            delivery_attempt: 1,
            pull_request,
            action,
            base_oid,
            head_oid,
            signature_verified: true,
        };
        envelope.validate().map_err(HostingError::InvalidResponse)?;
        Ok(envelope)
    }
}

impl PullRequestReviewIssuesProvider for GitHubAdapter {
    fn list_pull_request_review_issues(
        &self,
        reference: &PullRequestRef,
    ) -> Result<PullRequestReviewIssues, HostingError> {
        #[derive(Deserialize)]
        struct ApiComment {
            id: u64,
            user: Option<ApiUser>,
            body: Option<String>,
            path: Option<String>,
            line: Option<u64>,
            side: Option<String>,
            html_url: Option<String>,
            created_at: Option<String>,
            updated_at: Option<String>,
        }
        #[derive(Deserialize)]
        struct ApiUser {
            login: String,
        }

        let before = GitHostingProvider::get_pull_request(self, reference)?;
        let mut issues = Vec::new();
        let mut aggregate_text_bytes = 0usize;
        let mut complete = false;
        for page in 1..=30 {
            let mut url = self.path(reference, "/comments")?;
            url.query_pairs_mut()
                .append_pair("per_page", "100")
                .append_pair("page", &page.to_string());
            let response = self.request(Method::GET, url)?.send().map_err(|error| {
                HostingError::Transport(format!("listing GitHub review issues: {error}"))
            })?;
            let response = self.send(response)?;
            let comments: Vec<ApiComment> =
                Self::json_limited(response, MAX_REVIEW_ISSUES_RESPONSE_BYTES)?;
            let count = comments.len();
            for comment in comments {
                let body = comment.body.unwrap_or_default();
                aggregate_text_bytes = aggregate_text_bytes
                    .saturating_add(body.len())
                    .saturating_add(comment.path.as_deref().map_or(0, str::len))
                    .saturating_add(comment.html_url.as_deref().map_or(0, str::len))
                    .saturating_add(comment.created_at.as_deref().map_or(0, str::len))
                    .saturating_add(comment.updated_at.as_deref().map_or(0, str::len))
                    .saturating_add(comment.user.as_ref().map_or(0, |user| user.login.len()));
                if aggregate_text_bytes > MAX_REVIEW_ISSUES_RESPONSE_BYTES as usize {
                    return Err(HostingError::InvalidResponse(
                        "GitHub review issues exceed the 5 MiB aggregate text limit".into(),
                    ));
                }
                issues.push(PullRequestReviewIssue {
                    external_id: comment.id.to_string(),
                    author: comment.user.map(|user| user.login),
                    body,
                    path: comment.path,
                    line: comment.line,
                    side: match comment.side.as_deref() {
                        Some("LEFT") => Some(DiffSide::Old),
                        Some("RIGHT") => Some(DiffSide::New),
                        _ => None,
                    },
                    source_url: comment.html_url,
                    created_at: comment.created_at,
                    updated_at: comment.updated_at,
                    classification: "untrusted_external_review".into(),
                });
            }
            if count < 100 {
                complete = true;
                break;
            }
        }
        let after = GitHostingProvider::get_pull_request(self, reference)?;
        if before.revision != after.revision {
            return Err(HostingError::StaleRevision {
                expected: before.revision,
                actual: after.revision,
            });
        }
        Ok(PullRequestReviewIssues {
            schema_version: 1,
            provider: "github".into(),
            pull_request: reference.clone(),
            revision: before.revision,
            complete,
            gate_eligible: false,
            issues,
        })
    }
}

impl WorkItemProvider for GitHubAdapter {
    fn work_item_provider_id(&self) -> &'static str {
        "github"
    }

    fn get_work_item(&self, reference: &WorkItemRef) -> Result<WorkItemSnapshot, HostingError> {
        reference
            .validate()
            .map_err(HostingError::InvalidResponse)?;
        if !reference
            .repository
            .host
            .eq_ignore_ascii_case(self.config.api_base.host_str().unwrap_or_default())
            && !(reference.repository.host == "github.com"
                && self.config.api_base.host_str() == Some("api.github.com"))
        {
            return Err(HostingError::InvalidResponse(
                "work item host does not match configured GitHub API".into(),
            ));
        }

        #[derive(Deserialize)]
        struct ApiIssue {
            title: String,
            body: Option<String>,
            html_url: String,
            state: String,
            updated_at: String,
            labels: Vec<ApiLabel>,
        }
        #[derive(Deserialize)]
        struct ApiLabel {
            name: String,
        }

        let mut url = self.config.api_base.clone();
        let prefix = url.path().trim_end_matches('/');
        url.set_path(&format!(
            "{prefix}/repos/{}/issues/{}",
            reference.repository.full_name, reference.number
        ));
        let response = self
            .request(Method::GET, url)?
            .send()
            .map_err(|error| HostingError::Transport(format!("requesting work item: {error}")))?;
        let api: ApiIssue = Self::json_limited(self.send(response)?, MAX_WORK_ITEM_RESPONSE_BYTES)?;
        let item_url = Url::parse(&api.html_url)
            .map_err(|error| HostingError::InvalidResponse(error.to_string()))?;
        let expected_path = format!(
            "/{}/issues/{}",
            reference.repository.full_name, reference.number
        );
        if item_url.scheme() != "https"
            || !item_url
                .host_str()
                .is_some_and(|host| host.eq_ignore_ascii_case(&reference.repository.host))
            || item_url.path() != expected_path
            || item_url.query().is_some()
            || item_url.fragment().is_some()
        {
            return Err(HostingError::InvalidResponse(
                "GitHub returned a work item URL outside the requested repository".into(),
            ));
        }
        let mut labels = api
            .labels
            .into_iter()
            .map(|label| label.name)
            .collect::<Vec<_>>();
        labels.sort();
        let mut snapshot = WorkItemSnapshot {
            schema_version: 1,
            reference: reference.clone(),
            provider: self.work_item_provider_id().into(),
            api_base: self.config.api_base.to_string(),
            title: api.title,
            body: api.body,
            acceptance_criteria: None,
            url: api.html_url,
            state: api.state,
            updated_at: api.updated_at,
            labels,
            content_digest: String::new(),
        };
        snapshot.content_digest = work_item_digest(&snapshot);
        snapshot.validate().map_err(HostingError::InvalidResponse)?;
        Ok(snapshot)
    }
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.len() != 64 {
        return None;
    }
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    type FixtureResponse = (u16, Vec<(String, String)>, String);

    fn stable_pr_response() -> FixtureResponse {
        (
            200,
            vec![("ETag".into(), "\"rev-1\"".into())],
            r#"{"number":9,"title":"Change","body":null,"state":"open","merged":false,"base":{"sha":"base123"},"head":{"sha":"head456"}}"#.into(),
        )
    }

    fn fixture_server(
        responses: Vec<FixtureResponse>,
    ) -> (String, thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let mut requests = Vec::new();
            for (status, headers, body) in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = Vec::new();
                let mut chunk = [0u8; 1024];
                loop {
                    let count = stream.read(&mut chunk).unwrap();
                    if count == 0 {
                        break;
                    }
                    request.extend_from_slice(&chunk[..count]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                let header_end = request
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .unwrap()
                    + 4;
                let headers_text = String::from_utf8_lossy(&request[..header_end]);
                let content_length = headers_text
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .unwrap_or(0);
                while request.len() < header_end + content_length {
                    let count = stream.read(&mut chunk).unwrap();
                    if count == 0 {
                        break;
                    }
                    request.extend_from_slice(&chunk[..count]);
                }
                requests.push(String::from_utf8_lossy(&request).to_string());
                if status == 0 {
                    continue;
                }
                let reason = if status == 200 { "OK" } else { "Error" };
                if write!(
                    stream,
                    "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n",
                    body.len()
                )
                .is_err()
                {
                    continue;
                }
                for (name, value) in headers {
                    if write!(stream, "{name}: {value}\r\n").is_err() {
                        continue;
                    }
                }
                let _ = write!(stream, "\r\n{body}");
                let _ = stream.flush();
            }
            requests
        });
        (format!("http://{address}/api/v3/"), worker)
    }

    fn adapter(base: &str) -> GitHubAdapter {
        let config = GitHubConfig::new(
            base,
            "test-token".into(),
            "It's a Secret to Everybody".into(),
        )
        .unwrap();
        GitHubAdapter::new(config).unwrap()
    }

    fn reference(host: &str) -> PullRequestRef {
        PullRequestRef {
            repository: RepositoryRef {
                host: host.into(),
                full_name: "octo/repo".into(),
            },
            number: 9,
        }
    }

    fn work_item_reference(host: &str) -> WorkItemRef {
        WorkItemRef {
            repository: RepositoryRef {
                host: host.into(),
                full_name: "octo/repo".into(),
            },
            number: 9,
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn github_webhook_hmac_matches_official_test_vector_and_rejects_tampering() {
        let config = GitHubConfig::new(
            "http://127.0.0.1:1234/",
            "token".into(),
            "It's a Secret to Everybody".into(),
        )
        .unwrap();
        let adapter = GitHubAdapter::new(config).unwrap();
        let mut headers = BTreeMap::new();
        headers.insert(
            "X-Hub-Signature-256".into(),
            "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17".into(),
        );
        headers.insert("X-GitHub-Delivery".into(), "delivery-1".into());
        headers.insert("X-GitHub-Event".into(), "ping".into());
        adapter
            .verify_signature(&headers, b"Hello, World!")
            .unwrap();
        assert!(adapter.verify_signature(&headers, b"tampered").is_err());
        let payload = br#"{"pull_request":null}"#;
        let mut mac = HmacSha256::new_from_slice(b"It's a Secret to Everybody").unwrap();
        mac.update(payload);
        headers.insert(
            "X-Hub-Signature-256".into(),
            format!("sha256={}", hex(&mac.finalize().into_bytes())),
        );
        let envelope = adapter.verify_webhook(&headers, payload).unwrap();
        assert_eq!(envelope.provider, "github");
        assert_eq!(envelope.event_id, "delivery-1");
        assert!(envelope.signature_verified);
    }

    #[test]
    fn github_work_item_read_returns_digest_bound_source_context() {
        let (base, server) = fixture_server(vec![(
            200,
            vec![],
            r#"{"title":"Add export","body":"Acceptance: preserve the source digest.","html_url":"https://127.0.0.1/octo/repo/issues/9","state":"open","updated_at":"2026-11-14T12:00:00Z","labels":[{"name":"feature"}]}"#.into(),
        )]);
        let adapter = adapter(&base);
        let item =
            WorkItemProvider::get_work_item(&adapter, &work_item_reference("127.0.0.1")).unwrap();
        item.validate().unwrap();
        assert_eq!(item.title, "Add export");
        assert_eq!(
            item.body.as_deref(),
            Some("Acceptance: preserve the source digest.")
        );
        assert_eq!(item.labels, vec!["feature"]);
        assert_eq!(item.content_digest, work_item_digest(&item));
        let requests = server.join().unwrap();
        assert!(requests[0].starts_with("GET /api/v3/repos/octo/repo/issues/9 HTTP/1.1"));
        assert!(requests[0]
            .to_ascii_lowercase()
            .contains("authorization: bearer test-token"));
    }

    #[test]
    fn github_pr_review_issues_are_revision_bound_and_gate_ineligible() {
        let pr = r#"{"number":9,"title":"Improve retry handling","body":null,"state":"open","merged":false,"base":{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"head":{"sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}"#;
        let (base, server) = fixture_server(vec![
            (200, vec![], pr.into()),
            (200, vec![], r#"[{"id":42,"user":{"login":"reviewer"},"body":"Handle timeout before retrying","path":"src/retry.rs","line":18,"side":"RIGHT","html_url":"https://github.com/octo/repo/pull/9#discussion_r42","created_at":"2026-11-15T10:00:00Z","updated_at":"2026-11-15T10:05:00Z"}]"#.into()),
            (200, vec![], pr.into()),
        ]);
        let adapter = adapter(&base);
        let issues = adapter
            .list_pull_request_review_issues(&reference("127.0.0.1"))
            .unwrap();
        assert!(issues.complete);
        assert!(!issues.gate_eligible);
        assert_eq!(issues.issues.len(), 1);
        assert_eq!(issues.issues[0].external_id, "42");
        assert_eq!(issues.issues[0].author.as_deref(), Some("reviewer"));
        assert_eq!(issues.issues[0].path.as_deref(), Some("src/retry.rs"));
        assert_eq!(issues.issues[0].line, Some(18));
        assert_eq!(issues.issues[0].side, Some(DiffSide::New));
        assert_eq!(issues.issues[0].classification, "untrusted_external_review");
        let requests = server.join().unwrap();
        assert!(requests[0].starts_with("GET /api/v3/repos/octo/repo/pulls/9 HTTP/1.1"));
        assert!(requests[1].starts_with(
            "GET /api/v3/repos/octo/repo/pulls/9/comments?per_page=100&page=1 HTTP/1.1"
        ));
        assert!(requests[2].starts_with("GET /api/v3/repos/octo/repo/pulls/9 HTTP/1.1"));
    }

    #[test]
    fn github_pr_review_issues_enforce_aggregate_text_limit_across_pages() {
        let pr = r#"{"number":9,"title":"Review","body":null,"state":"open","merged":false,"base":{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"head":{"sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}"#;
        let page = |start: u64, count: usize| {
            let comments = (start..start + count as u64)
                .map(|id| {
                    serde_json::json!({
                        "id": id,
                        "user": { "login": "reviewer" },
                        "body": "x".repeat(30_000),
                        "path": "src/main.rs",
                        "line": 12,
                        "side": "RIGHT"
                    })
                })
                .collect::<Vec<_>>();
            serde_json::to_string(&comments).unwrap()
        };
        let (base, server) = fixture_server(vec![
            (200, vec![], pr.into()),
            (200, vec![], page(1, 100)),
            (200, vec![], page(101, 99)),
        ]);
        let adapter = adapter(&base);

        let error = adapter
            .list_pull_request_review_issues(&reference("127.0.0.1"))
            .unwrap_err();

        assert!(
            matches!(error, HostingError::InvalidResponse(message) if message.contains("aggregate text limit"))
        );
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 3);
        assert!(requests[1].starts_with(
            "GET /api/v3/repos/octo/repo/pulls/9/comments?per_page=100&page=1 HTTP/1.1"
        ));
        assert!(requests[2].starts_with(
            "GET /api/v3/repos/octo/repo/pulls/9/comments?per_page=100&page=2 HTTP/1.1"
        ));
    }

    #[test]
    fn github_pr_review_issue_page_bound_is_reported_as_incomplete() {
        let pr = r#"{"number":9,"title":"Review","body":null,"state":"open","merged":false,"base":{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"head":{"sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}"#;
        let mut responses = vec![(200, vec![], pr.to_owned())];
        for page in 0..30 {
            let comments = (0..100)
                .map(|item| {
                    serde_json::json!({
                        "id": page * 100 + item,
                        "body": "bounded comment",
                        "user": {"login": "reviewer"}
                    })
                })
                .collect::<Vec<_>>();
            responses.push((200, vec![], serde_json::to_string(&comments).unwrap()));
        }
        responses.push((200, vec![], pr.to_owned()));
        let (base, server) = fixture_server(responses);
        let adapter = adapter(&base);
        let report = adapter
            .list_pull_request_review_issues(&reference("127.0.0.1"))
            .unwrap();
        assert!(!report.complete);
        assert!(!report.gate_eligible);
        assert_eq!(report.issues.len(), 3_000);
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 32);
        assert!(requests[30].starts_with(
            "GET /api/v3/repos/octo/repo/pulls/9/comments?per_page=100&page=30 HTTP/1.1"
        ));
    }

    #[test]
    fn github_work_item_response_is_size_bounded_before_json_parsing() {
        let body = format!("{{\"padding\":\"{}\"}}", "x".repeat(1_048_576));
        let (base, server) = fixture_server(vec![(200, vec![], body)]);
        let adapter = adapter(&base);
        let error = WorkItemProvider::get_work_item(&adapter, &work_item_reference("127.0.0.1"))
            .unwrap_err();
        assert!(
            matches!(error, HostingError::InvalidResponse(message) if message.contains("exceeds"))
        );
        server.join().unwrap();
    }

    #[test]
    fn github_authorization_error_reports_required_permissions_and_sanitized_detail() {
        let (base, server) = fixture_server(vec![(
            403,
            vec![(
                "X-Accepted-GitHub-Permissions".into(),
                "checks=write;pull_requests=write".into(),
            )],
            r#"{"message":"Resource not accessible by integration\n\u001b[31m"}"#.into(),
        )]);
        let adapter = adapter(&base);
        let error = adapter
            .request(Method::GET, adapter.config.api_base.clone())
            .unwrap()
            .send()
            .unwrap();
        let error = adapter.send(error).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("Resource not accessible by integration"));
        assert!(message.contains("checks=write;pull_requests=write"));
        assert!(!message.contains('\u{001b}'));
        assert!(!message.contains("test-token"));
        server.join().unwrap();
    }

    #[test]
    fn github_api_redirect_is_not_followed_or_forwarded_with_credentials() {
        let (base, server) = fixture_server(vec![(
            302,
            vec![(
                "Location".into(),
                "https://credential-capture.invalid/collect".into(),
            )],
            String::new(),
        )]);
        let adapter = adapter(&base);
        let response = adapter
            .request(Method::GET, adapter.config.api_base.clone())
            .unwrap()
            .send()
            .expect("the adapter should return the redirect response without following it");

        assert_eq!(response.status(), StatusCode::FOUND);
        let error = adapter.send(response).unwrap_err();
        assert!(error.to_string().contains("HTTP 302"));
        assert!(!error.to_string().contains("test-token"));
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0]
            .to_ascii_lowercase()
            .contains("authorization: bearer test-token"));
    }

    #[test]
    fn github_oversized_authorization_error_does_not_return_unbounded_body() {
        let body = format!(
            "{{\"message\":\"{}\"}}",
            "x".repeat(MAX_GITHUB_ERROR_RESPONSE_BYTES as usize)
        );
        let (base, server) = fixture_server(vec![(403, vec![], body)]);
        let adapter = adapter(&base);
        let response = adapter
            .request(Method::GET, adapter.config.api_base.clone())
            .unwrap()
            .send()
            .unwrap();
        let error = adapter.send(response).unwrap_err();

        assert!(matches!(
            error,
            HostingError::AuthorizationDenied { detail: None, .. }
        ));
        assert!(error.to_string().len() < 300);
        server.join().unwrap();
    }

    #[test]
    fn github_pull_request_and_file_reads_bind_to_current_revision() {
        let (base, server) = fixture_server(vec![
            (
                200,
                vec![("ETag".into(), "\"rev-1\"".into())],
                r#"{"number":9,"title":"Change","body":null,"state":"open","merged":false,"base":{"sha":"base123"},"head":{"sha":"head456"}}"#.into(),
            ),
            (
                200,
                vec![("ETag".into(), "\"rev-1\"".into())],
                r#"{"number":9,"title":"Change","body":null,"state":"open","merged":false,"base":{"sha":"base123"},"head":{"sha":"head456"}}"#.into(),
            ),
            (
                200,
                vec![],
                r#"[{"filename":"src/new.rs","status":"renamed","previous_filename":"src/old.rs","patch":"@@ -1 +1 @@","additions":1,"deletions":1}]"#.into(),
            ),
        ]);
        let adapter = adapter(&base);
        let reference = reference("127.0.0.1");
        let snapshot = adapter.get_pull_request(&reference).unwrap();
        assert_eq!(snapshot.revision, "\"rev-1\":base123:head456");
        assert_eq!(snapshot.state, PullRequestState::Open);
        let files = adapter
            .list_changed_files(&reference, &snapshot.revision)
            .unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].change, FileChange::Renamed);
        assert_eq!(files[0].previous_path.as_deref(), Some("src/old.rs"));
        let requests = server.join().unwrap();
        assert!(requests[0].starts_with("GET /api/v3/repos/octo/repo/pulls/9 HTTP/1.1"));
        assert!(requests[0]
            .to_ascii_lowercase()
            .contains("authorization: bearer test-token"));
        assert!(requests[1].starts_with("GET /api/v3/repos/octo/repo/pulls/9 HTTP/1.1"));
        assert!(requests[2]
            .starts_with("GET /api/v3/repos/octo/repo/pulls/9/files?per_page=100&page=1 HTTP/1.1"));
    }

    #[test]
    fn github_changed_file_page_is_size_bounded_before_json_parsing() {
        let pr = r#"{"number":9,"title":"Change","body":null,"state":"open","merged":false,"base":{"sha":"base123"},"head":{"sha":"head456"}}"#;
        let body = format!(
            "[{{\"padding\":\"{}\"}}]",
            "x".repeat(MAX_GITHUB_JSON_RESPONSE_BYTES as usize)
        );
        let (base, server) = fixture_server(vec![(200, vec![], pr.into()), (200, vec![], body)]);
        let adapter = adapter(&base);
        let error = adapter
            .list_changed_files(&reference("127.0.0.1"), "base123:head456")
            .unwrap_err();

        assert!(
            matches!(&error, HostingError::InvalidResponse(message) if message.contains("exceeds")),
            "unexpected error: {error:?}"
        );
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests[1]
            .starts_with("GET /api/v3/repos/octo/repo/pulls/9/files?per_page=100&page=1 HTTP/1.1"));
    }

    #[test]
    fn github_diff_read_rejects_stale_revision_before_fetching_files() {
        let (base, server) = fixture_server(vec![(
            200,
            vec![],
            r#"{"number":9,"title":"Change","body":null,"state":"open","merged":false,"base":{"sha":"base123"},"head":{"sha":"head456"}}"#.into(),
        )]);
        let adapter = adapter(&base);
        let error = adapter
            .list_changed_files(&reference("127.0.0.1"), "old-revision")
            .unwrap_err();
        assert!(matches!(error, HostingError::StaleRevision { .. }));
        assert_eq!(server.join().unwrap().len(), 1);
    }

    #[test]
    fn github_check_publication_updates_existing_idempotency_key() {
        let revision = "\"rev-1\":base123:head456";
        let (base, server) = fixture_server(vec![
            (
                200,
                vec![("ETag".into(), "\"rev-1\"".into())],
                r#"{"number":9,"title":"Change","body":null,"state":"open","merged":false,"base":{"sha":"base123"},"head":{"sha":"head456"}}"#.into(),
            ),
            (
                200,
                vec![],
                r#"{"check_runs":[{"id":123,"external_id":"review:sha256:abc"}]}"#.into(),
            ),
            (200, vec![], r#"{"id":123}"#.into()),
            (
                200,
                vec![("ETag".into(), "\"rev-1\"".into())],
                r#"{"number":9,"title":"Change","body":null,"state":"open","merged":false,"base":{"sha":"base123"},"head":{"sha":"head456"}}"#.into(),
            ),
        ]);
        let adapter = adapter(&base);
        let pull_request = reference("127.0.0.1");
        let publication = ReviewPublication {
            pull_request: pull_request.clone(),
            expected_revision: revision.into(),
            check: CheckRun {
                pull_request,
                external_id: "review-1".into(),
                name: "Vee assurance".into(),
                status: CheckStatus::Completed,
                conclusion: Some(CheckConclusion::Failure),
                title: "Review blocked".into(),
                summary: "High severity finding".into(),
                snapshot_id: "sha256:abc".into(),
                idempotency_key: "review:sha256:abc".into(),
            },
            threads: vec![],
        };
        let receipt = adapter.publish_review(publication).unwrap();
        assert_eq!(receipt.provider_check_id, "123");
        assert_eq!(receipt.resulting_revision, revision);
        let requests = server.join().unwrap();
        assert!(requests[1].starts_with(
            "GET /api/v3/repos/octo/repo/commits/head456/check-runs?filter=all&per_page=100&page=1 HTTP/1.1"
        ));
        assert!(requests[2].starts_with("PATCH /api/v3/repos/octo/repo/check-runs/123 HTTP/1.1"));
        assert!(requests[2].contains("\"external_id\":\"review:sha256:abc\""));
        assert!(requests[2].contains("\"head_sha\":\"head456\""));
    }

    #[test]
    fn github_check_publication_rejects_head_movement_before_returning_receipt() {
        let (base, server) = fixture_server(vec![
            (
                200,
                vec![("ETag".into(), "\"rev-1\"".into())],
                r#"{"number":9,"title":"Change","body":null,"state":"open","merged":false,"base":{"sha":"base123"},"head":{"sha":"head456"}}"#.into(),
            ),
            (
                200,
                vec![],
                r#"{"check_runs":[{"id":123,"external_id":"review:sha256:abc"}]}"#.into(),
            ),
            (200, vec![], r#"{"id":123}"#.into()),
            (
                200,
                vec![("ETag".into(), "\"rev-2\"".into())],
                r#"{"number":9,"title":"Change","body":null,"state":"open","merged":false,"base":{"sha":"base123"},"head":{"sha":"head789"}}"#.into(),
            ),
        ]);
        let adapter = adapter(&base);
        let pull_request = reference("127.0.0.1");
        let publication = ReviewPublication {
            pull_request: pull_request.clone(),
            expected_revision: "\"rev-1\":base123:head456".into(),
            check: CheckRun {
                pull_request,
                external_id: "review-1".into(),
                name: "Vee assurance".into(),
                status: CheckStatus::Completed,
                conclusion: Some(CheckConclusion::Failure),
                title: "Review blocked".into(),
                summary: "High severity finding".into(),
                snapshot_id: "sha256:abc".into(),
                idempotency_key: "review:sha256:abc".into(),
            },
            threads: vec![],
        };

        assert!(matches!(
            adapter.publish_review(publication),
            Err(HostingError::StaleRevision { expected, actual })
                if expected == "\"rev-1\":base123:head456"
                    && actual == "\"rev-2\":base123:head789"
        ));
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 4);
        assert!(requests[3].starts_with("GET /api/v3/repos/octo/repo/pulls/9 HTTP/1.1"));
    }

    #[test]
    fn github_check_publication_rejects_head_movement_before_syncing_threads() {
        let (base, server) = fixture_server(vec![
            stable_pr_response(),
            (200, vec![], r#"{"check_runs":[]}"#.into()),
            (201, vec![], r#"{"id":123}"#.into()),
            (
                200,
                vec![("ETag".into(), "\"rev-2\"".into())],
                r#"{"number":9,"title":"Change","body":null,"state":"open","merged":false,"base":{"sha":"base123"},"head":{"sha":"head789"}}"#.into(),
            ),
        ]);
        let adapter = GitHubAdapter::new(
            GitHubConfig::new(&base, "test-token".into(), "webhook-secret".into())
                .unwrap()
                .with_actor_login("vee[bot]"),
        )
        .unwrap();
        let pull_request = reference("127.0.0.1");
        let publication = ReviewPublication {
            pull_request: pull_request.clone(),
            expected_revision: "\"rev-1\":base123:head456".into(),
            check: CheckRun {
                pull_request: pull_request.clone(),
                external_id: "review:sha256:snapshot".into(),
                name: "Vee assurance".into(),
                status: CheckStatus::Completed,
                conclusion: Some(CheckConclusion::Failure),
                title: "Review blocked".into(),
                summary: "Finding needs attention".into(),
                snapshot_id: "sha256:snapshot".into(),
                idempotency_key: "review:sha256:snapshot".into(),
            },
            threads: vec![ReviewThread {
                suggestion: None,
                pull_request,
                fingerprint: "sha256:f1".into(),
                path: "src/lib.rs".into(),
                line: 17,
                side: DiffSide::New,
                body: "issue".into(),
                resolution: ThreadResolution::Open,
                snapshot_id: "sha256:snapshot".into(),
                idempotency_key: "thread:sha256:f1".into(),
            }],
        };

        assert!(matches!(
            adapter.publish_review(publication),
            Err(HostingError::StaleRevision { .. })
        ));
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 4);
        assert!(requests
            .iter()
            .all(|request| !request.contains("/pulls/9/comments")));
    }

    #[test]
    fn github_review_comment_reconciliation_rejects_oversized_page() {
        let revision = "\"rev-1\":base123:head456";
        let oversized_page = " ".repeat(MAX_PUBLICATION_PAGE_RESPONSE_BYTES as usize + 1);
        let (base, server) = fixture_server(vec![
            (
                200,
                vec![("ETag".into(), "\"rev-1\"".into())],
                r#"{"number":9,"title":"Change","body":null,"state":"open","merged":false,"base":{"sha":"base123"},"head":{"sha":"head456"}}"#.into(),
            ),
            (200, vec![], r#"{"check_runs":[]}"#.into()),
            (201, vec![], r#"{"id":123}"#.into()),
            stable_pr_response(),
            (200, vec![], oversized_page),
        ]);
        let adapter = GitHubAdapter::new(
            GitHubConfig::new(&base, "test-token".into(), "webhook-secret".into())
                .unwrap()
                .with_actor_login("vee[bot]"),
        )
        .unwrap();
        let pull_request = reference("127.0.0.1");
        let publication = ReviewPublication {
            pull_request: pull_request.clone(),
            expected_revision: revision.into(),
            check: CheckRun {
                pull_request: pull_request.clone(),
                external_id: "review-size-bound".into(),
                name: "Vee assurance".into(),
                status: CheckStatus::Completed,
                conclusion: Some(CheckConclusion::Failure),
                title: "Review blocked".into(),
                summary: "Finding needs attention".into(),
                snapshot_id: "sha256:snapshot".into(),
                idempotency_key: "review:sha256:snapshot".into(),
            },
            threads: vec![ReviewThread {
                suggestion: None,
                pull_request,
                fingerprint: "sha256:f1".into(),
                path: "src/lib.rs".into(),
                line: 17,
                side: DiffSide::New,
                body: "issue".into(),
                resolution: ThreadResolution::Open,
                snapshot_id: "sha256:snapshot".into(),
                idempotency_key: "review:sha256:snapshot:sha256:f1".into(),
            }],
        };

        let error = adapter.publish_review(publication).unwrap_err();

        assert!(
            error.to_string().contains("8388608-byte limit"),
            "unexpected error: {error:?}"
        );
        assert_eq!(server.join().unwrap().len(), 5);
    }

    #[test]
    fn github_check_publication_follows_pages_before_creating_or_updating() {
        let revision = "\"rev-1\":base123:head456";
        let first_page = serde_json::json!({
            "check_runs": (0..100)
                .map(|id| serde_json::json!({ "id": id + 1, "external_id": format!("other:{id}") }))
                .collect::<Vec<_>>()
        })
        .to_string();
        let (base, server) = fixture_server(vec![
            (
                200,
                vec![("ETag".into(), "\"rev-1\"".into())],
                r#"{"number":9,"title":"Change","body":null,"state":"open","merged":false,"base":{"sha":"base123"},"head":{"sha":"head456"}}"#.into(),
            ),
            (200, vec![], first_page),
            (
                200,
                vec![],
                r#"{"check_runs":[{"id":123,"external_id":"review:sha256:abc"}]}"#.into(),
            ),
            (200, vec![], r#"{"id":123}"#.into()),
            (
                200,
                vec![("ETag".into(), "\"rev-1\"".into())],
                r#"{"number":9,"title":"Change","body":null,"state":"open","merged":false,"base":{"sha":"base123"},"head":{"sha":"head456"}}"#.into(),
            ),
        ]);
        let adapter = adapter(&base);
        let pull_request = reference("127.0.0.1");
        let publication = ReviewPublication {
            pull_request: pull_request.clone(),
            expected_revision: revision.into(),
            check: CheckRun {
                pull_request,
                external_id: "review-1".into(),
                name: "Vee assurance".into(),
                status: CheckStatus::Completed,
                conclusion: Some(CheckConclusion::Failure),
                title: "Review blocked".into(),
                summary: "High severity finding".into(),
                snapshot_id: "sha256:abc".into(),
                idempotency_key: "review:sha256:abc".into(),
            },
            threads: vec![],
        };
        let receipt = adapter.publish_review(publication).unwrap();
        assert_eq!(receipt.provider_check_id, "123");
        let requests = server.join().unwrap();
        assert!(requests[1].contains("check-runs?filter=all&per_page=100&page=1"));
        assert!(requests[2].contains("check-runs?filter=all&per_page=100&page=2"));
        assert!(requests[3].starts_with("PATCH /api/v3/repos/octo/repo/check-runs/123 HTTP/1.1"));
    }

    #[test]
    fn github_review_thread_reconciliation_fails_closed_at_pagination_bound() {
        let revision = "\"rev-1\":base123:head456";
        let full_page = serde_json::json!((0..100)
            .map(|id| serde_json::json!({
                "id": id + 1,
                "user": { "login": "someone-else" },
                "body": "unrelated comment"
            }))
            .collect::<Vec<_>>())
        .to_string();
        let mut responses = vec![
            (
                200,
                vec![("ETag".into(), "\"rev-1\"".into())],
                r#"{"number":9,"title":"Change","body":null,"state":"open","merged":false,"base":{"sha":"base123"},"head":{"sha":"head456"}}"#.into(),
            ),
            (200, vec![], r#"{"check_runs":[]}"#.into()),
            (201, vec![], r#"{"id":123}"#.into()),
            stable_pr_response(),
        ];
        responses.extend((0..30).map(|_| (200, vec![], full_page.clone())));
        let (base, server) = fixture_server(responses);
        let config = GitHubConfig::new(&base, "test-token".into(), "webhook-secret".into())
            .unwrap()
            .with_actor_login("vee[bot]");
        let adapter = GitHubAdapter::new(config).unwrap();
        let pull_request = reference("127.0.0.1");
        let publication = ReviewPublication {
            pull_request: pull_request.clone(),
            expected_revision: revision.into(),
            check: CheckRun {
                pull_request: pull_request.clone(),
                external_id: "review-boundary".into(),
                name: "Vee assurance".into(),
                status: CheckStatus::Completed,
                conclusion: Some(CheckConclusion::Failure),
                title: "Review blocked".into(),
                summary: "Finding needs attention".into(),
                snapshot_id: "sha256:snapshot".into(),
                idempotency_key: "review:sha256:snapshot".into(),
            },
            threads: vec![ReviewThread {
                suggestion: None,
                pull_request,
                fingerprint: "sha256:f1".into(),
                path: "src/lib.rs".into(),
                line: 17,
                side: DiffSide::New,
                body: "issue".into(),
                resolution: ThreadResolution::Open,
                snapshot_id: "sha256:snapshot".into(),
                idempotency_key: "review:sha256:snapshot:sha256:f1".into(),
            }],
        };
        let error = adapter.publish_review(publication).unwrap_err();
        assert!(
            error.to_string().contains("pagination exceeded"),
            "unexpected error: {error:?}"
        );
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 34);
        assert!(requests[33].contains("/pulls/9/comments?per_page=100&page=30"));
    }

    #[test]
    fn github_graphql_review_thread_reconciliation_has_a_page_bound() {
        let revision = "\"rev-1\":base123:head456";
        let mut responses = vec![
            (
                200,
                vec![("ETag".into(), "\"rev-1\"".into())],
                r#"{"number":9,"title":"Change","body":null,"state":"open","merged":false,"base":{"sha":"base123"},"head":{"sha":"head456"}}"#.into(),
            ),
            (200, vec![], r#"{"check_runs":[]}"#.into()),
            (201, vec![], r#"{"id":123}"#.into()),
            stable_pr_response(),
            (200, vec![], "[]".into()),
            (201, vec![], r#"{"id":501}"#.into()),
        ];
        responses.extend((0..MAX_REVIEW_THREAD_PAGES).map(|page| {
            (
                200,
                vec![],
                serde_json::json!({
                    "data": { "repository": { "pullRequest": { "reviewThreads": {
                        "nodes": [],
                        "pageInfo": { "hasNextPage": true, "endCursor": format!("cursor-{page}") }
                    }}}}
                })
                .to_string(),
            )
        }));
        let (base, server) = fixture_server(responses);
        let adapter = GitHubAdapter::new(
            GitHubConfig::new(&base, "test-token".into(), "webhook-secret".into())
                .unwrap()
                .with_actor_login("vee[bot]"),
        )
        .unwrap();
        let pull_request = reference("127.0.0.1");
        let publication = ReviewPublication {
            pull_request: pull_request.clone(),
            expected_revision: revision.into(),
            check: CheckRun {
                pull_request: pull_request.clone(),
                external_id: "review-pagination-bound".into(),
                name: "Vee assurance".into(),
                status: CheckStatus::Completed,
                conclusion: Some(CheckConclusion::Failure),
                title: "Review blocked".into(),
                summary: "Finding needs attention".into(),
                snapshot_id: "sha256:snapshot".into(),
                idempotency_key: "review:sha256:snapshot".into(),
            },
            threads: vec![ReviewThread {
                suggestion: None,
                pull_request,
                fingerprint: "sha256:f1".into(),
                path: "src/lib.rs".into(),
                line: 17,
                side: DiffSide::New,
                body: "issue".into(),
                resolution: ThreadResolution::Open,
                snapshot_id: "sha256:snapshot".into(),
                idempotency_key: "review:sha256:snapshot:sha256:f1".into(),
            }],
        };
        let error = adapter.publish_review(publication).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("review-thread pagination exceeded"),
            "unexpected error: {error:?}"
        );
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 6 + MAX_REVIEW_THREAD_PAGES as usize);
        assert!(requests
            .last()
            .unwrap()
            .starts_with("POST /api/graphql HTTP/1.1"));
    }

    #[test]
    fn github_inline_finding_creates_owned_comment() {
        let (base, server) = fixture_server(vec![
            (
                200,
                vec![("ETag".into(), "\"rev-1\"".into())],
                r#"{"number":9,"title":"Change","body":null,"state":"open","merged":false,"base":{"sha":"base123"},"head":{"sha":"head456"}}"#.into(),
            ),
            (200, vec![], r#"{"check_runs":[]}"#.into()),
            (201, vec![], r#"{"id":321}"#.into()),
            stable_pr_response(),
            (200, vec![], "[]".into()),
            (201, vec![], r#"{"id":501}"#.into()),
            (
                200,
                vec![],
                r#"{"data":{"repository":{"pullRequest":{"reviewThreads":{"nodes":[{"id":"PRRT_node_1","isResolved":false,"comments":{"nodes":[{"databaseId":501,"body":"issue\\n\\n<!-- vee:fingerprint:sha256:f1 -->","author":{"login":"vee[bot]"}}]}}],"pageInfo":{"hasNextPage":false}}}}}}"#.into(),
            ),
            (
                200,
                vec![("ETag".into(), "\"rev-1\"".into())],
                r#"{"number":9,"title":"Change","body":null,"state":"open","merged":false,"base":{"sha":"base123"},"head":{"sha":"head456"}}"#.into(),
            ),
        ]);
        let config = GitHubConfig::new(&base, "test-token".into(), "webhook-secret".into())
            .unwrap()
            .with_actor_login("vee[bot]");
        let adapter = GitHubAdapter::new(config).unwrap();
        let pull_request = reference("127.0.0.1");
        let publication = ReviewPublication {
            pull_request: pull_request.clone(),
            expected_revision: "\"rev-1\":base123:head456".into(),
            check: CheckRun {
                pull_request: pull_request.clone(),
                external_id: "review-2".into(),
                name: "Vee assurance".into(),
                status: CheckStatus::Completed,
                conclusion: Some(CheckConclusion::Failure),
                title: "Review blocked".into(),
                summary: "Finding needs attention".into(),
                snapshot_id: "sha256:snapshot".into(),
                idempotency_key: "review:sha256:snapshot".into(),
            },
            threads: vec![ReviewThread {
                suggestion: None,
                pull_request,
                fingerprint: "sha256:f1".into(),
                path: "src/lib.rs".into(),
                line: 17,
                side: DiffSide::New,
                body: "issue".into(),
                resolution: ThreadResolution::Open,
                snapshot_id: "sha256:snapshot".into(),
                idempotency_key: "thread:sha256:f1".into(),
            }],
        };
        let receipt = adapter.publish_review(publication).unwrap();
        assert_eq!(receipt.provider_check_id, "321");
        assert_eq!(receipt.thread_ids.get("sha256:f1").unwrap(), "PRRT_node_1");
        let requests = server.join().unwrap();
        assert!(requests[5].starts_with("POST /api/v3/repos/octo/repo/pulls/9/comments HTTP/1.1"));
        assert!(requests[5].contains("\"commit_id\":\"head456\""));
        assert!(requests[5].contains("<!-- vee:fingerprint:sha256:f1 -->"));
        assert!(requests[6].starts_with("POST /api/graphql HTTP/1.1"));
    }

    #[test]
    fn github_repeated_review_updates_owned_check_and_comment_without_duplicates() {
        let pr = r#"{"number":9,"title":"Change","body":null,"state":"open","merged":false,"base":{"sha":"base123"},"head":{"sha":"head456"}}"#;
        let owned_comment = r#"[{"id":501,"path":"src/lib.rs","line":17,"side":"RIGHT","body":"updated finding <!-- vee:fingerprint:sha256:f1 -->","user":{"login":"vee[bot]"}}]"#;
        let owned_thread = r#"{"data":{"repository":{"pullRequest":{"reviewThreads":{"nodes":[{"id":"PRRT_node_1","isResolved":false,"comments":{"nodes":[{"databaseId":501,"body":"updated finding\\n\\n<!-- vee:fingerprint:sha256:f1 -->","author":{"login":"vee[bot]"}}]}}],"pageInfo":{"hasNextPage":false}}}}}}"#;
        let (base, server) = fixture_server(vec![
            (200, vec![("ETag".into(), "\"rev-1\"".into())], pr.into()),
            (200, vec![], r#"{"check_runs":[]}"#.into()),
            (201, vec![], r#"{"id":321}"#.into()),
            stable_pr_response(),
            (200, vec![], "[]".into()),
            (201, vec![], r#"{"id":501}"#.into()),
            (200, vec![], owned_thread.into()),
            (200, vec![("ETag".into(), "\"rev-1\"".into())], pr.into()),
            (200, vec![("ETag".into(), "\"rev-1\"".into())], pr.into()),
            (
                200,
                vec![],
                r#"{"check_runs":[{"id":321,"external_id":"review:sha256:snapshot"}]}"#.into(),
            ),
            (200, vec![], r#"{"id":321}"#.into()),
            stable_pr_response(),
            (200, vec![], owned_comment.into()),
            (200, vec![], r#"{"id":501}"#.into()),
            (200, vec![], owned_thread.into()),
            (200, vec![("ETag".into(), "\"rev-1\"".into())], pr.into()),
        ]);
        let adapter = GitHubAdapter::new(
            GitHubConfig::new(&base, "test-token".into(), "webhook-secret".into())
                .unwrap()
                .with_actor_login("vee[bot]"),
        )
        .unwrap();
        let pull_request = reference("127.0.0.1");
        let publication = |summary: &str, body: &str| ReviewPublication {
            pull_request: pull_request.clone(),
            expected_revision: "\"rev-1\":base123:head456".into(),
            check: CheckRun {
                pull_request: pull_request.clone(),
                external_id: "review-2".into(),
                name: "Vee assurance".into(),
                status: CheckStatus::Completed,
                conclusion: Some(CheckConclusion::Failure),
                title: "Review blocked".into(),
                summary: summary.into(),
                snapshot_id: "sha256:snapshot".into(),
                idempotency_key: "review:sha256:snapshot".into(),
            },
            threads: vec![ReviewThread {
                suggestion: None,
                pull_request: pull_request.clone(),
                fingerprint: "sha256:f1".into(),
                path: "src/lib.rs".into(),
                line: 17,
                side: DiffSide::New,
                body: body.into(),
                resolution: ThreadResolution::Open,
                snapshot_id: "sha256:snapshot".into(),
                idempotency_key: "thread:sha256:f1".into(),
            }],
        };

        let first = adapter
            .publish_review(publication("Initial finding", "initial finding"))
            .unwrap();
        let repeated = adapter
            .publish_review(publication("Updated finding", "updated finding"))
            .unwrap();

        assert_eq!(first.provider_check_id, "321");
        assert_eq!(repeated.provider_check_id, first.provider_check_id);
        assert_eq!(
            first.thread_ids.get("sha256:f1").map(String::as_str),
            Some("PRRT_node_1")
        );
        assert_eq!(repeated.thread_ids, first.thread_ids);
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 16);
        assert_eq!(
            requests
                .iter()
                .filter(
                    |request| request.starts_with("POST /api/v3/repos/octo/repo/pulls/9/comments ")
                )
                .count(),
            1,
            "repeated delivery must not create a duplicate inline comment"
        );
        assert!(requests[2].starts_with("POST /api/v3/repos/octo/repo/check-runs HTTP/1.1"));
        assert!(requests[10].starts_with("PATCH /api/v3/repos/octo/repo/check-runs/321 HTTP/1.1"));
        assert!(
            requests[13].starts_with("PATCH /api/v3/repos/octo/repo/pulls/comments/501 HTTP/1.1")
        );
        assert!(requests[13].contains("updated finding"));
    }

    #[test]
    fn github_retry_after_lost_comment_response_reconciles_without_duplicate() {
        let pr = r#"{"number":9,"title":"Change","body":null,"state":"open","merged":false,"base":{"sha":"base123"},"head":{"sha":"head456"}}"#;
        let marker = "<!-- vee:fingerprint:sha256:f1 -->";
        let existing_comment = format!(
            r#"[{{"id":501,"path":"src/lib.rs","line":17,"side":"RIGHT","body":"finding {marker}","user":{{"login":"vee[bot]"}}}}]"#
        );
        let existing_thread = format!(
            r#"{{"data":{{"repository":{{"pullRequest":{{"reviewThreads":{{"nodes":[{{"id":"PRRT_node_1","isResolved":false,"comments":{{"nodes":[{{"databaseId":501,"body":"finding\\n\\n{marker}","author":{{"login":"vee[bot]"}}}}]}}}}],"pageInfo":{{"hasNextPage":false}}}}}}}}}}}}"#
        );
        let (base, server) = fixture_server(vec![
            (200, vec![("ETag".into(), "\"rev-1\"".into())], pr.into()),
            (200, vec![], r#"{"check_runs":[]}"#.into()),
            (201, vec![], r#"{"id":321}"#.into()),
            stable_pr_response(),
            (200, vec![], "[]".into()),
            (0, vec![], String::new()),
            (200, vec![("ETag".into(), "\"rev-1\"".into())], pr.into()),
            (
                200,
                vec![],
                r#"{"check_runs":[{"id":321,"external_id":"review:sha256:snapshot"}]}"#.into(),
            ),
            (200, vec![], r#"{"id":321}"#.into()),
            stable_pr_response(),
            (200, vec![], existing_comment),
            (200, vec![], r#"{"id":501}"#.into()),
            (200, vec![], existing_thread),
            (200, vec![("ETag".into(), "\"rev-1\"".into())], pr.into()),
        ]);
        let adapter = GitHubAdapter::new(
            GitHubConfig::new(&base, "test-token".into(), "webhook-secret".into())
                .unwrap()
                .with_actor_login("vee[bot]"),
        )
        .unwrap();
        let pull_request = reference("127.0.0.1");
        let publication = || ReviewPublication {
            pull_request: pull_request.clone(),
            expected_revision: "\"rev-1\":base123:head456".into(),
            check: CheckRun {
                pull_request: pull_request.clone(),
                external_id: "review-1".into(),
                name: "Vee assurance".into(),
                status: CheckStatus::Completed,
                conclusion: Some(CheckConclusion::Failure),
                title: "Review blocked".into(),
                summary: "Finding needs attention".into(),
                snapshot_id: "sha256:snapshot".into(),
                idempotency_key: "review:sha256:snapshot".into(),
            },
            threads: vec![ReviewThread {
                suggestion: None,
                pull_request: pull_request.clone(),
                fingerprint: "sha256:f1".into(),
                path: "src/lib.rs".into(),
                line: 17,
                side: DiffSide::New,
                body: "finding".into(),
                resolution: ThreadResolution::Open,
                snapshot_id: "sha256:snapshot".into(),
                idempotency_key: "thread:sha256:f1".into(),
            }],
        };

        assert!(matches!(
            adapter.publish_review(publication()),
            Err(HostingError::Transport(_))
        ));
        let receipt = adapter.publish_review(publication()).unwrap();
        assert_eq!(receipt.provider_check_id, "321");
        assert_eq!(
            receipt.thread_ids.get("sha256:f1").map(String::as_str),
            Some("PRRT_node_1")
        );
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 14);
        assert_eq!(
            requests
                .iter()
                .filter(
                    |request| request.starts_with("POST /api/v3/repos/octo/repo/pulls/9/comments ")
                )
                .count(),
            1,
            "retry after a lost response must not create a duplicate comment"
        );
        assert!(
            requests[11].starts_with("PATCH /api/v3/repos/octo/repo/pulls/comments/501 HTTP/1.1")
        );
    }

    #[test]
    fn github_inline_finding_reopens_only_a_matching_bot_owned_thread() {
        let (base, server) = fixture_server(vec![
            (
                200,
                vec![("ETag".into(), "\"rev-1\"".into())],
                r#"{"number":9,"title":"Change","body":null,"state":"open","merged":false,"base":{"sha":"base123"},"head":{"sha":"head456"}}"#.into(),
            ),
            (200, vec![], r#"{"check_runs":[{"id":321,"external_id":"check-key"}]}"#.into()),
            (200, vec![], r#"{"id":321}"#.into()),
            stable_pr_response(),
            (
                200,
                vec![],
                r#"[{"id":501,"path":"src/lib.rs","line":17,"side":"RIGHT","body":"old <!-- vee:fingerprint:sha256:f1 -->","user":{"login":"vee[bot]"}}]"#.into(),
            ),
            (200, vec![], r#"{"id":501}"#.into()),
            (
                200,
                vec![],
                r#"{"data":{"repository":{"pullRequest":{"reviewThreads":{"nodes":[{"id":"PRRT_node_1","isResolved":true,"comments":{"nodes":[{"databaseId":501,"body":"old <!-- vee:fingerprint:sha256:f1 -->","author":{"login":"vee[bot]"}}]}}],"pageInfo":{"hasNextPage":false}}}}}}"#.into(),
            ),
            (
                200,
                vec![],
                r#"{"data":{"unresolveReviewThread":{"thread":{"id":"PRRT_node_1","isResolved":false}}}}"#.into(),
            ),
            (
                200,
                vec![("ETag".into(), "\"rev-1\"".into())],
                r#"{"number":9,"title":"Change","body":null,"state":"open","merged":false,"base":{"sha":"base123"},"head":{"sha":"head456"}}"#.into(),
            ),
        ]);
        let config = GitHubConfig::new(&base, "test-token".into(), "webhook-secret".into())
            .unwrap()
            .with_actor_login("vee[bot]");
        let adapter = GitHubAdapter::new(config).unwrap();
        let pull_request = reference("127.0.0.1");
        let publication = ReviewPublication {
            pull_request: pull_request.clone(),
            expected_revision: "\"rev-1\":base123:head456".into(),
            check: CheckRun {
                pull_request: pull_request.clone(),
                external_id: "review-2".into(),
                name: "Vee assurance".into(),
                status: CheckStatus::Completed,
                conclusion: Some(CheckConclusion::Success),
                title: "Review passed".into(),
                summary: "Finding was resolved".into(),
                snapshot_id: "sha256:snapshot".into(),
                idempotency_key: "check-key".into(),
            },
            threads: vec![ReviewThread {
                suggestion: None,
                pull_request,
                fingerprint: "sha256:f1".into(),
                path: "src/lib.rs".into(),
                line: 17,
                side: DiffSide::New,
                body: "fixed".into(),
                resolution: ThreadResolution::Open,
                snapshot_id: "sha256:snapshot".into(),
                idempotency_key: "thread-key".into(),
            }],
        };
        adapter.publish_review(publication).unwrap();
        let requests = server.join().unwrap();
        assert!(
            requests[5].starts_with("PATCH /api/v3/repos/octo/repo/pulls/comments/501 HTTP/1.1")
        );
        assert!(requests[7].contains("unresolveReviewThread"));
    }

    #[test]
    fn github_resolves_owned_thread_when_old_inline_location_is_stale() {
        let (base, server) = fixture_server(vec![
            (
                200,
                vec![("ETag".into(), "\"rev-1\"".into())],
                r#"{"number":9,"title":"Change","body":null,"state":"open","merged":false,"base":{"sha":"base123"},"head":{"sha":"head456"}}"#.into(),
            ),
            (200, vec![], r#"{"check_runs":[]}"#.into()),
            (201, vec![], r#"{"id":321}"#.into()),
            stable_pr_response(),
            (
                200,
                vec![],
                r#"[{"id":501,"path":"src/old.rs","line":17,"original_line":17,"side":"RIGHT","body":"old <!-- vee:fingerprint:sha256:f1 -->","user":{"login":"vee[bot]"}}]"#.into(),
            ),
            (
                200,
                vec![],
                r#"{"data":{"repository":{"pullRequest":{"reviewThreads":{"nodes":[],"pageInfo":{"hasNextPage":true,"endCursor":"cursor-page-1"}}}}}}"#.into(),
            ),
            (
                200,
                vec![],
                r#"{"data":{"repository":{"pullRequest":{"reviewThreads":{"nodes":[{"id":"PRRT_node_1","isResolved":false,"comments":{"nodes":[{"databaseId":501,"body":"old <!-- vee:fingerprint:sha256:f1 -->","author":{"login":"vee[bot]"}}]}}],"pageInfo":{"hasNextPage":false,"endCursor":"cursor-page-2"}}}}}}"#.into(),
            ),
            (
                200,
                vec![],
                r#"{"data":{"resolveReviewThread":{"thread":{"id":"PRRT_node_1","isResolved":true}}}}"#.into(),
            ),
            (
                200,
                vec![("ETag".into(), "\"rev-1\"".into())],
                r#"{"number":9,"title":"Change","body":null,"state":"open","merged":false,"base":{"sha":"base123"},"head":{"sha":"head456"}}"#.into(),
            ),
        ]);
        let adapter = GitHubAdapter::new(
            GitHubConfig::new(&base, "test-token".into(), "webhook-secret".into())
                .unwrap()
                .with_actor_login("vee[bot]"),
        )
        .unwrap();
        let pull_request = reference("127.0.0.1");
        let publication = ReviewPublication {
            pull_request: pull_request.clone(),
            expected_revision: "\"rev-1\":base123:head456".into(),
            check: CheckRun {
                pull_request: pull_request.clone(),
                external_id: "review-3".into(),
                name: "Vee assurance".into(),
                status: CheckStatus::Completed,
                conclusion: Some(CheckConclusion::Success),
                title: "Review passed".into(),
                summary: "Resolved finding".into(),
                snapshot_id: "sha256:snapshot".into(),
                idempotency_key: "review:sha256:snapshot".into(),
            },
            threads: vec![ReviewThread {
                suggestion: None,
                pull_request,
                fingerprint: "sha256:f1".into(),
                path: "src/new.rs".into(),
                line: 3,
                side: DiffSide::New,
                body: "Resolved locally".into(),
                resolution: ThreadResolution::Resolved,
                snapshot_id: "sha256:snapshot".into(),
                idempotency_key: "thread:sha256:f1:resolved".into(),
            }],
        };
        let receipt = adapter.publish_review(publication).unwrap();
        assert_eq!(receipt.thread_ids.get("sha256:f1").unwrap(), "PRRT_node_1");
        let requests = server.join().unwrap();
        assert!(requests[4].starts_with("GET /api/v3/repos/octo/repo/pulls/9/comments?"));
        assert!(requests[5].starts_with("POST /api/graphql HTTP/1.1"));
        assert!(requests[7].contains("resolveReviewThread"));
        assert!(requests[5].contains("\"after\":null"));
        assert!(requests[6].contains("\"after\":\"cursor-page-1\""));
        assert_eq!(
            requests.len(),
            9,
            "stale location should not patch or recreate comment"
        );
    }

    /// Publish one open thread at `src/a.rs` line 3 whose suggestion replaces
    /// lines 3 and 4, with Vee's existing comment for it listed as `existing`
    /// and the rest of the host's answers as `after_listing`.
    fn publish_suggestion(existing: &str, after_listing: Vec<FixtureResponse>) -> Vec<String> {
        let pr = || {
            (
                200,
                vec![("ETag".into(), "\"rev-1\"".into())],
                r#"{"number":9,"title":"Change","body":null,"state":"open","merged":false,"base":{"sha":"base123"},"head":{"sha":"head456"}}"#.to_owned(),
            )
        };
        let mut responses = vec![
            pr(),
            (200, vec![], r#"{"check_runs":[]}"#.into()),
            (201, vec![], r#"{"id":321}"#.into()),
            stable_pr_response(),
            (200, vec![], format!("[{existing}]")),
        ];
        responses.extend(after_listing);
        responses.push(pr());
        let (base, server) = fixture_server(responses);
        let adapter = GitHubAdapter::new(
            GitHubConfig::new(&base, "test-token".into(), "webhook-secret".into())
                .unwrap()
                .with_actor_login("vee[bot]"),
        )
        .unwrap();
        let pull_request = reference("127.0.0.1");
        adapter
            .publish_review(ReviewPublication {
                pull_request: pull_request.clone(),
                expected_revision: "\"rev-1\":base123:head456".into(),
                check: CheckRun {
                    pull_request: pull_request.clone(),
                    external_id: "review-3".into(),
                    name: "Vee assurance".into(),
                    status: CheckStatus::Completed,
                    conclusion: Some(CheckConclusion::Failure),
                    title: "Review blocked".into(),
                    summary: "One finding".into(),
                    snapshot_id: "sha256:snapshot".into(),
                    idempotency_key: "review:sha256:snapshot".into(),
                },
                threads: vec![ReviewThread {
                    suggestion: Some(ThreadSuggestion {
                        end_line: 4,
                        original: vec!["let a = 1;".into(), "let b = a;".into()],
                        replacement: "let b = 1;".into(),
                    }),
                    pull_request,
                    fingerprint: "sha256:f1".into(),
                    path: "src/a.rs".into(),
                    line: 3,
                    side: DiffSide::New,
                    body: "Wrong value".into(),
                    resolution: ThreadResolution::Open,
                    snapshot_id: "sha256:snapshot".into(),
                    idempotency_key: "thread:sha256:f1".into(),
                }],
            })
            .unwrap();
        server.join().unwrap()
    }

    fn open_thread(id: u64) -> FixtureResponse {
        (
            200,
            vec![],
            format!(
                r#"{{"data":{{"repository":{{"pullRequest":{{"reviewThreads":{{"nodes":[{{"id":"PRRT_{id}","isResolved":false,"comments":{{"nodes":[{{"databaseId":{id},"body":"x","author":{{"login":"vee[bot]"}}}}]}}}}],"pageInfo":{{"hasNextPage":false,"endCursor":"c"}}}}}}}}}}}}"#
            ),
        )
    }

    #[test]
    fn a_github_suggestion_is_posted_on_a_comment_spanning_the_lines_it_replaces() {
        // Vee's earlier comment covers only line 3, so it cannot carry a
        // suggestion for lines 3-4: it is retired and a spanning one opens.
        let requests = publish_suggestion(
            r#"{"id":501,"path":"src/a.rs","line":3,"start_line":null,"side":"RIGHT","body":"old <!-- vee:fingerprint:sha256:f1 -->","user":{"login":"vee[bot]"}}"#,
            vec![
                (200, vec![], r#"{"id":501}"#.into()),
                open_thread(501),
                (
                    200,
                    vec![],
                    r#"{"data":{"resolveReviewThread":{"thread":{"id":"PRRT_501","isResolved":true}}}}"#.into(),
                ),
                (201, vec![], r#"{"id":777}"#.into()),
                open_thread(777),
            ],
        );
        assert!(requests[5].starts_with("PATCH /api/v3/repos/octo/repo/pulls/comments/501"));
        let created = &requests[8];
        assert!(
            created.starts_with("POST /api/v3/repos/octo/repo/pulls/9/comments"),
            "{created}"
        );
        for expected in [
            r#""start_line":3"#,
            r#""line":4"#,
            r#""start_side":"RIGHT""#,
            r#"```suggestion\nlet b = 1;\n```"#,
        ] {
            assert!(created.contains(expected), "{expected} in {created}");
        }
    }

    #[test]
    fn a_github_comment_already_spanning_the_suggestion_is_updated_in_place() {
        let requests = publish_suggestion(
            r#"{"id":501,"path":"src/a.rs","line":4,"start_line":3,"side":"RIGHT","body":"old <!-- vee:fingerprint:sha256:f1 -->","user":{"login":"vee[bot]"}}"#,
            vec![(200, vec![], r#"{"id":501}"#.into()), open_thread(501)],
        );
        assert!(requests[5].starts_with("PATCH /api/v3/repos/octo/repo/pulls/comments/501"));
        assert!(requests[5].contains("```suggestion"), "{}", requests[5]);
        assert!(!requests
            .iter()
            .any(|request| request.starts_with("POST /api/v3/repos/octo/repo/pulls/9/comments")));
    }

    #[test]
    fn github_replaces_the_thread_of_an_open_finding_whose_line_moved() {
        let (base, server) = fixture_server(vec![
            (
                200,
                vec![("ETag".into(), "\"rev-1\"".into())],
                r#"{"number":9,"title":"Change","body":null,"state":"open","merged":false,"base":{"sha":"base123"},"head":{"sha":"head456"}}"#.into(),
            ),
            (200, vec![], r#"{"check_runs":[]}"#.into()),
            (201, vec![], r#"{"id":321}"#.into()),
            stable_pr_response(),
            (
                200,
                vec![],
                r#"[{"id":501,"path":"src/old.rs","line":null,"original_line":17,"side":"RIGHT","body":"old <!-- vee:fingerprint:sha256:f1 -->","user":{"login":"vee[bot]"}}]"#.into(),
            ),
            (200, vec![], r#"{"id":501}"#.into()),
            (
                200,
                vec![],
                r#"{"data":{"repository":{"pullRequest":{"reviewThreads":{"nodes":[{"id":"PRRT_old","isResolved":false,"comments":{"nodes":[{"databaseId":501,"body":"moved","author":{"login":"vee[bot]"}}]}}],"pageInfo":{"hasNextPage":false,"endCursor":"c"}}}}}}"#.into(),
            ),
            (
                200,
                vec![],
                r#"{"data":{"resolveReviewThread":{"thread":{"id":"PRRT_old","isResolved":true}}}}"#.into(),
            ),
            (201, vec![], r#"{"id":777}"#.into()),
            (
                200,
                vec![],
                r#"{"data":{"repository":{"pullRequest":{"reviewThreads":{"nodes":[{"id":"PRRT_new","isResolved":false,"comments":{"nodes":[{"databaseId":777,"body":"new","author":{"login":"vee[bot]"}}]}}],"pageInfo":{"hasNextPage":false,"endCursor":"c"}}}}}}"#.into(),
            ),
            (
                200,
                vec![("ETag".into(), "\"rev-1\"".into())],
                r#"{"number":9,"title":"Change","body":null,"state":"open","merged":false,"base":{"sha":"base123"},"head":{"sha":"head456"}}"#.into(),
            ),
        ]);
        let adapter = GitHubAdapter::new(
            GitHubConfig::new(&base, "test-token".into(), "webhook-secret".into())
                .unwrap()
                .with_actor_login("vee[bot]"),
        )
        .unwrap();
        let pull_request = reference("127.0.0.1");
        let publication = ReviewPublication {
            pull_request: pull_request.clone(),
            expected_revision: "\"rev-1\":base123:head456".into(),
            check: CheckRun {
                pull_request: pull_request.clone(),
                external_id: "review-3".into(),
                name: "Vee assurance".into(),
                status: CheckStatus::Completed,
                conclusion: Some(CheckConclusion::Success),
                title: "Review passed".into(),
                summary: "Resolved finding".into(),
                snapshot_id: "sha256:snapshot".into(),
                idempotency_key: "review:sha256:snapshot".into(),
            },
            threads: vec![ReviewThread {
                suggestion: None,
                pull_request,
                fingerprint: "sha256:f1".into(),
                path: "src/new.rs".into(),
                line: 3,
                side: DiffSide::New,
                body: "Still wrong".into(),
                resolution: ThreadResolution::Open,
                snapshot_id: "sha256:snapshot".into(),
                idempotency_key: "thread:sha256:f1:resolved".into(),
            }],
        };
        let receipt = adapter.publish_review(publication).unwrap();
        assert_eq!(receipt.thread_ids.get("sha256:f1").unwrap(), "PRRT_new");
        let requests = server.join().unwrap();
        assert!(requests[5].starts_with("PATCH /api/v3/repos/octo/repo/pulls/comments/501"));
        assert!(requests[5].contains("src/new.rs") && !requests[5].contains("vee:fingerprint"));
        assert!(requests[7].contains("resolveReviewThread"));
        assert!(requests[8].starts_with("POST /api/v3/repos/octo/repo/pulls/9/comments"));
        assert!(requests[8].contains("\"line\":3"));
        assert_eq!(requests.len(), 11);
    }
}
