//! Bitbucket Cloud pull request context adapter.
//!
//! The adapter is deliberately read-only: it retrieves a PR and its bounded
//! diffstat without granting Vee write access to a workspace.

use crate::{
    CheckConclusion, CheckStatus, DiffSide, FileChange, GitHostingProvider, HostingError,
    PublicationReceipt, PullRequestContextProvider, PullRequestFile, PullRequestRef,
    PullRequestSnapshot, PullRequestState, ReviewPublication, SuggestionStyle, ThreadResolution,
    WebhookEnvelope,
};
use hmac::{Hmac, Mac};
use reqwest::{blocking::Client, header, Method, StatusCode, Url};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io::Read, time::Duration};

const MAX_RESPONSE_BYTES: u64 = 5_242_880;
type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct BitbucketConfig {
    pub api_base: Url,
    pub token: String,
    pub webhook_secret: String,
    pub timeout: Duration,
}

impl BitbucketConfig {
    pub fn new(api_base: &str, token: String) -> Result<Self, String> {
        let api_base = Url::parse(api_base).map_err(|error| error.to_string())?;
        let loopback = matches!(api_base.host_str(), Some("127.0.0.1" | "localhost" | "::1"));
        if !matches!(api_base.scheme(), "https" | "http")
            || (api_base.scheme() == "http" && !loopback)
            || api_base.host_str().is_none()
            || !api_base.username().is_empty()
            || api_base.password().is_some()
            || api_base.query().is_some()
            || api_base.fragment().is_some()
            || token.trim().is_empty()
        {
            return Err(
                "Bitbucket API URL and token are required; HTTP is allowed only on loopback".into(),
            );
        }
        Ok(Self {
            api_base,
            token,
            webhook_secret: String::new(),
            timeout: Duration::from_secs(30),
        })
    }

    pub fn with_webhook_secret(mut self, secret: String) -> Self {
        self.webhook_secret = secret;
        self
    }
}

pub struct BitbucketAdapter {
    config: BitbucketConfig,
    client: Client,
}

impl BitbucketAdapter {
    pub fn new(config: BitbucketConfig) -> Result<Self, String> {
        let client = Client::builder()
            .timeout(config.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| error.to_string())?;
        Ok(Self { config, client })
    }

    fn url(&self, reference: &PullRequestRef, suffix: &str) -> Result<Url, HostingError> {
        reference
            .validate()
            .map_err(HostingError::InvalidResponse)?;
        let api_host = self.config.api_base.host_str().unwrap_or_default();
        if !reference.repository.host.eq_ignore_ascii_case(api_host)
            && !(reference.repository.host == "bitbucket.org" && api_host == "api.bitbucket.org")
        {
            return Err(HostingError::InvalidResponse(
                "repository host does not match configured Bitbucket API".into(),
            ));
        }
        let prefix = self.config.api_base.path().trim_end_matches('/');
        let mut url = self.config.api_base.clone();
        url.set_path(&format!(
            "{prefix}/repositories/{}/pullrequests/{}{}",
            reference.repository.full_name, reference.number, suffix
        ));
        Ok(url)
    }

    fn get(&self, url: Url) -> Result<reqwest::blocking::Response, HostingError> {
        self.send(Method::GET, url, None)
    }

    fn send(
        &self,
        method: Method,
        url: Url,
        body: Option<serde_json::Value>,
    ) -> Result<reqwest::blocking::Response, HostingError> {
        let mut request = self
            .client
            .request(method, url)
            .bearer_auth(&self.config.token)
            .header(header::ACCEPT, "application/json");
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().map_err(|error| {
            HostingError::Transport(format!("requesting Bitbucket API: {error}"))
        })?;
        match response.status() {
            StatusCode::OK
            | StatusCode::CREATED
            | StatusCode::ACCEPTED
            | StatusCode::NO_CONTENT => Ok(response),
            StatusCode::NOT_FOUND => Err(HostingError::NotFound),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Err(HostingError::Unauthorized),
            StatusCode::TOO_MANY_REQUESTS => Err(HostingError::RateLimited {
                retry_after_seconds: response
                    .headers()
                    .get(header::RETRY_AFTER)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse().ok()),
            }),
            StatusCode::CONFLICT | StatusCode::PRECONDITION_FAILED => {
                Err(HostingError::StaleRevision {
                    expected: "current pull request revision".into(),
                    actual: "Bitbucket rejected a stale update".into(),
                })
            }
            status => Err(HostingError::Transport(format!(
                "Bitbucket returned HTTP {status}"
            ))),
        }
    }

    fn json<T: for<'de> Deserialize<'de>>(
        response: reqwest::blocking::Response,
    ) -> Result<T, HostingError> {
        Self::json_with_size(response).map(|(value, _)| value)
    }

    fn json_with_size<T: for<'de> Deserialize<'de>>(
        response: reqwest::blocking::Response,
    ) -> Result<(T, usize), HostingError> {
        if response
            .content_length()
            .is_some_and(|size| size > MAX_RESPONSE_BYTES)
        {
            return Err(HostingError::InvalidResponse(
                "Bitbucket response exceeds the 5 MiB limit".into(),
            ));
        }
        let mut bytes = Vec::new();
        response
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                HostingError::InvalidResponse(format!("reading Bitbucket response: {error}"))
            })?;
        if bytes.len() as u64 > MAX_RESPONSE_BYTES {
            return Err(HostingError::InvalidResponse(
                "Bitbucket response exceeds the 5 MiB limit".into(),
            ));
        }
        let size = bytes.len();
        let value = serde_json::from_slice(&bytes).map_err(|error| {
            HostingError::InvalidResponse(format!("invalid Bitbucket JSON: {error}"))
        })?;
        Ok((value, size))
    }

    fn text(response: reqwest::blocking::Response) -> Result<String, HostingError> {
        if response
            .content_length()
            .is_some_and(|size| size > MAX_RESPONSE_BYTES)
        {
            return Err(HostingError::InvalidResponse(
                "Bitbucket diff exceeds the 5 MiB limit".into(),
            ));
        }
        let mut bytes = Vec::new();
        response
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                HostingError::InvalidResponse(format!("reading Bitbucket diff: {error}"))
            })?;
        if bytes.len() as u64 > MAX_RESPONSE_BYTES {
            return Err(HostingError::InvalidResponse(
                "Bitbucket diff exceeds the 5 MiB limit".into(),
            ));
        }
        String::from_utf8(bytes)
            .map_err(|_| HostingError::InvalidResponse("Bitbucket diff is not UTF-8".into()))
    }

    fn repository_url(
        &self,
        reference: &PullRequestRef,
        suffix: &str,
    ) -> Result<Url, HostingError> {
        reference
            .validate()
            .map_err(HostingError::InvalidResponse)?;
        let api_host = self.config.api_base.host_str().unwrap_or_default();
        if !reference.repository.host.eq_ignore_ascii_case(api_host)
            && !(reference.repository.host == "bitbucket.org" && api_host == "api.bitbucket.org")
        {
            return Err(HostingError::InvalidResponse(
                "repository host does not match configured Bitbucket API".into(),
            ));
        }
        let prefix = self.config.api_base.path().trim_end_matches('/');
        let mut url = self.config.api_base.clone();
        url.set_path(&format!(
            "{prefix}/repositories/{}{}",
            reference.repository.full_name, suffix
        ));
        Ok(url)
    }

    fn verify_signature(
        &self,
        headers: &BTreeMap<String, String>,
        body: &[u8],
    ) -> Result<(), HostingError> {
        if self.config.webhook_secret.is_empty() {
            return Err(HostingError::InvalidResponse(
                "Bitbucket webhook secret is not configured".into(),
            ));
        }
        let signature = header_value(headers, "x-hub-signature").ok_or_else(|| {
            HostingError::InvalidResponse("missing Bitbucket webhook signature".into())
        })?;
        let (algorithm, hex) = signature.split_once('=').ok_or_else(|| {
            HostingError::InvalidResponse("invalid Bitbucket webhook signature".into())
        })?;
        if algorithm != "sha256" || hex.len() != 64 {
            return Err(HostingError::InvalidResponse(
                "unsupported Bitbucket webhook signature".into(),
            ));
        }
        let supplied = decode_hex(hex).ok_or_else(|| {
            HostingError::InvalidResponse("invalid Bitbucket webhook signature".into())
        })?;
        let mut mac =
            HmacSha256::new_from_slice(self.config.webhook_secret.as_bytes()).map_err(|_| {
                HostingError::InvalidResponse("invalid Bitbucket webhook secret".into())
            })?;
        mac.update(body);
        mac.verify_slice(&supplied).map_err(|_| {
            HostingError::InvalidResponse("Bitbucket webhook signature verification failed".into())
        })
    }
}

fn header_value<'a>(headers: &'a BTreeMap<String, String>, name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                b'A'..=b'F' => Some(byte - b'A' + 10),
                _ => None,
            };
            Some(digit(pair[0])? * 16 + digit(pair[1])?)
        })
        .collect()
}

fn bitbucket_status_key(idempotency_key: &str) -> String {
    let digest = Sha256::digest(idempotency_key.as_bytes());
    let suffix = digest
        .iter()
        .take(16)
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("vee-{suffix}")
}

impl PullRequestContextProvider for BitbucketAdapter {
    fn context_provider_id(&self) -> &'static str {
        "bitbucket"
    }

    fn get_pull_request_context(
        &self,
        reference: &PullRequestRef,
    ) -> Result<PullRequestSnapshot, HostingError> {
        #[derive(Deserialize)]
        struct Commit {
            hash: String,
        }
        #[derive(Deserialize)]
        struct Branch {
            commit: Commit,
        }
        #[derive(Deserialize)]
        struct ApiPr {
            id: u64,
            title: String,
            description: Option<String>,
            state: String,
            source: Branch,
            destination: Branch,
            updated_on: String,
        }
        let api: ApiPr = Self::json(self.get(self.url(reference, "")?)?)?;
        if api.id != reference.number {
            return Err(HostingError::InvalidResponse(
                "Bitbucket returned a different pull request".into(),
            ));
        }
        let state = match api.state.as_str() {
            "OPEN" => PullRequestState::Open,
            "MERGED" => PullRequestState::Merged,
            _ => PullRequestState::Closed,
        };
        let base_oid = self.full_hash(reference, &api.destination.commit.hash)?;
        let head_oid = self.full_hash(reference, &api.source.commit.hash)?;
        let revision = format!("{base_oid}:{head_oid}:{}", api.updated_on);
        Ok(PullRequestSnapshot {
            pull_request: reference.clone(),
            base_oid,
            head_oid,
            title: api.title,
            body: api.description,
            state,
            revision,
        })
    }

    fn list_pull_request_context_files(
        &self,
        reference: &PullRequestRef,
        expected_revision: &str,
    ) -> Result<Vec<PullRequestFile>, HostingError> {
        #[derive(Deserialize)]
        struct Page<T> {
            values: Vec<T>,
            #[serde(default)]
            next: Option<String>,
        }
        #[derive(Deserialize)]
        struct ApiFile {
            status: String,
            #[serde(default)]
            old: Option<Path>,
            new: Path,
            #[serde(default)]
            lines_added: u64,
            #[serde(default)]
            lines_removed: u64,
        }
        #[derive(Deserialize)]
        struct Path {
            path: String,
        }

        let current = PullRequestContextProvider::get_pull_request_context(self, reference)?;
        if current.revision != expected_revision {
            return Err(HostingError::StaleRevision {
                expected: expected_revision.into(),
                actual: current.revision,
            });
        }
        let mut files = Vec::new();
        let mut complete = false;
        let mut aggregate_response_bytes = 0_u64;
        for page in 1..=30 {
            let mut url = self.url(reference, "/diffstat")?;
            url.query_pairs_mut()
                .append_pair("pagelen", "100")
                .append_pair("page", &page.to_string());
            let (batch, response_bytes): (Page<ApiFile>, usize) =
                Self::json_with_size(self.get(url)?)?;
            aggregate_response_bytes =
                aggregate_response_bytes.saturating_add(response_bytes as u64);
            if aggregate_response_bytes > MAX_RESPONSE_BYTES {
                return Err(HostingError::InvalidResponse(
                    "Bitbucket diffstat exceeds the 5 MiB aggregate response limit".into(),
                ));
            }
            files.extend(batch.values.into_iter().map(|file| {
                let old_path = file.old.map(|path| path.path);
                let path = file.new.path;
                let change = match file.status.as_str() {
                    "added" => FileChange::Added,
                    "removed" => FileChange::Deleted,
                    "renamed" => FileChange::Renamed,
                    "copied" => FileChange::Copied,
                    _ => FileChange::Modified,
                };
                let previous_path = old_path.filter(|old| old != &path);
                PullRequestFile {
                    path,
                    change,
                    previous_path,
                    patch: None,
                    additions: file.lines_added,
                    deletions: file.lines_removed,
                }
            }));
            if batch.next.is_none() {
                complete = true;
                break;
            }
        }
        if !complete {
            return Err(HostingError::InvalidResponse(
                "Bitbucket diffstat pagination exceeded its 3000-file context bound".into(),
            ));
        }
        if files.len() > 3000 {
            return Err(HostingError::InvalidResponse(
                "pull request exceeds the 3000-file API limit".into(),
            ));
        }
        let diff = Self::text(self.get(self.url(reference, "/diff")?)?)?;
        let patches = parse_unified_diff(&diff);
        for file in &mut files {
            file.patch = patches.get(&file.path).cloned();
        }
        Ok(files)
    }
}

impl crate::PullRequestReviewIssuesProvider for BitbucketAdapter {
    fn list_pull_request_review_issues(
        &self,
        reference: &PullRequestRef,
    ) -> Result<crate::PullRequestReviewIssues, HostingError> {
        #[derive(Deserialize)]
        struct Page<T> {
            values: Vec<T>,
            #[serde(default)]
            next: Option<String>,
        }
        #[derive(Deserialize)]
        struct ApiComment {
            id: u64,
            content: Option<CommentContent>,
            user: Option<CommentUser>,
            inline: Option<CommentInline>,
            links: Option<CommentLinks>,
            created_on: Option<String>,
            updated_on: Option<String>,
            deleted: Option<bool>,
        }
        #[derive(Deserialize)]
        struct CommentContent {
            raw: Option<String>,
            html: Option<String>,
        }
        #[derive(Deserialize)]
        struct CommentUser {
            display_name: Option<String>,
            nickname: Option<String>,
        }
        #[derive(Deserialize)]
        struct CommentInline {
            path: Option<String>,
            from: Option<u64>,
            to: Option<u64>,
        }
        #[derive(Deserialize)]
        struct CommentLinks {
            html: Option<CommentLink>,
        }
        #[derive(Deserialize)]
        struct CommentLink {
            href: String,
        }

        const PAGE_SIZE: usize = 100;
        const MAX_PAGES: usize = 30;
        let before = GitHostingProvider::get_pull_request(self, reference)?;
        let mut issues = Vec::new();
        let mut total_body_bytes = 0usize;
        let mut complete = false;
        for page in 1..=MAX_PAGES {
            let mut url = self.url(reference, "/comments")?;
            url.query_pairs_mut()
                .append_pair("pagelen", &PAGE_SIZE.to_string())
                .append_pair("page", &page.to_string());
            let batch: Page<ApiComment> = Self::json(self.get(url)?)?;
            for comment in batch.values {
                if comment.deleted.unwrap_or(false) {
                    continue;
                }
                let content = comment.content.unwrap_or(CommentContent {
                    raw: None,
                    html: None,
                });
                let body = content.raw.or(content.html).unwrap_or_default();
                total_body_bytes = total_body_bytes.saturating_add(body.len());
                if total_body_bytes > MAX_RESPONSE_BYTES as usize {
                    return Err(HostingError::InvalidResponse(
                        "Bitbucket review issue bodies exceed the aggregate response limit".into(),
                    ));
                }
                let (path, line, side) = match comment.inline {
                    Some(inline) => {
                        let is_new = inline.to.is_some();
                        (
                            inline.path,
                            inline.to.or(inline.from),
                            Some(if is_new { DiffSide::New } else { DiffSide::Old }),
                        )
                    }
                    None => (None, None, None),
                };
                issues.push(crate::PullRequestReviewIssue {
                    external_id: comment.id.to_string(),
                    author: comment
                        .user
                        .and_then(|user| user.display_name.or(user.nickname)),
                    body,
                    path,
                    line,
                    side,
                    source_url: comment
                        .links
                        .and_then(|links| links.html.map(|link| link.href)),
                    created_at: comment.created_on,
                    updated_at: comment.updated_on,
                    classification: "untrusted_external_review".into(),
                });
            }
            if batch.next.is_none() {
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
        Ok(crate::PullRequestReviewIssues {
            schema_version: 1,
            provider: "bitbucket".into(),
            pull_request: reference.clone(),
            revision: before.revision,
            complete,
            gate_eligible: false,
            issues,
        })
    }
}

fn parse_unified_diff(diff: &str) -> BTreeMap<String, String> {
    let mut patches = BTreeMap::new();
    let mut block = Vec::new();
    let mut path: Option<String> = None;
    let flush = |block: &mut Vec<String>,
                 path: &mut Option<String>,
                 patches: &mut BTreeMap<String, String>| {
        if let Some(path) = path.take() {
            patches.insert(path, block.join("\n"));
        }
        block.clear();
    };
    for line in diff.lines() {
        if line.starts_with("diff --git ") {
            flush(&mut block, &mut path, &mut patches);
        }
        if path.is_none() && line.starts_with("+++ b/") {
            let candidate = line
                .trim_start_matches("+++ b/")
                .split('\t')
                .next()
                .unwrap_or_default();
            if !candidate.starts_with('"') && !candidate.is_empty() {
                path = Some(candidate.to_owned());
            }
        }
        block.push(line.to_owned());
    }
    flush(&mut block, &mut path, &mut patches);
    patches
}

impl GitHostingProvider for BitbucketAdapter {
    fn provider_id(&self) -> &'static str {
        "bitbucket"
    }

    fn get_pull_request(
        &self,
        reference: &PullRequestRef,
    ) -> Result<PullRequestSnapshot, HostingError> {
        PullRequestContextProvider::get_pull_request_context(self, reference)
    }

    fn list_changed_files(
        &self,
        reference: &PullRequestRef,
        expected_revision: &str,
    ) -> Result<Vec<PullRequestFile>, HostingError> {
        PullRequestContextProvider::list_pull_request_context_files(
            self,
            reference,
            expected_revision,
        )
    }

    fn publish_review(
        &self,
        publication: ReviewPublication,
    ) -> Result<PublicationReceipt, HostingError> {
        publication
            .validate()
            .map_err(HostingError::InvalidResponse)?;
        let current = self.get_pull_request(&publication.pull_request)?;
        if current.revision != publication.expected_revision {
            return Err(HostingError::StaleRevision {
                expected: publication.expected_revision,
                actual: current.revision,
            });
        }
        if current.state != PullRequestState::Open {
            return Err(HostingError::InvalidResponse(
                "cannot publish to a closed Bitbucket pull request".into(),
            ));
        }

        let user_uuid = self.authenticated_uuid()?;

        // Bitbucket Cloud commit statuses are naturally idempotent: posting the
        // same key overwrites the status for this commit.
        let status_name = publication.check.name.chars().take(100).collect::<String>();
        let description = publication
            .check
            .summary
            .chars()
            .take(140)
            .collect::<String>();
        let state = match (publication.check.status, publication.check.conclusion) {
            (CheckStatus::Queued | CheckStatus::InProgress, _) => "INPROGRESS",
            (_, Some(CheckConclusion::Success)) => "SUCCESSFUL",
            // Bitbucket has no neutral state; a neutral check must never read
            // as a success, so it shows as stopped.
            (_, Some(CheckConclusion::Neutral)) => "STOPPED",
            (_, Some(CheckConclusion::Failure | CheckConclusion::ActionRequired)) => "FAILED",
            (_, Some(CheckConclusion::Cancelled | CheckConclusion::TimedOut)) => "STOPPED",
            _ => {
                return Err(HostingError::InvalidResponse(
                    "completed Bitbucket status requires a conclusion".into(),
                ))
            }
        };
        let source_branch = self.pull_request_source_branch(&publication.pull_request)?;
        let status_url = self.repository_url(
            &publication.pull_request,
            &format!("/commit/{}/statuses/build/", current.head_oid),
        )?;
        let status_body = serde_json::json!({
            "key": bitbucket_status_key(&publication.check.idempotency_key),
            "name": status_name,
            "state": state,
            "description": description,
            "refname": source_branch,
        });
        let status_response = self.send(Method::POST, status_url, Some(status_body))?;
        let status: serde_json::Value = Self::json(status_response)?;
        let check_id = status
            .get("uuid")
            .and_then(serde_json::Value::as_str)
            .or_else(|| status.get("key").and_then(serde_json::Value::as_str))
            .unwrap_or(&publication.check.idempotency_key)
            .to_owned();

        let comments_url = self.repository_url(
            &publication.pull_request,
            &format!("/pullrequests/{}/comments", publication.pull_request.number),
        )?;
        let existing_comments = self.list_comments(comments_url.clone())?;
        let mut thread_ids = BTreeMap::new();
        for thread in &publication.threads {
            let marker = format!("<!-- vee:{} -->", thread.fingerprint);
            let prior = existing_comments.iter().find(|comment| {
                comment.raw().contains(&marker) && comment.author_uuid() == user_uuid
            });
            // A recovered local intent may describe a thread whose remote
            // write never landed. Never create a new comment just to resolve
            // it; resolution only applies to an existing Vee-owned comment.
            if prior.is_none() && thread.resolution == ThreadResolution::Resolved {
                continue;
            }
            let raw = format!(
                "{}\n\n{}",
                thread.body_with_suggestion(SuggestionStyle::Diff),
                marker
            );
            let inline = match thread.side {
                DiffSide::New => serde_json::json!({"path": thread.path, "to": thread.line}),
                DiffSide::Old => serde_json::json!({"path": thread.path, "from": thread.line}),
            };
            let url = if let Some(comment) = prior {
                let base = self.repository_url(
                    &publication.pull_request,
                    &format!(
                        "/pullrequests/{}/comments/{}",
                        publication.pull_request.number, comment.id
                    ),
                )?;
                thread_ids.insert(thread.fingerprint.clone(), comment.id.to_string());
                base
            } else {
                comments_url.clone()
            };
            let body = serde_json::json!({"content": {"raw": raw}, "inline": inline});
            let method = if prior.is_some() {
                Method::PUT
            } else {
                Method::POST
            };
            let response = self.send(method, url, Some(body))?;
            let comment: serde_json::Value = Self::json(response)?;
            let comment_id = comment
                .get("id")
                .and_then(serde_json::Value::as_u64)
                .or_else(|| prior.map(|comment| comment.id));
            if let Some(id) = comment_id {
                thread_ids.insert(thread.fingerprint.clone(), id.to_string());
            }
            if let Some(comment_id) = comment_id {
                let was_resolved = prior.is_some_and(|comment| comment.resolution.is_some());
                let should_resolve = thread.resolution == ThreadResolution::Resolved;
                if was_resolved == should_resolve || (prior.is_none() && !should_resolve) {
                    continue;
                }
                let resolution_url = self.repository_url(
                    &publication.pull_request,
                    &format!(
                        "/pullrequests/{}/comments/{comment_id}/resolve",
                        publication.pull_request.number
                    ),
                )?;
                let method = match thread.resolution {
                    ThreadResolution::Open => Method::DELETE,
                    ThreadResolution::Resolved => Method::POST,
                };
                self.send(method, resolution_url, None)?;
            }
        }
        Ok(PublicationReceipt {
            provider_check_id: check_id,
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
        let event_key = header_value(headers, "x-event-key")
            .ok_or_else(|| HostingError::InvalidResponse("missing Bitbucket event key".into()))?;
        let event_id = header_value(headers, "x-request-uuid")
            .map(str::to_owned)
            .unwrap_or_else(|| {
                format!(
                    "sha256:{}",
                    Sha256::digest(body)
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>()
                )
            });
        let attempt = header_value(headers, "x-attempt-number")
            .and_then(|value| value.parse().ok())
            .filter(|value| *value > 0)
            .unwrap_or(1);
        let payload: serde_json::Value = serde_json::from_slice(body).map_err(|error| {
            HostingError::InvalidResponse(format!("invalid Bitbucket webhook JSON: {error}"))
        })?;
        let pull = payload.get("pullrequest");
        let repo = payload.get("repository");
        let pull_number = pull
            .and_then(|value| value.get("id"))
            .and_then(serde_json::Value::as_u64);
        let full_name = repo
            .and_then(|value| value.get("full_name"))
            .and_then(serde_json::Value::as_str);
        let pr = match (pull_number, full_name) {
            (Some(number), Some(name)) => Some(PullRequestRef {
                repository: crate::RepositoryRef {
                    host: "bitbucket.org".into(),
                    full_name: name.to_owned(),
                },
                number,
            }),
            _ => None,
        };
        let base_oid = pull
            .and_then(|value| value.pointer("/destination/commit/hash"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        let head_oid = pull
            .and_then(|value| value.pointer("/source/commit/hash"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        let action = match event_key {
            "pullrequest:created" => Some("opened"),
            "pullrequest:updated" => Some("synchronize"),
            "pullrequest:fulfilled" | "pullrequest:rejected" | "pullrequest:declined" => {
                Some("closed")
            }
            _ => None,
        }
        .map(str::to_owned);
        let envelope = WebhookEnvelope {
            provider: "bitbucket".into(),
            event_id,
            event_type: "pull_request".into(),
            delivery_attempt: attempt,
            pull_request: pr,
            action,
            base_oid,
            head_oid,
            signature_verified: true,
        };
        envelope.validate().map_err(HostingError::InvalidResponse)?;
        Ok(envelope)
    }
}

impl BitbucketAdapter {
    fn authenticated_uuid(&self) -> Result<String, HostingError> {
        #[derive(Deserialize)]
        struct ApiUser {
            uuid: String,
        }
        let user_url = self
            .config
            .api_base
            .join("user")
            .map_err(|error| HostingError::InvalidResponse(error.to_string()))?;
        let user: ApiUser = Self::json(self.get(user_url)?)?;
        if user.uuid.trim().is_empty() {
            return Err(HostingError::InvalidResponse(
                "Bitbucket authenticated user has no UUID".into(),
            ));
        }
        Ok(user.uuid)
    }

    /// The full hash of a commit. Bitbucket abbreviates the commits of a pull
    /// request to 12 digits; Vee compares and publishes full hashes.
    fn full_hash(&self, reference: &PullRequestRef, hash: &str) -> Result<String, HostingError> {
        let hash = hash.to_ascii_lowercase();
        if hash.len() < 7 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(HostingError::InvalidResponse(
                "Bitbucket returned an invalid commit hash".into(),
            ));
        }
        if matches!(hash.len(), 40 | 64) {
            return Ok(hash);
        }
        #[derive(Deserialize)]
        struct ApiCommit {
            hash: String,
        }
        let commit: ApiCommit =
            Self::json(self.get(self.repository_url(reference, &format!("/commit/{hash}"))?)?)?;
        let full = commit.hash.to_ascii_lowercase();
        if !matches!(full.len(), 40 | 64)
            || !full.bytes().all(|byte| byte.is_ascii_hexdigit())
            || !full.starts_with(&hash)
        {
            return Err(HostingError::InvalidResponse(
                "Bitbucket resolved an abbreviated hash to a different commit".into(),
            ));
        }
        Ok(full)
    }

    fn pull_request_source_branch(
        &self,
        reference: &PullRequestRef,
    ) -> Result<String, HostingError> {
        #[derive(Deserialize)]
        struct Branch {
            name: String,
        }
        #[derive(Deserialize)]
        struct Source {
            branch: Branch,
        }
        #[derive(Deserialize)]
        struct ApiPr {
            source: Source,
        }
        let response = self.get(self.url(reference, "")?)?;
        let pr: ApiPr = Self::json(response)?;
        Ok(pr.source.branch.name)
    }

    fn list_comments(&self, base: Url) -> Result<Vec<BitbucketComment>, HostingError> {
        #[derive(Deserialize)]
        struct Page {
            values: Vec<BitbucketComment>,
            #[serde(default)]
            next: Option<String>,
        }
        let mut comments = Vec::new();
        for page in 1..=30 {
            let mut url = base.clone();
            url.query_pairs_mut()
                .append_pair("pagelen", "100")
                .append_pair("page", &page.to_string());
            let batch: Page = Self::json(self.get(url)?)?;
            let count = batch.values.len();
            comments.extend(batch.values);
            if batch.next.is_none() || count < 100 {
                return Ok(comments);
            }
        }
        Err(HostingError::InvalidResponse(
            "pull request exceeds the 3000-comment API limit".into(),
        ))
    }
}

/// Bitbucket approvals carry no text and no commit: an approval stands until
/// it is withdrawn, or until a push resets it where the repository is set to
/// reset approvals on changes.
impl crate::PullRequestApprovalProvider for BitbucketAdapter {
    fn own_approval_stands(&self, reference: &PullRequestRef) -> Result<bool, HostingError> {
        #[derive(Deserialize)]
        struct User {
            uuid: String,
        }
        #[derive(Deserialize)]
        struct Participant {
            user: User,
            #[serde(default)]
            approved: bool,
        }
        #[derive(Deserialize)]
        struct ApiPr {
            #[serde(default)]
            participants: Vec<Participant>,
        }
        let uuid = self.authenticated_uuid()?;
        let pr: ApiPr = Self::json(self.get(self.url(reference, "")?)?)?;
        Ok(pr
            .participants
            .iter()
            .any(|participant| participant.approved && participant.user.uuid == uuid))
    }

    fn approve_head(
        &self,
        reference: &PullRequestRef,
        head_oid: &str,
        _message: &str,
    ) -> Result<(), HostingError> {
        let current = self.get_pull_request(reference)?;
        if current.state != PullRequestState::Open || !crate::same_head(&current.head_oid, head_oid)
        {
            return Err(HostingError::StaleRevision {
                expected: head_oid.to_owned(),
                actual: current.head_oid,
            });
        }
        self.send(Method::POST, self.url(reference, "/approve")?, None)?;
        Ok(())
    }

    fn withdraw_approval(
        &self,
        reference: &PullRequestRef,
        _message: &str,
    ) -> Result<(), HostingError> {
        match self.send(Method::DELETE, self.url(reference, "/approve")?, None) {
            Ok(_) | Err(HostingError::NotFound) => Ok(()),
            Err(error) => Err(error),
        }
    }
}

#[derive(Deserialize)]
struct BitbucketComment {
    id: u64,
    #[serde(default)]
    content: Option<BitbucketCommentContent>,
    #[serde(default)]
    user: Option<BitbucketCommentUser>,
    #[serde(default)]
    resolution: Option<serde_json::Value>,
}

impl BitbucketComment {
    fn raw(&self) -> &str {
        self.content
            .as_ref()
            .map(|content| content.raw.as_str())
            .unwrap_or("")
    }
    fn author_uuid(&self) -> &str {
        self.user
            .as_ref()
            .map(|user| user.uuid.as_str())
            .unwrap_or("")
    }
}

#[derive(Deserialize)]
struct BitbucketCommentContent {
    #[serde(default)]
    raw: String,
}
#[derive(Deserialize)]
struct BitbucketCommentUser {
    #[serde(default)]
    uuid: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    fn fixture(response: &'static str) -> (String, thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let response = response.to_owned();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 4096];
            let size = stream.read(&mut request).unwrap();
            stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", response.len(), response).as_bytes()).unwrap();
            String::from_utf8_lossy(&request[..size]).into_owned()
        });
        (format!("http://{address}/2.0/"), handle)
    }

    fn fixture_sequence(responses: Vec<String>) -> (String, thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let mut requests = Vec::new();
            for response in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0; 4096];
                let size = stream.read(&mut request).unwrap();
                requests.push(String::from_utf8_lossy(&request[..size]).into_owned());
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}", response.len()).unwrap();
                stream.flush().unwrap();
            }
            requests
        });
        (format!("http://{address}/2.0/"), handle)
    }

    #[test]
    fn bitbucket_diffstat_pagination_bound_never_returns_partial_context() {
        let pr = r#"{"id":7,"title":"Review","description":null,"state":"OPEN","updated_on":"2026-11-15T10:00:00Z","source":{"commit":{"hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}},"destination":{"commit":{"hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}"#.to_owned();
        let mut responses = vec![pr];
        for page in 0..30 {
            let values = (0..90)
                .map(|file| {
                    serde_json::json!({
                        "status": "modified",
                        "new": { "path": format!("src/{page}-{file}.rs") }
                    })
                })
                .collect::<Vec<_>>();
            responses.push(
                serde_json::json!({ "values": values, "next": "https://api.example/next" })
                    .to_string(),
            );
        }
        let (base, worker) = fixture_sequence(responses);
        let adapter =
            BitbucketAdapter::new(BitbucketConfig::new(&base, "token".into()).unwrap()).unwrap();
        let reference = PullRequestRef {
            repository: crate::RepositoryRef {
                host: "127.0.0.1".into(),
                full_name: "team/repo".into(),
            },
            number: 7,
        };
        let revision = format!("{}:{}:2026-11-15T10:00:00Z", "a".repeat(40), "b".repeat(40));
        let result = PullRequestContextProvider::list_pull_request_context_files(
            &adapter, &reference, &revision,
        );
        assert!(
            matches!(result, Err(HostingError::InvalidResponse(message)) if message.contains("pagination exceeded"))
        );
        let requests = worker.join().unwrap();
        assert_eq!(requests.len(), 31);
        assert!(requests[30].contains("/diffstat?pagelen=100&page=30"));
    }

    #[test]
    fn bitbucket_diffstat_enforces_aggregate_response_bytes_across_pages() {
        let pr = r#"{"id":7,"title":"Review","description":null,"state":"OPEN","updated_on":"2026-11-15T10:00:00Z","source":{"commit":{"hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}},"destination":{"commit":{"hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}"#.to_owned();
        let mut responses = vec![pr];
        for page in 0..2 {
            let values = (0..100)
                .map(|file| {
                    serde_json::json!({
                        "status": "modified",
                        "new": { "path": format!("src/{page}-{file}.rs") }
                    })
                })
                .collect::<Vec<_>>();
            let mut response = serde_json::json!({
                "values": values,
                "padding": "x".repeat(2_700_000)
            });
            if page == 0 {
                response["next"] = serde_json::json!("https://api.example/next");
            }
            responses.push(response.to_string());
        }
        let (base, worker) = fixture_sequence(responses);
        let adapter =
            BitbucketAdapter::new(BitbucketConfig::new(&base, "token".into()).unwrap()).unwrap();
        let reference = PullRequestRef {
            repository: crate::RepositoryRef {
                host: "127.0.0.1".into(),
                full_name: "team/repo".into(),
            },
            number: 7,
        };
        let revision = format!("{}:{}:2026-11-15T10:00:00Z", "a".repeat(40), "b".repeat(40));
        let result = PullRequestContextProvider::list_pull_request_context_files(
            &adapter, &reference, &revision,
        );
        assert!(
            matches!(result, Err(HostingError::InvalidResponse(message)) if message.contains("aggregate response limit"))
        );
        assert_eq!(worker.join().unwrap().len(), 3);
    }

    #[test]
    fn bitbucket_diffstat_accepts_exactly_3000_files_when_pagination_is_complete() {
        let pr = r#"{"id":7,"title":"Review","description":null,"state":"OPEN","updated_on":"2026-11-15T10:00:00Z","source":{"commit":{"hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}},"destination":{"commit":{"hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}"#.to_owned();
        let mut responses = vec![pr];
        for page in 0..30 {
            let values = (0..100)
                .map(|file| {
                    serde_json::json!({
                        "status": "modified",
                        "new": { "path": format!("src/{page}-{file}.rs") }
                    })
                })
                .collect::<Vec<_>>();
            let mut response = serde_json::json!({ "values": values });
            if page < 29 {
                response["next"] = serde_json::json!("https://api.example/next");
            }
            responses.push(response.to_string());
        }
        responses.push(String::new()); // Unified diff, empty but complete.
        let (base, worker) = fixture_sequence(responses);
        let adapter =
            BitbucketAdapter::new(BitbucketConfig::new(&base, "token".into()).unwrap()).unwrap();
        let reference = PullRequestRef {
            repository: crate::RepositoryRef {
                host: "127.0.0.1".into(),
                full_name: "team/repo".into(),
            },
            number: 7,
        };
        let revision = format!("{}:{}:2026-11-15T10:00:00Z", "a".repeat(40), "b".repeat(40));

        let files = PullRequestContextProvider::list_pull_request_context_files(
            &adapter, &reference, &revision,
        )
        .unwrap();

        assert_eq!(files.len(), 3000);
        let requests = worker.join().unwrap();
        assert_eq!(requests.len(), 32);
        assert!(requests[30].contains("/diffstat?pagelen=100&page=30"));
        assert!(requests[31].contains("/diff"));
    }

    #[test]
    fn reads_revision_bound_pr_context_without_redirects_or_writes() {
        let (base, server) = fixture(
            r#"{"id":7,"title":"Improve validation","description":"Details","state":"OPEN","updated_on":"2026-11-15T10:00:00Z","source":{"commit":{"hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}},"destination":{"commit":{"hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}"#,
        );
        let adapter =
            BitbucketAdapter::new(BitbucketConfig::new(&base, "token".into()).unwrap()).unwrap();
        let reference = PullRequestRef {
            repository: crate::RepositoryRef {
                host: "127.0.0.1".into(),
                full_name: "team/repo".into(),
            },
            number: 7,
        };
        let pr = adapter.get_pull_request_context(&reference).unwrap();
        assert_eq!(pr.state, PullRequestState::Open);
        assert_eq!(
            pr.revision,
            format!("{}:{}:2026-11-15T10:00:00Z", "a".repeat(40), "b".repeat(40))
        );
        let request = server.join().unwrap();
        assert!(request.starts_with("GET /2.0/repositories/team/repo/pullrequests/7 HTTP/1.1"));
        assert!(request
            .to_ascii_lowercase()
            .contains("authorization: bearer token"));
    }

    #[test]
    fn bitbucket_review_issues_are_revision_bound_and_gate_ineligible() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let pr = r#"{"id":7,"title":"Review","description":null,"state":"OPEN","updated_on":"2026-11-15T10:00:00Z","source":{"commit":{"hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}},"destination":{"commit":{"hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}"#;
            let comments = r#"{"values":[{"id":81,"content":{"raw":"Check this branch"},"user":{"display_name":"Reviewer","nickname":"reviewer"},"inline":{"path":"src/lib.rs","from":12,"to":14},"links":{"html":{"href":"https://bitbucket.org/team/repo/pull-requests/7#comment-81"}},"created_on":"2026-11-15T10:00:00Z","updated_on":"2026-11-15T10:00:00Z"},{"id":82,"content":{"raw":"Deleted"},"deleted":true}],"next":null}"#;
            let mut requests = Vec::new();
            for body in [pr, comments, pr] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0; 4096];
                let size = stream.read(&mut request).unwrap();
                requests.push(String::from_utf8_lossy(&request[..size]).to_string());
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
                stream.flush().unwrap();
            }
            requests
        });
        let base = format!("http://{address}/2.0/");
        let adapter =
            BitbucketAdapter::new(BitbucketConfig::new(&base, "token".into()).unwrap()).unwrap();
        let reference = PullRequestRef {
            repository: crate::RepositoryRef {
                host: "127.0.0.1".into(),
                full_name: "team/repo".into(),
            },
            number: 7,
        };
        let report = crate::PullRequestReviewIssuesProvider::list_pull_request_review_issues(
            &adapter, &reference,
        )
        .unwrap();
        assert!(report.complete);
        assert!(!report.gate_eligible);
        assert_eq!(report.provider, "bitbucket");
        assert_eq!(report.issues.len(), 1);
        assert_eq!(report.issues[0].external_id, "81");
        assert_eq!(report.issues[0].author.as_deref(), Some("Reviewer"));
        assert_eq!(report.issues[0].path.as_deref(), Some("src/lib.rs"));
        assert_eq!(report.issues[0].line, Some(14));
        assert_eq!(report.issues[0].side, Some(DiffSide::New));
        assert_eq!(report.issues[0].classification, "untrusted_external_review");
        let requests = worker.join().unwrap();
        assert!(requests[1].contains("/pullrequests/7/comments?pagelen=100&page=1"));
    }

    #[test]
    fn bitbucket_review_issue_page_bound_is_reported_as_incomplete() {
        let pr = r#"{"id":7,"title":"Review","description":null,"state":"OPEN","updated_on":"2026-11-15T10:00:00Z","source":{"commit":{"hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}},"destination":{"commit":{"hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}"#.to_owned();
        let mut responses = vec![pr.clone()];
        for page in 1..=30 {
            let comments = serde_json::json!({
                "values": [{
                    "id": page,
                    "content": {"raw": "bounded comment"},
                    "user": {"display_name": "Reviewer"}
                }],
                "next": format!("https://api.example/comments?page={}", page + 1)
            });
            responses.push(comments.to_string());
        }
        responses.push(pr);
        let (base, worker) = fixture_sequence(responses);
        let adapter =
            BitbucketAdapter::new(BitbucketConfig::new(&base, "token".into()).unwrap()).unwrap();
        let reference = PullRequestRef {
            repository: crate::RepositoryRef {
                host: "127.0.0.1".into(),
                full_name: "team/repo".into(),
            },
            number: 7,
        };
        let report = crate::PullRequestReviewIssuesProvider::list_pull_request_review_issues(
            &adapter, &reference,
        )
        .unwrap();
        assert!(!report.complete);
        assert_eq!(report.issues.len(), 30);
        assert!(!report.gate_eligible);
        let requests = worker.join().unwrap();
        assert_eq!(requests.len(), 32);
        assert!(requests[30].contains("/pullrequests/7/comments?pagelen=100&page=30"));
    }

    #[test]
    fn rejects_non_loopback_http_api_urls() {
        assert!(BitbucketConfig::new("http://bitbucket.example/2.0/", "token".into()).is_err());
    }

    #[test]
    fn parses_per_file_unified_patches_for_line_evidence() {
        let diff = "diff --git a/src/lib.rs b/src/lib.rs\nindex 123..456 100644\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1 +1,2 @@\n old\n+new\n";
        let patches = parse_unified_diff(diff);
        assert!(patches["src/lib.rs"].contains("+new"));
        assert!(!patches.contains_key("missing.rs"));
    }

    #[test]
    fn verifies_bitbucket_webhook_hmac_and_normalizes_pr_update() {
        let vector_config = BitbucketConfig::new("https://api.bitbucket.org/2.0/", "token".into())
            .unwrap()
            .with_webhook_secret("It's a Secret to Everybody".into());
        let vector_adapter = BitbucketAdapter::new(vector_config).unwrap();
        vector_adapter
            .verify_signature(
                &BTreeMap::from([(
                    "X-Hub-Signature".into(),
                    "sha256=a4771c39fbe90f317c7824e83ddef3caae9cb3d976c214ace1f2937e133263c9"
                        .into(),
                )]),
                b"Hello World!",
            )
            .unwrap();
        let body = br#"{"repository":{"full_name":"team/repo"},"pullrequest":{"id":7,"source":{"commit":{"hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}},"destination":{"commit":{"hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}}"#;
        let mut mac = HmacSha256::new_from_slice(b"hook-secret").unwrap();
        mac.update(body);
        let signature = mac
            .finalize()
            .into_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let headers = BTreeMap::from([
            ("X-Hub-Signature".into(), format!("sha256={signature}")),
            ("X-Event-Key".into(), "pullrequest:updated".into()),
            ("X-Request-UUID".into(), "delivery-1".into()),
            ("X-Attempt-Number".into(), "2".into()),
        ]);
        let config = BitbucketConfig::new("https://api.bitbucket.org/2.0/", "token".into())
            .unwrap()
            .with_webhook_secret("hook-secret".into());
        let adapter = BitbucketAdapter::new(config).unwrap();
        let event = adapter.verify_webhook(&headers, body).unwrap();
        assert_eq!(event.provider, "bitbucket");
        assert_eq!(event.event_id, "delivery-1");
        assert_eq!(event.delivery_attempt, 2);
        assert_eq!(event.action.as_deref(), Some("synchronize"));
        assert_eq!(event.base_oid.as_deref(), Some("a".repeat(40).as_str()));
        assert_eq!(event.head_oid.as_deref(), Some("b".repeat(40).as_str()));
        assert_eq!(
            event.pull_request.unwrap().repository.full_name,
            "team/repo"
        );
        assert!(adapter.verify_webhook(&headers, b"tampered").is_err());
    }

    #[test]
    fn resolving_missing_owned_thread_does_not_create_comment() {
        use std::{
            io::{Read, Write},
            net::TcpListener,
            thread,
        };

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut requests = Vec::new();
            for _ in 0..7 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0u8; 16_384];
                let size = stream.read(&mut request).unwrap();
                let raw = String::from_utf8_lossy(&request[..size]).to_string();
                let path = raw.lines().next().unwrap_or_default();
                let (status, body) = if path.contains("/pullrequests/7 HTTP") {
                    (
                        "200 OK",
                        r#"{"id":7,"title":"T","state":"OPEN","updated_on":"2026-11-15T10:00:00Z","source":{"branch":{"name":"feature"},"commit":{"hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}},"destination":{"commit":{"hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}"#,
                    )
                } else if path.starts_with("GET /2.0/user ") {
                    ("200 OK", r#"{"uuid":"{vee-bot}"}"#)
                } else if path.starts_with("POST /2.0/repositories/team/repo/commit/") {
                    ("201 Created", r#"{"uuid":"status-uuid","key":"vee-key"}"#)
                } else if path
                    .starts_with("GET /2.0/repositories/team/repo/pullrequests/7/comments?")
                {
                    (
                        "200 OK",
                        r#"{"values":[{"id":99,"content":{"raw":"Existing finding <!-- vee:sha256:existing -->"},"user":{"uuid":"{vee-bot}"}}]}"#,
                    )
                } else if path
                    .starts_with("PUT /2.0/repositories/team/repo/pullrequests/7/comments/99 ")
                {
                    ("200 OK", r#"{"id":99}"#)
                } else if path.starts_with(
                    "POST /2.0/repositories/team/repo/pullrequests/7/comments/99/resolve ",
                ) {
                    ("200 OK", r#"{"type":"pullrequest_comment_resolution"}"#)
                } else {
                    panic!("unexpected Bitbucket request: {path}")
                };
                requests.push(raw);
                write!(stream, "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
                stream.flush().unwrap();
            }
            requests
        });
        let base = format!("http://{address}/2.0/");
        let adapter =
            BitbucketAdapter::new(BitbucketConfig::new(&base, "token".into()).unwrap()).unwrap();
        let pull_request = PullRequestRef {
            repository: crate::RepositoryRef {
                host: "127.0.0.1".into(),
                full_name: "team/repo".into(),
            },
            number: 7,
        };
        let revision = format!("{}:{}:2026-11-15T10:00:00Z", "a".repeat(40), "b".repeat(40));
        let publication = ReviewPublication {
            pull_request: pull_request.clone(),
            expected_revision: revision.clone(),
            check: crate::CheckRun {
                pull_request: pull_request.clone(),
                external_id: "review-1".into(),
                name: "Vee".into(),
                status: CheckStatus::Completed,
                conclusion: Some(CheckConclusion::Failure),
                title: "Vee blocked".into(),
                summary: "High severity finding".into(),
                snapshot_id: "snapshot-1".into(),
                idempotency_key: "review-1".into(),
            },
            threads: ["sha256:missing", "sha256:existing"]
                .into_iter()
                .map(|fingerprint| crate::ReviewThread {
                    suggestion: None,
                    pull_request: pull_request.clone(),
                    fingerprint: fingerprint.into(),
                    path: "src/lib.rs".into(),
                    line: 12,
                    side: DiffSide::New,
                    body: "High severity finding".into(),
                    resolution: ThreadResolution::Resolved,
                    snapshot_id: "snapshot-1".into(),
                    idempotency_key: format!("review-1:{fingerprint}"),
                })
                .collect(),
        };
        let receipt = adapter.publish_review(publication).unwrap();
        assert_eq!(receipt.provider_check_id, "status-uuid");
        assert_eq!(
            receipt
                .thread_ids
                .get("sha256:existing")
                .map(String::as_str),
            Some("99")
        );
        assert!(!receipt.thread_ids.contains_key("sha256:missing"));
        assert_eq!(receipt.resulting_revision, revision);
        let requests = server.join().unwrap();
        assert!(requests
            .iter()
            .any(|request| request.contains("\"state\":\"FAILED\"")));
        assert!(requests
            .iter()
            .any(|request| request.contains("\"refname\":\"feature\"")));
        assert!(requests.iter().all(|request| request
            .to_ascii_lowercase()
            .contains("authorization: bearer token")));
        assert!(requests.iter().any(|request| request
            .starts_with("PUT /2.0/repositories/team/repo/pullrequests/7/comments/99 ")));
        assert!(requests.iter().any(|request| request
            .starts_with("POST /2.0/repositories/team/repo/pullrequests/7/comments/99/resolve ")));
        assert!(requests.iter().all(|request| !request
            .starts_with("POST /2.0/repositories/team/repo/pullrequests/7/comments HTTP")));
    }
}
