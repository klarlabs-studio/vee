//! Bitbucket Data Center (and Server) adapter, over REST API 1.0.
//!
//! Context, publication, review issues, approval and webhooks for a
//! self-hosted server. A repository is `PROJECT/repo-slug`; the server is
//! named by its base URL, e.g. `https://git.example.com/` or one with a
//! context path such as `https://example.com/bitbucket/`.
//! Publication writes one build status per check name on the head commit,
//! one summary comment per check name, and one inline comment per finding,
//! each found again on republish through markers in Vee's own comments
//! (ADR 0047).

use crate::bitbucket::{decode_hex, header_value};
use crate::{
    same_head, CheckConclusion, CheckStatus, DiffSide, FileChange, GitHostingProvider,
    HostingError, PublicationReceipt, PullRequestContextProvider, PullRequestFile, PullRequestRef,
    PullRequestReviewIssue, PullRequestReviewIssues, PullRequestSnapshot, PullRequestState,
    RepositoryRef, ReviewPublication, ReviewThread, SuggestionStyle, ThreadResolution,
    WebhookEnvelope,
};
use hmac::{Hmac, Mac};
use reqwest::{blocking::Client, header, Method, StatusCode, Url};
use serde::{de::DeserializeOwned, Deserialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io::Read, sync::OnceLock, time::Duration};

/// The provider ID: in configuration, receipts and the webhook path.
pub const PROVIDER_ID: &str = "bitbucket-data-center";
const MAX_RESPONSE_BYTES: u64 = 5_242_880;
const MAX_ERROR_BYTES: u64 = 65_536;
const PAGE_SIZE: u64 = 100;
const MAX_PAGES: usize = 30;
/// Build status `name` and `description` are stored in 255 characters.
const MAX_BUILD_TEXT: usize = 255;
const SUMMARY_MARKER: &str = "<!-- vee:summary:";
type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct BitbucketDataCenterConfig {
    /// The server's base URL, ending in `/`; REST paths are joined to it.
    pub base_url: Url,
    pub token: String,
    pub webhook_secret: String,
    pub timeout: Duration,
}

impl BitbucketDataCenterConfig {
    /// A configuration for the server at `base_url`. HTTPS is required; plain
    /// HTTP is accepted only on loopback, for tests and local tunnels.
    pub fn new(base_url: &str, token: String) -> Result<Self, String> {
        let mut base_url = Url::parse(base_url).map_err(|error| error.to_string())?;
        let loopback = matches!(
            base_url.host_str(),
            Some("127.0.0.1" | "localhost" | "[::1]" | "::1")
        );
        if !matches!(base_url.scheme(), "https" | "http")
            || (base_url.scheme() == "http" && !loopback)
            || base_url.host_str().is_none()
            || !base_url.username().is_empty()
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
            || token.trim().is_empty()
        {
            return Err(
                "Bitbucket Data Center needs an https:// base URL without credentials, query or fragment, and a token; HTTP is allowed only on loopback"
                    .into(),
            );
        }
        if !base_url.path().ends_with('/') {
            let path = format!("{}/", base_url.path());
            base_url.set_path(&path);
        }
        Ok(Self {
            base_url,
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

pub struct BitbucketDataCenterAdapter {
    config: BitbucketDataCenterConfig,
    client: Client,
    /// The token's user name, read once from the `X-AUSERNAME` header.
    current_user: OnceLock<String>,
}

/// A repository on the server: its project key and repository slug.
struct RepositoryPath {
    project: String,
    slug: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApiPullRequest {
    id: u64,
    version: u64,
    title: String,
    #[serde(default)]
    description: Option<String>,
    state: String,
    from_ref: ApiRef,
    to_ref: ApiRef,
    #[serde(default)]
    reviewers: Vec<ApiParticipant>,
    #[serde(default)]
    participants: Vec<ApiParticipant>,
}

impl ApiPullRequest {
    fn participant(&self, name: &str) -> Option<&ApiParticipant> {
        self.reviewers
            .iter()
            .chain(&self.participants)
            .find(|participant| participant.user.name.eq_ignore_ascii_case(name))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApiRef {
    id: String,
    latest_commit: String,
}

#[derive(Deserialize)]
struct ApiParticipant {
    user: ApiUser,
    #[serde(default)]
    approved: bool,
    #[serde(default)]
    status: Option<String>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApiUser {
    name: String,
    #[serde(default)]
    slug: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Page<T> {
    #[serde(default = "Vec::new")]
    values: Vec<T>,
    #[serde(default)]
    is_last_page: bool,
    #[serde(default)]
    next_page_start: Option<u64>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApiComment {
    id: u64,
    version: u64,
    #[serde(default)]
    text: String,
    #[serde(default)]
    author: Option<ApiUser>,
    #[serde(default)]
    created_date: Option<i64>,
    #[serde(default)]
    updated_date: Option<i64>,
    #[serde(default)]
    thread_resolved: bool,
    #[serde(default)]
    anchor: Option<ApiAnchor>,
    #[serde(default)]
    comments: Vec<ApiComment>,
}

impl ApiComment {
    fn authored_by(&self, name: &str) -> bool {
        self.author
            .as_ref()
            .is_some_and(|author| author.name.eq_ignore_ascii_case(name))
    }
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApiAnchor {
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    line: Option<u64>,
    #[serde(default)]
    line_type: Option<String>,
    #[serde(default)]
    file_type: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApiActivity {
    action: String,
    #[serde(default)]
    comment_action: Option<String>,
    #[serde(default)]
    comment: Option<ApiComment>,
    #[serde(default)]
    comment_anchor: Option<ApiAnchor>,
}

/// A comment as the pull request's activity shows it, with its anchor.
struct ActivityComment {
    comment: ApiComment,
    /// Whether the activity started a thread rather than replied to one.
    root: bool,
}

impl BitbucketDataCenterAdapter {
    pub fn new(config: BitbucketDataCenterConfig) -> Result<Self, String> {
        let client = Client::builder()
            .timeout(config.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| error.to_string())?;
        Ok(Self {
            config,
            client,
            current_user: OnceLock::new(),
        })
    }

    /// The host a repository on this server is named by: the base URL's host,
    /// with its port when the URL names one.
    pub fn repository_host(&self) -> String {
        let host = self.config.base_url.host_str().unwrap_or_default();
        match self.config.base_url.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_owned(),
        }
    }

    fn repository_path(&self, repository: &RepositoryRef) -> Result<RepositoryPath, HostingError> {
        repository
            .validate()
            .map_err(HostingError::InvalidResponse)?;
        let host = self.config.base_url.host_str().unwrap_or_default();
        let matches_host = repository.host.eq_ignore_ascii_case(host)
            || repository
                .host
                .eq_ignore_ascii_case(&self.repository_host());
        if !matches_host {
            return Err(HostingError::InvalidResponse(
                "repository host does not match the configured Bitbucket Data Center server".into(),
            ));
        }
        match repository.full_name.split('/').collect::<Vec<_>>()[..] {
            [project, slug] => Ok(RepositoryPath {
                project: project.to_owned(),
                slug: slug.to_owned(),
            }),
            _ => Err(HostingError::InvalidResponse(
                "a Bitbucket Data Center repository is PROJECT/repository-slug".into(),
            )),
        }
    }

    fn rest_url(&self, path: &str) -> Url {
        let mut url = self.config.base_url.clone();
        let prefix = url.path().trim_end_matches('/').to_owned();
        url.set_path(&format!("{prefix}/rest/{path}"));
        url
    }

    fn pull_request_path(&self, reference: &PullRequestRef) -> Result<String, HostingError> {
        reference
            .validate()
            .map_err(HostingError::InvalidResponse)?;
        let repository = self.repository_path(&reference.repository)?;
        Ok(format!(
            "projects/{}/repos/{}/pull-requests/{}",
            repository.project, repository.slug, reference.number
        ))
    }

    fn pull_request_url(
        &self,
        reference: &PullRequestRef,
        suffix: &str,
    ) -> Result<Url, HostingError> {
        let path = self.pull_request_path(reference)?;
        Ok(self.rest_url(&format!("api/1.0/{path}{suffix}")))
    }

    /// The pull request's page in the web interface.
    fn web_url(&self, reference: &PullRequestRef, suffix: &str) -> Result<Url, HostingError> {
        let path = self.pull_request_path(reference)?;
        let mut url = self.config.base_url.clone();
        let prefix = url.path().trim_end_matches('/').to_owned();
        url.set_path(&format!("{prefix}/{path}{suffix}"));
        Ok(url)
    }

    fn send(
        &self,
        method: Method,
        url: Url,
        accept: &str,
        body: Option<serde_json::Value>,
    ) -> Result<reqwest::blocking::Response, HostingError> {
        let mut request = self
            .client
            .request(method, url)
            .bearer_auth(&self.config.token)
            .header(header::ACCEPT, accept)
            // Bitbucket's XSRF check applies to browser-style requests only;
            // the header makes the intent explicit for every write.
            .header("X-Atlassian-Token", "no-check");
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().map_err(|error| {
            HostingError::Transport(format!("requesting Bitbucket Data Center API: {error}"))
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
                    expected: "current pull request version".into(),
                    actual: "Bitbucket Data Center rejected an out-of-date update".into(),
                })
            }
            status => Err(HostingError::Transport(format!(
                "Bitbucket Data Center returned HTTP {status}{}",
                error_message(response)
                    .map(|message| format!(": {message}"))
                    .unwrap_or_default()
            ))),
        }
    }

    fn get(&self, url: Url) -> Result<reqwest::blocking::Response, HostingError> {
        self.send(Method::GET, url, "application/json", None)
    }

    fn write(
        &self,
        method: Method,
        url: Url,
        body: serde_json::Value,
    ) -> Result<reqwest::blocking::Response, HostingError> {
        self.send(method, url, "application/json", Some(body))
    }

    fn json<T: DeserializeOwned>(response: reqwest::blocking::Response) -> Result<T, HostingError> {
        Self::json_with_size(response).map(|(value, _)| value)
    }

    fn json_with_size<T: DeserializeOwned>(
        response: reqwest::blocking::Response,
    ) -> Result<(T, usize), HostingError> {
        let bytes = bounded_body(response, "response")?;
        let value = serde_json::from_slice(&bytes).map_err(|error| {
            HostingError::InvalidResponse(format!("invalid Bitbucket Data Center JSON: {error}"))
        })?;
        Ok((value, bytes.len()))
    }

    /// Every page of a paged resource, up to the page bound. The flag says
    /// whether the last page was reached; bodies are bounded in aggregate.
    fn paged<T: DeserializeOwned>(
        &self,
        base: &Url,
        query: &[(&str, &str)],
    ) -> Result<(Vec<T>, bool), HostingError> {
        let mut values = Vec::new();
        let mut start = 0_u64;
        let mut aggregate_bytes = 0_u64;
        for _ in 0..MAX_PAGES {
            let mut url = base.clone();
            {
                let mut pairs = url.query_pairs_mut();
                for (name, value) in query {
                    pairs.append_pair(name, value);
                }
                pairs
                    .append_pair("start", &start.to_string())
                    .append_pair("limit", &PAGE_SIZE.to_string());
            }
            let (page, size): (Page<T>, usize) = Self::json_with_size(self.get(url)?)?;
            aggregate_bytes = aggregate_bytes.saturating_add(size as u64);
            if aggregate_bytes > MAX_RESPONSE_BYTES {
                return Err(HostingError::InvalidResponse(
                    "Bitbucket Data Center pages exceed the 5 MiB aggregate response limit".into(),
                ));
            }
            let count = page.values.len() as u64;
            values.extend(page.values);
            if page.is_last_page {
                return Ok((values, true));
            }
            let next = page.next_page_start.unwrap_or(start + count);
            if next <= start {
                return Err(HostingError::InvalidResponse(
                    "Bitbucket Data Center pagination did not advance".into(),
                ));
            }
            start = next;
        }
        Ok((values, false))
    }

    fn fetch_pull_request(
        &self,
        reference: &PullRequestRef,
    ) -> Result<ApiPullRequest, HostingError> {
        let pull_request: ApiPullRequest =
            Self::json(self.get(self.pull_request_url(reference, "")?)?)?;
        if pull_request.id != reference.number {
            return Err(HostingError::InvalidResponse(
                "Bitbucket Data Center returned a different pull request".into(),
            ));
        }
        Ok(pull_request)
    }

    fn snapshot(
        reference: &PullRequestRef,
        pull_request: &ApiPullRequest,
    ) -> Result<PullRequestSnapshot, HostingError> {
        let base_oid = full_hash(&pull_request.to_ref.latest_commit)?;
        let head_oid = full_hash(&pull_request.from_ref.latest_commit)?;
        let state = match pull_request.state.as_str() {
            "OPEN" => PullRequestState::Open,
            "MERGED" => PullRequestState::Merged,
            _ => PullRequestState::Closed,
        };
        Ok(PullRequestSnapshot {
            pull_request: reference.clone(),
            revision: format!("{base_oid}:{head_oid}:{}", pull_request.version),
            base_oid,
            head_oid,
            title: pull_request.title.clone(),
            body: pull_request.description.clone(),
            state,
        })
    }

    /// The user name the token acts as. Bitbucket Data Center has no
    /// "current user" resource; every authenticated response names the user
    /// in `X-AUSERNAME`, and application properties is the cheapest one.
    fn current_user(&self) -> Result<String, HostingError> {
        if let Some(name) = self.current_user.get() {
            return Ok(name.clone());
        }
        let response = self.get(self.rest_url("api/1.0/application-properties"))?;
        let name = response
            .headers()
            .get("x-ausername")
            .and_then(|value| value.to_str().ok())
            .map(percent_decode)
            .filter(|name| !name.trim().is_empty())
            .ok_or_else(|| {
                HostingError::InvalidResponse(
                    "Bitbucket Data Center did not name the token's user (X-AUSERNAME); check that the token is valid"
                        .into(),
                )
            })?;
        Ok(self.current_user.get_or_init(|| name).clone())
    }

    /// The slug of user `name`, which participant URLs take. A slug may
    /// differ from the name, so it is read from the pull request's
    /// participants or the user directory, never derived.
    fn user_slug(&self, name: &str, pull_request: &ApiPullRequest) -> Result<String, HostingError> {
        if let Some(slug) = pull_request
            .participant(name)
            .and_then(|participant| participant.user.slug.clone())
        {
            return Ok(slug);
        }
        let mut url = self.rest_url("api/1.0/users");
        url.query_pairs_mut()
            .append_pair("filter", name)
            .append_pair("limit", &PAGE_SIZE.to_string());
        let page: Page<ApiUser> = Self::json(self.get(url)?)?;
        page.values
            .into_iter()
            .find(|user| user.name.eq_ignore_ascii_case(name))
            .and_then(|user| user.slug)
            .filter(|slug| !slug.is_empty())
            .ok_or_else(|| {
                HostingError::InvalidResponse(format!(
                    "Bitbucket Data Center user `{name}` has no slug Vee can approve as"
                ))
            })
    }

    /// Every comment on the pull request, from its activity stream, and
    /// whether the stream was read to the end.
    fn activity_comments(
        &self,
        reference: &PullRequestRef,
    ) -> Result<(Vec<ActivityComment>, bool), HostingError> {
        let url = self.pull_request_url(reference, "/activities")?;
        let (activities, complete): (Vec<ApiActivity>, bool) = self.paged(&url, &[])?;
        let mut seen: BTreeMap<u64, ActivityComment> = BTreeMap::new();
        for activity in activities {
            if activity.action != "COMMENTED" {
                continue;
            }
            let Some(mut comment) = activity.comment else {
                continue;
            };
            if activity.comment_action.as_deref() == Some("DELETED") {
                seen.remove(&comment.id);
                continue;
            }
            if comment.anchor.is_none() {
                comment.anchor = activity.comment_anchor;
            }
            let root = activity.comment_action.as_deref() != Some("REPLIED");
            match seen.get(&comment.id) {
                Some(known) if known.comment.version >= comment.version => {}
                _ => {
                    seen.insert(comment.id, ActivityComment { comment, root });
                }
            }
        }
        Ok((seen.into_values().collect(), complete))
    }

    /// Vee's own thread-starting comments, for publication. An incomplete
    /// read could duplicate a comment, so it fails instead.
    fn own_root_comments(
        &self,
        reference: &PullRequestRef,
        user: &str,
    ) -> Result<Vec<ApiComment>, HostingError> {
        let (comments, complete) = self.activity_comments(reference)?;
        if !complete {
            return Err(HostingError::InvalidResponse(
                "pull request activity exceeds the 3000-entry API limit".into(),
            ));
        }
        Ok(comments
            .into_iter()
            .filter(|entry| entry.root && entry.comment.authored_by(user))
            .map(|entry| entry.comment)
            .collect())
    }

    fn post_build_status(
        &self,
        publication: &ReviewPublication,
        pull_request: &ApiPullRequest,
        head_oid: &str,
        key: &str,
    ) -> Result<(), HostingError> {
        let state = build_state(publication.check.status, publication.check.conclusion)?;
        let repository = self.repository_path(&publication.pull_request.repository)?;
        let url = self.rest_url(&format!(
            "api/1.0/projects/{}/repos/{}/commits/{head_oid}/builds",
            repository.project, repository.slug
        ));
        let body = serde_json::json!({
            "key": key,
            "state": state,
            "name": truncate_chars(&publication.check.name, MAX_BUILD_TEXT),
            "description": truncate_chars(&publication.check.summary, MAX_BUILD_TEXT),
            "url": self.web_url(&publication.pull_request, "/overview")?.as_str(),
            "ref": pull_request.from_ref.id,
        });
        self.write(Method::POST, url, body)?;
        Ok(())
    }

    /// Bring one of Vee's comments to `text` and `resolved`: create it when
    /// missing (never just to resolve it), reopen before editing, and resolve
    /// after. Unchanged comments are left alone. Returns the comment's ID.
    fn sync_comment(
        &self,
        reference: &PullRequestRef,
        existing: Option<&ApiComment>,
        text: &str,
        resolved: bool,
        anchor: Option<serde_json::Value>,
    ) -> Result<Option<u64>, HostingError> {
        let Some(comment) = existing else {
            if resolved {
                return Ok(None);
            }
            let mut body = serde_json::json!({ "text": text });
            if let Some(anchor) = anchor {
                body["anchor"] = anchor;
            }
            let created: ApiComment = Self::json(self.write(
                Method::POST,
                self.pull_request_url(reference, "/comments")?,
                body,
            )?)?;
            return Ok(Some(created.id));
        };
        let mut version = comment.version;
        let mut thread_resolved = comment.thread_resolved;
        if thread_resolved && !resolved {
            version = self.update_comment(
                reference,
                comment.id,
                serde_json::json!({ "version": version, "threadResolved": false }),
            )?;
            thread_resolved = false;
        }
        // A resolved thread cannot be edited; its text is left as it was.
        if !thread_resolved && comment.text != text {
            version = self.update_comment(
                reference,
                comment.id,
                serde_json::json!({ "version": version, "text": text }),
            )?;
        }
        if resolved && !thread_resolved {
            self.update_comment(
                reference,
                comment.id,
                serde_json::json!({ "version": version, "threadResolved": true }),
            )?;
        }
        Ok(Some(comment.id))
    }

    /// Update a comment at its current version; returns its new version.
    fn update_comment(
        &self,
        reference: &PullRequestRef,
        id: u64,
        body: serde_json::Value,
    ) -> Result<u64, HostingError> {
        let url = self.pull_request_url(reference, &format!("/comments/{id}"))?;
        let updated: ApiComment = Self::json(self.write(Method::PUT, url, body)?)?;
        Ok(updated.version)
    }

    fn sync_thread(
        &self,
        reference: &PullRequestRef,
        thread: &ReviewThread,
        own: &[ApiComment],
    ) -> Result<Option<u64>, HostingError> {
        let marker = fingerprint_marker(&thread.fingerprint);
        let prior = own
            .iter()
            .find(|comment| comment.anchor.is_some() && comment.text.contains(&marker));
        let text = format!(
            "{}\n\n{marker}\n<!-- vee:idempotency:{} -->",
            neutralize_markers(&thread.body_with_suggestion(SuggestionStyle::Diff)),
            thread.idempotency_key
        );
        let (line_type, file_type) = match thread.side {
            DiffSide::New => ("ADDED", "TO"),
            DiffSide::Old => ("REMOVED", "FROM"),
        };
        let anchor = serde_json::json!({
            "path": thread.path,
            "line": thread.line,
            "lineType": line_type,
            "fileType": file_type,
            "diffType": "EFFECTIVE",
        });
        self.sync_comment(
            reference,
            prior,
            &text,
            thread.resolution == ThreadResolution::Resolved,
            Some(anchor),
        )
    }

    /// One summary comment per check name, kept current on republish.
    fn sync_summary(
        &self,
        publication: &ReviewPublication,
        key: &str,
        own: &[ApiComment],
    ) -> Result<(), HostingError> {
        if publication.check.status != CheckStatus::Completed {
            return Ok(());
        }
        let marker = format!("{SUMMARY_MARKER}{key} -->");
        let prior = own
            .iter()
            .find(|comment| comment.anchor.is_none() && comment.text.contains(&marker));
        let text = format!(
            "**{}**\n\n{}\n\n{marker}\n<!-- vee:idempotency:{} -->",
            neutralize_markers(&publication.check.title),
            neutralize_markers(&publication.check.summary),
            publication.check.idempotency_key
        );
        self.sync_comment(&publication.pull_request, prior, &text, false, None)?;
        Ok(())
    }

    fn verify_signature(
        &self,
        headers: &BTreeMap<String, String>,
        body: &[u8],
    ) -> Result<(), HostingError> {
        if self.config.webhook_secret.is_empty() {
            return Err(HostingError::InvalidResponse(
                "Bitbucket Data Center webhook secret is not configured".into(),
            ));
        }
        let invalid = || {
            HostingError::InvalidResponse("invalid Bitbucket Data Center webhook signature".into())
        };
        let signature = header_value(headers, "x-hub-signature").ok_or_else(|| {
            HostingError::InvalidResponse("missing Bitbucket Data Center webhook signature".into())
        })?;
        let (algorithm, hex) = signature.split_once('=').ok_or_else(invalid)?;
        if algorithm != "sha256" || hex.len() != 64 {
            return Err(HostingError::InvalidResponse(
                "unsupported Bitbucket Data Center webhook signature".into(),
            ));
        }
        let supplied = decode_hex(hex).ok_or_else(invalid)?;
        let mut mac = HmacSha256::new_from_slice(self.config.webhook_secret.as_bytes())
            .map_err(|_| invalid())?;
        mac.update(body);
        mac.verify_slice(&supplied).map_err(|_| {
            HostingError::InvalidResponse(
                "Bitbucket Data Center webhook signature verification failed".into(),
            )
        })
    }

    fn webhook_pull_request(&self, pull: &serde_json::Value) -> Option<PullRequestRef> {
        let number = pull.get("id")?.as_u64()?;
        let repository = pull.pointer("/toRef/repository")?;
        let project = repository.pointer("/project/key")?.as_str()?;
        let slug = repository.get("slug")?.as_str()?;
        Some(PullRequestRef {
            repository: RepositoryRef {
                host: self.repository_host(),
                full_name: format!("{project}/{slug}"),
            },
            number,
        })
    }
}

impl PullRequestContextProvider for BitbucketDataCenterAdapter {
    fn context_provider_id(&self) -> &'static str {
        PROVIDER_ID
    }

    fn get_pull_request_context(
        &self,
        reference: &PullRequestRef,
    ) -> Result<PullRequestSnapshot, HostingError> {
        let pull_request = self.fetch_pull_request(reference)?;
        Self::snapshot(reference, &pull_request)
    }

    fn list_pull_request_context_files(
        &self,
        reference: &PullRequestRef,
        expected_revision: &str,
    ) -> Result<Vec<PullRequestFile>, HostingError> {
        #[derive(Deserialize)]
        struct ApiPath {
            #[serde(rename = "toString")]
            text: String,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct ApiChange {
            path: ApiPath,
            #[serde(default)]
            src_path: Option<ApiPath>,
            #[serde(rename = "type", default)]
            kind: String,
        }

        let current = self.get_pull_request_context(reference)?;
        if current.revision != expected_revision {
            return Err(HostingError::StaleRevision {
                expected: expected_revision.into(),
                actual: current.revision,
            });
        }
        let url = self.pull_request_url(reference, "/changes")?;
        let (changes, complete): (Vec<ApiChange>, bool) =
            self.paged(&url, &[("withComments", "false")])?;
        if !complete {
            return Err(HostingError::InvalidResponse(
                "Bitbucket Data Center changes exceed the 3000-file context bound".into(),
            ));
        }
        let diff = bounded_text(self.send(
            Method::GET,
            self.pull_request_url(reference, ".diff")?,
            "text/plain",
            None,
        )?)?;
        let patches = parse_raw_diff(&diff);
        Ok(changes
            .into_iter()
            .map(|change| {
                let path = change.path.text;
                let patch = patches.get(&path).cloned();
                let (additions, deletions) = patch.as_deref().map(line_counts).unwrap_or((0, 0));
                PullRequestFile {
                    change: match change.kind.as_str() {
                        "ADD" => FileChange::Added,
                        "DELETE" => FileChange::Deleted,
                        "MOVE" => FileChange::Renamed,
                        "COPY" => FileChange::Copied,
                        _ => FileChange::Modified,
                    },
                    previous_path: change
                        .src_path
                        .map(|source| source.text)
                        .filter(|source| source != &path),
                    path,
                    patch,
                    additions,
                    deletions,
                }
            })
            .collect())
    }
}

impl crate::PullRequestReviewIssuesProvider for BitbucketDataCenterAdapter {
    fn list_pull_request_review_issues(
        &self,
        reference: &PullRequestRef,
    ) -> Result<PullRequestReviewIssues, HostingError> {
        let before = self.get_pull_request_context(reference)?;
        let (comments, complete) = self.activity_comments(reference)?;
        let mut issues = BTreeMap::new();
        let mut total_body_bytes = 0_usize;
        for entry in comments {
            let anchor = entry.comment.anchor.clone();
            for comment in flatten_thread(entry.comment) {
                if issues.contains_key(&comment.id) {
                    continue;
                }
                total_body_bytes = total_body_bytes.saturating_add(comment.text.len());
                if total_body_bytes > MAX_RESPONSE_BYTES as usize {
                    return Err(HostingError::InvalidResponse(
                        "Bitbucket Data Center review issue bodies exceed the aggregate response limit"
                            .into(),
                    ));
                }
                let issue = self.review_issue(reference, comment, anchor.as_ref())?;
                issues.insert(issue_key(&issue), issue);
            }
        }
        let after = self.get_pull_request_context(reference)?;
        if before.revision != after.revision {
            return Err(HostingError::StaleRevision {
                expected: before.revision,
                actual: after.revision,
            });
        }
        Ok(PullRequestReviewIssues {
            schema_version: 1,
            provider: PROVIDER_ID.into(),
            pull_request: reference.clone(),
            revision: before.revision,
            complete,
            gate_eligible: false,
            issues: issues.into_values().collect(),
        })
    }
}

impl BitbucketDataCenterAdapter {
    fn review_issue(
        &self,
        reference: &PullRequestRef,
        comment: ApiComment,
        anchor: Option<&ApiAnchor>,
    ) -> Result<PullRequestReviewIssue, HostingError> {
        let side = anchor.filter(|anchor| anchor.line.is_some()).map(|anchor| {
            if anchor.line_type.as_deref() == Some("REMOVED")
                || anchor.file_type.as_deref() == Some("FROM")
            {
                DiffSide::Old
            } else {
                DiffSide::New
            }
        });
        let mut source_url = self.web_url(reference, "/overview")?;
        source_url
            .query_pairs_mut()
            .append_pair("commentId", &comment.id.to_string());
        Ok(PullRequestReviewIssue {
            external_id: comment.id.to_string(),
            author: comment.author.map(|author| author.name),
            body: comment.text,
            path: anchor.and_then(|anchor| anchor.path.clone()),
            line: anchor.and_then(|anchor| anchor.line),
            side,
            source_url: Some(source_url.into()),
            created_at: comment.created_date.and_then(epoch_millis_to_rfc3339),
            updated_at: comment.updated_date.and_then(epoch_millis_to_rfc3339),
            classification: "untrusted_external_review".into(),
        })
    }
}

/// Issues are ordered by comment ID, numerically.
fn issue_key(issue: &PullRequestReviewIssue) -> u64 {
    issue.external_id.parse().unwrap_or(u64::MAX)
}

/// A comment followed by its replies, depth first.
fn flatten_thread(root: ApiComment) -> Vec<ApiComment> {
    let mut flat = Vec::new();
    let mut pending = vec![root];
    while let Some(mut comment) = pending.pop() {
        let replies = std::mem::take(&mut comment.comments);
        flat.push(comment);
        pending.extend(replies.into_iter().rev());
    }
    flat
}

impl GitHostingProvider for BitbucketDataCenterAdapter {
    fn provider_id(&self) -> &'static str {
        PROVIDER_ID
    }

    fn get_pull_request(
        &self,
        reference: &PullRequestRef,
    ) -> Result<PullRequestSnapshot, HostingError> {
        self.get_pull_request_context(reference)
    }

    fn list_changed_files(
        &self,
        reference: &PullRequestRef,
        expected_revision: &str,
    ) -> Result<Vec<PullRequestFile>, HostingError> {
        self.list_pull_request_context_files(reference, expected_revision)
    }

    fn publish_review(
        &self,
        publication: ReviewPublication,
    ) -> Result<PublicationReceipt, HostingError> {
        publication
            .validate()
            .map_err(HostingError::InvalidResponse)?;
        let reference = &publication.pull_request;
        let pull_request = self.fetch_pull_request(reference)?;
        let current = Self::snapshot(reference, &pull_request)?;
        if current.revision != publication.expected_revision {
            return Err(HostingError::StaleRevision {
                expected: publication.expected_revision,
                actual: current.revision,
            });
        }
        if current.state != PullRequestState::Open {
            return Err(HostingError::InvalidResponse(
                "cannot publish to a closed Bitbucket Data Center pull request".into(),
            ));
        }
        let user = self.current_user()?;
        let key = build_key(&publication.check.name);
        self.post_build_status(&publication, &pull_request, &current.head_oid, &key)?;
        let own = self.own_root_comments(reference, &user)?;
        self.sync_summary(&publication, &key, &own)?;
        let mut thread_ids = BTreeMap::new();
        for thread in &publication.threads {
            if let Some(id) = self.sync_thread(reference, thread, &own)? {
                thread_ids.insert(thread.fingerprint.clone(), id.to_string());
            }
        }
        Ok(PublicationReceipt {
            provider_check_id: key,
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
        let event_key = header_value(headers, "x-event-key").ok_or_else(|| {
            HostingError::InvalidResponse("missing Bitbucket Data Center event key".into())
        })?;
        let event_id = header_value(headers, "x-request-id")
            .filter(|value| !value.trim().is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| format!("sha256:{}", hex_digest(body)));
        let payload: serde_json::Value = serde_json::from_slice(body).map_err(|error| {
            HostingError::InvalidResponse(format!(
                "invalid Bitbucket Data Center webhook JSON: {error}"
            ))
        })?;
        let pull = payload.get("pullRequest");
        let commit = |pointer: &str| {
            pull.and_then(|value| value.pointer(pointer))
                .and_then(serde_json::Value::as_str)
                .map(str::to_ascii_lowercase)
        };
        let (event_type, action) = webhook_action(event_key, &payload);
        let envelope = WebhookEnvelope {
            provider: PROVIDER_ID.into(),
            event_id,
            event_type: event_type.into(),
            delivery_attempt: 1,
            pull_request: pull.and_then(|value| self.webhook_pull_request(value)),
            action: action.map(str::to_owned),
            base_oid: commit("/toRef/latestCommit"),
            head_oid: commit("/fromRef/latestCommit"),
            signature_verified: true,
        };
        envelope.validate().map_err(HostingError::InvalidResponse)?;
        Ok(envelope)
    }
}

/// The event type and action of a Data Center event key. A source push is a
/// `synchronize`, as is a change of target branch, which changes the diff;
/// other edits are acknowledged without a review.
fn webhook_action(
    event_key: &str,
    payload: &serde_json::Value,
) -> (&'static str, Option<&'static str>) {
    match event_key {
        "pr:opened" => ("pull_request", Some("opened")),
        "pr:from_ref_updated" => ("pull_request", Some("synchronize")),
        "pr:modified" => {
            let previous = payload.pointer("/previousTarget/id");
            let current = payload.pointer("/pullRequest/toRef/id");
            let retargeted = previous.is_some() && previous != current;
            (
                "pull_request",
                Some(if retargeted { "synchronize" } else { "edited" }),
            )
        }
        "pr:merged" | "pr:declined" | "pr:deleted" => ("pull_request", Some("closed")),
        "diagnostics:ping" => ("ping", None),
        key if key.starts_with("pr:comment:") => ("pull_request_comment", None),
        key if key.starts_with("pr:") => ("pull_request", None),
        _ => ("other", None),
    }
}

/// Vee's own approval: the token's user's participant status on the pull
/// request. Like Bitbucket Cloud, an approval carries no text; Data Center
/// records the head it was given at as the participant's last reviewed commit.
impl crate::PullRequestApprovalProvider for BitbucketDataCenterAdapter {
    fn own_approval_stands(&self, reference: &PullRequestRef) -> Result<bool, HostingError> {
        let user = self.current_user()?;
        let pull_request = self.fetch_pull_request(reference)?;
        Ok(pull_request.participant(&user).is_some_and(|participant| {
            participant.approved || participant.status.as_deref() == Some("APPROVED")
        }))
    }

    fn approve_head(
        &self,
        reference: &PullRequestRef,
        head_oid: &str,
        _message: &str,
    ) -> Result<(), HostingError> {
        let pull_request = self.fetch_pull_request(reference)?;
        let current = Self::snapshot(reference, &pull_request)?;
        if current.state != PullRequestState::Open || !same_head(&current.head_oid, head_oid) {
            return Err(HostingError::StaleRevision {
                expected: head_oid.to_owned(),
                actual: current.head_oid,
            });
        }
        let user = self.current_user()?;
        let slug = self.user_slug(&user, &pull_request)?;
        // The pull request version makes the server refuse the approval when
        // the pull request changed since the head was checked.
        let mut url = self.pull_request_url(reference, &format!("/participants/{slug}"))?;
        url.query_pairs_mut()
            .append_pair("version", &pull_request.version.to_string());
        self.write(
            Method::PUT,
            url,
            serde_json::json!({ "user": { "name": user }, "approved": true, "status": "APPROVED" }),
        )?;
        Ok(())
    }

    fn withdraw_approval(
        &self,
        reference: &PullRequestRef,
        _message: &str,
    ) -> Result<(), HostingError> {
        let user = self.current_user()?;
        let pull_request = self.fetch_pull_request(reference)?;
        let Some(participant) = pull_request.participant(&user) else {
            return Ok(());
        };
        if !participant.approved && participant.status.as_deref() != Some("APPROVED") {
            return Ok(());
        }
        let slug = self.user_slug(&user, &pull_request)?;
        let url = self.pull_request_url(reference, &format!("/participants/{slug}"))?;
        match self.write(
            Method::PUT,
            url,
            serde_json::json!({ "user": { "name": user }, "approved": false, "status": "UNAPPROVED" }),
        ) {
            Ok(_) | Err(HostingError::NotFound) => Ok(()),
            Err(error) => Err(error),
        }
    }
}

/// A build status key per check name, so a later review replaces the status
/// it published on the same commit: `vee` for "Vee", `vee-approval` for
/// "Vee approval".
fn build_key(name: &str) -> String {
    let slug = name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    if slug.is_empty() {
        format!("vee-{}", &hex_digest(name.as_bytes())[..16])
    } else {
        truncate_chars(&slug, MAX_BUILD_TEXT)
    }
}

fn build_state(
    status: CheckStatus,
    conclusion: Option<CheckConclusion>,
) -> Result<&'static str, HostingError> {
    Ok(match (status, conclusion) {
        (CheckStatus::Queued | CheckStatus::InProgress, _) => "INPROGRESS",
        (_, Some(CheckConclusion::Success)) => "SUCCESSFUL",
        // A neutral check must never read as a success.
        (_, Some(CheckConclusion::Neutral)) => "UNKNOWN",
        (_, Some(CheckConclusion::Failure | CheckConclusion::ActionRequired)) => "FAILED",
        (_, Some(CheckConclusion::Cancelled | CheckConclusion::TimedOut)) => "CANCELLED",
        (_, None) => {
            return Err(HostingError::InvalidResponse(
                "completed Bitbucket Data Center build status requires a conclusion".into(),
            ))
        }
    })
}

fn fingerprint_marker(fingerprint: &str) -> String {
    format!("<!-- vee:fingerprint:{fingerprint} -->")
}

/// Text from findings or checks cannot carry a marker of its own, so no
/// comment can claim another finding's thread.
fn neutralize_markers(text: &str) -> String {
    text.replace("<!-- vee:", "&lt;!-- vee:")
}

fn truncate_chars(text: &str, limit: usize) -> String {
    text.chars().take(limit).collect()
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// A commit hash as Vee compares it: full length, lowercase.
fn full_hash(hash: &str) -> Result<String, HostingError> {
    let hash = hash.to_ascii_lowercase();
    if !matches!(hash.len(), 40 | 64) || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(HostingError::InvalidResponse(
            "Bitbucket Data Center returned an invalid commit hash".into(),
        ));
    }
    Ok(hash)
}

fn bounded_body(
    response: reqwest::blocking::Response,
    what: &str,
) -> Result<Vec<u8>, HostingError> {
    let too_large = || {
        HostingError::InvalidResponse(format!(
            "Bitbucket Data Center {what} exceeds the 5 MiB limit"
        ))
    };
    if response
        .content_length()
        .is_some_and(|size| size > MAX_RESPONSE_BYTES)
    {
        return Err(too_large());
    }
    let mut bytes = Vec::new();
    response
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            HostingError::InvalidResponse(format!("reading Bitbucket Data Center {what}: {error}"))
        })?;
    if bytes.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(too_large());
    }
    Ok(bytes)
}

fn bounded_text(response: reqwest::blocking::Response) -> Result<String, HostingError> {
    String::from_utf8(bounded_body(response, "diff")?).map_err(|_| {
        HostingError::InvalidResponse("Bitbucket Data Center diff is not UTF-8".into())
    })
}

/// The first error message of a rejected request, bounded and printable.
fn error_message(response: reqwest::blocking::Response) -> Option<String> {
    #[derive(Deserialize)]
    struct Errors {
        errors: Vec<Message>,
    }
    #[derive(Deserialize)]
    struct Message {
        message: String,
    }
    let mut bytes = Vec::new();
    response
        .take(MAX_ERROR_BYTES)
        .read_to_end(&mut bytes)
        .ok()?;
    let errors: Errors = serde_json::from_slice(&bytes).ok()?;
    let message = errors.errors.into_iter().next()?.message;
    let clean = message
        .chars()
        .filter(|character| !character.is_control())
        .take(300)
        .collect::<String>();
    (!clean.trim().is_empty()).then_some(clean)
}

/// `X-AUSERNAME` is URL-encoded when the name is not plain ASCII.
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let Some(byte) = decode_hex(&value[index + 1..index + 3]) {
                decoded.push(byte[0]);
                index += 3;
                continue;
            }
        }
        decoded.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

/// Per-file patches of a raw pull request diff, keyed by the file's path
/// after the change (before it, for a deleted file). Bitbucket writes paths
/// with `src://` and `dst://` prefixes; `a/` and `b/` are accepted too.
/// Quoted paths are left out rather than guessed.
fn parse_raw_diff(diff: &str) -> BTreeMap<String, String> {
    fn strip(path: &str, prefixes: [&str; 2]) -> Option<String> {
        let path = path.split('\t').next().unwrap_or_default();
        if path == "/dev/null" || path.starts_with('"') {
            return None;
        }
        prefixes
            .iter()
            .find_map(|prefix| path.strip_prefix(prefix))
            .filter(|path| !path.is_empty())
            .map(str::to_owned)
    }
    let mut patches = BTreeMap::new();
    let mut block: Vec<&str> = Vec::new();
    let mut old_path = None;
    let mut new_path = None;
    let mut flush = |block: &mut Vec<&str>, old: &mut Option<String>, new: &mut Option<String>| {
        if let Some(path) = new.take().or(old.take()) {
            patches.insert(path, block.join("\n"));
        }
        *old = None;
        block.clear();
    };
    for line in diff.lines() {
        if line.starts_with("diff --git ") {
            flush(&mut block, &mut old_path, &mut new_path);
        }
        let in_header = !block.iter().any(|seen| seen.starts_with("@@"));
        if in_header {
            if let Some(path) = line.strip_prefix("--- ") {
                old_path = strip(path, ["src://", "a/"]);
            } else if let Some(path) = line.strip_prefix("+++ ") {
                new_path = strip(path, ["dst://", "b/"]);
            }
        }
        block.push(line);
    }
    flush(&mut block, &mut old_path, &mut new_path);
    patches
}

/// Added and removed lines in a file's patch, counted inside its hunks.
fn line_counts(patch: &str) -> (u64, u64) {
    let mut in_hunk = false;
    let (mut added, mut removed) = (0, 0);
    for line in patch.lines() {
        if line.starts_with("@@") {
            in_hunk = true;
        } else if in_hunk && line.starts_with('+') {
            added += 1;
        } else if in_hunk && line.starts_with('-') {
            removed += 1;
        }
    }
    (added, removed)
}

/// Milliseconds since the Unix epoch, as RFC 3339 in UTC.
fn epoch_millis_to_rfc3339(millis: i64) -> Option<String> {
    let seconds = millis.div_euclid(1000);
    let days = seconds.div_euclid(86_400);
    let of_day = seconds.rem_euclid(86_400);
    // Civil date from days since 1970-01-01 (proleptic Gregorian calendar).
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (0..=9999).contains(&year).then(|| {
        format!(
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
            of_day / 3600,
            of_day % 3600 / 60,
            of_day % 60
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_https_outside_loopback_and_no_embedded_credentials() {
        assert!(BitbucketDataCenterConfig::new("http://git.example.invalid/", "t".into()).is_err());
        assert!(
            BitbucketDataCenterConfig::new("https://user:pw@git.example.invalid/", "t".into())
                .is_err()
        );
        assert!(
            BitbucketDataCenterConfig::new("https://git.example.invalid/", " ".into()).is_err()
        );
        let config =
            BitbucketDataCenterConfig::new("https://git.example.invalid/bitbucket", "t".into())
                .unwrap();
        assert_eq!(config.base_url.path(), "/bitbucket/");
        assert!(BitbucketDataCenterConfig::new("http://127.0.0.1:7990/", "t".into()).is_ok());
    }

    #[test]
    fn rest_paths_keep_the_servers_context_path() {
        let adapter = BitbucketDataCenterAdapter::new(
            BitbucketDataCenterConfig::new(
                "https://git.example.invalid:8443/bitbucket/",
                "t".into(),
            )
            .unwrap(),
        )
        .unwrap();
        let reference = PullRequestRef {
            repository: RepositoryRef {
                host: "git.example.invalid:8443".into(),
                full_name: "PROJ/service".into(),
            },
            number: 7,
        };
        assert_eq!(
            adapter.pull_request_url(&reference, "/changes").unwrap().as_str(),
            "https://git.example.invalid:8443/bitbucket/rest/api/1.0/projects/PROJ/repos/service/pull-requests/7/changes"
        );
        assert_eq!(
            adapter.web_url(&reference, "/overview").unwrap().as_str(),
            "https://git.example.invalid:8443/bitbucket/projects/PROJ/repos/service/pull-requests/7/overview"
        );
        let nested = PullRequestRef {
            repository: RepositoryRef {
                host: "git.example.invalid".into(),
                full_name: "PROJ/group/service".into(),
            },
            number: 7,
        };
        assert!(adapter.pull_request_url(&nested, "").is_err());
        let elsewhere = PullRequestRef {
            repository: RepositoryRef {
                host: "other.example.invalid".into(),
                full_name: "PROJ/service".into(),
            },
            number: 7,
        };
        assert!(adapter.pull_request_url(&elsewhere, "").is_err());
    }

    #[test]
    fn parses_bitbucket_and_git_prefixed_raw_diffs() {
        let diff = "diff --git src://src/lib.rs dst://src/lib.rs\nindex 1..2 100644\n--- src://src/lib.rs\n+++ dst://src/lib.rs\n@@ -1,2 +1,2 @@\n-old\n+new\n+--- not a header\n context\ndiff --git a/gone.rs b/gone.rs\ndeleted file mode 100644\n--- a/gone.rs\n+++ /dev/null\n@@ -1 +0,0 @@\n-bye\ndiff --git \"src://odd name\" \"dst://odd name\"\n--- \"src://odd name\"\n+++ \"dst://odd name\"\n@@ -1 +1 @@\n-a\n+b\n";
        let patches = parse_raw_diff(diff);
        assert_eq!(patches.len(), 2, "{patches:?}");
        assert!(patches["src/lib.rs"].contains("+new"));
        assert_eq!(line_counts(&patches["src/lib.rs"]), (2, 1));
        assert_eq!(line_counts(&patches["gone.rs"]), (0, 1));
    }

    #[test]
    fn build_keys_and_states_follow_the_check() {
        assert_eq!(build_key("Vee"), "vee");
        assert_eq!(build_key("Vee approval"), "vee-approval");
        assert!(build_key("!!!").starts_with("vee-"));
        assert_eq!(
            build_state(CheckStatus::Completed, Some(CheckConclusion::Neutral)).unwrap(),
            "UNKNOWN"
        );
        assert_eq!(
            build_state(
                CheckStatus::Completed,
                Some(CheckConclusion::ActionRequired)
            )
            .unwrap(),
            "FAILED"
        );
        assert_eq!(
            build_state(CheckStatus::InProgress, None).unwrap(),
            "INPROGRESS"
        );
        assert!(build_state(CheckStatus::Completed, None).is_err());
    }

    #[test]
    fn converts_epoch_millis_and_percent_encoded_names() {
        assert_eq!(
            epoch_millis_to_rfc3339(1_795_780_800_000).as_deref(),
            Some("2026-11-27T12:00:00Z")
        );
        assert_eq!(
            epoch_millis_to_rfc3339(0).as_deref(),
            Some("1970-01-01T00:00:00Z")
        );
        assert_eq!(percent_decode("vee%20bot"), "vee bot");
        assert_eq!(percent_decode("vee-bot%"), "vee-bot%");
    }
}
