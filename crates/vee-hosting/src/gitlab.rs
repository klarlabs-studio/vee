//! GitLab REST adapter for provider-neutral work item lookup.

use crate::{
    work_item_digest, CheckConclusion, CheckRun, CheckStatus, DiffSide, FileChange,
    GitHostingProvider, HostingError, PublicationReceipt, PullRequestFile, PullRequestRef,
    PullRequestSnapshot, PullRequestState, ReviewPublication, ReviewThread, ThreadResolution,
    WebhookEnvelope, WorkItemProvider, WorkItemRef, WorkItemSnapshot,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use hmac::{Hmac, Mac};
use reqwest::{blocking::Client, header, Method, StatusCode, Url};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::Read,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const MAX_WORK_ITEM_RESPONSE_BYTES: u64 = 1_048_576;
const MAX_API_RESPONSE_BYTES: u64 = 5_242_880;
type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct GitLabConfig {
    pub api_base: Url,
    pub token: String,
    pub webhook_secret: String,
    pub actor_login: String,
    pub timeout: Duration,
}

impl GitLabConfig {
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
                "GitLab API URL and token are required; HTTP is allowed only on loopback".into(),
            );
        }
        Ok(Self {
            api_base,
            token,
            webhook_secret: String::new(),
            actor_login: String::new(),
            timeout: Duration::from_secs(30),
        })
    }

    pub fn with_webhook_secret(mut self, secret: String) -> Self {
        self.webhook_secret = secret;
        self
    }

    pub fn with_actor_login(mut self, login: String) -> Self {
        self.actor_login = login;
        self
    }
}

#[derive(Clone)]
pub struct GitLabAdapter {
    config: GitLabConfig,
    client: Client,
}

impl GitLabAdapter {
    pub fn new(config: GitLabConfig) -> Result<Self, String> {
        let client = Client::builder()
            .timeout(config.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| error.to_string())?;
        Ok(Self { config, client })
    }

    fn request_method(
        &self,
        method: Method,
        url: Url,
    ) -> Result<reqwest::blocking::RequestBuilder, HostingError> {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::HeaderName::from_static("private-token"),
            header::HeaderValue::from_str(&self.config.token)
                .map_err(|_| HostingError::InvalidResponse("invalid GitLab token".into()))?,
        );
        Ok(self
            .client
            .request(method, url)
            .headers(headers)
            .header(header::ACCEPT, "application/json"))
    }

    fn request(&self, url: Url) -> Result<reqwest::blocking::RequestBuilder, HostingError> {
        self.request_method(Method::GET, url)
    }

    fn project_path(&self, reference: &PullRequestRef, suffix: &str) -> Result<Url, HostingError> {
        reference
            .validate()
            .map_err(HostingError::InvalidResponse)?;
        let api_host = self.config.api_base.host_str().unwrap_or_default();
        if !reference.repository.host.eq_ignore_ascii_case(api_host) {
            return Err(HostingError::InvalidResponse(
                "pull request host does not match configured GitLab API".into(),
            ));
        }
        self.project_url(
            reference,
            &format!("/merge_requests/{}{suffix}", reference.number),
        )
    }

    fn project_url(&self, reference: &PullRequestRef, suffix: &str) -> Result<Url, HostingError> {
        reference
            .validate()
            .map_err(HostingError::InvalidResponse)?;
        let api_host = self.config.api_base.host_str().unwrap_or_default();
        if !reference.repository.host.eq_ignore_ascii_case(api_host) {
            return Err(HostingError::InvalidResponse(
                "pull request host does not match configured GitLab API".into(),
            ));
        }
        let project = reference.repository.full_name.replace('/', "%2F");
        let prefix = self.config.api_base.path().trim_end_matches('/');
        let mut url = self.config.api_base.clone();
        url.set_path(&format!("{prefix}/projects/{project}{suffix}"));
        Ok(url)
    }

    fn bounded_json<T: for<'de> Deserialize<'de>>(
        response: reqwest::blocking::Response,
        max_bytes: u64,
    ) -> Result<T, HostingError> {
        if response
            .content_length()
            .is_some_and(|length| length > max_bytes)
        {
            return Err(HostingError::InvalidResponse(format!(
                "GitLab response exceeds the {max_bytes}-byte limit"
            )));
        }
        let mut bytes = Vec::new();
        response
            .take(max_bytes + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                HostingError::InvalidResponse(format!("reading GitLab response body: {error}"))
            })?;
        if bytes.len() as u64 > max_bytes {
            return Err(HostingError::InvalidResponse(format!(
                "GitLab response exceeds the {max_bytes}-byte limit"
            )));
        }
        serde_json::from_slice(&bytes)
            .map_err(|error| HostingError::InvalidResponse(format!("invalid GitLab JSON: {error}")))
    }

    fn checked(
        response: reqwest::blocking::Response,
    ) -> Result<reqwest::blocking::Response, HostingError> {
        match response.status() {
            StatusCode::OK | StatusCode::CREATED | StatusCode::ACCEPTED => Ok(response),
            StatusCode::NOT_FOUND => Err(HostingError::NotFound),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Err(HostingError::Unauthorized),
            StatusCode::TOO_MANY_REQUESTS => Err(HostingError::RateLimited {
                retry_after_seconds: response
                    .headers()
                    .get(header::RETRY_AFTER)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse().ok()),
            }),
            status => Err(HostingError::Transport(format!(
                "GitLab returned HTTP {status}"
            ))),
        }
    }

    fn verify_webhook_signature(
        &self,
        headers: &BTreeMap<String, String>,
        body: &[u8],
    ) -> Result<(), HostingError> {
        let encoded_key = self
            .config
            .webhook_secret
            .strip_prefix("whsec_")
            .ok_or_else(|| {
                HostingError::InvalidResponse(
                    "GitLab webhook signing secret is not configured".into(),
                )
            })?;
        let key = STANDARD.decode(encoded_key).map_err(|_| {
            HostingError::InvalidResponse("invalid GitLab webhook signing secret".into())
        })?;
        let id = find_header(headers, "webhook-id")
            .ok_or_else(|| HostingError::InvalidResponse("missing GitLab webhook ID".into()))?;
        let timestamp = find_header(headers, "webhook-timestamp").ok_or_else(|| {
            HostingError::InvalidResponse("missing GitLab webhook timestamp".into())
        })?;
        let seconds: u64 = timestamp.parse().map_err(|_| {
            HostingError::InvalidResponse("invalid GitLab webhook timestamp".into())
        })?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now.abs_diff(seconds) > 300 {
            return Err(HostingError::InvalidResponse(
                "GitLab webhook timestamp is outside the accepted window".into(),
            ));
        }
        let signature = find_header(headers, "webhook-signature").ok_or_else(|| {
            HostingError::InvalidResponse("missing GitLab webhook signature".into())
        })?;
        let signed = format!("{id}.{timestamp}.");
        let verified = signature.split_whitespace().any(|part| {
            let Some(value) = part.strip_prefix("v1,") else {
                return false;
            };
            let Ok(signature) = STANDARD.decode(value) else {
                return false;
            };
            let Ok(mut mac) = HmacSha256::new_from_slice(&key) else {
                return false;
            };
            mac.update(signed.as_bytes());
            mac.update(body);
            mac.verify_slice(&signature).is_ok()
        });
        if !verified {
            return Err(HostingError::InvalidResponse(
                "GitLab webhook signature verification failed".into(),
            ));
        }
        Ok(())
    }

    fn find_owned_review_discussion(
        &self,
        reference: &PullRequestRef,
        marker: &str,
    ) -> Result<Option<(serde_json::Value, serde_json::Value)>, HostingError> {
        const PAGE_SIZE: usize = 100;
        const MAX_PAGES: usize = 30;
        let mut page = 1usize;
        loop {
            let mut url = self.project_path(reference, "/discussions")?;
            url.query_pairs_mut()
                .append_pair("per_page", &PAGE_SIZE.to_string())
                .append_pair("page", &page.to_string());
            let response = self.request(url)?.send().map_err(|error| {
                HostingError::Transport(format!("listing GitLab discussions: {error}"))
            })?;
            let response = Self::checked(response)?;
            let next_page = response
                .headers()
                .get("x-next-page")
                .and_then(|value| value.to_str().ok())
                .filter(|value| !value.is_empty())
                .map(|value| {
                    value.parse::<usize>().map_err(|_| {
                        HostingError::InvalidResponse(
                            "GitLab returned an invalid discussion pagination header".into(),
                        )
                    })
                })
                .transpose()?;
            let discussions: Vec<serde_json::Value> =
                Self::bounded_json(response, MAX_API_RESPONSE_BYTES)?;
            let count = discussions.len();
            for discussion in discussions {
                let Some(notes) = discussion
                    .get("notes")
                    .and_then(serde_json::Value::as_array)
                else {
                    continue;
                };
                for note in notes {
                    let owned = note
                        .pointer("/author/username")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|name| name.eq_ignore_ascii_case(&self.config.actor_login));
                    let matches = note
                        .get("body")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|value| value.contains(marker));
                    if owned && matches {
                        return Ok(Some((discussion.clone(), note.clone())));
                    }
                }
            }
            let next_page = match next_page {
                Some(next) if next > page && next <= MAX_PAGES => Some(next),
                Some(_) => {
                    return Err(HostingError::InvalidResponse(
                        "GitLab discussion pagination exceeded its supported bounds".into(),
                    ));
                }
                None if count >= PAGE_SIZE && page < MAX_PAGES => Some(page + 1),
                None if count >= PAGE_SIZE => {
                    return Err(HostingError::InvalidResponse(
                        "merge request exceeds the 3000-discussion reconciliation limit".into(),
                    ));
                }
                None => None,
            };
            match next_page {
                Some(next) => page = next,
                None => return Ok(None),
            }
        }
    }

    fn sync_review_thread(
        &self,
        snapshot: &PullRequestSnapshot,
        files: &[PullRequestFile],
        thread: &ReviewThread,
    ) -> Result<Option<String>, HostingError> {
        if self.config.actor_login.trim().is_empty() {
            return Err(HostingError::InvalidResponse(
                "GitLab actor_login must be configured before publishing review threads".into(),
            ));
        }
        let file = files.iter().find(|file| file.path == thread.path);
        let location_is_current = file.is_some_and(|file| {
            patch_has_line(
                file.patch.as_deref().unwrap_or_default(),
                thread.line,
                thread.side,
            )
        });
        let marker = format!("<!-- vee:fingerprint:{} -->", thread.fingerprint);
        let body = format!(
            "{}\n\n{}\n<!-- vee:idempotency:{} -->",
            thread
                .body
                .replace("<!-- vee:fingerprint:", "&lt;!-- vee:fingerprint:"),
            marker,
            thread.idempotency_key
        );
        if body.len() > 65_535 {
            return Err(HostingError::InvalidResponse(
                "review thread body exceeds GitLab's comment limit".into(),
            ));
        }
        if let Some((discussion, note)) =
            self.find_owned_review_discussion(&thread.pull_request, &marker)?
        {
            let discussion_id = discussion
                .get("id")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    HostingError::InvalidResponse("GitLab discussion has no ID".into())
                })?;
            let note_id = note
                .get("id")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| HostingError::InvalidResponse("GitLab note has no ID".into()))?;
            let resolved = discussion
                .get("resolved")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            if location_is_current {
                let position = discussion.get("position").ok_or_else(|| {
                    HostingError::InvalidResponse(
                        "GitLab review discussion has no diff position".into(),
                    )
                })?;
                let (position_path, position_line) = match thread.side {
                    DiffSide::Old => (
                        position.get("old_path").and_then(serde_json::Value::as_str),
                        position.get("old_line").and_then(serde_json::Value::as_u64),
                    ),
                    DiffSide::New => (
                        position.get("new_path").and_then(serde_json::Value::as_str),
                        position.get("new_line").and_then(serde_json::Value::as_u64),
                    ),
                };
                let moved = position_path != Some(thread.path.as_str())
                    || position_line != Some(thread.line);
                if !moved {
                    self.put_note(&thread.pull_request, discussion_id, note_id, &body)?;
                } else if thread.resolution == ThreadResolution::Open {
                    // GitLab cannot move a discussion. The old one says where
                    // the finding went and loses its fingerprint marker, so
                    // later publications no longer match it. It is resolved,
                    // and a new discussion opens at the new line.
                    let moved_body = format!(
                        "Vee now reports this finding at `{}` line {}; see the discussion there.\n<!-- vee:moved:{} -->",
                        thread.path, thread.line, thread.fingerprint
                    );
                    self.put_note(&thread.pull_request, discussion_id, note_id, &moved_body)?;
                    if !resolved {
                        self.set_discussion_resolved(&thread.pull_request, discussion_id, true)?;
                    }
                    return self.create_discussion(snapshot, thread, file, &body);
                }
            }
            let should_resolve = thread.resolution == ThreadResolution::Resolved;
            if should_resolve != resolved {
                self.set_discussion_resolved(&thread.pull_request, discussion_id, should_resolve)?;
            }
            return Ok(Some(discussion_id.into()));
        }
        if thread.resolution == ThreadResolution::Resolved {
            return Ok(None);
        }
        self.create_discussion(
            snapshot,
            thread,
            file.filter(|_| location_is_current),
            &body,
        )
    }

    fn put_note(
        &self,
        pull_request: &PullRequestRef,
        discussion_id: &str,
        note_id: u64,
        body: &str,
    ) -> Result<(), HostingError> {
        let note_url = self.project_path(
            pull_request,
            &format!("/discussions/{discussion_id}/notes/{note_id}"),
        )?;
        let response = self
            .request_method(Method::PUT, note_url)?
            .json(&serde_json::json!({"body":body}))
            .send()
            .map_err(|error| {
                HostingError::Transport(format!("updating GitLab review note: {error}"))
            })?;
        let _: serde_json::Value =
            Self::bounded_json(Self::checked(response)?, MAX_API_RESPONSE_BYTES)?;
        Ok(())
    }

    fn set_discussion_resolved(
        &self,
        pull_request: &PullRequestRef,
        discussion_id: &str,
        resolve: bool,
    ) -> Result<(), HostingError> {
        let mut url = self.project_path(pull_request, &format!("/discussions/{discussion_id}"))?;
        url.query_pairs_mut()
            .append_pair("resolved", if resolve { "true" } else { "false" });
        let response = self
            .request_method(Method::PUT, url)?
            .send()
            .map_err(|error| {
                HostingError::Transport(format!("resolving GitLab discussion: {error}"))
            })?;
        let _: serde_json::Value =
            Self::bounded_json(Self::checked(response)?, MAX_API_RESPONSE_BYTES)?;
        Ok(())
    }

    /// Open a discussion for `thread` on `file`, or nothing when the line is
    /// not in the merge request's diff.
    fn create_discussion(
        &self,
        snapshot: &PullRequestSnapshot,
        thread: &ReviewThread,
        file: Option<&PullRequestFile>,
        body: &str,
    ) -> Result<Option<String>, HostingError> {
        let Some(file) = file else {
            return Ok(None);
        };
        let url = self.project_path(&thread.pull_request, "/discussions")?;
        let start_sha = snapshot
            .revision
            .split(':')
            .nth(1)
            .unwrap_or(&snapshot.base_oid);
        let position = serde_json::json!({"position_type":"text","base_sha":snapshot.base_oid,"start_sha":start_sha,"head_sha":snapshot.head_oid,"old_path":file.previous_path.as_deref().unwrap_or(&file.path),"new_path":file.path,"old_line":if thread.side == DiffSide::Old {Some(thread.line)} else {None},"new_line":if thread.side == DiffSide::New {Some(thread.line)} else {None}});
        let response = self
            .request_method(Method::POST, url)?
            .json(&serde_json::json!({"body":body,"position":position}))
            .send()
            .map_err(|error| {
                HostingError::Transport(format!("creating GitLab review discussion: {error}"))
            })?;
        let created: serde_json::Value =
            Self::bounded_json(Self::checked(response)?, MAX_API_RESPONSE_BYTES)?;
        created
            .get("id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .map(Some)
            .ok_or_else(|| {
                HostingError::InvalidResponse("created GitLab discussion has no ID".into())
            })
    }
}

impl GitHostingProvider for GitLabAdapter {
    fn provider_id(&self) -> &'static str {
        "gitlab"
    }

    fn get_pull_request(
        &self,
        reference: &PullRequestRef,
    ) -> Result<PullRequestSnapshot, HostingError> {
        #[derive(Deserialize)]
        struct DiffRefs {
            base_sha: String,
            start_sha: String,
            head_sha: String,
        }
        #[derive(Deserialize)]
        struct ApiMergeRequest {
            iid: u64,
            title: String,
            description: Option<String>,
            state: String,
            diff_refs: Option<DiffRefs>,
        }

        let url = self.project_path(reference, "")?;
        let response = self.request(url)?.send().map_err(|error| {
            HostingError::Transport(format!("requesting merge request: {error}"))
        })?;
        let api: ApiMergeRequest =
            Self::bounded_json(Self::checked(response)?, MAX_API_RESPONSE_BYTES)?;
        if api.iid != reference.number {
            return Err(HostingError::InvalidResponse(
                "GitLab returned a different merge request".into(),
            ));
        }
        let refs = api.diff_refs.ok_or_else(|| {
            HostingError::InvalidResponse(
                "GitLab merge request diff refs are not available yet".into(),
            )
        })?;
        let revision = format!("{}:{}:{}", refs.base_sha, refs.start_sha, refs.head_sha);
        let state = match api.state.as_str() {
            "opened" => PullRequestState::Open,
            "merged" => PullRequestState::Merged,
            _ => PullRequestState::Closed,
        };
        Ok(PullRequestSnapshot {
            pull_request: reference.clone(),
            base_oid: refs.base_sha,
            head_oid: refs.head_sha,
            title: api.title,
            body: api.description,
            state,
            revision,
        })
    }

    fn list_changed_files(
        &self,
        reference: &PullRequestRef,
        expected_revision: &str,
    ) -> Result<Vec<PullRequestFile>, HostingError> {
        #[derive(Deserialize, serde::Serialize)]
        struct ApiDiff {
            old_path: String,
            new_path: String,
            diff: String,
            new_file: bool,
            renamed_file: bool,
            deleted_file: bool,
        }
        let current = GitHostingProvider::get_pull_request(self, reference)?;
        if current.revision != expected_revision {
            return Err(HostingError::StaleRevision {
                expected: expected_revision.into(),
                actual: current.revision,
            });
        }
        let mut files = Vec::new();
        let mut aggregate_response_bytes = 0usize;
        for page in 1..=30 {
            let mut url = self.project_path(reference, "/diffs")?;
            url.query_pairs_mut()
                .append_pair("per_page", "100")
                .append_pair("page", &page.to_string());
            let response = self.request(url)?.send().map_err(|error| {
                HostingError::Transport(format!("listing merge request diffs: {error}"))
            })?;
            let batch: Vec<ApiDiff> =
                Self::bounded_json(Self::checked(response)?, MAX_API_RESPONSE_BYTES)?;
            aggregate_response_bytes = aggregate_response_bytes.saturating_add(
                serde_json::to_vec(&batch)
                    .map_err(|error| {
                        HostingError::InvalidResponse(format!("encoding GitLab diff page: {error}"))
                    })?
                    .len(),
            );
            if aggregate_response_bytes > MAX_API_RESPONSE_BYTES as usize {
                return Err(HostingError::InvalidResponse(
                    "GitLab merge request diffs exceed the 5 MiB aggregate response limit".into(),
                ));
            }
            let count = batch.len();
            files.extend(batch.into_iter().map(|file| {
                let (additions, deletions) = diff_line_counts(&file.diff);
                let change = if file.new_file {
                    FileChange::Added
                } else if file.deleted_file {
                    FileChange::Deleted
                } else if file.renamed_file {
                    FileChange::Renamed
                } else {
                    FileChange::Modified
                };
                PullRequestFile {
                    path: file.new_path.clone(),
                    change,
                    previous_path: (file.old_path != file.new_path).then_some(file.old_path),
                    patch: Some(file.diff),
                    additions,
                    deletions,
                }
            }));
            if count < 100 {
                return Ok(files);
            }
        }
        Err(HostingError::InvalidResponse(
            "merge request exceeds the 3000-file API limit".into(),
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
        let status_name = format!(
            "vee-{}",
            sha256_hex(publication.check.idempotency_key.as_bytes())
        );
        let status_state = gitlab_status(&publication.check)?;
        let mut status_url = self.project_url(
            &publication.pull_request,
            &format!("/repository/commits/{}/statuses", snapshot.head_oid),
        )?;
        status_url
            .query_pairs_mut()
            .append_pair("name", &status_name)
            .append_pair("all", "true")
            .append_pair("per_page", "100")
            .append_pair("order_by", "id")
            .append_pair("sort", "desc");
        #[derive(Deserialize)]
        struct ExistingStatus {
            id: u64,
            status: String,
            description: Option<String>,
        }
        let response = self.request(status_url)?.send().map_err(|error| {
            HostingError::Transport(format!("looking up GitLab commit status: {error}"))
        })?;
        let existing: Vec<ExistingStatus> =
            Self::bounded_json(Self::checked(response)?, MAX_API_RESPONSE_BYTES)?;
        let description = truncate_chars(&publication.check.summary, 255);
        let check_id = if let Some(status) = existing.first().filter(|status| {
            status.status == status_state
                && status.description.as_deref() == Some(description.as_str())
        }) {
            status.id
        } else {
            let status_path = format!("/statuses/{}", snapshot.head_oid);
            let status_url = self.project_url(&publication.pull_request, &status_path)?;
            #[derive(Deserialize)]
            struct CreatedStatus {
                id: u64,
            }
            let response = self
                .request_method(Method::POST, status_url)?
                .json(&serde_json::json!({"state":status_state,"name":status_name,"description":description}))
                .send()
                .map_err(|error| HostingError::Transport(format!("publishing GitLab commit status: {error}")))?;
            let status: CreatedStatus =
                Self::bounded_json(Self::checked(response)?, MAX_API_RESPONSE_BYTES)?;
            status.id
        };

        let files =
            self.list_changed_files(&publication.pull_request, &publication.expected_revision)?;
        let mut thread_ids = BTreeMap::new();
        for thread in &publication.threads {
            if let Some(id) = self.sync_review_thread(&snapshot, &files, thread)? {
                thread_ids.insert(thread.fingerprint.clone(), id);
            }
        }
        Ok(PublicationReceipt {
            provider_check_id: check_id.to_string(),
            thread_ids,
            resulting_revision: publication.expected_revision,
        })
    }

    fn verify_webhook(
        &self,
        headers: &BTreeMap<String, String>,
        body: &[u8],
    ) -> Result<WebhookEnvelope, HostingError> {
        self.verify_webhook_signature(headers, body)?;
        let payload: serde_json::Value = serde_json::from_slice(body).map_err(|error| {
            HostingError::InvalidResponse(format!("invalid GitLab webhook JSON: {error}"))
        })?;
        let object = payload.get("object_attributes").ok_or_else(|| {
            HostingError::InvalidResponse("GitLab webhook has no object attributes".into())
        })?;
        let number = object
            .get("iid")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                HostingError::InvalidResponse("GitLab webhook has no merge request IID".into())
            })?;
        let project = payload
            .get("project")
            .ok_or_else(|| HostingError::InvalidResponse("GitLab webhook has no project".into()))?;
        let full_name = project
            .get("path_with_namespace")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                HostingError::InvalidResponse("GitLab webhook has no project path".into())
            })?;
        let project_url = project
            .get("web_url")
            .and_then(serde_json::Value::as_str)
            .and_then(|value| Url::parse(value).ok())
            .ok_or_else(|| {
                HostingError::InvalidResponse("GitLab webhook has no valid project URL".into())
            })?;
        let event_id = find_header(headers, "webhook-id")
            .or_else(|| find_header(headers, "x-gitlab-event-uuid"))
            .ok_or_else(|| {
                HostingError::InvalidResponse("missing GitLab webhook delivery ID".into())
            })?;
        let gitlab_event =
            find_header(headers, "x-gitlab-event").unwrap_or_else(|| "Merge Request Hook".into());
        if !gitlab_event.eq_ignore_ascii_case("Merge Request Hook") {
            return Err(HostingError::InvalidResponse(
                "unsupported GitLab webhook event type".into(),
            ));
        }
        let raw_action = object
            .get("action")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let action = match raw_action {
            "open" => Some("opened".to_owned()),
            "reopen" => Some("reopened".to_owned()),
            "update"
                if object
                    .get("oldrev")
                    .and_then(serde_json::Value::as_str)
                    .is_some() =>
            {
                Some("synchronize".to_owned())
            }
            "update" => Some("metadata_update".to_owned()),
            "" => None,
            other => Some(other.to_owned()),
        };
        let pull_request = PullRequestRef {
            repository: crate::RepositoryRef {
                host: project_url.host_str().unwrap_or_default().to_owned(),
                full_name: full_name.to_owned(),
            },
            number,
        };
        pull_request
            .validate()
            .map_err(HostingError::InvalidResponse)?;
        let (base_oid, head_oid) = if matches!(
            action.as_deref(),
            Some("opened" | "reopened" | "synchronize")
        ) {
            let event_head = object
                .pointer("/last_commit/id")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    HostingError::InvalidResponse(
                        "GitLab merge request event has no last commit".into(),
                    )
                })?;
            let remote = GitHostingProvider::get_pull_request(self, &pull_request)?;
            (Some(remote.base_oid), Some(event_head.to_owned()))
        } else {
            (None, None)
        };
        let envelope = WebhookEnvelope {
            provider: "gitlab".into(),
            event_id,
            event_type: "pull_request".into(),
            delivery_attempt: 1,
            pull_request: Some(pull_request),
            action,
            // The event contributes its head, while the adapter supplies the
            // live base. The event handler re-fetches and compares both before review.
            base_oid,
            head_oid,
            signature_verified: true,
        };
        envelope.validate().map_err(HostingError::InvalidResponse)?;
        Ok(envelope)
    }
}

impl crate::PullRequestReviewIssuesProvider for GitLabAdapter {
    fn list_pull_request_review_issues(
        &self,
        reference: &PullRequestRef,
    ) -> Result<crate::PullRequestReviewIssues, HostingError> {
        #[derive(Deserialize)]
        struct ApiNote {
            id: u64,
            body: Option<String>,
            author: Option<ApiAuthor>,
            position: Option<ApiPosition>,
            web_url: Option<String>,
            created_at: Option<String>,
            updated_at: Option<String>,
            system: Option<bool>,
        }
        #[derive(Deserialize)]
        struct ApiAuthor {
            username: String,
        }
        #[derive(Deserialize)]
        struct ApiPosition {
            new_path: Option<String>,
            old_path: Option<String>,
            new_line: Option<u64>,
            old_line: Option<u64>,
        }

        const PAGE_SIZE: usize = 100;
        const MAX_PAGES: usize = 30;
        let before = GitHostingProvider::get_pull_request(self, reference)?;
        let mut issues = Vec::new();
        let mut total_body_bytes = 0usize;
        let mut complete = false;
        let mut page = 1usize;
        while page <= MAX_PAGES {
            let mut url = self.project_path(reference, "/notes")?;
            url.query_pairs_mut()
                .append_pair("per_page", &PAGE_SIZE.to_string())
                .append_pair("page", &page.to_string());
            let response = self.request(url)?.send().map_err(|error| {
                HostingError::Transport(format!("listing GitLab review issues: {error}"))
            })?;
            let response = Self::checked(response)?;
            let next_page = response
                .headers()
                .get("x-next-page")
                .and_then(|value| value.to_str().ok())
                .filter(|value| !value.is_empty())
                .map(|value| {
                    value.parse::<usize>().map_err(|_| {
                        HostingError::InvalidResponse(
                            "GitLab returned an invalid note pagination header".into(),
                        )
                    })
                })
                .transpose()?;
            let notes: Vec<ApiNote> = Self::bounded_json(response, MAX_API_RESPONSE_BYTES)?;
            let count = notes.len();
            for note in notes {
                if note.system.unwrap_or(false) {
                    continue;
                }
                let body = note.body.unwrap_or_default();
                total_body_bytes = total_body_bytes.saturating_add(body.len());
                if total_body_bytes > MAX_API_RESPONSE_BYTES as usize {
                    return Err(HostingError::InvalidResponse(
                        "GitLab review issue bodies exceed the aggregate response limit".into(),
                    ));
                }
                let position = note.position;
                let (path, line, side) = match position {
                    Some(position) => {
                        let is_new = position.new_line.is_some();
                        (
                            position.new_path.or(position.old_path),
                            position.new_line.or(position.old_line),
                            Some(if is_new {
                                crate::DiffSide::New
                            } else {
                                crate::DiffSide::Old
                            }),
                        )
                    }
                    None => (None, None, None),
                };
                issues.push(crate::PullRequestReviewIssue {
                    external_id: note.id.to_string(),
                    author: note.author.map(|author| author.username),
                    body,
                    path,
                    line,
                    side,
                    source_url: note.web_url,
                    created_at: note.created_at,
                    updated_at: note.updated_at,
                    classification: "untrusted_external_review".into(),
                });
            }
            let next_page = match next_page {
                Some(next) if next > page && next <= MAX_PAGES => Some(next),
                Some(_) => {
                    return Err(HostingError::InvalidResponse(
                        "GitLab note pagination exceeded its supported bounds".into(),
                    ));
                }
                None if count >= PAGE_SIZE && page < MAX_PAGES => Some(page + 1),
                None => None,
            };
            match next_page {
                Some(next) => page = next,
                None => {
                    complete = count < PAGE_SIZE;
                    break;
                }
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
            provider: "gitlab".into(),
            pull_request: reference.clone(),
            revision: before.revision,
            complete,
            gate_eligible: false,
            issues,
        })
    }
}

fn diff_line_counts(patch: &str) -> (u64, u64) {
    patch.lines().fold((0, 0), |(added, removed), line| {
        if line.starts_with("+++") || line.starts_with("---") || line.starts_with("@@") {
            (added, removed)
        } else if line.starts_with('+') {
            (added + 1, removed)
        } else if line.starts_with('-') {
            (added, removed + 1)
        } else {
            (added, removed)
        }
    })
}

fn patch_has_line(patch: &str, target: u64, side: DiffSide) -> bool {
    let (mut old_line, mut new_line) = (0u64, 0u64);
    for line in patch.lines() {
        if line.starts_with("@@") {
            if let Some((old, new)) = line.split_once(" +") {
                old_line = old
                    .split('-')
                    .nth(1)
                    .and_then(|s| s.split(',').next())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                new_line = new
                    .split(',')
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
            }
            continue;
        }
        match line.as_bytes().first() {
            Some(b' ') => {
                if (side == DiffSide::Old && old_line == target)
                    || (side == DiffSide::New && new_line == target)
                {
                    return true;
                }
                old_line += 1;
                new_line += 1;
            }
            Some(b'-') if !line.starts_with("---") => {
                if side == DiffSide::Old && old_line == target {
                    return true;
                }
                old_line += 1;
            }
            Some(b'+') if !line.starts_with("+++") => {
                if side == DiffSide::New && new_line == target {
                    return true;
                }
                new_line += 1;
            }
            _ => {}
        }
    }
    false
}

fn sha256_hex(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

fn truncate_chars(value: &str, max: usize) -> String {
    value.chars().take(max).collect()
}

fn gitlab_status(check: &CheckRun) -> Result<&'static str, HostingError> {
    let status = match check.status {
        CheckStatus::Queued => "pending",
        CheckStatus::InProgress => "running",
        CheckStatus::Completed => match check.conclusion.ok_or_else(|| {
            HostingError::InvalidResponse("completed check has no conclusion".into())
        })? {
            CheckConclusion::Success => "success",
            CheckConclusion::Failure
            | CheckConclusion::TimedOut
            | CheckConclusion::ActionRequired => "failed",
            CheckConclusion::Cancelled => "canceled",
            CheckConclusion::Neutral => "skipped",
        },
    };
    Ok(status)
}

fn find_header(headers: &BTreeMap<String, String>, name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.clone())
}

impl WorkItemProvider for GitLabAdapter {
    fn work_item_provider_id(&self) -> &'static str {
        "gitlab"
    }

    fn get_work_item(&self, reference: &WorkItemRef) -> Result<WorkItemSnapshot, HostingError> {
        reference
            .validate()
            .map_err(HostingError::InvalidResponse)?;
        let api_host = self.config.api_base.host_str().unwrap_or_default();
        if !reference.repository.host.eq_ignore_ascii_case(api_host) {
            return Err(HostingError::InvalidResponse(
                "work item host does not match configured GitLab API".into(),
            ));
        }

        #[derive(Deserialize)]
        struct ApiIssue {
            title: String,
            description: Option<String>,
            web_url: String,
            state: String,
            updated_at: String,
            labels: Vec<String>,
        }

        // GitLab's API accepts a URL-encoded project path in this position.
        let encoded_project = reference.repository.full_name.replace('/', "%2F");
        let mut url = self.config.api_base.clone();
        let prefix = url.path().trim_end_matches('/');
        url.set_path(&format!(
            "{prefix}/projects/{encoded_project}/issues/{}",
            reference.number
        ));
        let response = self.request(url)?.send().map_err(|error| {
            HostingError::Transport(format!("requesting GitLab issue: {error}"))
        })?;
        let response = Self::checked(response)?;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_WORK_ITEM_RESPONSE_BYTES)
        {
            return Err(HostingError::InvalidResponse(format!(
                "GitLab response exceeds the {MAX_WORK_ITEM_RESPONSE_BYTES}-byte limit"
            )));
        }
        let mut bytes = Vec::new();
        response
            .take(MAX_WORK_ITEM_RESPONSE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                HostingError::InvalidResponse(format!("reading GitLab response body: {error}"))
            })?;
        if bytes.len() as u64 > MAX_WORK_ITEM_RESPONSE_BYTES {
            return Err(HostingError::InvalidResponse(format!(
                "GitLab response exceeds the {MAX_WORK_ITEM_RESPONSE_BYTES}-byte limit"
            )));
        }
        let issue: ApiIssue = serde_json::from_slice(&bytes).map_err(|error| {
            HostingError::InvalidResponse(format!("invalid GitLab JSON: {error}"))
        })?;
        let issue_url = Url::parse(&issue.web_url)
            .map_err(|error| HostingError::InvalidResponse(error.to_string()))?;
        let expected_path = format!(
            "/{}/-/issues/{}",
            reference.repository.full_name, reference.number
        );
        if issue_url.scheme() != "https"
            || !issue_url
                .host_str()
                .is_some_and(|host| host.eq_ignore_ascii_case(&reference.repository.host))
            || issue_url.path() != expected_path
            || issue_url.query().is_some()
            || issue_url.fragment().is_some()
        {
            return Err(HostingError::InvalidResponse(
                "GitLab returned an issue URL outside the requested project".into(),
            ));
        }
        let mut labels = issue.labels;
        labels.sort();
        let mut snapshot = WorkItemSnapshot {
            schema_version: 1,
            reference: reference.clone(),
            provider: self.work_item_provider_id().into(),
            api_base: self.config.api_base.to_string(),
            title: issue.title,
            body: issue.description,
            acceptance_criteria: None,
            url: issue.web_url,
            state: issue.state,
            updated_at: issue.updated_at,
            labels,
            content_digest: String::new(),
        };
        snapshot.content_digest = work_item_digest(&snapshot);
        snapshot.validate().map_err(HostingError::InvalidResponse)?;
        Ok(snapshot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    fn issue_ref(host: &str) -> WorkItemRef {
        WorkItemRef {
            repository: crate::RepositoryRef {
                host: host.into(),
                full_name: "group/subgroup/project".into(),
            },
            number: 17,
        }
    }

    fn pull_request_ref(host: &str) -> PullRequestRef {
        PullRequestRef {
            repository: crate::RepositoryRef {
                host: host.into(),
                full_name: "group/subgroup/project".into(),
            },
            number: 17,
        }
    }

    fn fixture(body: String) -> (String, thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 4096];
            let count = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..count]).to_string();
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.flush();
            request
        });
        (format!("http://{address}/api/v4/"), worker)
    }

    fn fixture_sequence(bodies: Vec<String>) -> (String, thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let mut requests = Vec::new();
            for body in bodies {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0u8; 4096];
                let count = stream.read(&mut request).unwrap();
                requests.push(String::from_utf8_lossy(&request[..count]).to_string());
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
                stream.flush().unwrap();
            }
            requests
        });
        (format!("http://{address}/api/v4/"), worker)
    }

    fn fixture_sequence_with_next_page(
        responses: Vec<(String, Option<String>)>,
    ) -> (String, thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let mut requests = Vec::new();
            for (body, next_page) in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0u8; 4096];
                let count = stream.read(&mut request).unwrap();
                requests.push(String::from_utf8_lossy(&request[..count]).to_string());
                let pagination = next_page
                    .map(|page| format!("X-Next-Page: {page}\r\n"))
                    .unwrap_or_default();
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n{pagination}Connection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
                stream.flush().unwrap();
            }
            requests
        });
        (format!("http://{address}/api/v4/"), worker)
    }

    #[test]
    fn gitlab_review_issues_are_revision_bound_and_gate_ineligible() {
        let merge_request = serde_json::json!({
            "iid": 17,
            "title": "Review branch",
            "description": null,
            "state": "opened",
            "diff_refs": {
                "base_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "start_sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "head_sha": "cccccccccccccccccccccccccccccccccccccccc"
            }
        })
        .to_string();
        let notes = serde_json::json!([{
            "id": 51,
            "body": "Please handle this error",
            "author": {"username": "reviewer"},
            "position": {
                "new_path": "src/lib.rs",
                "old_path": "src/lib.rs",
                "new_line": 24,
                "old_line": 23
            },
            "web_url": "https://gitlab.example/group/project/-/merge_requests/17#note_51",
            "created_at": "2026-11-15T10:00:00Z",
            "updated_at": "2026-11-15T10:00:00Z",
            "system": false
        }, {
            "id": 52,
            "body": "system note",
            "system": true
        }])
        .to_string();
        let (api_base, worker) =
            fixture_sequence(vec![merge_request.clone(), notes, merge_request]);
        let adapter =
            GitLabAdapter::new(GitLabConfig::new(&api_base, "fixture-token".into()).unwrap())
                .unwrap();
        let report = crate::PullRequestReviewIssuesProvider::list_pull_request_review_issues(
            &adapter,
            &pull_request_ref("127.0.0.1"),
        )
        .unwrap();
        assert!(report.complete);
        assert!(!report.gate_eligible);
        assert_eq!(report.provider, "gitlab");
        assert_eq!(report.issues.len(), 1);
        assert_eq!(report.issues[0].external_id, "51");
        assert_eq!(report.issues[0].path.as_deref(), Some("src/lib.rs"));
        assert_eq!(report.issues[0].line, Some(24));
        assert_eq!(report.issues[0].side, Some(crate::DiffSide::New));
        assert_eq!(report.issues[0].classification, "untrusted_external_review");
        let requests = worker.join().unwrap();
        assert!(requests[1].contains("/merge_requests/17/notes?per_page=100&page=1"));
        assert!(requests[1]
            .to_ascii_lowercase()
            .contains("private-token: fixture-token"));
    }

    fn merge_request_json() -> String {
        r#"{"iid":17,"title":"Example MR","description":"Body","state":"opened","diff_refs":{"base_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","start_sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","head_sha":"cccccccccccccccccccccccccccccccccccccccc"}}"#.into()
    }

    #[test]
    fn gitlab_review_issue_page_bound_is_reported_as_incomplete() {
        let mut responses = vec![(merge_request_json(), None)];
        for page in 1..=30 {
            let notes = (0..100)
                .map(|item| {
                    serde_json::json!({
                        "id": page * 100 + item,
                        "body": "bounded note",
                        "system": false
                    })
                })
                .collect::<Vec<_>>();
            let next = (page < 30).then(|| (page + 1).to_string());
            responses.push((serde_json::to_string(&notes).unwrap(), next));
        }
        responses.push((merge_request_json(), None));
        let (base, worker) = fixture_sequence_with_next_page(responses);
        let adapter =
            GitLabAdapter::new(GitLabConfig::new(&base, "secret".into()).unwrap()).unwrap();
        let report = crate::PullRequestReviewIssuesProvider::list_pull_request_review_issues(
            &adapter,
            &pull_request_ref("127.0.0.1"),
        )
        .unwrap();
        assert!(!report.complete);
        assert_eq!(report.issues.len(), 3_000);
        assert!(!report.gate_eligible);
        let requests = worker.join().unwrap();
        assert_eq!(requests.len(), 32);
        assert!(requests[30].contains("/notes?per_page=100&page=30"));
    }

    #[test]
    fn gitlab_issue_lookup_returns_provider_neutral_digest_bound_context() {
        let body = r#"{"title":"Add report export","description":"Acceptance: preserve source digest.","web_url":"https://127.0.0.1/group/subgroup/project/-/issues/17","state":"opened","updated_at":"2026-11-14T12:00:00Z","labels":["feature","export"]}"#;
        let (base, worker) = fixture(body.into());
        let adapter =
            GitLabAdapter::new(GitLabConfig::new(&base, "secret".into()).unwrap()).unwrap();
        let snapshot = adapter.get_work_item(&issue_ref("127.0.0.1")).unwrap();
        snapshot.validate().unwrap();
        assert_eq!(snapshot.provider, "gitlab");
        assert_eq!(snapshot.title, "Add report export");
        assert_eq!(snapshot.labels, ["export", "feature"]);
        assert_eq!(snapshot.content_digest, work_item_digest(&snapshot));
        let request = worker.join().unwrap();
        assert!(request
            .starts_with("GET /api/v4/projects/group%2Fsubgroup%2Fproject/issues/17 HTTP/1.1"));
        assert!(request
            .to_ascii_lowercase()
            .contains("private-token: secret"));
    }

    #[test]
    fn gitlab_issue_lookup_rejects_host_mismatch_and_oversized_body() {
        let config = GitLabConfig::new("https://gitlab.com/api/v4/", "secret".into()).unwrap();
        let adapter = GitLabAdapter::new(config).unwrap();
        assert!(matches!(
            adapter.get_work_item(&issue_ref("evil.example")),
            Err(HostingError::InvalidResponse(_))
        ));

        let (base, worker) = fixture("x".repeat(1_048_577));
        let adapter =
            GitLabAdapter::new(GitLabConfig::new(&base, "secret".into()).unwrap()).unwrap();
        assert!(
            matches!(adapter.get_work_item(&issue_ref("127.0.0.1")), Err(HostingError::InvalidResponse(message)) if message.contains("exceeds"))
        );
        worker.join().unwrap();
    }

    #[test]
    fn gitlab_configuration_requires_tls_except_for_loopback_fixtures() {
        assert!(GitLabConfig::new("http://gitlab.example/api/v4/", "secret".into()).is_err());
        assert!(GitLabConfig::new("https://gitlab.example/api/v4/", "secret".into()).is_ok());
        assert!(GitLabConfig::new("http://127.0.0.1/api/v4/", "secret".into()).is_ok());
    }

    #[test]
    fn gitlab_merge_request_diff_read_is_bound_to_diff_refs() {
        let diff = r#"[{"old_path":"src/lib.rs","new_path":"src/lib.rs","diff":"@@ -1,2 +1,2 @@\n before\n-old\n+new\n","new_file":false,"renamed_file":false,"deleted_file":false}]"#.to_string();
        let (base, worker) =
            fixture_sequence(vec![merge_request_json(), merge_request_json(), diff]);
        let adapter =
            GitLabAdapter::new(GitLabConfig::new(&base, "secret".into()).unwrap()).unwrap();
        let reference = pull_request_ref("127.0.0.1");
        let snapshot = adapter.get_pull_request(&reference).unwrap();
        assert_eq!(
            snapshot.revision,
            format!("{}:{}:{}", "a".repeat(40), "b".repeat(40), "c".repeat(40))
        );
        let files = adapter
            .list_changed_files(&reference, &snapshot.revision)
            .unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].additions, 1);
        assert_eq!(files[0].deletions, 1);
        assert!(patch_has_line(
            files[0].patch.as_deref().unwrap(),
            2,
            DiffSide::New
        ));
        let requests = worker.join().unwrap();
        assert!(requests[2].starts_with("GET /api/v4/projects/group%2Fsubgroup%2Fproject/merge_requests/17/diffs?per_page=100&page=1"));
    }

    #[test]
    fn gitlab_merge_request_diff_pages_enforce_aggregate_response_limit() {
        let oversized = "x".repeat(30_000);
        let page = (0..100)
            .map(|index| {
                serde_json::json!({
                    "old_path": format!("src/{index}.rs"),
                    "new_path": format!("src/{index}.rs"),
                    "diff": oversized,
                    "new_file": false,
                    "renamed_file": false,
                    "deleted_file": false
                })
            })
            .collect::<Vec<_>>();
        let (base, worker) = fixture_sequence_with_next_page(vec![
            (merge_request_json(), None),
            (serde_json::to_string(&page).unwrap(), Some("2".into())),
            (serde_json::to_string(&page).unwrap(), None),
        ]);
        let adapter =
            GitLabAdapter::new(GitLabConfig::new(&base, "secret".into()).unwrap()).unwrap();
        let result = adapter.list_changed_files(
            &pull_request_ref("127.0.0.1"),
            &format!("{}:{}:{}", "a".repeat(40), "b".repeat(40), "c".repeat(40)),
        );
        assert!(
            matches!(result, Err(HostingError::InvalidResponse(message)) if message.contains("aggregate response limit"))
        );
        assert_eq!(worker.join().unwrap().len(), 3);
    }

    #[test]
    fn gitlab_webhook_verifies_signed_timestamp_and_payload() {
        let key = [7u8; 32];
        let (base, worker) = fixture_sequence(vec![merge_request_json()]);
        let host = Url::parse(&base).unwrap().host_str().unwrap().to_owned();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let id = "delivery-17";
        let timestamp = now.to_string();
        let body = serde_json::to_vec(&serde_json::json!({
            "object_attributes":{"iid":17,"action":"update","oldrev":"dddddddddddddddddddddddddddddddddddddddd","last_commit":{"id":"cccccccccccccccccccccccccccccccccccccccc"}},
            "project":{"path_with_namespace":"group/subgroup/project","web_url":format!("http://{host}/group/subgroup/project")}
        })).unwrap();
        let mut mac = HmacSha256::new_from_slice(&key).unwrap();
        mac.update(format!("{id}.{timestamp}.").as_bytes());
        mac.update(&body);
        let signature = STANDARD.encode(mac.finalize().into_bytes());
        let mut headers = BTreeMap::from([
            ("webhook-id".into(), id.into()),
            ("webhook-timestamp".into(), timestamp),
            ("webhook-signature".into(), format!("v1,{signature}")),
            ("x-gitlab-event".into(), "Merge Request Hook".into()),
        ]);
        let adapter = GitLabAdapter::new(
            GitLabConfig::new(&base, "secret".into())
                .unwrap()
                .with_webhook_secret(format!("whsec_{}", STANDARD.encode(key))),
        )
        .unwrap();
        let envelope = adapter.verify_webhook(&headers, &body).unwrap();
        assert!(envelope.signature_verified);
        assert_eq!(envelope.event_id, id);
        assert_eq!(envelope.event_type, "pull_request");
        assert_eq!(envelope.action.as_deref(), Some("synchronize"));
        assert_eq!(
            envelope.head_oid.as_deref(),
            Some("cccccccccccccccccccccccccccccccccccccccc")
        );
        assert_eq!(envelope.pull_request.unwrap().number, 17);
        headers.insert("webhook-signature".into(), "v1,AAAA".into());
        assert!(matches!(
            adapter.verify_webhook(&headers, &body),
            Err(HostingError::InvalidResponse(_))
        ));
        worker.join().unwrap();
    }

    #[test]
    fn gitlab_publication_posts_snapshot_bound_status_and_inline_discussion() {
        let diff = r#"[{"old_path":"src/lib.rs","new_path":"src/lib.rs","diff":"@@ -1,2 +1,2 @@\n before\n-old\n+new\n","new_file":false,"renamed_file":false,"deleted_file":false}]"#.to_string();
        let (base, worker) = fixture_sequence(vec![
            merge_request_json(),
            "[]".into(),
            r#"{"id":91}"#.into(),
            merge_request_json(),
            diff,
            "[]".into(),
            r#"{"id":"discussion-1","notes":[]}"#.into(),
        ]);
        let adapter = GitLabAdapter::new(
            GitLabConfig::new(&base, "secret".into())
                .unwrap()
                .with_actor_login("vee-bot".into()),
        )
        .unwrap();
        let reference = pull_request_ref("127.0.0.1");
        let revision = format!("{}:{}:{}", "a".repeat(40), "b".repeat(40), "c".repeat(40));
        let publication = ReviewPublication {
            pull_request: reference.clone(),
            expected_revision: revision,
            check: CheckRun {
                pull_request: reference.clone(),
                external_id: "review-1".into(),
                name: "Vee".into(),
                status: CheckStatus::Completed,
                conclusion: Some(CheckConclusion::Failure),
                title: "Vee blocked".into(),
                summary: "A high severity issue".into(),
                snapshot_id: "snapshot-1".into(),
                idempotency_key: "review-1".into(),
            },
            threads: vec![ReviewThread {
                pull_request: reference,
                fingerprint: "finding-1".into(),
                path: "src/lib.rs".into(),
                line: 2,
                side: DiffSide::New,
                body: "Check this line".into(),
                resolution: ThreadResolution::Open,
                snapshot_id: "snapshot-1".into(),
                idempotency_key: "review-1:finding-1".into(),
            }],
        };
        let receipt = adapter.publish_review(publication).unwrap();
        assert_eq!(receipt.provider_check_id, "91");
        assert_eq!(receipt.thread_ids.get("finding-1").unwrap(), "discussion-1");
        let requests = worker.join().unwrap();
        assert!(
            requests[2].starts_with("POST /api/v4/projects/group%2Fsubgroup%2Fproject/statuses/")
        );
        assert!(requests[6].starts_with(
            "POST /api/v4/projects/group%2Fsubgroup%2Fproject/merge_requests/17/discussions"
        ));
        assert!(requests[6].contains("position_type"));
        assert!(requests[6].contains(&format!("\"start_sha\":\"{}\"", "b".repeat(40))));
    }

    #[test]
    fn gitlab_publication_updates_owned_discussion_and_resolves_stale_location() {
        let diff = r#"[{"old_path":"src/lib.rs","new_path":"src/lib.rs","diff":"@@ -1,2 +1,2 @@\n before\n-old\n+new\n","new_file":false,"renamed_file":false,"deleted_file":false}]"#.to_string();
        let existing = r#"[{"id":"discussion-1","resolved":false,"position":{"new_path":"src/lib.rs","new_line":2},"notes":[{"id":77,"body":"old comment <!-- vee:fingerprint:finding-1 -->","author":{"username":"vee-bot"}}]}]"#;
        let existing_current = r#"[{"id":"discussion-2","resolved":false,"position":{"new_path":"src/lib.rs","new_line":2},"notes":[{"id":78,"body":"old current comment <!-- vee:fingerprint:finding-2 -->","author":{"username":"vee-bot"}}]}]"#;
        let (base, worker) = fixture_sequence(vec![
            merge_request_json(),
            "[]".into(),
            r#"{"id":91}"#.into(),
            merge_request_json(),
            diff,
            existing.into(),
            r#"{}"#.into(),
            existing_current.into(),
            r#"{}"#.into(),
        ]);
        let adapter = GitLabAdapter::new(
            GitLabConfig::new(&base, "secret".into())
                .unwrap()
                .with_actor_login("vee-bot".into()),
        )
        .unwrap();
        let reference = pull_request_ref("127.0.0.1");
        let revision = format!("{}:{}:{}", "a".repeat(40), "b".repeat(40), "c".repeat(40));
        let publication = ReviewPublication {
            pull_request: reference.clone(),
            expected_revision: revision,
            check: CheckRun {
                pull_request: reference.clone(),
                external_id: "review-2".into(),
                name: "Vee".into(),
                status: CheckStatus::Completed,
                conclusion: Some(CheckConclusion::Success),
                title: "Vee passed".into(),
                summary: "Finding fixed".into(),
                snapshot_id: "snapshot-2".into(),
                idempotency_key: "review-2".into(),
            },
            threads: vec![
                ReviewThread {
                    pull_request: reference.clone(),
                    fingerprint: "finding-1".into(),
                    path: "src/removed.rs".into(),
                    line: 22,
                    side: DiffSide::New,
                    body: "Finding resolved".into(),
                    resolution: ThreadResolution::Resolved,
                    snapshot_id: "snapshot-2".into(),
                    idempotency_key: "review-2:finding-1".into(),
                },
                ReviewThread {
                    pull_request: reference,
                    fingerprint: "finding-2".into(),
                    path: "src/lib.rs".into(),
                    line: 2,
                    side: DiffSide::New,
                    body: "Updated finding details".into(),
                    resolution: ThreadResolution::Open,
                    snapshot_id: "snapshot-2".into(),
                    idempotency_key: "review-2:finding-2".into(),
                },
            ],
        };
        let receipt = adapter.publish_review(publication).unwrap();
        assert_eq!(receipt.thread_ids.get("finding-1").unwrap(), "discussion-1");
        assert_eq!(receipt.thread_ids.get("finding-2").unwrap(), "discussion-2");
        let requests = worker.join().unwrap();
        assert!(requests[5].starts_with(
            "GET /api/v4/projects/group%2Fsubgroup%2Fproject/merge_requests/17/discussions"
        ));
        assert!(requests[6].starts_with("PUT /api/v4/projects/group%2Fsubgroup%2Fproject/merge_requests/17/discussions/discussion-1?resolved=true"));
        assert!(!requests.iter().any(|request| request.contains("/notes/77")));
        assert!(requests[8].starts_with("PUT /api/v4/projects/group%2Fsubgroup%2Fproject/merge_requests/17/discussions/discussion-2/notes/78"));
        assert!(requests[8].contains("Updated finding details"));
        assert!(!requests.iter().any(|request| request.contains(
            "POST /api/v4/projects/group%2Fsubgroup%2Fproject/merge_requests/17/discussions HTTP"
        )));
    }

    #[test]
    fn gitlab_replaces_the_discussion_of_an_open_finding_whose_line_moved() {
        let diff = r#"[{"old_path":"src/lib.rs","new_path":"src/lib.rs","diff":"@@ -1,2 +1,2 @@\n before\n-old\n+new\n","new_file":false,"renamed_file":false,"deleted_file":false}]"#.to_string();
        let existing = r#"[{"id":"discussion-1","resolved":false,"position":{"new_path":"src/lib.rs","new_line":1},"notes":[{"id":77,"body":"old <!-- vee:fingerprint:finding-1 -->","author":{"username":"vee-bot"}}]}]"#;
        let (base, worker) = fixture_sequence(vec![
            merge_request_json(),
            "[]".into(),
            r#"{"id":91}"#.into(),
            merge_request_json(),
            diff,
            existing.into(),
            r#"{}"#.into(),
            r#"{}"#.into(),
            r#"{"id":"discussion-2"}"#.into(),
        ]);
        let adapter = GitLabAdapter::new(
            GitLabConfig::new(&base, "secret".into())
                .unwrap()
                .with_actor_login("vee-bot".into()),
        )
        .unwrap();
        let reference = pull_request_ref("127.0.0.1");
        let revision = format!("{}:{}:{}", "a".repeat(40), "b".repeat(40), "c".repeat(40));
        let publication = ReviewPublication {
            pull_request: reference.clone(),
            expected_revision: revision,
            check: CheckRun {
                pull_request: reference.clone(),
                external_id: "review-2".into(),
                name: "Vee".into(),
                status: CheckStatus::Completed,
                conclusion: Some(CheckConclusion::Failure),
                title: "Vee blocked".into(),
                summary: "Finding moved".into(),
                snapshot_id: "snapshot-2".into(),
                idempotency_key: "review-2".into(),
            },
            threads: vec![ReviewThread {
                pull_request: reference,
                fingerprint: "finding-1".into(),
                path: "src/lib.rs".into(),
                line: 2,
                side: DiffSide::New,
                body: "Still wrong".into(),
                resolution: ThreadResolution::Open,
                snapshot_id: "snapshot-2".into(),
                idempotency_key: "review-2:finding-1".into(),
            }],
        };
        let receipt = adapter.publish_review(publication).unwrap();
        assert_eq!(receipt.thread_ids.get("finding-1").unwrap(), "discussion-2");
        let requests = worker.join().unwrap();
        assert!(requests[6].starts_with("PUT /api/v4/projects/group%2Fsubgroup%2Fproject/merge_requests/17/discussions/discussion-1/notes/77"));
        assert!(
            requests[6].contains("vee:moved:finding-1") && !requests[6].contains("vee:fingerprint")
        );
        assert!(requests[7].contains("discussions/discussion-1?resolved=true"));
        assert!(requests[8].starts_with(
            "POST /api/v4/projects/group%2Fsubgroup%2Fproject/merge_requests/17/discussions HTTP"
        ));
        assert!(requests[8].contains("Still wrong"));
    }

    #[test]
    fn gitlab_review_reconciliation_follows_pagination_to_find_owned_thread() {
        let existing = r#"[{"id":"discussion-2","resolved":false,"position":{"new_path":"src/lib.rs","new_line":2},"notes":[{"id":88,"body":"old comment <!-- vee:fingerprint:finding-page-two -->","author":{"username":"vee-bot"}}]}]"#;
        let (base, worker) = fixture_sequence_with_next_page(vec![
            ("[]".into(), Some("2".into())),
            (existing.into(), None),
            ("{}".into(), None),
        ]);
        let adapter = GitLabAdapter::new(
            GitLabConfig::new(&base, "secret".into())
                .unwrap()
                .with_actor_login("vee-bot".into()),
        )
        .unwrap();
        let reference = pull_request_ref("127.0.0.1");
        let snapshot = PullRequestSnapshot {
            pull_request: reference.clone(),
            base_oid: "a".repeat(40),
            head_oid: "c".repeat(40),
            title: "Example".into(),
            body: None,
            state: PullRequestState::Open,
            revision: format!("{}:{}:{}", "a".repeat(40), "b".repeat(40), "c".repeat(40)),
        };
        let files = vec![PullRequestFile {
            path: "src/lib.rs".into(),
            change: FileChange::Modified,
            previous_path: None,
            patch: Some("@@ -1,2 +1,2 @@\n before\n-old\n+new\n".into()),
            additions: 1,
            deletions: 1,
        }];
        let thread = ReviewThread {
            pull_request: reference,
            fingerprint: "finding-page-two".into(),
            path: "src/lib.rs".into(),
            line: 2,
            side: DiffSide::New,
            body: "Updated finding details".into(),
            resolution: ThreadResolution::Open,
            snapshot_id: "snapshot-page-two".into(),
            idempotency_key: "snapshot-page-two:finding-page-two".into(),
        };
        let discussion_id = adapter
            .sync_review_thread(&snapshot, &files, &thread)
            .unwrap();
        assert_eq!(discussion_id.as_deref(), Some("discussion-2"));
        let requests = worker.join().unwrap();
        assert!(requests[0].contains("per_page=100&page=1"));
        assert!(requests[1].contains("per_page=100&page=2"));
        assert!(requests[2].starts_with("PUT /api/v4/projects/group%2Fsubgroup%2Fproject/merge_requests/17/discussions/discussion-2/notes/88"));
        assert!(requests[2].contains("Updated finding details"));
    }
}
