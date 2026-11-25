//! Gerrit change context, review publication, and review-comment adapter.
//!
//! Gerrit's REST API prefixes JSON responses with an XSSI guard. Only comments
//! on the current patch set are returned; all content remains untrusted.

use crate::{
    CheckConclusion, CheckRun, CheckStatus, DiffSide, FileChange, GitHostingProvider, HostingError,
    PublicationReceipt, PullRequestContextProvider, PullRequestFile, PullRequestRef,
    PullRequestReviewIssue, PullRequestReviewIssues, PullRequestReviewIssuesProvider,
    PullRequestSnapshot, PullRequestState, ReviewPublication, SuggestionStyle, ThreadResolution,
    WebhookEnvelope,
};
use hmac::{Hmac, Mac};
use reqwest::{blocking::Client, header, Method, StatusCode, Url};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io::Read, time::Duration};

const MAX_RESPONSE_BYTES: u64 = 5_242_880;
const MIN_WEBHOOK_SECRET_BYTES: usize = 32;
type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct GerritConfig {
    pub api_base: Url,
    pub token: String,
    pub username: Option<String>,
    pub webhook_secret: String,
    pub timeout: Duration,
}

impl GerritConfig {
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
                "Gerrit API URL and credential are required; HTTP is allowed only on loopback"
                    .into(),
            );
        }
        Ok(Self {
            api_base,
            token,
            username: None,
            webhook_secret: String::new(),
            timeout: Duration::from_secs(30),
        })
    }

    /// Use Gerrit's HTTP password/basic authentication instead of a bearer token.
    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    /// Verify events signed by a trusted Gerrit webhook relay.
    pub fn with_webhook_secret(mut self, secret: String) -> Self {
        self.webhook_secret = secret;
        self
    }
}

#[derive(Clone)]
pub struct GerritAdapter {
    config: GerritConfig,
    client: Client,
}

impl GerritAdapter {
    pub fn new(config: GerritConfig) -> Result<Self, String> {
        if !config.webhook_secret.is_empty()
            && config.webhook_secret.len() < MIN_WEBHOOK_SECRET_BYTES
        {
            return Err(format!(
                "Gerrit relay webhook secret must contain at least {MIN_WEBHOOK_SECRET_BYTES} bytes"
            ));
        }
        let client = Client::builder()
            .timeout(config.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| format!("building Gerrit client: {error}"))?;
        Ok(Self { config, client })
    }

    fn change_url(&self, reference: &PullRequestRef, suffix: &str) -> Result<Url, HostingError> {
        reference
            .validate()
            .map_err(HostingError::InvalidResponse)?;
        if reference.number == 0
            || !reference
                .repository
                .host
                .eq_ignore_ascii_case(self.config.api_base.host_str().unwrap_or_default())
        {
            return Err(HostingError::InvalidResponse(
                "Gerrit change host or number does not match the configured API".into(),
            ));
        }
        let mut url = self.config.api_base.clone();
        let prefix = url.path().trim_end_matches('/');
        url.set_path(&format!(
            "{prefix}/changes/{}/{}",
            reference.number,
            suffix.trim_start_matches('/')
        ));
        Ok(url)
    }

    fn get_json(&self, url: Url) -> Result<Value, HostingError> {
        self.json_request(Method::GET, url, None)
    }

    fn json_request(
        &self,
        method: Method,
        url: Url,
        body: Option<Value>,
    ) -> Result<Value, HostingError> {
        let mut request = self
            .client
            .request(method, url)
            .header(header::ACCEPT, "application/json");
        if body.is_some() {
            request = request.header(header::CONTENT_TYPE, "application/json");
        }
        request = if let Some(username) = &self.config.username {
            request.basic_auth(username, Some(&self.config.token))
        } else {
            request.bearer_auth(&self.config.token)
        };
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().map_err(|error| {
            HostingError::Transport(format!("requesting Gerrit review comments: {error}"))
        })?;
        let status = response.status();
        if !status.is_success() {
            return match status {
                StatusCode::NOT_FOUND => Err(HostingError::NotFound),
                StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Err(HostingError::Unauthorized),
                StatusCode::TOO_MANY_REQUESTS => Err(HostingError::RateLimited {
                    retry_after_seconds: response
                        .headers()
                        .get(header::RETRY_AFTER)
                        .and_then(|value| value.to_str().ok())
                        .and_then(|value| value.parse().ok()),
                }),
                _ => Err(HostingError::Transport(format!(
                    "Gerrit returned HTTP {status}"
                ))),
            };
        }
        if response
            .content_length()
            .is_some_and(|size| size > MAX_RESPONSE_BYTES)
        {
            return Err(HostingError::InvalidResponse(
                "Gerrit response exceeds the 5 MiB limit".into(),
            ));
        }
        let mut bytes = Vec::new();
        response
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                HostingError::InvalidResponse(format!("reading Gerrit response: {error}"))
            })?;
        if bytes.len() as u64 > MAX_RESPONSE_BYTES {
            return Err(HostingError::InvalidResponse(
                "Gerrit response exceeds the 5 MiB limit".into(),
            ));
        }
        let json = bytes
            .strip_prefix(b")]}'\n")
            .or_else(|| bytes.strip_prefix(b")]}'\r\n"))
            .unwrap_or(&bytes);
        serde_json::from_slice(json)
            .map_err(|error| HostingError::InvalidResponse(format!("invalid Gerrit JSON: {error}")))
    }

    fn api_base(&self) -> Url {
        self.config.api_base.clone()
    }

    fn revision_url(
        &self,
        reference: &PullRequestRef,
        revision: &str,
        suffix: &str,
    ) -> Result<Url, HostingError> {
        let mut url = self.change_url(reference, &format!("revisions/{revision}/{suffix}"))?;
        if !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(HostingError::InvalidResponse(
                "invalid Gerrit revision".into(),
            ));
        }
        url.set_path(&url.path().replace(revision, &revision.to_ascii_lowercase()));
        Ok(url)
    }

    fn change_detail(
        &self,
        reference: &PullRequestRef,
        options: &[&str],
    ) -> Result<Value, HostingError> {
        let mut url = self.change_url(reference, "detail")?;
        {
            let mut query = url.query_pairs_mut();
            for option in options {
                query.append_pair("o", option);
            }
        }
        self.get_json(url)
    }

    fn verify_change_identity(
        &self,
        reference: &PullRequestRef,
        value: &Value,
    ) -> Result<(), HostingError> {
        if value.get("_number").and_then(Value::as_u64) != Some(reference.number)
            || value.get("project").and_then(Value::as_str)
                != Some(reference.repository.full_name.as_str())
        {
            return Err(HostingError::InvalidResponse(
                "Gerrit change identity does not match the requested repository/change".into(),
            ));
        }
        Ok(())
    }

    fn current_revision(&self, reference: &PullRequestRef) -> Result<String, HostingError> {
        let change = self.change_detail(reference, &["CURRENT_REVISION"])?;
        self.verify_change_identity(reference, &change)?;
        let revision = change
            .get("current_revision")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                HostingError::InvalidResponse("Gerrit change has no current revision".into())
            })?;
        if !matches!(revision.len(), 40 | 64)
            || !revision.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(HostingError::InvalidResponse(
                "Gerrit returned an invalid current revision".into(),
            ));
        }
        Ok(revision.to_ascii_lowercase())
    }

    fn pull_request_snapshot(
        &self,
        reference: &PullRequestRef,
    ) -> Result<PullRequestSnapshot, HostingError> {
        let change = self.change_detail(reference, &["CURRENT_REVISION", "CURRENT_COMMIT"])?;
        self.verify_change_identity(reference, &change)?;
        let head_oid = change
            .get("current_revision")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                HostingError::InvalidResponse("Gerrit change has no current revision".into())
            })?
            .to_ascii_lowercase();
        let commit = change
            .pointer(&format!("/revisions/{head_oid}/commit"))
            .ok_or_else(|| {
                HostingError::InvalidResponse("Gerrit omitted current commit details".into())
            })?;
        let base_oid = commit
            .pointer("/parents/0/commit")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                HostingError::InvalidResponse("Gerrit change has no single parent commit".into())
            })?
            .to_ascii_lowercase();
        for oid in [&head_oid, &base_oid] {
            if !matches!(oid.len(), 40 | 64) || !oid.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(HostingError::InvalidResponse(
                    "Gerrit returned an invalid commit OID".into(),
                ));
            }
        }
        let state = match change
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or_default()
        {
            "NEW" => PullRequestState::Open,
            "MERGED" => PullRequestState::Merged,
            _ => PullRequestState::Closed,
        };
        Ok(PullRequestSnapshot {
            pull_request: reference.clone(),
            base_oid,
            head_oid: head_oid.clone(),
            title: change
                .get("subject")
                .and_then(Value::as_str)
                .unwrap_or("Gerrit change")
                .to_owned(),
            body: change
                .pointer(&format!("/revisions/{head_oid}/commit/message"))
                .and_then(Value::as_str)
                .map(str::to_owned),
            state,
            revision: head_oid,
        })
    }

    fn changed_files(
        &self,
        reference: &PullRequestRef,
        revision: &str,
    ) -> Result<Vec<PullRequestFile>, HostingError> {
        let files = self.get_json(self.revision_url(reference, revision, "files/")?)?;
        let files = files.as_object().ok_or_else(|| {
            HostingError::InvalidResponse("Gerrit revision files are not a file map".into())
        })?;
        let mut output = Vec::new();
        for (path, details) in files {
            if path == "/COMMIT_MSG" {
                continue;
            }
            let change = match details.get("status").and_then(Value::as_str).unwrap_or("M") {
                "A" => FileChange::Added,
                "D" => FileChange::Deleted,
                "R" => FileChange::Renamed,
                "C" => FileChange::Copied,
                _ => FileChange::Modified,
            };
            output.push(PullRequestFile {
                path: path.clone(),
                change,
                previous_path: details
                    .get("old_path")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                patch: None,
                additions: details
                    .get("lines_inserted")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                deletions: details
                    .get("lines_deleted")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
            });
        }
        output.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(output)
    }

    fn current_comments(
        &self,
        reference: &PullRequestRef,
        revision: &str,
    ) -> Result<Value, HostingError> {
        self.get_json(self.revision_url(reference, revision, "comments/")?)
    }

    fn current_account_id(&self) -> Result<u64, HostingError> {
        let mut url = self.api_base();
        let prefix = url.path().trim_end_matches('/');
        url.set_path(&format!("{prefix}/accounts/self/detail"));
        let account = self.get_json(url)?;
        account
            .get("_account_id")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                HostingError::InvalidResponse(
                    "Gerrit authenticated account has no account ID".into(),
                )
            })
    }

    fn current_messages(&self, reference: &PullRequestRef) -> Result<Vec<Value>, HostingError> {
        let messages = self.get_json(self.change_url(reference, "messages/")?)?;
        messages.as_array().cloned().ok_or_else(|| {
            HostingError::InvalidResponse("Gerrit messages response is not an array".into())
        })
    }

    fn review_tag(key: &str) -> String {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(key.as_bytes());
        format!("autogenerated:vee:{:x}", digest)
    }

    fn status_text(check: &CheckRun) -> Result<&'static str, HostingError> {
        match (check.status, check.conclusion) {
            (CheckStatus::Queued, _) => Ok("QUEUED"),
            (CheckStatus::InProgress, _) => Ok("IN PROGRESS"),
            (CheckStatus::Completed, Some(CheckConclusion::Success | CheckConclusion::Neutral)) => {
                Ok("PASS")
            }
            (
                CheckStatus::Completed,
                Some(CheckConclusion::Failure | CheckConclusion::ActionRequired),
            ) => Ok("BLOCK"),
            (
                CheckStatus::Completed,
                Some(CheckConclusion::Cancelled | CheckConclusion::TimedOut),
            ) => Ok("INCOMPLETE"),
            _ => Err(HostingError::InvalidResponse(
                "completed Gerrit review requires a conclusion".into(),
            )),
        }
    }

    fn verify_webhook_signature(
        &self,
        headers: &BTreeMap<String, String>,
        body: &[u8],
    ) -> Result<(), HostingError> {
        if self.config.webhook_secret.is_empty() {
            return Err(HostingError::InvalidResponse(
                "Gerrit webhook signing secret is not configured".into(),
            ));
        }
        let signature = headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case("x-gerrit-signature"))
            .map(|(_, value)| value.as_str())
            .ok_or_else(|| {
                HostingError::InvalidResponse("missing Gerrit webhook signature".into())
            })?;
        let hex = signature.strip_prefix("sha256=").ok_or_else(|| {
            HostingError::InvalidResponse("unsupported Gerrit webhook signature".into())
        })?;
        if hex.len() != 64 {
            return Err(HostingError::InvalidResponse(
                "invalid Gerrit webhook signature".into(),
            ));
        }
        let supplied = decode_hex(hex).ok_or_else(|| {
            HostingError::InvalidResponse("invalid Gerrit webhook signature".into())
        })?;
        let mut mac = HmacSha256::new_from_slice(self.config.webhook_secret.as_bytes())
            .map_err(|_| HostingError::InvalidResponse("invalid Gerrit webhook secret".into()))?;
        mac.update(body);
        mac.verify_slice(&supplied).map_err(|_| {
            HostingError::InvalidResponse("Gerrit webhook signature verification failed".into())
        })
    }
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
            Some((digit(pair[0])? << 4) | digit(pair[1])?)
        })
        .collect()
}

impl PullRequestContextProvider for GerritAdapter {
    fn context_provider_id(&self) -> &'static str {
        "gerrit"
    }

    fn get_pull_request_context(
        &self,
        reference: &PullRequestRef,
    ) -> Result<PullRequestSnapshot, HostingError> {
        self.pull_request_snapshot(reference)
    }

    fn list_pull_request_context_files(
        &self,
        reference: &PullRequestRef,
        expected_revision: &str,
    ) -> Result<Vec<PullRequestFile>, HostingError> {
        let before = self.current_revision(reference)?;
        if before != expected_revision {
            return Err(HostingError::StaleRevision {
                expected: expected_revision.into(),
                actual: before,
            });
        }
        let files = self.changed_files(reference, expected_revision)?;
        let after = self.current_revision(reference)?;
        if after != expected_revision {
            return Err(HostingError::StaleRevision {
                expected: expected_revision.into(),
                actual: after,
            });
        }
        Ok(files)
    }
}

impl GitHostingProvider for GerritAdapter {
    fn provider_id(&self) -> &'static str {
        "gerrit"
    }

    fn get_pull_request(
        &self,
        reference: &PullRequestRef,
    ) -> Result<PullRequestSnapshot, HostingError> {
        self.pull_request_snapshot(reference)
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
        let reference = &publication.pull_request;
        let before = self.current_revision(reference)?;
        if before != publication.expected_revision {
            return Err(HostingError::StaleRevision {
                expected: publication.expected_revision,
                actual: before,
            });
        }
        let snapshot = self.pull_request_snapshot(reference)?;
        if snapshot.state != PullRequestState::Open {
            return Err(HostingError::InvalidResponse(
                "cannot publish to a closed Gerrit change".into(),
            ));
        }
        let author_id = self.current_account_id()?;
        let existing = self.current_comments(reference, &before)?;
        let existing_files = existing.as_object().ok_or_else(|| {
            HostingError::InvalidResponse("Gerrit comments response is not a file map".into())
        })?;
        let mut comments: std::collections::BTreeMap<String, Vec<Value>> =
            std::collections::BTreeMap::new();
        let mut thread_ids = std::collections::BTreeMap::new();
        for thread in &publication.threads {
            let marker = format!("<!-- vee:{} -->", thread.fingerprint);
            let prior = existing_files
                .iter()
                .find_map(|(path, items)| {
                    items.as_array()?.iter().find_map(|item| {
                        let message = item.get("message").and_then(Value::as_str)?;
                        let account = item.pointer("/author/_account_id").and_then(Value::as_u64);
                        (account == Some(author_id) && message.contains(&marker))
                            .then_some((path.as_str(), item))
                    })
                })
                .filter(|(_, item)| item.get("in_reply_to").is_none());
            let (path, prior) = match prior {
                Some((path, comment)) => (path.to_owned(), Some(comment)),
                None => (thread.path.clone(), None),
            };
            let prior_id = prior.and_then(|item| item.get("id").and_then(Value::as_str));
            // Gerrit stores resolution on the latest comment in a thread. A
            // root comment can remain marked unresolved after a later reply
            // resolves it, so inspect the root and its direct replies ordered
            // by Gerrit's update timestamp.
            let prior_unresolved = prior
                .and_then(|root| root.get("id").and_then(Value::as_str))
                .and_then(|root_id| {
                    existing_files
                        .values()
                        .filter_map(Value::as_array)
                        .flatten()
                        .filter(|comment| {
                            comment.get("id").and_then(Value::as_str) == Some(root_id)
                                || comment.get("in_reply_to").and_then(Value::as_str)
                                    == Some(root_id)
                        })
                        .max_by(|left, right| {
                            left.get("updated")
                                .and_then(Value::as_str)
                                .cmp(&right.get("updated").and_then(Value::as_str))
                        })
                        .and_then(|comment| comment.get("unresolved").and_then(Value::as_bool))
                })
                .unwrap_or(false);
            let should_post = matches!(
                (thread.resolution, prior_id, prior_unresolved),
                (ThreadResolution::Open, None, _)
                    | (ThreadResolution::Resolved, Some(_), true)
                    | (ThreadResolution::Open, Some(_), false)
            );
            if let Some(id) = prior_id {
                thread_ids.insert(thread.fingerprint.clone(), id.to_owned());
            }
            if !should_post {
                continue;
            }
            let mut input = serde_json::json!({
                "path": thread.path,
                "line": thread.line,
                "side": match thread.side { DiffSide::Old => "PARENT", DiffSide::New => "REVISION" },
            });
            let message = match (thread.resolution, prior_id) {
                (ThreadResolution::Resolved, Some(_)) => format!(
                    "Resolved by Vee for snapshot `{}`. {}",
                    thread.snapshot_id, marker
                ),
                (ThreadResolution::Open, Some(_)) => format!(
                    "Finding is open again in snapshot `{}`.\n\n{}\n\n{}",
                    thread.snapshot_id,
                    thread.body_with_suggestion(SuggestionStyle::Diff),
                    marker
                ),
                _ => format!(
                    "{}\n\n{}",
                    thread.body_with_suggestion(SuggestionStyle::Diff),
                    marker
                ),
            };
            input["message"] = Value::String(message);
            input["unresolved"] = Value::Bool(thread.resolution == ThreadResolution::Open);
            if let Some(id) = prior_id {
                input["in_reply_to"] = Value::String(id.to_owned());
            }
            comments.entry(path).or_default().push(input);
        }
        let status = Self::status_text(&publication.check)?;
        let tag = Self::review_tag(&publication.check.idempotency_key);
        let messages = self.current_messages(reference)?;
        let detail = self.change_detail(reference, &["CURRENT_REVISION"])?;
        let patch_set_number = detail
            .get("current_revision_number")
            .and_then(Value::as_u64);
        let summary_already_posted = messages.iter().any(|message| {
            message.get("tag").and_then(Value::as_str) == Some(tag.as_str())
                && message.get("_revision_number").and_then(Value::as_u64) == patch_set_number
        });
        let summary = format!(
            "Vee gate: {status}\n\n{}\n\nVee review `{}` · snapshot `{}`",
            publication.check.summary, publication.check.external_id, publication.check.snapshot_id
        );
        let mut input = serde_json::json!({"tag": tag, "comments": comments});
        if !summary_already_posted {
            input["message"] = Value::String(summary);
        }
        let mut url = self.revision_url(reference, &before, "review")?;
        url.query_pairs_mut().append_pair("notify", "NONE");
        let result = self.json_request(Method::POST, url, Some(input))?;
        if let Some(error) = result.get("error").and_then(Value::as_str) {
            return Err(HostingError::Transport(format!(
                "Gerrit rejected review publication: {error}"
            )));
        }
        let after = self.current_revision(reference)?;
        if after != before {
            return Err(HostingError::StaleRevision {
                expected: before,
                actual: after,
            });
        }
        let published_comments = self.current_comments(reference, &before)?;
        if let Some(files) = published_comments.as_object() {
            for thread in &publication.threads {
                let marker = format!("<!-- vee:{} -->", thread.fingerprint);
                if let Some(id) = files
                    .values()
                    .filter_map(Value::as_array)
                    .flatten()
                    .find_map(|comment| {
                        let message = comment.get("message").and_then(Value::as_str)?;
                        let author = comment
                            .pointer("/author/_account_id")
                            .and_then(Value::as_u64);
                        (author == Some(author_id)
                            && message.contains(&marker)
                            && comment.get("in_reply_to").is_none())
                        .then(|| comment.get("id").and_then(Value::as_str))
                        .flatten()
                    })
                {
                    thread_ids.insert(thread.fingerprint.clone(), id.to_owned());
                }
            }
        }
        let check_id = result
            .pointer("/change_info/current_revision")
            .and_then(Value::as_str)
            .unwrap_or(&before)
            .to_owned();
        Ok(PublicationReceipt {
            provider_check_id: check_id,
            thread_ids,
            resulting_revision: after,
        })
    }

    fn verify_webhook(
        &self,
        headers: &BTreeMap<String, String>,
        body: &[u8],
    ) -> Result<WebhookEnvelope, HostingError> {
        self.verify_webhook_signature(headers, body)?;
        let payload: Value = serde_json::from_slice(body).map_err(|error| {
            HostingError::InvalidResponse(format!("invalid Gerrit webhook JSON: {error}"))
        })?;
        let event_name = payload
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| HostingError::InvalidResponse("missing Gerrit event type".into()))?;
        let event_created = payload
            .get("eventCreatedOn")
            .and_then(Value::as_i64)
            .filter(|created| *created > 0)
            .ok_or_else(|| {
                HostingError::InvalidResponse("missing Gerrit event creation time".into())
            })?;
        let change = payload.get("change");
        let supported = matches!(
            event_name,
            "patchset-created" | "change-restored" | "change-abandoned" | "change-merged"
        );
        if !supported {
            return Err(HostingError::InvalidResponse(format!(
                "unsupported Gerrit event type `{event_name}`"
            )));
        }
        let number = change
            .and_then(|value| value.get("number"))
            .and_then(Value::as_u64)
            .filter(|number| *number > 0);
        let project = change
            .and_then(|value| value.get("project"))
            .and_then(Value::as_str)
            .filter(|project| !project.trim().is_empty());
        let pull_request = match (number, project) {
            (Some(number), Some(project)) => Some(PullRequestRef {
                repository: crate::RepositoryRef {
                    host: self
                        .config
                        .api_base
                        .host_str()
                        .unwrap_or_default()
                        .to_owned(),
                    full_name: project.to_owned(),
                },
                number,
            }),
            _ => None,
        };
        if !matches!(event_name, "change-abandoned" | "change-merged") && pull_request.is_none() {
            return Err(HostingError::InvalidResponse(
                "Gerrit review event is missing project or change number".into(),
            ));
        }
        let head_oid = payload
            .pointer("/patchSet/revision")
            .or_else(|| payload.pointer("/change/currentPatchSet/revision"))
            .and_then(Value::as_str)
            .map(str::to_ascii_lowercase);
        if matches!(event_name, "patchset-created" | "change-restored") && head_oid.is_none() {
            return Err(HostingError::InvalidResponse(
                "Gerrit review event is missing patch-set revision".into(),
            ));
        }
        let action = match event_name {
            "patchset-created" => Some("synchronize"),
            "change-restored" => Some("reopened"),
            "change-abandoned" | "change-merged" => Some("closed"),
            _ => None,
        }
        .map(str::to_owned);
        let body_digest = Sha256::digest(body)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let event = WebhookEnvelope {
            provider: "gerrit".into(),
            event_id: format!("gerrit:{event_name}:{event_created}:{body_digest}"),
            event_type: "pull_request".into(),
            delivery_attempt: headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case("x-gerrit-attempt"))
                .and_then(|(_, value)| value.parse::<u32>().ok())
                .filter(|attempt| *attempt > 0)
                .unwrap_or(1),
            pull_request,
            action,
            base_oid: None,
            head_oid,
            signature_verified: true,
        };
        event.validate().map_err(HostingError::InvalidResponse)?;
        Ok(event)
    }
}

impl PullRequestReviewIssuesProvider for GerritAdapter {
    fn list_pull_request_review_issues(
        &self,
        reference: &PullRequestRef,
    ) -> Result<PullRequestReviewIssues, HostingError> {
        let before = self.current_revision(reference)?;
        let comments_url = self.change_url(reference, &format!("revisions/{before}/comments/"))?;
        let comments = self.get_json(comments_url)?;
        let files = comments.as_object().ok_or_else(|| {
            HostingError::InvalidResponse("Gerrit revision comments are not a file map".into())
        })?;
        let mut issues = Vec::new();
        let mut total_body_bytes = 0usize;
        for (path, path_comments) in files {
            let path_comments = path_comments.as_array().ok_or_else(|| {
                HostingError::InvalidResponse("Gerrit file comments are not an array".into())
            })?;
            for comment in path_comments {
                let Some(body) = comment.get("message").and_then(Value::as_str) else {
                    continue;
                };
                total_body_bytes = total_body_bytes.saturating_add(body.len());
                if total_body_bytes > MAX_RESPONSE_BYTES as usize {
                    return Err(HostingError::InvalidResponse(
                        "Gerrit review comments exceed the aggregate response limit".into(),
                    ));
                }
                let comment_revision = comment
                    .get("commit_id")
                    .and_then(Value::as_str)
                    .map(str::to_ascii_lowercase);
                if comment_revision
                    .as_deref()
                    .is_some_and(|revision| revision != before)
                {
                    continue;
                }
                let side = match comment.get("side").and_then(Value::as_str) {
                    Some("PARENT") => Some(DiffSide::Old),
                    Some("REVISION") | None => Some(DiffSide::New),
                    _ => None,
                };
                let line = comment
                    .get("line")
                    .and_then(Value::as_u64)
                    .or_else(|| comment.pointer("/range/end_line").and_then(Value::as_u64));
                issues.push(PullRequestReviewIssue {
                    external_id: comment
                        .get("id")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                        .unwrap_or_else(|| format!("{}:{}", path, issues.len())),
                    author: comment
                        .pointer("/author/name")
                        .or_else(|| comment.pointer("/author/username"))
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    body: body.to_owned(),
                    path: Some(path.clone()),
                    line,
                    side,
                    source_url: None,
                    created_at: comment
                        .get("updated")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    updated_at: comment
                        .get("updated")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    classification: "untrusted_external_review".into(),
                });
            }
        }
        let after = self.current_revision(reference)?;
        if before != after {
            return Err(HostingError::StaleRevision {
                expected: before,
                actual: after,
            });
        }
        Ok(PullRequestReviewIssues {
            schema_version: 1,
            provider: "gerrit".into(),
            pull_request: reference.clone(),
            revision: before,
            complete: true,
            gate_eligible: false,
            issues,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ReviewThread;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    fn reference(host: String) -> PullRequestRef {
        PullRequestRef {
            repository: crate::RepositoryRef {
                host,
                full_name: "team/repo".into(),
            },
            number: 17,
        }
    }

    fn respond(stream: &mut std::net::TcpStream, body: &str) {
        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        stream.flush().unwrap();
    }

    #[test]
    fn verifies_signed_gerrit_patchset_events_and_extracts_live_revision_identity() {
        let config = GerritConfig::new("https://gerrit.example/", "api-token".into())
            .unwrap()
            .with_webhook_secret("gerrit-relay-secret-at-least-32-bytes".into());
        let adapter = GerritAdapter::new(config).unwrap();
        let body = br#"{"type":"patchset-created","eventCreatedOn":1794700000,"change":{"number":17,"project":"team/repo"},"patchSet":{"revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}"#;
        let mut mac = HmacSha256::new_from_slice(b"gerrit-relay-secret-at-least-32-bytes").unwrap();
        mac.update(body);
        let signature = mac
            .finalize()
            .into_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let headers = BTreeMap::from([(
            "X-Gerrit-Signature".to_owned(),
            format!("sha256={signature}"),
        )]);
        let envelope = adapter.verify_webhook(&headers, body).unwrap();
        assert_eq!(envelope.provider, "gerrit");
        assert_eq!(envelope.event_type, "pull_request");
        assert_eq!(envelope.action.as_deref(), Some("synchronize"));
        assert_eq!(
            envelope.pull_request.unwrap().repository.host,
            "gerrit.example"
        );
        let expected_revision = "a".repeat(40);
        assert_eq!(
            envelope.head_oid.as_deref(),
            Some(expected_revision.as_str())
        );
        assert!(envelope.base_oid.is_none());

        let invalid = BTreeMap::from([(
            "X-Gerrit-Signature".to_owned(),
            format!("sha256={}", "0".repeat(64)),
        )]);
        assert!(adapter.verify_webhook(&invalid, body).is_err());
    }

    #[test]
    fn rejects_unsigned_or_unrecognized_gerrit_events() {
        let config = GerritConfig::new("https://gerrit.example/", "api-token".into())
            .unwrap()
            .with_webhook_secret("gerrit-relay-secret-at-least-32-bytes".into());
        let adapter = GerritAdapter::new(config).unwrap();
        assert!(adapter
            .verify_webhook(&BTreeMap::new(), b"{}")
            .unwrap_err()
            .to_string()
            .contains("signature"));
    }

    #[test]
    fn rejects_short_gerrit_relay_secrets_at_adapter_startup() {
        let config = GerritConfig::new("https://gerrit.example/", "api-token".into())
            .unwrap()
            .with_webhook_secret("short-secret".into());
        assert!(matches!(
            GerritAdapter::new(config),
            Err(error) if error.contains("at least 32 bytes")
        ));

        let read_only = GerritConfig::new("https://gerrit.example/", "api-token".into()).unwrap();
        assert!(GerritAdapter::new(read_only).is_ok());
    }

    #[test]
    fn reads_current_revision_comments_as_untrusted_context() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let revision = "a".repeat(40);
        let expected_revision = revision.clone();
        let server = thread::spawn(move || {
            let mut requests = Vec::new();
            for body in [
                format!(")]}}\'\n{{\"_number\":17,\"project\":\"team/repo\",\"current_revision\":\"{expected_revision}\"}}"),
                ")]}'\n{\"src/lib.rs\":[{\"id\":\"c1\",\"message\":\"Check bounds\",\"line\":23,\"side\":\"REVISION\",\"updated\":\"2026-11-15 10:00:00.000000000\",\"author\":{\"name\":\"Reviewer\"}}]}".to_owned(),
                format!(")]}}\'\n{{\"_number\":17,\"project\":\"team/repo\",\"current_revision\":\"{expected_revision}\"}}"),
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0u8; 4096];
                let count = stream.read(&mut request).unwrap();
                requests.push(String::from_utf8_lossy(&request[..count]).to_string());
                respond(&mut stream, &body);
            }
            requests
        });
        let host = address.ip().to_string();
        let config = GerritConfig::new(&format!("http://{address}/"), "secret".into()).unwrap();
        let adapter = GerritAdapter::new(config).unwrap();
        let report = adapter
            .list_pull_request_review_issues(&reference(host))
            .unwrap();
        assert_eq!(report.revision, revision);
        assert!(!report.gate_eligible);
        assert_eq!(report.issues.len(), 1);
        let issue = &report.issues[0];
        assert_eq!(issue.external_id, "c1");
        assert_eq!(issue.author.as_deref(), Some("Reviewer"));
        assert_eq!(issue.path.as_deref(), Some("src/lib.rs"));
        assert_eq!(issue.line, Some(23));
        assert_eq!(issue.side, Some(DiffSide::New));
        assert_eq!(issue.classification, "untrusted_external_review");
        let requests = server.join().unwrap();
        assert!(requests[0].contains("/changes/17/detail?o=CURRENT_REVISION"));
        assert!(requests[1].contains(&format!(
            "/changes/17/revisions/{}/comments/",
            "a".repeat(40)
        )));
        assert!(requests[0]
            .to_ascii_lowercase()
            .contains("authorization: bearer secret"));
    }

    #[test]
    fn rejects_a_change_that_moves_during_comment_retrieval() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let revision = "a".repeat(40);
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 4096];
            let _ = stream.read(&mut request).unwrap();
            let body = format!(")]}}\'\n{{\"_number\":17,\"project\":\"team/repo\",\"current_revision\":\"{revision}\"}}");
            respond(&mut stream, &body);
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 4096];
            let _ = stream.read(&mut request).unwrap();
            respond(&mut stream, ")]}'\n{\"src/lib.rs\":[]}");
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 4096];
            let _ = stream.read(&mut request).unwrap();
            let revision = "b".repeat(40);
            let body = format!(")]}}'\n{{\"_number\":17,\"project\":\"team/repo\",\"current_revision\":\"{revision}\"}}");
            respond(&mut stream, &body);
        });
        let config = GerritConfig::new(&format!("http://{address}/"), "secret".into()).unwrap();
        let adapter = GerritAdapter::new(config).unwrap();
        let error = adapter
            .list_pull_request_review_issues(&reference(address.ip().to_string()))
            .unwrap_err();
        assert_eq!(
            error,
            HostingError::StaleRevision {
                expected: "a".repeat(40),
                actual: "b".repeat(40)
            }
        );
        server.join().unwrap();
    }

    #[test]
    fn publishes_revision_bound_gate_summary_and_fingerprinted_inline_thread() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let revision = "a".repeat(40);
        let base = "b".repeat(40);
        let rev = revision.clone();
        let parent = base.clone();
        let server = thread::spawn(move || {
            let mut requests = Vec::new();
            let detail = format!(")]}}'\n{{\"_number\":17,\"project\":\"team/repo\",\"current_revision\":\"{rev}\",\"current_revision_number\":3,\"status\":\"NEW\",\"subject\":\"Review target\",\"revisions\":{{\"{rev}\":{{\"_number\":3,\"commit\":{{\"message\":\"details\",\"parents\":[{{\"commit\":\"{parent}\"}}]}}}}}}}}");
            let marker = "<!-- vee:sha256:fixture -->";
            for (expected_method, body) in [
                ("GET", format!(")]}}'\n{{\"_number\":17,\"project\":\"team/repo\",\"current_revision\":\"{rev}\"}}")),
                ("GET", detail.clone()),
                ("GET", ")]}'\n{\"_account_id\":99}".into()),
                ("GET", ")]}'\n{\"src/lib.rs\":[]}".into()),
                ("GET", ")]}'\n[]".into()),
                ("GET", detail.clone()),
                ("POST", format!(")]}}'\n{{\"change_info\":{{\"current_revision\":\"{rev}\"}}}}")),
                ("GET", format!(")]}}'\n{{\"_number\":17,\"project\":\"team/repo\",\"current_revision\":\"{rev}\"}}")),
                ("GET", format!(")]}}'\n{{\"src/lib.rs\":[{{\"id\":\"comment-1\",\"message\":\"Check bounds\\n\\n{marker}\",\"unresolved\":true,\"author\":{{\"_account_id\":99}}}}]}}")),
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0u8; 16_384];
                let count = stream.read(&mut request).unwrap();
                let request = String::from_utf8_lossy(&request[..count]).to_string();
                assert!(request.starts_with(expected_method), "unexpected request: {request}");
                requests.push(request);
                respond(&mut stream, &body);
            }
            requests
        });
        let config = GerritConfig::new(&format!("http://{address}/"), "secret".into()).unwrap();
        let adapter = GerritAdapter::new(config).unwrap();
        let pull_request = reference(address.ip().to_string());
        let publication = ReviewPublication {
            pull_request: pull_request.clone(),
            expected_revision: revision.clone(),
            check: CheckRun {
                pull_request: pull_request.clone(),
                external_id: "rev_fixture".into(),
                name: "Vee".into(),
                status: CheckStatus::Completed,
                conclusion: Some(CheckConclusion::Success),
                title: "Vee passed".into(),
                summary: "No blocking findings".into(),
                snapshot_id: "sha256:snapshot".into(),
                idempotency_key: "rev_fixture".into(),
            },
            threads: vec![ReviewThread {
                suggestion: None,
                pull_request,
                fingerprint: "sha256:fixture".into(),
                path: "src/lib.rs".into(),
                line: 23,
                side: DiffSide::New,
                body: "Check bounds".into(),
                resolution: ThreadResolution::Open,
                snapshot_id: "sha256:snapshot".into(),
                idempotency_key: "rev_fixture:sha256:fixture".into(),
            }],
        };
        let receipt = adapter.publish_review(publication).unwrap();
        assert_eq!(receipt.resulting_revision, revision);
        assert_eq!(
            receipt.thread_ids.get("sha256:fixture").map(String::as_str),
            Some("comment-1")
        );
        let requests = server.join().unwrap();
        let posted = requests
            .iter()
            .find(|request| request.starts_with("POST"))
            .unwrap();
        assert!(posted.contains("/revisions/"));
        assert!(posted.contains("/review?notify=NONE"));
        assert!(posted
            .to_ascii_lowercase()
            .contains("authorization: bearer secret"));
        let request_body = posted.split("\r\n\r\n").nth(1).unwrap();
        let value: Value = serde_json::from_str(request_body).unwrap();
        assert!(value["message"]
            .as_str()
            .unwrap()
            .contains("Vee gate: PASS"));
        assert!(value["tag"]
            .as_str()
            .unwrap()
            .starts_with("autogenerated:vee:"));
        assert!(value["comments"]["src/lib.rs"][0]["message"]
            .as_str()
            .unwrap()
            .contains("<!-- vee:sha256:fixture -->"));
        assert_eq!(value["comments"]["src/lib.rs"][0]["unresolved"], true);
    }
}
