//! Azure DevOps Work Item Tracking adapter.
//!
//! Work item content is untrusted review context; it is never gate evidence.

use crate::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use reqwest::{blocking::Client, header, StatusCode, Url};
use serde_json::Value;
use std::{io::Read, time::Duration};

const MAX_RESPONSE_BYTES: u64 = 1_048_576;
const MAX_DIFF_RESPONSE_BYTES: u64 = 5_242_880;

#[derive(Clone)]
pub struct AzureDevOpsConfig {
    pub api_base: Url,
    pub token: String,
    pub timeout: Duration,
    pub webhook_secret: String,
}

impl AzureDevOpsConfig {
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
                "Azure DevOps API URL and personal access token are required; HTTP is allowed only on loopback".into(),
            );
        }
        Ok(Self {
            api_base,
            token,
            timeout: Duration::from_secs(30),
            webhook_secret: String::new(),
        })
    }

    pub fn with_webhook_secret(mut self, secret: String) -> Self {
        self.webhook_secret = secret;
        self
    }
}

#[derive(Clone)]
pub struct AzureDevOpsAdapter {
    config: AzureDevOpsConfig,
    client: Client,
}

impl AzureDevOpsAdapter {
    pub fn new(config: AzureDevOpsConfig) -> Result<Self, String> {
        let client = Client::builder()
            .timeout(config.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| error.to_string())?;
        Ok(Self { config, client })
    }

    fn work_item_url(&self, reference: &WorkItemRef) -> Result<Url, HostingError> {
        reference
            .validate()
            .map_err(HostingError::InvalidResponse)?;
        let mut components = reference.repository.full_name.split('/');
        let organization = components.next().unwrap_or_default();
        let project = components.next().unwrap_or_default();
        if organization.is_empty() || project.is_empty() || components.next().is_some() {
            return Err(HostingError::InvalidResponse(
                "Azure DevOps work item identity must use ORGANIZATION/PROJECT#ID".into(),
            ));
        }
        if let Some(host) = self.config.api_base.host_str() {
            let host = self
                .config
                .api_base
                .port()
                .map(|port| format!("{host}:{port}"))
                .unwrap_or_else(|| host.to_owned());
            if !reference.repository.host.eq_ignore_ascii_case(&host) {
                return Err(HostingError::InvalidResponse(
                    "Azure DevOps API host does not match the work item reference".into(),
                ));
            }
        }
        let mut url = self.config.api_base.clone();
        {
            let mut path = url.path_segments_mut().map_err(|_| {
                HostingError::InvalidResponse(
                    "Azure DevOps API base cannot accept path segments".into(),
                )
            })?;
            path.pop_if_empty()
                .push(organization)
                .push(project)
                .push("_apis")
                .push("wit")
                .push("workitems")
                .push(&reference.number.to_string());
        }
        url.query_pairs_mut().append_pair("api-version", "7.1");
        Ok(url)
    }

    fn pull_request_url(
        &self,
        reference: &PullRequestRef,
        suffix: &str,
    ) -> Result<Url, HostingError> {
        reference
            .validate()
            .map_err(HostingError::InvalidResponse)?;
        let host = self.config.api_base.host_str().unwrap_or_default();
        let configured_host = self
            .config
            .api_base
            .port()
            .map(|port| format!("{host}:{port}"))
            .unwrap_or_else(|| host.to_owned());
        if !reference
            .repository
            .host
            .eq_ignore_ascii_case(&configured_host)
        {
            return Err(HostingError::InvalidResponse(
                "pull request host does not match the configured Azure DevOps API".into(),
            ));
        }
        let components = reference
            .repository
            .full_name
            .split('/')
            .collect::<Vec<_>>();
        if components.len() != 3 {
            return Err(HostingError::InvalidResponse(
                "Azure DevOps pull request identity must use ORGANIZATION/PROJECT/REPOSITORY#ID"
                    .into(),
            ));
        }
        let mut url = self.config.api_base.clone();
        {
            let mut path = url.path_segments_mut().map_err(|_| {
                HostingError::InvalidResponse(
                    "Azure DevOps API base cannot accept path segments".into(),
                )
            })?;
            path.pop_if_empty()
                .push(components[0])
                .push(components[1])
                .push("_apis")
                .push("git")
                .push("repositories")
                .push(components[2]);
            for segment in suffix.split('/').filter(|segment| !segment.is_empty()) {
                path.push(segment);
            }
        }
        url.query_pairs_mut().append_pair("api-version", "7.1");
        Ok(url)
    }

    /// Publish a revision-bound Vee status on an Azure DevOps pull request.
    /// Azure DevOps treats a repeated status context (genre + name) as an
    /// update, which gives retries stable, provider-native upsert behavior.
    pub fn publish_check(
        &self,
        reference: &PullRequestRef,
        expected_revision: &str,
        check: &CheckRun,
    ) -> Result<String, HostingError> {
        if check.pull_request != *reference
            || check.name.trim().is_empty()
            || check.snapshot_id.trim().is_empty()
            || check.idempotency_key.trim().is_empty()
            || (check.status == CheckStatus::Completed) != check.conclusion.is_some()
        {
            return Err(HostingError::InvalidResponse(
                "invalid Azure DevOps check publication".into(),
            ));
        }
        let snapshot =
            <Self as PullRequestContextProvider>::get_pull_request_context(self, reference)?;
        if snapshot.revision != expected_revision {
            return Err(HostingError::StaleRevision {
                expected: expected_revision.into(),
                actual: snapshot.revision,
            });
        }
        if snapshot.state != PullRequestState::Open {
            return Err(HostingError::InvalidResponse(
                "pull request is not open".into(),
            ));
        }
        let mut url = self.pull_request_url(
            reference,
            &format!("pullRequests/{}/statuses", reference.number),
        )?;
        url.query_pairs_mut().append_pair("api-version", "7.1");
        let state = match (check.status, check.conclusion) {
            (CheckStatus::Queued | CheckStatus::InProgress, _) => "pending",
            (_, Some(CheckConclusion::Success)) => "succeeded",
            (_, Some(CheckConclusion::Failure | CheckConclusion::ActionRequired)) => "failed",
            (
                _,
                Some(
                    CheckConclusion::Cancelled
                    | CheckConclusion::TimedOut
                    | CheckConclusion::Neutral,
                ),
            ) => "error",
            _ => "pending",
        };
        let body = serde_json::json!({
            "context": { "genre": "vee", "name": check.name },
            "state": state,
            "description": format!("{} · snapshot {} · key {}", check.title, check.snapshot_id, check.idempotency_key),
            "targetUrl": format!("https://{}/", reference.repository.host)
        });
        let response = self
            .client
            .post(url)
            .basic_auth("", Some(&self.config.token))
            .header(header::ACCEPT, "application/json")
            .json(&body)
            .send()
            .map_err(|error| {
                HostingError::Transport(format!("publishing Azure DevOps status: {error}"))
            })?;
        let value = Self::bounded_json(Self::checked(response)?)?;
        value
            .get("id")
            .and_then(Value::as_u64)
            .map(|id| id.to_string())
            .ok_or_else(|| {
                HostingError::InvalidResponse("Azure DevOps status response omitted its ID".into())
            })
    }

    /// Publish idempotent line threads for findings that the caller has
    /// already proven belong to added lines in the exact reviewed Git diff.
    pub fn publish_threads(
        &self,
        reference: &PullRequestRef,
        expected_revision: &str,
        threads: &[ReviewThread],
    ) -> Result<std::collections::BTreeMap<String, String>, HostingError> {
        if threads.len() > 300 {
            return Err(HostingError::InvalidResponse(
                "Azure DevOps publication exceeds the 300-thread limit".into(),
            ));
        }
        let mut fingerprints = std::collections::BTreeSet::new();
        let mut idempotency_keys = std::collections::BTreeSet::new();
        for thread in threads {
            if thread.pull_request != *reference
                || (thread.resolution == ThreadResolution::Open
                    && (thread.line == 0
                        || thread.line > i32::MAX as u64
                        || thread.path.trim().is_empty()
                        || thread
                            .path
                            .split('/')
                            .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))))
                || thread.fingerprint.trim().is_empty()
                || thread.body.len() > 32_768
                || thread.idempotency_key.is_empty()
                || !thread
                    .idempotency_key
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b":._-".contains(&byte))
                || !fingerprints.insert(&thread.fingerprint)
                || !idempotency_keys.insert(&thread.idempotency_key)
            {
                return Err(HostingError::InvalidResponse(
                    "invalid Azure DevOps review thread".into(),
                ));
            }
        }
        let snapshot =
            <Self as PullRequestContextProvider>::get_pull_request_context(self, reference)?;
        if snapshot.revision != expected_revision {
            return Err(HostingError::StaleRevision {
                expected: expected_revision.into(),
                actual: snapshot.revision,
            });
        }
        if snapshot.state != PullRequestState::Open {
            return Err(HostingError::InvalidResponse(
                "pull request is not open".into(),
            ));
        }

        let iterations = self.get_json(self.pull_request_url(
            reference,
            &format!("pullRequests/{}/iterations", reference.number),
        )?)?;
        let iterations = iterations
            .get("value")
            .and_then(Value::as_array)
            .or_else(|| iterations.as_array())
            .ok_or_else(|| {
                HostingError::InvalidResponse("Azure DevOps omitted PR iterations".into())
            })?;
        let iteration = iterations
            .iter()
            .filter_map(|item| {
                let id = item.get("id")?.as_u64()?;
                Some((id, item))
            })
            .max_by_key(|(id, _)| *id)
            .ok_or_else(|| {
                HostingError::InvalidResponse("Azure DevOps PR has no iteration".into())
            })?;
        let iteration_id = iteration.0;
        let iteration_head = iteration
            .1
            .pointer("/sourceRefCommit/commitId")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                HostingError::InvalidResponse(
                    "Azure DevOps latest iteration omitted its source commit".into(),
                )
            })?;
        if !iteration_head.eq_ignore_ascii_case(&snapshot.head_oid) {
            return Err(HostingError::StaleRevision {
                expected: snapshot.head_oid,
                actual: iteration_head.to_owned(),
            });
        }

        let mut tracking_ids = std::collections::BTreeMap::new();
        let mut skip = 0_u64;
        loop {
            let mut url = self.pull_request_url(
                reference,
                &format!(
                    "pullRequests/{}/iterations/{iteration_id}/changes",
                    reference.number
                ),
            )?;
            url.query_pairs_mut()
                .append_pair("$compareTo", "0")
                .append_pair("$top", "2000")
                .append_pair("$skip", &skip.to_string());
            let value = self.get_json(url)?;
            let changes = value
                .get("changeEntries")
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    HostingError::InvalidResponse("Azure DevOps omitted iteration changes".into())
                })?;
            for change in changes {
                let Some(path) = change.pointer("/item/path").and_then(Value::as_str) else {
                    continue;
                };
                let Some(tracking_id) = change.get("changeTrackingId").and_then(Value::as_u64)
                else {
                    continue;
                };
                tracking_ids.insert(path.trim_start_matches('/').to_owned(), tracking_id);
            }
            let next_skip = value.get("nextSkip").and_then(Value::as_u64).unwrap_or(0);
            if next_skip == 0 {
                break;
            }
            if next_skip <= skip || next_skip > 20_000 {
                return Err(HostingError::InvalidResponse(
                    "Azure DevOps iteration pagination exceeded its bounds".into(),
                ));
            }
            skip = next_skip;
        }
        for thread in threads
            .iter()
            .filter(|thread| thread.resolution == ThreadResolution::Open)
        {
            if !tracking_ids.contains_key(thread.path.trim_start_matches('/')) {
                return Err(HostingError::InvalidResponse(format!(
                    "Azure DevOps iteration has no tracked diff entry for {}",
                    thread.path
                )));
            }
        }

        let existing = self.get_json(self.pull_request_url(
            reference,
            &format!("pullRequests/{}/threads", reference.number),
        )?)?;
        let existing = existing
            .get("value")
            .and_then(Value::as_array)
            .or_else(|| existing.as_array())
            .ok_or_else(|| {
                HostingError::InvalidResponse("Azure DevOps omitted PR threads".into())
            })?;
        let actor_id = self.authenticated_actor_id(reference)?;
        let mut ids = std::collections::BTreeMap::new();
        for thread in threads {
            let marker = format!("<!-- vee:{} -->", thread.idempotency_key);
            // The stable finding marker lets a later review reconcile the same
            // finding even though its per-review idempotency key has changed.
            let finding_marker = format!("<!-- vee:fingerprint:{} -->", thread.fingerprint);
            let mut found = existing.iter().filter_map(|existing_thread| {
                let id = existing_thread.get("id")?.as_u64()?;
                let comment =
                    existing_thread
                        .get("comments")?
                        .as_array()?
                        .iter()
                        .find(|comment| {
                            comment.pointer("/author/id").and_then(Value::as_str)
                                == Some(actor_id.as_str())
                                && comment
                                    .get("parentCommentId")
                                    .and_then(Value::as_u64)
                                    .unwrap_or(0)
                                    == 0
                                && comment.get("content").and_then(Value::as_str).is_some_and(
                                    |content| {
                                        content.contains(&marker)
                                            || content.contains(&finding_marker)
                                    },
                                )
                        })?;
                Some((
                    id,
                    comment.clone(),
                    existing_thread
                        .get("status")
                        .cloned()
                        .unwrap_or(Value::Null),
                ))
            });
            let matched = match (found.next(), found.next()) {
                (Some(entry), None) => Some(entry),
                (Some(_), Some(_)) => {
                    return Err(HostingError::InvalidResponse(
                        "duplicate Vee-owned finding threads already exist in Azure DevOps".into(),
                    ))
                }
                (None, _) => None,
            };
            let thread_id = if let Some((id, comment, current_status)) = matched {
                let comment_id = comment.get("id").and_then(Value::as_u64).ok_or_else(|| {
                    HostingError::InvalidResponse("Azure DevOps Vee comment omitted its ID".into())
                })?;
                let content = format!("{}\n\n{}\n{}", thread.body, finding_marker, marker);
                if comment.get("content").and_then(Value::as_str) != Some(content.as_str()) {
                    self.patch_json(
                        self.pull_request_url(
                            reference,
                            &format!(
                                "pullRequests/{}/threads/{id}/comments/{comment_id}",
                                reference.number
                            ),
                        )?,
                        &serde_json::json!({"content": content}),
                    )?;
                }
                let desired = if thread.resolution == ThreadResolution::Open {
                    1
                } else {
                    2
                };
                if azure_thread_status(&current_status) != Some(desired) {
                    self.patch_json(
                        self.pull_request_url(
                            reference,
                            &format!("pullRequests/{}/threads/{id}", reference.number),
                        )?,
                        &serde_json::json!({"status": desired}),
                    )?;
                }
                id
            } else if thread.resolution == ThreadResolution::Resolved {
                // A resolved occurrence only closes a matching Vee-owned thread.
                continue;
            } else {
                let current = <Self as PullRequestContextProvider>::get_pull_request_context(
                    self, reference,
                )?;
                if current.revision != expected_revision {
                    return Err(HostingError::StaleRevision {
                        expected: expected_revision.into(),
                        actual: current.revision,
                    });
                }
                if current.state != PullRequestState::Open {
                    return Err(HostingError::InvalidResponse(
                        "pull request is not open".into(),
                    ));
                }
                let tracking_id = tracking_ids[thread.path.trim_start_matches('/')];
                let mut url = self.pull_request_url(
                    reference,
                    &format!("pullRequests/{}/threads", reference.number),
                )?;
                url.query_pairs_mut().append_pair("api-version", "7.1");
                let body = serde_json::json!({
                    "comments": [{
                        "parentCommentId": 0,
                        "content": format!("{}\n\n{}\n{}", thread.body, finding_marker, marker),
                        "commentType": 1
                    }],
                    "status": 1,
                    "threadContext": {
                        "filePath": format!("/{}", thread.path.trim_start_matches('/')),
                        "rightFileStart": { "line": thread.line, "offset": 1 },
                        "rightFileEnd": { "line": thread.line, "offset": 1 }
                    },
                    "pullRequestThreadContext": {
                        "changeTrackingId": tracking_id,
                        "iterationContext": {
                            "firstComparingIteration": 1,
                            "secondComparingIteration": iteration_id
                        }
                    }
                });
                let response = self
                    .client
                    .post(url)
                    .basic_auth("", Some(&self.config.token))
                    .header(header::ACCEPT, "application/json")
                    .json(&body)
                    .send()
                    .map_err(|error| {
                        HostingError::Transport(format!(
                            "publishing Azure DevOps review thread: {error}"
                        ))
                    })?;
                Self::bounded_json(Self::checked(response)?)?
                    .get("id")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| {
                        HostingError::InvalidResponse(
                            "Azure DevOps thread response omitted its ID".into(),
                        )
                    })?
            };
            ids.insert(thread.fingerprint.clone(), thread_id.to_string());
        }
        Ok(ids)
    }

    fn verify_basic_webhook_auth(
        &self,
        headers: &std::collections::BTreeMap<String, String>,
    ) -> Result<(), HostingError> {
        if self.config.webhook_secret.is_empty() {
            return Err(HostingError::InvalidResponse(
                "Azure DevOps webhook credentials are not configured".into(),
            ));
        }
        let authorization = headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            .map(|(_, value)| value.as_str())
            .ok_or_else(|| HostingError::InvalidResponse("missing webhook authorization".into()))?;
        let encoded = authorization
            .split_once(' ')
            .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("Basic"))
            .map(|(_, value)| value)
            .ok_or_else(|| {
                HostingError::InvalidResponse("webhook requires Basic authentication".into())
            })?;
        let decoded = STANDARD.decode(encoded).map_err(|_| {
            HostingError::InvalidResponse("invalid webhook Basic credentials".into())
        })?;
        let credentials = std::str::from_utf8(&decoded).map_err(|_| {
            HostingError::InvalidResponse("invalid webhook Basic credentials".into())
        })?;
        let (_, password) = credentials.split_once(':').ok_or_else(|| {
            HostingError::InvalidResponse("invalid webhook Basic credentials".into())
        })?;
        if !constant_time_eq(password.as_bytes(), self.config.webhook_secret.as_bytes()) {
            return Err(HostingError::InvalidResponse(
                "invalid webhook credentials".into(),
            ));
        }
        Ok(())
    }

    fn authenticated_actor_id(&self, reference: &PullRequestRef) -> Result<String, HostingError> {
        let organization = reference
            .repository
            .full_name
            .split('/')
            .next()
            .unwrap_or_default();
        let mut url = self.config.api_base.clone();
        url.path_segments_mut()
            .map_err(|_| {
                HostingError::InvalidResponse(
                    "Azure DevOps API base cannot accept identity path".into(),
                )
            })?
            .pop_if_empty()
            .push(organization)
            .push("_apis")
            .push("connectionData");
        url.query_pairs_mut()
            .append_pair("connectOptions", "1")
            .append_pair("lastChangeId", "-1")
            .append_pair("lastChangeId64", "-1")
            .append_pair("api-version", "7.1-preview.1");
        self.get_json(url)?
            .pointer("/authenticatedUser/id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| {
                HostingError::InvalidResponse(
                    "Azure DevOps did not identify the authenticated account".into(),
                )
            })
    }

    fn patch_json(&self, mut url: Url, body: &Value) -> Result<Value, HostingError> {
        url.query_pairs_mut().append_pair("api-version", "7.1");
        let response = self
            .client
            .patch(url)
            .basic_auth("", Some(&self.config.token))
            .header(header::ACCEPT, "application/json")
            .json(body)
            .send()
            .map_err(|error| {
                HostingError::Transport(format!("updating Azure DevOps Vee thread: {error}"))
            })?;
        Self::bounded_json(Self::checked(response)?)
    }

    fn get_json(&self, url: Url) -> Result<Value, HostingError> {
        let response = self
            .client
            .get(url)
            .basic_auth("", Some(&self.config.token))
            .header(header::ACCEPT, "application/json")
            .send()
            .map_err(|error| {
                HostingError::Transport(format!("requesting Azure DevOps Git context: {error}"))
            })?;
        let response = Self::checked(response)?;
        Self::bounded_json_with_limit(response, MAX_DIFF_RESPONSE_BYTES)
    }

    fn bounded_json_with_limit(
        response: reqwest::blocking::Response,
        max_bytes: u64,
    ) -> Result<Value, HostingError> {
        if response
            .content_length()
            .is_some_and(|length| length > max_bytes)
        {
            return Err(HostingError::InvalidResponse(format!(
                "Azure DevOps response exceeds the {max_bytes}-byte limit"
            )));
        }
        let mut bytes = Vec::new();
        response
            .take(max_bytes + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                HostingError::InvalidResponse(format!("reading Azure DevOps response: {error}"))
            })?;
        if bytes.len() as u64 > max_bytes {
            return Err(HostingError::InvalidResponse(format!(
                "Azure DevOps response exceeds the {max_bytes}-byte limit"
            )));
        }
        serde_json::from_slice(&bytes).map_err(|error| {
            HostingError::InvalidResponse(format!("invalid Azure DevOps JSON: {error}"))
        })
    }

    fn request(&self, url: Url) -> Result<reqwest::blocking::Response, HostingError> {
        self.client
            .get(url)
            .basic_auth("", Some(&self.config.token))
            .header(header::ACCEPT, "application/json")
            .send()
            .map_err(|error| {
                HostingError::Transport(format!("requesting Azure DevOps work item: {error}"))
            })
    }

    fn checked(
        response: reqwest::blocking::Response,
    ) -> Result<reqwest::blocking::Response, HostingError> {
        match response.status() {
            StatusCode::OK => Ok(response),
            StatusCode::NOT_FOUND => Err(HostingError::NotFound),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Err(HostingError::Unauthorized),
            StatusCode::TOO_MANY_REQUESTS => Err(HostingError::RateLimited {
                retry_after_seconds: response
                    .headers()
                    .get(header::RETRY_AFTER)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse().ok()),
            }),
            status => Err(HostingError::InvalidResponse(format!(
                "Azure DevOps returned HTTP {status}"
            ))),
        }
    }

    fn bounded_json(response: reqwest::blocking::Response) -> Result<Value, HostingError> {
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BYTES)
        {
            return Err(HostingError::InvalidResponse(
                "Azure DevOps work item response exceeds the 1 MiB limit".into(),
            ));
        }
        let mut bytes = Vec::new();
        response
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                HostingError::InvalidResponse(format!("reading Azure DevOps response: {error}"))
            })?;
        if bytes.len() as u64 > MAX_RESPONSE_BYTES {
            return Err(HostingError::InvalidResponse(
                "Azure DevOps work item response exceeds the 1 MiB limit".into(),
            ));
        }
        serde_json::from_slice(&bytes).map_err(|error| {
            HostingError::InvalidResponse(format!("invalid Azure DevOps JSON: {error}"))
        })
    }
}

impl WorkItemProvider for AzureDevOpsAdapter {
    fn work_item_provider_id(&self) -> &'static str {
        "azure-devops"
    }

    fn get_work_item(&self, reference: &WorkItemRef) -> Result<WorkItemSnapshot, HostingError> {
        let response = Self::checked(self.request(self.work_item_url(reference)?)?)?;
        let value = Self::bounded_json(response)?;
        let id = value.get("id").and_then(Value::as_u64).ok_or_else(|| {
            HostingError::InvalidResponse("Azure DevOps work item response omitted its ID".into())
        })?;
        if id != reference.number {
            return Err(HostingError::InvalidResponse(
                "Azure DevOps returned a different work item".into(),
            ));
        }
        let fields = value
            .get("fields")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                HostingError::InvalidResponse(
                    "Azure DevOps work item response omitted fields".into(),
                )
            })?;
        let field = |name: &str| fields.get(name).and_then(Value::as_str);
        let title = field("System.Title")
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                HostingError::InvalidResponse("Azure DevOps work item has no title".into())
            })?
            .to_owned();
        let state = field("System.State")
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                HostingError::InvalidResponse("Azure DevOps work item has no state".into())
            })?
            .to_owned();
        let updated_at = field("System.ChangedDate")
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                HostingError::InvalidResponse("Azure DevOps work item has no changed date".into())
            })?
            .to_owned();
        let organization = reference
            .repository
            .full_name
            .split('/')
            .next()
            .unwrap_or_default();
        let project = reference
            .repository
            .full_name
            .split('/')
            .nth(1)
            .unwrap_or_default();
        let url = value
            .pointer("/_links/html/href")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .unwrap_or_else(|| {
                format!(
                    "https://{}/{}/{}/_workitems/edit/{}",
                    reference.repository.host, organization, project, id
                )
            });
        let labels = field("System.Tags")
            .unwrap_or_default()
            .split(';')
            .map(str::trim)
            .filter(|label| !label.is_empty())
            .take(100)
            .map(str::to_owned)
            .collect();
        let mut snapshot = WorkItemSnapshot {
            schema_version: 1,
            reference: reference.clone(),
            provider: self.work_item_provider_id().into(),
            api_base: self.config.api_base.as_str().to_owned(),
            title,
            body: field("System.Description").map(str::to_owned),
            acceptance_criteria: field("Microsoft.VSTS.Common.AcceptanceCriteria")
                .map(str::to_owned),
            url,
            state,
            updated_at,
            labels,
            content_digest: String::new(),
        };
        snapshot.content_digest = work_item_digest(&snapshot);
        snapshot.validate().map_err(HostingError::InvalidResponse)?;
        Ok(snapshot)
    }
}

impl PullRequestContextProvider for AzureDevOpsAdapter {
    fn context_provider_id(&self) -> &'static str {
        "azure-devops"
    }

    fn get_pull_request_context(
        &self,
        reference: &PullRequestRef,
    ) -> Result<PullRequestSnapshot, HostingError> {
        let value = self.get_json(
            self.pull_request_url(reference, &format!("pullRequests/{}", reference.number))?,
        )?;
        let id = value
            .get("pullRequestId")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                HostingError::InvalidResponse("Azure DevOps PR response omitted its ID".into())
            })?;
        if id != reference.number {
            return Err(HostingError::InvalidResponse(
                "Azure DevOps returned a different pull request".into(),
            ));
        }
        let text = |key: &str| value.get(key).and_then(Value::as_str);
        let commit = |path: &str| value.pointer(path).and_then(Value::as_str);
        let title = text("title")
            .filter(|text| !text.trim().is_empty())
            .ok_or_else(|| HostingError::InvalidResponse("Azure DevOps PR has no title".into()))?
            .to_owned();
        let base_oid = commit("/lastMergeTargetCommit/commitId")
            .filter(|oid| valid_oid(oid))
            .ok_or_else(|| {
                HostingError::InvalidResponse("Azure DevOps PR has no valid target commit".into())
            })?
            .to_ascii_lowercase();
        let head_oid = commit("/lastMergeSourceCommit/commitId")
            .filter(|oid| valid_oid(oid))
            .ok_or_else(|| {
                HostingError::InvalidResponse("Azure DevOps PR has no valid source commit".into())
            })?
            .to_ascii_lowercase();
        let state = match text("status")
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str()
        {
            "active" => PullRequestState::Open,
            "completed" => PullRequestState::Merged,
            _ => PullRequestState::Closed,
        };
        Ok(PullRequestSnapshot {
            pull_request: reference.clone(),
            base_oid: base_oid.clone(),
            head_oid: head_oid.clone(),
            title,
            body: text("description").map(str::to_owned),
            state,
            revision: format!("{base_oid}:{head_oid}"),
        })
    }

    fn list_pull_request_context_files(
        &self,
        reference: &PullRequestRef,
        expected_revision: &str,
    ) -> Result<Vec<PullRequestFile>, HostingError> {
        let snapshot = PullRequestContextProvider::get_pull_request_context(self, reference)?;
        if snapshot.revision != expected_revision {
            return Err(HostingError::StaleRevision {
                expected: expected_revision.to_owned(),
                actual: snapshot.revision,
            });
        }
        let mut files = Vec::new();
        let mut skip = 0_u64;
        let mut aggregate_response_bytes = 0_u64;
        loop {
            let mut url = self.pull_request_url(reference, "diffs/commits")?;
            url.query_pairs_mut()
                .append_pair("baseVersion", &snapshot.base_oid)
                .append_pair("baseVersionType", "commit")
                .append_pair("targetVersion", &snapshot.head_oid)
                .append_pair("targetVersionType", "commit")
                .append_pair("diffCommonCommit", "false")
                .append_pair("$top", "2000")
                .append_pair("$skip", &skip.to_string());
            let value = self.get_json(url)?;
            let page_bytes = serde_json::to_vec(&value)
                .map_err(|error| {
                    HostingError::InvalidResponse(format!(
                        "encoding Azure DevOps diff page: {error}"
                    ))
                })?
                .len() as u64;
            aggregate_response_bytes = aggregate_response_bytes.saturating_add(page_bytes);
            if aggregate_response_bytes > MAX_DIFF_RESPONSE_BYTES {
                return Err(HostingError::InvalidResponse(
                    "Azure DevOps pull request diff exceeds the 5 MiB aggregate response limit"
                        .into(),
                ));
            }
            let changes = value
                .get("changes")
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    HostingError::InvalidResponse(
                        "Azure DevOps diff response omitted changes".into(),
                    )
                })?;
            for change in changes {
                let item = change
                    .get("item")
                    .and_then(Value::as_object)
                    .ok_or_else(|| {
                        HostingError::InvalidResponse(
                            "Azure DevOps diff entry omitted its item".into(),
                        )
                    })?;
                if item.get("isFolder").and_then(Value::as_bool) == Some(true)
                    || item.get("gitObjectType").and_then(Value::as_str) == Some("tree")
                {
                    continue;
                }
                let path = item
                    .get("path")
                    .and_then(Value::as_str)
                    .map(|path| path.trim_start_matches('/'))
                    .filter(|path| !path.is_empty())
                    .ok_or_else(|| {
                        HostingError::InvalidResponse(
                            "Azure DevOps diff entry omitted file path".into(),
                        )
                    })?;
                let kind = change
                    .get("changeType")
                    .and_then(Value::as_str)
                    .unwrap_or("edit");
                let change_kind = match kind.to_ascii_lowercase().as_str() {
                    "add" => FileChange::Added,
                    "delete" => FileChange::Deleted,
                    "rename" | "sourcerename" | "targetrename" => FileChange::Renamed,
                    _ => FileChange::Modified,
                };
                let previous_path = change
                    .get("originalPath")
                    .and_then(Value::as_str)
                    .map(|path| path.trim_start_matches('/').to_owned())
                    .filter(|previous| previous != path);
                files.push(PullRequestFile {
                    path: path.to_owned(),
                    change: change_kind,
                    previous_path,
                    patch: None,
                    additions: 0,
                    deletions: 0,
                });
                if files.len() > 20_000 {
                    return Err(HostingError::InvalidResponse(
                        "Azure DevOps pull request exceeds the 20,000-file context limit".into(),
                    ));
                }
            }
            let all_included = value.get("allChangesIncluded").and_then(Value::as_bool);
            if all_included == Some(true) || changes.len() < 2000 {
                break;
            }
            skip += changes.len() as u64;
            if skip > 20_000 {
                return Err(HostingError::InvalidResponse(
                    "Azure DevOps diff pagination exceeded the 20,000-file context limit".into(),
                ));
            }
        }
        files.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(files)
    }
}

impl PullRequestReviewIssuesProvider for AzureDevOpsAdapter {
    fn list_pull_request_review_issues(
        &self,
        reference: &PullRequestRef,
    ) -> Result<PullRequestReviewIssues, HostingError> {
        let before = PullRequestContextProvider::get_pull_request_context(self, reference)?;
        let value = self.get_json(self.pull_request_url(
            reference,
            &format!("pullRequests/{}/threads", reference.number),
        )?)?;
        let threads = value
            .get("value")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                HostingError::InvalidResponse("Azure DevOps omitted PR threads".into())
            })?;
        let mut issues = Vec::new();
        let mut total_body_bytes = 0usize;
        for thread in threads {
            if thread.get("isDeleted").and_then(Value::as_bool) == Some(true) {
                continue;
            }
            let thread_id = thread.get("id").and_then(Value::as_u64).ok_or_else(|| {
                HostingError::InvalidResponse("Azure DevOps PR thread omitted its ID".into())
            })?;
            let context = thread.get("threadContext");
            let path = context
                .and_then(|context| context.get("filePath"))
                .and_then(Value::as_str)
                .map(|path| path.trim_start_matches('/').to_owned());
            let right_line = context
                .and_then(|context| context.pointer("/rightFileStart/line"))
                .and_then(Value::as_u64);
            let left_line = context
                .and_then(|context| context.pointer("/leftFileStart/line"))
                .and_then(Value::as_u64);
            let (line, side) = match (right_line, left_line) {
                (Some(line), _) => (Some(line), Some(DiffSide::New)),
                (None, Some(line)) => (Some(line), Some(DiffSide::Old)),
                (None, None) => (None, None),
            };
            let comments = thread
                .get("comments")
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    HostingError::InvalidResponse("Azure DevOps PR thread omitted comments".into())
                })?;
            for comment in comments {
                if comment.get("isDeleted").and_then(Value::as_bool) == Some(true)
                    || comment
                        .get("commentType")
                        .and_then(Value::as_str)
                        .is_some_and(|kind| kind.eq_ignore_ascii_case("system"))
                {
                    continue;
                }
                let Some(body) = comment.get("content").and_then(Value::as_str) else {
                    continue;
                };
                total_body_bytes = total_body_bytes.saturating_add(body.len());
                if total_body_bytes > MAX_RESPONSE_BYTES as usize {
                    return Err(HostingError::InvalidResponse(
                        "Azure DevOps review issue bodies exceed the aggregate response limit"
                            .into(),
                    ));
                }
                let author = comment
                    .pointer("/author/displayName")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                let created_at = comment
                    .get("publishedDate")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                let updated_at = comment
                    .get("lastUpdatedDate")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                let comment_id = comment.get("id").and_then(Value::as_u64);
                issues.push(PullRequestReviewIssue {
                    external_id: comment_id
                        .map(|id| format!("{thread_id}:{id}"))
                        .unwrap_or_else(|| thread_id.to_string()),
                    author,
                    body: body.to_owned(),
                    path: path.clone(),
                    line,
                    side,
                    source_url: None,
                    created_at,
                    updated_at,
                    classification: "untrusted_external_review".into(),
                });
            }
        }
        let after = PullRequestContextProvider::get_pull_request_context(self, reference)?;
        if before.revision != after.revision {
            return Err(HostingError::StaleRevision {
                expected: before.revision,
                actual: after.revision,
            });
        }
        Ok(PullRequestReviewIssues {
            schema_version: 1,
            provider: "azure-devops".into(),
            pull_request: reference.clone(),
            revision: before.revision,
            complete: true,
            gate_eligible: false,
            issues,
        })
    }
}

impl GitHostingProvider for AzureDevOpsAdapter {
    fn provider_id(&self) -> &'static str {
        "azure-devops"
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
        let check_id = self.publish_check(
            &publication.pull_request,
            &publication.expected_revision,
            &publication.check,
        )?;
        let thread_ids = self.publish_threads(
            &publication.pull_request,
            &publication.expected_revision,
            &publication.threads,
        )?;
        Ok(PublicationReceipt {
            provider_check_id: check_id,
            thread_ids,
            resulting_revision: publication.expected_revision,
        })
    }

    fn verify_webhook(
        &self,
        headers: &std::collections::BTreeMap<String, String>,
        body: &[u8],
    ) -> Result<WebhookEnvelope, HostingError> {
        self.verify_basic_webhook_auth(headers)?;
        let payload: Value = serde_json::from_slice(body).map_err(|error| {
            HostingError::InvalidResponse(format!("invalid Azure DevOps webhook JSON: {error}"))
        })?;
        let event_type = payload
            .get("eventType")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                HostingError::InvalidResponse("Azure DevOps webhook omitted eventType".into())
            })?;
        let resource = payload.get("resource").ok_or_else(|| {
            HostingError::InvalidResponse("Azure DevOps webhook omitted resource".into())
        })?;
        let pr_number = resource
            .get("pullRequestId")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                HostingError::InvalidResponse("Azure DevOps webhook omitted pullRequestId".into())
            })?;
        let repo = resource.get("repository").ok_or_else(|| {
            HostingError::InvalidResponse("Azure DevOps webhook omitted repository".into())
        })?;
        let remote_url = repo
            .get("remoteUrl")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                HostingError::InvalidResponse(
                    "Azure DevOps webhook omitted repository remoteUrl".into(),
                )
            })?;
        let remote_url = Url::parse(remote_url).map_err(|error| {
            HostingError::InvalidResponse(format!("invalid Azure DevOps repository URL: {error}"))
        })?;
        let segments = remote_url
            .path_segments()
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        let git_index = segments
            .iter()
            .position(|segment| *segment == "_git")
            .ok_or_else(|| {
                HostingError::InvalidResponse(
                    "Azure DevOps repository URL has no _git segment".into(),
                )
            })?;
        if git_index < 1 || git_index + 1 >= segments.len() {
            return Err(HostingError::InvalidResponse(
                "Azure DevOps repository URL has an unsupported path".into(),
            ));
        }
        // The event's repository project metadata handles collection-prefixed
        // Azure DevOps Server URLs whose path does not contain the project name.
        let organization = segments[0];
        let project = repo
            .pointer("/project/name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
            .unwrap_or(segments[git_index - 1]);
        let repository_name = repo
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
            .unwrap_or(segments[git_index + 1]);
        let pull_request = PullRequestRef {
            repository: RepositoryRef {
                host: remote_url.host_str().unwrap_or_default().to_owned(),
                full_name: format!("{organization}/{project}/{repository_name}"),
            },
            number: pr_number,
        };
        pull_request
            .validate()
            .map_err(HostingError::InvalidResponse)?;
        if !pull_request
            .repository
            .host
            .eq_ignore_ascii_case(self.config.api_base.host_str().unwrap_or_default())
        {
            return Err(HostingError::InvalidResponse(
                "Azure DevOps webhook host does not match configured API".into(),
            ));
        }
        let action = match event_type {
            "git.pullrequest.created" => Some("opened".to_owned()),
            "git.pullrequest.updated" => match resource.get("status").and_then(Value::as_str) {
                Some("completed") => Some("closed".to_owned()),
                Some("active")
                    if resource
                        .pointer("/lastMergeSourceCommit/commitId")
                        .and_then(Value::as_str)
                        .is_some_and(valid_oid)
                        && resource
                            .pointer("/lastMergeTargetCommit/commitId")
                            .and_then(Value::as_str)
                            .is_some_and(valid_oid) =>
                {
                    Some("synchronize".to_owned())
                }
                _ => Some("updated".to_owned()),
            },
            "git.pullrequest.merged" => Some("closed".to_owned()),
            _ => {
                return Err(HostingError::InvalidResponse(format!(
                    "unsupported Azure DevOps webhook event {event_type}"
                )))
            }
        };
        let commit = |key: &str| {
            resource
                .pointer(&format!("/{key}/commitId"))
                .and_then(Value::as_str)
                .map(str::to_owned)
        };
        let (base_oid, head_oid) = if matches!(action.as_deref(), Some("opened" | "synchronize")) {
            (
                commit("lastMergeTargetCommit"),
                commit("lastMergeSourceCommit"),
            )
        } else {
            (None, None)
        };
        let envelope = WebhookEnvelope {
            provider: "azure-devops".into(),
            event_id: payload
                .get("id")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .filter(|id| !id.is_empty())
                .ok_or_else(|| {
                    HostingError::InvalidResponse("Azure DevOps webhook omitted event id".into())
                })?,
            event_type: "pull_request".into(),
            delivery_attempt: 1,
            pull_request: Some(pull_request),
            action,
            base_oid,
            head_oid,
            signature_verified: true,
        };
        envelope.validate().map_err(HostingError::InvalidResponse)?;
        Ok(envelope)
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        difference |= usize::from(
            left.get(index).copied().unwrap_or(0) ^ right.get(index).copied().unwrap_or(0),
        );
    }
    difference == 0
}

fn valid_oid(oid: &str) -> bool {
    matches!(oid.len(), 40 | 64) && oid.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn azure_thread_status(value: &Value) -> Option<u64> {
    value.as_u64().or_else(|| match value.as_str()? {
        "active" => Some(1),
        "fixed" => Some(2),
        "wontFix" => Some(3),
        "closed" => Some(4),
        "byDesign" => Some(5),
        "pending" => Some(6),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    #[test]
    fn azure_devops_service_hook_basic_auth_and_pull_request_event_are_verified() {
        let adapter = AzureDevOpsAdapter::new(
            AzureDevOpsConfig::new("https://dev.azure.com/", "token".into())
                .unwrap()
                .with_webhook_secret("receiver-secret".into()),
        )
        .unwrap();
        let body = serde_json::json!({
            "id": "delivery-123",
            "eventType": "git.pullrequest.updated",
            "resource": {
                "pullRequestId": 17,
                "notificationType": "PushNotification",
                "status": "active",
                "repository": {
                    "name": "service",
                    "remoteUrl": "https://dev.azure.com/acme/DefaultCollection/_git/service",
                    "project": {"name": "platform"}
                },
                "lastMergeTargetCommit": {"commitId": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                "lastMergeSourceCommit": {"commitId": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
            }
        })
        .to_string();
        let mut headers = std::collections::BTreeMap::new();
        headers.insert(
            "authorization".into(),
            format!("Basic {}", STANDARD.encode("service-hook:receiver-secret")),
        );
        let envelope = adapter.verify_webhook(&headers, body.as_bytes()).unwrap();
        assert_eq!(envelope.provider, "azure-devops");
        assert_eq!(envelope.event_id, "delivery-123");
        assert_eq!(envelope.action.as_deref(), Some("synchronize"));
        assert_eq!(
            envelope.pull_request.as_ref().unwrap().repository.full_name,
            "acme/platform/service"
        );
        assert_eq!(
            envelope.base_oid.as_deref(),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
        assert_eq!(
            envelope.head_oid.as_deref(),
            Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        );

        headers.insert(
            "authorization".into(),
            format!("Basic {}", STANDARD.encode("service-hook:wrong")),
        );
        assert!(adapter.verify_webhook(&headers, body.as_bytes()).is_err());
    }

    fn reference(host: &str) -> WorkItemRef {
        WorkItemRef {
            repository: crate::RepositoryRef {
                host: host.into(),
                full_name: "acme/platform".into(),
            },
            number: 42,
        }
    }

    fn pr_reference(host: &str) -> PullRequestRef {
        PullRequestRef {
            repository: crate::RepositoryRef {
                host: host.into(),
                full_name: "acme/platform/service".into(),
            },
            number: 17,
        }
    }

    fn serve_json(listener: &TcpListener, requests: &mut Vec<String>, body: &str) {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        let mut buffer = [0u8; 2048];
        loop {
            let read = stream.read(&mut buffer).unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let header_end = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap()
            + 4;
        let header_text = String::from_utf8_lossy(&request[..header_end]);
        let content_length = header_text
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        while request.len() < header_end + content_length {
            let read = stream.read(&mut buffer).unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
        }
        requests.push(String::from_utf8_lossy(&request).into_owned());
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .unwrap();
        stream.flush().unwrap();
    }

    fn pr_response(head: &str) -> String {
        serde_json::json!({
            "pullRequestId": 17,
            "status": "active",
            "title": "Handle renamed module",
            "description": "Review metadata only",
            "lastMergeSourceCommit": { "commitId": head },
            "lastMergeTargetCommit": { "commitId": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
        })
        .to_string()
    }

    #[test]
    fn azure_devops_pull_request_context_is_revision_bound_and_marks_metadata_only() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let mut requests = Vec::new();
            serve_json(
                &listener,
                &mut requests,
                &pr_response("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            );
            serve_json(
                &listener,
                &mut requests,
                &pr_response("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            );
            serve_json(
                &listener,
                &mut requests,
                &serde_json::json!({
                    "allChangesIncluded": true,
                    "changes": [
                        { "changeType": "edit", "item": { "path": "/src/lib.rs", "gitObjectType": "blob" } },
                        { "changeType": "rename", "originalPath": "/old.rs", "item": { "path": "/new.rs", "gitObjectType": "blob" } },
                        { "changeType": "add", "item": { "path": "/folder", "isFolder": true } }
                    ]
                })
                .to_string(),
            );
            requests
        });
        let host = format!("127.0.0.1:{}", address.port());
        let adapter = AzureDevOpsAdapter::new(
            AzureDevOpsConfig::new(&format!("http://{host}/"), "pat-secret".into()).unwrap(),
        )
        .unwrap();
        let reference = pr_reference(&host);
        let snapshot =
            PullRequestContextProvider::get_pull_request_context(&adapter, &reference).unwrap();
        assert_eq!(snapshot.state, PullRequestState::Open);
        assert_eq!(snapshot.title, "Handle renamed module");
        assert_eq!(snapshot.revision.len(), 81);
        let files = PullRequestContextProvider::list_pull_request_context_files(
            &adapter,
            &reference,
            &snapshot.revision,
        )
        .unwrap();
        assert_eq!(files.len(), 2);
        let renamed = files.iter().find(|file| file.path == "new.rs").unwrap();
        assert_eq!(renamed.change, FileChange::Renamed);
        assert_eq!(renamed.previous_path.as_deref(), Some("old.rs"));
        assert!(renamed.patch.is_none());
        assert_eq!(renamed.additions, 0);
        let requests = worker.join().unwrap();
        assert!(requests[0].starts_with(
            "GET /acme/platform/_apis/git/repositories/service/pullRequests/17?api-version=7.1"
        ));
        assert!(requests[2].contains("baseVersion=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        assert!(requests[2].contains("targetVersion=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));
        assert!(requests.iter().all(|request| request
            .to_ascii_lowercase()
            .contains("authorization: basic ")));
    }

    #[test]
    fn azure_devops_pull_request_context_enforces_aggregate_page_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let mut requests = Vec::new();
            let same_pr = pr_response("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
            serve_json(&listener, &mut requests, &same_pr);
            let changes = (0..2000)
                .map(|index| serde_json::json!({"changeType":"edit","item":{"path":format!("/src/{index}.rs")}}))
                .collect::<Vec<_>>();
            let first = serde_json::json!({"allChangesIncluded":false,"padding":"x".repeat(2_700_000),"changes":changes}).to_string();
            let second = serde_json::json!({"allChangesIncluded":true,"padding":"y".repeat(2_700_000),"changes":[]}).to_string();
            serve_json(&listener, &mut requests, &first);
            serve_json(&listener, &mut requests, &second);
            requests
        });
        let host = format!("127.0.0.1:{}", address.port());
        let adapter = AzureDevOpsAdapter::new(
            AzureDevOpsConfig::new(&format!("http://{host}/"), "pat-secret".into()).unwrap(),
        )
        .unwrap();
        let result = PullRequestContextProvider::list_pull_request_context_files(
            &adapter,
            &pr_reference(&host),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        );
        assert!(
            matches!(result, Err(HostingError::InvalidResponse(message)) if message.contains("aggregate response limit"))
        );
        assert_eq!(worker.join().unwrap().len(), 3);
    }

    #[test]
    fn azure_devops_review_issues_are_revision_bound_and_gate_ineligible() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let mut requests = Vec::new();
            let same_pr = pr_response("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
            serve_json(&listener, &mut requests, &same_pr);
            serve_json(
                &listener,
                &mut requests,
                &serde_json::json!({
                    "value": [
                        {
                            "id": 51,
                            "isDeleted": false,
                            "threadContext": {
                                "filePath": "/src/lib.rs",
                                "rightFileStart": {"line": 24, "offset": 0}
                            },
                            "comments": [
                                {
                                    "id": 1,
                                    "author": {"displayName": "Build service"},
                                    "content": "automated event",
                                    "commentType": "system",
                                    "publishedDate": "2026-11-15T10:00:00Z"
                                },
                                {
                                    "id": 2,
                                    "author": {"displayName": "Reviewer"},
                                    "content": "Handle this error case",
                                    "commentType": "text",
                                    "publishedDate": "2026-11-15T10:01:00Z",
                                    "lastUpdatedDate": "2026-11-15T10:02:00Z"
                                },
                                {
                                    "id": 3,
                                    "isDeleted": true,
                                    "content": "deleted"
                                }
                            ]
                        }
                    ]
                })
                .to_string(),
            );
            serve_json(&listener, &mut requests, &same_pr);
            requests
        });
        let host = format!("127.0.0.1:{}", address.port());
        let adapter = AzureDevOpsAdapter::new(
            AzureDevOpsConfig::new(&format!("http://{host}/"), "pat-secret".into()).unwrap(),
        )
        .unwrap();
        let reference = pr_reference(&host);
        let report =
            PullRequestReviewIssuesProvider::list_pull_request_review_issues(&adapter, &reference)
                .unwrap();
        assert!(report.complete);
        assert!(!report.gate_eligible);
        assert_eq!(report.provider, "azure-devops");
        assert_eq!(report.issues.len(), 1);
        assert_eq!(report.issues[0].external_id, "51:2");
        assert_eq!(report.issues[0].author.as_deref(), Some("Reviewer"));
        assert_eq!(report.issues[0].path.as_deref(), Some("src/lib.rs"));
        assert_eq!(report.issues[0].line, Some(24));
        assert_eq!(report.issues[0].side, Some(DiffSide::New));
        assert_eq!(report.issues[0].classification, "untrusted_external_review");
        let requests = worker.join().unwrap();
        assert!(requests[1].contains("pullRequests/17/threads?api-version=7.1"));
        assert!(requests[1]
            .to_ascii_lowercase()
            .contains("authorization: basic "));
    }

    #[test]
    fn azure_devops_review_issues_reject_revision_change_during_retrieval() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let mut requests = Vec::new();
            serve_json(
                &listener,
                &mut requests,
                &pr_response("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            );
            serve_json(&listener, &mut requests, r#"{"value":[]}"#);
            serve_json(
                &listener,
                &mut requests,
                &pr_response("cccccccccccccccccccccccccccccccccccccccc"),
            );
            requests
        });
        let host = format!("127.0.0.1:{}", address.port());
        let adapter = AzureDevOpsAdapter::new(
            AzureDevOpsConfig::new(&format!("http://{host}/"), "pat-secret".into()).unwrap(),
        )
        .unwrap();
        let error = PullRequestReviewIssuesProvider::list_pull_request_review_issues(
            &adapter,
            &pr_reference(&host),
        )
        .unwrap_err();
        assert!(matches!(error, HostingError::StaleRevision { .. }));
        worker.join().unwrap();
    }

    #[test]
    fn azure_devops_rejects_stale_pull_request_file_context() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            serve_json(
                &listener,
                &mut Vec::new(),
                &pr_response("cccccccccccccccccccccccccccccccccccccccc"),
            );
        });
        let host = format!("127.0.0.1:{}", address.port());
        let adapter = AzureDevOpsAdapter::new(
            AzureDevOpsConfig::new(&format!("http://{host}/"), "pat-secret".into()).unwrap(),
        )
        .unwrap();
        let error = PullRequestContextProvider::list_pull_request_context_files(
            &adapter,
            &pr_reference(&host),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap_err();
        assert!(matches!(error, HostingError::StaleRevision { .. }));
        worker.join().unwrap();
    }

    #[test]
    fn azure_devops_publishes_gate_status_bound_to_current_revision() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let mut requests = Vec::new();
            serve_json(
                &listener,
                &mut requests,
                &pr_response("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            );
            serve_json(&listener, &mut requests, r#"{"id":23,"state":"succeeded"}"#);
            requests
        });
        let host = format!("127.0.0.1:{}", address.port());
        let adapter = AzureDevOpsAdapter::new(
            AzureDevOpsConfig::new(&format!("http://{host}/"), "pat-secret".into()).unwrap(),
        )
        .unwrap();
        let reference = pr_reference(&host);
        let check = CheckRun {
            pull_request: reference.clone(),
            external_id: "rev-1".into(),
            name: "Vee".into(),
            status: CheckStatus::Completed,
            conclusion: Some(CheckConclusion::Success),
            title: "Vee passed".into(),
            summary: "Gate status: Pass".into(),
            snapshot_id: "sha256:fixture".into(),
            idempotency_key: "review-1".into(),
        };
        assert_eq!(
            adapter
                .publish_check(
                    &reference,
                    &format!(
                        "{}:{}",
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    ),
                    &check,
                )
                .unwrap(),
            "23"
        );
        let requests = worker.join().unwrap();
        assert!(requests[1].starts_with("POST "));
        assert!(requests[1].contains("\"genre\":\"vee\""));
        assert!(requests[1].contains("\"name\":\"Vee\""));
        assert!(requests[1].contains("\"state\":\"succeeded\""));
    }

    #[test]
    fn azure_devops_posts_line_thread_with_revision_and_iteration_binding() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let mut requests = Vec::new();
            serve_json(
                &listener,
                &mut requests,
                &pr_response("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            );
            serve_json(
                &listener,
                &mut requests,
                r#"[{"id":2,"sourceRefCommit":{"commitId":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}]"#,
            );
            serve_json(
                &listener,
                &mut requests,
                r#"{"changeEntries":[{"item":{"path":"/src/lib.rs"},"changeTrackingId":7}],"nextSkip":0}"#,
            );
            serve_json(&listener, &mut requests, r#"{"value":[]}"#);
            serve_json(
                &listener,
                &mut requests,
                r#"{"authenticatedUser":{"id":"actor-1"}}"#,
            );
            serve_json(
                &listener,
                &mut requests,
                &pr_response("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            );
            serve_json(&listener, &mut requests, r#"{"id":42}"#);
            serve_json(
                &listener,
                &mut requests,
                &pr_response("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            );
            serve_json(
                &listener,
                &mut requests,
                r#"[{"id":2,"sourceRefCommit":{"commitId":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}]"#,
            );
            serve_json(
                &listener,
                &mut requests,
                r#"{"changeEntries":[{"item":{"path":"/src/lib.rs"},"changeTrackingId":7}],"nextSkip":0}"#,
            );
            serve_json(
                &listener,
                &mut requests,
                r#"{"value":[{"id":42,"status":"active","comments":[{"id":1,"parentCommentId":0,"author":{"id":"actor-1"},"content":"comment <!-- vee:fingerprint:fingerprint-1 --> <!-- vee:review-1:fingerprint-1 -->"}]}]}"#,
            );
            serve_json(
                &listener,
                &mut requests,
                r#"{"authenticatedUser":{"id":"actor-1"}}"#,
            );
            serve_json(&listener, &mut requests, r#"{"id":1}"#);
            for status in ["active", "fixed"] {
                serve_json(
                    &listener,
                    &mut requests,
                    &pr_response("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
                );
                serve_json(
                    &listener,
                    &mut requests,
                    r#"[{"id":2,"sourceRefCommit":{"commitId":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}]"#,
                );
                serve_json(
                    &listener,
                    &mut requests,
                    r#"{"changeEntries":[{"item":{"path":"/src/lib.rs"},"changeTrackingId":7}],"nextSkip":0}"#,
                );
                let content = if status == "active" {
                    "comment <!-- vee:fingerprint:fingerprint-1 --> <!-- vee:review-2:fingerprint-1 -->"
                } else {
                    "comment <!-- vee:fingerprint:fingerprint-1 --> <!-- vee:review-3:fingerprint-1:resolved -->"
                };
                let thread = format!(
                    "{{\"value\":[{{\"id\":42,\"status\":\"{status}\",\"comments\":[{{\"id\":1,\"parentCommentId\":0,\"author\":{{\"id\":\"actor-1\"}},\"content\":\"{content}\"}}]}}]}}"
                );
                serve_json(&listener, &mut requests, &thread);
                serve_json(
                    &listener,
                    &mut requests,
                    r#"{"authenticatedUser":{"id":"actor-1"}}"#,
                );
                serve_json(&listener, &mut requests, r#"{"id":1}"#);
                serve_json(&listener, &mut requests, r#"{"id":42}"#);
            }
            serve_json(
                &listener,
                &mut requests,
                &pr_response("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            );
            serve_json(
                &listener,
                &mut requests,
                r#"[{"id":2,"sourceRefCommit":{"commitId":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}]"#,
            );
            serve_json(
                &listener,
                &mut requests,
                r#"{"changeEntries":[{"item":{"path":"/src/lib.rs"},"changeTrackingId":7}],"nextSkip":0}"#,
            );
            serve_json(
                &listener,
                &mut requests,
                r#"{"value":[{"id":99,"status":"active","comments":[{"id":5,"parentCommentId":0,"author":{"id":"reviewer-2"},"content":"forged <!-- vee:fingerprint:fingerprint-1 -->"}]}]}"#,
            );
            serve_json(
                &listener,
                &mut requests,
                r#"{"authenticatedUser":{"id":"actor-1"}}"#,
            );
            serve_json(
                &listener,
                &mut requests,
                &pr_response("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            );
            serve_json(&listener, &mut requests, r#"{"id":43}"#);
            requests
        });
        let host = format!("127.0.0.1:{}", address.port());
        let adapter = AzureDevOpsAdapter::new(
            AzureDevOpsConfig::new(&format!("http://{host}/"), "pat-secret".into()).unwrap(),
        )
        .unwrap();
        let reference = pr_reference(&host);
        let thread = ReviewThread {
            pull_request: reference.clone(),
            fingerprint: "fingerprint-1".into(),
            path: "src/lib.rs".into(),
            line: 12,
            side: crate::DiffSide::New,
            body: "Potential defect on this added line".into(),
            resolution: ThreadResolution::Open,
            snapshot_id: "sha256:snapshot".into(),
            idempotency_key: "review-1:fingerprint-1".into(),
        };
        let ids = adapter
            .publish_threads(
                &reference,
                &format!(
                    "{}:{}",
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                ),
                &[thread],
            )
            .unwrap();
        assert_eq!(ids.get("fingerprint-1").map(String::as_str), Some("42"));
        let retry_ids = adapter
            .publish_threads(
                &reference,
                &format!(
                    "{}:{}",
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                ),
                &[ReviewThread {
                    pull_request: reference.clone(),
                    fingerprint: "fingerprint-1".into(),
                    path: "src/lib.rs".into(),
                    line: 12,
                    side: crate::DiffSide::New,
                    body: "Potential defect on this added line".into(),
                    resolution: ThreadResolution::Open,
                    snapshot_id: "sha256:snapshot".into(),
                    idempotency_key: "review-2:fingerprint-1".into(),
                }],
            )
            .unwrap();
        assert_eq!(retry_ids, ids);
        let resolved_ids = adapter
            .publish_threads(
                &reference,
                &format!(
                    "{}:{}",
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                ),
                &[ReviewThread {
                    pull_request: reference.clone(),
                    fingerprint: "fingerprint-1".into(),
                    path: "src/lib.rs".into(),
                    line: 12,
                    side: crate::DiffSide::New,
                    body: "Resolved locally".into(),
                    resolution: ThreadResolution::Resolved,
                    snapshot_id: "sha256:snapshot".into(),
                    idempotency_key: "review-3:fingerprint-1:resolved".into(),
                }],
            )
            .unwrap();
        assert_eq!(
            resolved_ids.get("fingerprint-1").map(String::as_str),
            Some("42")
        );
        let reopened_ids = adapter
            .publish_threads(
                &reference,
                &format!(
                    "{}:{}",
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                ),
                &[ReviewThread {
                    pull_request: reference.clone(),
                    fingerprint: "fingerprint-1".into(),
                    path: "src/lib.rs".into(),
                    line: 12,
                    side: crate::DiffSide::New,
                    body: "The issue recurred".into(),
                    resolution: ThreadResolution::Open,
                    snapshot_id: "sha256:snapshot-2".into(),
                    idempotency_key: "review-4:fingerprint-1".into(),
                }],
            )
            .unwrap();
        assert_eq!(
            reopened_ids.get("fingerprint-1").map(String::as_str),
            Some("42")
        );
        let safe_duplicate = adapter
            .publish_threads(
                &reference,
                &format!(
                    "{}:{}",
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                ),
                &[ReviewThread {
                    pull_request: reference.clone(),
                    fingerprint: "fingerprint-1".into(),
                    path: "src/lib.rs".into(),
                    line: 12,
                    side: crate::DiffSide::New,
                    body: "The issue recurred".into(),
                    resolution: ThreadResolution::Open,
                    snapshot_id: "sha256:snapshot-3".into(),
                    idempotency_key: "review-5:fingerprint-1".into(),
                }],
            )
            .unwrap();
        assert_eq!(
            safe_duplicate.get("fingerprint-1").map(String::as_str),
            Some("43")
        );
        let requests = worker.join().unwrap();
        assert!(requests[6].starts_with("POST "));
        assert!(requests[6].contains("\"changeTrackingId\":7"));
        assert!(requests[6].contains("\"secondComparingIteration\":2"));
        assert!(requests[6].contains("\"filePath\":\"/src/lib.rs\""));
        assert!(requests[6].contains("<!-- vee:fingerprint:fingerprint-1 -->"));
        assert!(requests[12].starts_with("PATCH "));
        assert!(requests[12].contains("threads/42/comments/1"));
        assert!(requests[12].contains("<!-- vee:review-2:fingerprint-1 -->"));
        assert!(requests
            .iter()
            .any(|request| request.starts_with("PATCH ") && request.contains("\"status\":2")));
        assert!(requests
            .iter()
            .any(|request| request.starts_with("PATCH ") && request.contains("\"status\":1")));
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.starts_with("POST "))
                .count(),
            2,
            "a reviewer-authored comment with a Vee marker must not be mutated"
        );
        assert_eq!(
            requests.len(),
            34,
            "later reviews should refresh, resolve, reopen one owned thread, and ignore a reviewer-owned marker"
        );
    }

    #[test]
    fn azure_devops_work_item_is_digest_bound_and_uses_basic_pat_auth() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 1024];
            loop {
                let read = stream.read(&mut buffer).unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let text = String::from_utf8_lossy(&request).to_ascii_lowercase();
            assert!(text.starts_with("get /acme/platform/_apis/wit/workitems/42?api-version=7.1"));
            assert!(text.contains("authorization: basic "));
            let body = serde_json::json!({
                "id": 42,
                "fields": {
                    "System.Title": "Harden API",
                    "System.Description": "Review untrusted text",
                    "Microsoft.VSTS.Common.AcceptanceCriteria": "<ul><li>Reject unsafe input</li><li>Keep API stable &amp; documented</li></ul>",
                    "System.State": "Active",
                    "System.ChangedDate": "2026-11-14T12:00:00Z",
                    "System.Tags": "security; api"
                },
                "_links": { "html": { "href": "https://dev.azure.com/acme/platform/_workitems/edit/42" } }
            }).to_string();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
            stream.flush().unwrap();
        });
        let host = format!("127.0.0.1:{}", address.port());
        let adapter = AzureDevOpsAdapter::new(
            AzureDevOpsConfig::new(&format!("http://{host}/"), "pat-secret".into()).unwrap(),
        )
        .unwrap();
        let snapshot = adapter.get_work_item(&reference(&host)).unwrap();
        assert_eq!(snapshot.provider, "azure-devops");
        assert_eq!(snapshot.title, "Harden API");
        assert_eq!(
            snapshot.acceptance_criteria.as_deref(),
            Some("<ul><li>Reject unsafe input</li><li>Keep API stable &amp; documented</li></ul>")
        );
        assert_eq!(snapshot.labels, vec!["security", "api"]);
        assert_eq!(
            snapshot.url,
            "https://dev.azure.com/acme/platform/_workitems/edit/42"
        );
        assert_eq!(snapshot.content_digest, crate::work_item_digest(&snapshot));
        worker.join().unwrap();
    }

    #[test]
    fn azure_devops_rejects_host_mismatch_and_ambiguous_project_identity() {
        let adapter = AzureDevOpsAdapter::new(
            AzureDevOpsConfig::new("https://dev.azure.com/", "token".into()).unwrap(),
        )
        .unwrap();
        assert!(adapter.work_item_url(&reference("other.example")).is_err());
        let mut invalid = reference("dev.azure.com");
        invalid.repository.full_name = "acme/team/platform".into();
        assert!(adapter.work_item_url(&invalid).is_err());
    }
}
