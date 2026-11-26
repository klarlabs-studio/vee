//! Issue trackers that hold work items but not code: Jira and Linear
//! (ADR 0033).
//!
//! A work item `KEY-123` is the reference `{repository: KEY, number: 123}`
//! on the tracker's host. Snapshots are bounded and digest-bound like every
//! work item, and their text is untrusted.

use crate::{work_item_digest, HostingError, WorkItemProvider, WorkItemRef, WorkItemSnapshot};
use base64::{engine::general_purpose::STANDARD, Engine};
use reqwest::{blocking::Client, header, StatusCode, Url};
use serde_json::Value;
use std::io::Read;
use std::time::Duration;

const MAX_RESPONSE_BYTES: u64 = 1_048_576;
const MAX_TEXT_BYTES: usize = 131_072;
const MAX_LABELS: usize = 100;

/// The key a tracker shows, such as `PROJ-123`.
pub fn tracker_key(reference: &WorkItemRef) -> String {
    format!("{}-{}", reference.repository.full_name, reference.number)
}

/// Parse `PROJ-123` into the project or team key and the number.
pub fn parse_tracker_key(key: &str) -> Option<(String, u64)> {
    let (project, number) = key.trim().rsplit_once('-')?;
    let valid_project = !project.is_empty()
        && project.len() <= 64
        && project
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && project.as_bytes()[0].is_ascii_alphabetic();
    let number = number.parse::<u64>().ok().filter(|number| *number > 0)?;
    valid_project.then(|| (project.to_owned(), number))
}

fn checked_api_base(api_base: &str, what: &str) -> Result<Url, String> {
    let url = Url::parse(api_base).map_err(|error| format!("{what} API URL: {error}"))?;
    let loopback = matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
    if !(url.scheme() == "https" || url.scheme() == "http" && loopback)
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(format!(
            "{what} API URL must use HTTPS (HTTP only on loopback) without credentials, a query or a fragment"
        ));
    }
    Ok(url)
}

fn client() -> Result<Client, String> {
    Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| error.to_string())
}

fn bounded_json(response: reqwest::blocking::Response, what: &str) -> Result<Value, HostingError> {
    match response.status() {
        StatusCode::OK => {}
        StatusCode::NOT_FOUND => return Err(HostingError::NotFound),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => return Err(HostingError::Unauthorized),
        StatusCode::TOO_MANY_REQUESTS => {
            return Err(HostingError::RateLimited {
                retry_after_seconds: response
                    .headers()
                    .get(header::RETRY_AFTER)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse().ok()),
            })
        }
        status => {
            return Err(HostingError::Transport(format!(
                "{what} returned HTTP {status}"
            )))
        }
    }
    let mut bytes = Vec::new();
    response
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| HostingError::InvalidResponse(format!("reading {what}: {error}")))?;
    if bytes.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(HostingError::InvalidResponse(format!(
            "{what} response exceeds the {MAX_RESPONSE_BYTES}-byte limit"
        )));
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| HostingError::InvalidResponse(format!("invalid {what} JSON: {error}")))
}

/// Text cut to the snapshot's bound, on a character boundary.
fn bounded_text(text: &str) -> String {
    if text.len() <= MAX_TEXT_BYTES {
        return text.to_owned();
    }
    let mut end = MAX_TEXT_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

#[allow(clippy::too_many_arguments)]
fn snapshot(
    provider: &str,
    api_base: &Url,
    reference: &WorkItemRef,
    title: String,
    body: Option<String>,
    acceptance_criteria: Option<String>,
    url: String,
    state: String,
    updated_at: String,
    mut labels: Vec<String>,
) -> Result<WorkItemSnapshot, HostingError> {
    labels.sort();
    labels.dedup();
    labels.truncate(MAX_LABELS);
    let mut snapshot = WorkItemSnapshot {
        schema_version: 1,
        reference: reference.clone(),
        provider: provider.into(),
        api_base: api_base.to_string(),
        title,
        body: body
            .filter(|body| !body.trim().is_empty())
            .map(|body| bounded_text(&body)),
        acceptance_criteria: acceptance_criteria
            .filter(|criteria| !criteria.trim().is_empty())
            .map(|criteria| bounded_text(&criteria)),
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

/// Jira Cloud (email and API token) or Data Center (personal access token).
pub struct JiraAdapter {
    api_base: Url,
    authorization: String,
    acceptance_field: Option<String>,
    client: Client,
}

impl JiraAdapter {
    /// `email` selects Jira Cloud basic auth; without it, `token` is a Data
    /// Center personal access token.
    pub fn new(
        api_base: &str,
        token: &str,
        email: Option<&str>,
        acceptance_field: Option<String>,
    ) -> Result<Self, String> {
        if token.trim().is_empty() {
            return Err("the Jira token is empty".into());
        }
        let authorization = match email.filter(|email| !email.trim().is_empty()) {
            Some(email) => format!("Basic {}", STANDARD.encode(format!("{email}:{token}"))),
            None => format!("Bearer {token}"),
        };
        Ok(Self {
            api_base: checked_api_base(api_base, "Jira")?,
            authorization,
            acceptance_field,
            client: client()?,
        })
    }
}

/// Jira text fields are wiki markup in API v2, or Atlassian Document Format
/// objects for some custom fields; only plain strings are kept.
fn jira_text(value: Option<&Value>) -> Option<String> {
    value.and_then(Value::as_str).map(str::to_owned)
}

impl WorkItemProvider for JiraAdapter {
    fn work_item_provider_id(&self) -> &'static str {
        "jira"
    }

    fn get_work_item(&self, reference: &WorkItemRef) -> Result<WorkItemSnapshot, HostingError> {
        reference
            .validate()
            .map_err(HostingError::InvalidResponse)?;
        let api_host = self.api_base.host_str().unwrap_or_default();
        if !reference.repository.host.eq_ignore_ascii_case(api_host) {
            return Err(HostingError::InvalidResponse(
                "work item host does not match the configured Jira API".into(),
            ));
        }
        let key = tracker_key(reference);
        if parse_tracker_key(&key).is_none() {
            return Err(HostingError::InvalidResponse(format!(
                "`{key}` is not a Jira issue key"
            )));
        }
        let mut fields = vec!["summary", "description", "status", "updated", "labels"];
        if let Some(field) = &self.acceptance_field {
            fields.push(field);
        }
        let mut url = self.api_base.clone();
        let prefix = url.path().trim_end_matches('/').to_owned();
        url.set_path(&format!("{prefix}/rest/api/2/issue/{key}"));
        url.query_pairs_mut()
            .append_pair("fields", &fields.join(","));
        let response = self
            .client
            .get(url)
            .header(header::AUTHORIZATION, &self.authorization)
            .header(header::ACCEPT, "application/json")
            .send()
            .map_err(|error| HostingError::Transport(format!("requesting Jira issue: {error}")))?;
        let issue = bounded_json(response, "Jira")?;
        if issue.get("key").and_then(Value::as_str) != Some(key.as_str()) {
            // A moved issue answers with its new key; that is another item.
            return Err(HostingError::InvalidResponse(format!(
                "Jira answered for another issue than {key}"
            )));
        }
        let field = |name: &str| issue.pointer(&format!("/fields/{name}"));
        let title = jira_text(field("summary"))
            .filter(|title| !title.trim().is_empty())
            .ok_or_else(|| HostingError::InvalidResponse("the Jira issue has no summary".into()))?;
        let state = field("status")
            .and_then(|status| status.get("name"))
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_owned();
        let updated_at = jira_text(field("updated")).ok_or_else(|| {
            HostingError::InvalidResponse("the Jira issue has no update time".into())
        })?;
        let labels = field("labels")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        let site = format!(
            "{}://{}{}",
            self.api_base.scheme(),
            reference.repository.host,
            self.api_base
                .port()
                .map(|port| format!(":{port}"))
                .unwrap_or_default()
        );
        snapshot(
            self.work_item_provider_id(),
            &self.api_base,
            reference,
            title,
            jira_text(field("description")),
            self.acceptance_field
                .as_deref()
                .and_then(|name| jira_text(field(name))),
            format!("{site}/browse/{key}"),
            state,
            updated_at,
            labels,
        )
    }
}

/// Linear, through its GraphQL API with a personal API key.
pub struct LinearAdapter {
    api_base: Url,
    token: String,
    client: Client,
}

impl LinearAdapter {
    pub fn new(api_base: &str, token: &str) -> Result<Self, String> {
        if token.trim().is_empty() {
            return Err("the Linear API key is empty".into());
        }
        Ok(Self {
            api_base: checked_api_base(api_base, "Linear")?,
            token: token.to_owned(),
            client: client()?,
        })
    }
}

const LINEAR_QUERY: &str = "query VeeIssue($id: String!) { issue(id: $id) { identifier title description url updatedAt state { name } labels(first: 100) { nodes { name } } } }";

impl WorkItemProvider for LinearAdapter {
    fn work_item_provider_id(&self) -> &'static str {
        "linear"
    }

    fn get_work_item(&self, reference: &WorkItemRef) -> Result<WorkItemSnapshot, HostingError> {
        reference
            .validate()
            .map_err(HostingError::InvalidResponse)?;
        let key = tracker_key(reference);
        if parse_tracker_key(&key).is_none() {
            return Err(HostingError::InvalidResponse(format!(
                "`{key}` is not a Linear issue identifier"
            )));
        }
        let response = self
            .client
            .post(self.api_base.clone())
            .header(header::AUTHORIZATION, &self.token)
            .header(header::ACCEPT, "application/json")
            .json(&serde_json::json!({"query": LINEAR_QUERY, "variables": {"id": key}}))
            .send()
            .map_err(|error| {
                HostingError::Transport(format!("requesting Linear issue: {error}"))
            })?;
        let answer = bounded_json(response, "Linear")?;
        if let Some(message) = answer.pointer("/errors/0/message").and_then(Value::as_str) {
            return Err(if message.to_ascii_lowercase().contains("not found") {
                HostingError::NotFound
            } else {
                HostingError::InvalidResponse(format!("Linear: {message}"))
            });
        }
        let issue = answer
            .pointer("/data/issue")
            .filter(|issue| !issue.is_null())
            .ok_or(HostingError::NotFound)?;
        let text = |pointer: &str| issue.pointer(pointer).and_then(Value::as_str);
        if text("/identifier") != Some(key.as_str()) {
            return Err(HostingError::InvalidResponse(format!(
                "Linear answered for another issue than {key}"
            )));
        }
        let title = text("/title")
            .filter(|title| !title.trim().is_empty())
            .ok_or_else(|| HostingError::InvalidResponse("the Linear issue has no title".into()))?
            .to_owned();
        let url = text("/url")
            .filter(|url| url.starts_with("https://linear.app/"))
            .ok_or_else(|| {
                HostingError::InvalidResponse("the Linear issue URL is not on linear.app".into())
            })?
            .to_owned();
        let labels = issue
            .pointer("/labels/nodes")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|label| label.get("name").and_then(Value::as_str))
            .map(str::to_owned)
            .collect();
        snapshot(
            self.work_item_provider_id(),
            &self.api_base,
            reference,
            title,
            text("/description").map(str::to_owned),
            None,
            url,
            text("/state/name").unwrap_or("unknown").to_owned(),
            text("/updatedAt")
                .ok_or_else(|| {
                    HostingError::InvalidResponse("the Linear issue has no update time".into())
                })?
                .to_owned(),
            labels,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RepositoryRef;
    use std::io::Write;
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    fn serve(body: String) -> (String, Arc<Mutex<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(String::new()));
        let record = seen.clone();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = vec![0u8; 16384];
            let count = stream.read(&mut buffer).unwrap();
            *record.lock().unwrap() = String::from_utf8_lossy(&buffer[..count]).to_string();
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        });
        (format!("http://127.0.0.1:{}/", address.port()), seen)
    }

    fn reference(project: &str, number: u64) -> WorkItemRef {
        WorkItemRef {
            repository: RepositoryRef {
                host: "127.0.0.1".into(),
                full_name: project.into(),
            },
            number,
        }
    }

    #[test]
    fn keys_parse_into_a_project_and_a_number() {
        assert_eq!(parse_tracker_key("PROJ-123"), Some(("PROJ".into(), 123)));
        assert_eq!(parse_tracker_key("ENG_2-7"), Some(("ENG_2".into(), 7)));
        assert_eq!(parse_tracker_key("PROJ-0"), None);
        assert_eq!(parse_tracker_key("1PROJ-3"), None);
        assert_eq!(parse_tracker_key("../x-3"), None);
        assert_eq!(parse_tracker_key("acme/app#3"), None);
    }

    #[test]
    fn a_jira_issue_becomes_a_digest_bound_snapshot_with_its_acceptance_field() {
        let (api_base, seen) = serve(
            serde_json::json!({
                "key": "PROJ-123",
                "fields": {
                    "summary": "Cache token lookups",
                    "description": "Avoid a round trip per request.",
                    "status": {"name": "In Progress"},
                    "updated": "2026-11-26T10:00:00.000+0000",
                    "labels": ["perf", "auth", "perf"],
                    "customfield_10050": "Given a cached token, no request is made."
                }
            })
            .to_string(),
        );
        let adapter = JiraAdapter::new(
            &api_base,
            "token",
            Some("dev@example.invalid"),
            Some("customfield_10050".into()),
        )
        .unwrap();
        let item = adapter.get_work_item(&reference("PROJ", 123)).unwrap();
        assert_eq!(item.provider, "jira");
        assert_eq!(item.title, "Cache token lookups");
        assert_eq!(item.state, "In Progress");
        assert_eq!(item.labels, ["auth", "perf"]);
        assert_eq!(
            item.acceptance_criteria.as_deref(),
            Some("Given a cached token, no request is made.")
        );
        assert!(item.url.ends_with("/browse/PROJ-123"));
        assert!(item.validate().is_ok());
        let request = seen.lock().unwrap().clone();
        assert!(
            request.starts_with("GET /rest/api/2/issue/PROJ-123?fields="),
            "{request}"
        );
        assert!(request.contains("customfield_10050"));
        assert!(request
            .to_ascii_lowercase()
            .contains("authorization: basic "));
    }

    #[test]
    fn jira_refuses_an_answer_for_another_issue() {
        let (api_base, _) = serve(
            serde_json::json!({"key": "OTHER-1", "fields": {"summary": "x", "updated": "t"}})
                .to_string(),
        );
        let adapter = JiraAdapter::new(&api_base, "pat", None, None).unwrap();
        assert!(matches!(
            adapter.get_work_item(&reference("PROJ", 123)),
            Err(HostingError::InvalidResponse(message)) if message.contains("another issue")
        ));
    }

    #[test]
    fn a_linear_issue_is_read_by_identifier() {
        let (api_base, seen) = serve(
            serde_json::json!({"data": {"issue": {
                "identifier": "ENG-42",
                "title": "Retry failed webhooks",
                "description": "## Acceptance criteria\n- Retries three times",
                "url": "https://linear.app/acme/issue/ENG-42/retry",
                "updatedAt": "2026-11-26T10:00:00.000Z",
                "state": {"name": "Todo"},
                "labels": {"nodes": [{"name": "backend"}]}
            }}})
            .to_string(),
        );
        let adapter = LinearAdapter::new(&api_base, "lin_api_key").unwrap();
        let item = adapter.get_work_item(&reference("ENG", 42)).unwrap();
        assert_eq!(item.provider, "linear");
        assert_eq!(item.state, "Todo");
        assert_eq!(item.labels, ["backend"]);
        assert!(item
            .body
            .as_deref()
            .unwrap()
            .contains("Acceptance criteria"));
        let request = seen.lock().unwrap().clone();
        assert!(request.starts_with("POST / "), "{request}");
        assert!(request.contains("\"id\":\"ENG-42\""), "{request}");

        let (api_base, _) = serve(
            serde_json::json!({"data": {"issue": {"identifier": "ENG-42", "title": "x", "url": "https://evil.example/x", "updatedAt": "t"}}})
                .to_string(),
        );
        let adapter = LinearAdapter::new(&api_base, "lin_api_key").unwrap();
        assert!(adapter.get_work_item(&reference("ENG", 42)).is_err());
    }
}
