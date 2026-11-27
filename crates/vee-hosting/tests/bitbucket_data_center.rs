//! The Bitbucket Data Center adapter against a fake server that keeps pull
//! request state (comments, build statuses, participants) across requests,
//! so republishing can be checked for duplicates. Each fake server stops
//! when its test ends.

use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
};
use vee_hosting::{
    bitbucket_data_center::{BitbucketDataCenterAdapter, BitbucketDataCenterConfig},
    CheckConclusion, CheckRun, CheckStatus, DiffSide, FileChange, GitHostingProvider, HostingError,
    PullRequestApprovalProvider, PullRequestContextProvider, PullRequestRef,
    PullRequestReviewIssuesProvider, PullRequestState, RepositoryRef, ReviewPublication,
    ReviewThread, ThreadResolution,
};

const HEAD: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const BASE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const PR_PATH: &str = "/rest/api/1.0/projects/PROJ/repos/service/pull-requests/7";
const BOT: &str = "vee-bot";

struct Reply {
    status: &'static str,
    headers: Vec<(&'static str, String)>,
    body: String,
}

fn ok(body: Value) -> Reply {
    Reply {
        status: "200 OK",
        headers: Vec::new(),
        body: body.to_string(),
    }
}

fn status(status: &'static str) -> Reply {
    Reply {
        status,
        headers: Vec::new(),
        body: String::new(),
    }
}

/// What the fake server knows about pull request 7.
#[derive(Default)]
struct Server {
    head: String,
    version: u64,
    state: String,
    comments: Vec<Value>,
    builds: BTreeMap<String, Value>,
    /// Participant name to (slug, status).
    participants: BTreeMap<String, (String, String)>,
    diff: String,
    /// Responses name no user, as for an anonymous request.
    anonymous: bool,
}

impl Server {
    fn new() -> Self {
        Self {
            head: HEAD.into(),
            version: 3,
            state: "OPEN".into(),
            diff: "diff --git src://src/lib.rs dst://src/lib.rs\nindex 1..2 100644\n--- src://src/lib.rs\n+++ dst://src/lib.rs\n@@ -1,2 +1,3 @@\n fn a() {}\n+fn b() {}\n+fn c() {}\n".into(),
            ..Self::default()
        }
    }

    fn pull_request(&self) -> Value {
        let participants = self
            .participants
            .iter()
            .map(|(name, (slug, status))| {
                json!({
                    "user": {"name": name, "slug": slug},
                    "role": "PARTICIPANT",
                    "approved": status == "APPROVED",
                    "status": status,
                })
            })
            .collect::<Vec<_>>();
        json!({
            "id": 7, "version": self.version, "title": "Improve validation",
            "description": "Details", "state": self.state,
            "fromRef": {"id": "refs/heads/feature", "latestCommit": self.head},
            "toRef": {"id": "refs/heads/main", "latestCommit": BASE},
            "reviewers": [], "participants": participants,
        })
    }

    fn activities(&self) -> Value {
        let values = self
            .comments
            .iter()
            .rev()
            .map(|comment| {
                json!({
                    "action": "COMMENTED", "commentAction": "ADDED",
                    "comment": comment, "commentAnchor": comment.get("anchor"),
                })
            })
            .collect::<Vec<_>>();
        json!({"values": values, "isLastPage": true})
    }

    fn add_comment(&mut self, body: &Value) -> Reply {
        let id = 100 + self.comments.len() as u64;
        let mut comment = json!({
            "id": id, "version": 0, "text": body["text"],
            "author": {"name": BOT, "slug": BOT},
            "createdDate": 1_795_780_800_000_i64, "threadResolved": false,
        });
        if let Some(anchor) = body.get("anchor") {
            comment["anchor"] = anchor.clone();
        }
        self.comments.push(comment.clone());
        Reply {
            status: "201 Created",
            headers: Vec::new(),
            body: comment.to_string(),
        }
    }

    fn update_comment(&mut self, id: u64, body: &Value) -> Reply {
        let Some(comment) = self.comments.iter_mut().find(|comment| comment["id"] == id) else {
            return status("404 Not Found");
        };
        if body["version"] != comment["version"] {
            return status("409 Conflict");
        }
        if let Some(text) = body.get("text") {
            if comment["threadResolved"] == true {
                return status("409 Conflict");
            }
            comment["text"] = text.clone();
        }
        if let Some(resolved) = body.get("threadResolved") {
            comment["threadResolved"] = resolved.clone();
        }
        comment["version"] = json!(comment["version"].as_u64().unwrap() + 1);
        ok(comment.clone())
    }

    fn handle(&mut self, line: &str, body: &str) -> Reply {
        let (method, target) = line
            .split_once(' ')
            .map(|(method, rest)| (method, rest.split(' ').next().unwrap_or_default()))
            .unwrap_or_default();
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        let body: Value = serde_json::from_str(body).unwrap_or(Value::Null);
        match (method, path) {
            ("GET", "/rest/api/1.0/application-properties") => Reply {
                status: "200 OK",
                headers: if self.anonymous {
                    Vec::new()
                } else {
                    vec![("X-AUSERNAME", BOT.into())]
                },
                body: json!({"version": "9.4.0"}).to_string(),
            },
            ("GET", "/rest/api/1.0/users") => ok(json!({
                "values": [{"name": "vee-bot-two", "slug": "vee-bot-two"}, {"name": BOT, "slug": BOT}],
                "isLastPage": true,
            })),
            ("GET", PR_PATH) => ok(self.pull_request()),
            ("GET", path) if path == format!("{PR_PATH}/activities") => ok(self.activities()),
            ("GET", path) if path == format!("{PR_PATH}/changes") => ok(json!({
                "values": [
                    {"path": {"toString": "src/lib.rs"}, "type": "MODIFY"},
                    {"path": {"toString": "src/new.rs"}, "srcPath": {"toString": "src/old.rs"}, "type": "MOVE"},
                ],
                "isLastPage": true,
            })),
            ("GET", path) if path == format!("{PR_PATH}.diff") => Reply {
                status: "200 OK",
                headers: vec![("Content-Type", "text/plain".into())],
                body: self.diff.clone(),
            },
            ("POST", path) if path == format!("{PR_PATH}/comments") => self.add_comment(&body),
            ("PUT", path) if path.starts_with(&format!("{PR_PATH}/comments/")) => {
                let id = path.rsplit('/').next().unwrap().parse().unwrap();
                self.update_comment(id, &body)
            }
            ("POST", path)
                if path.starts_with("/rest/api/1.0/projects/PROJ/repos/service/commits/") =>
            {
                self.builds
                    .insert(body["key"].as_str().unwrap().to_owned(), body.clone());
                status("204 No Content")
            }
            ("PUT", path) if path.starts_with(&format!("{PR_PATH}/participants/")) => {
                if !query.is_empty() && query != format!("version={}", self.version) {
                    return status("409 Conflict");
                }
                let slug = path.rsplit('/').next().unwrap().to_owned();
                let name = body["user"]["name"].as_str().unwrap().to_owned();
                let state = body["status"].as_str().unwrap().to_owned();
                self.participants.insert(name, (slug, state.clone()));
                ok(json!({"user": {"name": BOT, "slug": BOT}, "status": state}))
            }
            _ => status("404 Not Found"),
        }
    }
}

/// A fake server on loopback; it stops and joins its thread when dropped.
struct FakeHost {
    address: SocketAddr,
    server: Arc<Mutex<Server>>,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl FakeHost {
    fn start(server: Server) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = Arc::new(Mutex::new(server));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let worker = {
            let (server, requests, stop) = (server.clone(), requests.clone(), stop.clone());
            thread::spawn(move || {
                for stream in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(mut stream) = stream else { continue };
                    let request = read_request(&mut stream);
                    let line = request.lines().next().unwrap_or_default().to_owned();
                    let body = request.split_once("\r\n\r\n").map_or("", |(_, body)| body);
                    let reply = server.lock().unwrap().handle(&line, body);
                    requests.lock().unwrap().push(request.clone());
                    let mut response = format!(
                        "HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\n",
                        reply.status,
                        reply.body.len()
                    );
                    if !reply
                        .headers
                        .iter()
                        .any(|(name, _)| *name == "Content-Type")
                    {
                        response.push_str("Content-Type: application/json\r\n");
                    }
                    for (name, value) in &reply.headers {
                        response.push_str(&format!("{name}: {value}\r\n"));
                    }
                    response.push_str("\r\n");
                    response.push_str(&reply.body);
                    let _ = stream.write_all(response.as_bytes());
                    let _ = stream.flush();
                }
            })
        };
        Self {
            address,
            server,
            requests,
            stop,
            worker: Some(worker),
        }
    }

    fn adapter(&self) -> BitbucketDataCenterAdapter {
        self.adapter_with_secret("")
    }

    fn adapter_with_secret(&self, secret: &str) -> BitbucketDataCenterAdapter {
        BitbucketDataCenterAdapter::new(
            BitbucketDataCenterConfig::new(&format!("http://{}/", self.address), "token".into())
                .unwrap()
                .with_webhook_secret(secret.into()),
        )
        .unwrap()
    }

    fn reference(&self) -> PullRequestRef {
        PullRequestRef {
            repository: RepositoryRef {
                host: "127.0.0.1".into(),
                full_name: "PROJ/service".into(),
            },
            number: 7,
        }
    }

    fn lines(&self) -> Vec<String> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .map(|request| request.lines().next().unwrap_or_default().to_owned())
            .collect()
    }

    fn writes(&self) -> Vec<String> {
        self.lines()
            .into_iter()
            .filter(|line| !line.starts_with("GET "))
            .collect()
    }

    fn clear(&self) {
        self.requests.lock().unwrap().clear();
    }
}

impl Drop for FakeHost {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the accept loop so it sees the stop flag.
        let _ = TcpStream::connect(self.address);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn read_request(stream: &mut TcpStream) -> String {
    let mut request = Vec::new();
    let mut buffer = [0u8; 4096];
    while let Ok(read) = stream.read(&mut buffer) {
        request.extend_from_slice(&buffer[..read]);
        let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
            if read == 0 {
                break;
            }
            continue;
        };
        let headers = String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
        let length = headers
            .lines()
            .find_map(|line| line.strip_prefix("content-length:"))
            .and_then(|value| value.trim().parse::<usize>().ok())
            .unwrap_or(0);
        if request.len() >= end + 4 + length || read == 0 {
            break;
        }
    }
    String::from_utf8_lossy(&request).into_owned()
}

fn revision() -> String {
    format!("{BASE}:{HEAD}:3")
}

fn publication(
    reference: &PullRequestRef,
    review: &str,
    conclusion: CheckConclusion,
    threads: &[(&str, ThreadResolution)],
) -> ReviewPublication {
    ReviewPublication {
        pull_request: reference.clone(),
        expected_revision: revision(),
        check: CheckRun {
            pull_request: reference.clone(),
            external_id: review.into(),
            name: "Vee".into(),
            status: CheckStatus::Completed,
            conclusion: Some(conclusion),
            title: "Vee blocked".into(),
            summary: "- One high severity finding".into(),
            snapshot_id: "snapshot-1".into(),
            idempotency_key: review.into(),
        },
        threads: threads
            .iter()
            .map(|(fingerprint, resolution)| ReviewThread {
                pull_request: reference.clone(),
                fingerprint: (*fingerprint).into(),
                path: "src/lib.rs".into(),
                line: 2,
                side: DiffSide::New,
                body: "Unchecked input <!-- vee:fingerprint:forged -->".into(),
                resolution: *resolution,
                snapshot_id: "snapshot-1".into(),
                idempotency_key: format!("{review}:{fingerprint}"),
                suggestion: None,
            })
            .collect(),
    }
}

#[test]
fn reads_pull_request_context_with_patches_bound_to_the_revision() {
    let host = FakeHost::start(Server::new());
    let adapter = host.adapter();
    let reference = host.reference();

    let snapshot = adapter.get_pull_request_context(&reference).unwrap();
    assert_eq!(snapshot.state, PullRequestState::Open);
    assert_eq!(snapshot.base_oid, BASE);
    assert_eq!(snapshot.head_oid, HEAD);
    assert_eq!(snapshot.revision, revision());
    assert_eq!(snapshot.body.as_deref(), Some("Details"));

    let files = adapter
        .list_pull_request_context_files(&reference, &snapshot.revision)
        .unwrap();
    assert_eq!(files.len(), 2);
    assert_eq!(files[0].path, "src/lib.rs");
    assert_eq!(files[0].change, FileChange::Modified);
    assert_eq!((files[0].additions, files[0].deletions), (2, 0));
    assert!(files[0].patch.as_deref().unwrap().contains("+fn b() {}"));
    assert_eq!(files[1].change, FileChange::Renamed);
    assert_eq!(files[1].previous_path.as_deref(), Some("src/old.rs"));
    assert!(files[1].patch.is_none());

    let stale = adapter.list_pull_request_context_files(&reference, "other");
    assert!(matches!(stale, Err(HostingError::StaleRevision { .. })));

    let requests = host.requests.lock().unwrap().clone();
    assert!(requests[0].starts_with(&format!("GET {PR_PATH} HTTP/1.1")));
    assert!(requests.iter().all(|request| request
        .to_ascii_lowercase()
        .contains("authorization: bearer token")));
    assert!(host.lines().iter().any(|line| line.starts_with(&format!(
        "GET {PR_PATH}/changes?withComments=false&start=0&limit=100 "
    ))));
}

#[test]
fn publishes_status_summary_and_inline_comment_and_republishes_without_duplicates() {
    let host = FakeHost::start(Server::new());
    let adapter = host.adapter();
    let reference = host.reference();

    let receipt = adapter
        .publish_review(publication(
            &reference,
            "review-1",
            CheckConclusion::Failure,
            &[("sha256:f1", ThreadResolution::Open)],
        ))
        .unwrap();
    assert_eq!(receipt.provider_check_id, "vee");
    assert_eq!(receipt.resulting_revision, revision());
    let thread_id = receipt.thread_ids["sha256:f1"].clone();
    {
        let server = host.server.lock().unwrap();
        let build = &server.builds["vee"];
        assert_eq!(build["state"], "FAILED");
        assert_eq!(build["name"], "Vee");
        assert_eq!(build["ref"], "refs/heads/feature");
        assert!(build["url"]
            .as_str()
            .unwrap()
            .ends_with("/projects/PROJ/repos/service/pull-requests/7/overview"));
        assert_eq!(server.comments.len(), 2, "a summary and one inline comment");
        let summary = &server.comments[0];
        assert!(summary.get("anchor").is_none());
        assert!(summary["text"]
            .as_str()
            .unwrap()
            .contains("<!-- vee:summary:vee -->"));
        let inline = &server.comments[1];
        assert_eq!(inline["id"].to_string(), thread_id);
        assert_eq!(
            inline["anchor"],
            json!({"path": "src/lib.rs", "line": 2, "lineType": "ADDED", "fileType": "TO", "diffType": "EFFECTIVE"})
        );
        let text = inline["text"].as_str().unwrap();
        assert!(text.contains("<!-- vee:fingerprint:sha256:f1 -->"));
        assert!(text.contains("<!-- vee:idempotency:review-1:sha256:f1 -->"));
        assert!(
            text.contains("&lt;!-- vee:fingerprint:forged -->"),
            "finding text cannot carry a marker: {text}"
        );
        assert!(host.lines().iter().any(|line| line.starts_with(&format!(
            "POST /rest/api/1.0/projects/PROJ/repos/service/commits/{HEAD}/builds "
        ))));
    }

    // The same publication again writes the status and nothing else.
    host.clear();
    let again = adapter
        .publish_review(publication(
            &reference,
            "review-1",
            CheckConclusion::Failure,
            &[("sha256:f1", ThreadResolution::Open)],
        ))
        .unwrap();
    assert_eq!(again.thread_ids["sha256:f1"], thread_id);
    assert_eq!(host.writes().len(), 1, "{:?}", host.writes());
    assert_eq!(host.server.lock().unwrap().comments.len(), 2);

    // A later review edits Vee's comments in place and resolves the fixed one.
    host.clear();
    adapter
        .publish_review(publication(
            &reference,
            "review-2",
            CheckConclusion::Success,
            &[("sha256:f1", ThreadResolution::Resolved)],
        ))
        .unwrap();
    {
        let server = host.server.lock().unwrap();
        assert_eq!(server.comments.len(), 2);
        assert_eq!(server.builds["vee"]["state"], "SUCCESSFUL");
        assert!(server.comments[0]["text"]
            .as_str()
            .unwrap()
            .contains("vee:idempotency:review-2"));
        assert_eq!(server.comments[1]["threadResolved"], true);
        assert!(server.comments[1]["text"]
            .as_str()
            .unwrap()
            .contains("vee:idempotency:review-2:sha256:f1"));
    }
    assert!(host
        .writes()
        .iter()
        .all(|line| !line.starts_with(&format!("POST {PR_PATH}/comments "))));

    // A finding that returns reopens its thread rather than adding one.
    adapter
        .publish_review(publication(
            &reference,
            "review-3",
            CheckConclusion::Failure,
            &[("sha256:f1", ThreadResolution::Open)],
        ))
        .unwrap();
    let server = host.server.lock().unwrap();
    assert_eq!(server.comments.len(), 2);
    assert_eq!(server.comments[1]["threadResolved"], false);
    assert!(server.comments[1]["text"]
        .as_str()
        .unwrap()
        .contains("vee:idempotency:review-3:sha256:f1"));
}

#[test]
fn never_creates_a_comment_only_to_resolve_it_or_adopts_someone_elses() {
    let mut server = Server::new();
    server.comments.push(json!({
        "id": 50, "version": 0, "author": {"name": "reviewer", "slug": "reviewer"},
        "text": "copied <!-- vee:fingerprint:sha256:f1 -->", "threadResolved": false,
        "anchor": {"path": "src/lib.rs", "line": 2, "lineType": "ADDED", "fileType": "TO"},
    }));
    let host = FakeHost::start(server);
    let adapter = host.adapter();
    let reference = host.reference();

    let receipt = adapter
        .publish_review(publication(
            &reference,
            "review-1",
            CheckConclusion::Success,
            &[
                ("sha256:gone", ThreadResolution::Resolved),
                ("sha256:f1", ThreadResolution::Open),
            ],
        ))
        .unwrap();
    assert!(!receipt.thread_ids.contains_key("sha256:gone"));
    assert_ne!(receipt.thread_ids["sha256:f1"], "50");
    let server = host.server.lock().unwrap();
    assert_eq!(
        server.comments.len(),
        3,
        "the reviewer's comment and Vee's two"
    );
    assert_eq!(
        server.comments[0]["version"], 0,
        "the reviewer's comment is untouched"
    );
}

#[test]
fn refuses_to_publish_a_stale_or_closed_pull_request() {
    let host = FakeHost::start(Server::new());
    let adapter = host.adapter();
    let reference = host.reference();
    let mut stale = publication(&reference, "review-1", CheckConclusion::Success, &[]);
    stale.expected_revision = format!("{BASE}:{HEAD}:2");
    assert!(matches!(
        adapter.publish_review(stale),
        Err(HostingError::StaleRevision { .. })
    ));
    host.server.lock().unwrap().state = "DECLINED".into();
    assert!(adapter
        .publish_review(publication(
            &reference,
            "review-1",
            CheckConclusion::Success,
            &[]
        ))
        .is_err());
    assert!(host.writes().is_empty());
}

#[test]
fn reads_review_issues_back_including_replies_as_untrusted_context() {
    let mut server = Server::new();
    server.comments.push(json!({
        "id": 81, "version": 1, "text": "Check this branch",
        "author": {"name": "reviewer", "slug": "reviewer"},
        "createdDate": 1_795_780_800_000_i64, "updatedDate": 1_795_780_860_000_i64,
        "anchor": {"path": "src/lib.rs", "line": 14, "lineType": "ADDED", "fileType": "TO"},
        "comments": [{"id": 82, "version": 0, "text": "Agreed", "author": {"name": BOT, "slug": BOT}}],
    }));
    server.comments.push(json!({
        "id": 90, "version": 0, "text": "Removed line", "author": {"name": "reviewer"},
        "anchor": {"path": "src/lib.rs", "line": 3, "lineType": "REMOVED", "fileType": "FROM"},
    }));
    let host = FakeHost::start(server);
    let adapter = host.adapter();
    let report = adapter
        .list_pull_request_review_issues(&host.reference())
        .unwrap();
    assert!(report.complete);
    assert!(!report.gate_eligible);
    assert_eq!(report.provider, "bitbucket-data-center");
    assert_eq!(report.revision, revision());
    let ids = report
        .issues
        .iter()
        .map(|issue| issue.external_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(ids, ["81", "82", "90"]);
    let first = &report.issues[0];
    assert_eq!(first.author.as_deref(), Some("reviewer"));
    assert_eq!(first.path.as_deref(), Some("src/lib.rs"));
    assert_eq!(first.line, Some(14));
    assert_eq!(first.side, Some(DiffSide::New));
    assert_eq!(first.created_at.as_deref(), Some("2026-11-27T12:00:00Z"));
    assert_eq!(first.updated_at.as_deref(), Some("2026-11-27T12:01:00Z"));
    assert_eq!(first.classification, "untrusted_external_review");
    assert!(first
        .source_url
        .as_deref()
        .unwrap()
        .ends_with("/pull-requests/7/overview?commentId=81"));
    assert_eq!(report.issues[1].path.as_deref(), Some("src/lib.rs"));
    assert_eq!(report.issues[2].side, Some(DiffSide::Old));
    assert!(host.writes().is_empty());
}

#[test]
fn approves_the_reviewed_head_reads_it_back_and_withdraws() {
    let host = FakeHost::start(Server::new());
    let adapter = host.adapter();
    let reference = host.reference();

    assert!(!adapter.own_approval_stands(&reference).unwrap());
    adapter.approve_head(&reference, HEAD, "why").unwrap();
    assert!(adapter.own_approval_stands(&reference).unwrap());
    assert!(host
        .lines()
        .iter()
        .any(|line| line.starts_with(&format!("PUT {PR_PATH}/participants/{BOT}?version=3 "))));

    adapter.withdraw_approval(&reference, "why").unwrap();
    assert!(!adapter.own_approval_stands(&reference).unwrap());
    assert_eq!(
        host.server.lock().unwrap().participants[BOT].1,
        "UNAPPROVED"
    );
    // Nothing to withdraw: no write.
    host.clear();
    adapter.withdraw_approval(&reference, "why").unwrap();
    assert!(host.writes().is_empty());
}

#[test]
fn refuses_to_approve_a_moved_head_or_a_closed_pull_request() {
    let host = FakeHost::start(Server::new());
    let adapter = host.adapter();
    let reference = host.reference();
    host.server.lock().unwrap().head = "c".repeat(40);
    assert!(matches!(
        adapter.approve_head(&reference, HEAD, "why"),
        Err(HostingError::StaleRevision { .. })
    ));
    {
        let mut server = host.server.lock().unwrap();
        server.head = HEAD.into();
        server.state = "MERGED".into();
    }
    assert!(matches!(
        adapter.approve_head(&reference, HEAD, "why"),
        Err(HostingError::StaleRevision { .. })
    ));
    assert!(host.writes().is_empty());
}

fn sign(secret: &str, body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(body);
    let hex = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("sha256={hex}")
}

fn webhook_body(event_key: &str) -> Vec<u8> {
    json!({
        "eventKey": event_key,
        "pullRequest": {
            "id": 7,
            "fromRef": {"id": "refs/heads/feature", "latestCommit": HEAD,
                        "repository": {"slug": "service", "project": {"key": "PROJ"}}},
            "toRef": {"id": "refs/heads/main", "latestCommit": BASE,
                      "repository": {"slug": "service", "project": {"key": "PROJ"}}},
        }
    })
    .to_string()
    .into_bytes()
}

#[test]
fn verifies_signed_webhooks_and_normalizes_pull_request_events() {
    let adapter = BitbucketDataCenterAdapter::new(
        BitbucketDataCenterConfig::new("https://git.example.invalid/", "token".into())
            .unwrap()
            .with_webhook_secret("hook-secret".into()),
    )
    .unwrap();
    let headers = |event: &str, body: &[u8]| {
        BTreeMap::from([
            ("X-Hub-Signature".to_owned(), sign("hook-secret", body)),
            ("X-Event-Key".to_owned(), event.to_owned()),
            ("X-Request-Id".to_owned(), "delivery-1".to_owned()),
        ])
    };
    let body = webhook_body("pr:from_ref_updated");
    let event = adapter
        .verify_webhook(&headers("pr:from_ref_updated", &body), &body)
        .unwrap();
    assert_eq!(event.provider, "bitbucket-data-center");
    assert_eq!(event.event_id, "delivery-1");
    assert_eq!(event.event_type, "pull_request");
    assert_eq!(event.action.as_deref(), Some("synchronize"));
    assert_eq!(event.head_oid.as_deref(), Some(HEAD));
    assert_eq!(event.base_oid.as_deref(), Some(BASE));
    let pull_request = event.pull_request.unwrap();
    assert_eq!(pull_request.repository.host, "git.example.invalid");
    assert_eq!(pull_request.repository.full_name, "PROJ/service");
    assert_eq!(pull_request.number, 7);

    for (key, event_type, action) in [
        ("pr:opened", "pull_request", Some("opened")),
        ("pr:modified", "pull_request", Some("edited")),
        ("pr:merged", "pull_request", Some("closed")),
        ("pr:declined", "pull_request", Some("closed")),
        ("pr:comment:added", "pull_request_comment", None),
    ] {
        let body = webhook_body(key);
        let event = adapter.verify_webhook(&headers(key, &body), &body).unwrap();
        assert_eq!(event.event_type, event_type, "{key}");
        assert_eq!(event.action.as_deref(), action, "{key}");
    }

    let mut retargeted: Value = serde_json::from_slice(&webhook_body("pr:modified")).unwrap();
    retargeted["previousTarget"] = json!({"id": "refs/heads/release"});
    let retargeted = retargeted.to_string().into_bytes();
    let event = adapter
        .verify_webhook(&headers("pr:modified", &retargeted), &retargeted)
        .unwrap();
    assert_eq!(event.action.as_deref(), Some("synchronize"));
}

#[test]
fn rejects_unsigned_tampered_or_wrongly_signed_webhooks() {
    let adapter = BitbucketDataCenterAdapter::new(
        BitbucketDataCenterConfig::new("https://git.example.invalid/", "token".into())
            .unwrap()
            .with_webhook_secret("hook-secret".into()),
    )
    .unwrap();
    let body = webhook_body("pr:opened");
    let signed = BTreeMap::from([
        ("X-Hub-Signature".to_owned(), sign("hook-secret", &body)),
        ("X-Event-Key".to_owned(), "pr:opened".to_owned()),
    ]);
    assert!(adapter
        .verify_webhook(&signed, b"{\"tampered\":true}")
        .is_err());
    let wrong = BTreeMap::from([
        ("X-Hub-Signature".to_owned(), sign("other-secret", &body)),
        ("X-Event-Key".to_owned(), "pr:opened".to_owned()),
    ]);
    assert!(adapter.verify_webhook(&wrong, &body).is_err());
    let unsigned = BTreeMap::from([("X-Event-Key".to_owned(), "pr:opened".to_owned())]);
    assert!(adapter.verify_webhook(&unsigned, &body).is_err());
    let sha1 = BTreeMap::from([
        (
            "X-Hub-Signature".to_owned(),
            format!("sha1={}", "0".repeat(40)),
        ),
        ("X-Event-Key".to_owned(), "pr:opened".to_owned()),
    ]);
    assert!(adapter.verify_webhook(&sha1, &body).is_err());

    let without_secret = BitbucketDataCenterAdapter::new(
        BitbucketDataCenterConfig::new("https://git.example.invalid/", "token".into()).unwrap(),
    )
    .unwrap();
    assert!(without_secret.verify_webhook(&signed, &body).is_err());
    // A signed delivery without a request ID gets a stable ID from its body.
    let event = adapter.verify_webhook(&signed, &body).unwrap();
    assert!(event.event_id.starts_with("sha256:"));
}

#[test]
fn refuses_to_publish_when_the_server_does_not_name_the_tokens_user() {
    let mut server = Server::new();
    server.anonymous = true;
    let host = FakeHost::start(server);
    let adapter = host.adapter();
    let reference = host.reference();
    let error = adapter
        .publish_review(publication(
            &reference,
            "review-1",
            CheckConclusion::Success,
            &[],
        ))
        .unwrap_err();
    assert!(error.to_string().contains("X-AUSERNAME"), "{error}");
    assert!(adapter.own_approval_stands(&reference).is_err());
    assert!(host.writes().is_empty());
}
