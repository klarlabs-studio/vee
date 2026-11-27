//! Vee's own approval on Bitbucket, Azure DevOps and Gerrit, against fake
//! hosts that answer by request line and record every request.

use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::{Arc, Mutex},
    thread,
};
use vee_hosting::{
    azure_devops::{AzureDevOpsAdapter, AzureDevOpsConfig},
    bitbucket::{BitbucketAdapter, BitbucketConfig},
    gerrit::{GerritAdapter, GerritConfig},
    HostingError, PullRequestApprovalProvider, PullRequestRef, RepositoryRef,
};

const HEAD: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const BASE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

type Route = (&'static str, String);

/// A host that answers each request with the body of the first route whose
/// prefix starts the request line ("METHOD /path"), and 404 otherwise.
fn fake_host(routes: Vec<Route>) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&requests);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let request = read_request(&mut stream);
            let line = request.lines().next().unwrap_or_default().to_owned();
            recorded.lock().unwrap().push(request);
            let (status, body) = routes
                .iter()
                .find(|(prefix, _)| line.starts_with(prefix))
                .map(|(_, body)| ("200 OK", body.as_str()))
                .unwrap_or(("404 Not Found", "{}"));
            write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        }
    });
    (address.to_string(), requests)
}

fn read_request(stream: &mut std::net::TcpStream) -> String {
    let mut request = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        let read = stream.read(&mut buffer).unwrap();
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

fn lines(requests: &Arc<Mutex<Vec<String>>>) -> Vec<String> {
    requests
        .lock()
        .unwrap()
        .iter()
        .map(|request| request.lines().next().unwrap_or_default().to_owned())
        .collect()
}

fn body_of(requests: &Arc<Mutex<Vec<String>>>, prefix: &str) -> serde_json::Value {
    let requests = requests.lock().unwrap();
    let request = requests
        .iter()
        .find(|request| request.starts_with(prefix))
        .unwrap_or_else(|| panic!("no request {prefix}"));
    let body = request.split_once("\r\n\r\n").unwrap().1;
    serde_json::from_str(body).unwrap()
}

fn reference(host: &str, full_name: &str, number: u64) -> PullRequestRef {
    PullRequestRef {
        repository: RepositoryRef {
            host: host.into(),
            full_name: full_name.into(),
        },
        number,
    }
}

fn bitbucket_pr(head: &str, approved: bool) -> String {
    serde_json::json!({
        "id": 7, "title": "T", "state": "OPEN", "updated_on": "2026-11-27T10:00:00Z",
        "source": {"branch": {"name": "feature"}, "commit": {"hash": head}},
        "destination": {"commit": {"hash": BASE}},
        "participants": [
            {"user": {"uuid": "{someone}"}, "approved": true},
            {"user": {"uuid": "{vee-bot}"}, "approved": approved}
        ]
    })
    .to_string()
}

fn bitbucket(routes: Vec<Route>) -> (BitbucketAdapter, PullRequestRef, Arc<Mutex<Vec<String>>>) {
    let mut all = vec![("GET /2.0/user ", r#"{"uuid":"{vee-bot}"}"#.to_owned())];
    all.extend(routes);
    let (address, requests) = fake_host(all);
    let adapter = BitbucketAdapter::new(
        BitbucketConfig::new(&format!("http://{address}/2.0/"), "token".into()).unwrap(),
    )
    .unwrap();
    (adapter, reference("127.0.0.1", "team/repo", 7), requests)
}

#[test]
fn bitbucket_reads_only_its_own_approval() {
    let (adapter, pr, _) = bitbucket(vec![(
        "GET /2.0/repositories/team/repo/pullrequests/7 ",
        bitbucket_pr(HEAD, false),
    )]);
    assert!(!adapter.own_approval_stands(&pr).unwrap());

    let (adapter, pr, _) = bitbucket(vec![(
        "GET /2.0/repositories/team/repo/pullrequests/7 ",
        bitbucket_pr(HEAD, true),
    )]);
    assert!(adapter.own_approval_stands(&pr).unwrap());
}

#[test]
fn bitbucket_approves_the_reviewed_head_and_withdraws() {
    // Bitbucket abbreviates hashes to 12 digits; the adapter resolves them.
    let (adapter, pr, requests) = bitbucket(vec![
        (
            "GET /2.0/repositories/team/repo/pullrequests/7 ",
            bitbucket_pr(&HEAD[..12], false).replace(BASE, &BASE[..12]),
        ),
        (
            "GET /2.0/repositories/team/repo/commit/bbbbbbbbbbbb ",
            format!(r#"{{"hash":"{HEAD}"}}"#),
        ),
        (
            "GET /2.0/repositories/team/repo/commit/aaaaaaaaaaaa ",
            format!(r#"{{"hash":"{BASE}"}}"#),
        ),
        (
            "POST /2.0/repositories/team/repo/pullrequests/7/approve ",
            r#"{"approved":true}"#.into(),
        ),
        (
            "DELETE /2.0/repositories/team/repo/pullrequests/7/approve ",
            "{}".into(),
        ),
    ]);
    adapter.approve_head(&pr, HEAD, "why").unwrap();
    adapter.withdraw_approval(&pr, "why").unwrap();
    let lines = lines(&requests);
    assert!(lines
        .iter()
        .any(|line| line.starts_with("POST /2.0/repositories/team/repo/pullrequests/7/approve ")));
    assert!(
        lines
            .iter()
            .any(|line| line
                .starts_with("DELETE /2.0/repositories/team/repo/pullrequests/7/approve "))
    );
}

#[test]
fn bitbucket_pull_requests_report_full_hashes() {
    use vee_hosting::GitHostingProvider;
    let (adapter, pr, _) = bitbucket(vec![
        (
            "GET /2.0/repositories/team/repo/pullrequests/7 ",
            bitbucket_pr(&HEAD[..12], false).replace(BASE, &BASE[..12]),
        ),
        (
            "GET /2.0/repositories/team/repo/commit/bbbbbbbbbbbb ",
            format!(r#"{{"hash":"{HEAD}"}}"#),
        ),
        (
            "GET /2.0/repositories/team/repo/commit/aaaaaaaaaaaa ",
            format!(r#"{{"hash":"{BASE}"}}"#),
        ),
    ]);
    let snapshot = adapter.get_pull_request(&pr).unwrap();
    assert_eq!(
        (snapshot.base_oid.as_str(), snapshot.head_oid.as_str()),
        (BASE, HEAD)
    );

    // A resolution to another commit is refused.
    let (adapter, pr, _) = bitbucket(vec![
        (
            "GET /2.0/repositories/team/repo/pullrequests/7 ",
            bitbucket_pr(&HEAD[..12], false),
        ),
        (
            "GET /2.0/repositories/team/repo/commit/bbbbbbbbbbbb ",
            format!(r#"{{"hash":"{}"}}"#, "c".repeat(40)),
        ),
    ]);
    assert!(adapter.get_pull_request(&pr).is_err());
}

#[test]
fn bitbucket_refuses_to_approve_a_moved_head() {
    let (adapter, pr, requests) = bitbucket(vec![(
        "GET /2.0/repositories/team/repo/pullrequests/7 ",
        bitbucket_pr(&"c".repeat(40), false),
    )]);
    assert!(matches!(
        adapter.approve_head(&pr, HEAD, "why"),
        Err(HostingError::StaleRevision { .. })
    ));
    assert!(lines(&requests)
        .iter()
        .all(|line| !line.starts_with("POST ")));
}

fn azure(routes: Vec<Route>) -> (AzureDevOpsAdapter, PullRequestRef, Arc<Mutex<Vec<String>>>) {
    let mut all = vec![
        (
            "GET /acme/_apis/connectionData?",
            r#"{"authenticatedUser":{"id":"actor-1"}}"#.to_owned(),
        ),
        (
            "GET /acme/platform/_apis/git/repositories/service/pullRequests/17?",
            serde_json::json!({
                "pullRequestId": 17, "status": "active", "title": "T", "description": "",
                "lastMergeSourceCommit": {"commitId": HEAD},
                "lastMergeTargetCommit": {"commitId": BASE}
            })
            .to_string(),
        ),
    ];
    all.extend(routes);
    let (address, requests) = fake_host(all);
    let adapter = AzureDevOpsAdapter::new(
        AzureDevOpsConfig::new(&format!("http://{address}/"), "token".into()).unwrap(),
    )
    .unwrap();
    (
        adapter,
        reference(&address, "acme/platform/service", 17),
        requests,
    )
}

const AZURE_REVIEWER: &str =
    "/acme/platform/_apis/git/repositories/service/pullRequests/17/reviewers/actor-1?";

#[test]
fn azure_devops_approval_is_a_vote_of_ten() {
    let (adapter, pr, _) = azure(vec![]);
    // Not a reviewer: no vote.
    assert!(!adapter.own_approval_stands(&pr).unwrap());

    let (adapter, pr, _) = azure(vec![(
        "GET /acme/platform/_apis/git/repositories/service/pullRequests/17/reviewers/actor-1?",
        r#"{"vote":5}"#.into(),
    )]);
    assert!(!adapter.own_approval_stands(&pr).unwrap());

    let (adapter, pr, requests) = azure(vec![
        (
            "GET /acme/platform/_apis/git/repositories/service/pullRequests/17/reviewers/actor-1?",
            r#"{"vote":10}"#.into(),
        ),
        (
            "PUT /acme/platform/_apis/git/repositories/service/pullRequests/17/reviewers/actor-1?",
            r#"{"vote":10}"#.into(),
        ),
    ]);
    assert!(adapter.own_approval_stands(&pr).unwrap());
    adapter.approve_head(&pr, HEAD, "why").unwrap();
    assert_eq!(
        body_of(&requests, &format!("PUT {AZURE_REVIEWER}")),
        serde_json::json!({"vote": 10})
    );
    requests.lock().unwrap().clear();
    adapter.withdraw_approval(&pr, "why").unwrap();
    assert_eq!(
        body_of(&requests, &format!("PUT {AZURE_REVIEWER}")),
        serde_json::json!({"vote": 0})
    );
}

#[test]
fn azure_devops_refuses_to_vote_on_a_moved_head() {
    let (adapter, pr, requests) = azure(vec![]);
    assert!(matches!(
        adapter.approve_head(&pr, &"c".repeat(40), "why"),
        Err(HostingError::StaleRevision { .. })
    ));
    assert!(lines(&requests)
        .iter()
        .all(|line| !line.starts_with("PUT ")));
}

fn gerrit_change(status: &str, permitted: &[&str], votes: serde_json::Value) -> String {
    serde_json::json!({
        "_number": 42, "project": "platform/service", "status": status,
        "current_revision": HEAD,
        "labels": {"Code-Review": {"all": votes}},
        "permitted_labels": {"Code-Review": permitted}
    })
    .to_string()
}

fn gerrit(change: String) -> (GerritAdapter, PullRequestRef, Arc<Mutex<Vec<String>>>) {
    let (address, requests) = fake_host(vec![
        (
            "GET /a/accounts/self/detail ",
            r#"{"_account_id":1000}"#.into(),
        ),
        ("GET /a/changes/42/detail?", format!(")]}}'\n{change}")),
        (
            "POST /a/changes/42/revisions/",
            ")]}'\n{\"labels\":{\"Code-Review\":2}}".into(),
        ),
    ]);
    let adapter = GerritAdapter::new(
        GerritConfig::new(&format!("http://{address}/a/"), "token".into()).unwrap(),
    )
    .unwrap();
    (
        adapter,
        reference("127.0.0.1", "platform/service", 42),
        requests,
    )
}

#[test]
fn gerrit_reads_only_its_own_positive_vote() {
    let others =
        serde_json::json!([{"_account_id": 7, "value": 2}, {"_account_id": 1000, "value": 0}]);
    let (adapter, pr, _) = gerrit(gerrit_change("NEW", &["0", "+1"], others));
    assert!(!adapter.own_approval_stands(&pr).unwrap());

    let own = serde_json::json!([{"_account_id": 1000, "value": 1}]);
    let (adapter, pr, _) = gerrit(gerrit_change("NEW", &["0", "+1"], own));
    assert!(adapter.own_approval_stands(&pr).unwrap());
}

#[test]
fn gerrit_votes_the_highest_permitted_value_on_the_reviewed_patch_set() {
    let (adapter, pr, requests) = gerrit(gerrit_change(
        "NEW",
        &["-2", "-1", " 0", "+1", "+2"],
        serde_json::json!([]),
    ));
    adapter.approve_head(&pr, HEAD, "Vee approves").unwrap();
    let prefix = format!("POST /a/changes/42/revisions/{HEAD}/review?");
    let body = body_of(&requests, &prefix);
    assert_eq!(body["labels"]["Code-Review"], 2);
    assert_eq!(body["message"], "Vee approves");
    assert_eq!(body["tag"], "autogenerated:vee:approval");

    requests.lock().unwrap().clear();
    adapter.withdraw_approval(&pr, "Vee withdrew").unwrap();
    assert_eq!(body_of(&requests, &prefix)["labels"]["Code-Review"], 0);
}

#[test]
fn gerrit_refuses_without_a_positive_permitted_vote_or_on_another_patch_set() {
    let (adapter, pr, requests) = gerrit(gerrit_change("NEW", &[" 0"], serde_json::json!([])));
    assert!(matches!(
        adapter.approve_head(&pr, HEAD, "why"),
        Err(HostingError::InvalidResponse(message)) if message.contains("may not vote")
    ));
    assert!(matches!(
        adapter.approve_head(&pr, &"c".repeat(40), "why"),
        Err(HostingError::StaleRevision { .. })
    ));
    let (closed, _, closed_requests) =
        gerrit(gerrit_change("MERGED", &["+2"], serde_json::json!([])));
    assert!(matches!(
        closed.approve_head(&pr, HEAD, "why"),
        Err(HostingError::StaleRevision { .. })
    ));
    for recorded in [requests, closed_requests] {
        assert!(lines(&recorded)
            .iter()
            .all(|line| !line.starts_with("POST ")));
    }
}
