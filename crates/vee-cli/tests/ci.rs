//! `vee ci run` end to end: a GitHub Actions pull request job against a fake
//! GitHub API.

mod support;
use support::vee;

#[cfg(unix)]
use std::io::{Read, Write};
#[cfg(unix)]
use std::net::TcpListener;
use std::path::Path;
use std::process::Command;
#[cfg(unix)]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(unix)]
use std::sync::Arc;

fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args([
            "-c",
            "user.email=vee@example.invalid",
            "-c",
            "user.name=Vee test",
        ])
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

/// Serves GitHub API requests until `stop` is set, answering a pull request
/// whose base is `base_tip` and head is `head`. Returns the request lines.
#[cfg(unix)]
fn fake_github(
    listener: TcpListener,
    stop: Arc<AtomicBool>,
    base_tip: String,
    head: String,
) -> std::thread::JoinHandle<Vec<String>> {
    listener.set_nonblocking(true).unwrap();
    std::thread::spawn(move || {
        let mut requests = Vec::new();
        while !stop.load(Ordering::SeqCst) {
            let mut stream = match listener.accept() {
                Ok((stream, _)) => stream,
                Err(_) => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
            };
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            let mut chunk = [0u8; 4096];
            let header_end = loop {
                let count = stream.read(&mut chunk).unwrap();
                request.extend_from_slice(&chunk[..count]);
                if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                    break end + 4;
                }
            };
            let headers = String::from_utf8_lossy(&request[..header_end]).to_ascii_lowercase();
            let length = headers
                .lines()
                .find_map(|line| line.strip_prefix("content-length: "))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            while request.len() < header_end + length {
                let count = stream.read(&mut chunk).unwrap();
                request.extend_from_slice(&chunk[..count]);
            }
            let request = String::from_utf8_lossy(&request).to_string();
            let line = request.lines().next().unwrap_or("").to_owned();
            let body = if line.starts_with("GET ") && line.contains("/pulls/9/files?") {
                serde_json::json!([{"filename": "src/lib.rs", "status": "modified",
                    "previous_filename": null, "patch": "@@ -1 +1 @@\n-pub fn initial() {}\n+pub fn changed() {}",
                    "additions": 1, "deletions": 1}])
                .to_string()
            } else if line.starts_with("GET ") && line.contains("/pulls/9 ") {
                serde_json::json!({"number": 9, "title": "Change", "body": null, "state": "open",
                    "merged": false, "base": {"sha": base_tip}, "head": {"sha": head}})
                .to_string()
            } else if line.starts_with("GET ") && line.contains("/pulls/9/comments?") {
                // An earlier run's thread for a finding the change has since fixed.
                serde_json::json!([{"id": 501, "path": "src/lib.rs", "line": 1, "original_line": 1,
                    "side": "RIGHT", "body": "Old finding\n\n<!-- vee:fingerprint:sha256:fixed -->",
                    "user": {"login": "github-actions[bot]"},
                    "html_url": "https://example.invalid/c/501",
                    "created_at": "2026-11-20T00:00:00Z", "updated_at": "2026-11-20T00:00:00Z"}])
                .to_string()
            } else if line.starts_with("GET ") && line.contains("/issues/9/comments?") {
                // The conversation, where comment commands would be.
                "[]".to_owned()
            } else if line.starts_with("POST ") && line.contains("/issues/9/comments ") {
                // Vee's summary comment.
                r#"{"id":880}"#.to_owned()
            } else if line.starts_with("GET ") && line.contains("/collaborators/") {
                r#"{"permission":"read","role_name":"read"}"#.to_owned()
            } else if line.starts_with("PATCH ") && line.contains("/pulls/comments/501 ") {
                r#"{"id":501}"#.to_owned()
            } else if line.starts_with("POST ") && line.contains("/pulls/9/comments ") {
                r#"{"id":777}"#.to_owned()
            } else if line.starts_with("POST ") && line.contains("graphql") {
                if request.contains("resolveReviewThread") {
                    r#"{"data":{"resolveReviewThread":{"thread":{"id":"PRRT_1","isResolved":true}}}}"#.to_owned()
                } else {
                    r#"{"data":{"repository":{"pullRequest":{"reviewThreads":{"nodes":[{"id":"PRRT_1","isResolved":false,"comments":{"nodes":[{"databaseId":501,"body":"x","author":{"login":"github-actions[bot]"}}]}},{"id":"PRRT_2","isResolved":false,"comments":{"nodes":[{"databaseId":777,"body":"x","author":{"login":"github-actions[bot]"}}]}}],"pageInfo":{"hasNextPage":false,"endCursor":"c"}}}}}}"#.to_owned()
                }
            } else if line.starts_with("GET ") && line.contains("check-runs?") {
                r#"{"check_runs":[]}"#.to_owned()
            } else if line.starts_with("POST ") && line.contains("/check-runs ") {
                r#"{"id":1234}"#.to_owned()
            } else {
                panic!("unexpected GitHub request: {line}");
            };
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
            requests.push(
                if line.contains("graphql")
                    || line.contains("/pulls/9/comments ")
                    || line.contains("/issues/9/comments ")
                {
                    request.clone()
                } else {
                    line
                },
            );
        }
        requests
    })
}

/// A repository on a pull request branch whose head changes `src/lib.rs`
/// line 1, reviewed by a provider that prints `findings`, a JSON array.
#[cfg(unix)]
struct PullRequestRepository {
    directory: tempfile::TempDir,
    outside: tempfile::TempDir,
    head: String,
    base_tip: String,
}

#[cfg(unix)]
fn pull_request_repository(findings: &str) -> PullRequestRepository {
    pull_request_repository_with(findings, "")
}

/// A pull request repository whose `.vee.yaml` ends with `extra_config`.
#[cfg(unix)]
fn pull_request_repository_with(findings: &str, extra_config: &str) -> PullRequestRepository {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let outside = tempfile::tempdir().unwrap();
    let provider = outside.path().join("provider");
    std::fs::write(
        &provider,
        format!("#!/bin/sh\ncat >/dev/null\nprintf '%s' '{{\"schema_version\":1,\"findings\":{findings}}}'\n"),
    )
    .unwrap();
    std::fs::set_permissions(&provider, std::fs::Permissions::from_mode(0o755)).unwrap();

    git(root, &["init", "-q", "-b", "main"]);
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/lib.rs"), "pub fn initial() {}\n").unwrap();
    std::fs::write(root.join("reviewer.md"), "Review the change.\n").unwrap();
    std::fs::write(
        root.join(".vee.yaml"),
        format!(
            "version: 1\noffline: false\nproviders:\n  fake: {{ kind: cli, executable: {} }}\nreviewers:\n  correctness: {{ provider: fake, instructions_file: reviewer.md }}\n{extra_config}",
            provider.display()
        ),
    )
    .unwrap();
    git(root, &["add", "."]);
    git(root, &["commit", "-qm", "base"]);
    git(root, &["checkout", "-q", "-b", "feature"]);
    std::fs::write(root.join("src/lib.rs"), "pub fn changed() {}\n").unwrap();
    git(root, &["commit", "-qam", "change"]);
    let head = git(root, &["rev-parse", "HEAD"]);
    // The base branch moves on after the pull request was opened.
    git(root, &["checkout", "-q", "main"]);
    std::fs::write(root.join("other.txt"), "other\n").unwrap();
    git(root, &["add", "."]);
    git(root, &["commit", "-qm", "main moved"]);
    let base_tip = git(root, &["rev-parse", "HEAD"]);
    git(root, &["checkout", "-q", &head]);
    PullRequestRepository {
        directory,
        outside,
        head,
        base_tip,
    }
}

#[cfg(unix)]
#[test]
fn ci_run_reviews_a_github_pull_request_and_publishes_its_gate() {
    let repository = pull_request_repository("[]");
    let (root, outside) = (repository.directory.path(), &repository.outside);
    let (head, base_tip) = (repository.head.clone(), repository.base_tip.clone());

    let event = outside.path().join("event.json");
    std::fs::write(
        &event,
        serde_json::json!({"pull_request": {"number": 9, "base": {"sha": base_tip}, "head": {"sha": head}}})
            .to_string(),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let server = fake_github(listener, stop.clone(), base_tip.clone(), head.clone());

    let output = vee()
        .args(["ci", "run", "--output", "json"])
        .env("GITHUB_ACTIONS", "true")
        .env("GITHUB_EVENT_NAME", "pull_request")
        .env("GITHUB_EVENT_PATH", &event)
        .env("GITHUB_REPOSITORY", "team/repo")
        .env("GITHUB_SERVER_URL", "http://127.0.0.1")
        .env("GITHUB_API_URL", format!("http://{address}"))
        .env("GH_TOKEN", "fixture-token")
        .current_dir(root)
        .output()
        .unwrap();
    stop.store(true, Ordering::SeqCst);
    let requests = server.join().unwrap();
    assert!(
        output.status.success(),
        "exit={:?}\nstdout={}\nstderr={}\nrequests={requests:#?}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let run: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../schemas/ci-run-v1.schema.json")).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let errors: Vec<String> = validator.iter_errors(&run).map(|e| e.to_string()).collect();
    assert!(errors.is_empty(), "{errors:?}\n{run:#}");
    assert_eq!(run["gate"], "pass");
    assert_eq!(run["pull_request"]["number"], 9);
    assert_eq!(run["publication"]["provider_check_id"], "1234");
    assert!(requests
        .iter()
        .any(|line| line.starts_with("POST /repos/team/repo/check-runs")));
    assert!(
        requests
            .iter()
            .any(|request| request.contains("resolveReviewThread")),
        "the fixed finding's thread is resolved from what the pull request shows: {requests:#?}"
    );
    let exclude = std::fs::read_to_string(root.join(".git/info/exclude")).unwrap();
    assert!(exclude.contains("/.vee/"));

    // A checkout of anything but the pull request's head is refused.
    git(root, &["checkout", "-q", &base_tip]);
    let wrong = vee()
        .args(["ci", "run", "--output", "json"])
        .env("GITHUB_ACTIONS", "true")
        .env("GITHUB_EVENT_NAME", "pull_request")
        .env("GITHUB_EVENT_PATH", &event)
        .env("GITHUB_REPOSITORY", "team/repo")
        .env("GH_TOKEN", "fixture-token")
        .current_dir(root)
        .output()
        .unwrap();
    assert!(!wrong.status.success());
    assert!(String::from_utf8_lossy(&wrong.stdout).contains("pull_request.head.sha"));
}

#[cfg(unix)]
#[test]
fn ci_run_describe_adds_a_walkthrough_to_the_summary() {
    let repository = pull_request_repository("[]");
    let (root, outside) = (repository.directory.path(), &repository.outside);
    let event = outside.path().join("event.json");
    std::fs::write(
        &event,
        serde_json::json!({"pull_request": {"number": 9, "base": {"sha": repository.base_tip}, "head": {"sha": repository.head}}})
            .to_string(),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let server = fake_github(
        listener,
        stop.clone(),
        repository.base_tip.clone(),
        repository.head.clone(),
    );
    let output = vee()
        .args(["ci", "run", "--describe", "--output", "json"])
        .env("GITHUB_ACTIONS", "true")
        .env("GITHUB_EVENT_NAME", "pull_request")
        .env("GITHUB_EVENT_PATH", &event)
        .env("GITHUB_REPOSITORY", "team/repo")
        .env("GITHUB_SERVER_URL", "http://127.0.0.1")
        .env("GITHUB_API_URL", format!("http://{address}"))
        .env("GH_TOKEN", "fixture-token")
        .current_dir(root)
        .output()
        .unwrap();
    stop.store(true, Ordering::SeqCst);
    let requests = server.join().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary = requests
        .iter()
        .find(|request| {
            request.starts_with("POST /repos/team/repo/issues/9/comments")
                && request.contains("vee:summary")
        })
        .unwrap_or_else(|| panic!("a summary is posted: {requests:#?}"));
    assert!(summary.contains("### Walkthrough"), "{summary}");
    assert!(summary.contains("**Risk:**"), "{summary}");
    // The fake reviewer cannot draft a description; the summary goes out
    // without one.
    assert!(!summary.contains("Drafted description"), "{summary}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("the description was not drafted"));
}

#[cfg(unix)]
#[test]
fn ci_run_runs_the_verifications_the_policy_requires() {
    use std::os::unix::fs::PermissionsExt;
    let checks = tempfile::tempdir().unwrap();
    let marker = checks.path().join("ran");
    let check = checks.path().join("check");
    std::fs::write(&check, format!("#!/bin/sh\ntouch '{}'\n", marker.display())).unwrap();
    std::fs::set_permissions(&check, std::fs::Permissions::from_mode(0o755)).unwrap();
    let repository = pull_request_repository_with(
        "[]",
        &format!(
            "verification:\n  check: {{ executable: {} }}\npolicy:\n  required_reviewers: [correctness]\n  required_verifications: [check]\n",
            check.display()
        ),
    );
    let (root, outside) = (repository.directory.path(), &repository.outside);
    let event = outside.path().join("event.json");
    std::fs::write(
        &event,
        serde_json::json!({"pull_request": {"number": 9, "base": {"sha": repository.base_tip}, "head": {"sha": repository.head}}})
            .to_string(),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let server = fake_github(
        listener,
        stop.clone(),
        repository.base_tip.clone(),
        repository.head.clone(),
    );
    let output = vee()
        .args(["ci", "run", "--output", "json"])
        .env("GITHUB_ACTIONS", "true")
        .env("GITHUB_EVENT_NAME", "pull_request")
        .env("GITHUB_EVENT_PATH", &event)
        .env("GITHUB_REPOSITORY", "team/repo")
        .env("GITHUB_SERVER_URL", "http://127.0.0.1")
        .env("GITHUB_API_URL", format!("http://{address}"))
        .env("GH_TOKEN", "fixture-token")
        .current_dir(root)
        .output()
        .unwrap();
    stop.store(true, Ordering::SeqCst);
    server.join().unwrap();
    assert!(marker.exists(), "the required check ran");
    let run: serde_json::Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&output.stderr)));
    assert_eq!(
        run["gate"],
        "pass",
        "{run:#}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn init_ci_writes_a_pipeline_once_and_names_its_secrets() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    git(root, &["init", "-q"]);
    std::fs::write(root.join(".vee.yaml"), "version: 1\n").unwrap();
    let init = || {
        vee()
            .args([
                "init",
                "--ci",
                "github",
                "--provider",
                "anthropic-api",
                "--model",
                "model-id",
                "--output",
                "json",
            ])
            .current_dir(root)
            .output()
            .unwrap()
    };
    let first = init();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stdout)
    );
    let report: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(report["path"], ".github/workflows/vee.yml");
    assert_eq!(report["secrets"], serde_json::json!(["ANTHROPIC_API_KEY"]));
    let workflow = std::fs::read_to_string(root.join(".github/workflows/vee.yml")).unwrap();
    assert!(workflow.contains(&format!(
        "uses: klarlabs-studio/vee@v{}",
        env!("CARGO_PKG_VERSION")
    )));
    // An existing pipeline is never overwritten.
    assert!(!init().status.success());

    let without_model = vee()
        .args(["init", "--ci", "gitlab", "--provider", "openai-api"])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(!without_model.status.success());
}

#[cfg(unix)]
#[test]
fn ci_run_posts_a_reviewers_fix_as_a_committable_suggestion() {
    let repository = pull_request_repository(
        r#"[{"category":"correctness","severity":"high","confidence":90,"rationale":"changed() drops the result callers rely on.","path":"src/lib.rs","line":1,"suggestion":{"replacement":"pub fn changed() -> u32 { 0 }"}}]"#,
    );
    let (root, outside) = (repository.directory.path(), &repository.outside);
    let event = outside.path().join("event.json");
    std::fs::write(
        &event,
        serde_json::json!({"pull_request": {"number": 9, "base": {"sha": repository.base_tip}, "head": {"sha": repository.head}}})
            .to_string(),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let server = fake_github(
        listener,
        stop.clone(),
        repository.base_tip.clone(),
        repository.head.clone(),
    );
    let output = vee()
        .args(["ci", "run", "--output", "json"])
        .env("GITHUB_ACTIONS", "true")
        .env("GITHUB_EVENT_NAME", "pull_request")
        .env("GITHUB_EVENT_PATH", &event)
        .env("GITHUB_REPOSITORY", "team/repo")
        .env("GITHUB_SERVER_URL", "http://127.0.0.1")
        .env("GITHUB_API_URL", format!("http://{address}"))
        .env("GH_TOKEN", "fixture-token")
        .current_dir(root)
        .output()
        .unwrap();
    stop.store(true, Ordering::SeqCst);
    let requests = server.join().unwrap();
    assert_eq!(
        output.status.code(),
        Some(1),
        "the high finding blocks\nstdout={}\nstderr={}\nrequests={requests:#?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let comment = requests
        .iter()
        .find(|request| request.starts_with("POST /repos/team/repo/pulls/9/comments"))
        .unwrap_or_else(|| panic!("an inline comment is posted: {requests:#?}"));
    assert!(
        comment.contains(r#"```suggestion\npub fn changed() -> u32 { 0 }\n```"#),
        "{comment}"
    );
    assert!(comment.contains(r#""line":1"#), "{comment}");
    assert!(
        !comment.contains("start_line"),
        "one line needs no range: {comment}"
    );
}

/// A local review signed with a key the base branch trusts is reused in CI:
/// the reviewers are not asked again, and the run says whose review it
/// reused (ADR 0043). A key the base does not list is not trusted.
#[cfg(unix)]
#[test]
fn ci_run_reuses_a_signed_local_review_of_the_same_head() {
    use base64::Engine;
    use std::os::unix::fs::PermissionsExt;
    let keys = tempfile::tempdir().unwrap();
    let key = |name: &str| {
        let (private, public) = (
            keys.path().join(name),
            keys.path().join(format!("{name}.pub")),
        );
        let output = vee()
            .args(["reviews", "keygen", "--private-key"])
            .arg(&private)
            .arg("--public-key")
            .arg(&public)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(std::fs::read(&public).unwrap());
        (private, encoded)
    };
    let (trusted_key, trusted_public) = key("alice");
    let (untrusted_key, _) = key("mallory");
    let repository = pull_request_repository_with(
        "[]",
        &format!("review_signers:\n  - {{ id: alice, public_key: {trusted_public} }}\n"),
    );
    let (root, outside) = (repository.directory.path(), &repository.outside);
    let (head, base_tip) = (repository.head.clone(), repository.base_tip.clone());
    // The reviewer records every call.
    let calls = outside.path().join("calls");
    std::fs::write(
        outside.path().join("provider"),
        format!(
            "#!/bin/sh\ncat >/dev/null\necho call >> '{}'\nprintf '%s' '{{\"schema_version\":1,\"findings\":[]}}'\n",
            calls.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(
        outside.path().join("provider"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();

    // The developer reviews the head and shares the review.
    let local = vee()
        .args(["review", "--base", "main", "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        local.status.success(),
        "{}",
        String::from_utf8_lossy(&local.stderr)
    );
    let review_id = serde_json::from_slice::<serde_json::Value>(&local.stdout).unwrap()
        ["review_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let share = |private_key: &Path| {
        let output = vee()
            .args([
                "reviews", "share", &review_id, "--key-id", "laptop", "--output", "json",
            ])
            .arg("--private-key")
            .arg(private_key)
            .current_dir(root)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };

    let ci_run = || {
        let _ = std::fs::remove_file(&calls);
        let event = outside.path().join("event.json");
        std::fs::write(
            &event,
            serde_json::json!({"pull_request": {"number": 9, "base": {"sha": base_tip}, "head": {"sha": head}}})
                .to_string(),
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let server = fake_github(listener, stop.clone(), base_tip.clone(), head.clone());
        let output = vee()
            .args(["ci", "run", "--output", "json"])
            .env("GITHUB_ACTIONS", "true")
            .env("GITHUB_EVENT_NAME", "pull_request")
            .env("GITHUB_EVENT_PATH", &event)
            .env("GITHUB_REPOSITORY", "team/repo")
            .env("GITHUB_SERVER_URL", "http://127.0.0.1")
            .env("GITHUB_API_URL", format!("http://{address}"))
            .env("GH_TOKEN", "fixture-token")
            .current_dir(root)
            .output()
            .unwrap();
        stop.store(true, Ordering::SeqCst);
        server.join().unwrap();
        assert!(
            output.status.success(),
            "stdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let run: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let reviewer_calls = std::fs::read_to_string(&calls)
            .unwrap_or_default()
            .lines()
            .count();
        (
            run,
            reviewer_calls,
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    };

    // Signed with a key the base does not list: reviewed again.
    let shared = share(&untrusted_key);
    assert_eq!(shared["head_oid"], head);
    let (run, reviewer_calls, stderr) = ci_run();
    assert!(run.get("reused_review").is_none(), "{run:#}");
    assert!(reviewer_calls > 0);
    assert!(stderr.contains("was not reused"), "{stderr}");

    // Signed with alice's key: reused, without asking the reviewer.
    share(&trusted_key);
    let (run, reviewer_calls, stderr) = ci_run();
    assert_eq!(run["reused_review"]["signer"], "alice", "{run:#}\n{stderr}");
    assert_eq!(run["reused_review"]["review_id"], review_id.as_str());
    assert_eq!(run["reused_review"]["reused_files"], 1);
    assert_eq!(reviewer_calls, 0, "{stderr}");
    assert_eq!(run["gate"], "pass");
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../schemas/ci-run-v1.schema.json")).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let errors: Vec<String> = validator.iter_errors(&run).map(|e| e.to_string()).collect();
    assert!(errors.is_empty(), "{errors:?}\n{run:#}");
}
