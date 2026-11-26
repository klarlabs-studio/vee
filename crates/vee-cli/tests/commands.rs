//! `vee ci command` end to end, against a fake GitHub that remembers the
//! comments Vee posts (ADR 0020).
#![cfg(unix)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

fn vee() -> std::process::Command {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_vee"));
    command.env("NO_COLOR", "1").env_remove("VEE_HOSTING_HOSTS");
    command
}

fn git(root: &Path, args: &[&str]) -> String {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .env("GIT_AUTHOR_NAME", "Vee test")
        .env("GIT_AUTHOR_EMAIL", "vee@example.invalid")
        .env("GIT_COMMITTER_NAME", "Vee test")
        .env("GIT_COMMITTER_EMAIL", "vee@example.invalid")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// RFC 3339 for a Unix time, as GitHub writes it.
fn rfc3339(unix: i64) -> String {
    let days = unix.div_euclid(86_400);
    let seconds = unix.rem_euclid(86_400);
    // Civil date from days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z - era * 146_097;
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
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60
    )
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

const BOT: &str = "github-actions[bot]";

/// What the fake GitHub remembers.
#[derive(Default)]
struct State {
    /// Inline review comments.
    review: Vec<serde_json::Value>,
    /// Comments in the pull request's conversation.
    conversation: Vec<serde_json::Value>,
    /// Conclusions of the check runs Vee created, in order.
    checks: Vec<String>,
    next_id: u64,
    /// The pull request's head, when a test pushes after the server started.
    head: Option<String>,
    /// Requests to edit a conversation comment.
    edits: usize,
    /// A bare repository whose `feature` branch is the pull request's head.
    origin: Option<std::path::PathBuf>,
}

impl State {
    fn add(&mut self, review: bool, author: &str, mut comment: serde_json::Value) -> u64 {
        self.next_id += 1;
        let id = 700 + self.next_id;
        comment["id"] = id.into();
        comment["user"] = serde_json::json!({
            "login": author,
            "type": if author.ends_with("[bot]") { "Bot" } else { "User" },
        });
        comment["created_at"] = rfc3339(now()).into();
        comment["updated_at"] = comment["created_at"].clone();
        comment["html_url"] = format!("https://example.invalid/c/{id}").into();
        if review {
            &mut self.review
        } else {
            &mut self.conversation
        }
        .push(comment);
        id
    }
}

fn read_request(stream: &mut std::net::TcpStream) -> (String, String) {
    let mut request = Vec::new();
    let mut chunk = [0u8; 8192];
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
    let line = String::from_utf8_lossy(&request[..header_end])
        .lines()
        .next()
        .unwrap_or("")
        .to_owned();
    (
        line,
        String::from_utf8_lossy(&request[header_end..]).to_string(),
    )
}

fn respond(state: &Mutex<State>, line: &str, body: &str, base: &str, head: &str) -> (u16, String) {
    let mut state = state.lock().unwrap();
    let json = |value: serde_json::Value| (200, value.to_string());
    let request: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
    let (method, target) = line.split_once(' ').unwrap();
    let path = target.split(' ').next().unwrap();
    let route = path.split('?').next().unwrap();
    let pushed = state.head.clone().or_else(|| {
        state
            .origin
            .as_ref()
            .map(|origin| git(origin, &["rev-parse", "refs/heads/feature"]))
    });
    let head = pushed.as_deref().unwrap_or(head);
    match (method, route) {
        ("GET", "/repos/team/repo/pulls/9") => json(serde_json::json!({
            "number": 9, "title": "Change", "body": null, "state": "open", "merged": false,
            "base": {"sha": base, "repo": {"full_name": "team/repo"}},
            "head": {"sha": head, "ref": "feature", "repo": {"full_name": "team/repo"}},
        })),
        ("GET", "/repos/team/repo/pulls/9/files") => json(serde_json::json!([{
            "filename": "src/lib.rs", "status": "modified", "previous_filename": null,
            "patch": "@@ -1 +1 @@\n-pub fn initial() {}\n+pub fn changed() {}",
            "additions": 1, "deletions": 1,
        }])),
        ("GET", "/repos/team/repo/pulls/9/comments") => {
            let page_one = path.contains("page=1") || !path.contains("page=");
            json(if page_one {
                state.review.clone().into()
            } else {
                serde_json::json!([])
            })
        }
        ("GET", "/repos/team/repo/issues/9/comments") => {
            let page_one = path.contains("page=1") || !path.contains("page=");
            json(if page_one {
                state.conversation.clone().into()
            } else {
                serde_json::json!([])
            })
        }
        ("POST", "/repos/team/repo/pulls/9/comments") => {
            let id = state.add(
                true,
                BOT,
                serde_json::json!({
                    "body": request["body"], "path": request["path"],
                    "line": request["line"], "side": "RIGHT",
                }),
            );
            (201, serde_json::json!({"id": id}).to_string())
        }
        ("POST", route) if route.starts_with("/repos/team/repo/pulls/9/comments/") => {
            let parent: u64 = route.split('/').nth(7).unwrap().parse().unwrap();
            let id = state.add(
                true,
                BOT,
                serde_json::json!({
                    "body": request["body"], "in_reply_to_id": parent,
                    "path": "src/lib.rs", "line": 1,
                }),
            );
            (201, serde_json::json!({"id": id}).to_string())
        }
        ("POST", "/repos/team/repo/issues/9/comments") => {
            let id = state.add(false, BOT, serde_json::json!({"body": request["body"]}));
            (201, serde_json::json!({"id": id}).to_string())
        }
        ("PATCH", route) if route.starts_with("/repos/team/repo/issues/comments/") => {
            let id: u64 = route.rsplit('/').next().unwrap().parse().unwrap();
            state.edits += 1;
            if let Some(comment) = state.conversation.iter_mut().find(|c| c["id"] == id) {
                comment["body"] = request["body"].clone();
            }
            json(serde_json::json!({"id": id}))
        }
        ("PATCH", route) if route.starts_with("/repos/team/repo/pulls/comments/") => {
            let id: u64 = route.rsplit('/').next().unwrap().parse().unwrap();
            if let Some(comment) = state.review.iter_mut().find(|c| c["id"] == id) {
                comment["body"] = request["body"].clone();
            }
            json(serde_json::json!({"id": id}))
        }
        ("GET", "/repos/team/repo/collaborators/alice/permission") => {
            json(serde_json::json!({"permission": "write", "role_name": "write"}))
        }
        ("GET", route) if route.starts_with("/repos/team/repo/collaborators/") => {
            json(serde_json::json!({"permission": "read", "role_name": "read"}))
        }
        ("GET", "/repos/team/repo/commits/head/check-runs") | ("GET", _)
            if route.ends_with("/check-runs") =>
        {
            json(serde_json::json!({"check_runs": []}))
        }
        ("POST", "/repos/team/repo/check-runs") => {
            state
                .checks
                .push(request["conclusion"].as_str().unwrap_or("").to_owned());
            json(serde_json::json!({"id": 1234}))
        }
        ("POST", "/graphql") | ("POST", "/api/graphql") => {
            if body.contains("resolveReviewThread") || body.contains("unresolveReviewThread") {
                json(
                    serde_json::json!({"data": {"resolveReviewThread": {"thread": {"id": "T", "isResolved": true}}, "unresolveReviewThread": {"thread": {"id": "T", "isResolved": false}}}}),
                )
            } else {
                let nodes: Vec<_> = state
                    .review
                    .iter()
                    .filter(|comment| comment.get("in_reply_to_id").is_none())
                    .map(|comment| serde_json::json!({
                        "id": format!("T{}", comment["id"]), "isResolved": false,
                        "comments": {"nodes": [{"databaseId": comment["id"], "body": "x", "author": {"login": BOT}}]},
                    }))
                    .collect();
                json(
                    serde_json::json!({"data": {"repository": {"pullRequest": {"reviewThreads": {
                    "nodes": nodes, "pageInfo": {"hasNextPage": false, "endCursor": "c"}}}}}}),
                )
            }
        }
        _ => panic!("unexpected GitHub request: {line}"),
    }
}

fn serve(
    listener: TcpListener,
    stop: Arc<AtomicBool>,
    state: Arc<Mutex<State>>,
    base: String,
    head: String,
) -> std::thread::JoinHandle<()> {
    listener.set_nonblocking(true).unwrap();
    std::thread::spawn(move || {
        while !stop.load(Ordering::SeqCst) {
            let Ok((mut stream, _)) = listener.accept() else {
                std::thread::sleep(std::time::Duration::from_millis(5));
                continue;
            };
            stream.set_nonblocking(false).unwrap();
            let (line, body) = read_request(&mut stream);
            let (status, reply) = respond(&state, &line, &body, &base, &head);
            write!(
                stream,
                "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                reply.len()
            )
            .unwrap();
        }
    })
}

#[test]
fn a_waiver_given_in_a_finding_thread_passes_the_gate_on_that_head() {
    use std::os::unix::fs::PermissionsExt;
    let outside = tempfile::tempdir().unwrap();
    let provider = outside.path().join("provider");
    std::fs::write(
        &provider,
        "#!/bin/sh\ncat >/dev/null\nprintf '%s' '{\"schema_version\":1,\"findings\":[{\"category\":\"correctness\",\"severity\":\"high\",\"confidence\":90,\"rationale\":\"changed() drops the result callers rely on.\",\"path\":\"src/lib.rs\",\"line\":1}]}'\n",
    )
    .unwrap();
    std::fs::set_permissions(&provider, std::fs::Permissions::from_mode(0o755)).unwrap();

    // origin has main and the pull request's head; the job checks out main.
    let origin = outside.path().join("origin.git");
    std::fs::create_dir_all(&origin).unwrap();
    git(&origin, &["init", "-q", "--bare", "-b", "main"]);
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    git(root, &["init", "-q", "-b", "main"]);
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/lib.rs"), "pub fn initial() {}\n").unwrap();
    std::fs::write(root.join("reviewer.md"), "Review the change.\n").unwrap();
    std::fs::write(
        root.join(".vee.yaml"),
        format!(
            "version: 1\noffline: false\nproviders:\n  fake: {{ kind: cli, executable: {} }}\nreviewers:\n  correctness: {{ provider: fake, instructions_file: reviewer.md }}\n",
            provider.display()
        ),
    )
    .unwrap();
    git(root, &["add", "."]);
    git(root, &["commit", "-qm", "base"]);
    let base = git(root, &["rev-parse", "HEAD"]);
    git(root, &["checkout", "-q", "-b", "feature"]);
    std::fs::write(root.join("src/lib.rs"), "pub fn changed() {}\n").unwrap();
    git(root, &["commit", "-qam", "change"]);
    let head = git(root, &["rev-parse", "HEAD"]);
    git(root, &["remote", "add", "origin", origin.to_str().unwrap()]);
    git(
        root,
        &["push", "-q", "origin", "main", "feature:refs/pull/9/head"],
    );

    let state = Arc::new(Mutex::new(State::default()));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let server = serve(
        listener,
        stop.clone(),
        state.clone(),
        base.clone(),
        head.clone(),
    );
    let github =
        |command: &mut std::process::Command, event_name: &str, event: &serde_json::Value| {
            let path = outside.path().join(format!("{event_name}.json"));
            std::fs::write(&path, event.to_string()).unwrap();
            command
                .env("GITHUB_ACTIONS", "true")
                .env("GITHUB_EVENT_NAME", event_name)
                .env("GITHUB_EVENT_PATH", &path)
                .env("GITHUB_REPOSITORY", "team/repo")
                .env("GITHUB_SERVER_URL", "http://127.0.0.1")
                .env("GITHUB_API_URL", format!("http://{address}"))
                .env("GH_TOKEN", "fixture-token")
                .current_dir(root);
        };
    let run_ci = || {
        let mut command = vee();
        command.args(["ci", "run", "--output", "json"]);
        github(
            &mut command,
            "pull_request",
            &serde_json::json!({"pull_request": {"number": 9, "base": {"sha": base}, "head": {"sha": head}}}),
        );
        command.output().unwrap()
    };

    // 1. The review blocks and opens the finding's thread.
    let first = run_ci();
    assert_eq!(
        first.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let thread = state.lock().unwrap().review[0].clone();
    let thread_id = thread["id"].as_u64().unwrap();
    assert!(
        thread["body"].as_str().unwrap().contains("vee:fingerprint"),
        "{thread}"
    );

    // 2. Alice waives it in the thread, from a job that checked out main.
    git(root, &["checkout", "-q", "main"]);
    let command_id = state.lock().unwrap().add(
        true,
        "alice",
        serde_json::json!({"body": "@vee waive 7d accepted for the hotfix", "in_reply_to_id": thread_id, "path": "src/lib.rs", "line": 1}),
    );
    let event = {
        let state = state.lock().unwrap();
        let comment = state
            .review
            .iter()
            .find(|c| c["id"] == command_id)
            .unwrap()
            .clone();
        serde_json::json!({"action": "created", "comment": comment, "pull_request": {"number": 9}})
    };
    let mut command = vee();
    command.args(["ci", "command", "--output", "json"]);
    github(&mut command, "pull_request_review_comment", &event);
    let handled = command.output().unwrap();
    assert!(
        handled.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&handled.stdout),
        String::from_utf8_lossy(&handled.stderr)
    );
    let outcome: serde_json::Value = serde_json::from_slice(&handled.stdout).unwrap();
    let mut schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../schemas/ci-command-v1.schema.json")).unwrap();
    let mut run_schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../schemas/ci-run-v1.schema.json")).unwrap();
    // The run is the published ci-run schema; inline it for the validator.
    run_schema.as_object_mut().unwrap().remove("$id");
    schema["properties"]["run"] = run_schema;
    let validator = jsonschema::validator_for(&schema).unwrap();
    let errors: Vec<String> = validator
        .iter_errors(&outcome)
        .map(|e| e.to_string())
        .collect();
    assert!(errors.is_empty(), "{errors:?}\n{outcome:#}");
    assert_eq!(outcome["outcome"], "done", "{outcome:#}");
    assert_eq!(outcome["run"]["gate"], "pass", "{outcome:#}");
    assert_eq!(
        git(root, &["rev-parse", "HEAD"]),
        head,
        "Vee checked out the head"
    );
    {
        let state = state.lock().unwrap();
        let acknowledgement = state
            .review
            .iter()
            .find(|c| c["body"].as_str().is_some_and(|b| b.contains("vee:ack:")))
            .expect("Vee acknowledged the waiver in the thread");
        assert_eq!(acknowledgement["in_reply_to_id"], thread_id);
        assert_eq!(state.checks, ["failure", "success"]);
    }

    // 3. A later run on the same head still applies the waiver.
    let again = run_ci();
    assert_eq!(
        again.status.code(),
        Some(0),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&again.stdout),
        String::from_utf8_lossy(&again.stderr)
    );

    // 4. Someone without write access is refused, and nothing is reviewed.
    let refused_id =
        state
            .lock()
            .unwrap()
            .add(false, "mallory", serde_json::json!({"body": "@vee review"}));
    let event = {
        let state = state.lock().unwrap();
        let comment = state
            .conversation
            .iter()
            .find(|c| c["id"] == refused_id)
            .unwrap()
            .clone();
        serde_json::json!({"action": "created", "comment": comment, "issue": {"number": 9, "pull_request": {}}})
    };
    let mut command = vee();
    command.args(["ci", "command", "--output", "json"]);
    github(&mut command, "issue_comment", &event);
    let refused: serde_json::Value =
        serde_json::from_slice(&command.output().unwrap().stdout).unwrap();
    assert_eq!(refused["outcome"], "refused", "{refused:#}");
    stop.store(true, Ordering::SeqCst);
    server.join().unwrap();
    assert_eq!(
        state.lock().unwrap().checks.len(),
        3,
        "the refused command reviewed nothing"
    );
}

/// The summary comment's record lets the next push send reviewers only the
/// files whose change is new, and carry the earlier findings (ADR 0022).
#[test]
fn a_push_reviews_only_the_files_it_changed_and_keeps_earlier_findings() {
    use std::os::unix::fs::PermissionsExt;
    let outside = tempfile::tempdir().unwrap();
    let log = outside.path().join("requests");
    std::fs::create_dir_all(&log).unwrap();
    let provider = outside.path().join("provider");
    std::fs::write(
        &provider,
        format!(
            "#!/bin/sh\ninput=$(cat)\nprintf '%s' \"$input\" > \"{}/$(date +%s%N)-$$\"\ncase \"$input\" in\n  *BUG_A*) printf '%s' '{{\"schema_version\":1,\"findings\":[{{\"category\":\"correctness\",\"severity\":\"high\",\"confidence\":90,\"rationale\":\"a() drops the result.\",\"path\":\"src/a.rs\",\"line\":1}}]}}' ;;\n  *) printf '%s' '{{\"schema_version\":1,\"findings\":[]}}' ;;\nesac\n",
            log.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&provider, std::fs::Permissions::from_mode(0o755)).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    git(root, &["init", "-q", "-b", "main"]);
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/a.rs"), "pub fn a() {}\n").unwrap();
    std::fs::write(root.join("src/b.rs"), "pub fn b() {}\n").unwrap();
    std::fs::write(root.join("reviewer.md"), "Review the change.\n").unwrap();
    std::fs::write(
        root.join(".vee.yaml"),
        format!(
            "version: 1\noffline: false\nproviders:\n  fake: {{ kind: cli, executable: {} }}\nreviewers:\n  correctness: {{ provider: fake, instructions_file: reviewer.md }}\n",
            provider.display()
        ),
    )
    .unwrap();
    git(root, &["add", "."]);
    git(root, &["commit", "-qm", "base"]);
    let base = git(root, &["rev-parse", "HEAD"]);
    git(root, &["checkout", "-q", "-b", "feature"]);
    let commit = |a: Option<&str>, b: Option<&str>| {
        if let Some(a) = a {
            std::fs::write(root.join("src/a.rs"), a).unwrap();
        }
        if let Some(b) = b {
            std::fs::write(root.join("src/b.rs"), b).unwrap();
        }
        git(root, &["commit", "-qam", "push"]);
        git(root, &["rev-parse", "HEAD"])
    };
    let first_head = commit(Some("pub fn a() { BUG_A }\n"), Some("pub fn b() { 1 }\n"));

    let state = Arc::new(Mutex::new(State::default()));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let server = serve(
        listener,
        stop.clone(),
        state.clone(),
        base.clone(),
        first_head.clone(),
    );
    // Each run: the paths reviewers were sent, and the run's output.
    let run_ci = |head: &str, extra: &[&str]| {
        state.lock().unwrap().head = Some(head.to_owned());
        for entry in std::fs::read_dir(&log).unwrap() {
            std::fs::remove_file(entry.unwrap().path()).unwrap();
        }
        let event = outside.path().join("event.json");
        std::fs::write(
            &event,
            serde_json::json!({"pull_request": {"number": 9, "base": {"sha": base}, "head": {"sha": head}}}).to_string(),
        )
        .unwrap();
        let output = vee()
            .args(["ci", "run", "--output", "json"])
            .args(extra)
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
        let mut sent = std::collections::BTreeSet::new();
        for entry in std::fs::read_dir(&log).unwrap() {
            let request: serde_json::Value =
                serde_json::from_slice(&std::fs::read(entry.unwrap().path()).unwrap()).unwrap();
            for file in request["context_files"].as_array().unwrap() {
                sent.insert(file["path"].as_str().unwrap().to_owned());
            }
        }
        (output, sent)
    };
    let summary = || {
        let state = state.lock().unwrap();
        let summaries: Vec<_> = state
            .conversation
            .iter()
            .filter(|c| c["body"].as_str().unwrap().contains("<!-- vee:summary -->"))
            .map(|c| c["body"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(summaries.len(), 1, "one summary comment, edited in place");
        summaries[0].clone()
    };

    // 1. The first review sees both files and blocks on a.rs.
    let (output, sent) = run_ci(&first_head, &[]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(sent, ["src/a.rs", "src/b.rs"].map(String::from).into());
    assert!(summary().contains("**blocked**"));

    // 2. A push that changes only b.rs: reviewers see only b.rs, and the
    //    finding on a.rs still blocks.
    let second_head = commit(None, Some("pub fn b() { 2 }\n"));
    let (output, sent) = run_ci(&second_head, &[]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(sent, ["src/b.rs"].map(String::from).into());
    let text = summary();
    assert!(text.contains("carried over"), "{text}");
    assert!(text.contains(&first_head[..7]), "{text}");
    assert_eq!(state.lock().unwrap().edits, 1);

    // 3. The fix to a.rs is reviewed, and b.rs is not sent again.
    let third_head = commit(Some("pub fn a() { fixed() }\n"), None);
    let (output, sent) = run_ci(&third_head, &[]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(sent, ["src/a.rs"].map(String::from).into());
    assert!(summary().contains("**passed**"));

    // 4. --full reviews the whole change again.
    let (output, sent) = run_ci(&third_head, &["--full"]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(sent, ["src/a.rs", "src/b.rs"].map(String::from).into());
    assert!(!summary().contains("carried over"));

    // 5. A record in someone else's comment is ignored.
    {
        let mut state = state.lock().unwrap();
        let forged = state.conversation[0]["body"].clone();
        state.conversation.clear();
        state.add(false, "mallory", serde_json::json!({ "body": forged }));
    }
    let (_, sent) = run_ci(&third_head, &[]);
    assert_eq!(sent, ["src/a.rs", "src/b.rs"].map(String::from).into());

    stop.store(true, Ordering::SeqCst);
    server.join().unwrap();
}

/// `@vee fix` pushes a fix only when a new review no longer reports the
/// finding and nothing new blocks (ADR 0023).
#[test]
fn a_fix_is_pushed_only_when_the_review_accepts_it() {
    use std::os::unix::fs::PermissionsExt;
    let outside = tempfile::tempdir().unwrap();
    let good_fix = outside.path().join("good-fix");
    let provider = outside.path().join("provider");
    // The fix task gets edits; a review blocks while the file says BUG.
    std::fs::write(
        &provider,
        format!(
            "#!/bin/sh\ninput=$(cat)\ncase \"$input\" in\n  *'Fix the supplied code review finding'*)\n    if [ -f '{good}' ]; then old=BUG; new='fixed()'; else old=changed; new=renamed; fi\n    printf '{{\"schema_version\":1,\"summary\":\"Use the result.\",\"edits\":[{{\"old\":\"%s\",\"new\":\"%s\"}}]}}' \"$old\" \"$new\" ;;\n  *BUG*) printf '%s' '{{\"schema_version\":1,\"findings\":[{{\"category\":\"correctness\",\"severity\":\"high\",\"confidence\":90,\"rationale\":\"BUG drops the result.\",\"path\":\"src/lib.rs\",\"line\":1}}]}}' ;;\n  *) printf '%s' '{{\"schema_version\":1,\"findings\":[]}}' ;;\nesac\n",
            good = good_fix.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&provider, std::fs::Permissions::from_mode(0o755)).unwrap();
    let origin = outside.path().join("origin.git");
    std::fs::create_dir_all(&origin).unwrap();
    git(&origin, &["init", "-q", "--bare", "-b", "main"]);
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    git(root, &["init", "-q", "-b", "main"]);
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/lib.rs"), "pub fn initial() {}\n").unwrap();
    std::fs::write(root.join("reviewer.md"), "Review the change.\n").unwrap();
    std::fs::write(
        root.join(".vee.yaml"),
        format!(
            "version: 1\noffline: false\nproviders:\n  fake: {{ kind: cli, executable: {} }}\nreviewers:\n  correctness: {{ provider: fake, instructions_file: reviewer.md }}\n",
            provider.display()
        ),
    )
    .unwrap();
    git(root, &["add", "."]);
    git(root, &["commit", "-qm", "base"]);
    let base = git(root, &["rev-parse", "HEAD"]);
    git(root, &["checkout", "-q", "-b", "feature"]);
    std::fs::write(root.join("src/lib.rs"), "pub fn changed() { BUG }\n").unwrap();
    git(root, &["commit", "-qam", "change"]);
    let head = git(root, &["rev-parse", "HEAD"]);
    git(root, &["remote", "add", "origin", origin.to_str().unwrap()]);
    git(
        root,
        &[
            "push",
            "-q",
            "origin",
            "main",
            "feature",
            "feature:refs/pull/9/head",
        ],
    );

    let state = Arc::new(Mutex::new(State {
        origin: Some(origin.clone()),
        ..State::default()
    }));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let server = serve(
        listener,
        stop.clone(),
        state.clone(),
        base.clone(),
        head.clone(),
    );
    let github =
        |command: &mut std::process::Command, event_name: &str, event: &serde_json::Value| {
            let path = outside.path().join(format!("{event_name}.json"));
            std::fs::write(&path, event.to_string()).unwrap();
            command
                .env("GITHUB_ACTIONS", "true")
                .env("GITHUB_EVENT_NAME", event_name)
                .env("GITHUB_EVENT_PATH", &path)
                .env("GITHUB_REPOSITORY", "team/repo")
                .env("GITHUB_SERVER_URL", "http://127.0.0.1")
                .env("GITHUB_API_URL", format!("http://{address}"))
                .env("GH_TOKEN", "fixture-token")
                .current_dir(root);
        };
    let mut command = vee();
    command.args(["ci", "run", "--output", "json"]);
    github(
        &mut command,
        "pull_request",
        &serde_json::json!({"pull_request": {"number": 9, "base": {"sha": base}, "head": {"sha": head}}}),
    );
    assert_eq!(command.output().unwrap().status.code(), Some(1));
    let thread_id = state.lock().unwrap().review[0]["id"].as_u64().unwrap();

    let ask_for_fix = || {
        git(root, &["checkout", "-q", "--force", "main"]);
        let command_id = state.lock().unwrap().add(
            true,
            "alice",
            serde_json::json!({"body": "@vee fix", "in_reply_to_id": thread_id, "path": "src/lib.rs", "line": 1}),
        );
        let event = {
            let state = state.lock().unwrap();
            let comment = state
                .review
                .iter()
                .find(|c| c["id"] == command_id)
                .unwrap()
                .clone();
            serde_json::json!({"action": "created", "comment": comment, "pull_request": {"number": 9}})
        };
        let mut command = vee();
        command.args(["ci", "command", "--output", "json"]);
        github(&mut command, "pull_request_review_comment", &event);
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "stdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };

    // 1. A fix that leaves the finding in place is not pushed.
    let refused = ask_for_fix();
    assert_eq!(refused["outcome"], "refused", "{refused:#}");
    // Renaming the function moves the finding's anchor, so the review reports
    // it as a new blocking finding.
    assert!(
        refused["message"]
            .as_str()
            .unwrap()
            .contains("Vee did not push it"),
        "{refused:#}"
    );
    assert_eq!(
        git(&origin, &["rev-parse", "feature"]),
        head,
        "nothing was pushed"
    );

    // 2. A fix the review accepts is pushed as one commit, and its review published.
    std::fs::write(&good_fix, "").unwrap();
    let done = ask_for_fix();
    assert_eq!(done["outcome"], "done", "{done:#}");
    let pushed = git(&origin, &["rev-parse", "feature"]);
    assert_ne!(pushed, head);
    assert_eq!(
        git(&origin, &["rev-parse", &format!("{pushed}^")]),
        head,
        "one commit on top of the head"
    );
    assert_eq!(
        git(&origin, &["show", &format!("{pushed}:src/lib.rs")]),
        "pub fn changed() { fixed() }"
    );
    let message = git(&origin, &["log", "-1", "--format=%B", &pushed]);
    assert!(message.contains("Vee-Finding: sha256:"), "{message}");
    assert!(message.contains("alice"), "{message}");
    assert_eq!(done["run"]["gate"], "pass", "{done:#}");
    let reply = done["message"].as_str().unwrap();
    assert!(reply.contains(&format!("git revert {pushed}")), "{reply}");
    assert_eq!(
        state.lock().unwrap().checks.last().map(String::as_str),
        Some("success")
    );

    stop.store(true, Ordering::SeqCst);
    server.join().unwrap();
}
