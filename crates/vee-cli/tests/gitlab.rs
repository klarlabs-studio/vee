//! `vee ci run` on a GitLab merge request: the status, labels and Vee's
//! summary note with its review record, kept across runs (ADR 0030).
#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

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

#[derive(Default)]
struct State {
    discussions: Vec<serde_json::Value>,
    labels: Vec<String>,
    requests: Vec<String>,
    next_id: u64,
}

/// A GitLab that holds one merge request's discussions and labels.
fn fake_gitlab(
    listener: TcpListener,
    stop: Arc<AtomicBool>,
    base: String,
    head: String,
    diff: String,
    state: Arc<Mutex<State>>,
) -> std::thread::JoinHandle<()> {
    listener.set_nonblocking(true).unwrap();
    std::thread::spawn(move || {
        while !stop.load(Ordering::SeqCst) {
            let stream = match listener.accept() {
                Ok((stream, _)) => stream,
                Err(_) => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                    continue;
                }
            };
            stream.set_nonblocking(false).unwrap();
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let mut length = 0usize;
            loop {
                let mut header = String::new();
                reader.read_line(&mut header).unwrap();
                if header.trim().is_empty() {
                    break;
                }
                if let Some(value) = header.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse().unwrap();
                }
            }
            let mut body = vec![0u8; length];
            reader.read_exact(&mut body).unwrap();
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
            let mut parts = line.split_whitespace();
            let method = parts.next().unwrap_or_default().to_owned();
            let target = parts.next().unwrap_or_default().to_owned();
            let path = target.split('?').next().unwrap_or_default().to_owned();
            let mut state = state.lock().unwrap();
            state.requests.push(format!("{method} {target} {body}"));
            let project = "/api/v4/projects/group%2Fapp";
            let request = format!("{project}/merge_requests/9");
            let reply = match (method.as_str(), path.as_str()) {
                ("GET", "/api/v4/user") => serde_json::json!({"username": "vee-bot"}),
                ("GET", p) if p == request => serde_json::json!({
                    "iid": 9, "title": "Change", "description": "", "state": "opened",
                    "sha": head, "source_branch": "feature",
                    "source_project_id": 1, "target_project_id": 1,
                    "labels": state.labels,
                    "diff_refs": {"base_sha": base, "start_sha": base, "head_sha": head}
                }),
                ("PUT", p) if p == request => {
                    let split = |key: &str| -> Vec<String> {
                        body[key]
                            .as_str()
                            .unwrap_or_default()
                            .split(',')
                            .filter(|label| !label.is_empty())
                            .map(str::to_owned)
                            .collect()
                    };
                    let (add, remove) = (split("add_labels"), split("remove_labels"));
                    state.labels.retain(|label| !remove.contains(label));
                    state.labels.extend(add);
                    serde_json::json!({})
                }
                ("GET", p) if p == format!("{request}/diffs") => serde_json::json!([{
                    "old_path": "src/lib.rs", "new_path": "src/lib.rs", "diff": diff,
                    "new_file": false, "deleted_file": false, "renamed_file": false
                }]),
                ("GET", p) if p == format!("{request}/notes") => serde_json::json!([]),
                ("GET", p) if p == format!("{request}/discussions") => {
                    serde_json::Value::Array(state.discussions.clone())
                }
                ("POST", p) if p == format!("{request}/discussions") => {
                    state.next_id += 1;
                    let id = state.next_id;
                    let discussion = serde_json::json!({
                        "id": format!("d{id}"),
                        "notes": [{
                            "id": id, "system": false, "body": body["body"],
                            "created_at": "2026-11-26T10:00:00Z",
                            "author": {"username": "vee-bot", "bot": true},
                            "position": body.get("position").cloned().unwrap_or(serde_json::Value::Null)
                        }]
                    });
                    state.discussions.push(discussion.clone());
                    discussion
                }
                ("PUT", p)
                    if p.starts_with(&format!("{request}/discussions/"))
                        && p.contains("/notes/") =>
                {
                    let note: u64 = p.rsplit('/').next().unwrap().parse().unwrap();
                    for discussion in &mut state.discussions {
                        for stored in discussion["notes"].as_array_mut().unwrap() {
                            if stored["id"] == note {
                                stored["body"] = body["body"].clone();
                            }
                        }
                    }
                    serde_json::json!({"id": note})
                }
                ("GET", p) if p.starts_with(&format!("{project}/repository/commits/")) => {
                    serde_json::json!([])
                }
                ("POST", p) if p.starts_with(&format!("{project}/statuses/")) => {
                    serde_json::json!({"id": 77})
                }
                _ => serde_json::Value::Null,
            };
            let (status, text) = if reply.is_null() {
                ("404 Not Found", "{}".to_owned())
            } else {
                ("200 OK", reply.to_string())
            };
            let mut stream = reader.into_inner();
            let _ = write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
                text.len()
            );
        }
    })
}

#[test]
fn ci_run_on_gitlab_keeps_its_summary_record_and_labels() {
    use std::os::unix::fs::PermissionsExt;
    let outside = tempfile::tempdir().unwrap();
    let provider = outside.path().join("provider");
    std::fs::write(
        &provider,
        "#!/bin/sh\ncat >/dev/null\nprintf '%s' '{\"schema_version\":1,\"findings\":[]}'\n",
    )
    .unwrap();
    std::fs::set_permissions(&provider, std::fs::Permissions::from_mode(0o755)).unwrap();

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
    git(root, &["checkout", "-q", "--detach", &head]);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let state = Arc::new(Mutex::new(State::default()));
    let server = fake_gitlab(
        listener,
        stop.clone(),
        base.clone(),
        head.clone(),
        "@@ -1 +1 @@\n-pub fn initial() {}\n+pub fn changed() {}\n".into(),
        state.clone(),
    );
    let run = || {
        std::process::Command::new(env!("CARGO_BIN_EXE_vee"))
            .args(["ci", "run", "--labels", "--output", "json"])
            .current_dir(root)
            .env("NO_COLOR", "1")
            .env("VEE_CONFIG", outside.path().join("no-user-config.yaml"))
            .env_remove("GITHUB_ACTIONS")
            .env("GITLAB_CI", "true")
            .env("CI_MERGE_REQUEST_IID", "9")
            .env("CI_SERVER_URL", "http://127.0.0.1")
            .env("CI_API_V4_URL", format!("http://{address}/api/v4"))
            .env("CI_PROJECT_PATH", "group/app")
            .env("CI_MERGE_REQUEST_DIFF_BASE_SHA", &base)
            .env("CI_COMMIT_SHA", &head)
            .env("GL_TOKEN", "fixture-token")
            .output()
            .unwrap()
    };
    let first = run();
    let summaries = |state: &State| {
        state
            .discussions
            .iter()
            .filter(|discussion| {
                discussion["notes"][0]["body"]
                    .as_str()
                    .is_some_and(|body| body.contains("<!-- vee:summary -->"))
            })
            .count()
    };
    {
        let state = state.lock().unwrap();
        assert!(
            first.status.success(),
            "stdout={}\nstderr={}\nrequests={:#?}",
            String::from_utf8_lossy(&first.stdout),
            String::from_utf8_lossy(&first.stderr),
            state.requests
        );
        assert_eq!(summaries(&state), 1, "{:#?}", state.requests);
        let summary = state.discussions[0]["notes"][0]["body"].as_str().unwrap();
        assert!(summary.contains("<!-- vee:record:"), "{summary}");
        assert!(
            state.labels.contains(&"vee:gate:pass".to_owned()),
            "{:?}",
            state.labels
        );
        assert!(state
            .requests
            .iter()
            .any(|request| request.starts_with("POST /api/v4/projects/group%2Fapp/statuses/")));
    }
    let report: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    assert!(report["labels"]
        .as_array()
        .unwrap()
        .iter()
        .any(|label| label == "vee:gate:pass"));

    // The next run finds its own summary, by the token's user, and edits it.
    let second = run();
    stop.store(true, Ordering::SeqCst);
    server.join().unwrap();
    let state = state.lock().unwrap();
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert_eq!(summaries(&state), 1, "{:#?}", state.requests);
    assert!(
        state.requests.iter().any(|request| request
            .starts_with("PUT /api/v4/projects/group%2Fapp/merge_requests/9/discussions/d")),
        "{:#?}",
        state.requests
    );
}
