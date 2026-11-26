//! `--work-item PROJ-5` reads a Jira issue when `.vee.yaml` names the
//! tracker, and the gate notices when the issue changes (ADR 0033).
#![cfg(unix)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

fn vee(root: &Path, args: &[&str]) -> std::process::Command {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_vee"));
    command
        .current_dir(root)
        .env("NO_COLOR", "1")
        .env("VEE_CONFIG", root.join("no-user-config.yaml"))
        .env("JIRA_API_TOKEN", "fixture-token")
        .env("JIRA_EMAIL", "dev@example.invalid")
        .args(args);
    command
}

fn git(root: &Path, args: &[&str]) {
    assert!(std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .status()
        .unwrap()
        .success());
}

/// Serves each body once, in order, recording the request lines.
fn fake_jira(bodies: Vec<String>) -> (String, std::thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let mut seen = Vec::new();
        for body in bodies {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut chunk = [0u8; 4096];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let count = stream.read(&mut chunk).unwrap();
                if count == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..count]);
            }
            let text = String::from_utf8_lossy(&request).to_string();
            seen.push(text);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        }
        seen
    });
    (format!("http://127.0.0.1:{}/", address.port()), server)
}

fn issue(criteria: &str, updated: &str) -> String {
    serde_json::json!({
        "key": "PROJ-5",
        "fields": {
            "summary": "Keep the export format",
            "description": "Exports must stay compatible.",
            "status": {"name": "In Progress"},
            "updated": updated,
            "labels": ["export"],
            "customfield_10050": criteria
        }
    })
    .to_string()
}

#[test]
fn a_jira_work_item_is_read_traced_and_revalidated_by_the_gate() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let outside = tempfile::tempdir().unwrap();
    let provider = outside.path().join("provider");
    std::fs::write(
        &provider,
        "#!/bin/sh\ncat >/dev/null\nprintf '%s' '{\"schema_version\":1,\"findings\":[]}'\n",
    )
    .unwrap();
    std::fs::set_permissions(&provider, std::fs::Permissions::from_mode(0o755)).unwrap();
    git(root, &["init", "-q"]);
    git(root, &["config", "user.email", "vee@example.invalid"]);
    git(root, &["config", "user.name", "Vee test"]);
    std::fs::write(root.join("export.rs"), "fn export() {}\n").unwrap();
    std::fs::write(root.join("reviewer.md"), "Review the change.\n").unwrap();
    git(root, &["add", "."]);
    git(root, &["commit", "-qm", "initial"]);
    std::fs::write(root.join("export.rs"), "fn export() { let _ = 1; }\n").unwrap();

    let (api_base, server) = fake_jira(vec![
        issue("* Keep format v1", "2026-11-26T10:00:00.000+0000"),
        issue("* Keep format v2", "2026-11-26T10:05:00.000+0000"),
    ]);
    std::fs::write(
        root.join(".vee.yaml"),
        format!(
            "version: 1\nproviders:\n  fake: {{ kind: cli, executable: {} }}\nreviewers:\n  correctness: {{ provider: fake, instructions_file: reviewer.md }}\nwork_items: {{ provider: jira, host: 127.0.0.1, api_base: \"{api_base}\", acceptance_field: customfield_10050 }}\npolicy:\n  required_reviewers: [correctness]\n  block_severities: [high]\n  minimum_confidence: 80\n  on_incomplete: block\n",
            provider.display()
        ),
    )
    .unwrap();

    // The repository configuration alone may not send the token to a site.
    let refused = vee(root, &["review", "--working-tree", "--work-item", "PROJ-5"])
        .output()
        .unwrap();
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("VEE_HOSTING_HOSTS"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );

    let review = vee(
        root,
        &[
            "review",
            "--working-tree",
            "--gate",
            "--output",
            "json",
            "--work-item",
            "PROJ-5",
        ],
    )
    .env("VEE_HOSTING_HOSTS", "127.0.0.1")
    .output()
    .unwrap();
    assert_eq!(
        review.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&review.stderr)
    );
    let review: serde_json::Value = serde_json::from_slice(&review.stdout).unwrap();
    assert_eq!(review["work_item"]["provider"], "jira");
    assert_eq!(
        review["work_item"]["acceptance_criteria"],
        "* Keep format v1"
    );
    let review_id = review["review_id"].as_str().unwrap();

    let acceptance = vee(
        root,
        &[
            "acceptance",
            "report",
            "--review",
            review_id,
            "--output",
            "json",
        ],
    )
    .output()
    .unwrap();
    assert!(
        acceptance.status.success(),
        "{}",
        String::from_utf8_lossy(&acceptance.stderr)
    );
    let acceptance: serde_json::Value = serde_json::from_slice(&acceptance.stdout).unwrap();
    assert_eq!(acceptance["criteria"][0]["text"], "Keep format v1");

    // The issue changed since the review: the gate no longer trusts it.
    let gate = vee(
        root,
        &["gate", "check", "--review", review_id, "--output", "json"],
    )
    .env("VEE_HOSTING_HOSTS", "127.0.0.1")
    .output()
    .unwrap();
    assert_eq!(
        gate.status.code(),
        Some(2),
        "{}{}",
        String::from_utf8_lossy(&gate.stdout),
        String::from_utf8_lossy(&gate.stderr)
    );
    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with("GET /rest/api/2/issue/PROJ-5?fields="));
    assert!(requests[0]
        .to_ascii_lowercase()
        .contains("authorization: basic "));
}
