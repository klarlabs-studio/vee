//! The internal snapshot tool server, driven over stdio like a reviewer CLI.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};

fn git(root: &Path, args: &[&str]) {
    assert!(Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .status()
        .unwrap()
        .success());
}

#[test]
fn snapshot_server_serves_confined_reads_and_logs_every_call() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    git(root, &["init", "-q"]);
    git(root, &["config", "user.email", "vee@example.invalid"]);
    git(root, &["config", "user.name", "Vee test"]);
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("src/billing.rs"),
        "pub fn charge(cents: u64) {}\n",
    )
    .unwrap();
    std::fs::write(root.join("src/caller.rs"), "fn pay() { charge(1); }\n").unwrap();
    std::fs::write(root.join(".env"), "API_TOKEN=tracked-secret\n").unwrap();
    git(root, &["add", "."]);
    git(root, &["commit", "-qm", "initial"]);
    std::fs::write(root.join("src/caller.rs"), "fn pay() { charge(100); }\n").unwrap();
    let change_set = vee_git::capture(root, vee_git::ChangeScope::WorkingTree).unwrap();
    let spec = vee_application::exploration::ExplorationSpec::new(
        root,
        &change_set,
        &vee_core::ReviewConfig::default(),
    );
    let work = tempfile::tempdir().unwrap();
    let spec_path = work.path().join("spec.json");
    let log_path = work.path().join("calls.jsonl");
    std::fs::write(&spec_path, serde_json::to_vec(&spec).unwrap()).unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_vee"))
        .args(["mcp", "snapshot", "--spec"])
        .arg(&spec_path)
        .arg("--log")
        .arg(&log_path)
        // A reviewer CLI may start the server anywhere; reads still come
        // from the spec's repository snapshot.
        .current_dir(work.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let mut next_id = 0;
    let mut request = |method: &str, params: Value| -> Value {
        next_id += 1;
        writeln!(
            input,
            "{}",
            json!({"jsonrpc":"2.0","id":next_id,"method":method,"params":params})
        )
        .unwrap();
        input.flush().unwrap();
        let mut line = String::new();
        output.read_line(&mut line).unwrap();
        let response: Value = serde_json::from_str(&line).unwrap();
        assert!(response.get("error").is_none(), "{method}: {response}");
        response["result"].clone()
    };
    let initialized = request(
        "initialize",
        json!({"protocolVersion":"2025-06-18","capabilities":{},
            "clientInfo":{"name":"reviewer","version":"1"}}),
    );
    assert_eq!(
        initialized["serverInfo"]["name"],
        vee_core::EXPLORATION_SERVER_NAME
    );

    let tools = request("tools/list", json!({}));
    let mut names = tools["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(names, vee_core::EXPLORATION_TOOLS);
    assert!(tools["tools"]
        .as_array()
        .unwrap()
        .iter()
        .all(|tool| tool["annotations"]["readOnlyHint"] == true));

    let text = |result: Value| result["content"][0]["text"].as_str().unwrap().to_string();
    let billing = text(request(
        "tools/call",
        json!({"name":"read_file","arguments":{"path":"src/billing.rs"}}),
    ));
    assert!(
        billing.contains("1| pub fn charge(cents: u64) {}"),
        "{billing}"
    );
    let caller = text(request(
        "tools/call",
        json!({"name":"search","arguments":{"pattern":"charge(100)"}}),
    ));
    assert!(
        caller.contains("src/caller.rs:1:"),
        "changed file is searched as captured: {caller}"
    );
    let secret = text(request(
        "tools/call",
        json!({"name":"read_file","arguments":{"path":".env"}}),
    ));
    assert!(!secret.contains("tracked-secret"), "{secret}");
    let _ = child.kill();
    let _ = child.wait();

    let calls = std::fs::read_to_string(&log_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    let summary = calls
        .iter()
        .map(|call| {
            (
                call["tool"].as_str().unwrap(),
                call["outcome"].as_str().unwrap(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        summary,
        [
            ("read_file", "ok"),
            ("search", "ok"),
            ("read_file", "denied")
        ]
    );
    assert_eq!(calls[0]["paths"], json!(["src/billing.rs"]));
}
