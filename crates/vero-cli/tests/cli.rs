use std::{fs, process::Command};

fn assert_matches_schema(value: &serde_json::Value, schema_json: &str, contract: &str) {
    let schema: serde_json::Value = serde_json::from_str(schema_json)
        .unwrap_or_else(|error| panic!("{contract} schema is invalid: {error}"));
    let registry = jsonschema::Registry::new()
        .add(
            "https://vero.dev/schemas/verification-run-v1.schema.json",
            serde_json::from_str::<serde_json::Value>(include_str!(
                "../../../schemas/verification-run-v1.schema.json"
            ))
            .unwrap(),
        )
        .unwrap()
        .add(
            "https://vero.dev/schemas/gate-decision-v1.schema.json",
            serde_json::from_str::<serde_json::Value>(include_str!(
                "../../../schemas/gate-decision-v1.schema.json"
            ))
            .unwrap(),
        )
        .unwrap()
        .add(
            "https://vero.dev/schemas/evidence-v1.schema.json",
            serde_json::from_str::<serde_json::Value>(include_str!(
                "../../../schemas/evidence-v1.schema.json"
            ))
            .unwrap(),
        )
        .unwrap()
        .add(
            "https://vero.dev/schemas/waiver-v1.schema.json",
            serde_json::from_str::<serde_json::Value>(include_str!(
                "../../../schemas/waiver-v1.schema.json"
            ))
            .unwrap(),
        )
        .unwrap()
        .prepare()
        .unwrap();
    let validator = jsonschema::options()
        .with_registry(&registry)
        .build(&schema)
        .unwrap_or_else(|error| panic!("{contract} schema cannot be compiled: {error}"));
    let errors = validator
        .iter_errors(value)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    assert!(
        errors.is_empty(),
        "{contract} violates its schema: {errors:#?}"
    );
}

#[test]
fn repository_config_schema_accepts_initialized_and_configured_examples() {
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/repository-config-v1.schema.json"
    ))
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let init = Command::new(env!("CARGO_BIN_EXE_vero"))
        .current_dir(directory.path())
        .arg("init")
        .output()
        .unwrap();
    assert!(init.status.success());
    let initialized_yaml = fs::read_to_string(directory.path().join(".vero.yaml")).unwrap();
    let initialized = serde_yaml::from_str::<serde_json::Value>(&initialized_yaml).unwrap();
    let configured = serde_yaml::from_str::<serde_json::Value>(
        "version: 1\noffline: false\nreview:\n  max_concurrency: 4\nproviders:\n  codex: { kind: codex_cli, egress: network, executable: codex, model: gpt-5-codex, env_allowlist: [PATH, HOME] }\nreviewers:\n  correctness: { provider: codex, instructions_file: .vero/reviewers/correctness.md, include: [src/**/*.rs] }\nverification:\n  unit: { executable: cargo, args: [test], timeout_seconds: 120, output_limit_bytes: 65536, env_allowlist: [PATH] }\npolicy:\n  required_reviewers: [correctness]\n  required_verifications: [unit]\n  block_severities: [critical, high]\n  minimum_confidence: 80\n  on_incomplete: block\npolicy_profiles:\n  strict:\n    required_reviewers: [correctness]\n    block_severities: [critical, high, medium]\n    minimum_confidence: 90\n    on_incomplete: block\n",
    )
    .unwrap();

    assert!(validator.is_valid(&initialized));
    assert!(validator.is_valid(&configured));
    let api_config = serde_yaml::from_str::<serde_json::Value>(
        "version: 1\noffline: true\nproviders:\n  local:\n    kind: openai_compatible\n    egress: local\n    endpoint: http://127.0.0.1:11434/v1/chat/completions\n    model: qwen-local\n    env_allowlist: [OPENAI_API_KEY]\n",
    )
    .unwrap();
    assert!(validator.is_valid(&api_config));
    let api_yaml = serde_yaml::to_string(&api_config).unwrap();
    fs::write(directory.path().join("api.yaml"), api_yaml).unwrap();
    assert!(vero_core::RepositoryConfig::load(&directory.path().join("api.yaml")).is_ok());
    assert!(vero_core::RepositoryConfig::load(&directory.path().join(".vero.yaml")).is_ok());
    let parsed = serde_yaml::from_str::<vero_core::RepositoryConfig>(
        &serde_yaml::to_string(&configured).unwrap(),
    );
    assert!(
        parsed.is_ok(),
        "schema fixture must also match domain config: {parsed:?}"
    );
    let invalid =
        serde_yaml::from_str::<serde_json::Value>("version: 1\nreview:\n  max_concurrency: 33\n")
            .unwrap();
    assert!(!validator.is_valid(&invalid));
}

#[cfg(unix)]
#[test]
fn configured_openai_compatible_local_provider_runs_through_review_and_gate() {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("repo");
    fs::create_dir_all(&root).unwrap();
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(&root)
            .args(args)
            .output()
            .unwrap()
    };
    assert!(Command::new("git")
        .arg("init")
        .arg("-q")
        .arg(&root)
        .status()
        .unwrap()
        .success());
    assert!(git(&["config", "user.email", "vero@example.invalid"])
        .status
        .success());
    assert!(git(&["config", "user.name", "Vero test"]).status.success());
    fs::write(root.join("tracked.rs"), "fn main() {}\n").unwrap();
    assert!(git(&["add", "tracked.rs"]).status.success());
    assert!(git(&["commit", "-qm", "initial"]).status.success());
    fs::write(root.join("tracked.rs"), "fn main() { let value = 1; }\n").unwrap();
    fs::write(root.join("reviewer.md"), "Check correctness.\n").unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!(
        "http://{}/v1/chat/completions",
        listener.local_addr().unwrap()
    );
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        let mut chunk = [0; 4096];
        loop {
            let read = stream.read(&mut chunk).unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);
            if let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&request[..header_end]);
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .and_then(|value| value.parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                if request.len() >= header_end + 4 + content_length {
                    break;
                }
            }
        }
        let split = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap()
            + 4;
        let body: serde_json::Value = serde_json::from_slice(&request[split..]).unwrap();
        assert_eq!(body["model"], "local-test-model");
        assert_eq!(body["response_format"]["type"], "json_schema");
        let result =
            br#"{"choices":[{"message":{"content":"{\"schema_version\":1,\"findings\":[]}"}}]}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            result.len()
        )
        .unwrap();
        stream.write_all(result).unwrap();
    });
    fs::write(root.join(".vero.yaml"), format!("version: 1\noffline: true\nproviders:\n  local:\n    kind: openai_compatible\n    egress: local\n    endpoint: {endpoint}\n    model: local-test-model\nreviewers:\n  correctness:\n    provider: local\n    instructions_file: reviewer.md\npolicy:\n  required_reviewers: [correctness]\n  on_incomplete: block\n")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_vero"))
        .args(["review", "--working-tree", "--gate", "--output", "json"])
        .current_dir(&root)
        .output()
        .unwrap();
    server.join().unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let review: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(review["gate"]["status"], "pass");
    assert_eq!(
        review["reviewer_outcomes"][0]["provider_kind"],
        "openai_compatible"
    );
    assert_eq!(review["reviewer_outcomes"][0]["status"], "completed");
}

#[test]
fn provider_findings_schema_matches_the_versioned_output_contract() {
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/provider-findings-v1.schema.json"
    ))
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let valid = serde_json::json!({
        "schema_version": 1,
        "findings": [{
            "category": "correctness",
            "severity": "high",
            "confidence": 90,
            "rationale": "The bounds check permits an out of range access.",
            "path": "src/lib.rs",
            "line": 12
        }]
    });
    let forged_identity = serde_json::json!({
        "schema_version": 1,
        "findings": [{
            "id": "forged",
            "category": "correctness",
            "severity": "high",
            "rationale": "bug"
        }]
    });
    assert!(validator.is_valid(&valid));
    assert!(!validator.is_valid(&forged_identity));
}

#[test]
fn gated_review_with_no_reviewer_is_incomplete_and_persisted() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap()
    };
    assert!(Command::new("git")
        .arg("init")
        .arg("-q")
        .arg(root)
        .status()
        .unwrap()
        .success());
    assert!(git(&["config", "user.email", "vero@example.invalid"])
        .status
        .success());
    assert!(git(&["config", "user.name", "Vero test"]).status.success());
    fs::write(root.join("tracked.rs"), "fn main() {}\n").unwrap();
    assert!(git(&["add", "tracked.rs"]).status.success());
    assert!(git(&["commit", "-qm", "initial"]).status.success());
    fs::write(root.join(".vero.yaml"), "version: 1\n").unwrap();
    fs::write(root.join("tracked.rs"), "fn main() { let _x = 1; }\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_vero"))
        .arg("review")
        .arg("--gate")
        .arg("--output")
        .arg("json")
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["status"], "incomplete");
    assert_eq!(value["selected_reviewers"], serde_json::json!([]));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Review "));
    assert!(stderr.contains("Status: incomplete"));
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/review-output-v2.schema.json"
    ))
    .unwrap();
    let verification_schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/verification-run-v1.schema.json"
    ))
    .unwrap();
    let evidence_schema: serde_json::Value = serde_json::from_str::<serde_json::Value>(
        include_str!("../../../schemas/evidence-v1.schema.json"),
    )
    .unwrap();
    let gate_schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/gate-decision-v1.schema.json"
    ))
    .unwrap();
    let registry = jsonschema::Registry::new()
        .add(
            "https://vero.dev/schemas/verification-run-v1.schema.json",
            verification_schema,
        )
        .unwrap()
        .add(
            "https://vero.dev/schemas/evidence-v1.schema.json",
            evidence_schema,
        )
        .unwrap()
        .add(
            "https://vero.dev/schemas/gate-decision-v1.schema.json",
            gate_schema,
        )
        .unwrap()
        .prepare()
        .unwrap();
    assert!(jsonschema::options()
        .with_registry(&registry)
        .build(&schema)
        .unwrap()
        .is_valid(&value));
    assert!(root.join(".vero/vero.sqlite").exists());
}

#[test]
fn json_mode_emits_versioned_error_document_for_invalid_configuration() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap()
    };
    assert!(Command::new("git")
        .args(["init", "-q"])
        .arg(root)
        .status()
        .unwrap()
        .success());
    assert!(git(&["config", "user.email", "vero@example.invalid"])
        .status
        .success());
    assert!(git(&["config", "user.name", "Vero test"]).status.success());
    fs::write(root.join("source.rs"), "fn main() {}\n").unwrap();
    assert!(git(&["add", "source.rs"]).status.success());
    assert!(git(&["commit", "-qm", "initial"]).status.success());
    fs::write(root.join(".vero.yaml"), "version: [invalid\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_vero"))
        .args(["review", "--working-tree", "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(3));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["error"]["code"], "configuration_error");
    assert!(!value["error"]["message"].as_str().unwrap().is_empty());
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../schemas/cli-error-v1.schema.json")).unwrap();
    assert!(jsonschema::validator_for(&schema).unwrap().is_valid(&value));
    assert!(output.stderr.is_empty());
}

#[test]
fn json_mode_emits_versioned_error_document_for_invalid_invocation() {
    let output = Command::new(env!("CARGO_BIN_EXE_vero"))
        .args(["review", "--output", "json", "--not-a-review-option"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(3));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["error"]["code"], "usage_error");
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../schemas/cli-error-v1.schema.json")).unwrap();
    assert!(jsonschema::validator_for(&schema).unwrap().is_valid(&value));
    assert!(output.stderr.is_empty());
}

#[test]
fn json_mode_maps_repository_execution_failure_to_exit_code_two() {
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_vero"))
        .args(["review", "--working-tree", "--output", "json"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["error"]["code"], "execution_failed");
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../schemas/cli-error-v1.schema.json")).unwrap();
    assert!(jsonschema::validator_for(&schema).unwrap().is_valid(&value));
    assert!(output.stderr.is_empty());
}

#[test]
fn top_level_help_is_a_successful_cli_invocation() {
    let output = Command::new(env!("CARGO_BIN_EXE_vero"))
        .arg("--help")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stdout).contains("Usage:"));
    assert!(output.stderr.is_empty());
}

#[test]
fn gate_check_unknown_review_is_a_usage_error() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    assert!(Command::new("git")
        .args(["init", "-q"])
        .arg(root)
        .status()
        .unwrap()
        .success());
    fs::write(root.join("tracked.txt"), "baseline\n").unwrap();
    assert!(Command::new("git")
        .args(["-C", root.to_str().unwrap(), "add", "tracked.txt"])
        .status()
        .unwrap()
        .success());
    assert!(Command::new("git")
        .args([
            "-C",
            root.to_str().unwrap(),
            "-c",
            "user.name=Vero test",
            "-c",
            "user.email=vero@example.invalid",
            "commit",
            "-qm",
            "initial",
        ])
        .status()
        .unwrap()
        .success());
    fs::create_dir_all(root.join(".vero")).unwrap();
    vero_core::ReviewStore::open(&root.join(".vero/vero.sqlite")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_vero"))
        .args([
            "gate",
            "check",
            "--review",
            "rev_missing",
            "--output",
            "json",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["error"]["code"], "usage_error");
}

#[test]
fn review_commit_uses_the_selected_commit_tree_not_dirty_worktree() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap()
    };
    assert!(Command::new("git")
        .args(["init", "-q"])
        .arg(root)
        .status()
        .unwrap()
        .success());
    assert!(git(&["config", "user.email", "vero@example.invalid"])
        .status
        .success());
    assert!(git(&["config", "user.name", "Vero test"]).status.success());
    fs::write(root.join("source.rs"), "fn original() {}\n").unwrap();
    assert!(git(&["add", "source.rs"]).status.success());
    assert!(git(&["commit", "-qm", "initial"]).status.success());
    fs::write(root.join("source.rs"), "fn committed() {}\n").unwrap();
    assert!(git(&["add", "source.rs"]).status.success());
    assert!(git(&["commit", "-qm", "selected commit"]).status.success());
    fs::write(root.join(".vero.yaml"), "version: 1\n").unwrap();
    let selected_oid = String::from_utf8(git(&["rev-parse", "HEAD"]).stdout)
        .unwrap()
        .trim()
        .to_owned();
    fs::write(root.join("source.rs"), "fn dirty_worktree() {}\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_vero"))
        .args(["review", "--commit", "HEAD~1..HEAD", "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();

    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["change_set"]["head_oid"], selected_oid);
    assert_eq!(
        value["change_set"]["scope"],
        format!(
            "commit_range:{}..{selected_oid}",
            value["change_set"]["base_oid"].as_str().unwrap()
        )
    );
    assert_eq!(
        value["change_set"]["files"][0]["content_digest"],
        vero_core::digest(b"fn committed() {}\n")
    );
}

#[test]
fn protected_policy_requires_configured_reviewer_even_if_repository_policy_omits_it() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap()
    };
    assert!(Command::new("git")
        .args(["init", "-q"])
        .arg(root)
        .status()
        .unwrap()
        .success());
    assert!(git(&["config", "user.email", "vero@example.invalid"])
        .status
        .success());
    assert!(git(&["config", "user.name", "Vero test"]).status.success());
    fs::write(root.join("source.rs"), "fn main() {}\n").unwrap();
    assert!(git(&["add", "source.rs"]).status.success());
    assert!(git(&["commit", "-qm", "initial"]).status.success());
    fs::create_dir_all(root.join(".vero")).unwrap();
    fs::write(
        root.join(".vero.yaml"),
        r#"
version: 1
providers:
  local: { kind: cli, executable: /bin/true }
reviewers:
  correctness: { provider: local, instructions_file: reviewer.md, enabled: false }
policy:
  required_reviewers: []
  on_incomplete: allow
"#,
    )
    .unwrap();
    fs::write(root.join("reviewer.md"), "Check correctness.").unwrap();
    fs::write(
        root.join(".vero/policy.yaml"),
        "required_reviewers: [correctness]\non_incomplete: block\n",
    )
    .unwrap();
    fs::write(root.join("source.rs"), "fn main() { let _x = 1; }\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_vero"))
        .args(["review", "--gate", "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["status"], "incomplete");
}

#[test]
fn impact_cli_emits_snapshot_bound_evidence_paths() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap()
    };
    assert!(Command::new("git")
        .args(["init", "-q"])
        .arg(root)
        .status()
        .unwrap()
        .success());
    assert!(git(&["config", "user.email", "vero@example.invalid"])
        .status
        .success());
    assert!(git(&["config", "user.name", "Vero test"]).status.success());
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(root.join("src/lib.rs"), "pub fn changed_api() {}\n").unwrap();
    fs::write(
        root.join("src/caller.rs"),
        "fn caller() { changed_api(); }\n",
    )
    .unwrap();
    git(&["add", "."]);
    assert!(git(&["commit", "-qm", "initial"]).status.success());
    fs::write(
        root.join("src/lib.rs"),
        "pub fn changed_api() { assert!(true); }\n",
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_vero"))
        .args(["impact", "--working-tree", "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();

    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let impact: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/impact-assessment-v1.schema.json"
    ))
    .unwrap();
    assert!(jsonschema::validator_for(&schema)
        .unwrap()
        .is_valid(&impact));
    assert_eq!(impact["schema_version"], 1);
    assert_eq!(impact["changed_paths"][0], "src/lib.rs");
    assert!(impact["paths"]
        .as_array()
        .unwrap()
        .iter()
        .any(|edge| edge["affected_path"] == "src/caller.rs" && edge["evidence_line"] == 1));
}

#[cfg(unix)]
#[test]
fn mcp_stdio_exposes_findings_tool_over_the_pinned_protocol() {
    use mcp_rs::client::Client;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap()
    };
    assert!(Command::new("git")
        .args(["init", "-q"])
        .arg(root)
        .status()
        .unwrap()
        .success());
    assert!(git(&["config", "user.email", "vero@example.invalid"])
        .status
        .success());
    assert!(git(&["config", "user.name", "Vero test"]).status.success());
    fs::write(root.join("tracked.rs"), "fn main() {}\n").unwrap();
    assert!(git(&["add", "tracked.rs"]).status.success());
    assert!(git(&["commit", "-qm", "initial"]).status.success());
    fs::write(root.join("tracked.rs"), "fn second_commit() {}\n").unwrap();
    fs::write(root.join("large.txt"), "x".repeat(100)).unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("secret.txt"), "outside secret").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(outside.path(), root.join("outside-link")).unwrap();
    assert!(git(&["add", "tracked.rs"]).status.success());
    assert!(git(&["commit", "-qm", "second"]).status.success());
    fs::write(
        root.join(".vero.yaml"),
        "version: 1\npolicy_profiles:\n  strict:\n    minimum_confidence: 93\n",
    )
    .unwrap();
    fs::create_dir_all(root.join(".vero")).unwrap();
    let db = vero_core::ReviewStore::open(&root.join(".vero/vero.sqlite")).unwrap();
    drop(db);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async move {
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_vero"));
        command
            .args(["mcp", "serve", "--transport", "stdio"])
            .current_dir(root)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let transport =
            mcp_rs::protocol::transport::child_process::TokioChildProcess::new(command).unwrap();
        use mcp_rs::protocol::ClientServiceExt;
        let client = Client::from_service(
            mcp_rs::model::ClientConfig::new(
                mcp_rs::model::ClientCapabilities::builder()
                    .enable_tasks()
                    .build(),
                mcp_rs::model::Implementation::new("vero-integration-test", "1"),
            )
            .serve_with_lifecycle(
                transport,
                mcp_rs::protocol::ClientLifecycleMode::Discover {
                    preferred_versions: vec![mcp_rs::model::ProtocolVersion::V_2026_07_28],
                },
            )
            .await
            .unwrap(),
        )
        .unwrap();
        let tools = client.peer().list_tools(None).await.unwrap();
        assert!(tools.tools.iter().any(|tool| tool.name == "start_review"));
        assert!(tools
            .tools
            .iter()
            .any(|tool| tool.name == "get_repository_context"));
        let task = match client
            .call_once(
                "start_review",
                &serde_json::json!({"scope":"working_tree", "policy_profile":"strict"}),
            )
            .await
            .unwrap()
        {
            mcp_rs::model::CallToolResponse::Task(task) => task,
            other => panic!("start_review did not return an MCP task: {other:?}"),
        };
        let task_id = task.task.task_id.clone();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        let finished_task = loop {
            let state = client
                .peer()
                .get_task(mcp_rs::model::GetTaskParams::new(task_id.clone()))
                .await
                .unwrap()
                .task;
            if state.status().is_terminal() {
                break state;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "review task did not finish"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        };
        assert_eq!(finished_task.status(), mcp_rs::model::TaskStatus::Completed);
        let task_result = match finished_task.payload {
            mcp_rs::model::TaskPayload::Completed { result } => result,
            payload => panic!("unexpected review task payload: {payload:?}"),
        };
        let task_output = &task_result["structuredContent"];
        let review_id = task_output["review_id"].as_str().unwrap();
        assert_eq!(task_output["policy_profile"], "strict");
        let persisted_review: serde_json::Value = client
            .call("get_review", &serde_json::json!({"review_id": review_id}))
            .await
            .unwrap();
        assert_eq!(persisted_review["review_id"], review_id);
        let context: serde_json::Value = client
            .call(
                "get_repository_context",
                &serde_json::json!({"review_id":review_id,"path":"tracked.rs","symbol":"second_commit"}),
            )
            .await
            .unwrap();
        assert_eq!(context["schema_version"], 1);
        assert_eq!(context["path"], "tracked.rs");
        assert!(context["content"]
            .as_str()
            .unwrap()
            .contains("second_commit"));
        assert_eq!(context["matching_lines"], serde_json::json!([1]));
        assert_eq!(context["classification"], "untrusted_repository_source");
        fs::write(root.join("tracked.rs"), "fn modified_after_review() {}\n").unwrap();
        let old_context: serde_json::Value = client.call(
            "get_repository_context",
            &serde_json::json!({"review_id":review_id,"path":"tracked.rs"}),
        ).await.unwrap();
        assert!(old_context["content"].as_str().unwrap().contains("second_commit"));
        assert!(!old_context["content"].as_str().unwrap().contains("modified_after_review"));
        fs::write(root.join("tracked.rs"), "fn second_commit() {}\n").unwrap();
        assert!(git(&["add", "large.txt"]).status.success());
        let large_review: serde_json::Value = client.call(
            "review_changes",
            &serde_json::json!({"scope":"working_tree"}),
        ).await.unwrap();
        let bounded_context: serde_json::Value = client
            .call(
                "get_repository_context",
                &serde_json::json!({"review_id":large_review["review_id"],"path":"large.txt","max_bytes":12}),
            )
            .await
            .unwrap();
        assert_eq!(bounded_context["content"].as_str().unwrap().len(), 12);
        assert_eq!(bounded_context["truncated"], true);
        assert!(client
            .call::<_, serde_json::Value>(
                "get_repository_context",
                &serde_json::json!({"review_id":review_id,"path":".vero/vero.sqlite"}),
            )
            .await
            .is_err());
        #[cfg(unix)]
        assert!(client
            .call::<_, serde_json::Value>(
                "get_repository_context",
                &serde_json::json!({"review_id":review_id,"path":"outside-link/secret.txt"}),
            )
            .await
            .is_err());
        let result: serde_json::Value = client
            .call("list_findings", &serde_json::json!({"limit": 5}))
            .await
            .unwrap();
        assert_eq!(result["schema_version"], 1);
        assert_eq!(result["findings"].as_array().unwrap().len(), 0);
        assert_eq!(result["total"], 0);
        let review: serde_json::Value = client
            .call(
                "review_changes",
                &serde_json::json!({"scope":"working_tree"}),
            )
            .await
            .unwrap();
        assert_eq!(review["schema_version"], 2);
        assert_eq!(review["status"], "incomplete");
        assert!(review["review_id"].as_str().unwrap().starts_with("rev_"));
        assert!(review["snapshot_id"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"));
        let impact: serde_json::Value = client
            .call(
                "analyze_impact",
                &serde_json::json!({"review_id":review["review_id"]}),
            )
            .await
            .unwrap();
        assert_eq!(impact["schema_version"], 1);
        assert_eq!(impact["assessment"]["snapshot_id"], review["snapshot_id"]);
        let committed: serde_json::Value = client
            .call(
                "review_changes",
                &serde_json::json!({"scope":"commit", "commit":"HEAD~1..HEAD"}),
            )
            .await
            .unwrap();
        let stored: serde_json::Value = client
            .call(
                "get_review",
                &serde_json::json!({"review_id":committed["review_id"]}),
            )
            .await
            .unwrap();
        assert_eq!(
            stored["review"]["change_set"]["scope"],
            format!(
                "commit_range:{}..{}",
                stored["review"]["change_set"]["base_oid"].as_str().unwrap(),
                stored["review"]["change_set"]["head_oid"].as_str().unwrap()
            )
        );
        fs::write(
            root.join("tracked.rs"),
            "fn changed_after_commit_review() {}\n",
        )
        .unwrap();
        let gate: serde_json::Value = client
            .call(
                "evaluate_gate",
                &serde_json::json!({"review_id":committed["review_id"]}),
            )
            .await
            .unwrap();
        assert_eq!(gate["reviewed_snapshot_id"], gate["current_snapshot_id"]);
        client.close().await.unwrap();
    });
}

#[cfg(unix)]
#[test]
fn mcp_gate_check_rejects_source_changed_after_review() {
    use mcp_rs::client::Client;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap()
    };
    assert!(Command::new("git")
        .args(["init", "-q"])
        .arg(root)
        .status()
        .unwrap()
        .success());
    assert!(git(&["config", "user.email", "vero@example.invalid"])
        .status
        .success());
    assert!(git(&["config", "user.name", "Vero test"]).status.success());
    fs::write(root.join("tracked.rs"), "fn main() {}\n").unwrap();
    assert!(git(&["add", "tracked.rs"]).status.success());
    assert!(git(&["commit", "-qm", "initial"]).status.success());
    fs::write(root.join(".vero.yaml"), "version: 1\n").unwrap();
    fs::write(root.join("tracked.rs"), "fn main() { let _x = 1; }\n").unwrap();
    let reviewed = Command::new(env!("CARGO_BIN_EXE_vero"))
        .args(["review", "--gate", "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(reviewed.status.code(), Some(2));
    let review: serde_json::Value = serde_json::from_slice(&reviewed.stdout).unwrap();
    let review_id = review["review_id"].as_str().unwrap().to_owned();
    fs::write(root.join("tracked.rs"), "fn main() { let _x = 2; }\n").unwrap();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async move {
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_vero"));
        command
            .args(["mcp", "serve", "--transport", "stdio"])
            .current_dir(root)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let transport =
            mcp_rs::protocol::transport::child_process::TokioChildProcess::new(command).unwrap();
        let client = Client::connect(transport).await.unwrap();
        let result: serde_json::Value = client
            .call(
                "evaluate_gate",
                &serde_json::json!({"review_id": review_id}),
            )
            .await
            .unwrap();
        let schema: serde_json::Value =
            serde_json::from_str(include_str!("../../../schemas/gate-check-v1.schema.json"))
                .unwrap();
        assert!(jsonschema::validator_for(&schema)
            .unwrap()
            .is_valid(&result));
        assert_eq!(result["status"], "incomplete");
        assert!(result["reasons"][0]
            .as_str()
            .unwrap()
            .contains("source snapshot changed"));
        client.close().await.unwrap();
    });
}

#[cfg(unix)]
#[test]
fn explicit_verification_profile_persists_failure_against_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap()
    };
    assert!(Command::new("git")
        .args(["init", "-q"])
        .arg(root)
        .status()
        .unwrap()
        .success());
    assert!(git(&["config", "user.email", "vero@example.invalid"])
        .status
        .success());
    assert!(git(&["config", "user.name", "Vero test"]).status.success());
    fs::write(root.join("tracked.rs"), "fn main() {}\n").unwrap();
    assert!(git(&["add", "tracked.rs"]).status.success());
    assert!(git(&["commit", "-qm", "initial"]).status.success());
    fs::write(root.join(".vero.yaml"), "version: 1\nverification:\n  failing-check:\n    executable: /usr/bin/false\n    timeout_seconds: 2\n    output_limit_bytes: 64\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_vero"))
        .args(["verify", "--profile", "failing-check", "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["status"], "failed");
    assert_eq!(value["snapshot_id"].as_str().unwrap().len(), 71);
    assert_matches_schema(
        &value,
        include_str!("../../../schemas/verification-run-v1.schema.json"),
        "verification run",
    );
    assert!(root.join(".vero/vero.sqlite").exists());
    let run_id = value["run_id"].as_str().unwrap();
    let show = Command::new(env!("CARGO_BIN_EXE_vero"))
        .args(["verification", "show", run_id, "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(show.status.code(), Some(0));
    let persisted: serde_json::Value = serde_json::from_slice(&show.stdout).unwrap();
    assert_matches_schema(
        &persisted,
        include_str!("../../../schemas/verification-run-v1.schema.json"),
        "persisted verification run",
    );
    assert_eq!(persisted, value);
}

#[cfg(unix)]
#[test]
fn required_verification_gate_uses_latest_result_for_exact_snapshot() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap()
    };
    assert!(Command::new("git")
        .args(["init", "-q"])
        .arg(root)
        .status()
        .unwrap()
        .success());
    assert!(git(&["config", "user.email", "vero@example.invalid"])
        .status
        .success());
    assert!(git(&["config", "user.name", "Vero test"]).status.success());
    fs::write(root.join("tracked.rs"), "fn main() {}\n").unwrap();
    assert!(git(&["add", "tracked.rs"]).status.success());
    assert!(git(&["commit", "-qm", "initial"]).status.success());
    let provider = root.join("fake-provider");
    fs::write(
        &provider,
        "#!/bin/sh\ncat >/dev/null\nprintf '%s' '{\"schema_version\":1,\"findings\":[]}'\n",
    )
    .unwrap();
    let mut permissions = fs::metadata(&provider).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&provider, permissions).unwrap();
    fs::write(root.join("reviewer.md"), "Review changed code.\n").unwrap();
    let marker = dir.path().with_extension("verification-marker");
    let verification_script = format!(
        "if [ -f '{}' ]; then exit 1; else touch '{}'; exit 0; fi",
        marker.display(),
        marker.display()
    );
    let config = format!(
        "version: 1\nproviders:\n  fake:\n    kind: cli\n    executable: {}\nreviewers:\n  correctness:\n    provider: fake\n    instructions_file: reviewer.md\nverification:\n  unit:\n    executable: /bin/sh\n    args: [-c, \"{}\"]\n    timeout_seconds: 3\n    output_limit_bytes: 64\npolicy:\n  required_reviewers: [correctness]\n  required_verifications: [unit]\n  block_severities: [high]\n  minimum_confidence: 80\n  on_incomplete: block\n",
        provider.display(),
        verification_script
    );
    fs::write(root.join(".vero.yaml"), config).unwrap();

    let run_verify = || {
        Command::new(env!("CARGO_BIN_EXE_vero"))
            .args(["verify", "--profile", "unit", "--output", "json"])
            .current_dir(root)
            .output()
            .unwrap()
    };
    let initial_review = Command::new(env!("CARGO_BIN_EXE_vero"))
        .args(["review", "--gate", "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(
        initial_review.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&initial_review.stderr)
    );
    let initial_json: serde_json::Value = serde_json::from_slice(&initial_review.stdout).unwrap();
    assert_eq!(initial_json["status"], "incomplete");
    let review_id = initial_json["review_id"].as_str().unwrap();
    let initial_decision_id = initial_json["gate"]["decision_id"].as_str().unwrap();

    let first = run_verify();
    assert_eq!(
        first.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let recheck = Command::new(env!("CARGO_BIN_EXE_vero"))
        .args(["gate", "check", "--review", review_id, "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(
        recheck.status.code(),
        Some(0),
        "stderr: {}; stdout: {}",
        String::from_utf8_lossy(&recheck.stderr),
        String::from_utf8_lossy(&recheck.stdout)
    );
    let recheck_json: serde_json::Value = serde_json::from_slice(&recheck.stdout).unwrap();
    assert_eq!(recheck_json["status"], "pass");
    assert_ne!(
        recheck_json["decision_id"].as_str().unwrap(),
        initial_decision_id
    );
    assert_eq!(
        recheck_json["verification_run_ids"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    let second = run_verify();
    assert_eq!(second.status.code(), Some(1));
    let revoked = Command::new(env!("CARGO_BIN_EXE_vero"))
        .args(["gate", "check", "--review", review_id, "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(
        revoked.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&revoked.stderr)
    );
    let revoked_json: serde_json::Value = serde_json::from_slice(&revoked.stdout).unwrap();
    assert_eq!(revoked_json["status"], "incomplete");
    assert!(revoked_json["reasons"][0]
        .as_str()
        .unwrap()
        .contains("unit"));
    let history = Command::new(env!("CARGO_BIN_EXE_vero"))
        .args(["gate", "history", "--review", review_id, "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(history.status.code(), Some(0));
    let decisions: serde_json::Value = serde_json::from_slice(&history.stdout).unwrap();
    assert_matches_schema(
        &decisions,
        include_str!("../../../schemas/gate-history-v1.schema.json"),
        "gate history",
    );
    assert_eq!(decisions["schema_version"], 1);
    assert_eq!(decisions["decisions"].as_array().unwrap().len(), 3);
    assert_eq!(decisions["decisions"][0]["status"], "incomplete");
    assert_eq!(decisions["decisions"][1]["status"], "pass");
    assert_eq!(decisions["decisions"][2]["status"], "incomplete");
    let _ = fs::remove_file(marker);
}

#[cfg(unix)]
#[test]
fn configured_provider_finding_blocks_gate() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap()
    };
    assert!(Command::new("git")
        .arg("init")
        .arg("-q")
        .arg(root)
        .status()
        .unwrap()
        .success());
    assert!(git(&["config", "user.email", "vero@example.invalid"])
        .status
        .success());
    assert!(git(&["config", "user.name", "Vero test"]).status.success());
    fs::write(root.join("tracked.rs"), "fn main() {}\n").unwrap();
    assert!(git(&["add", "tracked.rs"]).status.success());
    assert!(git(&["commit", "-qm", "initial"]).status.success());
    fs::write(root.join("tracked.rs"), "fn main() { unsafe {} }\n").unwrap();
    fs::write(root.join("reviewer.md"), "Look for correctness defects.\n").unwrap();
    let provider = root.join("fake-provider");
    fs::write(&provider, "#!/bin/sh\ncat >/dev/null\nprintf '%s' '{\"schema_version\":1,\"findings\":[{\"category\":\"correctness\",\"severity\":\"high\",\"confidence\":95,\"rationale\":\"unsafe operation\",\"path\":\"tracked.rs\",\"line\":1}]}'\n").unwrap();
    let mut permissions = fs::metadata(&provider).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&provider, permissions).unwrap();
    let config = format!("version: 1\nproviders:\n  fake:\n    kind: cli\n    executable: {}\nreviewers:\n  correctness:\n    provider: fake\n    instructions_file: reviewer.md\nverification:\n  unit:\n    executable: /usr/bin/true\npolicy:\n  required_reviewers: [correctness]\n  block_severities: []\n  minimum_confidence: 80\n  on_incomplete: block\npolicy_profiles:\n  strict:\n    required_reviewers: [correctness]\n    block_severities: [critical, high]\n    minimum_confidence: 80\n    on_incomplete: block\n", provider.display());
    fs::write(root.join(".vero.yaml"), config).unwrap();
    let report_dir = tempfile::tempdir().unwrap();
    let markdown_report = report_dir.path().join("review-report.md");
    let output = Command::new(env!("CARGO_BIN_EXE_vero"))
        .arg("review")
        .arg("--reviewer")
        .arg("correctness")
        .arg("--gate")
        .arg("--policy-profile")
        .arg("strict")
        .arg("--output")
        .arg("json")
        .arg("--markdown")
        .arg(&markdown_report)
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["status"], "block");
    assert_eq!(value["policy_profile"], "strict");
    assert_eq!(
        value["gate"]["effective_config_digest"],
        value["effective_config_digest"]
    );
    let markdown = fs::read_to_string(markdown_report).unwrap();
    assert!(markdown.contains("# Vero review"));
    assert!(markdown.contains("Status: **block**"));
    assert!(markdown.contains("unsafe operation"));
    assert_eq!(
        value["selected_reviewers"],
        serde_json::json!(["correctness"])
    );
    assert_eq!(value["evidence"].as_array().unwrap().len(), 1);
    let evidence_id = value["evidence"][0]["id"].as_str().unwrap();
    assert_eq!(value["findings"][0]["evidence_ids"][0], evidence_id);
    assert_eq!(value["evidence"][0]["classification"], "observed");
    assert_eq!(value["evidence"][0]["verification"], "unverified");
    assert!(value["gate"]["blocking_findings"][0]
        .as_str()
        .unwrap()
        .starts_with("find_"));
    let finding_id = value["findings"][0]["id"].as_str().unwrap().to_owned();
    let snapshot_id = value["snapshot_id"].as_str().unwrap().to_owned();
    let review_id = value["review_id"].as_str().unwrap();
    let gate_check = Command::new(env!("CARGO_BIN_EXE_vero"))
        .args(["gate", "check", "--review", review_id, "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(gate_check.status.code(), Some(1));
    let gate_check: serde_json::Value = serde_json::from_slice(&gate_check.stdout).unwrap();
    assert_eq!(gate_check["status"], "block");
    assert_eq!(
        gate_check["effective_config_digest"],
        value["effective_config_digest"]
    );
    for (args, schema_text, key) in [
        (
            vec![
                "findings", "list", "--review", review_id, "--output", "json",
            ],
            include_str!("../../../schemas/findings-list-v1.schema.json"),
            "findings",
        ),
        (
            vec!["findings", "show", finding_id.as_str(), "--output", "json"],
            include_str!("../../../schemas/finding-detail-v1.schema.json"),
            "finding",
        ),
        (
            vec!["gate", "history", "--review", review_id, "--output", "json"],
            include_str!("../../../schemas/gate-history-v1.schema.json"),
            "decisions",
        ),
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_vero"))
            .args(args)
            .current_dir(root)
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(0));
        let response: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        let schema: serde_json::Value = serde_json::from_str(schema_text).unwrap();
        assert!(jsonschema::validator_for(&schema)
            .unwrap()
            .is_valid(&response));
        assert_eq!(response["schema_version"], 1);
        assert!(!response[key].is_null());
    }
    let sarif = Command::new(env!("CARGO_BIN_EXE_vero"))
        .args(["reviews", "export", review_id, "--format", "sarif"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(
        sarif.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&sarif.stderr)
    );
    let sarif: serde_json::Value = serde_json::from_slice(&sarif.stdout).unwrap();
    assert_eq!(sarif["version"], "2.1.0");
    assert_eq!(sarif["runs"][0]["tool"]["driver"]["name"], "Vero");
    assert_eq!(sarif["runs"][0]["results"][0]["ruleId"], "correctness");
    assert_eq!(sarif["runs"][0]["results"][0]["level"], "error");
    assert_eq!(
        sarif["runs"][0]["results"][0]["partialFingerprints"]["vero/v1"],
        value["findings"][0]["fingerprint"]
    );
    assert_eq!(
        sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
            ["uri"],
        "tracked.rs"
    );
    assert_eq!(
        sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"],
        1
    );
    let targeted_verification = Command::new(env!("CARGO_BIN_EXE_vero"))
        .args([
            "verify",
            finding_id.as_str(),
            "--profile",
            "unit",
            "--output",
            "json",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(
        targeted_verification.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&targeted_verification.stderr)
    );
    let targeted_run: serde_json::Value =
        serde_json::from_slice(&targeted_verification.stdout).unwrap();
    assert_eq!(targeted_run["finding_id"], finding_id);
    assert_eq!(targeted_run["snapshot_id"], snapshot_id);
    let verification_schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/verification-run-v1.schema.json"
    ))
    .unwrap();
    assert!(jsonschema::validator_for(&verification_schema)
        .unwrap()
        .is_valid(&targeted_run));
    assert!(root
        .join(targeted_run["stdout_artifact"]["path"].as_str().unwrap())
        .exists());
    let mcp_finding_id = finding_id.clone();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async move {
        use mcp_rs::client::Client;
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_vero"));
        command
            .args(["mcp", "serve", "--transport", "stdio"])
            .current_dir(root)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let transport =
            mcp_rs::protocol::transport::child_process::TokioChildProcess::new(command).unwrap();
        let client = Client::connect(transport).await.unwrap();
        fs::write(
            root.join("tracked.rs"),
            "fn main() { unsafe { let _ = 1; } }\n",
        )
        .unwrap();
        let stale = client
            .call::<_, serde_json::Value>(
                "verify_finding",
                &serde_json::json!({"finding_id":mcp_finding_id,"profile_id":"unit"}),
            )
            .await;
        assert!(stale.is_err());
        fs::write(root.join("tracked.rs"), "fn main() { unsafe {} }\n").unwrap();
        let verification: serde_json::Value = client
            .call(
                "verify_finding",
                &serde_json::json!({"finding_id":mcp_finding_id,"profile_id":"unit"}),
            )
            .await
            .unwrap();
        assert_eq!(verification["schema_version"], 1);
        assert_eq!(verification["run"]["status"], "passed");
        assert_eq!(verification["run"]["snapshot_id"], snapshot_id);
        assert_eq!(verification["run"]["finding_id"], mcp_finding_id);
        let details: serde_json::Value = client
            .call(
                "get_finding",
                &serde_json::json!({"finding_id":mcp_finding_id}),
            )
            .await
            .unwrap();
        assert_eq!(details["evidence"].as_array().unwrap().len(), 1);
        assert_eq!(details["evidence"][0]["kind"], "source");
        let page: serde_json::Value = client
            .call(
                "list_findings",
                &serde_json::json!({"review_id":review_id,"limit":1,"offset":0}),
            )
            .await
            .unwrap();
        assert_eq!(page["total"], 1);
        assert_eq!(page["limit"], 1);
        assert_eq!(page["findings"].as_array().unwrap().len(), 1);
        assert_eq!(page["findings"][0]["finding"]["id"], mcp_finding_id);
        client.close().await.unwrap();
    });
    let list = Command::new(env!("CARGO_BIN_EXE_vero"))
        .args([
            "findings",
            "list",
            "--severity",
            "high",
            "--status",
            "open",
            "--output",
            "json",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(list.status.code(), Some(0));
    let listed: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    assert_matches_schema(
        &listed,
        include_str!("../../../schemas/findings-list-v1.schema.json"),
        "findings list",
    );
    assert_eq!(listed["schema_version"], 1);
    assert_eq!(listed["findings"].as_array().unwrap().len(), 1);
    let show = Command::new(env!("CARGO_BIN_EXE_vero"))
        .args(["findings", "show", finding_id.as_str(), "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(show.status.code(), Some(0));
    let shown: serde_json::Value = serde_json::from_slice(&show.stdout).unwrap();
    assert_matches_schema(
        &shown,
        include_str!("../../../schemas/finding-detail-v1.schema.json"),
        "finding detail",
    );
    assert_eq!(shown["schema_version"], 1);
    assert_eq!(shown["finding"]["occurrence_count"], 1);
    let update = Command::new(env!("CARGO_BIN_EXE_vero"))
        .args([
            "findings",
            "set-status",
            finding_id.as_str(),
            "--status",
            "verified",
            "--reason",
            "confirmed in source",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(update.status.code(), Some(0));
    let verified = Command::new(env!("CARGO_BIN_EXE_vero"))
        .args([
            "findings", "list", "--status", "verified", "--output", "json",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    let verified_json: serde_json::Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert_eq!(verified_json["findings"].as_array().unwrap().len(), 1);
}

#[cfg(unix)]
#[test]
fn user_provider_config_supplies_repo_reviewer_and_passes_gate() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap()
    };
    assert!(Command::new("git")
        .args(["init", "-q"])
        .arg(root)
        .status()
        .unwrap()
        .success());
    assert!(git(&["config", "user.email", "vero@example.invalid"])
        .status
        .success());
    assert!(git(&["config", "user.name", "Vero test"]).status.success());
    fs::write(root.join("source.rs"), "fn main() {}\n").unwrap();
    assert!(git(&["add", "source.rs"]).status.success());
    assert!(git(&["commit", "-qm", "initial"]).status.success());
    fs::write(root.join("source.rs"), "fn main() { let _ = 1; }\n").unwrap();
    fs::write(root.join("reviewer.md"), "Review for defects.\n").unwrap();

    let provider = root.join("fake-provider");
    fs::write(
        &provider,
        r##"#!/bin/sh
cat >/dev/null
printf '%s' '{"schema_version":1,"findings":[]}'
"##,
    )
    .unwrap();
    let mut permissions = fs::metadata(&provider).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&provider, permissions).unwrap();

    fs::write(
        root.join(".vero.yaml"),
        "version: 1\nreviewers:\n  correctness:\n    provider: local-codex\n    instructions_file: reviewer.md\npolicy:\n  required_reviewers: [correctness]\n",
    )
    .unwrap();
    let user_config_dir = tempfile::tempdir().unwrap();
    let user_config = user_config_dir.path().join("config.yaml");
    fs::write(
        &user_config,
        format!(
            "version: 1\nproviders:\n  local-codex:\n    kind: cli\n    executable: {}\n    egress: local\n",
            provider.display()
        ),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_vero"))
        .args(["review", "--gate", "--output", "json"])
        .env("VERO_CONFIG", &user_config)
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["status"], "pass");
    assert_eq!(
        value["selected_reviewers"],
        serde_json::json!(["correctness"])
    );

    let review_id = value["review_id"].as_str().unwrap();
    fs::write(
        &user_config,
        "version: 1\nproviders:\n  local-codex:\n    kind: cli\n    executable: /bin/true\n    egress: local\n",
    )
    .unwrap();
    let check = Command::new(env!("CARGO_BIN_EXE_vero"))
        .args(["gate", "check", "--review", review_id, "--output", "json"])
        .env("VERO_CONFIG", &user_config)
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(check.status.code(), Some(2));
    let check_value: serde_json::Value = serde_json::from_slice(&check.stdout).unwrap();
    assert!(
        check_value["reasons"][0]
            .as_str()
            .unwrap()
            .contains("effective configuration changed"),
        "{check_value}"
    );
}

#[cfg(unix)]
#[test]
fn configured_codex_cli_provider_completes_a_schema_bound_review() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("repo");
    fs::create_dir_all(&root).unwrap();
    let root = root.as_path();
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap()
    };
    assert!(Command::new("git")
        .arg("init")
        .arg("-q")
        .arg(root)
        .status()
        .unwrap()
        .success());
    assert!(git(&["config", "user.email", "vero@example.invalid"])
        .status
        .success());
    assert!(git(&["config", "user.name", "Vero test"]).status.success());
    fs::write(root.join("tracked.rs"), "fn main() {}\n").unwrap();
    assert!(git(&["add", "tracked.rs"]).status.success());
    assert!(git(&["commit", "-qm", "initial"]).status.success());
    fs::write(root.join("tracked.rs"), "fn main() { let value = 1; }\n").unwrap();
    fs::write(root.join("reviewer.md"), "Review correctness.\n").unwrap();
    let provider = dir.path().join("fake-codex");
    fs::write(
        &provider,
        "#!/bin/sh\nif [ \"$1\" = '--version' ]; then printf '%s\\n' 'codex-cli 0.99.1-test'; exit 0; fi\nschema=''\nprevious=''\nfor arg in \"$@\"; do if [ \"$previous\" = '--output-schema' ]; then schema=\"$arg\"; fi; previous=\"$arg\"; done\ntest -f \"$schema\" || exit 21\ncat >/dev/null\nprintf '%s' '{\"schema_version\":1,\"findings\":[]}'\n",
    )
    .unwrap();
    let mut permissions = fs::metadata(&provider).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&provider, permissions).unwrap();
    fs::write(
        root.join(".vero.yaml"),
        format!(
            "version: 1\nproviders:\n  codex:\n    kind: codex_cli\n    executable: {}\n    model: test-model\nreviewers:\n  correctness:\n    provider: codex\n    instructions_file: reviewer.md\npolicy:\n  required_reviewers: [correctness]\n  on_incomplete: block\n",
            provider.display()
        ),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_vero"))
        .args(["review", "--working-tree", "--gate", "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let review: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(review["gate"]["status"], "pass");
    assert_eq!(review["schema_version"], 2);
    assert_eq!(review["reviewer_outcomes"][0]["status"], "completed");
    assert_eq!(
        review["reviewer_outcomes"][0]["provider_version"],
        "codex-cli 0.99.1-test"
    );

    fs::write(
        &provider,
        "#!/bin/sh\nif [ \"$1\" = '--version' ]; then printf '%s\\n' 'codex-cli 0.99.2-test'; exit 0; fi\nexit 90\n",
    )
    .unwrap();
    let mut permissions = fs::metadata(&provider).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&provider, permissions).unwrap();
    let check = Command::new(env!("CARGO_BIN_EXE_vero"))
        .args([
            "gate",
            "check",
            "--review",
            review["review_id"].as_str().unwrap(),
            "--output",
            "json",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(check.status.code(), Some(2));
    let checked: serde_json::Value = serde_json::from_slice(&check.stdout).unwrap();
    assert_eq!(checked["status"], "incomplete");
    assert!(checked["reasons"][0]
        .as_str()
        .unwrap()
        .contains("effective configuration changed"));
}

#[cfg(unix)]
#[test]
fn snapshot_waiver_is_auditable_expires_and_only_applies_to_its_review() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap()
    };
    assert!(Command::new("git")
        .args(["init", "-q"])
        .arg(root)
        .status()
        .unwrap()
        .success());
    assert!(git(&["config", "user.email", "vero@example.invalid"])
        .status
        .success());
    assert!(git(&["config", "user.name", "Vero test"]).status.success());
    fs::write(root.join("tracked.rs"), "fn main() {}\n").unwrap();
    assert!(git(&["add", "tracked.rs"]).status.success());
    assert!(git(&["commit", "-qm", "initial"]).status.success());
    fs::write(root.join("tracked.rs"), "fn main() { risky(); }\n").unwrap();
    fs::write(root.join("reviewer.md"), "Review correctness.\n").unwrap();
    let provider = root.join("fake-provider");
    fs::write(
        &provider,
        "#!/bin/sh\ncat >/dev/null\nprintf '%s' '{\"schema_version\":1,\"findings\":[{\"category\":\"correctness\",\"severity\":\"high\",\"confidence\":95,\"rationale\":\"risky call\",\"path\":\"tracked.rs\",\"line\":1}]}'\n",
    )
    .unwrap();
    let mut permissions = fs::metadata(&provider).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&provider, permissions).unwrap();
    fs::write(
        root.join(".vero.yaml"),
        format!("version: 1\nproviders:\n  fake: {{ kind: cli, executable: {} }}\nreviewers:\n  correctness: {{ provider: fake, instructions_file: reviewer.md }}\npolicy:\n  required_reviewers: [correctness]\n  block_severities: [high]\n  minimum_confidence: 80\n", provider.display()),
    )
    .unwrap();

    let review_output = Command::new(env!("CARGO_BIN_EXE_vero"))
        .args(["review", "--working-tree", "--gate", "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(review_output.status.code(), Some(1));
    let review: serde_json::Value = serde_json::from_slice(&review_output.stdout).unwrap();
    let review_id = review["review_id"].as_str().unwrap();
    let finding_id = review["findings"][0]["id"].as_str().unwrap();

    let created = Command::new(env!("CARGO_BIN_EXE_vero"))
        .args([
            "waivers",
            "create",
            finding_id,
            "--review",
            review_id,
            "--reason",
            "Accepted until the next maintenance window",
            "--author",
            "maintainer@example.invalid",
            "--expires-in-days",
            "2",
            "--output",
            "json",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(
        created.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let waiver: serde_json::Value = serde_json::from_slice(&created.stdout).unwrap();
    let waiver_schema: serde_json::Value = serde_json::from_str::<serde_json::Value>(include_str!(
        "../../../schemas/waiver-v1.schema.json"
    ))
    .unwrap();
    assert!(jsonschema::validator_for(&waiver_schema)
        .unwrap()
        .is_valid(&waiver));
    assert_eq!(waiver["snapshot_id"], review["snapshot_id"]);
    assert_eq!(waiver["author"], "maintainer@example.invalid");

    let checked = Command::new(env!("CARGO_BIN_EXE_vero"))
        .args(["gate", "check", "--review", review_id, "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(
        checked.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );
    let decision: serde_json::Value = serde_json::from_slice(&checked.stdout).unwrap();
    assert_matches_schema(
        &decision,
        include_str!("../../../schemas/gate-check-v1.schema.json"),
        "gate check",
    );
    assert_eq!(decision["status"], "pass");
    assert!(decision["reasons"][0]
        .as_str()
        .unwrap()
        .contains(waiver["id"].as_str().unwrap()));

    let listed = Command::new(env!("CARGO_BIN_EXE_vero"))
        .args(["waivers", "list", "--review", review_id, "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(listed.status.code(), Some(0));
    let list: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_matches_schema(
        &list,
        include_str!("../../../schemas/waivers-list-v1.schema.json"),
        "waiver list",
    );
    assert_eq!(list["waivers"][0], waiver);
    let list_schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../schemas/waivers-list-v1.schema.json")).unwrap();
    let registry = jsonschema::Registry::new()
        .add(
            "https://vero.dev/schemas/waiver-v1.schema.json",
            waiver_schema,
        )
        .unwrap()
        .prepare()
        .unwrap();
    assert!(jsonschema::options()
        .with_registry(&registry)
        .build(&list_schema)
        .unwrap()
        .is_valid(&list));

    fs::write(root.join("tracked.rs"), "fn main() { safer(); }\n").unwrap();
    let stale = Command::new(env!("CARGO_BIN_EXE_vero"))
        .args(["gate", "check", "--review", review_id, "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(stale.status.code(), Some(2));
    let stale_result: serde_json::Value = serde_json::from_slice(&stale.stdout).unwrap();
    assert_eq!(stale_result["status"], "incomplete");
}

#[cfg(unix)]
#[test]
fn malformed_provider_findings_make_the_gate_incomplete() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap()
    };
    assert!(Command::new("git")
        .args(["init", "-q"])
        .arg(root)
        .status()
        .unwrap()
        .success());
    assert!(git(&["config", "user.email", "vero@example.invalid"])
        .status
        .success());
    assert!(git(&["config", "user.name", "Vero test"]).status.success());
    fs::write(root.join("tracked.rs"), "fn main() {}\n").unwrap();
    assert!(git(&["add", "tracked.rs"]).status.success());
    assert!(git(&["commit", "-qm", "initial"]).status.success());
    fs::write(root.join("tracked.rs"), "fn changed() {}\n").unwrap();
    fs::write(root.join("reviewer.md"), "Review changes.\n").unwrap();
    let provider = root.join("fake-provider");
    fs::write(&provider, "#!/bin/sh\ncat >/dev/null\nprintf '%s' '{\"schema_version\":1,\"findings\":[{\"id\":\"forged\",\"category\":\"correctness\",\"severity\":\"high\",\"rationale\":\"bug\"}]}'\n").unwrap();
    let mut permissions = fs::metadata(&provider).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&provider, permissions).unwrap();
    fs::write(root.join(".vero.yaml"), format!("version: 1\nproviders:\n  fake:\n    kind: cli\n    executable: {}\nreviewers:\n  correctness:\n    provider: fake\n    instructions_file: reviewer.md\npolicy:\n  required_reviewers: [correctness]\n  on_incomplete: block\n", provider.display())).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_vero"))
        .args(["review", "--gate", "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let review: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(review["status"], "incomplete");
    assert_eq!(review["findings"].as_array().unwrap().len(), 0);
    assert_eq!(review["reviewer_outcomes"][0]["status"], "invalid_findings");
}

#[cfg(unix)]
#[test]
fn gate_check_rejects_snapshot_after_source_edit() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap()
    };
    assert!(Command::new("git")
        .arg("init")
        .arg("-q")
        .arg(root)
        .status()
        .unwrap()
        .success());
    assert!(git(&["config", "user.email", "vero@example.invalid"])
        .status
        .success());
    assert!(git(&["config", "user.name", "Vero test"]).status.success());
    fs::write(root.join("tracked.rs"), "fn main() {}\n").unwrap();
    assert!(git(&["add", "tracked.rs"]).status.success());
    assert!(git(&["commit", "-qm", "initial"]).status.success());
    fs::write(root.join("reviewer.md"), "Review changes.\n").unwrap();
    let provider = root.join("fake-provider");
    fs::write(
        &provider,
        "#!/bin/sh\ncat >/dev/null\nprintf '%s' '{\"schema_version\":1,\"findings\":[]}'\n",
    )
    .unwrap();
    let mut permissions = fs::metadata(&provider).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&provider, permissions).unwrap();
    fs::write(root.join(".vero.yaml"), format!("version: 1\nproviders:\n  fake:\n    kind: cli\n    executable: {}\nreviewers:\n  correctness:\n    provider: fake\n    instructions_file: reviewer.md\npolicy:\n  required_reviewers: [correctness]\n  block_severities: [high]\n  minimum_confidence: 80\n  on_incomplete: block\n", provider.display())).unwrap();
    let review = Command::new(env!("CARGO_BIN_EXE_vero"))
        .arg("review")
        .arg("--gate")
        .arg("--output")
        .arg("json")
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(
        review.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&review.stderr)
    );
    let review_json: serde_json::Value = serde_json::from_slice(&review.stdout).unwrap();
    let review_id = review_json["review_id"].as_str().unwrap();
    let first_check = Command::new(env!("CARGO_BIN_EXE_vero"))
        .args(["gate", "check", "--review", review_id, "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(first_check.status.code(), Some(0));
    let config_path = root.join(".vero.yaml");
    let config_bytes = fs::read(&config_path).unwrap();
    let changed_config = String::from_utf8(config_bytes.clone())
        .unwrap()
        .replace("minimum_confidence: 80", "minimum_confidence: 79");
    fs::write(&config_path, changed_config).unwrap();
    let config_stale = Command::new(env!("CARGO_BIN_EXE_vero"))
        .args(["gate", "check", "--review", review_id, "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(config_stale.status.code(), Some(2));
    let config_stale_json: serde_json::Value =
        serde_json::from_slice(&config_stale.stdout).unwrap();
    assert!(
        config_stale_json["reasons"][0]
            .as_str()
            .unwrap()
            .contains("effective configuration changed"),
        "{config_stale_json}"
    );
    fs::write(&config_path, config_bytes).unwrap();
    fs::write(
        root.join("tracked.rs"),
        "fn main() { let _changed = true; }\n",
    )
    .unwrap();
    let stale_check = Command::new(env!("CARGO_BIN_EXE_vero"))
        .args(["gate", "check", "--review", review_id, "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(stale_check.status.code(), Some(2));
    let stale_json: serde_json::Value = serde_json::from_slice(&stale_check.stdout).unwrap();
    assert_eq!(stale_json["status"], "incomplete");
    assert_ne!(
        stale_json["reviewed_snapshot_id"],
        stale_json["current_snapshot_id"]
    );
}

#[test]
fn staged_snapshot_ignores_unstaged_edits_to_same_path() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap()
    };
    assert!(Command::new("git")
        .arg("init")
        .arg("-q")
        .arg(root)
        .status()
        .unwrap()
        .success());
    assert!(git(&["config", "user.email", "vero@example.invalid"])
        .status
        .success());
    assert!(git(&["config", "user.name", "Vero test"]).status.success());
    fs::write(root.join("file.rs"), "base\n").unwrap();
    assert!(git(&["add", "file.rs"]).status.success());
    assert!(git(&["commit", "-qm", "initial"]).status.success());
    fs::write(root.join("file.rs"), "staged contents\n").unwrap();
    assert!(git(&["add", "file.rs"]).status.success());
    fs::write(root.join("file.rs"), "unstaged contents one\n").unwrap();
    fs::write(root.join(".vero.yaml"), "version: 1\n").unwrap();
    let run_review = || {
        let output = Command::new(env!("CARGO_BIN_EXE_vero"))
            .arg("review")
            .arg("--staged")
            .arg("--output")
            .arg("json")
            .current_dir(root)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(0));
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };
    let first = run_review();
    assert_eq!(
        first["change_set"]["files"][0]["content_digest"],
        vero_core::digest(b"staged contents\n")
    );
    fs::write(root.join("file.rs"), "unstaged contents two\n").unwrap();
    let second = run_review();
    assert_eq!(first["snapshot_id"], second["snapshot_id"]);
}

#[test]
fn working_tree_scope_excludes_staged_only_paths() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap()
    };
    assert!(Command::new("git")
        .arg("init")
        .arg("-q")
        .arg(root)
        .status()
        .unwrap()
        .success());
    assert!(git(&["config", "user.email", "vero@example.invalid"])
        .status
        .success());
    assert!(git(&["config", "user.name", "Vero test"]).status.success());
    fs::write(root.join("staged.rs"), "base\n").unwrap();
    fs::write(root.join("working.rs"), "base\n").unwrap();
    assert!(git(&["add", "."]).status.success());
    assert!(git(&["commit", "-qm", "initial"]).status.success());
    fs::write(root.join("staged.rs"), "staged edit\n").unwrap();
    assert!(git(&["add", "staged.rs"]).status.success());
    fs::write(root.join("working.rs"), "unstaged edit\n").unwrap();
    fs::write(root.join(".vero.yaml"), "version: 1\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_vero"))
        .arg("review")
        .arg("--working-tree")
        .arg("--output")
        .arg("json")
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    let review: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let paths: Vec<_> = review["change_set"]["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["path"].as_str().unwrap())
        .collect();
    assert!(paths.contains(&"working.rs"));
    assert!(!paths.contains(&"staged.rs"));
}

#[test]
fn reviews_list_and_show_return_persisted_review_records() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap()
    };
    assert!(Command::new("git")
        .arg("init")
        .arg("-q")
        .arg(root)
        .status()
        .unwrap()
        .success());
    assert!(git(&["config", "user.email", "vero@example.invalid"])
        .status
        .success());
    assert!(git(&["config", "user.name", "Vero test"]).status.success());
    fs::write(root.join("file.rs"), "fn main() {}\n").unwrap();
    assert!(git(&["add", "file.rs"]).status.success());
    assert!(git(&["commit", "-qm", "initial"]).status.success());
    fs::write(root.join(".vero.yaml"), "version: 1\n").unwrap();
    fs::write(root.join("file.rs"), "fn main() { let x = 1; }\n").unwrap();

    let review = Command::new(env!("CARGO_BIN_EXE_vero"))
        .args(["review", "--working-tree", "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(review.status.code(), Some(0));
    let review: serde_json::Value = serde_json::from_slice(&review.stdout).unwrap();
    let review_id = review["review_id"].as_str().unwrap();

    let listed = Command::new(env!("CARGO_BIN_EXE_vero"))
        .args(["reviews", "list", "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(
        listed.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let listed: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../schemas/reviews-list-v1.schema.json")).unwrap();
    assert!(jsonschema::validator_for(&schema)
        .unwrap()
        .is_valid(&listed));
    assert_eq!(listed["schema_version"], 1);
    assert_eq!(listed["reviews"].as_array().unwrap().len(), 1);
    assert_eq!(listed["reviews"][0]["review_id"], review_id);

    let shown = Command::new(env!("CARGO_BIN_EXE_vero"))
        .args(["reviews", "show", review_id, "--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(shown.status.code(), Some(0));
    let shown: serde_json::Value = serde_json::from_slice(&shown.stdout).unwrap();
    assert_matches_schema(
        &shown,
        include_str!("../../../schemas/review-output-v2.schema.json"),
        "review detail",
    );
    assert_eq!(shown["review_id"], review_id);
    assert_eq!(shown["snapshot_id"], review["snapshot_id"]);
}
