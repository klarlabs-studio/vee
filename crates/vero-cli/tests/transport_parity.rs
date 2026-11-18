//! The CLI and the MCP server are two transports over one set of operations.
//! For every operation both expose, `--output json` and the MCP tool result must be
//! the same document, and that document must satisfy the published schema.
#![cfg(unix)]

use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

/// A `vero` invocation isolated from the developer's machine. Setup detection
/// probes agent CLIs on PATH, a local Ollama, API keys, and the user config;
/// the CLI and the MCP server probe separately, so any of those answering
/// differently between the two calls would make their documents differ.
fn vero() -> Command {
    static HOME: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
    let home = HOME.get_or_init(|| tempfile::tempdir().unwrap());
    let mut command = Command::new(env!("CARGO_BIN_EXE_vero"));
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", home.path())
        // Port 9 (discard) has no Ollama, so detection reports it unavailable.
        .env("OLLAMA_HOST", "127.0.0.1:9");
    command
}

fn schemas_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schemas")
}

fn assert_matches_published_schema(document: &Value, schema_name: &str) {
    let mut registry = jsonschema::Registry::new();
    for entry in fs::read_dir(schemas_dir()).unwrap() {
        let path = entry.unwrap().path();
        let schema: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        if let Some(id) = schema["$id"].as_str() {
            registry = registry.add(id, schema.clone()).unwrap();
        }
    }
    let registry = registry.prepare().unwrap();
    let schema: Value = serde_json::from_str(
        &fs::read_to_string(schemas_dir().join(format!("{schema_name}.schema.json"))).unwrap(),
    )
    .unwrap();
    let validator = jsonschema::options()
        .offline()
        .with_registry(&registry)
        .build(&schema)
        .unwrap();
    let errors: Vec<String> = validator
        .iter_errors(document)
        .map(|error| format!("{} at {}", error, error.instance_path()))
        .collect();
    assert!(
        errors.is_empty(),
        "{schema_name} violations: {errors:#?}\n{document:#}"
    );
}

fn git(root: &Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?} failed");
}

/// A repository with one saved review containing one finding.
fn seeded_repository() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    git(root, &["init", "-q"]);
    git(root, &["config", "user.email", "vero@example.invalid"]);
    git(root, &["config", "user.name", "Vero test"]);
    fs::write(root.join("tracked.rs"), "fn main() {}\n").unwrap();
    git(root, &["add", "tracked.rs"]);
    git(root, &["commit", "-qm", "initial"]);
    fs::write(root.join("tracked.rs"), "fn main() { unsafe {} }\n").unwrap();
    fs::write(root.join("reviewer.md"), "Look for correctness defects.\n").unwrap();
    fs::write(root.join("AGENTS.md"), "Prefer explicit error handling.\n").unwrap();
    let provider = root.join("fake-provider");
    fs::write(
        &provider,
        concat!(
            "#!/bin/sh\ninput=$(cat)\n",
            // PR-description tasks ask for an object with a `body`; reviews ask for findings.
            "case \"$input\" in\n",
            "  *'\"body\"'*) printf '%s' '{\"title\":\"Mark main unsafe\",\"body\":\"## Summary\\nAdds an unsafe block to main.\"}' ;;\n",
            "  *) printf '%s' '{\"schema_version\":1,\"findings\":[{\"category\":\"correctness\",\"severity\":\"medium\",\"confidence\":95,\"rationale\":\"potential defect\",\"path\":\"tracked.rs\",\"line\":1}]}' ;;\n",
            "esac\n"
        ),
    )
    .unwrap();
    fs::set_permissions(&provider, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(
        root.join(".vero.yaml"),
        format!(
            "version: 1\nproviders:\n  fake:\n    kind: cli\n    executable: {}\nreviewers:\n  correctness:\n    provider: fake\n    instructions_file: reviewer.md\nverification:\n  unit:\n    executable: /usr/bin/true\npolicy:\n  required_reviewers: [correctness]\n  block_severities: [critical]\n  minimum_confidence: 80\n  on_incomplete: block\n",
            provider.display()
        ),
    )
    .unwrap();
    git(
        root,
        &[
            "add",
            ".vero.yaml",
            "reviewer.md",
            "AGENTS.md",
            "fake-provider",
        ],
    );
    git(root, &["commit", "-qm", "configure vero"]);
    directory
}

fn cli_json(root: &Path, args: &[&str]) -> Value {
    let output = vero()
        .args(args)
        .args(["--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        matches!(output.status.code(), Some(0..=2)),
        "vero {args:?} failed: {}{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "vero {args:?} did not emit JSON ({error}): {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

struct McpSession {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
    next_id: u64,
}

impl McpSession {
    fn start(root: &Path) -> Self {
        let mut child = vero()
            .args(["mcp", "serve", "--transport", "stdio"])
            .current_dir(root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let output = BufReader::new(child.stdout.take().unwrap());
        let mut session = Self {
            child,
            input,
            output,
            next_id: 1,
        };
        session.request(
            "initialize",
            json!({"protocolVersion":"2025-06-18","capabilities":{},
                "clientInfo":{"name":"vero-parity-test","version":"1"}}),
        );
        session.send(json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}));
        session
    }

    fn send(&mut self, message: Value) {
        writeln!(self.input, "{message}").unwrap();
        self.input.flush().unwrap();
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}));
        let mut line = String::new();
        self.output.read_line(&mut line).unwrap();
        let response: Value = serde_json::from_str(&line).unwrap();
        assert!(
            response.get("error").is_none(),
            "{method} failed: {response}"
        );
        response["result"].clone()
    }

    /// Call a tool and return its document. The text block and any structured
    /// content must carry the same JSON.
    fn call(&mut self, tool: &str, arguments: Value) -> Value {
        let result = self.request("tools/call", json!({"name": tool, "arguments": arguments}));
        assert_ne!(
            result["isError"], true,
            "{tool} returned an error: {result}"
        );
        let text = result["content"][0]["text"].as_str().unwrap();
        let document: Value = serde_json::from_str(text).unwrap();
        if let Some(structured) = result.get("structuredContent") {
            assert_eq!(
                structured, &document,
                "{tool} text and structured content differ"
            );
        }
        document
    }
}

impl Drop for McpSession {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn assert_same(cli: &Value, mcp: &Value, operation: &str, schema: &str) {
    assert_eq!(cli, mcp, "{operation}: CLI and MCP documents differ");
    assert_matches_published_schema(cli, schema);
}

#[test]
fn cli_and_mcp_return_identical_documents_for_shared_operations() {
    let repository = seeded_repository();
    let root = repository.path();
    let review = cli_json(root, &["review", "--working-tree"]);
    let review_id = review["review_id"].as_str().unwrap().to_owned();
    let mut mcp = McpSession::start(root);

    let cli = cli_json(root, &["reviews", "show", &review_id]);
    let via_mcp = mcp.call("get_review", json!({"review_id": review_id}));
    assert_same(&cli, &via_mcp, "get review", "review-output-v2");

    let cli = cli_json(root, &["findings", "list"]);
    let via_mcp = mcp.call("list_findings", json!({}));
    assert_same(&cli, &via_mcp, "list findings", "findings-list-v2");
    assert_eq!(cli["total"], 1);
    let finding_id = cli["findings"][0]["finding"]["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let cli = cli_json(root, &["findings", "show", &finding_id]);
    let via_mcp = mcp.call("get_finding", json!({"finding_id": finding_id}));
    assert_same(&cli, &via_mcp, "show finding", "finding-detail-v2");

    let cli = cli_json(root, &["findings", "task", &finding_id]);
    let via_mcp = mcp.call("get_finding_task", json!({"finding_id": finding_id}));
    assert_same(&cli, &via_mcp, "finding task", "finding-task-v3");

    let cli = cli_json(root, &["findings", "package", &finding_id]);
    let via_mcp = mcp.call(
        "get_finding_work_package",
        json!({"finding_ids": [finding_id]}),
    );
    assert_same(
        &cli,
        &via_mcp,
        "finding work package",
        "finding-work-package-v2",
    );

    let cli = cli_json(root, &["impact", "--review", &review_id]);
    let via_mcp = mcp.call("analyze_impact", json!({"review_id": review_id}));
    assert_same(&cli, &via_mcp, "impact", "impact-assessment-v3");

    let cli = cli_json(root, &["acceptance", "report", "--review", &review_id]);
    let via_mcp = mcp.call("acceptance_traceability", json!({"review_id": review_id}));
    assert_same(&cli, &via_mcp, "acceptance", "acceptance-traceability-v1");

    let cli = cli_json(root, &["standards", "--path", "tracked.rs"]);
    let via_mcp = mcp.call("get_applicable_standards", json!({"path": "tracked.rs"}));
    assert_same(&cli, &via_mcp, "standards", "standards-resolution-v1");

    let cli = cli_json(root, &["rules", "candidates"]);
    let via_mcp = mcp.call("list_rule_candidates", json!({}));
    assert_same(&cli, &via_mcp, "rule candidates", "rule-candidates-v3");

    let cli = cli_json(root, &["gate", "check", "--review", &review_id]);
    let via_mcp = mcp.call("evaluate_gate", json!({"review_id": review_id}));
    assert_same(&cli, &via_mcp, "gate check", "gate-check-v1");

    let cli = cli_json(
        root,
        &[
            "findings",
            "set-status",
            &finding_id,
            "--status",
            "verified",
            "--reason",
            "confirmed in source",
        ],
    );
    let via_mcp = mcp.call(
        "set_finding_status",
        json!({"finding_id": finding_id, "status": "verified", "reason": "confirmed in source"}),
    );
    assert_same(
        &cli,
        &via_mcp,
        "set finding status",
        "finding-status-update-v1",
    );

    let cli = cli_json(root, &["verify", &finding_id, "--profile", "unit"]);
    let via_mcp = mcp.call(
        "verify_finding",
        json!({"finding_id": finding_id, "profile_id": "unit"}),
    );
    assert_matches_published_schema(&cli, "verification-run-v1");
    assert_matches_published_schema(&via_mcp, "verification-run-v1");
    assert_eq!(cli["snapshot_id"], via_mcp["snapshot_id"]);
    assert_eq!(cli["finding_id"], via_mcp["finding_id"]);

    let cli = cli_json(root, &["tests", "recommend", "--review", &review_id]);
    let via_mcp = mcp.call("recommend_tests", json!({"review_id": review_id}));
    assert_same(&cli, &via_mcp, "recommend tests", "test-recommendations-v1");

    let cli = cli_json(root, &["owners", "--path", "tracked.rs"]);
    let via_mcp = mcp.call("resolve_owners", json!({"paths": ["tracked.rs"]}));
    assert_same(&cli, &via_mcp, "owners", "ownership-report-v1");

    let cli = cli_json(root, &["waivers", "list", "--review", &review_id]);
    let via_mcp = mcp.call("list_waivers", json!({"review_id": review_id}));
    assert_same(&cli, &via_mcp, "waivers", "waivers-list-v1");

    let cli = cli_json(root, &["gate", "history", "--review", &review_id]);
    let via_mcp = mcp.call("get_gate_history", json!({"review_id": review_id}));
    assert_same(&cli, &via_mcp, "gate history", "gate-history-v1");
    // Both gate checks evaluated identical inputs, so they share one decision identity.
    assert_eq!(cli["decisions"].as_array().unwrap().len(), 1);

    let cli = cli_json(root, &["pr", "draft", "--review", &review_id]);
    let via_mcp = mcp.call("draft_pr_description", json!({"review_id": review_id}));
    assert_matches_published_schema(&cli, "pr-description-v1");
    assert_eq!(cli["output"], via_mcp["output"]);
    assert_eq!(cli["snapshot_id"], via_mcp["snapshot_id"]);
    assert_matches_published_schema(&via_mcp, "pr-description-v1");

    // Two different patches, so each transport saves its own immutable proposal.
    let patch = |replacement: &str| {
        format!(
            "diff --git a/tracked.rs b/tracked.rs\n--- a/tracked.rs\n+++ b/tracked.rs\n@@ -1 +1 @@\n-fn main() {{ unsafe {{}} }}\n+{replacement}\n"
        )
    };
    // Outside the repository: an untracked file would change the reviewed snapshot.
    let patch_directory = tempfile::tempdir().unwrap();
    let patch_file = patch_directory.path().join("cli.patch");
    fs::write(&patch_file, patch("fn main() {}")).unwrap();
    let cli = cli_json(
        root,
        &[
            "findings",
            "propose-patch",
            "--review",
            &review_id,
            patch_file.to_str().unwrap(),
        ],
    );
    let via_mcp = mcp.call(
        "propose_patch",
        json!({"review_id": review_id, "patch": patch("fn main() { let _ = 1; }")}),
    );
    for proposal in [&cli, &via_mcp] {
        assert_matches_published_schema(proposal, "patch-proposal-v1");
        assert_eq!(proposal["application"], "not_applied");
        assert_eq!(proposal["review_id"], review_id.as_str());
    }
    assert_ne!(cli["patch_digest"], via_mcp["patch_digest"]);
    assert_eq!(
        fs::read_to_string(root.join("tracked.rs")).unwrap(),
        "fn main() { unsafe {} }\n",
        "proposing must not change repository files"
    );

    let cli = cli_json(root, &["doctor"]);
    let via_mcp = mcp.call("check_setup", json!({}));
    assert_same(&cli, &via_mcp, "doctor", "doctor-report-v1");
    assert_eq!(cli["ready"], true, "{cli:#}");

    let cli = cli_json(root, &["analytics"]);
    let via_mcp = mcp.call("get_quality_analytics", json!({}));
    assert_same(&cli, &via_mcp, "analytics", "quality-analytics-v9");
}

#[test]
fn both_transports_reject_waiving_through_a_status_change() {
    let repository = seeded_repository();
    let root = repository.path();
    cli_json(root, &["review", "--working-tree"]);
    let finding_id = cli_json(root, &["findings", "list"])["findings"][0]["finding"]["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let cli = vero()
        .args([
            "findings",
            "set-status",
            &finding_id,
            "--status",
            "waived",
            "--reason",
            "skip",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    // The CLI does not offer `waived` as a status value, so the argument parser rejects it.
    assert_eq!(
        cli.status.code(),
        Some(3),
        "waiving via set-status must be a usage error"
    );
    let message = String::from_utf8_lossy(&cli.stderr);
    assert!(message.contains("invalid value 'waived'"), "{message}");

    let mut mcp = McpSession::start(root);
    let result = mcp.request(
        "tools/call",
        json!({"name":"set_finding_status","arguments":{"finding_id":finding_id,"status":"waived","reason":"skip"}}),
    );
    assert_eq!(result["isError"], true);
    assert!(result["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("waiver workflow"));
}
