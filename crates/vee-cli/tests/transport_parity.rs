//! The CLI and the MCP server are two transports over one set of operations.
//! For every operation both expose, `--output json` and the MCP tool result must be
//! the same document, and that document must satisfy the published schema.
#![cfg(unix)]

use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

/// A `vee` invocation isolated from the developer's machine. Setup detection
/// probes agent CLIs on PATH, a local Ollama, API keys, and the user config;
/// the CLI and the MCP server probe separately, so any of those answering
/// differently between the two calls would make their documents differ.
fn vee() -> Command {
    static HOME: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
    let home = HOME.get_or_init(|| tempfile::tempdir().unwrap());
    let mut command = Command::new(env!("CARGO_BIN_EXE_vee"));
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
    git(root, &["config", "user.email", "vee@example.invalid"]);
    git(root, &["config", "user.name", "Vee test"]);
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
        root.join(".vee.yaml"),
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
            ".vee.yaml",
            "reviewer.md",
            "AGENTS.md",
            "fake-provider",
        ],
    );
    git(root, &["commit", "-qm", "configure vee"]);
    directory
}

fn cli_json(root: &Path, args: &[&str]) -> Value {
    let output = vee()
        .args(args)
        .args(["--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        matches!(output.status.code(), Some(0..=2)),
        "vee {args:?} failed: {}{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "vee {args:?} did not emit JSON ({error}): {}",
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
        let mut child = vee()
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
                "clientInfo":{"name":"vee-parity-test","version":"1"}}),
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

    /// Call a tool and return its document. A tool with a shared view returns
    /// that view as Markdown text and the document as structured content;
    /// other tools return the document as JSON text.
    fn call(&mut self, tool: &str, arguments: Value) -> Value {
        self.call_with_text(tool, arguments).0
    }

    fn call_with_text(&mut self, tool: &str, arguments: Value) -> (Value, String) {
        let result = self.request("tools/call", json!({"name": tool, "arguments": arguments}));
        assert_ne!(
            result["isError"], true,
            "{tool} returned an error: {result}"
        );
        let text = result["content"][0]["text"].as_str().unwrap().to_owned();
        let document = match serde_json::from_str::<Value>(&text) {
            Ok(document) => {
                if let Some(structured) = result.get("structuredContent") {
                    assert_eq!(
                        structured, &document,
                        "{tool} text and structured content differ"
                    );
                }
                document
            }
            Err(_) => result.get("structuredContent").cloned().unwrap_or_else(|| {
                panic!("{tool} returned a text view without structured content")
            }),
        };
        (document, text)
    }
}

impl Drop for McpSession {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Both transports show the same view of the same document: MCP as Markdown,
/// the CLI as terminal text (`--color never` here, so it is comparable).
fn assert_same_view<T>(root: &Path, cli_args: &[&str], document: &Value, mcp_text: &str)
where
    T: serde::de::DeserializeOwned + vee_present::ToView,
{
    let typed: T = serde_json::from_value(document.clone())
        .unwrap_or_else(|error| panic!("{cli_args:?}: document does not deserialize: {error}"));
    let view = typed.to_view();
    assert_eq!(
        mcp_text,
        vee_present::markdown::render(&view),
        "{cli_args:?}: MCP text is not the shared view"
    );
    let output = vee()
        .args(cli_args)
        .args(["--color", "never"])
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        vee_present::ansi::render(&view, false),
        "{cli_args:?}: CLI text is not the shared view"
    );
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
    let (via_mcp, text) = mcp.call_with_text("get_review", json!({"review_id": review_id}));
    assert_same(&cli, &via_mcp, "get review", "review-output-v2");
    assert_same_view::<vee_application::ReviewResult>(
        root,
        &["reviews", "show", &review_id],
        &via_mcp,
        &text,
    );

    let cli = cli_json(root, &["findings", "list"]);
    let (via_mcp, text) = mcp.call_with_text("list_findings", json!({}));
    assert_same(&cli, &via_mcp, "list findings", "findings-list-v2");
    assert_same_view::<vee_application::operations::FindingsPage>(
        root,
        &["findings", "list"],
        &via_mcp,
        &text,
    );
    assert_eq!(cli["total"], 1);
    let finding_id = cli["findings"][0]["finding"]["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let cli = cli_json(root, &["findings", "show", &finding_id]);
    let (via_mcp, text) = mcp.call_with_text("get_finding", json!({"finding_id": finding_id}));
    assert_same_view::<vee_application::operations::FindingDetail>(
        root,
        &["findings", "show", &finding_id],
        &via_mcp,
        &text,
    );
    assert_same(&cli, &via_mcp, "show finding", "finding-detail-v2");

    let cli = cli_json(root, &["findings", "task", &finding_id]);
    let (via_mcp, text) = mcp.call_with_text("get_finding_task", json!({"finding_id": finding_id}));
    assert_same(&cli, &via_mcp, "finding task", "finding-task-v4");
    assert_same_view::<vee_application::finding_task::FindingTask>(
        root,
        &["findings", "task", &finding_id],
        &via_mcp,
        &text,
    );

    let cli = cli_json(root, &["findings", "package", &finding_id]);
    let (via_mcp, text) = mcp.call_with_text(
        "get_finding_work_package",
        json!({"finding_ids": [finding_id]}),
    );
    assert_same(
        &cli,
        &via_mcp,
        "finding work package",
        "finding-work-package-v3",
    );
    assert_same_view::<vee_application::finding_task::FindingWorkPackage>(
        root,
        &["findings", "package", &finding_id],
        &via_mcp,
        &text,
    );

    // `gate approval` exits non-zero when the change needs a human, so read its
    // JSON regardless of the exit status.
    let output = vee()
        .args([
            "gate", "approval", "--review", &review_id, "--output", "json",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    let cli: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let (via_mcp, text) = mcp.call_with_text(
        "check_approval_eligibility",
        json!({"review_id": review_id}),
    );
    assert_same(&cli, &via_mcp, "approval", "approval-eligibility-v1");
    assert_same_view::<vee_application::ApprovalEligibility>(
        root,
        &["gate", "approval", "--review", &review_id],
        &via_mcp,
        &text,
    );

    let output = vee()
        .args([
            "reviews", "session", "--review", &review_id, "--output", "json",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    let cli: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let (via_mcp, text) = mcp.call_with_text("review_session", json!({"review_ids": [review_id]}));
    assert_same(&cli, &via_mcp, "session", "review-session-v1");
    assert_same_view::<vee_application::ReviewSession>(
        root,
        &["reviews", "session", "--review", &review_id],
        &via_mcp,
        &text,
    );

    let cli = cli_json(root, &["risk", "--review", &review_id]);
    let (via_mcp, text) = mcp.call_with_text("assess_change_risk", json!({"review_id": review_id}));
    assert_same(&cli, &via_mcp, "risk", "change-risk-v1");
    assert_same_view::<vee_application::ChangeRisk>(
        root,
        &["risk", "--review", &review_id],
        &via_mcp,
        &text,
    );

    let cli = cli_json(root, &["impact", "--review", &review_id]);
    let (via_mcp, text) = mcp.call_with_text("analyze_impact", json!({"review_id": review_id}));
    assert_same(&cli, &via_mcp, "impact", "impact-assessment-v4");
    assert_same_view::<vee_application::ImpactAssessment>(
        root,
        &["impact", "--review", &review_id],
        &via_mcp,
        &text,
    );

    let cli = cli_json(root, &["acceptance", "report", "--review", &review_id]);
    let (via_mcp, text) =
        mcp.call_with_text("acceptance_traceability", json!({"review_id": review_id}));
    assert_same(&cli, &via_mcp, "acceptance", "acceptance-traceability-v1");
    assert_same_view::<vee_application::acceptance::AcceptanceReport>(
        root,
        &["acceptance", "report", "--review", &review_id],
        &via_mcp,
        &text,
    );

    let cli = cli_json(root, &["standards", "--path", "tracked.rs"]);
    let (via_mcp, text) =
        mcp.call_with_text("get_applicable_standards", json!({"path": "tracked.rs"}));
    assert_same(&cli, &via_mcp, "standards", "standards-resolution-v1");
    assert_same_view::<vee_application::standards::StandardsReport>(
        root,
        &["standards", "--path", "tracked.rs"],
        &via_mcp,
        &text,
    );

    let cli = cli_json(root, &["rules", "candidates"]);
    let (via_mcp, text) = mcp.call_with_text("list_rule_candidates", json!({}));
    assert_same(&cli, &via_mcp, "rule candidates", "rule-candidates-v3");
    assert_same_view::<vee_application::rule_candidates::CandidateReport>(
        root,
        &["rules", "candidates"],
        &via_mcp,
        &text,
    );

    let cli = cli_json(root, &["gate", "check", "--review", &review_id]);
    let (via_mcp, text) = mcp.call_with_text("evaluate_gate", json!({"review_id": review_id}));
    assert_same(&cli, &via_mcp, "gate check", "gate-check-v1");
    // Re-evaluating identical inputs yields the same decision, so this adds no history.
    assert_same_view::<vee_application::GateCheckResult>(
        root,
        &["gate", "check", "--review", &review_id],
        &via_mcp,
        &text,
    );

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
    let verified_snapshot = cli["snapshot_id"].as_str().unwrap().to_owned();
    let cli = cli_json(
        root,
        &["verification", "list", "--snapshot", &verified_snapshot],
    );
    let (via_mcp, text) = mcp.call_with_text(
        "list_verification_runs",
        json!({"snapshot_id": verified_snapshot}),
    );
    assert_same(&cli, &via_mcp, "verification list", "verification-list-v1");
    // Both transports ran the same command on the same snapshot: one content-addressed run.
    assert_eq!(cli["runs"].as_array().unwrap().len(), 1, "{cli:#}");
    assert_same_view::<vee_application::operations::VerificationList>(
        root,
        &["verification", "list", "--snapshot", &verified_snapshot],
        &via_mcp,
        &text,
    );

    let cli = cli_json(root, &["tests", "recommend", "--review", &review_id]);
    let (via_mcp, text) = mcp.call_with_text("recommend_tests", json!({"review_id": review_id}));
    assert_same(&cli, &via_mcp, "recommend tests", "test-recommendations-v1");
    assert_same_view::<vee_application::test_recommendations::TestRecommendationReport>(
        root,
        &["tests", "recommend", "--review", &review_id],
        &via_mcp,
        &text,
    );

    let cli = cli_json(root, &["owners", "--path", "tracked.rs"]);
    let (via_mcp, text) = mcp.call_with_text("resolve_owners", json!({"paths": ["tracked.rs"]}));
    assert_same(&cli, &via_mcp, "owners", "ownership-report-v1");
    assert_same_view::<vee_application::ownership::OwnershipReport>(
        root,
        &["owners", "--path", "tracked.rs"],
        &via_mcp,
        &text,
    );

    let cli = cli_json(root, &["waivers", "list", "--review", &review_id]);
    let (via_mcp, text) = mcp.call_with_text("list_waivers", json!({"review_id": review_id}));
    assert_same_view::<vee_application::operations::WaiverList>(
        root,
        &["waivers", "list", "--review", &review_id],
        &via_mcp,
        &text,
    );
    assert_same(&cli, &via_mcp, "waivers", "waivers-list-v1");

    let cli = cli_json(root, &["gate", "history", "--review", &review_id]);
    let (via_mcp, text) = mcp.call_with_text("get_gate_history", json!({"review_id": review_id}));
    assert_same(&cli, &via_mcp, "gate history", "gate-history-v1");
    // Both gate checks evaluated identical inputs, so they share one decision identity.
    assert_eq!(cli["decisions"].as_array().unwrap().len(), 1);
    assert_same_view::<vee_application::operations::GateHistory>(
        root,
        &["gate", "history", "--review", &review_id],
        &via_mcp,
        &text,
    );

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
    let (via_mcp, text) = mcp.call_with_text(
        "propose_patch",
        json!({"review_id": review_id, "patch": patch("fn main() { let _ = 1; }")}),
    );
    // Proposals are immutable records, so only the MCP side renders this one.
    let proposal: vee_application::operations::PatchProposal =
        serde_json::from_value(via_mcp.clone()).unwrap();
    assert_eq!(
        text,
        vee_present::markdown::render(&vee_present::ToView::to_view(&proposal))
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
    let (via_mcp, text) = mcp.call_with_text("check_setup", json!({}));
    assert_same(&cli, &via_mcp, "doctor", "doctor-report-v1");
    assert_same_view::<vee_application::setup::DoctorReport>(root, &["doctor"], &via_mcp, &text);
    assert_eq!(cli["ready"], true, "{cli:#}");

    let cli = cli_json(root, &["analytics"]);
    let (via_mcp, text) = mcp.call_with_text("get_quality_analytics", json!({}));
    assert_same(&cli, &via_mcp, "analytics", "quality-analytics-v9");
    assert_same_view::<vee_application::analytics::QualityAnalytics>(
        root,
        &["analytics"],
        &via_mcp,
        &text,
    );

    let archive = tempfile::NamedTempFile::new().unwrap();
    fs::write(archive.path(), serde_json::to_vec(&review).unwrap()).unwrap();
    let imported = vee()
        .args(["reviews", "import"])
        .arg(archive.path())
        .current_dir(root)
        .output()
        .unwrap();
    assert!(imported.status.success(), "{imported:?}");
    let cli = cli_json(root, &["reviews", "imported", "search", "potential defect"]);
    assert_eq!(cli["matches"].as_array().unwrap().len(), 1, "{cli:#}");
    let (via_mcp, text) = mcp.call_with_text(
        "search_imported_review_history",
        json!({"query": "potential defect"}),
    );
    assert_same(
        &cli,
        &via_mcp,
        "imported search",
        "imported-review-search-v3",
    );
    assert_same_view::<vee_application::imported_history::ImportedHistorySearch>(
        root,
        &["reviews", "imported", "search", "potential defect"],
        &via_mcp,
        &text,
    );

    let cli = cli_json(root, &["reviews", "list"]);
    let (via_mcp, text) = mcp.call_with_text("list_reviews", json!({}));
    assert_same(&cli, &via_mcp, "reviews list", "reviews-list-v1");
    assert_eq!(cli["reviews"][0]["review_id"], review_id);
    assert_same_view::<vee_application::operations::ReviewsList>(
        root,
        &["reviews", "list"],
        &via_mcp,
        &text,
    );

    let snapshot_id = review["snapshot_id"].as_str().unwrap();
    cli_json(
        root,
        &[
            "findings",
            "feedback",
            "set",
            &finding_id,
            "--snapshot",
            snapshot_id,
            "--label",
            "confirmed",
            "--reason",
            "Reproduced the defect.",
            "--reviewer",
            "maintainer",
        ],
    );
    let cli = cli_json(
        root,
        &["findings", "feedback", "list", "--finding", &finding_id],
    );
    let (via_mcp, text) =
        mcp.call_with_text("list_finding_feedback", json!({"finding_id": finding_id}));
    assert_same(&cli, &via_mcp, "feedback list", "finding-feedback-list-v1");
    assert_eq!(cli["feedback"].as_array().unwrap().len(), 1, "{cli:#}");
    assert_same_view::<vee_application::operations::FindingFeedbackList>(
        root,
        &["findings", "feedback", "list", "--finding", &finding_id],
        &via_mcp,
        &text,
    );
}

#[test]
fn both_transports_record_the_same_work_item_credential_for_later_gate_checks() {
    let repository = seeded_repository();
    let root = repository.path();
    let cli = cli_json(root, &["review", "--working-tree"]);
    let mut mcp = McpSession::start(root);
    let via_mcp = mcp.call("review_changes", json!({"scope": "working_tree"}));
    // A later `gate check` re-fetches the work item with this variable, so a
    // review started over MCP must record the one the CLI would.
    assert_eq!(cli["work_item_token_env"], "GH_TOKEN");
    assert_eq!(via_mcp["work_item_token_env"], cli["work_item_token_env"]);
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

    let cli = vee()
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

/// The CLI's `--color never` text for `args`.
fn cli_text(root: &Path, args: &[&str]) -> String {
    let output = vee()
        .args(args)
        .args(["--color", "never"])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "vee {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

/// The MCP text of a write operation is the Markdown view of its own document.
fn assert_mcp_view<T>(document: &Value, mcp_text: &str, operation: &str)
where
    T: serde::de::DeserializeOwned + vee_present::ToView,
{
    let typed: T = serde_json::from_value(document.clone())
        .unwrap_or_else(|error| panic!("{operation}: document does not deserialize: {error}"));
    assert_eq!(
        mcp_text,
        vee_present::markdown::render(&typed.to_view()),
        "{operation}: MCP text is not the shared view"
    );
}

/// The terminal view of `document`, as `--color never` prints it.
fn terminal_view<T>(document: Value) -> String
where
    T: serde::de::DeserializeOwned + vee_present::ToView,
{
    let typed: T = serde_json::from_value(document).unwrap();
    vee_present::ansi::render(&typed.to_view(), false)
}

/// A repository holding one archived provider discussion with three comments.
fn repository_with_provider_discussion() -> (tempfile::TempDir, String) {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    git(root, &["init", "-q"]);
    fs::write(root.join(".vee.yaml"), "version: 1\n").unwrap();
    let issue = |id: &str, line: u64| {
        json!({
            "external_id": id,
            "author": "reviewer",
            "body": "Check the retry bound",
            "path": "src/retry.rs",
            "line": line,
            "side": null,
            "source_url": null,
            "created_at": null,
            "updated_at": null,
            "classification": "untrusted_external_review"
        })
    };
    let discussion = json!({
        "schema_version": 1,
        "provider": "github",
        "pull_request": {
            "repository": {"host": "github.com", "full_name": "example/service"},
            "number": 9
        },
        "revision": "b".repeat(40),
        "complete": true,
        "gate_eligible": false,
        "issues": [issue("42", 18), issue("43", 19), issue("44", 20)]
    });
    let digest = vee_application::imported_history::store_imported_history(
        root,
        &serde_json::to_vec(&discussion).unwrap(),
    )
    .unwrap();
    (directory, digest)
}

/// Recording a label or an approval creates a new timestamped record on each
/// call, so for those writes each transport's document is checked against the
/// schema and its own view rather than against the other transport's. The
/// CLI text of a write is compared with the view of the record it saved, read
/// back through the list command.
#[test]
fn cli_and_mcp_share_external_feedback_and_rule_guidance_documents() {
    let (repository, archive_digest) = repository_with_provider_discussion();
    let root = repository.path();
    let archive_digest = archive_digest.as_str();
    let mut mcp = McpSession::start(root);
    let reason = "The retry bound is enforced by the caller.";
    let feedback_list = ["reviews", "imported", "feedback", "list"];

    let cli = cli_json(root, &feedback_list);
    let (via_mcp, text) = mcp.call_with_text("list_external_review_feedback", json!({}));
    assert_same(
        &cli,
        &via_mcp,
        "empty external feedback list",
        "external-review-feedback-list-v1",
    );
    assert_same_view::<vee_application::operations::ExternalFeedbackList>(
        root,
        &feedback_list,
        &via_mcp,
        &text,
    );

    let set = |external_id: &'static str| {
        [
            "reviews",
            "imported",
            "feedback",
            "set",
            archive_digest,
            external_id,
            "--category",
            "correctness",
            "--label",
            "false-positive",
            "--reason",
            reason,
            "--reviewer",
            "maintainer",
        ]
    };
    let cli = cli_json(root, &set("42"));
    assert_matches_published_schema(&cli, "external-review-feedback-recorded-v1");
    let (via_mcp, text) = mcp.call_with_text(
        "record_external_review_feedback",
        json!({"archive_digest": archive_digest, "external_id": "43", "category": "correctness",
            "label": "false_positive", "reason": reason, "reviewer": "maintainer"}),
    );
    assert_matches_published_schema(&via_mcp, "external-review-feedback-recorded-v1");
    assert_mcp_view::<vee_application::operations::ExternalFeedbackRecorded>(
        &via_mcp,
        &text,
        "record external feedback",
    );
    let printed = cli_text(root, &set("44"));

    let filtered = [
        "reviews",
        "imported",
        "feedback",
        "list",
        "--archive-digest",
        archive_digest,
    ];
    let cli = cli_json(root, &filtered);
    let (via_mcp, text) = mcp.call_with_text(
        "list_external_review_feedback",
        json!({"archive_digest": archive_digest}),
    );
    assert_same(
        &cli,
        &via_mcp,
        "external feedback list",
        "external-review-feedback-list-v1",
    );
    assert_eq!(cli["feedback"].as_array().unwrap().len(), 3, "{cli:#}");
    assert_same_view::<vee_application::operations::ExternalFeedbackList>(
        root, &filtered, &via_mcp, &text,
    );
    let saved = cli["feedback"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["external_id"] == "44")
        .unwrap()
        .clone();
    assert_eq!(
        printed,
        terminal_view::<vee_application::operations::ExternalFeedbackRecorded>(json!({
            "schema_version": 1,
            "feedback": saved,
            "trust": "human_labeled_external_context",
            "gate_eligible": false
        })),
        "CLI text of feedback set is not the shared view"
    );

    let candidates = cli_json(root, &["rules", "candidates"]);
    assert_eq!(
        candidates["candidates"].as_array().unwrap().len(),
        1,
        "{candidates:#}"
    );
    let candidate_id = candidates["candidates"][0]["candidate_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let evidence_digest = candidates["candidates"][0]["evidence_digest"]
        .as_str()
        .unwrap()
        .to_owned();
    // One active approval per candidate and scope, so each approval gets its own scope.
    let approve = |scope: &'static str| {
        [
            "rules",
            "approve",
            candidate_id.as_str(),
            "--evidence-digest",
            evidence_digest.as_str(),
            "--scope",
            scope,
            "--instruction",
            "Ask for the caller's retry bound before reporting this pattern.",
            "--approver",
            "maintainer",
            "--reason",
            "Reviewed the three archived discussion labels.",
        ]
    };
    let cli_approval = cli_json(root, &approve("src/cli.rs"));
    assert_matches_published_schema(&cli_approval, "rule-approval-v2");
    assert_eq!(cli_approval["status"], "active");
    let (mcp_approval, text) = mcp.call_with_text(
        "approve_rule_candidate",
        json!({"candidate_id": candidate_id, "evidence_digest": evidence_digest,
            "scope": "src/mcp.rs",
            "instruction": "Ask for the caller's retry bound before reporting this pattern.",
            "approver": "maintainer", "reason": "Reviewed the three archived discussion labels."}),
    );
    assert_matches_published_schema(&mcp_approval, "rule-approval-v2");
    assert_mcp_view::<vee_core::RuleApproval>(&mcp_approval, &text, "approve rule");
    let printed = cli_text(root, &approve("src/text.rs"));

    let cli = cli_json(root, &["rules", "list"]);
    let (via_mcp, text) = mcp.call_with_text("list_rule_approvals", json!({}));
    assert_same(&cli, &via_mcp, "rule approvals", "rule-approval-list-v1");
    assert_same_view::<vee_application::operations::RuleApprovalList>(
        root,
        &["rules", "list"],
        &via_mcp,
        &text,
    );
    let approval_with_scope = |list: &Value, scope: &str| {
        list["approvals"]
            .as_array()
            .unwrap()
            .iter()
            .find(|approval| approval["scope"] == scope)
            .unwrap()
            .clone()
    };
    assert_eq!(approval_with_scope(&cli, "src/cli.rs"), cli_approval);
    assert_eq!(approval_with_scope(&cli, "src/mcp.rs"), mcp_approval);
    let text_approval = approval_with_scope(&cli, "src/text.rs");
    assert_eq!(
        printed,
        terminal_view::<vee_core::RuleApproval>(text_approval.clone()),
        "CLI text of rules approve is not the shared view"
    );

    let revoke = |approval: &Value| -> Vec<String> {
        let approval_id = approval["approval_id"].as_str().unwrap();
        ["rules", "revoke", approval_id, "--actor", "maintainer"]
            .into_iter()
            .chain(["--reason", "Superseded by repository policy."])
            .map(str::to_owned)
            .collect()
    };
    let args = revoke(&cli_approval);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let revoked = cli_json(root, &args);
    assert_matches_published_schema(&revoked, "rule-approval-v2");
    assert_eq!(revoked["status"], "revoked");
    let (via_mcp, text) = mcp.call_with_text(
        "revoke_rule_approval",
        json!({"approval_id": mcp_approval["approval_id"], "actor": "maintainer",
            "reason": "Superseded by repository policy."}),
    );
    assert_matches_published_schema(&via_mcp, "rule-approval-v2");
    assert_eq!(via_mcp["status"], "revoked");
    assert_mcp_view::<vee_core::RuleApproval>(&via_mcp, &text, "revoke rule");
    let args = revoke(&text_approval);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let printed = cli_text(root, &args);

    let cli = cli_json(root, &["rules", "list"]);
    let (via_mcp, text) = mcp.call_with_text("list_rule_approvals", json!({}));
    assert_same(
        &cli,
        &via_mcp,
        "revoked rule approvals",
        "rule-approval-list-v1",
    );
    assert!(cli["approvals"]
        .as_array()
        .unwrap()
        .iter()
        .all(|approval| approval["status"] == "revoked"));
    assert_same_view::<vee_application::operations::RuleApprovalList>(
        root,
        &["rules", "list"],
        &via_mcp,
        &text,
    );
    assert_eq!(
        printed,
        terminal_view::<vee_core::RuleApproval>(approval_with_scope(&cli, "src/text.rs")),
        "CLI text of rules revoke is not the shared view"
    );
}

/// `get_repository_context` has no CLI command, so only the MCP side is checked.
#[test]
fn repository_context_text_is_the_shared_view_of_its_document() {
    let repository = seeded_repository();
    let root = repository.path();
    let review = cli_json(root, &["review", "--working-tree"]);
    let review_id = review["review_id"].as_str().unwrap();
    let mut mcp = McpSession::start(root);
    let (document, text) = mcp.call_with_text(
        "get_repository_context",
        json!({"review_id": review_id, "path": "tracked.rs", "symbol": "unsafe"}),
    );
    assert_matches_published_schema(&document, "repository-context-v2");
    assert_eq!(document["matching_lines"], json!([1]));
    assert_eq!(document["snapshot_id"], review["snapshot_id"]);
    assert_mcp_view::<vee_application::operations::RepositoryContext>(
        &document,
        &text,
        "repository context",
    );
    assert!(text.contains("`fn main() { unsafe {} }`"), "{text}");
}
