//! Trusted SARIF analyzers: results on changed lines block the gate at the
//! configured levels, results elsewhere never block, waivers apply, and the
//! decision replays from its recorded inputs.
#![cfg(unix)]

use serde_json::Value;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

mod support;
use support::vee as vee_command;

fn git(root: &Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(root)
        .args([
            "-c",
            "user.name=Vee Test",
            "-c",
            "user.email=vee@example.invalid",
        ])
        .args(args)
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?} failed");
}

fn executable(path: &Path, script: &str) {
    fs::write(path, script).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn vee(root: &Path, args: &[&str]) -> (Option<i32>, Value) {
    let output = vee_command()
        .args(args)
        .args(["--output", "json"])
        .current_dir(root)
        .output()
        .unwrap();
    let document = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "vee {args:?} did not print JSON ({error}): {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (output.status.code(), document)
}

/// SARIF with an `error` on changed line 2, an `error` on untouched line 1, and a
/// `warning` (from the rule default) on changed line 3, plus a suppressed `error`.
const SARIF: &str = r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"fakelint","semanticVersion":"1.2.3","rules":[{"id":"W1","defaultConfiguration":{"level":"warning"}}]}},"results":[
{"ruleId":"E1","level":"error","message":{"text":"changed line defect"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/lib.rs"},"region":{"startLine":2}}}]},
{"ruleId":"E1","level":"error","message":{"text":"pre-existing defect"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/lib.rs"},"region":{"startLine":1}}}]},
{"ruleId":"E1","level":"error","message":{"text":"accepted by the team"},"suppressions":[{"kind":"external","status":"accepted"}],"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/lib.rs"},"region":{"startLine":2}}}]},
{"ruleId":"W1","ruleIndex":0,"message":{"text":"style"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/lib.rs"},"region":{"startLine":3}}}]}
]}]}"#;

struct Fixture {
    _repository: tempfile::TempDir,
    _tools: tempfile::TempDir,
}

/// A repository whose working tree changes lines 2 and 3 of `src/lib.rs`, with a
/// required SARIF analyzer that blocks on `error`.
fn repository(analyzer_script: impl FnOnce(&Path) -> String) -> (Fixture, std::path::PathBuf) {
    let repository = tempfile::tempdir().unwrap();
    let tools = tempfile::tempdir().unwrap();
    let root = repository.path().to_path_buf();
    git(&root, &["init", "-q"]);
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(root.join("src/lib.rs"), "fn a() {}\nfn b() {}\nfn c() {}\n").unwrap();
    fs::write(root.join("reviewer.md"), "Review for correctness.\n").unwrap();
    let provider = tools.path().join("provider");
    executable(
        &provider,
        "#!/bin/sh\ncat >/dev/null\nprintf '%s' '{\"schema_version\":1,\"findings\":[]}'\n",
    );
    let analyzer = tools.path().join("fakelint");
    executable(&analyzer, &analyzer_script(tools.path()));
    fs::write(
        root.join(".vee.yaml"),
        format!(
            "version: 1\nproviders:\n  fake:\n    kind: cli\n    executable: {}\nreviewers:\n  correctness:\n    provider: fake\n    instructions_file: reviewer.md\nverification:\n  lint:\n    executable: {}\n    sarif:\n      block_levels: [error]\npolicy:\n  required_reviewers: [correctness]\n  required_verifications: [lint]\n  block_severities: [critical]\n  on_incomplete: block\n",
            provider.display(),
            analyzer.display()
        ),
    )
    .unwrap();
    git(&root, &["add", "."]);
    git(&root, &["commit", "-qm", "baseline"]);
    fs::write(
        root.join("src/lib.rs"),
        "fn a() {}\nfn b() { todo!() }\nfn c() { 1 }\n",
    )
    .unwrap();
    (
        Fixture {
            _repository: repository,
            _tools: tools,
        },
        root,
    )
}

/// Analyzers usually exit non-zero when they report results.
fn reporting_analyzer(tools: &Path) -> String {
    fs::write(tools.join("report.sarif"), SARIF).unwrap();
    format!(
        "#!/bin/sh\ncat '{}'\nexit 1\n",
        tools.join("report.sarif").display()
    )
}

#[test]
fn analyzer_results_on_changed_lines_block_and_can_be_waived() {
    let (_fixture, root) = repository(reporting_analyzer);

    let (code, run) = vee(&root, &["verify", "--profile", "lint", "--working-tree"]);
    assert_eq!(code, Some(1), "the analyzer exited 1: {run:#}");
    let run_id = run["run_id"].as_str().unwrap().to_owned();

    let (code, report) = vee(&root, &["verification", "findings", &run_id]);
    assert_eq!(code, Some(0), "{report:#}");
    assert_eq!(report["parsed"], true);
    assert_eq!(report["tools"], serde_json::json!(["fakelint 1.2.3"]));
    assert_eq!(report["results_total"], 4);
    assert_eq!(
        report["results_suppressed"], 1,
        "accepted suppressions never block"
    );
    assert_eq!(report["results_outside_changes"], 1, "line 1 is unchanged");
    let findings = report["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 2);
    assert_eq!(findings[0]["line"], 2);
    assert_eq!(findings[0]["level"], "error");
    assert_eq!(findings[1]["line"], 3);
    assert_eq!(
        findings[1]["level"], "warning",
        "level falls back to the rule default"
    );
    let blocking_id = findings[0]["id"].as_str().unwrap().to_owned();

    let (code, review) = vee(&root, &["review", "--working-tree", "--gate"]);
    assert_eq!(code, Some(1), "{review:#}");
    let gate = &review["gate"];
    assert_eq!(gate["status"], "block");
    assert_eq!(gate["blocking_findings"], serde_json::json!([blocking_id]));
    assert!(gate["reasons"][0]
        .as_str()
        .unwrap()
        .contains("trusted analyzers reported blocking results"));
    assert_eq!(
        gate["replay_inputs"]["analyzer_reports"][0]["run_id"],
        run_id.as_str()
    );
    let review_id = review["review_id"].as_str().unwrap().to_owned();

    let (code, waiver) = vee(
        &root,
        &[
            "waivers",
            "create",
            &blocking_id,
            "--review",
            &review_id,
            "--reason",
            "tracked in issue 12",
            "--author",
            "maintainer",
        ],
    );
    assert_eq!(code, Some(0), "{waiver:#}");

    let (code, check) = vee(&root, &["gate", "check", "--review", &review_id]);
    assert_eq!(code, Some(0), "{check:#}");
    assert_eq!(check["status"], "pass");
    assert!(check["reasons"].to_string().contains("waiver"), "{check:#}");
}

#[test]
fn an_analyzer_without_valid_sarif_leaves_the_gate_incomplete() {
    let (_fixture, root) = repository(|_| "#!/bin/sh\necho 'not sarif'\n".into());

    let (code, run) = vee(&root, &["verify", "--profile", "lint", "--working-tree"]);
    assert_eq!(code, Some(0), "{run:#}");
    let (code, report) = vee(
        &root,
        &["verification", "findings", run["run_id"].as_str().unwrap()],
    );
    assert_eq!(code, Some(2));
    assert_eq!(report["parsed"], false);

    let (code, review) = vee(&root, &["review", "--working-tree", "--gate"]);
    assert_eq!(code, Some(2), "{review:#}");
    assert_eq!(review["gate"]["status"], "incomplete");
}
