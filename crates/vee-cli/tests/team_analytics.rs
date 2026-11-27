//! `vee analytics aggregate` end to end: real `vee analytics` exports from two
//! repositories become one report, as JSON and as a static HTML page.
#![cfg(unix)]

use std::path::Path;

fn vee() -> std::process::Command {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_vee"));
    command.env("NO_COLOR", "1");
    command
}

fn git(root: &Path, args: &[&str]) {
    let status = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?}");
}

/// A repository's `vee analytics --output json`.
fn export(directory: &Path) -> Vec<u8> {
    git(directory, &["init", "-q", "-b", "main"]);
    std::fs::write(directory.join(".vee.yaml"), "version: 1\n").unwrap();
    let output = vee()
        .args(["analytics", "--output", "json"])
        .current_dir(directory)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

#[test]
fn analytics_from_two_repositories_become_one_report() {
    let exports = tempfile::tempdir().unwrap();
    for name in ["service", "web"] {
        let repository = tempfile::tempdir().unwrap();
        std::fs::write(
            exports.path().join(format!("{name}.json")),
            export(repository.path()),
        )
        .unwrap();
    }
    std::fs::write(
        exports.path().join("approvals.json"),
        serde_json::json!({
            "schema_version": 1, "repository": "team/<service>", "pull_requests_read": 5,
            "with_verdicts": 4, "eligible": 4,
            "outcomes": {"merged_as_eligible": 3, "changed_after_eligible": 1},
            "agreement_rate": 0.75, "override_rate": 0.25, "cases": [], "limitations": []
        })
        .to_string(),
    )
    .unwrap();
    let html = exports.path().join("report.html");
    let output = vee()
        .args(["analytics", "aggregate", "--output", "json", "--html"])
        .arg(&html)
        .arg(exports.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/team-analytics-v1.schema.json"
    ))
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let errors: Vec<String> = validator
        .iter_errors(&report)
        .map(|e| e.to_string())
        .collect();
    assert!(errors.is_empty(), "{errors:?}\n{report:#}");
    assert_eq!(report["sources"].as_array().unwrap().len(), 3);
    assert_eq!(report["approvals"]["eligible"], 4);
    assert_eq!(report["approvals"]["override_rate"], 0.25);

    let page = std::fs::read_to_string(&html).unwrap();
    assert!(page.starts_with("<!doctype html>"));
    assert!(page.contains("Approval without a person"));
    // Text from a document is escaped.
    assert!(page.contains("team/&lt;service&gt;") && !page.contains("team/<service>"));

    // The existing summary still works without a subcommand.
    let repository = tempfile::tempdir().unwrap();
    assert!(!export(repository.path()).is_empty());
}
