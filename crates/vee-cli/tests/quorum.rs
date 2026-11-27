//! `vee analytics quorum` end to end: a sampled reviewer with no labelled
//! findings is listed without a recommendation, and the JSON matches its schema.
#![cfg(unix)]

#[test]
fn analytics_quorum_lists_sampled_reviewers_and_matches_its_schema() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let status = std::process::Command::new("git")
        .args(["init", "-q", "-b", "main"])
        .current_dir(root)
        .status()
        .unwrap();
    assert!(status.success());
    std::fs::write(root.join("reviewer.md"), "Review for defects.\n").unwrap();
    std::fs::write(
        root.join(".vee.yaml"),
        "version: 1\nproviders:\n  p: { kind: cli, executable: reviewer }\nreviewers:\n  correctness: { provider: p, instructions_file: reviewer.md, samples: 3 }\n  style: { provider: p, instructions_file: reviewer.md }\n",
    )
    .unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_vee"))
        .args(["analytics", "quorum", "--output", "json"])
        .env("NO_COLOR", "1")
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/quorum-calibration-v1.schema.json"
    ))
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let errors: Vec<String> = validator
        .iter_errors(&report)
        .map(|error| error.to_string())
        .collect();
    assert!(errors.is_empty(), "{errors:?}\n{report:#}");
    let reviewers = report["reviewers"].as_array().unwrap();
    assert_eq!(reviewers.len(), 1, "{report:#}");
    assert_eq!(reviewers[0]["reviewer_id"], "correctness");
    assert_eq!(reviewers[0]["configured_quorum"], 2);
    assert!(reviewers[0]["recommended_quorum"].is_null());

    let text = std::process::Command::new(env!("CARGO_BIN_EXE_vee"))
        .args(["analytics", "quorum"])
        .env("NO_COLOR", "1")
        .current_dir(root)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&text.stdout);
    assert!(text.contains("not enough labels"), "{text}");
}
