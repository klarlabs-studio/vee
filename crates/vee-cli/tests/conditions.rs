//! Approval conditions are classified once per change, recorded, and only
//! decide whether a person approves; the gate is unaffected (ADR 0035).
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

fn vee(root: &Path, args: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_vee"))
        .current_dir(root)
        .env("NO_COLOR", "1")
        .env("VEE_CONFIG", root.join("no-user-config.yaml"))
        .args(args)
        .output()
        .unwrap()
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

#[test]
fn a_condition_that_holds_sends_the_change_to_a_person_and_replays() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let outside = tempfile::tempdir().unwrap();
    let calls = outside.path().join("calls");
    let provider = outside.path().join("provider");
    // Reviews find nothing; the conditions task says the auth flow changed.
    std::fs::write(
        &provider,
        format!(
            "#!/bin/sh\ninput=$(cat)\ncase \"$input\" in\n  *auth_flow*) echo call >> {calls}; printf '%s' '{{\"conditions\":[{{\"id\":\"auth_flow\",\"holds\":true,\"evidence\":\"src/auth.rs changes login.\"}}]}}' ;;\n  *) printf '%s' '{{\"schema_version\":1,\"findings\":[]}}' ;;\nesac\n",
            calls = calls.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&provider, std::fs::Permissions::from_mode(0o755)).unwrap();
    git(root, &["init", "-q"]);
    git(root, &["config", "user.email", "vee@example.invalid"]);
    git(root, &["config", "user.name", "Vee test"]);
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/auth.rs"), "fn login() {}\n").unwrap();
    std::fs::write(root.join("reviewer.md"), "Review the change.\n").unwrap();
    std::fs::write(
        root.join(".vee.yaml"),
        format!(
            "version: 1\nproviders:\n  fake: {{ kind: cli, executable: {} }}\nreviewers:\n  correctness: {{ provider: fake, instructions_file: reviewer.md }}\npolicy:\n  required_reviewers: [correctness]\n  block_severities: [high]\n  minimum_confidence: 80\n  on_incomplete: block\napproval:\n  max_risk: elevated\n  conditions:\n    - {{ id: auth_flow, when: changes the authentication flow }}\n",
            provider.display()
        ),
    )
    .unwrap();
    git(root, &["add", "."]);
    git(root, &["commit", "-qm", "initial"]);
    std::fs::write(root.join("src/auth.rs"), "fn login() { let _ = 1; }\n").unwrap();

    let review = vee(
        root,
        &["review", "--working-tree", "--gate", "--output", "json"],
    );
    assert_eq!(
        review.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&review.stderr)
    );
    let review: serde_json::Value = serde_json::from_slice(&review.stdout).unwrap();
    let review_id = review["review_id"].as_str().unwrap();
    let stage = |approval: &serde_json::Value| {
        approval["stages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|stage| stage["id"] == "conditions")
            .cloned()
            .unwrap()
    };

    // Before classification, approval waits for a person.
    let before = vee(
        root,
        &[
            "gate", "approval", "--review", review_id, "--output", "json",
        ],
    );
    let before: serde_json::Value = serde_json::from_slice(&before.stdout).unwrap();
    assert_eq!(before["eligible"], false);
    assert!(stage(&before)["detail"]
        .as_str()
        .unwrap()
        .contains("not classified"));

    let classified = vee(
        root,
        &[
            "gate",
            "conditions",
            "--review",
            review_id,
            "--output",
            "json",
        ],
    );
    assert_eq!(
        classified.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&classified.stderr)
    );
    let classified: serde_json::Value = serde_json::from_slice(&classified.stdout).unwrap();
    assert_eq!(classified["results"][0]["id"], "auth_flow");
    assert_eq!(classified["results"][0]["holds"], true);
    assert!(classified["output_digest"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    let valid = |schema: &str, value: &serde_json::Value| {
        let schema: serde_json::Value = serde_json::from_str(schema).unwrap();
        jsonschema::validator_for(&schema).unwrap().is_valid(value)
    };
    assert!(valid(
        include_str!("../../../schemas/condition-classification-v1.schema.json"),
        &classified
    ));

    // Asking again reads the stored classification, not the model.
    let again = vee(
        root,
        &[
            "gate",
            "conditions",
            "--review",
            review_id,
            "--output",
            "json",
        ],
    );
    let again: serde_json::Value = serde_json::from_slice(&again.stdout).unwrap();
    assert_eq!(again, classified);
    assert_eq!(std::fs::read_to_string(&calls).unwrap().lines().count(), 1);

    let after = vee(
        root,
        &[
            "gate", "approval", "--review", review_id, "--output", "json",
        ],
    );
    let after: serde_json::Value = serde_json::from_slice(&after.stdout).unwrap();
    assert_eq!(after["eligible"], false);
    assert!(valid(
        include_str!("../../../schemas/approval-eligibility-v1.schema.json"),
        &after
    ));
    assert!(
        stage(&after)["detail"]
            .as_str()
            .unwrap()
            .contains("auth_flow (src/auth.rs changes login.)"),
        "{after}"
    );

    // The gate does not depend on conditions.
    let gate = vee(root, &["gate", "check", "--review", review_id]);
    assert_eq!(
        gate.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&gate.stderr)
    );
}
